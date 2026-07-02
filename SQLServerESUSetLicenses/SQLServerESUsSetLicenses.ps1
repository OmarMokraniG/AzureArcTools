#requires -Version 7.3 -module Az.ResourceGraph -module Az.Accounts
<#
.DESCRIPTION
  This script detects out-of-support SQL Server instances enabled by Azure Arc (SQL Server 2016 by
  default) and creates SQL Server Extended Security Updates (ESU) p-core licenses
  (Microsoft.AzureArcData/sqlServerEsuLicenses) for them.

  The ESU p-core license (a.k.a. "physical cores with unlimited virtualization") is the SQL Server
  equivalent of the Windows Server 2012 ESU license used by ESUsSetLicenses.ps1. Just like a
  Windows Server ESU license, it can be created WITHOUT being activated and activated later, so you
  can coordinate the activation (and therefore the billing start) with the end-of-support date.

  Activation state lifecycle (property 'activationState', enum 'State'):
    Inactive   -> license created, applied to the scope, NOT billed yet   (apply without activating)
    Active     -> license activated, ESUs delivered, billing starts        (activate)
    Terminated -> license terminated, ESU subscription stopped             (deactivate/terminate)

  SQL Server 2016 (13.x) extended support ends on July 14, 2026. Year 1 of the ESU program starts on
  that date. You can create the licenses now in the Inactive state and activate them on/after that
  date to avoid early charges.

  This script also supports the alternative PER-MACHINE ESU subscription (v-core model): it enables or
  disables ESUs directly in the SQL Server configuration of each Azure Arc machine by setting the
  'enableExtendedSecurityUpdates' property on the Azure Extension for SQL Server (and 'LicenseType' =
  PAYG/Paid). That model is billed by v-cores (or physical cores on bare metal), the extension
  auto-detects host size/type/edition, and subscribing activates it immediately (there is no
  "create inactive, activate later"). Existing extension settings are preserved.

  Docs:
    https://learn.microsoft.com/sql/sql-server/azure-arc/extended-security-updates
    https://learn.microsoft.com/sql/sql-server/azure-arc/manage-configuration#manage-pcore-esu-license
    https://learn.microsoft.com/azure/templates/microsoft.azurearcdata/sqlserveresulicenses
  Pricing:
    https://learn.microsoft.com/sql/sql-server/end-of-support/sql-server-extended-security-updates

.EXAMPLE
  Detect the Azure Arc-enabled SQL Server 2016 instances and build the source CSV files.
  No change is made with this switch parameter.

  A 'SQLServerESUArcInstances.csv' file (one row per SQL instance) and a
  'SQLServerESULicensesSourcefile.csv' file (one row per ESU license to create) are generated.
  Review and modify them as needed.

   .\SQLServerESUsSetLicenses.ps1 -ReadOnly

.EXAMPLE
  Create the SQL Server 2016 ESU licenses using the SQLServerESULicensesSourcefile.csv file.
  By default the licenses are created in the 'Inactive' state (applied but NOT activated).

  A 'SQLServerESUAssignmentInfo.csv' file is generated with the ids of the licenses created.

   .\SQLServerESUsSetLicenses.ps1 -ProvisionLicenses

.EXAMPLE
  Create the licenses using a modified source file and activate them immediately (billing starts).

   .\SQLServerESUsSetLicenses.ps1 -ProvisionLicenses -SourceLicensesFile 'MyLicenses.csv' -Activate

.EXAMPLE
  Activate previously created (Inactive) ESU licenses using the SQLServerESUAssignmentInfo.csv file.

   .\SQLServerESUsSetLicenses.ps1 -ActivateLicenses

.EXAMPLE
  Terminate (deactivate) ESU licenses to stop the ESU subscription and billing.

   .\SQLServerESUsSetLicenses.ps1 -DeactivateLicenses -SourceLicenseInfoFileDeactivate MyAssignmentInfo.csv

.EXAMPLE
  Per-machine (v-core) model: subscribe every Arc machine that hosts a SQL Server 2016 instance to
  Extended Security Updates, setting the license type to pay-as-you-go. This activates ESUs immediately.

   .\SQLServerESUsSetLicenses.ps1 -EnableEsuPerMachine
   .\SQLServerESUsSetLicenses.ps1 -EnableEsuPerMachine -LicenseType Paid

.EXAMPLE
  Per-machine (v-core) model: unsubscribe the machines from Extended Security Updates (stops charges).

   .\SQLServerESUsSetLicenses.ps1 -DisableEsuPerMachine

.NOTES
  The ESU p-core license covers the physical cores of the hosts in the selected scope with unlimited
  virtualization. This script sizes each license as the sum of the physical cores of the DISTINCT
  Arc-enabled machines that host the out-of-support SQL Server instances (minimum 16 p-cores).
  When your SQL Server instances run on virtual machines, the Arc agent reports the cores of the VM,
  not of the physical host. Review the generated CSV and set 'physicalCores' to the real number of
  physical cores of the hosts before provisioning.
#>

[CmdletBinding(DefaultParameterSetName = 'Readonly')]
Param (
  [Parameter(Mandatory = $false, ParameterSetName = 'Readonly')]
  [switch]$ReadOnly,

  [Parameter(Mandatory = $false, ParameterSetName = 'ProvisionLicenses')]
  [switch]$ProvisionLicenses,
  [Parameter(Mandatory = $false, ParameterSetName = 'ProvisionLicenses')]
  [string]$SourceLicensesFile,
  # Create the licenses already activated instead of Inactive (billing starts immediately).
  [Parameter(Mandatory = $false, ParameterSetName = 'ProvisionLicenses')]
  [switch]$Activate,
  [Parameter(Mandatory = $false, ParameterSetName = 'ProvisionLicenses')]
  [string]$LicenseSubscriptionId,
  [Parameter(Mandatory = $false, ParameterSetName = 'ProvisionLicenses')]
  [string]$LicenseResourceGroup,

  [Parameter(Mandatory = $false, ParameterSetName = 'ActivateLicenses')]
  [switch]$ActivateLicenses,
  [Parameter(Mandatory = $false, ParameterSetName = 'ActivateLicenses')]
  [string]$SourceLicenseInfoFile,

  [Parameter(Mandatory = $false, ParameterSetName = 'DeactivateLicenses')]
  [switch]$DeactivateLicenses,
  [Parameter(Mandatory = $false, ParameterSetName = 'DeactivateLicenses')]
  [string]$SourceLicenseInfoFileDeactivate,

  # Per-machine (v-core) model: subscribe each Arc machine to ESUs in the SQL Server configuration.
  [Parameter(Mandatory = $false, ParameterSetName = 'EnableEsuPerMachine')]
  [switch]$EnableEsuPerMachine,
  [Parameter(Mandatory = $false, ParameterSetName = 'EnableEsuPerMachine')]
  [string]$SourceInstancesFile,
  # License type set on the SQL extension when subscribing. Must be PAYG or Paid for ESUs.
  # If not specified, an existing PAYG/Paid license type on the machine is preserved.
  [Parameter(Mandatory = $false, ParameterSetName = 'EnableEsuPerMachine')]
  [ValidateSet('PAYG', 'Paid')]
  [string]$LicenseType = 'PAYG',

  # Per-machine (v-core) model: unsubscribe each Arc machine from ESUs.
  [Parameter(Mandatory = $false, ParameterSetName = 'DisableEsuPerMachine')]
  [switch]$DisableEsuPerMachine,
  [Parameter(Mandatory = $false, ParameterSetName = 'DisableEsuPerMachine')]
  [string]$SourceInstancesFileDisable,

  # SQL Server version eligible for ESU. Valid values: 'SQL Server 2012', 'SQL Server 2014', 'SQL Server 2016'.
  [Parameter(Mandatory = $false)]
  [ValidateSet('SQL Server 2012', 'SQL Server 2014', 'SQL Server 2016')]
  [string]$SqlVersion = 'SQL Server 2016',

  # Azure scope the ESU license applies to. One license is proposed per scope unit.
  [Parameter(Mandatory = $false, ParameterSetName = 'Readonly')]
  [ValidateSet('ResourceGroup', 'Subscription', 'Tenant')]
  [string]$ScopeType = 'ResourceGroup',

  # Billing plan for the ESU license. ESU is always billed pay-as-you-go (PAYG).
  [Parameter(Mandatory = $false, ParameterSetName = 'Readonly')]
  [ValidateSet('PAYG', 'Paid')]
  [string]$BillingPlan = 'PAYG'
)

# Latest Microsoft.AzureArcData API version that supports sqlServerEsuLicenses with version 'SQL Server 2016'.
$apiversion = '2026-03-01-preview'

# Minimum number of physical cores per ESU license.
$MinimumPhysicalCores = 16

# API version for the Azure Extension for SQL Server (Microsoft.HybridCompute machine extension),
# used by the per-machine (v-core) ESU subscription modes.
$machineExtensionApiVersion = '2024-07-10'

#region Helper functions

function Get-SqlEsuLicenseName {
  param([string]$Scope, [string]$Identifier)
  # Resource name must match ^[-\w\._\(\)]+$
  $safe = ($Identifier -replace '[^-\w\._\(\)]', '-')
  return "SQLServerESU-$($SqlVersion.Replace('SQL Server ', ''))-$Scope-$safe"
}

function Set-SqlEsuActivationState {
  param(
    [Parameter(Mandatory)] [string]$LicenseId,
    [Parameter(Mandatory)] [ValidateSet('Active', 'Inactive', 'Terminated')] [string]$State
  )
  # Change only the activationState with a minimal PATCH (SqlServerEsuLicenseUpdate). Using PATCH
  # instead of a full PUT avoids re-sending read-only properties (uniqueId, activatedAt, systemData...).
  $payload = @"
{
  "properties": {
    "activationState": "$State"
  }
}
"@
  $result = Invoke-AzRestMethod -Path "$($LicenseId)?api-version=$apiversion" -Method PATCH -Payload $payload -ErrorAction Stop
  if ($result.StatusCode -ge 400) {
    throw "PATCH failed for $LicenseId (HTTP $($result.StatusCode)): $($result.Content)"
  }
  return $result
}

function Get-SqlEsuArcInstances {
  # Detect the out-of-support SQL Server instances enabled by Azure Arc and join them to their
  # hosting Arc machine to obtain the physical core count (detectedProperties.coreCount).
  param([Parameter(Mandatory)] [string]$Version)
  Write-Host "Querying Azure Arc-enabled SQL Server instances of version '$Version'..." -ForegroundColor Green
  $sqlQuery = @"
resources
| where type =~ 'microsoft.azurearcdata/sqlserverinstances'
| where tostring(properties.version) == '$Version'
| extend machineId = tolower(tostring(properties.containerResourceId))
| extend sqlEdition = tostring(properties.edition), vCores = toint(properties.vCore), licenseType = tostring(properties.licenseType)
| join kind=leftouter (
    resources
    | where type =~ 'microsoft.hybridcompute/machines'
    | extend mId = tolower(tostring(id))
    | project mId, machineName = name,
              physicalCores = toint(properties.detectedProperties.coreCount),
              logicalCores  = toint(properties.detectedProperties.logicalCoreCount),
              model  = tostring(properties.detectedProperties.model),
              osName = tostring(properties.osName),
              machineStatus = tostring(properties.status)
  ) on `$left.machineId == `$right.mId
| extend Type = iff(model contains 'Virtual' or model contains 'VMware', 'Virtual', 'Physical')
| project SqlInstance = name, version = tostring(properties.version), sqlEdition, vCores, licenseType,
          location, subscriptionId, resourceGroup, machineName, machineId, physicalCores, logicalCores,
          Type, osName, machineStatus
| order by subscriptionId asc, resourceGroup asc, machineName asc
"@
  return Search-AzGraph -Query $sqlQuery -First 1000
}

function Set-SqlEsuPerMachine {
  # Enable or disable the per-machine (v-core) ESU subscription on the Azure Extension for SQL Server.
  param(
    [Parameter(Mandatory)] [string]$MachineId,
    [Parameter(Mandatory)] [bool]$Enable,
    [string]$LicenseType = 'PAYG',
    [switch]$ForceLicenseType
  )
  # Locate the SQL extension on the machine (Windows or Linux) and read its current settings.
  $extName = $null; $extObj = $null
  foreach ($n in @('WindowsAgent.SqlServer', 'LinuxAgent.SqlServer')) {
    $get = Invoke-AzRestMethod -Path "$MachineId/extensions/$($n)?api-version=$machineExtensionApiVersion" -Method GET
    if ($get.StatusCode -eq 200) { $extName = $n; $extObj = $get.Content | ConvertFrom-Json; break }
  }
  if (-not $extName) { throw "Azure Extension for SQL Server not found on $MachineId." }
  if ($extObj.properties.provisioningState -ne 'Succeeded') {
    throw "Extension is in '$($extObj.properties.provisioningState)' state; skipping."
  }

  # Preserve ALL existing settings (an update replaces the settings object) and change only ESU keys.
  $settings = @{}
  if ($extObj.properties.settings) {
    foreach ($p in $extObj.properties.settings.PSObject.Properties) { $settings[$p.Name] = $p.Value }
  }

  if ($Enable) {
    $currentLicense = [string]$settings['LicenseType']
    if ($ForceLicenseType -or ($currentLicense -notin @('PAYG', 'Paid'))) {
      $settings['LicenseType'] = $LicenseType
    }
    if (@('PAYG', 'Paid') -notcontains [string]$settings['LicenseType']) {
      throw "LicenseType must be 'PAYG' or 'Paid' to subscribe to ESUs (current: '$($settings['LicenseType'])')."
    }
    $settings['enableExtendedSecurityUpdates'] = $true
  }
  else {
    $settings['enableExtendedSecurityUpdates'] = $false
  }
  $settings['esuLastUpdatedTimestamp'] = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')

  $body = @{ properties = @{ settings = $settings } } | ConvertTo-Json -Depth 30
  $result = Invoke-AzRestMethod -Path "$MachineId/extensions/$($extName)?api-version=$machineExtensionApiVersion" -Method PATCH -Payload $body -ErrorAction Stop
  if ($result.StatusCode -ge 400) {
    throw "PATCH failed for $MachineId (HTTP $($result.StatusCode)): $($result.Content)"
  }
  return [PSCustomObject]@{
    extension   = $extName
    licenseType = $settings['LicenseType']
    esu         = $settings['enableExtendedSecurityUpdates']
    statusCode  = $result.StatusCode
  }
}

#endregion

#region Detect (ReadOnly) and build the source CSV files
if ($ReadOnly -or ($ProvisionLicenses -and (-not $SourceLicensesFile))) {

  if ($ReadOnly) {
    Write-Host "Running in read-only mode. No licenses will be created, activated or terminated." -ForegroundColor Yellow
  }
  $sqlInstances = Get-SqlEsuArcInstances -Version $SqlVersion

  if (-not $sqlInstances -or $sqlInstances.Count -eq 0) {
    Write-Host "No Azure Arc-enabled SQL Server instances of version '$SqlVersion' were found in the accessible subscriptions." -ForegroundColor Yellow
    if ($ReadOnly) { break }
  }
  else {
    $sqlInstances |
      Select-Object SqlInstance, version, sqlEdition, vCores, licenseType, Type, physicalCores, logicalCores, machineName, location, resourceGroup, subscriptionId, machineId |
      Sort-Object -Property subscriptionId, resourceGroup, machineName | Format-Table -AutoSize

    $sqlInstances |
      Select-Object SqlInstance, version, sqlEdition, vCores, licenseType, Type, physicalCores, logicalCores, machineName, machineId, location, resourceGroup, subscriptionId, osName, machineStatus |
      Export-Csv -Path .\SQLServerESUArcInstances.csv -Force -NoTypeInformation

    Write-Host "`nThe '$($SqlVersion)' Arc-enabled SQL Server instances were exported to 'SQLServerESUArcInstances.csv'.`n" -ForegroundColor Yellow

    #region Build one ESU license per scope unit
    Write-Host "Building the ESU license source file (scope: $ScopeType)..." -ForegroundColor Green

    # Group the DISTINCT host machines per scope unit and sum their physical cores (each host once).
    switch ($ScopeType) {
      'Subscription' { $groupKey = { $_.subscriptionId } }
      'Tenant'       { $groupKey = { 'tenant' } }
      default        { $groupKey = { "$($_.subscriptionId)/$($_.resourceGroup)" } } # ResourceGroup
    }

    $esuLicenses = @()
    $sqlInstances | Group-Object -Property $groupKey | ForEach-Object {
      $group = $_.Group
      # Distinct hosts in this scope unit (a host may run several SQL instances).
      $hosts = $group | Sort-Object machineId -Unique
      $sumCores = ($hosts | ForEach-Object {
          $pc = [int]$_.physicalCores
          if ($pc -le 0) { [int]$_.logicalCores } else { $pc }
        } | Measure-Object -Sum).Sum
      if (-not $sumCores -or $sumCores -lt $MinimumPhysicalCores) { $sumCores = $MinimumPhysicalCores }

      $sample = $group | Select-Object -First 1
      $subscriptionId = $sample.subscriptionId
      $resourceGroup  = $sample.resourceGroup
      # ESU subscriptions are pinned to a location; use the most common location of the hosts.
      $location = ($group | Group-Object location | Sort-Object Count -Descending | Select-Object -First 1).Name

      switch ($ScopeType) {
        'Subscription' { $nameId = $subscriptionId }
        'Tenant'       { $nameId = 'tenant' }
        default        { $nameId = $resourceGroup }
      }

      $esuLicenses += [PSCustomObject]@{
        LicenseName     = Get-SqlEsuLicenseName -Scope $ScopeType -Identifier $nameId
        location        = $location
        subscriptionId  = $subscriptionId
        resourceGroup   = $resourceGroup       # RG where the license resource will be created
        scopeType       = $ScopeType
        version         = $SqlVersion
        billingPlan     = $BillingPlan
        physicalCores   = [int]$sumCores
        activationState = 'Inactive'           # apply without activating; use -Activate or -ActivateLicenses later
        coveredHosts    = (($hosts | Select-Object -ExpandProperty machineName) -join ';')
      }
    }

    $esuLicenses | Select-Object LicenseName, scopeType, version, billingPlan, physicalCores, activationState, location, resourceGroup, subscriptionId, coveredHosts | Format-Table -AutoSize
    $esuLicenses | Export-Csv -Path .\SQLServerESULicensesSourcefile.csv -Force -NoTypeInformation

    Write-Host "`n'SQLServerESULicensesSourcefile.csv' was created with the ESU licenses proposed for your environment." -ForegroundColor Yellow
    Write-Host "Review the 'physicalCores', 'location' and 'scopeType' columns (min $MinimumPhysicalCores p-cores) before provisioning.`n" -ForegroundColor Yellow
    #endregion
  }
}

if ($ReadOnly) {
  break
}
#endregion

#region Provision (create) the ESU licenses
if ($ProvisionLicenses) {

  $desiredState = if ($Activate) { 'Active' } else { 'Inactive' }
  Write-Host "Creating SQL Server ESU licenses (activationState = $desiredState) ..." -ForegroundColor Green

  if ($SourceLicensesFile) {
    $licensesToCreate = Import-Csv -Path .\$SourceLicensesFile -ErrorAction Stop
  }
  else {
    $licensesToCreate = Import-Csv -Path .\SQLServerESULicensesSourcefile.csv -ErrorAction Stop
  }

  $assignmentInfo = @()
  foreach ($license in $licensesToCreate) {

    $subscriptionId = if ($LicenseSubscriptionId) { $LicenseSubscriptionId } else { $license.subscriptionId }
    $resourceGroup  = if ($LicenseResourceGroup)  { $LicenseResourceGroup }  else { $license.resourceGroup }
    $state          = if ($license.activationState) { $license.activationState } else { $desiredState }
    if ($Activate) { $state = 'Active' }

    $payload = @"
{
  "location": "$($license.location)",
  "properties": {
    "billingPlan": "$($license.billingPlan)",
    "version": "$($license.version)",
    "physicalCores": $([int]$license.physicalCores),
    "activationState": "$state",
    "scopeType": "$($license.scopeType)"
  }
}
"@

    $path = "/subscriptions/$subscriptionId/resourceGroups/$resourceGroup/providers/Microsoft.AzureArcData/sqlServerEsuLicenses/$($license.LicenseName)?api-version=$apiversion"
    try {
      $response = Invoke-AzRestMethod -Path $path -Method PUT -Payload $payload -ErrorAction Stop
      if ($response.StatusCode -ge 400) {
        throw "HTTP $($response.StatusCode): $($response.Content)"
      }
      $created = $response.Content | ConvertFrom-Json
      $assignmentInfo += [PSCustomObject]@{
        LicenseName     = $license.LicenseName
        ESUlicenseid    = $created.id
        scopeType       = $license.scopeType
        version         = $license.version
        physicalCores   = $license.physicalCores
        activationState = $created.properties.activationState
        location        = $license.location
        resourceGroup   = $resourceGroup
        subscriptionId  = $subscriptionId
      }
      Write-Host "  Created '$($license.LicenseName)' (activationState = $($created.properties.activationState))." -ForegroundColor Green
    }
    catch {
      Write-Host "  Could not create license '$($license.LicenseName)':" -ForegroundColor Red
      $_.Exception.Message
    }
  }

  $assignmentInfo | Export-Csv -Path .\SQLServerESUAssignmentInfo.csv -Force -NoTypeInformation
  Write-Host "`nCreated $($assignmentInfo.Count) SQL Server ESU license(s). Details saved to 'SQLServerESUAssignmentInfo.csv'." -ForegroundColor Green
  if ($desiredState -eq 'Inactive') {
    Write-Host "The licenses are Inactive (applied without activating). Run -ActivateLicenses to activate them." -ForegroundColor Yellow
  }
}
#endregion

#region Activate the ESU licenses
if ($ActivateLicenses) {
  Write-Host "Activating SQL Server ESU licenses (activationState = Active) ..." -ForegroundColor Green

  $infoFile = if ($SourceLicenseInfoFile) { $SourceLicenseInfoFile } else { 'SQLServerESUAssignmentInfo.csv' }
  $licenses = Import-Csv -Path .\$infoFile -ErrorAction Stop

  foreach ($license in $licenses) {
    try {
      $result = Set-SqlEsuActivationState -LicenseId $license.ESUlicenseid -State 'Active'
      $new = ($result.Content | ConvertFrom-Json).properties.activationState
      Write-Host "  Activated '$($license.LicenseName)' (activationState = $new)." -ForegroundColor Green
    }
    catch {
      Write-Host "  Could not activate '$($license.LicenseName)':" -ForegroundColor Red
      $_.Exception.Message
    }
  }
}
#endregion

#region Deactivate (terminate) the ESU licenses
if ($DeactivateLicenses) {
  Write-Host "Terminating SQL Server ESU licenses (activationState = Terminated) ..." -ForegroundColor Green
  Write-Host "This stops the ESU subscription and its billing for the covered scope." -ForegroundColor Yellow

  $infoFile = if ($SourceLicenseInfoFileDeactivate) { $SourceLicenseInfoFileDeactivate } else { 'SQLServerESUAssignmentInfo.csv' }
  $licenses = Import-Csv -Path .\$infoFile -ErrorAction Stop

  foreach ($license in $licenses) {
    try {
      $result = Set-SqlEsuActivationState -LicenseId $license.ESUlicenseid -State 'Terminated'
      $new = ($result.Content | ConvertFrom-Json).properties.activationState
      Write-Host "  Terminated '$($license.LicenseName)' (activationState = $new)." -ForegroundColor Green
    }
    catch {
      Write-Host "  Could not terminate '$($license.LicenseName)':" -ForegroundColor Red
      $_.Exception.Message
    }
  }
}
#endregion

#region Enable ESUs per machine (v-core subscription in the SQL Server configuration)
if ($EnableEsuPerMachine) {
  Write-Host "Subscribing Azure Arc machines that host '$SqlVersion' to Extended Security Updates (v-core model, LicenseType = $LicenseType) ..." -ForegroundColor Green
  Write-Host "This enables ESUs in the SQL Server configuration of each machine and activates the subscription immediately." -ForegroundColor Yellow

  if ($SourceInstancesFile) {
    $instances = Import-Csv -Path .\$SourceInstancesFile -ErrorAction Stop
  }
  else {
    $instances = Get-SqlEsuArcInstances -Version $SqlVersion
  }

  $machines = $instances | Where-Object { $_.machineId } | Sort-Object machineId -Unique
  if (-not $machines) {
    Write-Host "No Azure Arc machines hosting '$SqlVersion' instances were found." -ForegroundColor Yellow
  }
  # Only override LicenseType when the caller passed it explicitly; otherwise keep an existing PAYG/Paid value.
  $forceLicense = $PSBoundParameters.ContainsKey('LicenseType')
  foreach ($m in $machines) {
    try {
      $r = Set-SqlEsuPerMachine -MachineId $m.machineId -Enable $true -LicenseType $LicenseType -ForceLicenseType:$forceLicense
      Write-Host "  Subscribed '$($m.machineName)' (extension $($r.extension), LicenseType = $($r.licenseType), ESU = $($r.esu))." -ForegroundColor Green
    }
    catch {
      Write-Host "  Could not subscribe '$($m.machineName)':" -ForegroundColor Red
      $_.Exception.Message
    }
  }
}
#endregion

#region Disable ESUs per machine (unsubscribe in the SQL Server configuration)
if ($DisableEsuPerMachine) {
  Write-Host "Unsubscribing Azure Arc machines that host '$SqlVersion' from Extended Security Updates (v-core model) ..." -ForegroundColor Green
  Write-Host "This stops the per-machine ESU charges." -ForegroundColor Yellow

  if ($SourceInstancesFileDisable) {
    $instances = Import-Csv -Path .\$SourceInstancesFileDisable -ErrorAction Stop
  }
  else {
    $instances = Get-SqlEsuArcInstances -Version $SqlVersion
  }

  $machines = $instances | Where-Object { $_.machineId } | Sort-Object machineId -Unique
  if (-not $machines) {
    Write-Host "No Azure Arc machines hosting '$SqlVersion' instances were found." -ForegroundColor Yellow
  }
  foreach ($m in $machines) {
    try {
      $r = Set-SqlEsuPerMachine -MachineId $m.machineId -Enable $false
      Write-Host "  Unsubscribed '$($m.machineName)' (extension $($r.extension), ESU = $($r.esu))." -ForegroundColor Green
    }
    catch {
      Write-Host "  Could not unsubscribe '$($m.machineName)':" -ForegroundColor Red
      $_.Exception.Message
    }
  }
}
#endregion
