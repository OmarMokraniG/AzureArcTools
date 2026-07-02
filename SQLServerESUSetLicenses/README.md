# SQL Server ESU license creation and activation script

## Description

`SQLServerESUsSetLicenses.ps1` detects out-of-support **SQL Server** instances enabled by **Azure Arc**
(SQL Server 2016 by default) and creates **SQL Server Extended Security Updates (ESU) p-core licenses**
(`Microsoft.AzureArcData/sqlServerEsuLicenses`) for them.

It is the SQL Server counterpart of [`ESUSetLicenses/ESUsSetLicenses.ps1`](../ESUSetLicenses/), which
creates Windows Server 2012 / 2012 R2 ESU licenses. The SQL Server ESU **p-core license** (physical
cores with unlimited virtualization) has the same *create-first / activate-later* capability as the
Windows Server ESU license, so you can **apply the ESUs without activating them** and **activate them
later** to control when billing starts.

> SQL Server 2016 (13.x) reaches end of extended support on **July 14, 2026**. Year 1 of the ESU
> program starts on that date. Create the licenses now in the `Inactive` state and activate them
> on/after that date to avoid early charges.

### Activation state lifecycle

The license `activationState` property (enum `State`) drives the lifecycle:

| activationState | Meaning | Billing |
| --------------- | ------- | ------- |
| `Inactive`   | License created and applied to the scope, **not activated** | Not billed |
| `Active`     | License **activated**, ESUs delivered | Billed (PAYG, hourly) |
| `Terminated` | License terminated, ESU subscription stopped | Billing stops |

> Note: the base SQL Server *licensing* resource (`sqlServerLicenses`) uses `Activated`/`Deactivated`,
> but the **ESU** license resource (`sqlServerEsuLicenses`) uses the `State` enum
> (`Inactive`/`Active`/`Terminated`). This script targets the ESU license resource.

## Requirements

- PowerShell 7.3+
- Modules: `Az.Accounts`, `Az.ResourceGraph` (`Connect-AzAccount` before running)
- RBAC permissions on the target scope:
  - `Microsoft.AzureArcData/sqlServerEsuLicenses/read`
  - `Microsoft.AzureArcData/sqlServerEsuLicenses/write`
  - `Microsoft.Resources/subscriptions/read`
  - `Microsoft.Resources/subscriptions/resourceGroups/read`

## How it works

The script detects the SQL Server 2016 instances with Azure Resource Graph
(`microsoft.azurearcdata/sqlserverinstances` where `properties.version == 'SQL Server 2016'`), joins
each instance to its hosting Azure Arc machine (`microsoft.hybridcompute/machines`) to read the
physical core count (`detectedProperties.coreCount`), and proposes **one ESU license per scope unit**
(a resource group by default) sized to the sum of the physical cores of the distinct hosts
(minimum 16 p-cores).

## Parameters (modes)

| Mode | Switch | Description |
| ---- | ------ | ----------- |
| Detect | `-ReadOnly` (default) | Detects the instances and generates the CSV files. **No change is made.** |
| Provision | `-ProvisionLicenses` | Creates the ESU licenses. `Inactive` by default (apply without activating); add `-Activate` to create them already activated. |
| Activate | `-ActivateLicenses` | Sets `activationState = Active` on existing licenses. |
| Deactivate | `-DeactivateLicenses` | Sets `activationState = Terminated` (stops the ESU subscription). |

Common parameters:

- `-SqlVersion` – `SQL Server 2012` / `SQL Server 2014` / `SQL Server 2016` (default `SQL Server 2016`).
- `-ScopeType` – `ResourceGroup` (default) / `Subscription` / `Tenant`. One license is proposed per scope unit.
- `-BillingPlan` – `PAYG` (default) / `Paid`.

## Generated files

| File | Content |
| ---- | ------- |
| `SQLServerESUArcInstances.csv` | One row per detected Arc-enabled SQL Server instance. |
| `SQLServerESULicensesSourcefile.csv` | One row per ESU license to create. **Review before provisioning.** |
| `SQLServerESUAssignmentInfo.csv` | Ids of the licenses created (used by the activate/deactivate modes). |

A committed sample of the source file is provided in
[`SQLServerESULicensesSourcefilesample.csv`](./SQLServerESULicensesSourcefilesample.csv).

> **Sizing note:** when SQL Server runs on virtual machines, the Arc agent reports the cores of the VM,
> not of the physical host. For the unlimited-virtualization benefit you license the **physical host**
> cores. Review the `physicalCores` column in `SQLServerESULicensesSourcefile.csv` and set it to the
> real number of physical cores of the hosts (minimum 16) before running `-ProvisionLicenses`.

## Examples

Detect the SQL Server 2016 instances and build the source CSV files (no change):

```powershell
.\SQLServerESUsSetLicenses.ps1 -ReadOnly
```

Create the ESU licenses **without activating** them (Inactive):

```powershell
.\SQLServerESUsSetLicenses.ps1 -ProvisionLicenses
```

Create the ESU licenses and activate them immediately (billing starts):

```powershell
.\SQLServerESUsSetLicenses.ps1 -ProvisionLicenses -Activate
```

Activate previously created (Inactive) licenses — e.g. on July 14, 2026:

```powershell
.\SQLServerESUsSetLicenses.ps1 -ActivateLicenses
```

Terminate the ESU licenses to stop the subscription and billing:

```powershell
.\SQLServerESUsSetLicenses.ps1 -DeactivateLicenses
```

One license per subscription instead of per resource group:

```powershell
.\SQLServerESUsSetLicenses.ps1 -ReadOnly -ScopeType Subscription
```

## References

- [SQL Server Extended Security Updates enabled by Azure Arc](https://learn.microsoft.com/sql/sql-server/azure-arc/extended-security-updates)
- [Manage the unlimited virtualization benefit for a SQL Server ESU subscription](https://learn.microsoft.com/sql/sql-server/azure-arc/manage-configuration#manage-pcore-esu-license)
- [`Microsoft.AzureArcData/sqlServerEsuLicenses` ARM reference](https://learn.microsoft.com/azure/templates/microsoft.azurearcdata/sqlserveresulicenses)
- [What are Extended Security Updates for SQL Server?](https://learn.microsoft.com/sql/sql-server/end-of-support/sql-server-extended-security-updates)
