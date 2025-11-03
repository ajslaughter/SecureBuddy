# WinSysAuto v0.1

WinSysAuto is a PowerShell automation module that orchestrates common Windows Server operations—inventory, patching, hardening, and monitoring—through composable functions. Version **v0.1** focuses on day-zero visibility and remediation so that administrators can standardize baseline management from a single toolchain.

## Table of Contents
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
  - [Install with `install.ps1`](#install-with-installps1)
  - [Manual import](#manual-import)
- [Usage Examples](#usage-examples)
  - [Module discovery](#module-discovery)
  - [Core functions](#core-functions)
- [Roadmap](#roadmap)
- [Contribution Guidelines](#contribution-guidelines)
- [Testing Instructions](#testing-instructions)

## Features
WinSysAuto v0.1 includes the following capabilities:

- **Unified inventory** – Collect hardware, OS, and role metadata with one command.
- **Safe patch orchestration** – Stage, install, and verify updates with optional maintenance-window guards.
- **Hardening baselines** – Apply opinionated security baselines and report drifts.
- **Lightweight monitoring** – Poll critical Windows services and resource counters on demand.
- **Idempotent design** – Each function re-evaluates state to avoid unintended reconfiguration.
- **Composable pipelines** – Functions emit rich objects so you can pipe results into logging, reporting, or ticketing systems.

## Requirements
Before using WinSysAuto v0.1 ensure the following prerequisites are met:

- PowerShell 5.1 or PowerShell 7.2+.
- Windows Server 2016, 2019, or 2022 with latest security updates.
- Local administrator rights (remote administrative permissions if managing other hosts).
- Remote management enabled via WinRM for cross-machine operations.
- Optional: Access to your update management solution (WSUS, Microsoft Update, or SCCM) for patch orchestration commands.

## Installation
### Install with `install.ps1`
The repository provides an `install.ps1` bootstrapper that copies the module into your PowerShell module path and registers default configuration files.

```powershell
# From a PowerShell prompt in the repository root
git clone https://github.com/your-org/WinSysAuto.git
cd WinSysAuto
.\install.ps1 -Scope CurrentUser -Verbose
```

Parameters:

- `-Scope` (`CurrentUser` | `AllUsers`): Controls whether the module installs to `~/Documents/WindowsPowerShell/Modules` or `C:\Program Files\WindowsPowerShell\Modules`.
- `-Force`: Overwrites any existing WinSysAuto installation.
- `-Verbose`: Enables detailed progress logging.

### Manual import
If you prefer manual installation:

```powershell
# Copy the module folder into a PSModulePath location
Copy-Item -Path .\WinSysAuto -Destination "$env:USERPROFILE\Documents\WindowsPowerShell\Modules" -Recurse

# Import the module in your session
Import-Module WinSysAuto -Force

# Confirm the module is available
Get-Module WinSysAuto -ListAvailable
```

To load the module in every session, add `Import-Module WinSysAuto` to your PowerShell profile script.

## Usage Examples
### Module discovery
List module commands and review in-session help:

```powershell
Get-Command -Module WinSysAuto
Get-Help Get-WSAInventory -Detailed
```

### Core functions
Each exported function includes verbose logging, supports `-WhatIf`, and returns structured objects. The snippets below illustrate common usage patterns and expected output.

#### `Get-WSAInventory`
Collects host-level hardware and OS metadata.

```powershell
Get-WSAInventory -ComputerName "FS-01"
```

Expected output (abbreviated):

```text
ComputerName : FS-01
OSVersion    : 10.0.17763
Roles        : {File-Services, DFS-Replication}
LastBoot     : 2024-02-12T03:31:45
BiosSerial   : 4CD1234XYZ
```

#### `Invoke-WSAPatching`
Stages and installs Windows Updates with optional maintenance-window validation.

```powershell
Invoke-WSAPatching -ComputerName "FS-01" -Schedule "Sundays 02:00" -WhatIf
```

Expected output (abbreviated):

```text
VERBOSE: Validated maintenance window "Sundays 02:00".
VERBOSE: Discovered 5 applicable updates.
VERBOSE: [WhatIf] Would download KB5034123 (Security Update).
```

#### `Invoke-WSAHardening`
Applies baseline security configurations and reports drifts.

```powershell
Invoke-WSAHardening -Baseline "CIS-Level1" -Remediate
```

Expected output (abbreviated):

```text
Baseline      : CIS-Level1
AppliedRules  : 37
SkippedRules  : 3 (requires manual validation)
Compliance    : 92%
```

#### `Get-WSAMonitoring`
Retrieves lightweight health telemetry such as service state and resource utilization.

```powershell
Get-WSAMonitoring -ComputerName "FS-01" -Counters "Processor(_Total)\% Processor Time","Memory\Available MBytes"
```

Expected output (abbreviated):

```text
Timestamp               Counter                                   Value
---------               -------                                   -----
2024-03-14T15:22:03Z    Processor(_Total)\\% Processor Time        23.7
2024-03-14T15:22:03Z    Memory\\Available MBytes                  6128
```

#### `Test-WSACompliance`
Evaluates compliance of a server fleet against defined policy files.

```powershell
Test-WSACompliance -ComputerName (Get-Content .\servers.txt) -PolicyPath .\Policies\core.json
```

Expected output (abbreviated):

```text
ComputerName Status  DriftCount
------------ ------  ----------
FS-01        Pass    0
DB-02        Fail    4
```

#### `Invoke-WSARemediation`
Triggers targeted remediation actions for failed compliance checks.

```powershell
Invoke-WSARemediation -InputObject (Test-WSACompliance -ComputerName "DB-02" -PolicyPath .\Policies\core.json)
```

Expected output (abbreviated):

```text
ComputerName : DB-02
Action       : Reset-NTFSPermissions
Result       : Success
Notes        : Remediation completed; re-run compliance scan.
```

## Roadmap
Planned enhancements for upcoming releases include:

1. **Desired State Configuration (DSC) export** – Generate DSC configurations from inventory snapshots.
2. **Role-specific baselines** – Extend hardening templates for SQL Server, IIS, and AD DS roles.
3. **Azure Arc integration** – Surface WinSysAuto jobs in centralized hybrid dashboards.
4. **Interactive dashboard** – Provide a cross-platform UI for monitoring and remediation pipelines.
5. **Plugin SDK** – Allow partners to deliver custom inventory collectors and remediations.

## Contribution Guidelines
We welcome community contributions. To get started:

1. Fork the repository and create a feature branch from `main`.
2. Adhere to PowerShell naming conventions and include comment-based help for new cmdlets.
3. Update documentation and examples when you change functionality.
4. Submit a pull request describing the motivation, solution, and testing evidence.
5. Respond to review feedback within 5 business days.

For substantial contributions, open an issue first to discuss design goals and alignment with the roadmap.

## Testing Instructions
WinSysAuto uses [Pester](https://pester.dev/) for unit and integration testing.

```powershell
# Install Pester if needed
Install-Module Pester -Scope CurrentUser -Force

# Run all module tests
Invoke-Pester -Path .\Tests -Output Detailed
```

Before submitting a pull request:

- Ensure `Invoke-Pester` reports zero failures.
- Validate that `install.ps1` completes without errors using `-WhatIf` and live execution.
- Test new functions on a Windows Server sandbox or virtual machine.

For additional QA steps, document environment details (OS version, PowerShell edition, remoting topology) in the PR description.
