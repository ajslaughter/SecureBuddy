# WinSysAuto

WinSysAuto is a PowerShell 5.1 module that standardises common Windows Server
automation tasks—inventory collection, patch visibility, security hardening and
health monitoring—from a single toolchain. The module is designed for Windows
Server 2022 Core systems running in Constrained Language Mode and ships without
external dependencies.

## Requirements

- Windows Server 2016, 2019 or 2022 (tested on Windows Server 2022 Core)
- PowerShell 5.1 running in Constrained Language Mode
- Local administrator privileges for remediation tasks
- Windows Defender feature installed (for Defender preference adjustments)

## Installation

Use the provided installer to place the module in a module path that works
without Internet access:

```powershell
# From the repository root
.\install.ps1 -Scope CurrentUser -Verbose
```

The installer copies the WinSysAuto folder into
`$env:USERPROFILE\Documents\WindowsPowerShell\Modules\WinSysAuto`. To install for
all users run `.\install.ps1 -Scope AllUsers` from an elevated session.

To manually import during development:

```powershell
Import-Module (Join-Path -Path $PSScriptRoot -ChildPath 'WinSysAuto.psd1') -Force
```

## Baseline management

Security baselines live in the `baselines/` directory as JSON files. Use
`Get-SecurityBaseline` to inspect available definitions and `Set-SecurityBaseline`
to apply them.

```powershell
# List available baselines
Get-SecurityBaseline -ListAvailable

# Review the contents of the sample baseline
Get-SecurityBaseline -BaselineName 'SampleBaseline'

# Apply the sample baseline
Set-SecurityBaseline -Baseline 'SampleBaseline' -Verbose
```

`Set-SecurityBaseline` honours `-WhatIf`/`-Confirm` semantics and returns a rich
object that summarises how each settings area was handled. The function reads the
baseline JSON file, applies firewall, Remote Desktop, password policy and
Microsoft Defender settings, then records the applied baseline in
`baselines/CurrentBaseline.(txt|json)`.

### Baseline schema

The bundled `SampleBaseline.json` uses the following structure:

- `Name` / `Version` *(optional)* – Metadata used for reporting.
- `Firewall` – Optional `Domain`, `Private` and `Public` profile entries. Each
  profile can specify `Enabled`, `DefaultInboundAction`, and
  `DefaultOutboundAction` values accepted by `Set-NetFirewallProfile`.
- `RemoteDesktop` – Controls Terminal Services registry keys.
  - `Enable` *(bool)* – Enables or disables Remote Desktop.
  - `AllowOnlySecureConnections` *(bool)* – Enforces Network Level Authentication
    when set to `true`.
- `PasswordPolicy` – Maps to `secedit.exe` "System Access" entries.
  - `MinimumPasswordLength`, `MaximumPasswordAgeDays`,
    `MinimumPasswordAgeDays`, `PasswordHistorySize` *(int)*.
  - `ComplexityEnabled` *(bool)* – Enables password complexity enforcement.
  - `LockoutThreshold`, `LockoutDurationMinutes`,
    `ResetLockoutCounterMinutes` *(int)*.
- `Defender` – Maps to `Set-MpPreference` parameters.
  - `RealTimeMonitoring` *(bool)* – Keeps real-time protection enabled when true.
  - `CloudProtection` *(string)* – One of `Disabled`, `Basic`, or `Advanced`.
  - `SampleSubmission` *(string)* – One of `SafeSamples`, `AllSamples`, or
    `NeverSend`.
  - `SignatureUpdateIntervalHours` *(int)* – Schedules definition update checks.

## Exported functions

The module exports the following public functions:

### `Get-Inventory`
Collects OS, hardware, memory, network and patch information from the local
machine and returns a structured object ready for reporting.

```powershell
Get-Inventory | Format-List
```

### `Invoke-PatchScan`
Performs a scan for applicable Windows Updates using the Windows Update APIs.
The function reports available updates and respects the Windows Update service
state.

```powershell
Invoke-PatchScan -Verbose
```

### `Get-SecurityBaseline`
Parses JSON baseline definitions from the `baselines/` folder and returns the
requested baseline, along with metadata about available baselines and the
currently recorded baseline.

```powershell
Get-SecurityBaseline -BaselineName 'SampleBaseline'
```

### `Set-SecurityBaseline`
Applies the requested baseline using the schema described earlier. Returns a
summary object detailing the outcome for each category of settings.

```powershell
Set-SecurityBaseline -Baseline 'SampleBaseline' -WhatIf
```

### `Watch-Health`
Samples CPU, memory and disk usage, emitting detailed objects for each sample
interval. Use `-MaxSamples` to collect a finite set of samples.

```powershell
Watch-Health -CpuThreshold 85 -SampleIntervalSeconds 10 -MaxSamples 3
```

### `Export-InventoryReport`
Generates an HTML report of the inventory data collected by `Get-Inventory`.
Specify `-OutputDirectory` to control where the HTML file is written.

```powershell
Get-Inventory | Export-InventoryReport -OutputDirectory C:\Reports
```

## Testing

WinSysAuto ships with Pester tests. Run them from the repository root with:

```powershell
pwsh -NoLogo -NoProfile -File .\WinSysAuto\WinSysAuto.Tests.ps1
```

If `PSScriptAnalyzer` is available in your environment you can lint the module:

```powershell
pwsh -NoLogo -NoProfile -Command "Invoke-ScriptAnalyzer -Path .\WinSysAuto -Recurse"
```

Both commands run without requiring Internet access.
