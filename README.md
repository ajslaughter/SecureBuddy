# WinSysAuto

WinSysAuto is a reusable PowerShell 5.1+ automation module tailored for the lab.local
Windows Server 2022 environment. It focuses on idempotent configuration of core
infrastructure services—Active Directory, DNS, DHCP, file services, and security
hardening—while producing consistent reports and backups.

## Features
- Ten production-ready public functions (health reporting, configuration enforcement,
  provisioning, and backups)
- Structured logging to `C:\LabReports\WinSysAuto\WinSysAuto-<date>.log`
- Supports `-WhatIf` and `-Verbose` across the module
- Example recipes and security baseline JSON for quick adoption
- Pester tests for module loading and smoke validation

## Getting Started
```powershell
# From an elevated PowerShell session on DC01.lab.local
Set-Location C:\Tools\WinSysAuto
.\install.ps1
```

See [Docs/Usage.md](Docs/Usage.md) for command quickstarts and [Docs/LabOverview.md](Docs/LabOverview.md)
for environment assumptions.
