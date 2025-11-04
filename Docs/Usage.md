# Usage

Import the module and explore available commands:

```powershell
Import-Module WinSysAuto -Force
Get-Command -Module WinSysAuto
```

## Function Quickstart

### Get-WsaHealth
Collect a daily snapshot of the environment.
```powershell
Get-WsaHealth -Verbose
```

### Ensure-WsaDnsForwarders
Reconcile DNS forwarders (defaults to 1.1.1.1 and 8.8.8.8).
```powershell
Ensure-WsaDnsForwarders -Verbose
```

### Ensure-WsaDhcpScope
Validate the 192.168.200.0/24 scope.
```powershell
Ensure-WsaDhcpScope -WhatIf
```

### Ensure-WsaOuModel
Create or confirm the departmental OU tree.
```powershell
Ensure-WsaOuModel -ProtectFromAccidentalDeletion
```

### New-WsaUsersFromCsv
Provision users from structured CSV input.
```powershell
New-WsaUsersFromCsv -Path .\users.csv -AutoCreateGroups -ResetPasswordIfProvided
```

### Ensure-WsaDeptShares
Ensure folder structure and share permissions.
```powershell
Ensure-WsaDeptShares -SeparateShares
```

### Ensure-WsaDriveMappings
Deploy Group Policy Preferences for department drive mappings.
```powershell
Ensure-WsaDriveMappings
```

### Invoke-WsaSecurityBaseline
Apply or rollback the security baseline.
```powershell
Invoke-WsaSecurityBaseline
Invoke-WsaSecurityBaseline -Rollback
```

### Start-WsaDailyReport
Register the automated health reporting task.
```powershell
Start-WsaDailyReport
```

### Backup-WsaConfig
Archive configuration artefacts to C:\LabReports\Backups.
```powershell
Backup-WsaConfig -Verbose
```
