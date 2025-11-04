Import-Module WinSysAuto -Force

Ensure-WsaDnsForwarders -Verbose
Ensure-WsaDhcpScope -Verbose
Ensure-WsaOuModel -ProtectFromAccidentalDeletion -Verbose
Invoke-WsaSecurityBaseline -WhatIf -Verbose
