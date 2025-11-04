Import-Module WinSysAuto -Force

$result = Get-WsaHealth -Verbose
Write-Host "Health report exported to: $($result.Data.ExportPath)" -ForegroundColor Cyan
Start-Process explorer.exe $result.Data.ExportPath
