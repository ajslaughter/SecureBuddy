[CmdletBinding()]
param()

$moduleSource = $PSScriptRoot
$moduleName = 'WinSysAuto'
$targetRoot = Join-Path -Path $env:USERPROFILE -ChildPath 'Documents\WindowsPowerShell\Modules'
$targetPath = Join-Path -Path $targetRoot -ChildPath $moduleName

Write-Host "Installing $moduleName to $targetPath" -ForegroundColor Cyan
New-Item -Path $targetPath -ItemType Directory -Force | Out-Null
Copy-Item -Path (Join-Path $moduleSource '*') -Destination $targetPath -Recurse -Force

Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -Force

Import-Module (Join-Path $targetPath 'WinSysAuto.psd1') -Force
Get-Command -Module WinSysAuto
