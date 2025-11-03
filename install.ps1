param(
    [string]$DestinationRoot = "$env:ProgramFiles\WindowsPowerShell\Modules"
)

$moduleName = 'WinSysAuto'
$sourcePath = Split-Path -Parent $MyInvocation.MyCommand.Path
$destinationPath = Join-Path -Path $DestinationRoot -ChildPath $moduleName

if (-not (Test-Path -Path $DestinationRoot)) {
    New-Item -Path $DestinationRoot -ItemType Directory -Force | Out-Null
}

if (Test-Path -Path $destinationPath) {
    Remove-Item -Path $destinationPath -Recurse -Force
}

Copy-Item -Path $sourcePath -Destination $destinationPath -Recurse -Force

Write-Host "WinSysAuto installed to $destinationPath"
