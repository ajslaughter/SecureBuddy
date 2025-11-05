<#
.SYNOPSIS
    Start the WinSysAuto M4 Live Health Dashboard.

.DESCRIPTION
    This script demonstrates how to launch the futuristic live health dashboard
    that displays real-time system metrics with a cyberpunk-style UI.

.EXAMPLE
    .\Start-Dashboard.ps1
    Starts the dashboard on the default port (8080).

.EXAMPLE
    .\Start-Dashboard.ps1 -Port 9090
    Starts the dashboard on port 9090.

.NOTES
    The dashboard will be available at http://localhost:8080 (or your specified port).
    Press Ctrl+C to stop the server.
    The dashboard auto-refreshes every 30 seconds.
#>

param(
    [Parameter()]
    [int]$Port = 8080,

    [Parameter()]
    [switch]$TestMode
)

# Import the WinSysAuto module
$moduleRoot = Split-Path -Parent $PSScriptRoot
Import-Module (Join-Path -Path $moduleRoot -ChildPath 'WinSysAuto.psd1') -Force

Write-Host @"

╔════════════════════════════════════════════════════════════════╗
║                                                                ║
║   ◢ WinSysAuto M4 Live Health Dashboard ◣                     ║
║                                                                ║
║   Futuristic real-time system monitoring with                 ║
║   cyberpunk-style visualization                               ║
║                                                                ║
╚════════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan

Write-Host "Starting dashboard server on port $Port..." -ForegroundColor Yellow
Write-Host ""
Write-Host "Once started, navigate to: " -NoNewline
Write-Host "http://localhost:$Port" -ForegroundColor Green
Write-Host ""
Write-Host "Features:" -ForegroundColor Cyan
Write-Host "  • Real-time health score with pulsing glow animation" -ForegroundColor White
Write-Host "  • CPU, Memory, and Disk metrics with animated progress bars" -ForegroundColor White
Write-Host "  • Service status monitoring with color-coded indicators" -ForegroundColor White
Write-Host "  • Security event tracking (failed logons, errors)" -ForegroundColor White
Write-Host "  • Auto-refresh every 30 seconds" -ForegroundColor White
Write-Host "  • Futuristic cyberpunk UI with neon accents" -ForegroundColor White
Write-Host ""
Write-Host "Press Ctrl+C to stop the server" -ForegroundColor Yellow
Write-Host ""

# Start the dashboard
Start-WsaDashboard -Port $Port -TestMode:$TestMode
