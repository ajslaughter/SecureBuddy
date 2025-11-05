# WinSysAuto

WinSysAuto is a reusable PowerShell 5.1+ automation module tailored for the lab.local
Windows Server 2022 environment. It focuses on idempotent configuration of core
infrastructure services—Active Directory, DNS, DHCP, file services, and security
hardening—while producing consistent reports and backups.

## Features
- Ten production-ready public functions (health reporting, configuration enforcement,
  provisioning, and backups)
- **M4 Live Health Dashboard**: Futuristic, real-time web dashboard with cyberpunk-style UI
- **M3 Automated Health Monitoring**: Daily health reports with trending and email notifications
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

## M4 Live Health Dashboard

The M4 Live Health Dashboard provides real-time system monitoring with a stunning futuristic interface
inspired by cyberpunk aesthetics and sci-fi command centers.

### Features
- **Futuristic UI**: Cyberpunk-style design with neon accents, glowing borders, and animated effects
- **Real-time Monitoring**: Auto-refreshes every 30 seconds with smooth transitions
- **Health Score**: Large hexagonal health indicator with pulsing glow animation
- **System Metrics**: CPU, memory, and disk usage with gradient progress bars
- **Service Monitoring**: Color-coded service status with live indicators
- **Security Events**: Failed logon tracking and error monitoring
- **Responsive Design**: Works on desktop and mobile devices

### Quick Start
```powershell
# Start the dashboard on default port 8080
Start-WsaDashboard

# Start on a custom port
Start-WsaDashboard -Port 9090

# Use test data for demonstration
Start-WsaDashboard -TestMode
```

Then navigate to `http://localhost:8080` in your browser.

### Using the Example Script
```powershell
# From the WinSysAuto directory
.\examples\Start-Dashboard.ps1

# Or with a custom port
.\examples\Start-Dashboard.ps1 -Port 9090
```

### Visual Features
- **Dark cyberpunk theme** with animated grid background
- **Scan-line effect** for retro-futuristic feel
- **Hexagonal panels** with angular, non-rectangular design
- **Neon glow effects** on health score and borders (cyan, purple, pink)
- **Animated progress bars** with gradient fills and shimmer effects
- **Glass-morphism** with backdrop blur for modern depth
- **Color-coded status**: Green (healthy), Yellow (warning), Red (critical)
- **Hover animations** and smooth transitions throughout

### API Endpoint
The dashboard server also provides a JSON API endpoint for programmatic access:
```
GET http://localhost:8080/api/health
```

Returns JSON with current system metrics, health score, service status, and security events.

### Stopping the Server
Press `Ctrl+C` in the PowerShell window running the dashboard to stop the server.
