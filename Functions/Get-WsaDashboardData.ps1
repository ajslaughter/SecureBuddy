function Get-WsaDashboardData {
    <#
    .SYNOPSIS
        Collects current system metrics for the live dashboard in JSON format.

    .DESCRIPTION
        Fast-executing function that gathers CPU, memory, disk, service, and security metrics
        using the M3 health monitoring functions. Returns data formatted for the live dashboard.

    .PARAMETER TestMode
        Use test/mock data instead of live system metrics.

    .EXAMPLE
        Get-WsaDashboardData
        Returns live system metrics as a PowerShell object.

    .EXAMPLE
        Get-WsaDashboardData | ConvertTo-Json
        Returns live system metrics as JSON.

    .NOTES
        Designed to execute in under 2 seconds for real-time dashboard updates.
    #>
    [CmdletBinding()]
    param(
        [switch]$TestMode
    )

    $moduleRoot = Split-Path -Parent $PSScriptRoot
    $configPath = Join-Path -Path $moduleRoot -ChildPath 'M3_automation_monitoring/config/default_config.yaml'

    # Load configuration if available, otherwise use defaults
    $config = $null
    if (Test-Path -Path $configPath) {
        try {
            $config = Get-WsaM3Configuration -Path $configPath -ResourceRoot (Join-Path -Path $moduleRoot -ChildPath 'M3_automation_monitoring')
        }
        catch {
            Write-WsaLog -Component 'M4' -Message "Failed to load M3 config: $($_.Exception.Message)" -Level 'WARN'
        }
    }

    # Use default config if loading failed
    if (-not $config) {
        $config = @{
            thresholds = @{
                cpu = @{ warning = 70; critical = 90 }
                memory = @{ warning = 75; critical = 90 }
                disk = @{ warning = 80; critical = 95 }
                failed_logons = @{ warning = 10; critical = 25 }
            }
            services = @{
                critical = @('LanmanServer', 'LanmanWorkstation', 'Dhcp', 'DNS', 'EventLog')
                monitor_windows_update = $true
                monitor_windows_defender = $true
                monitor_pending_reboot = $true
                monitor_firewall = $true
            }
        }
    }

    # Collect metrics
    $metrics = Get-WsaM3SystemMetrics -TestMode:$TestMode
    $services = Get-WsaM3ServiceHealth -Config $config -TestMode:$TestMode
    $events = Get-WsaM3EventSummary -Config $config -TestMode:$TestMode

    # Calculate health score
    $analysis = Test-WsaM3Thresholds -Metrics $metrics -Services $services -Events $events -Config $config

    # Format disk data for dashboard
    $diskData = @()
    foreach ($disk in $metrics.DiskUsage) {
        $diskData += @{
            name = $disk.Name
            totalGB = $disk.TotalGB
            usedGB = $disk.UsedGB
            freeGB = $disk.FreeGB
            usagePercent = $disk.UsagePercent
        }
    }

    # Format service data for dashboard
    $serviceData = @()
    foreach ($svc in $services.Services) {
        $status = 'healthy'
        if ($svc.Status -ne 'Running') {
            $status = 'critical'
        }
        $serviceData += @{
            name = $svc.Name
            status = $svc.Status
            startType = $svc.StartType
            health = $status
        }
    }

    # Determine overall health status
    $healthStatus = 'healthy'
    if ($analysis.HealthScore -lt 70) {
        $healthStatus = 'critical'
    }
    elseif ($analysis.HealthScore -lt 90) {
        $healthStatus = 'warning'
    }

    # Build response object
    $data = [ordered]@{
        timestamp = (Get-Date -Format 'yyyy-MM-ddTHH:mm:ss')
        healthScore = $analysis.HealthScore
        healthStatus = $healthStatus
        cpu = @{
            total = $metrics.CpuTotal
            perCore = $metrics.CpuPerCore
        }
        memory = @{
            percent = $metrics.MemoryPercent
            usedGB = $metrics.MemoryUsedGB
            totalGB = $metrics.MemoryTotalGB
        }
        disk = $diskData
        services = $serviceData
        events = @{
            failedLogons = if ($events.FailedLogons -ge 0) { $events.FailedLogons } else { 0 }
            systemErrors = if ($events.Summary) { ($events.Summary | Where-Object { $_.Log -eq 'System' }).Errors } else { 0 }
            applicationErrors = if ($events.Summary) { ($events.Summary | Where-Object { $_.Log -eq 'Application' }).Errors } else { 0 }
        }
        system = @{
            uptimeDays = $metrics.UptimeDays
            processCount = $metrics.ProcessCount
            pendingReboot = $services.PendingReboot
            firewall = $services.Firewall
        }
        alerts = @($analysis.Alerts | ForEach-Object {
            @{
                metric = $_.Metric
                level = $_.Level
                message = $_.Message
            }
        })
    }

    return [pscustomobject]$data
}
