<#
.SYNOPSIS
Monitors system health metrics and outputs detailed sample data.

.DESCRIPTION
Collects CPU, memory and disk utilisation data for each sample interval. The
function writes structured objects to the pipeline so that callers can review or
log the collected metrics. When a threshold is exceeded a warning is emitted in
addition to including the details in the Alerts property of the sample.

.PARAMETER CpuThreshold
Percentage of CPU usage that triggers a warning. Defaults to 90.

.PARAMETER SampleIntervalSeconds
Delay between samples in seconds. Defaults to 15 seconds.

.PARAMETER MaxSamples
Maximum number of samples to collect. A value of 0 collects indefinitely.

.EXAMPLE
Watch-Health -CpuThreshold 85 -SampleIntervalSeconds 10 -MaxSamples 3
Collects three samples and writes them to the pipeline while flagging any
threshold breaches.
#>
function Watch-Health {
    [CmdletBinding()]
    param(
        [ValidateRange(1, 100)]
        [int]$CpuThreshold = 90,

        [ValidateRange(1, 3600)]
        [int]$SampleIntervalSeconds = 15,

        [ValidateRange(0, 1000)]
        [int]$MaxSamples = 0
    )

    $samplesTaken = 0

    while ($true) {
        if ($MaxSamples -gt 0 -and $samplesTaken -ge $MaxSamples) {
            break
        }

        $samplesTaken++
        $alerts = @()
        $timestamp = Get-Date

        $cpuUsage = $null
        try {
            $cpuCounter = Get-Counter -Counter '\\Processor(_Total)\\% Processor Time' -ErrorAction Stop
            if ($cpuCounter.CounterSamples.Count -gt 0) {
                $cpuUsage = [math]::Round($cpuCounter.CounterSamples[0].CookedValue, 2)
            }
        }
        catch {
            $alerts += 'Unable to read CPU usage counters.'
        }

        $memoryPercentUsed = $null
        $memoryAvailableMB = $null
        try {
            $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop
            if ($osInfo) {
                $totalMemoryKB = [double]$osInfo.TotalVisibleMemorySize
                $freeMemoryKB = [double]$osInfo.FreePhysicalMemory
                if ($totalMemoryKB -gt 0) {
                    $usedMemoryKB = $totalMemoryKB - $freeMemoryKB
                    $memoryPercentUsed = [math]::Round(($usedMemoryKB / $totalMemoryKB) * 100, 2)
                    $memoryAvailableMB = [math]::Round($freeMemoryKB / 1024, 2)
                }
            }
        }
        catch {
            $alerts += 'Unable to read memory statistics.'
        }

        $diskUsage = @()
        try {
            $logicalDisks = Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction Stop
            foreach ($disk in $logicalDisks) {
                if (-not $disk.Size) {
                    continue
                }

                $sizeGB = [math]::Round(([double]$disk.Size) / 1GB, 2)
                $freeGB = [math]::Round(([double]$disk.FreeSpace) / 1GB, 2)
                $percentFree = if ($disk.Size -gt 0) {
                    [math]::Round((([double]$disk.FreeSpace) / [double]$disk.Size) * 100, 2)
                } else { $null }
                $percentUsed = if ($percentFree -ne $null) { [math]::Round(100 - $percentFree, 2) } else { $null }

                $diskUsage += [pscustomobject]@{
                    Drive        = $disk.DeviceID
                    SizeGB       = $sizeGB
                    FreeGB       = $freeGB
                    PercentFree  = $percentFree
                    PercentUsed  = $percentUsed
                }
            }
        }
        catch {
            $alerts += 'Unable to read disk statistics.'
        }

        if ($cpuUsage -ne $null -and $cpuUsage -ge $CpuThreshold) {
            $alerts += "CPU usage ${cpuUsage}% exceeds threshold ${CpuThreshold}%."
        }

        $healthState = if ($alerts.Count -eq 0) { 'Healthy' } else { 'Attention' }

        $sample = [pscustomobject]@{
            Timestamp          = $timestamp
            CpuPercent         = $cpuUsage
            CpuThreshold       = $CpuThreshold
            MemoryPercentUsed  = $memoryPercentUsed
            MemoryAvailableMB  = $memoryAvailableMB
            DiskUsage          = $diskUsage
            Alerts             = $alerts
            HealthState        = $healthState
        }

        Write-Output $sample

        foreach ($alert in $alerts) {
            Write-Warning $alert
        }

        if ($MaxSamples -gt 0 -and $samplesTaken -ge $MaxSamples) {
            break
        }

        Start-Sleep -Seconds $SampleIntervalSeconds
    }
}
