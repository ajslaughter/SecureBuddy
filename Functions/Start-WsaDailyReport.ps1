function Start-WsaDailyReport {
    <#
    .SYNOPSIS
        Registers the WsaDailyReport scheduled task to capture daily health data.

    .DESCRIPTION
        Creates a scheduled task running as SYSTEM that imports the WinSysAuto module,
        executes Get-WsaHealth at 08:00 daily, and prunes report folders beyond 14 copies.

    .EXAMPLE
        Start-WsaDailyReport -Verbose

        Registers or updates the scheduled task.

    .OUTPUTS
        PSCustomObject
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param()

    $component = 'Start-WsaDailyReport'
    Write-WsaLog -Component $component -Message 'Configuring scheduled task for daily report.'

    if (-not (Get-Command -Name Register-ScheduledTask -ErrorAction SilentlyContinue)) {
        $message = 'ScheduledTasks module not available on this system.'
        Write-WsaLog -Component $component -Message $message -Level 'ERROR'
        throw $message
    }

    $taskName = 'WsaDailyReport'
    $script = "Import-Module WinSysAuto -Force; Get-WsaHealth | Out-Null; \$folders = Get-ChildItem -Path 'C:\\LabReports' -Directory -Filter 'Daily-*' | Sort-Object CreationTime -Descending; if (\$folders.Count -gt 14) { \$folders[14..(\$folders.Count-1)] | Remove-Item -Recurse -Force }"
    $action = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument "-NoProfile -WindowStyle Hidden -Command \"$script\""
    $trigger = New-ScheduledTaskTrigger -Daily -At 08:00
    $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest

    $changes  = New-Object System.Collections.Generic.List[object]
    $findings = New-Object System.Collections.Generic.List[object]

    try {
        $existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    }
    catch {
        $existing = $null
    }

    if ($PSCmdlet.ShouldProcess($taskName, 'Register or update scheduled task', 'Register scheduled task')) {
        try {
            Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -Principal $principal -Settings (New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 60) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries) -Force -ErrorAction Stop | Out-Null
            if ($existing) {
                $changes.Add('Updated existing WsaDailyReport task.') | Out-Null
            }
            else {
                $changes.Add('Created WsaDailyReport scheduled task.') | Out-Null
            }
        }
        catch {
            $msg = "Failed to register scheduled task: $($_.Exception.Message)"
            Write-WsaLog -Component $component -Message $msg -Level 'ERROR'
            throw $msg
        }
    }
    else {
        $findings.Add('Registration skipped due to -WhatIf.') | Out-Null
    }

    $status = if ($changes.Count -gt 0) { 'Changed' } else { 'Compliant' }
    if ($findings.Count -gt 0 -and $status -ne 'Changed') { $status = 'Changed' }

    return New-WsaResult -Status $status -Changes $changes.ToArray() -Findings $findings.ToArray() -Data @{ TaskName = $taskName }
}
