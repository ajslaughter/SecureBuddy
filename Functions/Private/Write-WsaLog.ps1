function Write-WsaLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$Component,

        [Parameter(Mandatory)]
        [string]$Message,

        [ValidateSet('INFO','WARN','ERROR','DEBUG')]
        [string]$Level = 'INFO'
    )

    try {
        $logRoot = 'C:\LabReports\WinSysAuto'
        if (-not (Test-Path -Path $logRoot)) {
            New-Item -Path $logRoot -ItemType Directory -Force | Out-Null
        }

        $dateStamp = Get-Date -Format 'yyyyMMdd'
        $logFile = Join-Path -Path $logRoot -ChildPath ("WinSysAuto-{0}.log" -f $dateStamp)
        $entry = [pscustomobject]@{
            Timestamp = (Get-Date).ToString('s')
            Level     = $Level
            Component = $Component
            Message   = $Message
        }

        $json = $entry | ConvertTo-Json -Depth 3 -Compress
        Add-Content -Path $logFile -Value $json
        Write-Verbose -Message ("[{0}] {1}: {2}" -f $Level, $Component, $Message)
    }
    catch {
        Write-Verbose -Message ("[WARN] {0}: Failed to write log entry. {1}" -f $Component, $_.Exception.Message)
    }
}
