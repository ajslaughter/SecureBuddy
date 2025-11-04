function Get-WsaHealth {
    <#
    .SYNOPSIS
        Collects an operational health summary for core lab services.

    .DESCRIPTION
        Gathers inventory for Active Directory, DNS, DHCP, Group Policy, file shares,
        disk utilisation, and recent warning/error events. The function exports a
        Summary.txt and supporting CSV files to C:\LabReports\Daily-<timestamp> and
        returns a structured object describing the results. Safe to run repeatedly.

    .EXAMPLE
        Get-WsaHealth -Verbose

        Runs the health check, writes verbose details, and exports the reports.

    .OUTPUTS
        PSCustomObject
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param()

    $component = 'Get-WsaHealth'
    Write-WsaLog -Component $component -Message 'Starting health inventory.'

    $changes  = New-Object System.Collections.Generic.List[object]
    $findings = New-Object System.Collections.Generic.List[object]

    if (-not $PSCmdlet.ShouldProcess('lab.local environment', 'Collect health data')) {
        Write-WsaLog -Component $component -Message 'WhatIf specified - skipping health run.' -Level 'WARN'
        $findings.Add('WhatIf: Health check was not executed.') | Out-Null
        return New-WsaResult -Status 'Compliant' -Findings $findings.ToArray()
    }

    $timestamp = Get-Date -Format 'yyyyMMdd-HHmmss'
    $exportRoot = "C:\LabReports\Daily-$timestamp"

    try {
        if (-not (Test-Path -Path $exportRoot)) {
            New-Item -Path $exportRoot -ItemType Directory -Force | Out-Null
            $changes.Add("Created report directory $exportRoot") | Out-Null
        }
    }
    catch {
        $message = "Failed to prepare export directory: $($_.Exception.Message)"
        Write-WsaLog -Component $component -Message $message -Level 'ERROR'
        throw $message
    }

    $summaryLines = New-Object System.Collections.Generic.List[string]

    # Active Directory
    if (Get-Command -Name Get-ADDomain -ErrorAction SilentlyContinue) {
        try {
            $adDomain = Get-ADDomain -ErrorAction Stop
            $adForest = Get-ADForest -ErrorAction Stop
            $summaryLines.Add("Active Directory Domain: $($adDomain.DNSRoot) (Mode: $($adDomain.DomainMode))") | Out-Null
            $summaryLines.Add("Forest Mode: $($adForest.ForestMode); GC: $($adForest.GlobalCatalogs -join ', ')") | Out-Null
            $domainCsv = Join-Path -Path $exportRoot -ChildPath 'ActiveDirectory.csv'
            $adDomain | Select-Object Name, DNSRoot, DomainMode, InfrastructureMaster, RIDMaster, PDCEmulator |
                Export-Csv -Path $domainCsv -NoTypeInformation
        }
        catch {
            $msg = "Unable to query Active Directory: $($_.Exception.Message)"
            Write-WsaLog -Component $component -Message $msg -Level 'ERROR'
            $findings.Add($msg) | Out-Null
        }
    }
    else {
        $findings.Add('ActiveDirectory module unavailable - skipping AD inventory.') | Out-Null
    }

    # DNS Forwarders
    if (Get-Command -Name Get-DnsServerForwarder -ErrorAction SilentlyContinue) {
        try {
            $dnsForwarders = Get-DnsServerForwarder -ErrorAction Stop
            $summaryLines.Add('DNS Forwarders: ' + ($dnsForwarders.IPAddress.IPAddressToString -join ', ')) | Out-Null
            $dnsCsv = Join-Path -Path $exportRoot -ChildPath 'DnsForwarders.csv'
            $dnsForwarders | Select-Object IPAddress, TimeOut, Retries | Export-Csv -Path $dnsCsv -NoTypeInformation
        }
        catch {
            $msg = "Unable to query DNS forwarders: $($_.Exception.Message)"
            Write-WsaLog -Component $component -Message $msg -Level 'ERROR'
            $findings.Add($msg) | Out-Null
        }
    }
    else {
        $findings.Add('DnsServer module unavailable - skipping DNS inventory.') | Out-Null
    }

    # DHCP scope
    if (Get-Command -Name Get-DhcpServerv4Scope -ErrorAction SilentlyContinue) {
        try {
            $dhcpScopes = Get-DhcpServerv4Scope -ErrorAction Stop
            $summaryLines.Add("DHCP Scopes: $($dhcpScopes.Count)") | Out-Null
            $dhcpCsv = Join-Path -Path $exportRoot -ChildPath 'DhcpScopes.csv'
            $dhcpScopes | Select-Object ScopeId, Name, StartRange, EndRange, State | Export-Csv -Path $dhcpCsv -NoTypeInformation
        }
        catch {
            $msg = "Unable to query DHCP scopes: $($_.Exception.Message)"
            Write-WsaLog -Component $component -Message $msg -Level 'ERROR'
            $findings.Add($msg) | Out-Null
        }
    }
    else {
        $findings.Add('DhcpServer module unavailable - skipping DHCP inventory.') | Out-Null
    }

    # Group Policy
    if (Get-Command -Name Get-GPO -ErrorAction SilentlyContinue) {
        try {
            $gpos = Get-GPO -All -ErrorAction Stop
            $summaryLines.Add("GPO Count: $($gpos.Count)") | Out-Null
            $gpoCsv = Join-Path -Path $exportRoot -ChildPath 'GroupPolicy.csv'
            $gpos | Select-Object DisplayName, Id, CreationTime, ModificationTime | Export-Csv -Path $gpoCsv -NoTypeInformation
        }
        catch {
            $msg = "Unable to query Group Policy: $($_.Exception.Message)"
            Write-WsaLog -Component $component -Message $msg -Level 'ERROR'
            $findings.Add($msg) | Out-Null
        }
    }
    else {
        $findings.Add('GroupPolicy module unavailable - skipping GPO inventory.') | Out-Null
    }

    # Shares and disks
    if (Get-Command -Name Get-SmbShare -ErrorAction SilentlyContinue) {
        try {
            $shares = Get-SmbShare -Special $false -ErrorAction Stop
            $shareCsv = Join-Path -Path $exportRoot -ChildPath 'FileShares.csv'
            $shares | Select-Object Name, Path, Description, FolderEnumerationMode | Export-Csv -Path $shareCsv -NoTypeInformation
            $summaryLines.Add("File Shares: $($shares.Count)") | Out-Null
        }
        catch {
            $msg = "Unable to query SMB shares: $($_.Exception.Message)"
            Write-WsaLog -Component $component -Message $msg -Level 'ERROR'
            $findings.Add($msg) | Out-Null
        }
    }
    else {
        $findings.Add('SMBShare cmdlets unavailable - skipping share inventory.') | Out-Null
    }

    try {
        $drives = Get-PSDrive -PSProvider FileSystem
        $driveCsv = Join-Path -Path $exportRoot -ChildPath 'DiskUsage.csv'
        $drives | Select-Object Name, Root, Used, Free, @{Name='FreePercent';Expression={[math]::Round(($_.Free/($_.Used + $_.Free))*100,2)}} |
            Export-Csv -Path $driveCsv -NoTypeInformation
        $summaryLines.Add('Disk usage exported.') | Out-Null
    }
    catch {
        $msg = "Unable to query disk utilisation: $($_.Exception.Message)"
        Write-WsaLog -Component $component -Message $msg -Level 'ERROR'
        $findings.Add($msg) | Out-Null
    }

    # Event log warnings (last 24h)
    try {
        $events = Get-WinEvent -FilterHashtable @{LogName='System'; Level=2,3; StartTime=(Get-Date).AddHours(-24)} -ErrorAction Stop
        $eventCsv = Join-Path -Path $exportRoot -ChildPath 'SystemEvents.csv'
        $events | Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message |
            Export-Csv -Path $eventCsv -NoTypeInformation
        $summaryLines.Add("System warnings/errors (last 24h): $($events.Count)") | Out-Null
    }
    catch {
        $msg = "Unable to query event logs: $($_.Exception.Message)"
        Write-WsaLog -Component $component -Message $msg -Level 'WARN'
        $findings.Add($msg) | Out-Null
    }

    $summaryPath = Join-Path -Path $exportRoot -ChildPath 'Summary.txt'
    try {
        $summaryLines.Add("Export Folder: $exportRoot") | Out-Null
        $summaryLines.Add("Generated: $(Get-Date -Format 's')") | Out-Null
        $summaryLines | Out-File -FilePath $summaryPath -Encoding UTF8
    }
    catch {
        $msg = "Failed to write summary: $($_.Exception.Message)"
        Write-WsaLog -Component $component -Message $msg -Level 'ERROR'
        $findings.Add($msg) | Out-Null
    }

    $status = if ($findings.Count -eq 0) { 'Compliant' } else { 'Changed' }
    Write-WsaLog -Component $component -Message "Health inventory complete with status $status."

    return New-WsaResult -Status $status -Changes $changes.ToArray() -Findings $findings.ToArray() -Data @{ ExportPath = $exportRoot; Summary = $summaryPath }
}
