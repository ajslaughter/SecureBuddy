function Ensure-WsaDhcpScope {
    <#
    .SYNOPSIS
        Ensures the primary IPv4 DHCP scope exists and is configured correctly.

    .DESCRIPTION
        Verifies the 192.168.200.0/24 DHCP scope exists with the expected range and
        options. Creates or reconciles the scope as required, including router, DNS, and
        domain name options.

    .EXAMPLE
        Ensure-WsaDhcpScope -Verbose

        Confirms the DHCP scope is present and aligned with the baseline configuration.

    .OUTPUTS
        PSCustomObject
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param()

    $component = 'Ensure-WsaDhcpScope'
    Write-WsaLog -Component $component -Message 'Evaluating DHCP scope configuration.'

    if (-not (Get-Command -Name Get-DhcpServerv4Scope -ErrorAction SilentlyContinue)) {
        $message = 'DhcpServer module not available on this system.'
        Write-WsaLog -Component $component -Message $message -Level 'ERROR'
        throw $message
    }

    $scopeId = [ipaddress]'192.168.200.0'
    $startRange = [ipaddress]'192.168.200.21'
    $endRange = [ipaddress]'192.168.200.200'
    $router = '192.168.200.2'
    $dnsServer = '192.168.200.10'
    $dnsDomain = 'lab.local'

    $changes  = New-Object System.Collections.Generic.List[object]
    $findings = New-Object System.Collections.Generic.List[object]

    try {
        $scope = Get-DhcpServerv4Scope -ScopeId $scopeId -ErrorAction SilentlyContinue
    }
    catch {
        $message = "Failed to query DHCP scope: $($_.Exception.Message)"
        Write-WsaLog -Component $component -Message $message -Level 'ERROR'
        throw $message
    }

    if (-not $scope) {
        if ($PSCmdlet.ShouldProcess("DHCP scope $scopeId", 'Create scope', 'Create DHCP scope')) {
            try {
                Add-DhcpServerv4Scope -Name 'Lab Scope' -StartRange $startRange -EndRange $endRange -SubnetMask '255.255.255.0' -ScopeId $scopeId -ErrorAction Stop | Out-Null
                $changes.Add('Created DHCP scope Lab Scope (192.168.200.0/24).') | Out-Null
                Write-WsaLog -Component $component -Message 'Created Lab Scope DHCP scope.'
                $scope = Get-DhcpServerv4Scope -ScopeId $scopeId -ErrorAction Stop
            }
            catch {
                $msg = "Unable to create DHCP scope: $($_.Exception.Message)"
                Write-WsaLog -Component $component -Message $msg -Level 'ERROR'
                throw $msg
            }
        }
        else {
            $findings.Add('Scope missing but creation skipped due to -WhatIf.') | Out-Null
        }
    }
    else {
        Write-WsaLog -Component $component -Message 'DHCP scope already exists.'
    }

    if ($scope) {
        # Ensure range values
        if ($scope.StartRange -ne $startRange -or $scope.EndRange -ne $endRange) {
            if ($PSCmdlet.ShouldProcess("DHCP scope $scopeId", 'Update address range', 'Adjust DHCP scope range')) {
                try {
                    Set-DhcpServerv4Scope -ScopeId $scopeId -StartRange $startRange -EndRange $endRange -ErrorAction Stop
                    $changes.Add('Updated DHCP scope range to 192.168.200.21-192.168.200.200.') | Out-Null
                    Write-WsaLog -Component $component -Message 'Updated DHCP scope range.'
                }
                catch {
                    $msg = "Failed to update DHCP range: $($_.Exception.Message)"
                    Write-WsaLog -Component $component -Message $msg -Level 'ERROR'
                    $findings.Add($msg) | Out-Null
                }
            }
        }

        # Options
        try {
            $options = Get-DhcpServerv4OptionValue -ScopeId $scopeId -ErrorAction SilentlyContinue
        }
        catch {
            $msg = "Failed to read DHCP options: $($_.Exception.Message)"
            Write-WsaLog -Component $component -Message $msg -Level 'ERROR'
            $findings.Add($msg) | Out-Null
        }

        $needsRouter = -not $options -or -not ($options | Where-Object { $_.OptionId -eq 3 -and $_.Value -contains $router })
        $needsDnsServer = -not $options -or -not ($options | Where-Object { $_.OptionId -eq 6 -and $_.Value -contains $dnsServer })
        $needsDnsDomain = -not $options -or -not ($options | Where-Object { $_.OptionId -eq 15 -and $_.Value -contains $dnsDomain })

        if ($needsRouter -and $PSCmdlet.ShouldProcess("DHCP scope $scopeId", "Set router option $router", 'Configure DHCP option 3')) {
            try {
                Set-DhcpServerv4OptionValue -ScopeId $scopeId -Router $router -ErrorAction Stop
                $changes.Add("Set DHCP option 3 router to $router") | Out-Null
                Write-WsaLog -Component $component -Message "Set DHCP router option to $router."
            }
            catch {
                $msg = "Failed to set router option: $($_.Exception.Message)"
                Write-WsaLog -Component $component -Message $msg -Level 'ERROR'
                $findings.Add($msg) | Out-Null
            }
        }

        if ($needsDnsServer -and $PSCmdlet.ShouldProcess("DHCP scope $scopeId", "Set DNS server $dnsServer", 'Configure DHCP option 6')) {
            try {
                Set-DhcpServerv4OptionValue -ScopeId $scopeId -DnsServer $dnsServer -ErrorAction Stop
                $changes.Add("Set DHCP option 6 DNS server to $dnsServer") | Out-Null
                Write-WsaLog -Component $component -Message "Set DHCP DNS option to $dnsServer."
            }
            catch {
                $msg = "Failed to set DNS server option: $($_.Exception.Message)"
                Write-WsaLog -Component $component -Message $msg -Level 'ERROR'
                $findings.Add($msg) | Out-Null
            }
        }

        if ($needsDnsDomain -and $PSCmdlet.ShouldProcess("DHCP scope $scopeId", "Set domain name $dnsDomain", 'Configure DHCP option 15')) {
            try {
                Set-DhcpServerv4OptionValue -ScopeId $scopeId -DnsDomain $dnsDomain -ErrorAction Stop
                $changes.Add("Set DHCP option 15 domain to $dnsDomain") | Out-Null
                Write-WsaLog -Component $component -Message "Set DHCP domain option to $dnsDomain."
            }
            catch {
                $msg = "Failed to set DNS domain option: $($_.Exception.Message)"
                Write-WsaLog -Component $component -Message $msg -Level 'ERROR'
                $findings.Add($msg) | Out-Null
            }
        }
    }

    $status = if ($changes.Count -gt 0) { 'Changed' } else { 'Compliant' }
    if ($findings.Count -gt 0 -and $status -ne 'Changed') { $status = 'Changed' }

    return New-WsaResult -Status $status -Changes $changes.ToArray() -Findings $findings.ToArray() -Data @{ ScopeId = $scopeId.ToString() }
}
