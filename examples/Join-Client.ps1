# Requires: Run on client workstation prior to domain join
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
param(
    [Parameter(Mandatory)]
    [string]$ComputerName,

    [Parameter(Mandatory)]
    [pscredential]$Credential
)

$dnsServer = '192.168.200.10'
Write-Verbose "Setting DNS server to $dnsServer"
Set-DnsClientServerAddress -InterfaceAlias 'Ethernet' -ServerAddresses $dnsServer

if ($PSCmdlet.ShouldProcess($ComputerName, 'Join domain lab.local', 'Join domain')) {
    Add-Computer -DomainName 'lab.local' -Credential $Credential -NewName $ComputerName -Restart
}
