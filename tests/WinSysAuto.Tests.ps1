$moduleManifest = Join-Path -Path $PSScriptRoot -ChildPath '..\WinSysAuto.psd1'
Import-Module $moduleManifest -Force

$expectedFunctions = @(
    'Get-WsaHealth',
    'Ensure-WsaDnsForwarders',
    'Ensure-WsaDhcpScope',
    'Ensure-WsaOuModel',
    'New-WsaUsersFromCsv',
    'Ensure-WsaDeptShares',
    'Ensure-WsaDriveMappings',
    'Invoke-WsaSecurityBaseline',
    'Start-WsaDailyReport',
    'Backup-WsaConfig'
)

Describe 'WinSysAuto module' {
    It 'exports the expected public functions' {
        $commands = Get-Command -Module WinSysAuto | Select-Object -ExpandProperty Name
        $commands | Should -ContainExactly $expectedFunctions
    }

    It 'supports ShouldProcess on all public functions' {
        foreach ($name in $expectedFunctions) {
            $cmd = Get-Command -Name $name
            $cmd | Should -Not -BeNullOrEmpty
            $cmd.CommandType | Should -Be 'Function'
            $cmd.ScriptBlock.Attributes.SupportsShouldProcess | Should -BeTrue
        }
    }

    It 'returns a structured object from Get-WsaHealth with -WhatIf' {
        $result = Get-WsaHealth -WhatIf
        $result | Should -Not -BeNullOrEmpty
        $result | Should -BeOfType 'System.Management.Automation.PSCustomObject'
        $result.PSObject.Properties.Name | Should -Contain 'Status'
        $result.PSObject.Properties.Name | Should -Contain 'Findings'
    }
}
