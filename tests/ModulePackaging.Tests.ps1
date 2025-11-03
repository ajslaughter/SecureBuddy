$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$moduleRoot = Split-Path -Parent $here
$manifestPath = Join-Path -Path $moduleRoot -ChildPath 'WinSysAuto.psd1'
$installScriptPath = Join-Path -Path $moduleRoot -ChildPath 'install.ps1'

Describe 'Module packaging' {
    It 'does not use dynamic expressions in the module manifest' {
        $manifestContent = Get-Content -Path $manifestPath -Raw
        $manifestContent | Should -Not -Match '\$\('
    }

    It 'installs into WindowsPowerShell module directories only' {
        $installContent = Get-Content -Path $installScriptPath -Raw
        $installContent | Should -Match "Documents\\\\WindowsPowerShell\\\\Modules"
        $installContent | Should -Match "WindowsPowerShell\\\\Modules"
    }

    It 'avoids PowerShell Gallery dependencies during installation' {
        $installContent = Get-Content -Path $installScriptPath -Raw
        $installContent | Should -Not -Match 'Install-Module'
        $installContent | Should -Not -Match 'Install-PackageProvider'
    }
}
