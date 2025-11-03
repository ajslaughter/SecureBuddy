Import-Module (Join-Path -Path $PSScriptRoot -ChildPath '..\WinSysAuto.psd1') -Force

Describe 'Get-SecurityBaseline' {
    BeforeAll {
        $script:TestModuleRoot = Join-Path -Path $TestDrive -ChildPath 'Module'
        $script:BaselineDirectory = Join-Path -Path $script:TestModuleRoot -ChildPath 'baselines'
        New-Item -ItemType Directory -Path $script:BaselineDirectory -Force | Out-Null

        $baselineContent = @'
{
  "Name": "Sample Security Baseline",
  "Version": "1.0",
  "Firewall": {
    "Domain": {
      "Enabled": true
    }
  },
  "RemoteDesktop": {
    "Enable": false
  }
}
'@
        Set-Content -Path (Join-Path -Path $script:BaselineDirectory -ChildPath 'SampleBaseline.json') -Value $baselineContent -Encoding UTF8
        Set-Content -Path (Join-Path -Path $script:BaselineDirectory -ChildPath 'CurrentBaseline.txt') -Value 'Sample Security Baseline' -Encoding UTF8
    }

    AfterAll {
        Remove-Item -Path $script:TestModuleRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'lists available baselines' {
        $result = InModuleScope WinSysAuto {
            param($moduleRoot)
            $original = $script:ModuleRoot
            $script:ModuleRoot = $moduleRoot
            try {
                Get-SecurityBaseline -ListAvailable
            }
            finally {
                $script:ModuleRoot = $original
            }
        } -ArgumentList $script:TestModuleRoot

        $result | Should -Not -BeNullOrEmpty
        $result[0].Name | Should -Be 'Sample Security Baseline'
    }

    It 'returns the current baseline when no name is provided' {
        $result = InModuleScope WinSysAuto {
            param($moduleRoot)
            $original = $script:ModuleRoot
            $script:ModuleRoot = $moduleRoot
            try {
                Get-SecurityBaseline
            }
            finally {
                $script:ModuleRoot = $original
            }
        } -ArgumentList $script:TestModuleRoot

        $result.Name | Should -Be 'Sample Security Baseline'
        $result.IsCurrent | Should -BeTrue
        $result.Settings.Firewall.Domain.Enabled | Should -BeTrue
    }
}
