Import-Module (Join-Path -Path $PSScriptRoot -ChildPath '..\WinSysAuto.psd1') -Force

Describe 'Set-SecurityBaseline' {
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
      "Enabled": true,
      "DefaultInboundAction": "Block",
      "DefaultOutboundAction": "Allow"
    },
    "Private": {
      "Enabled": true
    },
    "Public": {
      "Enabled": false
    }
  },
  "RemoteDesktop": {
    "Enable": false,
    "AllowOnlySecureConnections": true
  },
  "PasswordPolicy": {
    "MinimumPasswordLength": 14,
    "MaximumPasswordAgeDays": 60,
    "MinimumPasswordAgeDays": 1,
    "PasswordHistorySize": 24,
    "ComplexityEnabled": true,
    "LockoutThreshold": 5,
    "LockoutDurationMinutes": 15,
    "ResetLockoutCounterMinutes": 15
  },
  "Defender": {
    "RealTimeMonitoring": true,
    "CloudProtection": "Advanced",
    "SampleSubmission": "SafeSamples",
    "SignatureUpdateIntervalHours": 4
  }
}
'@
        Set-Content -Path (Join-Path -Path $script:BaselineDirectory -ChildPath 'SampleBaseline.json') -Value $baselineContent -Encoding UTF8
    }

    AfterAll {
        Remove-Item -Path $script:TestModuleRoot -Recurse -Force -ErrorAction SilentlyContinue
    }

    It 'applies baseline configuration from JSON' {
        InModuleScope WinSysAuto {
            param($moduleRoot)
            $original = $script:ModuleRoot
            $script:ModuleRoot = $moduleRoot
            try {
                Mock -CommandName Get-Command -ParameterFilter { $Name -eq 'Set-NetFirewallProfile' } -MockWith {
                    [pscustomobject]@{ Name = 'Set-NetFirewallProfile' }
                }
                Mock -CommandName Get-Command -ParameterFilter { $Name -eq 'secedit.exe' } -MockWith {
                    [pscustomobject]@{ Source = 'secedit.exe'; Definition = 'secedit.exe'; Path = 'secedit.exe' }
                }
                Mock -CommandName Get-Command -ParameterFilter { $Name -eq 'Set-MpPreference' } -MockWith {
                    [pscustomobject]@{ Name = 'Set-MpPreference' }
                }

                Mock -CommandName Set-NetFirewallProfile
                Mock -CommandName Set-ItemProperty
                Mock -CommandName secedit.exe -MockWith {
                    param($configure, $dbLiteral, $dbPath, $cfgLiteral, $cfgPath, $areasLiteral, $areasValue)
                    Set-Variable -Name LASTEXITCODE -Scope Global -Value 0
                }
                Mock -CommandName Set-MpPreference

                $result = Set-SecurityBaseline -Baseline 'SampleBaseline' -Confirm:$false

                Assert-MockCalled -CommandName Set-NetFirewallProfile -Times 3
                Assert-MockCalled -CommandName Set-ItemProperty -Times 2
                Assert-MockCalled -CommandName secedit.exe -Times 1
                Assert-MockCalled -CommandName Set-MpPreference -Times 1

                $result.Success | Should -BeTrue
                $result.AppliedSettings.PasswordPolicy.Status | Should -Be 'Applied'
                $result.AppliedSettings.Defender.Status | Should -Be 'Applied'
            }
            finally {
                $script:ModuleRoot = $original
            }
        } -ArgumentList $script:TestModuleRoot
    }
}
