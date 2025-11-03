Import-Module (Join-Path -Path $PSScriptRoot -ChildPath '..\WinSysAuto.psd1') -Force

Describe 'Watch-Health' {
    BeforeEach {
        Mock -CommandName Get-Counter -MockWith {
            [pscustomobject]@{
                CounterSamples = @([pscustomobject]@{ CookedValue = 95 })
            }
        }
        Mock -CommandName Get-CimInstance -ParameterFilter { $ClassName -eq 'Win32_OperatingSystem' } -MockWith {
            [pscustomobject]@{
                TotalVisibleMemorySize = 4096000
                FreePhysicalMemory     = 1024000
            }
        }
        Mock -CommandName Get-CimInstance -ParameterFilter { $ClassName -eq 'Win32_LogicalDisk' -and $Filter -eq 'DriveType=3' } -MockWith {
            @(
                [pscustomobject]@{ DeviceID = 'C:'; Size = 100GB; FreeSpace = 40GB }
            )
        }
        Mock -CommandName Start-Sleep
        Mock -CommandName Write-Warning
    }

    It 'emits structured samples and warnings when thresholds are exceeded' {
        $result = @(Watch-Health -CpuThreshold 90 -SampleIntervalSeconds 1 -MaxSamples 1)

        $result | Should -HaveCount 1
        $sample = $result[0]
        $sample.CpuPercent | Should -Be 95
        $sample.HealthState | Should -Be 'Attention'
        $sample.Alerts | Should -Contain 'CPU usage 95% exceeds threshold 90%.'

        Assert-MockCalled -CommandName Write-Warning -Times 1 -Exactly
    }
}
