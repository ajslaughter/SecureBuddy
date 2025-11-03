<#
.SYNOPSIS
Retrieves security baseline definitions bundled with the module.

.DESCRIPTION
Reads JSON baseline definitions from the baselines directory and returns structured
information about the requested or current baseline. Provides details on the
currently applied baseline when tracking information exists and lists all available
baselines.

.PARAMETER BaselineName
Optional baseline file or display name to load. Matches against the JSON Name or
file name (without extension).

.PARAMETER ListAvailable
Switch to list available baselines without loading a specific definition.

.EXAMPLE
Get-SecurityBaseline -ListAvailable
Lists all baseline definitions shipped with the module.

.EXAMPLE
Get-SecurityBaseline -BaselineName 'SampleBaseline'
Returns the full baseline configuration for SampleBaseline.json.

.OUTPUTS
System.Object
Returns information about current and available baselines. When a baseline is
loaded the Settings property contains the parsed JSON definition.
#>
function Get-SecurityBaseline {
    [CmdletBinding(DefaultParameterSetName = 'Current')]
    param(
        [Parameter(ParameterSetName = 'ByName')]
        [string]$BaselineName,

        [Parameter(ParameterSetName = 'List')]
        [switch]$ListAvailable
    )

    $baselineDirectory = Join-Path -Path $script:ModuleRoot -ChildPath 'baselines'
    if (-not (Test-Path -LiteralPath $baselineDirectory)) {
        Write-Error "Baseline directory '$baselineDirectory' was not found."
        return
    }

    $baselineFiles = Get-ChildItem -Path $baselineDirectory -Filter '*.json' -File -ErrorAction SilentlyContinue |
        Sort-Object -Property Name

    if (-not $baselineFiles) {
        Write-Error "No baseline files were located in '$baselineDirectory'."
        return
    }

    $availableBaselines = foreach ($file in $baselineFiles) {
        $content = $null
        try {
            $content = Get-Content -Path $file.FullName -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            Write-Warning "Unable to parse baseline file '$($file.FullName)'. $_"
        }

        $displayName = if ($content -and $content.PSObject.Properties['Name']) {
            [string]$content.Name
        }
        else {
            [System.IO.Path]::GetFileNameWithoutExtension($file.Name)
        }

        [pscustomobject]@{
            Name        = $displayName
            Version     = if ($content -and $content.PSObject.Properties['Version']) { [string]$content.Version } else { $null }
            FileName    = $file.Name
            Path        = $file.FullName
            RawSettings = $content
        }
    }

    $currentBaselineName = $null
    $currentMarkerFiles = @(
        Join-Path -Path $baselineDirectory -ChildPath 'CurrentBaseline.txt'
        Join-Path -Path $baselineDirectory -ChildPath 'CurrentBaseline.json'
    )

    foreach ($marker in $currentMarkerFiles) {
        if (Test-Path -LiteralPath $marker) {
            try {
                if ($marker.EndsWith('.json')) {
                    $markerData = Get-Content -Path $marker -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
                    if ($markerData -and $markerData.PSObject.Properties['Name']) {
                        $currentBaselineName = [string]$markerData.Name
                        break
                    }
                }
                else {
                    $currentBaselineName = (Get-Content -Path $marker -TotalCount 1 -ErrorAction Stop).Trim()
                    if ($currentBaselineName) {
                        break
                    }
                }
            }
            catch {
                Write-Warning "Failed to read baseline tracking file '$marker'. $_"
            }
        }
    }

    if ($ListAvailable) {
        return $availableBaselines | Select-Object Name, Version, Path, FileName
    }

    $selectedBaseline = $null
    if ($PSBoundParameters.ContainsKey('BaselineName')) {
        $selectedBaseline = $availableBaselines | Where-Object {
            $_.Name -eq $BaselineName -or [System.IO.Path]::GetFileNameWithoutExtension($_.FileName) -eq $BaselineName
        } | Select-Object -First 1

        if (-not $selectedBaseline) {
            Write-Error "Baseline '$BaselineName' was not found in '$baselineDirectory'."
            return
        }
    }
    elseif ($currentBaselineName) {
        $selectedBaseline = $availableBaselines | Where-Object {
            $_.Name -eq $currentBaselineName -or [System.IO.Path]::GetFileNameWithoutExtension($_.FileName) -eq $currentBaselineName
        } | Select-Object -First 1
    }
    elseif ($availableBaselines.Count -eq 1) {
        $selectedBaseline = $availableBaselines[0]
    }

    $availableSummary = $availableBaselines | Select-Object Name, Version, Path, FileName

    if (-not $selectedBaseline) {
        return [pscustomobject]@{
            CurrentBaseline    = $currentBaselineName
            AvailableBaselines = $availableSummary
            Settings           = $null
        }
    }

    $isCurrent = $false
    if ($currentBaselineName) {
        $isCurrent = ($currentBaselineName -eq $selectedBaseline.Name) -or (
            $currentBaselineName -eq [System.IO.Path]::GetFileNameWithoutExtension($selectedBaseline.FileName)
        )
    }

    [pscustomobject]@{
        Name               = $selectedBaseline.Name
        Version            = $selectedBaseline.Version
        Path               = $selectedBaseline.Path
        IsCurrent          = $isCurrent
        CurrentBaseline    = $currentBaselineName
        AvailableBaselines = $availableSummary
        Settings           = $selectedBaseline.RawSettings
    }
}
