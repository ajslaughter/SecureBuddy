function Ensure-WsaDeptShares {
    <#
    .SYNOPSIS
        Ensures departmental file shares and NTFS permissions are configured.

    .DESCRIPTION
        Creates the CompanyFiles folder structure, applies NTFS permissions, and configures
        SMB shares. Optional creation of department-specific shares aligns share
        permissions with security groups.

    .PARAMETER SeparateShares
        When supplied, creates per-department SMB shares (CompanyFiles_<Dept>) targeted at
        each department folder.

    .EXAMPLE
        Ensure-WsaDeptShares -Verbose

        Ensures the default CompanyFiles share and NTFS layout exist.

    .EXAMPLE
        Ensure-WsaDeptShares -SeparateShares -Verbose

        Configures per-department SMB shares aligned with security groups.

    .OUTPUTS
        PSCustomObject
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param(
        [switch]$SeparateShares
    )

    $component = 'Ensure-WsaDeptShares'
    Write-WsaLog -Component $component -Message 'Validating departmental shares.'

    if (-not (Get-Command -Name Get-SmbShare -ErrorAction SilentlyContinue)) {
        $message = 'SMBShare module not available on this system.'
        Write-WsaLog -Component $component -Message $message -Level 'ERROR'
        throw $message
    }

    if (-not (Get-Command -Name Get-ADDomain -ErrorAction SilentlyContinue)) {
        $message = 'ActiveDirectory module required for identity resolution.'
        Write-WsaLog -Component $component -Message $message -Level 'ERROR'
        throw $message
    }

    $domain = Get-ADDomain -ErrorAction Stop
    $netbios = $domain.NetBIOSName
    $domainAdmins = "$netbios\Domain Admins"
    $allStaff = "$netbios\AllStaff"

    $rootPath = 'C:\Shares\CompanyFiles'
    $departments = @('IT','Sales','HR','Finance')

    $changes  = New-Object System.Collections.Generic.List[object]
    $findings = New-Object System.Collections.Generic.List[object]

    if (-not (Test-Path -Path $rootPath)) {
        if ($PSCmdlet.ShouldProcess($rootPath, 'Create directory', 'Create root directory')) {
            New-Item -Path $rootPath -ItemType Directory -Force | Out-Null
            $changes.Add("Created root directory $rootPath") | Out-Null
            Write-WsaLog -Component $component -Message "Created $rootPath."
        }
        else {
            $findings.Add("Root directory $rootPath missing but creation skipped (-WhatIf).") | Out-Null
        }
    }

    function Add-WsaNtfsRule {
        param(
            [string]$Path,
            [string]$Identity,
            [System.Security.AccessControl.FileSystemRights]$Rights
        )

        $acl = Get-Acl -Path $Path
        $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($Identity, $Rights, 'ContainerInherit,ObjectInherit', 'None', 'Allow')
        $existing = $acl.Access | Where-Object { $_.IdentityReference -eq $Identity -and ($_.FileSystemRights -band $Rights) }
        if (-not $existing) {
            $acl.SetAccessRule($rule)
            Set-Acl -Path $Path -AclObject $acl
            return $true
        }
        return $false
    }

    foreach ($dept in $departments) {
        $deptPath = Join-Path -Path $rootPath -ChildPath $dept
        if (-not (Test-Path -Path $deptPath)) {
            if ($PSCmdlet.ShouldProcess($deptPath, "Create $dept folder", 'Create department folder')) {
                New-Item -Path $deptPath -ItemType Directory -Force | Out-Null
                $changes.Add("Created folder $deptPath") | Out-Null
            }
            else {
                $findings.Add("Department folder $deptPath missing but creation skipped (-WhatIf).") | Out-Null
                continue
            }
        }

        if ($PSCmdlet.ShouldProcess($deptPath, 'Ensure NTFS permissions', 'Set NTFS permissions')) {
            if (Add-WsaNtfsRule -Path $deptPath -Identity $domainAdmins -Rights 'FullControl') {
                $changes.Add("Ensured FullControl for $domainAdmins on $deptPath") | Out-Null
            }
            if (Add-WsaNtfsRule -Path $deptPath -Identity $allStaff -Rights 'ReadAndExecute') {
                $changes.Add("Ensured Read on $deptPath for $allStaff") | Out-Null
            }
            $deptGroup = "SG_$dept"
            try {
                $groupExists = Get-ADGroup -Identity $deptGroup -ErrorAction SilentlyContinue
            }
            catch {
                $groupExists = $null
            }
            if ($groupExists) {
                if (Add-WsaNtfsRule -Path $deptPath -Identity "$netbios\$deptGroup" -Rights 'Modify') {
                    $changes.Add("Ensured Modify on $deptPath for $netbios\\$deptGroup") | Out-Null
                }
            }
            else {
                $findings.Add("Group $deptGroup not found for NTFS delegation.") | Out-Null
            }
        }
    }

    # Ensure root share
    try {
        $share = Get-SmbShare -Name 'CompanyFiles' -ErrorAction SilentlyContinue
    }
    catch {
        $share = $null
    }

    if (-not $share) {
        if ($PSCmdlet.ShouldProcess('CompanyFiles share', 'Create SMB share', 'Create SMB share')) {
            New-SmbShare -Name 'CompanyFiles' -Path $rootPath -FullAccess $domainAdmins -ChangeAccess $allStaff -ErrorAction Stop | Out-Null
            $changes.Add('Created SMB share CompanyFiles.') | Out-Null
            Write-WsaLog -Component $component -Message 'Created CompanyFiles share.'
        }
        else {
            $findings.Add('CompanyFiles share missing but creation skipped (-WhatIf).') | Out-Null
        }
    }
    else {
        if ($share.Path -ne $rootPath) {
            if ($PSCmdlet.ShouldProcess('CompanyFiles share', "Update path to $rootPath", 'Update SMB share path')) {
                Set-SmbShare -Name 'CompanyFiles' -Path $rootPath -Force -ErrorAction Stop
                $changes.Add('Updated CompanyFiles share path.') | Out-Null
            }
        }
    }

    # Validate share permissions
    try {
        $shareAccess = Get-SmbShareAccess -Name 'CompanyFiles' -ErrorAction Stop
        $requiredAccess = @{
            $domainAdmins = 'Full'
            $allStaff     = 'Change'
        }
        foreach ($principal in $requiredAccess.Keys) {
            $expected = $requiredAccess[$principal]
            $actual = $shareAccess | Where-Object { $_.AccountName -eq $principal }
            if (-not $actual -or $actual.AccessControlType -ne 'Allow' -or $actual.AccessRight -ne $expected) {
                if ($PSCmdlet.ShouldProcess($principal, "Grant $expected on CompanyFiles", 'Grant SMB access')) {
                    Grant-SmbShareAccess -Name 'CompanyFiles' -AccountName $principal -AccessRight $expected -Force -ErrorAction Stop | Out-Null
                    $changes.Add("Granted $expected access to $principal on CompanyFiles") | Out-Null
                }
            }
        }

        foreach ($entry in $shareAccess) {
            if ($entry.AccountName -notin $requiredAccess.Keys -and $entry.AccountName -ne 'CREATOR OWNER') {
                if ($PSCmdlet.ShouldProcess($entry.AccountName, 'Revoke unexpected share access', 'Revoke SMB access')) {
                    Revoke-SmbShareAccess -Name 'CompanyFiles' -AccountName $entry.AccountName -Force -ErrorAction Stop
                    $changes.Add("Revoked share access for $($entry.AccountName)") | Out-Null
                }
            }
        }
    }
    catch {
        $msg = "Failed to validate CompanyFiles share permissions: $($_.Exception.Message)"
        Write-WsaLog -Component $component -Message $msg -Level 'ERROR'
        $findings.Add($msg) | Out-Null
    }

    if ($SeparateShares.IsPresent) {
        foreach ($dept in $departments) {
            $deptPath = Join-Path -Path $rootPath -ChildPath $dept
            $shareName = "CompanyFiles_$dept"
            try {
                $deptShare = Get-SmbShare -Name $shareName -ErrorAction SilentlyContinue
            }
            catch {
                $deptShare = $null
            }

            if (-not $deptShare) {
                if ($PSCmdlet.ShouldProcess($shareName, 'Create departmental share', 'Create SMB share')) {
                    New-SmbShare -Name $shareName -Path $deptPath -FullAccess $domainAdmins -ReadAccess $allStaff -ErrorAction Stop | Out-Null
                    $changes.Add("Created share $shareName") | Out-Null
                }
            }

            try {
                $deptAccess = Get-SmbShareAccess -Name $shareName -ErrorAction Stop
                $deptGroup = "${netbios}\\SG_$dept"
                $expected = @{
                    $domainAdmins = 'Full'
                    $allStaff     = 'Read'
                }
                if (Get-ADGroup -Identity "SG_$dept" -ErrorAction SilentlyContinue) {
                    $expected[$deptGroup] = 'Change'
                }

                foreach ($principal in $expected.Keys) {
                    $right = $expected[$principal]
                    $current = $deptAccess | Where-Object { $_.AccountName -eq $principal }
                    if (-not $current -or $current.AccessRight -ne $right) {
                        if ($PSCmdlet.ShouldProcess($shareName, "Grant $right to $principal", 'Grant SMB access')) {
                            Grant-SmbShareAccess -Name $shareName -AccountName $principal -AccessRight $right -Force -ErrorAction Stop | Out-Null
                            $changes.Add("Granted $right on $shareName to $principal") | Out-Null
                        }
                    }
                }

                foreach ($entry in $deptAccess) {
                    if ($entry.AccountName -notin $expected.Keys) {
                        if ($PSCmdlet.ShouldProcess($shareName, "Revoke $($entry.AccountName)", 'Revoke SMB access')) {
                            Revoke-SmbShareAccess -Name $shareName -AccountName $entry.AccountName -Force -ErrorAction Stop
                            $changes.Add("Revoked $($entry.AccountName) from $shareName") | Out-Null
                        }
                    }
                }
            }
            catch {
                $msg = "Failed to manage $shareName permissions: $($_.Exception.Message)"
                Write-WsaLog -Component $component -Message $msg -Level 'WARN'
                $findings.Add($msg) | Out-Null
            }
        }
    }

    if ($changes.Count -eq 0 -and $findings.Count -eq 0) {
        $findings.Add('Compliant') | Out-Null
    }

    $status = if ($changes.Count -gt 0) { 'Changed' } else { 'Compliant' }
    if ($findings.Count -gt 0 -and -not $findings.Contains('Compliant')) { $status = 'Changed' }

    return New-WsaResult -Status $status -Changes $changes.ToArray() -Findings $findings.ToArray() -Data @{ RootPath = $rootPath; SeparateShares = $SeparateShares.IsPresent }
}
