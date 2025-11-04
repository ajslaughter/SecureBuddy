function Ensure-WsaDriveMappings {
    <#
    .SYNOPSIS
        Configures departmental drive mappings via Group Policy Preferences.

    .DESCRIPTION
        Ensures the “Drive Mappings – Departments” user GPO exists, is linked to
        OU=Departments, and defines item-level targeted drive mappings for each
        department. Drive H: is mapped to the departmental share path.

    .EXAMPLE
        Ensure-WsaDriveMappings -Verbose

        Creates or updates the drive mapping GPO and preference XML.

    .OUTPUTS
        PSCustomObject
    #>
    [CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'Medium')]
    param()

    $component = 'Ensure-WsaDriveMappings'
    Write-WsaLog -Component $component -Message 'Ensuring drive mapping GPO.'

    if (-not (Get-Command -Name Get-GPO -ErrorAction SilentlyContinue)) {
        $message = 'GroupPolicy module not available on this system.'
        Write-WsaLog -Component $component -Message $message -Level 'ERROR'
        throw $message
    }
    if (-not (Get-Command -Name Get-ADDomain -ErrorAction SilentlyContinue)) {
        $message = 'ActiveDirectory module required for domain resolution.'
        Write-WsaLog -Component $component -Message $message -Level 'ERROR'
        throw $message
    }

    $domain = Get-ADDomain -ErrorAction Stop
    $departmentsDn = "OU=Departments,$($domain.DistinguishedName)"
    $departments = @('IT','Sales','HR','Finance')

    $changes  = New-Object System.Collections.Generic.List[object]
    $findings = New-Object System.Collections.Generic.List[object]

    $gpoName = 'Drive Mappings – Departments'

    try {
        $gpo = Get-GPO -Name $gpoName -ErrorAction SilentlyContinue
        if (-not $gpo -and $PSCmdlet.ShouldProcess($gpoName, 'Create GPO', 'Create drive mapping GPO')) {
            $gpo = New-GPO -Name $gpoName -ErrorAction Stop
            $changes.Add('Created drive mapping GPO.') | Out-Null
        }
    }
    catch {
        $message = "Failed to retrieve or create GPO: $($_.Exception.Message)"
        Write-WsaLog -Component $component -Message $message -Level 'ERROR'
        throw $message
    }

    if (-not $gpo) {
        $findings.Add('GPO not created due to -WhatIf or prior errors.') | Out-Null
        return New-WsaResult -Status 'Error' -Changes $changes.ToArray() -Findings $findings.ToArray()
    }

    try {
        $inheritance = Get-GPInheritance -Target $departmentsDn -ErrorAction Stop
        $linked = $inheritance.GpoLinks | Where-Object { $_.DisplayName -eq $gpo.DisplayName }
        if (-not $linked) {
            if ($PSCmdlet.ShouldProcess($departmentsDn, 'Link GPO', 'Link drive mapping GPO')) {
                New-GPLink -Name $gpo.DisplayName -Target $departmentsDn -LinkEnabled Yes -ErrorAction Stop | Out-Null
                $changes.Add('Linked drive mapping GPO to OU=Departments.') | Out-Null
            }
        }
    }
    catch {
        $msg = "Failed to evaluate GPO links: $($_.Exception.Message)"
        Write-WsaLog -Component $component -Message $msg -Level 'WARN'
        $findings.Add($msg) | Out-Null
    }

    $policyPath = Join-Path -Path "\\$($domain.DNSRoot)\SYSVOL\$($domain.DNSRoot)\Policies" -ChildPath ("{{$($gpo.Id)}}")
    $drivesDir = Join-Path -Path $policyPath -ChildPath 'User\Preferences\Drives'
    $drivesFile = Join-Path -Path $drivesDir -ChildPath 'Drives.xml'

    if (-not (Test-Path -Path $drivesDir)) {
        if ($PSCmdlet.ShouldProcess($drivesDir, 'Create GPP directory', 'Create drives directory')) {
            New-Item -Path $drivesDir -ItemType Directory -Force | Out-Null
            $changes.Add("Created $drivesDir") | Out-Null
        }
        else {
            $findings.Add('Drives preference directory missing but creation skipped (-WhatIf).') | Out-Null
        }
    }

    function Get-WsaDeterministicGuid {
        param([string]$Seed)
        $md5 = [System.Security.Cryptography.MD5]::Create()
        $bytes = [System.Text.Encoding]::UTF8.GetBytes($Seed)
        $hash = $md5.ComputeHash($bytes)
        return [Guid]::new($hash)
    }

    $doc = New-Object System.Xml.XmlDocument
    $decl = $doc.CreateXmlDeclaration('1.0', 'utf-8', $null)
    $doc.AppendChild($decl) | Out-Null
    $root = $doc.CreateElement('Drives')
    $root.SetAttribute('clsid', '{C631DF4C-088F-4156-B058-4375F0853CD8}')
    $doc.AppendChild($root) | Out-Null

    foreach ($dept in $departments) {
        $drive = $doc.CreateElement('Drive')
        $drive.SetAttribute('clsid', '{79F92669-4224-476c-9C5C-6EFB4D87DF4A}')
        $drive.SetAttribute('name', 'H')
        $drive.SetAttribute('status', 'Replace')
        $drive.SetAttribute('image', '1')
        $drive.SetAttribute('changed', (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'))
        $drive.SetAttribute('uid', "{$(Get-WsaDeterministicGuid -Seed $dept)}")

        $properties = $doc.CreateElement('Properties')
        $properties.SetAttribute('action', 'R')
        $properties.SetAttribute('thisDrive', 'NO')
        $properties.SetAttribute('allDrives', 'NO')
        $properties.SetAttribute('userName', '')
        $properties.SetAttribute('password', '')
        $properties.SetAttribute('path', "\\\\DC01\\CompanyFiles\\$dept")
        $properties.SetAttribute('label', "$dept Department")
        $properties.SetAttribute('persistent', '1')
        $properties.SetAttribute('useLetter', '1')
        $properties.SetAttribute('letter', 'H')
        $drive.AppendChild($properties) | Out-Null

        $filters = $doc.CreateElement('Filters')
        $filter = $doc.CreateElement('FilterLDAP')
        $filter.SetAttribute('bool', 'AND')
        $filter.SetAttribute('not', '0')
        $filter.SetAttribute('userContext', '0')

        $ldap = $doc.CreateElement('LDAP')
        $ldap.SetAttribute('name', "LDAP://OU=$dept,OU=Departments,$($domain.DistinguishedName)")
        $ldap.SetAttribute('query', '(objectClass=organizationalUnit)')
        $filter.AppendChild($ldap) | Out-Null
        $filters.AppendChild($filter) | Out-Null
        $drive.AppendChild($filters) | Out-Null

        $root.AppendChild($drive) | Out-Null
    }

    $xmlContent = $doc.OuterXml
    $needsWrite = $true
    if (Test-Path -Path $drivesFile) {
        $existing = Get-Content -Path $drivesFile -Raw
        if ($existing -eq $xmlContent) {
            $needsWrite = $false
        }
    }

    if ($needsWrite) {
        if ($PSCmdlet.ShouldProcess($drivesFile, 'Write drive preference XML', 'Update drive mappings')) {
            $xmlContent | Out-File -FilePath $drivesFile -Encoding UTF8
            $changes.Add('Updated drive mapping preferences.') | Out-Null
        }
    }

    if ($changes.Count -eq 0 -and $findings.Count -eq 0) {
        $findings.Add('Compliant') | Out-Null
    }

    $status = if ($changes.Count -gt 0) { 'Changed' } else { 'Compliant' }
    if ($findings.Count -gt 0 -and -not $findings.Contains('Compliant')) { $status = 'Changed' }

    return New-WsaResult -Status $status -Changes $changes.ToArray() -Findings $findings.ToArray() -Data @{ GpoId = $gpo.Id; PreferenceFile = $drivesFile }
}
