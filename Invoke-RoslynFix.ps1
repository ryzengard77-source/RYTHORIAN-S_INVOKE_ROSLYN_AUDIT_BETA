#Requires -Version 5.1
<#
.SYNOPSIS
   Companion auto-fixer for Rythorian's Invoke-RoslynAudit.

.AUTHOR
    Justin Ross (Farmington, Maine) 2026

.DESCRIPTION
    Invoke-RoslynFix consumes a JSON report produced by Invoke-RoslynAudit
    (-ReportPath), applies every correction that can be made deterministically
    and safely, and writes the corrected source tree to an output folder.
    Originals are NEVER modified.

.PARAMETER ReportPath
    JSON report produced by Invoke-RoslynAudit -ReportPath. Mandatory.

.PARAMETER TargetPath
    Source root to mirror. Defaults to the common root of the file paths in
    the report. Must be a directory (or a single file).

.PARAMETER OutputPath
    Destination folder for the corrected tree. Defaults to the 'Assets'
    folder on the current user's Desktop (created if missing), under a
    subfolder named after the target.

.PARAMETER RedactSecrets
    Also apply the RA006 secret-placeholder codemod.

.PARAMETER Force
    Allow writing into an existing, non-empty -OutputPath.

.NOTES
    Exit codes:
      0 = success (applied; manual-review items may remain)
      1 = fatal error (unreadable report, invalid paths, blocked output dir)
      2 = report contains no findings - nothing to fix
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$ReportPath,

    [Parameter()]
    [string]$TargetPath,

    [Parameter()]
    [string]$OutputPath,

    [switch]$RedactSecrets,

    [switch]$Force
)

Set-StrictMode -Version 3.0
$script:ExitCode = 0
$script:ExcludedDirNames = @('.git', 'bin', 'obj', 'node_modules', '.vs', 'packages', 'TestResults')

#region Logging

function Write-FixLog {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter()]
        [ValidateSet('INFO', 'WARNING', 'ERROR')]
        [string]$Level = 'INFO'
    )
    $line = '[{0}] [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    switch ($Level) {
        'INFO'    { Write-Information -MessageData $line -InformationAction Continue -Tags 'Invoke-RoslynFix' }
        'WARNING' { Write-Warning $Message }
        'ERROR'   { [System.Console]::Error.WriteLine($line) }
    }
}

#endregion Logging

#region Helpers

function Get-CommonRoot {
    param ([string[]]$Paths)
    if (-not $Paths -or $Paths.Count -eq 0) { throw 'No paths provided to determine common root.' }
    $normalized = @($Paths | ForEach-Object { [System.IO.Path]::GetFullPath($_) })
    $sep    = [System.IO.Path]::DirectorySeparatorChar
    $altSep = [System.IO.Path]::AltDirectorySeparatorChar
    $root = Split-Path -Path $normalized[0] -Parent
    $rootWithSep = $root.TrimEnd($sep, $altSep) + $sep
    foreach ($p in $normalized) {
        $dir = Split-Path -Path $p -Parent
        while ($dir) {
            $dirWithSep = $dir.TrimEnd($sep, $altSep) + $sep
            if ($dirWithSep.StartsWith($rootWithSep, [System.StringComparison]::OrdinalIgnoreCase)) { break }
            $root = Split-Path -Path $root -Parent
            if (-not $root) { throw 'Could not determine a common root for the report files.' }
            $rootWithSep = $root.TrimEnd($sep, $altSep) + $sep
        }
    }
    return $root
}

function Read-SourceText {
    param ([string]$Path)
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    if ($bytes.Length -ge 3 -and $bytes[0] -eq 0xEF -and $bytes[1] -eq 0xBB -and $bytes[2] -eq 0xBF) {
        return @{ Text = [System.Text.Encoding]::UTF8.GetString($bytes, 3, $bytes.Length - 3); Encoding = [System.Text.UTF8Encoding]::new($true) }
    }
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) {
        return @{ Text = [System.Text.Encoding]::Unicode.GetString($bytes, 2, $bytes.Length - 2); Encoding = [System.Text.Encoding]::Unicode }
    }
    if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFE -and $bytes[1] -eq 0xFF) {
        return @{ Text = [System.Text.Encoding]::BigEndianUnicode.GetString($bytes, 2, $bytes.Length - 2); Encoding = [System.Text.Encoding]::BigEndianUnicode }
    }
    return @{ Text = [System.Text.Encoding]::UTF8.GetString($bytes); Encoding = [System.Text.UTF8Encoding]::new($false) }
}

function ConvertTo-DemangledText {
    param ([string]$Text)
    $pattern = '\[([A-Za-z0-9][A-Za-z0-9._\-]*)\]\(https?://\1(?=/|\))\)'
    $count = [regex]::Matches($Text, $pattern).Count
    if ($count -gt 0) {
        $Text = [regex]::Replace($Text, $pattern, '$1')
    }
    return @{ Text = $Text; Count = $count }
}

function ConvertTo-RedactedSecretText {
    param ([string]$Text)
    $pattern = '(?i)((?:password|passwd|pwd|secret|api[_-]?key|access[_-]?key|token)\s*[:=]\s*")[^"]{6,}(")'
    $count = [regex]::Matches($Text, $pattern).Count
    if ($count -gt 0) {
        $Text = [regex]::Replace($Text, $pattern, '$1__REDACTED_SECRET__$2')
    }
    return @{ Text = $Text; Count = $count }
}

function Get-FirstAvailableCommand {
    param ([string[]]$Names)
    foreach ($n in $Names) {
        $c = Get-Command -Name $n -ErrorAction SilentlyContinue
        if ($c) {
            if ($c.PSObject.Properties['Source'] -and $c.Source) { return [string]$c.Source }
            if ($c.PSObject.Properties['Path'] -and $c.Path) { return [string]$c.Path }
            return [string]$c.Name
        }
    }
    return ''
}

$script:CxxCompiler = Get-FirstAvailableCommand -Names @('clang++', 'clang', 'g++', 'c++', 'gcc')
$script:PythonExe   = Get-FirstAvailableCommand -Names @('python3', 'python')

function Get-PythonSyntaxErrorCount {
    param ([string]$Path)
    if (-not $script:PythonExe) { return $null }
    $pyCode = 'import ast,sys' + "`n" +
        'try:' + "`n" +
        '    ast.parse(open(sys.argv[1], "rb").read().decode("utf-8", "replace"))' + "`n" +
        'except SyntaxError as e:' + "`n" +
        '    print("PYAUDIT:" + str(e.lineno))' + "`n" +
        '    sys.exit(1)'
    $null = & $script:PythonExe -c $pyCode $Path 2>&1
    if ($LASTEXITCODE -ne 0) { return 1 }
    return 0
}

function Get-CxxSyntaxErrorCount {
    param ([string]$Path)
    if (-not $script:CxxCompiler) { return $null }
    try {
        $out = & $script:CxxCompiler -fsyntax-only -x c++ $Path 2>&1
        $count = 0
        foreach ($line in $out) {
            if ("$line" -match ':\s*\d+:\d+:\s*(?:fatal\s+)?error:') { $count++ }
        }
        return $count
    }
    catch { return $null }
}

function Get-XmlMalformedCount {
    param ([string]$Text)
    try {
        $doc = New-Object System.Xml.XmlDocument
        $doc.LoadXml($Text)
        return 0
    }
    catch { return 1 }
}

function Get-PowerShellSyntaxErrorCount {
    param ([string]$Text)
    $tokens = $null
    $errors = $null
    $null = [System.Management.Automation.Language.Parser]::ParseInput($Text, [ref]$tokens, [ref]$errors)
    return $errors.Count
}

function Get-SourceSyntaxErrorCount {
    param ([string]$Extension, [string]$Text)
    switch ($Extension) {
        '.ps1'  { return Get-PowerShellSyntaxErrorCount -Text $Text }
        '.psm1' { return Get-PowerShellSyntaxErrorCount -Text $Text }
        '.py' {
            if (-not $script:PythonExe) { return $null }
            $tmp = [System.IO.Path]::GetTempFileName()
            try {
                [System.IO.File]::WriteAllText($tmp, $Text)
                return Get-PythonSyntaxErrorCount -Path $tmp
            }
            finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
        }
        '.xaml'   { return Get-XmlMalformedCount -Text $Text }
        '.csproj' { return Get-XmlMalformedCount -Text $Text }
        '.props'  { return Get-XmlMalformedCount -Text $Text }
        '.targets' { return Get-XmlMalformedCount -Text $Text }
        '.xml'    { return Get-XmlMalformedCount -Text $Text }
        '.config' { return Get-XmlMalformedCount -Text $Text }
        default {
            if ($Extension -in @('.cpp', '.cxx', '.cc', '.c', '.hpp', '.hxx', '.hh', '.h')) {
                if (-not $script:CxxCompiler) { return $null }
                $tmp = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), ([System.IO.Path]::GetRandomFileName() + '.cpp'))
                try {
                    [System.IO.File]::WriteAllText($tmp, $Text)
                    return Get-CxxSyntaxErrorCount -Path $tmp
                }
                finally {
                    if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
                }
            }
            return $null
        }
    }
}

function Get-ChildPowerShell {
    try {
        $procPath = (Get-Process -Id $PID -ErrorAction SilentlyContinue).Path
        if ($procPath -and (Test-Path -LiteralPath $procPath)) { return $procPath }
    }
    catch {}

    $candidates = @(
        (Join-Path $PSHOME 'pwsh.exe'),
        (Join-Path $PSHOME 'pwsh'),
        (Join-Path $PSHOME 'powershell.exe')
    )
    foreach ($c in $candidates) {
        if (Test-Path -LiteralPath $c) { return $c }
    }
    throw "Could not locate the current PowerShell binary under '$PSHOME'."
}

#endregion Helpers

Write-FixLog ("Fix started. Report: '{0}'" -f $ReportPath) -Level INFO

try {
    $ErrorActionPreference = 'Stop'

    if (-not (Test-Path -LiteralPath $ReportPath)) {
        throw "Report file not found: '$ReportPath'."
    }

    $ReportPath = [System.IO.Path]::GetFullPath($ReportPath)

    if ((Get-Item -LiteralPath $ReportPath).PSIsContainer) {
        $auditScriptForReport = Join-Path $PSScriptRoot 'Invoke-RoslynAudit.ps1'
        if (-not (Test-Path -LiteralPath $auditScriptForReport)) {
            throw ("ReportPath is a directory ('{0}'), not an audit JSON report, and " +
                   "Invoke-RoslynAudit.ps1 was not found next to this script to generate one. " +
                   "Run the audit with -ReportPath first, then pass that JSON file.") -f $ReportPath
        }
        $dirLeaf = [System.IO.Path]::GetFileName($ReportPath.TrimEnd('\', '/'))
        $generatedReport = [System.IO.Path]::GetFullPath((Join-Path (Join-Path $ReportPath '..') ("RoslynFixInput_" + $dirLeaf + ".json")))
        Write-FixLog ("ReportPath is a directory - generating an audit report for '{0}' first..." -f $ReportPath) -Level INFO
        $shellForReport = Get-ChildPowerShell
        $null = & $shellForReport -NoProfile -File $auditScriptForReport $ReportPath -ReportPath $generatedReport 2>&1
        if (-not (Test-Path -LiteralPath $generatedReport)) {
            throw "The audit run for '$ReportPath' did not produce a report."
        }
        $ReportPath = $generatedReport
        Write-FixLog ("Audit report generated: '{0}'" -f $ReportPath) -Level INFO
    }

    $report = Get-Content -LiteralPath $ReportPath -Raw | ConvertFrom-Json
    $findingsProp = if ($report -and $report.PSObject.Properties['Findings']) { $report.Findings } else { $null }

    if ($null -eq $report -or $null -eq $findingsProp) {
        throw "Report '$ReportPath' is not a valid Invoke-RoslynAudit JSON report."
    }

    $findings = @($findingsProp)
    if ($findings.Count -eq 0) {
        Write-FixLog 'Report contains no findings - nothing to fix.' -Level WARNING
        $script:ExitCode = 2
    }
    else {
        if (-not $TargetPath) {
            $reportFiles = @($findings | ForEach-Object {
                if ($_.PSObject.Properties['File']) { [string]$_.File }
            } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Select-Object -Unique)
            $TargetPath = Get-CommonRoot -Paths $reportFiles
        }
        if (-not (Test-Path -LiteralPath $TargetPath)) {
            throw "Target path not found: '$TargetPath'."
        }

        $TargetPath = [System.IO.Path]::GetFullPath($TargetPath)
        $isTargetDir = (Get-Item -LiteralPath $TargetPath).PSIsContainer
        if (-not $isTargetDir) {
            throw "TargetPath must be a directory (got file: '$TargetPath'). Fix single files by pointing at their folder."
        }

        $sep = [System.IO.Path]::DirectorySeparatorChar
        $TargetPathNorm = $TargetPath.TrimEnd($sep, [System.IO.Path]::AltDirectorySeparatorChar) + $sep

        $assetsDefault = $false
        if (-not $OutputPath) {
            $desktop = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Desktop)
            if ([string]::IsNullOrWhiteSpace($desktop)) { $desktop = Join-Path $HOME 'Desktop' }
            $OutputPath = Join-Path $desktop 'Assets'
            $assetsDefault = $true
        }
        if ($assetsDefault) {
            $OutputPath = Join-Path $OutputPath (Split-Path -Path $TargetPath -Leaf)
        }

        $OutputPath = [System.IO.Path]::GetFullPath($OutputPath)

        if (Test-Path -LiteralPath $OutputPath) {
            $existing = @(Get-ChildItem -LiteralPath $OutputPath -Force -ErrorAction SilentlyContinue)
            if ($existing.Count -gt 0 -and -not $Force) {
                throw "Output folder '$OutputPath' exists and is not empty. Supply -Force to write into it, or remove it."
            }
        }
        else {
            New-Item -Path $OutputPath -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }

        $fixPlan = @{}
        foreach ($f in $findings) {
            if (-not $f.PSObject.Properties['File']) { continue }
            $rawPath = [string]$f.File
            $path = if ([System.IO.Path]::IsPathRooted($rawPath)) { [System.IO.Path]::GetFullPath($rawPath) } else { [System.IO.Path]::GetFullPath((Join-Path $TargetPath $rawPath)) }

            if (-not $fixPlan.ContainsKey($path)) {
                $fixPlan[$path] = @{ Demangle = $false; RedactSecret = $false; FindingIds = New-Object System.Collections.Generic.List[string] }
            }
            $plan = $fixPlan[$path]
            $rule = if ($f.PSObject.Properties['Rule']) { [string]$f.Rule } else { '' }
            $plan.FindingIds.Add($rule)
            if ($rule -in @('SYNTAX','RA306','AUDIT-ERR')) { $plan.Demangle = $true }
            if ($rule -eq 'RA006' -and $RedactSecrets) { $plan.RedactSecret = $true }
        }

        $filesCopied = 0
        $filesChanged = 0
        $linksRemoved = 0
        $secretsRedacted = 0
        $skippedOutsideTarget = 0
        $autoFixed = New-Object System.Collections.Generic.List[object]

        $outputFullPath = $OutputPath
        $allSourceFiles = @(Get-ChildItem -LiteralPath $TargetPath -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object {
                $relSegment = $_.FullName.Substring($TargetPathNorm.Length)
                $segments = $relSegment -split '[\\/]'
                $excluded = $false
                foreach ($s in $segments) {
                    if ($script:ExcludedDirNames -contains $s) { $excluded = $true; break }
                }
                (-not $excluded) -and (-not $_.FullName.StartsWith($outputFullPath, [System.StringComparison]::OrdinalIgnoreCase))
            })

        foreach ($src in $allSourceFiles) {
            $rel = $src.FullName.Substring($TargetPathNorm.Length).TrimStart('\', '/')
            $dest = Join-Path $OutputPath $rel
            $destDir = Split-Path -Path $dest -Parent
            if (-not (Test-Path -LiteralPath $destDir)) {
                New-Item -Path $destDir -ItemType Directory -Force -ErrorAction Stop | Out-Null
            }

            if ($fixPlan.ContainsKey($src.FullName)) {
                $plan = $fixPlan[$src.FullName]
                $read = Read-SourceText -Path $src.FullName
                $text = $read.Text
                $originalText = $text

                if ($plan.Demangle) {
                    $dem = ConvertTo-DemangledText -Text $text
                    $text = $dem.Text
                    $linksRemoved += $dem.Count
                }
                if ($plan.RedactSecret) {
                    $red = ConvertTo-RedactedSecretText -Text $text
                    $text = $red.Text
                    $secretsRedacted += $red.Count
                }

                if ($text -ne $originalText) {
                    $gateBefore = Get-SourceSyntaxErrorCount -Extension $src.Extension -Text $originalText
                    if ($null -ne $gateBefore) {
                        $gateAfter = Get-SourceSyntaxErrorCount -Extension $src.Extension -Text $text
                        if ($gateAfter -gt $gateBefore) {
                            Write-FixLog ("Fix REJECTED for '{0}': syntax errors would increase ({1} -> {2}). File copied unchanged." -f $rel, $gateBefore, $gateAfter) -Level WARNING
                            [System.IO.File]::Copy($src.FullName, $dest, $true)
                            $filesCopied++
                            continue
                        }
                    }
                    [System.IO.File]::WriteAllText($dest, $text, $read.Encoding)
                    $filesChanged++
                    $transforms = New-Object System.Collections.Generic.List[string]
                    if ($plan.Demangle) { $transforms.Add('MarkdownLinkDemangle') }
                    if ($plan.RedactSecret) { $transforms.Add('SecretRedaction') }
                    $autoFixed.Add([PSCustomObject]@{
                        File       = $rel
                        FindingIds = @($plan.FindingIds)
                        Transforms = $transforms
                    })
                    Write-FixLog ("Fixed '{0}' (findings: {1})." -f $rel, ($plan.FindingIds -join ', ')) -Level INFO
                    continue
                }
                Write-FixLog ("Flagged file '{0}' needed no automated change; copied unchanged." -f $rel) -Level WARNING
            }

            [System.IO.File]::Copy($src.FullName, $dest, $true)
            $filesCopied++
        }

        foreach ($path in @($fixPlan.Keys)) {
            if (-not $path.StartsWith($TargetPathNorm, [System.StringComparison]::OrdinalIgnoreCase)) {
                $skippedOutsideTarget++
                Write-FixLog ("Reported file '{0}' lies outside TargetPath; not mirrored." -f $path) -Level WARNING
            }
        }

        $verification = @{ ChildAuditAvailable = $false; FindingsBefore = $findings.Count; FindingsAfter = $null; Command = '' }
        $remainingKeys = New-Object System.Collections.Generic.HashSet[string]
        $verificationRan = $false
        $auditScript = Join-Path $PSScriptRoot 'Invoke-RoslynAudit.ps1'
        if (Test-Path -LiteralPath $auditScript) {
            $verification.ChildAuditAvailable = $true
            $shell = Get-ChildPowerShell
            $verifyReport = [System.IO.Path]::GetFullPath((Join-Path (Join-Path $OutputPath '..') 'FixVerifyReport.json'))
            $verifyArgs = @('-NoProfile', '-File', $auditScript, $OutputPath, '-ReportPath', $verifyReport)
            $verification.Command = "$shell $($verifyArgs -join ' ')"
            Write-FixLog 'Re-running the audit against the corrected output...' -Level INFO
            $null = & $shell @verifyArgs 2>&1
            if (Test-Path -LiteralPath $verifyReport) {
                $verifyJson = Get-Content -LiteralPath $verifyReport -Raw | ConvertFrom-Json
                $verifySummary = if ($verifyJson -and $verifyJson.PSObject.Properties['Summary']) { $verifyJson.Summary } else { $null }
                if ($verifySummary -and $verifySummary.PSObject.Properties['TotalFindings']) {
                    $verification.FindingsAfter = [int]$verifySummary.TotalFindings
                }
                $verificationRan = $true
                $verifyFindings = if ($verifyJson -and $verifyJson.PSObject.Properties['Findings']) { @($verifyJson.Findings) } else { @() }
                foreach ($vf in $verifyFindings) {
                    $vFile = if ($vf.PSObject.Properties['File']) { [string]$vf.File } else { '' }
                    $vLine = if ($vf.PSObject.Properties['Line']) { [string]$vf.Line } else { '' }
                    $vRule = if ($vf.PSObject.Properties['Rule']) { [string]$vf.Rule } else { '' }
                    $null = $remainingKeys.Add(("{0}|{1}|{2}" -f (Split-Path -Path $vFile -Leaf), $vLine, $vRule))
                }
            }
            else {
                Write-FixLog 'Verification audit did not produce a report.' -Level WARNING
            }
        }
        else {
            Write-FixLog 'Invoke-RoslynAudit.ps1 not found next to this script; skipped verification re-run.' -Level WARNING
        }

        $manual = New-Object System.Collections.Generic.List[object]
        foreach ($f in $findings) {
            $path = if ($f.PSObject.Properties['File']) { [string]$f.File } else { '' }
            $line = if ($f.PSObject.Properties['Line']) { [string]$f.Line } else { '' }
            $rule = if ($f.PSObject.Properties['Rule']) { [string]$f.Rule } else { '' }
            $key = "{0}|{1}|{2}" -f (Split-Path -Path $path -Leaf), $line, $rule
            if ($verificationRan) {
                $resolved = -not $remainingKeys.Contains($key)
            }
            else {
                $resolved = $fixPlan.ContainsKey([System.IO.Path]::GetFullPath($path)) -and
                    (($rule -eq 'SYNTAX' -and $linksRemoved -gt 0) -or
                     ($rule -eq 'RA306' -and $linksRemoved -gt 0) -or
                     ($rule -eq 'RA006' -and $secretsRedacted -gt 0))
            }
            if (-not $resolved) {
                $remProp = $f.PSObject.Properties['Remediation']
                $remediationText = if ($remProp) { [string]$remProp.Value } else { '' }
                $manual.Add([PSCustomObject]@{
                    File        = $path
                    Line        = $line
                    Rule        = $rule
                    Severity    = if ($f.PSObject.Properties['Severity']) { $f.Severity } else { '' }
                    Message     = if ($f.PSObject.Properties['Message']) { $f.Message } else { '' }
                    Remediation = $remediationText
                })
            }
        }

        $fixReport = [PSCustomObject]@{
            GeneratedBy      = 'Invoke-RoslynFix 1.0'
            SourceRoot       = $TargetPath
            OutputRoot       = $OutputPath
            FilesCopied      = $filesCopied
            FilesChanged     = $filesChanged
            TransformCounts  = @{ MarkdownLinksRemoved = $linksRemoved; SecretsRedacted = $secretsRedacted }
            AutoFixed        = $autoFixed
            ManualReview     = $manual
            Verification     = $verification
        }
        $fixReportPath = Join-Path $OutputPath 'FixReport.json'
        [System.IO.File]::WriteAllText($fixReportPath, ($fixReport | ConvertTo-Json -Depth 6), [System.Text.UTF8Encoding]::new($false))

        Write-FixLog ("Fix finished: {0} file(s) mirrored, {1} corrected, {2} markdown link(s) removed, {3} secret(s) redacted." -f
            $filesCopied, $filesChanged, $linksRemoved, $secretsRedacted) -Level INFO
        Write-FixLog ("Manual review: {0} finding(s) require human decisions (see FixReport.json)." -f $manual.Count) -Level WARNING
        if ($verification.ChildAuditAvailable -and $null -ne $verification.FindingsAfter) {
            Write-FixLog ("Verification: findings {0} -> {1} in the corrected tree." -f
                $verification.FindingsBefore, $verification.FindingsAfter) -Level INFO
        }
        Write-FixLog ("Corrected tree written to '{0}'. Originals untouched." -f $OutputPath) -Level INFO
    }
}
catch {
    Write-FixLog ("Fix failed: {0}" -f $_) -Level ERROR
    $script:ExitCode = 1
}

$env:LASTEXITCODE = $script:ExitCode
exit $script:ExitCode
