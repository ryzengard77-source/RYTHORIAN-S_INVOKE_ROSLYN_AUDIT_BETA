#Requires -Version 5.1
<#
.SYNOPSIS
   Enterprise Roslyn SAST and code quality analyzer for PowerShell.

.AUTHOR
    Justin Ross (Farmington, Maine) 2026

.DESCRIPTION
    Rythorian's Invoke-RoslynAudit bootstraps Roslyn assemblies, builds in-memory
    syntax trees, executes AST syntax diagnostics (Roslyn for C#/VB, the
    PowerShell AST parser for .ps1/.psm1, the host C++ compiler for C/C++
    sources, and the host Python interpreter for .py), evaluates heuristic
    patterns, supports SARIF 2.1.0 output, handles .auditignore suppressions,
    and allows incremental git diff scanning.

.PARAMETER Path
    A .cs/.vb/.ps1/.psm1/.cpp/.cc/.cxx/.c/.hpp/.h/.py file, a folder, or a
    .zip archive to audit. Project and markup files (.xaml/.csproj/.props/
    .targets/.xml/.config) are also audited.

.PARAMETER MaxThreads
    Degree of Parallelism (runspace pool size). Default: CPU count, clamped 1-32.

.PARAMETER TimeoutSeconds
    Overall wall-clock budget for the audit phase. 0 = unlimited.

.PARAMETER LogPath
    Optional log file destination.

.PARAMETER ReportPath
    Optional report output path. Formatted as JSON or SARIF based on extension/switch.

.PARAMETER RulePackPath
    Optional JSON file with custom audit rules.

.PARAMETER AuditIgnorePath
    Optional path to a .auditignore file.

.PARAMETER LocalAssemblyPath
    Optional local directory path for Roslyn assemblies, enabling air-gapped execution.

.PARAMETER NugetHash
    Optional SHA-256 hash to verify nuget.exe integrity upon download.

.PARAMETER ReuseCachedNuget
    When set, an existing nuget.exe is reused.

.PARAMETER Sarif
    Switch to force output report format to SARIF 2.1.0 schema.

.PARAMETER FailOn
    Optional severity gate: ERROR, WARNING, or INFO.

.PARAMETER GitDiffOnly
    Audits only modified or untracked source files relative to git HEAD.

.PARAMETER KeepWorkspace
    Do not delete the extracted-archive scratch directory on exit.

.PARAMETER PassThru
    Emit the result object (Summary + Findings) to the pipeline.

.PARAMETER AutoFix
    After the audit completes, automatically runs Invoke-RoslynFix.ps1.

.NOTES
    Exit codes:
      0 = success
      1 = fatal error
      2 = no auditable files found
      3 = severity gate breach (-FailOn)
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$Path,

    [Parameter()]
    [ValidateRange(1, 32)]
    [int]$MaxThreads = [Math]::Min(32, [Math]::Max(1, [Environment]::ProcessorCount)),

    [Parameter()]
    [ValidateRange(0, 86400)]
    [int]$TimeoutSeconds = 0,

    [Parameter()]
    [string]$LogPath,

    [Parameter()]
    [string]$ReportPath,

    [Parameter()]
    [string]$RulePackPath,

    [Parameter()]
    [string]$AuditIgnorePath,

    [Parameter()]
    [string]$LocalAssemblyPath,

    [Parameter()]
    [string]$NugetHash,

    [Parameter()]
    [ValidateSet('ERROR', 'WARNING', 'INFO')]
    [string]$FailOn,

    [switch]$ReuseCachedNuget,
    [switch]$Sarif,
    [switch]$GitDiffOnly,
    [switch]$KeepWorkspace,
    [switch]$PassThru,
    [switch]$AutoFix
)

#region Setup

Set-StrictMode -Version 3.0

$script:WasDotSourced = ($MyInvocation.InvocationName -eq '.')

$script:PinnedPackageVersion = '4.5.0'
$script:AuditSentinelKey    = 'AuditExitSentinel'
$script:AuditExitCodeKey    = 'AuditExitCode'
$script:ExitCode            = 0
$script:AuditStoppedFiles   = 0

$script:UserKey = try {
    if ($env:USERNAME) { $env:USERNAME } else { [System.Environment]::UserName }
}
catch { 'default' }
if ([string]::IsNullOrWhiteSpace($script:UserKey)) { $script:UserKey = 'default' }
$script:UserKey = $script:UserKey -replace '[^A-Za-z0-9_\-]', '_'
if ([string]::IsNullOrWhiteSpace($script:UserKey)) { $script:UserKey = 'default' }

$script:WorkspacePath        = Join-Path ([System.IO.Path]::GetTempPath()) ("RoslynAuditWorkspace_{0}" -f $script:UserKey)
$script:PackagesPath         = Join-Path $script:WorkspacePath 'Packages'
$script:NugetExePath         = Join-Path $script:WorkspacePath 'nuget.exe'
$script:ExtractPath          = Join-Path $script:WorkspacePath 'Extracted'
$script:LogWriter            = $null
$script:LogPathLocal         = $LogPath
$script:ResolvedRoslynPaths  = New-Object System.Collections.Generic.List[string]

#endregion Setup

function Complete-Audit {
    param ([int]$Code)
    $ex = New-Object System.Exception ("Audit exit code: {0}" -f $Code)
    $ex.Data[$script:AuditSentinelKey] = $true
    $ex.Data[$script:AuditExitCodeKey] = $Code
    throw $ex
}

#region Logging

function ConvertTo-RedactedText {
    param ([string]$Value)
    if (-not $Value) { return $Value }
    return $Value -replace '(?i)(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|token|bearer|connectionstring)(\s*[:=]\s*)("[^"]*"|\S+)', '$1$2***REDACTED***'
}

function Write-AuditLog {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter()]
        [ValidateSet('INFO', 'WARNING', 'ERROR', 'VERBOSE')]
        [string]$Level = 'INFO'
    )

    $safeMessage = ConvertTo-RedactedText -Value $Message
    $logLine = '[{0}] [{1}] {2}' -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $safeMessage

    switch ($Level) {
        'INFO'    { Write-Information -MessageData $logLine -InformationAction Continue -Tags 'Invoke-RoslynAudit' }
        'WARNING' { Write-Warning $safeMessage }
        'ERROR'   { [System.Console]::Error.WriteLine($logLine) }
        'VERBOSE' { Write-Verbose $safeMessage }
    }

    if ($script:LogPathLocal) {
        try {
            if (-not $script:LogWriter) {
                $directory = Split-Path -Path $script:LogPathLocal -Parent -ErrorAction SilentlyContinue
                if ($directory) {
                    New-Item -Path $directory -ItemType Directory -Force -ErrorAction Stop | Out-Null
                }
                $fileStream = [System.IO.FileStream]::new($script:LogPathLocal, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
                $script:LogWriter = [System.IO.StreamWriter]::new($fileStream, [System.Text.UTF8Encoding]::new($false))
            }
            $script:LogWriter.WriteLine($logLine)
            $script:LogWriter.Flush()
        }
        catch {
            Write-Warning ("Failed to write to log file '{0}': {1}" -f $script:LogPathLocal, $_)
        }
    }
}

function Close-LogWriter {
    if ($script:LogWriter) {
        try     { $script:LogWriter.Dispose() }
        catch   { Write-Verbose ("Log writer dispose failed (ignored during teardown): {0}" -f $_) }
        finally { $script:LogWriter = $null }
    }
}

#endregion Logging

#region Bootstrap

function Test-RoslynLoaded {
    return ($null -ne ('Microsoft.CodeAnalysis.CSharp.CSharpSyntaxTree' -as [type]))
}

function Test-IsPS7OrLater {
    return ($PSVersionTable.PSVersion.Major -ge 6)
}

function Initialize-Workspace {
    foreach ($dir in @($script:WorkspacePath, $script:PackagesPath)) {
        if (-not (Test-Path -LiteralPath $dir)) {
            New-Item -Path $dir -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
    }
}

function Add-ZipSupport {
    if ('System.IO.Compression.ZipFile' -as [type]) { return }

    foreach ($asm in @('System.IO.Compression.ZipFile', 'System.IO.Compression.FileSystem', 'System.IO.Compression')) {
        try { Add-Type -AssemblyName $asm -ErrorAction Stop }
        catch { Write-Verbose ("Zip assembly probe failed for '{0}': {1}" -f $asm, $_) }
        if ('System.IO.Compression.ZipFile' -as [type]) { return }
    }
    throw 'Could not load System.IO.Compression.ZipFile support on this host.'
}

function Test-IsWindowsHost {
    if (Get-Variable -Name IsWindows -ErrorAction SilentlyContinue) { return $IsWindows }
    return $true
}

function Invoke-WithTls12 {
    param ([scriptblock]$Action)

    $previousProtocol = $null
    try {
        $previousProtocol = [Net.ServicePointManager]::SecurityProtocol
        [Net.ServicePointManager]::SecurityProtocol = $previousProtocol -bor [Net.SecurityProtocolType]::Tls12
    }
    catch {
        Write-Verbose ("TLS protocol configuration not applicable on this host: {0}" -f $_)
    }

    try { & $Action }
    finally {
        if ($null -ne $previousProtocol) {
            try { [Net.ServicePointManager]::SecurityProtocol = $previousProtocol }
            catch { Write-Verbose ("Could not restore TLS protocol policy: {0}" -f $_) }
        }
    }
}

function Invoke-WebDownload {
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSReviewUnusedParameter', '', Justification = 'Uri and OutFile are consumed inside a scriptblock closure; PSScriptAnalyzer cannot track this usage pattern.')]
    param ([string]$Uri, [string]$OutFile)
    Invoke-WithTls12 {
        $params = @{ ErrorAction = 'Stop' }
        if (-not (Test-IsPS7OrLater)) { $params['UseBasicParsing'] = $true }
        Invoke-WebRequest -Uri $Uri -OutFile $OutFile @params
    }
}

function Get-NugetExe {
    param ([string]$ExpectedHash, [bool]$ReuseCached)

    if (Test-Path -LiteralPath $script:NugetExePath) {
        if ($ExpectedHash) {
            $currentHash = (Get-FileHash -Path $script:NugetExePath -Algorithm SHA256).Hash
            if ($currentHash -eq $ExpectedHash) { return }
            Write-AuditLog "Existing nuget.exe hash mismatch ($currentHash vs expected $ExpectedHash). Re-downloading..." -Level WARNING
            Remove-Item -LiteralPath $script:NugetExePath -Force -ErrorAction SilentlyContinue
        }
        elseif ($ReuseCached) {
            Write-AuditLog 'Reusing cached nuget.exe (-ReuseCachedNuget specified).' -Level VERBOSE
            return
        }
        else {
            Write-AuditLog 'Existing nuget.exe present but -NugetHash not supplied; re-downloading (pass -ReuseCachedNuget to skip).' -Level VERBOSE
            Remove-Item -LiteralPath $script:NugetExePath -Force -ErrorAction SilentlyContinue
        }
    }

    Write-AuditLog 'Downloading nuget.exe...' -Level INFO
    $uri = 'https://dist.nuget.org/win-x86-commandline/latest/nuget.exe'
    try {
        Invoke-WebDownload -Uri $uri -OutFile $script:NugetExePath

        if ($ExpectedHash) {
            $downloadHash = (Get-FileHash -Path $script:NugetExePath -Algorithm SHA256).Hash
            if ($downloadHash -ne $ExpectedHash) {
                Remove-Item -LiteralPath $script:NugetExePath -Force -ErrorAction SilentlyContinue
                throw "Downloaded nuget.exe hash ($downloadHash) does not match expected SHA-256 ($ExpectedHash)."
            }
            Write-AuditLog 'nuget.exe SHA-256 checksum verified.' -Level INFO
        }
    }
    catch {
        throw "Failed to download or verify nuget.exe from $uri : $($_.Exception.Message)"
    }
}

function Write-PackageCompleteMarker {
    param ([string]$PackageDir)
    $marker = Join-Path $PackageDir '.extraction.complete'
    try {
        [System.IO.File]::WriteAllText($marker, (Get-Date).ToString('o'), [System.Text.UTF8Encoding]::new($false))
    }
    catch {
        Write-Verbose ("Failed to write extraction marker in '{0}': {1}" -f $PackageDir, $_)
    }
}

function Test-PackageComplete {
    param ([string]$PackageDir)
    return (Test-Path -LiteralPath (Join-Path $PackageDir '.extraction.complete'))
}

function Install-RoslynPackageDirect {
    $packages = @(
        'Microsoft.CodeAnalysis.Common',
        'Microsoft.CodeAnalysis.CSharp',
        'Microsoft.CodeAnalysis.VisualBasic'
    )

    Add-ZipSupport

    foreach ($package in $packages) {
        $pkgDir = Join-Path $script:PackagesPath ("{0}.{1}" -f $package, $script:PinnedPackageVersion)

        if ((Test-Path -LiteralPath $pkgDir) -and (Test-PackageComplete -PackageDir $pkgDir)) {
            continue
        }

        if (Test-Path -LiteralPath $pkgDir) {
            Write-AuditLog ("Removing incomplete extraction at '{0}'." -f $pkgDir) -Level WARNING
            Remove-Item -LiteralPath $pkgDir -Recurse -Force -ErrorAction Stop
        }

        Write-AuditLog ("Fetching {0} {1} directly from nuget.org..." -f $package, $script:PinnedPackageVersion) -Level INFO
        $nupkgPath = Join-Path $script:PackagesPath ("{0}.{1}.nupkg" -f $package, $script:PinnedPackageVersion)
        $uri = "https://www.nuget.org/api/v2/package/{0}/{1}" -f $package, $script:PinnedPackageVersion

        try {
            Invoke-WebDownload -Uri $uri -OutFile $nupkgPath
        }
        catch {
            throw "Failed to download '$package' from $uri : $($_.Exception.Message)"
        }

        try {
            [System.IO.Compression.ZipFile]::ExtractToDirectory($nupkgPath, $pkgDir)
        }
        catch {
            Remove-Item -LiteralPath $pkgDir -Recurse -Force -ErrorAction SilentlyContinue
            throw ("Extraction of '{0}' failed: {1}" -f $package, $_.Exception.Message)
        }
        finally {
            Remove-Item -LiteralPath $nupkgPath -Force -ErrorAction SilentlyContinue
        }

        Write-PackageCompleteMarker -PackageDir $pkgDir
        Write-AuditLog ("Extracted {0} to '{1}'." -f $package, $pkgDir) -Level INFO
    }
}

function Install-RoslynPackage {
    $packages = @('Microsoft.CodeAnalysis.CSharp', 'Microsoft.CodeAnalysis.VisualBasic')
    foreach ($package in $packages) {
        $marker = Join-Path $script:PackagesPath ("{0}.{1}" -f $package, $script:PinnedPackageVersion)
        if ((Test-Path -LiteralPath $marker) -and (Test-PackageComplete -PackageDir $marker)) { continue }

        Write-AuditLog ("Fetching {0} {1} via NuGet..." -f $package, $script:PinnedPackageVersion) -Level INFO
        $previousPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            & $script:NugetExePath 'install' $package -Version $script:PinnedPackageVersion -OutputDirectory $script:PackagesPath -NonInteractive -Verbosity quiet 2>&1 | Out-Null
            if ($LASTEXITCODE -ne 0) {
                throw ("nuget.exe install for '{0}' returned exit code {1}." -f $package, $LASTEXITCODE)
            }
        }
        finally {
            $ErrorActionPreference = $previousPreference
        }

        if (Test-Path -LiteralPath $marker) {
            Write-PackageCompleteMarker -PackageDir $marker
        }
    }
}

function Get-PreferredFrameworkOrder {
    if (Test-IsPS7OrLater) {
        return @('netstandard2.0', 'net8.0', 'net7.0', 'net6.0', 'net472', 'net461')
    }
    return @('net472', 'net462', 'net461', 'netstandard2.0')
}

function Resolve-RoslynFramework {
    param ([string[]]$SearchRoots, [string[]]$PreferredFrameworks)

    $probeFile = 'Microsoft.CodeAnalysis.dll'
    $candidates = New-Object System.Collections.Generic.List[System.IO.FileInfo]
    foreach ($root in $SearchRoots) {
        if (-not $root) { continue }
        if (-not (Test-Path -LiteralPath $root)) { continue }
        Get-ChildItem -Path $root -Filter $probeFile -Recurse -File -ErrorAction SilentlyContinue |
            ForEach-Object { $candidates.Add($_) }
    }

    foreach ($fw in $PreferredFrameworks) {
        $pattern = '[\\/]' + [regex]::Escape($fw) + '[\\/]?$'
        if ($candidates | Where-Object { $_.DirectoryName -match $pattern } | Select-Object -First 1) {
            return $fw
        }
    }
    return $null
}

function Find-RoslynAssembly {
    param (
        [string]$FileName,
        [string[]]$SearchRoots,
        [string[]]$PreferredFrameworks,
        [string]$FrameworkHint
    )

    $candidates = New-Object System.Collections.Generic.List[System.IO.FileInfo]
    foreach ($root in $SearchRoots) {
        if (-not $root) { continue }
        if (-not (Test-Path -LiteralPath $root)) { continue }
        Get-ChildItem -Path $root -Filter $FileName -Recurse -File -ErrorAction SilentlyContinue |
            ForEach-Object { $candidates.Add($_) }
    }

    if ($candidates.Count -eq 0) { return $null }

    if ($FrameworkHint) {
        $pattern = '[\\/]' + [regex]::Escape($FrameworkHint) + '[\\/]?$'
        $match = $candidates |
            Where-Object { $_.DirectoryName -match $pattern } |
            Sort-Object FullName |
            Select-Object -First 1
        if ($match) { return $match.FullName }
    }

    foreach ($fw in $PreferredFrameworks) {
        $pattern = '[\\/]' + [regex]::Escape($fw) + '[\\/]?$'
        $match = $candidates |
            Where-Object { $_.DirectoryName -match $pattern } |
            Sort-Object FullName |
            Select-Object -First 1
        if ($match) { return $match.FullName }
    }

    return ($candidates | Sort-Object FullName | Select-Object -First 1).FullName
}

function Import-RoslynAssembly {
    param ([string]$LocalPath)

    $searchRoots = New-Object System.Collections.Generic.List[string]
    if ($LocalPath -and (Test-Path -LiteralPath $LocalPath)) {
        $searchRoots.Add($LocalPath)
    }
    $searchRoots.Add($script:PackagesPath)

    $preferred = Get-PreferredFrameworkOrder
    $frameworkHint = Resolve-RoslynFramework -SearchRoots $searchRoots -PreferredFrameworks $preferred
    if ($frameworkHint) {
        Write-AuditLog ("Using Roslyn framework directory: {0}" -f $frameworkHint) -Level VERBOSE
    }

    if (-not (Test-IsPS7OrLater)) {
        $shims = @(
            'System.Collections.Immutable.dll',
            'System.Reflection.Metadata.dll',
            'System.Memory.dll',
            'System.Buffers.dll',
            'System.Numerics.Vectors.dll',
            'System.Runtime.CompilerServices.Unsafe.dll',
            'System.Text.Encoding.CodePages.dll',
            'System.Threading.Tasks.Extensions.dll'
        )
        foreach ($shim in $shims) {
            $path = Find-RoslynAssembly -FileName $shim -SearchRoots $searchRoots -PreferredFrameworks $preferred -FrameworkHint $frameworkHint
            if ($path) {
                try { Add-Type -Path $path -ErrorAction Stop }
                catch { Write-Verbose ("Shim '{0}' could not be loaded (may already be present): {1}" -f $shim, $_) }
            }
        }
    }

    $targets = @(
        @{ Name = 'Microsoft.CodeAnalysis';              Label = 'Core' }
        @{ Name = 'Microsoft.CodeAnalysis.CSharp';       Label = 'CSharp' }
        @{ Name = 'Microsoft.CodeAnalysis.VisualBasic';  Label = 'VisualBasic' }
    )

    $script:ResolvedRoslynPaths.Clear()

    foreach ($target in $targets) {
        $dll = Find-RoslynAssembly -FileName ($target.Name + '.dll') -SearchRoots $searchRoots -PreferredFrameworks $preferred -FrameworkHint $frameworkHint
        if (-not $dll) {
            throw ("Failed to locate required assembly '{0}.dll' in search paths: {1}" -f $target.Name, ($searchRoots -join '; '))
        }
        Write-Verbose ("Loading {0} from {1}" -f $target.Label, $dll)
        Add-Type -Path $dll -ErrorAction Stop
        $script:ResolvedRoslynPaths.Add($dll)
    }

    $coreVer = $null
    $csVer   = $null
    try {
        $coreVer = [Microsoft.CodeAnalysis.SyntaxTree].Assembly.GetName().Version
        $csVer   = [Microsoft.CodeAnalysis.CSharp.CSharpSyntaxTree].Assembly.GetName().Version
    }
    catch [System.Management.Automation.RuntimeException] {
        throw ("Roslyn type binding check failed after load: {0}" -f $_.Exception.Message)
    }
    if ($coreVer.Major -ne $csVer.Major -or $coreVer.Minor -ne $csVer.Minor) {
        throw ("Roslyn assembly version mismatch: Microsoft.CodeAnalysis {0} vs Microsoft.CodeAnalysis.CSharp {1}" -f $coreVer, $csVer)
    }
}

function Initialize-Roslyn {
    param ([string]$LocalPath, [string]$ExpectedHash, [bool]$ReuseCachedNuget)

    if (Test-RoslynLoaded) { return }
    Write-AuditLog 'Bootstrapping Roslyn engine...' -Level INFO

    if ($LocalPath -and (Test-Path -LiteralPath $LocalPath)) {
        Write-AuditLog ("Loading Roslyn assemblies from local path: '{0}'" -f $LocalPath) -Level INFO
        Import-RoslynAssembly -LocalPath $LocalPath
        return
    }

    Initialize-Workspace
    if (Test-IsWindowsHost) {
        Get-NugetExe -ExpectedHash $ExpectedHash -ReuseCached $ReuseCachedNuget
        Install-RoslynPackage
    }
    else {
        if ($ExpectedHash) {
            Write-AuditLog '-NugetHash applies to the Windows nuget.exe bootstrap only; direct download mode does not use nuget.exe.' -Level VERBOSE
        }
        Install-RoslynPackageDirect
    }
    Import-RoslynAssembly -LocalPath $LocalPath
}

#endregion Bootstrap

#region Input & Filters

function Get-AuditIgnoreList {
    param ([string]$IgnorePath, [string]$RootPath)
    $patterns = New-Object System.Collections.Generic.List[object]

    $targetFile = if ($IgnorePath) { $IgnorePath } else { Join-Path $RootPath '.auditignore' }
    if (Test-Path -LiteralPath $targetFile) {
        Write-AuditLog ("Loading suppression rules from '{0}'" -f $targetFile) -Level INFO
        Get-Content -LiteralPath $targetFile | ForEach-Object {
            $line = $_.Trim()
            if ($line -and -not $line.StartsWith('#')) {
                $patterns.Add((ConvertTo-IgnorePattern -Raw $line))
            }
        }
    }
    return $patterns
}

function ConvertTo-IgnorePattern {
    param ([string]$Raw)

    $hasGlobWild = $Raw -match '[*?]'
    $hasRegexMeta = $Raw -match '[(){}\[\]^$|+\\]'
    $hasRegexAnchor = $Raw -match '^[\^]' -or $Raw -match '[\$]$'

    if ($hasGlobWild -and -not $hasRegexMeta) {
        return [PSCustomObject]@{ Kind = 'glob'; Value = $Raw }
    }
    if ($hasRegexMeta -or $hasRegexAnchor) {
        return [PSCustomObject]@{ Kind = 'regex'; Value = $Raw }
    }
    return [PSCustomObject]@{ Kind = 'literal'; Value = $Raw }
}

function Test-IsIgnored {
    param ([string]$FilePath, $IgnorePatterns)

    foreach ($p in $IgnorePatterns) {
        switch ($p.Kind) {
            'glob' {
                if ($FilePath -like $p.Value) { return $true }
            }
            'literal' {
                if ($FilePath.IndexOf($p.Value, [System.StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
            }
            'regex' {
                try {
                    if ($FilePath -match $p.Value) { return $true }
                }
                catch {
                    Write-Verbose ("Invalid regex pattern '{0}' in ignore list; skipping." -f $p.Value)
                }
            }
            default {
                Write-Verbose ("Unknown ignore pattern kind '{0}' for '{1}'; skipping." -f $p.Kind, $p.Value)
            }
        }
    }
    return $false
}

function Get-GitRepoRoot {
    param ([string]$StartPath)
    try {
        $output = git -C $StartPath rev-parse --show-toplevel 2>$null
        if ($LASTEXITCODE -eq 0 -and $output) {
            return [string](@($output) | Select-Object -First 1).Trim()
        }
    }
    catch {
        Write-Verbose ("Git repo root detection failed: {0}" -f $_)
    }
    return $null
}

$script:AuditableExtensions = [System.Collections.Generic.HashSet[string]]::new(
    [string[]]@(
        '.cs','.vb','.ps1','.psm1',
        '.cpp','.cxx','.cc','.c','.hpp','.hxx','.hh','.h',
        '.py',
        '.xaml','.csproj','.props','.targets','.xml','.config'
    ),
    [System.StringComparer]::OrdinalIgnoreCase
)

function Test-IsAuditablePath {
    param ([string]$FilePath)
    if ([string]::IsNullOrWhiteSpace($FilePath)) { return $false }
    return $script:AuditableExtensions.Contains([System.IO.Path]::GetExtension($FilePath))
}

function Get-GitDiffFile {
    param ([string]$RepoRoot)

    if (-not (Get-Command -Name git -ErrorAction SilentlyContinue)) {
        Write-AuditLog 'Git executable not found on PATH; cannot diff.' -Level WARNING
        return $null
    }

    $root = Get-GitRepoRoot -StartPath $RepoRoot
    if (-not $root) {
        Write-AuditLog ("'{0}' is not inside a git work tree; cannot diff." -f $RepoRoot) -Level WARNING
        return $null
    }

    Write-AuditLog ('Executing Git diff detection (repository root: {0})...' -f $root) -Level INFO
    $files = New-Object System.Collections.Generic.List[string]

    try {
        $previousPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            $modified  = git -C $root diff --name-only HEAD 2>$null
            if ($LASTEXITCODE -ne 0) {
                throw ("git diff failed with exit code {0} (unborn HEAD or corrupt work tree)." -f $LASTEXITCODE)
            }
            $untracked = git -C $root ls-files --others --exclude-standard 2>$null
            if ($LASTEXITCODE -ne 0) {
                throw ("git ls-files failed with exit code {0}." -f $LASTEXITCODE)
            }
        }
        finally {
            $ErrorActionPreference = $previousPreference
        }

        @($modified) + @($untracked) |
            Where-Object { $_ -and (Test-IsAuditablePath -FilePath $_) } |
            ForEach-Object {
                $full = [System.IO.Path]::GetFullPath((Join-Path $root $_))
                if (Test-Path -LiteralPath $full) { $files.Add($full) }
            }
    }
    catch {
        Write-AuditLog ("Git command failed: {0}; falling back to full scan." -f $_) -Level WARNING
        return $null
    }

    return ,@($files.ToArray())
}

function Expand-AuditArchive {
    param ([string]$ArchivePath, [string]$Destination)
    Add-ZipSupport
    New-Item -Path $Destination -ItemType Directory -Force -ErrorAction Stop | Out-Null

    $zip = [System.IO.Compression.ZipFile]::OpenRead($ArchivePath)
    try {
        $destRoot = [System.IO.Path]::GetFullPath($Destination) + [System.IO.Path]::DirectorySeparatorChar
        $trimChars = [char[]]@('\', '/')
        foreach ($entry in $zip.Entries) {
            if ([string]::IsNullOrWhiteSpace($entry.Name)) { continue }
            $safeRelativePath = $entry.FullName.TrimStart($trimChars)
            $targetPath = [System.IO.Path]::GetFullPath([System.IO.Path]::Combine($Destination, $safeRelativePath))
            $comparison = if (Test-IsWindowsHost) { [System.StringComparison]::OrdinalIgnoreCase } else { [System.StringComparison]::Ordinal }
            if (-not $targetPath.StartsWith($destRoot, $comparison)) {
                throw ("Blocked path traversal attempt: {0}" -f $entry.FullName)
            }
            $dir = Split-Path -Path $targetPath -Parent
            if (-not (Test-Path -LiteralPath $dir)) { New-Item -Path $dir -ItemType Directory -Force -ErrorAction Stop | Out-Null }
            $fs = [System.IO.File]::Create($targetPath)
            try {
                $entryStream = $entry.Open()
                try { $entryStream.CopyTo($fs) } finally { $entryStream.Dispose() }
            }
            finally { $fs.Dispose() }
        }
    }
    finally { $zip.Dispose() }
    return $Destination
}

function Get-AuditTarget {
    if (-not (Test-Path -LiteralPath $Path)) { throw "Path not found: $Path" }
    $item = Get-Item -LiteralPath $Path
    if ($item.PSIsContainer) { return $item.FullName }
    if ($item.Extension -ieq '.zip') {
        $dest = Join-Path $script:ExtractPath ([System.IO.Path]::GetFileNameWithoutExtension($item.Name))
        if (Test-Path -LiteralPath $dest) { Remove-Item -LiteralPath $dest -Recurse -Force -ErrorAction Stop }
        return (Expand-AuditArchive -ArchivePath $item.FullName -Destination $dest)
    }
    return $item.FullName
}

function Get-SourceFile {
    param ([string]$Root, [switch]$GitOnly, $IgnoreList)
    $files = New-Object System.Collections.Generic.List[string]

    if (Test-Path -LiteralPath $Root -PathType Leaf) {
        if ($GitOnly) {
            $diffResult = Get-GitDiffFile -RepoRoot (Split-Path -Path $Root -Parent)
            if ($null -eq $diffResult) {
                Write-AuditLog 'Git diff unavailable; auditing the explicit file target.' -Level WARNING
            }
            elseif ($diffResult -notcontains $Root) {
                return $files
            }
        }
        if (-not (Test-IsIgnored -FilePath $Root -IgnorePatterns $IgnoreList)) {
            $files.Add($Root)
        }
        return $files
    }

    $candidates = $null
    if ($GitOnly) {
        $candidates = Get-GitDiffFile -RepoRoot $Root
        if ($null -eq $candidates) {
            Write-AuditLog 'Falling back to a full directory scan.' -Level WARNING
        }
    }

    if ($null -eq $candidates) {
        $candidates = Get-ChildItem -Path $Root -Recurse -File -ErrorAction SilentlyContinue |
            Where-Object { Test-IsAuditablePath -FilePath $_.FullName } |
            ForEach-Object { $_.FullName }
    }

    foreach ($file in $candidates) {
        if (-not (Test-IsIgnored -FilePath $file -IgnorePatterns $IgnoreList)) {
            $files.Add($file)
        }
    }
    return $files
}

#endregion Input & Filters

#region Audit Engine & AST Syntax Walkers

function Get-RuleSet {
    param ([string]$PackPath)

    $rules = New-Object System.Collections.Generic.List[object]
    $ruleIndex = @{}
    $validSeverities = @('ERROR', 'WARNING', 'INFO')

    $builtin = @(
        @{ Id = 'RA001'; Severity = 'ERROR';   Pattern = '(?s)catch\s*(\([^)]*\))?\s*\{\s{0,200}\}';  Remediation = 'Handle the exception (log, wrap, or rethrow). An empty catch hides failures; at minimum log it with context.'; Message = 'Empty catch block swallows exceptions.' }
        @{ Id = 'RA002'; Severity = 'WARNING'; Pattern = 'async\s+void\s+\w+';                     Remediation = 'Return Task instead of async void; if an event handler must be async void, wrap the body in try/catch.'; Message = 'async void method (unobserved exceptions).' }
        @{ Id = 'RA003'; Severity = 'WARNING'; Pattern = 'Thread\.Sleep\s*\(';                     Remediation = 'Use await Task.Delay or a timer instead of blocking the thread with Thread.Sleep.'; Message = 'Thread.Sleep blocks a thread.' }
        @{ Id = 'RA004'; Severity = 'WARNING'; Pattern = 'GC\.Collect\s*\(';                       Remediation = 'Remove the explicit GC.Collect call; rely on the GC or fix the allocation pattern.'; Message = 'Explicit GC.Collect call.' }
        @{ Id = 'RA005'; Severity = 'INFO';    Pattern = 'Process\.Start\s*\(';                    Remediation = 'Review the process launch: validate and quote arguments, use full executable paths, never pass untrusted input to the command line.'; Message = 'External process launch.' }
        @{ Id = 'RA006'; Severity = 'ERROR';   Pattern = '(?i)(password|passwd|pwd|secret|api[_-]?key|access[_-]?key|token)\s*[:=]\s*"(?!__REDACTED_SECRET__)[^"]{6,}"'; Remediation = 'Move the secret to environment variables, configuration, or a secrets store; rotate any value already committed.'; Message = 'Potential hardcoded secret. Value withheld.' }
        @{ Id = 'RA007'; Severity = 'WARNING'; Pattern = '(?i)\b(MD5|SHA1|Rijndael|DES|RC2|TripleDES)\b'; Remediation = 'Use SHA-256 or newer for hashes and AES-GCM for encryption; MD5/SHA1/DES are cryptographically broken.'; Message = 'Weak/legacy crypto primitive referenced.' }
        @{ Id = 'RA008'; Severity = 'INFO';    Pattern = 'Console\.WriteLine\s*\(';                Remediation = 'Prefer structured logging; ensure credentials and PII never reach console output.'; Message = 'Console output (possible sensitive data exposure).' }
        @{ Id = 'RA009'; Severity = 'WARNING'; Pattern = '\.Result\b|\.Wait\s*\(';                 Remediation = 'Await the task instead of blocking on .Result or .Wait to avoid deadlocks and thread starvation.'; Message = 'Sync-over-async blocking (bottleneck).' }
        @{ Id = 'RA010'; Severity = 'INFO';    Pattern = 'Convert\.ToBase64String\s*\(';           Remediation = 'Verify the purpose; Base64 is not encryption - use proper key management when protecting data.'; Message = 'Base64 encoding (possible exfil pattern).' }
        @{ Id = 'RA011'; Severity = 'WARNING'; Pattern = '\bunsafe\s+(?:\{|class\b|struct\b|interface\b|void\b|int\b|long\b|short\b|byte\b|char\b|float\b|double\b|decimal\b|bool\b|string\b|static\b|public\b|private\b|protected\b|internal\b|sealed\b|readonly\b|fixed\b|delegate\b|event\b)'; Remediation = 'Prefer safe managed constructs (Span<T>, Memory<T>); if unsafe is unavoidable, bound-check every pointer access.'; Message = 'Unsafe/pointer code bypasses memory safety.' }
        @{ Id = 'RA012'; Severity = 'WARNING'; Pattern = '\block\s*\(\s*(this|typeof\s*\([^)]+\))\s*\)'; Remediation = 'Lock on a private, dedicated readonly object (private static readonly object _sync = new object()).'; Message = 'Lock on a publicly visible object (this / typeof) - deadlock risk.' }
        @{ Id = 'RA013'; Severity = 'ERROR';   Pattern = '\bThread\.Abort\s*\(';                   Remediation = 'Use cooperative cancellation (CancellationToken) instead of Thread.Abort.'; Message = 'Thread.Abort is unsafe and unsupported on .NET Core / .NET 5+.' }
        @{ Id = 'RA014'; Severity = 'WARNING'; Pattern = '\bthrow\s+([A-Za-z_]\w*)\s*;';           Remediation = 'Use bare throw; to preserve the original stack trace, or throw new Exception("...", ex) to wrap.'; Message = 'Rethrowing a caught exception by name resets the stack trace; use bare throw; instead.' }
        @{ Id = 'RA015'; Severity = 'INFO';    Pattern = 'catch\s*\(\s*Exception(\s+\w+)?\s*\)\s*\{'; Remediation = 'Catch specific exception types; if a catch-all is required, log and rethrow appropriately.'; Message = 'Broad catch(Exception) may hide specific failures.' }
        @{ Id = 'RA016'; Severity = 'ERROR';   Pattern = '\bBinaryFormatter\b';                    Remediation = 'Migrate to System.Text.Json or another safe serializer; BinaryFormatter deserialization of untrusted data is remote code execution.'; Message = 'BinaryFormatter is insecure and removed in .NET 9+.' }
        @{ Id = 'RA017'; Severity = 'WARNING'; Pattern = '\.LoadXml\s*\(';                         Remediation = 'Disable DTD processing and external entities: XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null }.'; Message = 'XmlDocument.LoadXml defaults permit external entity resolution (XXE).' }
        @{ Id = 'RA018'; Severity = 'WARNING'; Pattern = '\bXDocument\.Load\s*\(';                 Remediation = 'Pass an XmlReader with DtdProcessing.Prohibit and XmlResolver = null.'; Message = 'XDocument.Load without XmlReaderSettings permits XXE.' }
        @{ Id = 'RA019'; Severity = 'WARNING'; Pattern = '\bnew\s+(?:[A-Za-z_]\w*\.)*HttpClient\s*\('; Remediation = 'Use IHttpClientFactory (DI) or a single static HttpClient instance.'; Message = 'New HttpClient per call can exhaust sockets (TIME_WAIT).' }
        @{ Id = 'RA020'; Severity = 'INFO';    Pattern = '\bnew\s+Regex\s*\(';                     Remediation = 'Pass a RegexOptions and a TimeSpan timeout: new Regex(pattern, options, TimeSpan.FromSeconds(2)).'; Message = 'Regex construction - verify a match timeout is set (ReDoS risk).' }
        @{ Id = 'RA021'; Severity = 'INFO';    Pattern = '\bDateTime\.Now\b';                      Remediation = 'Use DateTime.UtcNow / DateTimeOffset.UtcNow; convert to local time at the UI boundary only.'; Message = 'DateTime.Now is timezone-dependent; prefer UtcNow for persistence and comparison.' }
        @{ Id = 'RA022'; Severity = 'WARNING'; Pattern = '\bEnvironment\.Exit\s*\(';               Remediation = 'Return a status code / throw an exception; let the host decide when to exit.'; Message = 'Environment.Exit terminates the process abruptly; unsafe in library code.' }
        @{ Id = 'RA023'; Severity = 'INFO';    Pattern = '\bDebug\.Assert\s*\(';                   Remediation = 'Use runtime validation (throw ArgumentException) for inputs that must be validated in production.'; Message = 'Debug.Assert is stripped in release builds; do not rely on it for validation.' }
        @{ Id = 'RA024'; Severity = 'WARNING'; Pattern = '\bAssembly\.(LoadFrom|LoadFile|UnsafeLoadFrom)\s*\('; Remediation = 'Validate assembly paths and strong names; prefer AssemblyLoadContext with explicit resolution.'; Message = 'Assembly.LoadFrom/LoadFile can load untrusted code.' }
        @{ Id = 'RA025'; Severity = 'INFO';    Pattern = '\b(SHA256|SHA384|SHA512|MD5|SHA1)\.Create\s*\(\s*\)'; Remediation = 'Prefer SHA256.HashData(data) / SHA256.TryHashData(...) (static, allocation-free).'; Message = 'Creating a hash algorithm per call is wasteful; use the static one-shot API.' }
        @{ Id = 'RA026'; Severity = 'WARNING'; Pattern = '\bRNGCryptoServiceProvider\b';           Remediation = 'Use RandomNumberGenerator.GetBytes / GetInt32 (static, modern).'; Message = 'RNGCryptoServiceProvider is legacy; use RandomNumberGenerator static APIs.' }
        @{ Id = 'RA027'; Severity = 'WARNING'; Pattern = '\bWebClient\b';                          Remediation = 'Replace WebClient with HttpClient (via IHttpClientFactory).'; Message = 'WebClient is deprecated; use HttpClient.' }
        @{ Id = 'RA028'; Severity = 'WARNING'; Pattern = '\bWebRequest\.Create\s*\(|\bHttpWebRequest\b'; Remediation = 'Use HttpClient.'; Message = 'WebRequest / HttpWebRequest are deprecated.' }
        @{ Id = 'RA029'; Severity = 'WARNING'; Pattern = '(?i)"\s*(SELECT|INSERT|UPDATE|DELETE)\b[^"]*"\s*\+\s*\w+'; Remediation = 'Use parameterized queries (SqlCommand.Parameters, Dapper, EF Core); never concatenate user input into SQL. This rule detects the most common inline-concatenation form only; predicate fragments (e.g. "WHERE id = " + x) and interpolated strings are not caught.'; Message = 'SQL built by string concatenation - SQL injection risk.' }
        @{ Id = 'RA030'; Severity = 'INFO';    Pattern = '(?i)"\s*SELECT\s+\*\s+FROM';             Remediation = 'List the required columns explicitly.'; Message = 'SELECT * pulls unneeded columns and is brittle to schema changes.' }

        @{ Id = 'RA201'; Severity = 'ERROR';   Pattern = '(?i)\bInvoke-Expression\b|\biex\b';                                          Remediation = 'Remove Invoke-Expression/iex; use parameterized invocation or switch-based dispatch.'; Message = 'Dynamic code execution (Invoke-Expression injection).' }
        @{ Id = 'RA202'; Severity = 'WARNING'; Pattern = '(?i)-AsPlainText\s+-Force';                                                  Remediation = 'Use DPAPI or a secrets vault; never convert SecureString with AsPlainText -Force.'; Message = 'Insecure SecureString conversion to plain text.' }
        @{ Id = 'RA203'; Severity = 'WARNING'; Pattern = '(?i)\[System\.Net\.ServicePointManager\]::ServerCertificateValidationCallback'; Remediation = 'Remove the certificate validation override and fix the certificate chain instead.'; Message = 'Disabling SSL/TLS certificate validation.' }
        @{ Id = 'RA204'; Severity = 'INFO';    Pattern = '(?i)\bSet-ExecutionPolicy\b';                                              Remediation = 'Set execution policy at machine provisioning time, not inside scripts.'; Message = 'Execution policy mutation inside script execution.' }
        @{ Id = 'RA211'; Severity = 'ERROR';   Pattern = '(?i)\.(DownloadString|DownloadFile|DownloadData)\s*\(';                       Remediation = 'Use Invoke-WebRequest/Invoke-RestMethod with TLS validation; if WebClient is required, validate TLS and source.'; Message = 'WebClient download methods are a common malware staging primitive.' }
        @{ Id = 'RA212'; Severity = 'WARNING'; Pattern = '(?i)New-Object\s+System\.Net\.WebClient|\[System\.Net\.WebClient\]';         Remediation = 'Use Invoke-WebRequest/Invoke-RestMethod.'; Message = 'WebClient instantiation - deprecated and commonly abused.' }
        @{ Id = 'RA213'; Severity = 'WARNING'; Pattern = '(?i)Start-Process\b[^\n]*-Verb\s+RunAs';                                    Remediation = 'Do not elevate silently; deploy with a manifest or an explicit admin context.'; Message = 'UAC elevation via -Verb RunAs in script code.' }
        @{ Id = 'RA214'; Severity = 'INFO';    Pattern = '(?i)Invoke-Command\b[^\n]*-ComputerName';                                   Remediation = 'Verify the target host list and credential source; prefer -Session over per-call -ComputerName for repeated calls.'; Message = 'Remote command execution (Invoke-Command).' }
        @{ Id = 'RA215'; Severity = 'INFO';    Pattern = '(?i)\bEnter-PSSession\b';                                                   Remediation = 'Use Invoke-Command for automation; Enter-PSSession is for interactive use only.'; Message = 'Interactive remote PowerShell session.' }
        @{ Id = 'RA216'; Severity = 'INFO';    Pattern = '(?i)\bNew-PSSession\b';                                                     Remediation = 'Dispose sessions with Remove-PSSession in a finally block.'; Message = 'Persistent remote PowerShell session created.' }
        @{ Id = 'RA217'; Severity = 'WARNING'; Pattern = '(?i)Add-Type\b[^\n]*-TypeDefinition';                                       Remediation = 'Ship pre-compiled assemblies; runtime compilation is hard to audit and slows startup.'; Message = 'Runtime C# compilation via Add-Type -TypeDefinition.' }
        @{ Id = 'RA218'; Severity = 'WARNING'; Pattern = '(?i)\[System\.Reflection\.Assembly\]::(Load|LoadFrom|LoadFile)';             Remediation = 'Validate assembly paths and strong names; prefer static references.'; Message = 'Reflection assembly load - can run untrusted code.' }
        @{ Id = 'RA219'; Severity = 'ERROR';   Pattern = '(?i)Set-ExecutionPolicy\s+(Unrestricted|Bypass)\b';                          Remediation = 'Set execution policy at machine provisioning; never weaken it inside a script.'; Message = 'Execution policy weakened to Unrestricted/Bypass.' }
        @{ Id = 'RA220'; Severity = 'WARNING'; Pattern = '(?i)-ExecutionPolicy\s+Bypass';                                              Remediation = 'Sign scripts and use RemoteSigned or AllSigned policy instead.'; Message = '-ExecutionPolicy Bypass - bypasses script signing policy.' }
        @{ Id = 'RA221'; Severity = 'WARNING'; Pattern = '(?i)\$env:PATH\s*(=|\+=)';                                                  Remediation = 'Prefer absolute paths and full command names; if PATH must change, scope it tightly.'; Message = 'Modifying $env:PATH can redirect command resolution.' }
        @{ Id = 'RA222'; Severity = 'WARNING'; Pattern = '(?i)\bRegister-ScheduledTask\b|\bschtasks\b';                              Remediation = 'Justify the persistence; document the task, owner, and trigger; audit at install time.'; Message = 'Scheduled task creation - common persistence mechanism.' }
        @{ Id = 'RA223'; Severity = 'WARNING'; Pattern = '(?i)\bNew-Service\b|\bsc\.exe\s+create\b';                                  Remediation = 'Install services via the MSI/installer; document the service account and required privileges.'; Message = 'Service creation - persistence / privilege escalation primitive.' }
        @{ Id = 'RA224'; Severity = 'INFO';    Pattern = '(?i)\bGet-WmiObject\b';                                                     Remediation = 'Use Get-CimInstance.'; Message = 'Get-WmiObject is deprecated on PowerShell 7.' }
        @{ Id = 'RA225'; Severity = 'WARNING'; Pattern = '(?i)\bInvoke-WmiMethod\b';                                                  Remediation = 'Use Invoke-CimMethod with a reviewed class/parameters.'; Message = 'Invoke-WmiMethod is deprecated and can execute remote code.' }
        @{ Id = 'RA226'; Severity = 'WARNING'; Pattern = '(?i)\bwmic\b';                                                              Remediation = 'Use Get-CimInstance / Invoke-CimMethod.'; Message = 'wmic.exe is deprecated and often used for lateral movement.' }
        @{ Id = 'RA227'; Severity = 'WARNING'; Pattern = '(?i)\bnet\s+(user|localgroup)\b';                                           Remediation = 'Use ActiveDirectory or LocalAccounts cmdlets; log the change with the target account and group.'; Message = 'net user / net localgroup manipulation - account/group modification.' }
        @{ Id = 'RA228'; Severity = 'WARNING'; Pattern = '(?i)\breg\s+(add|delete)\b';                                                Remediation = 'Use New-ItemProperty / Remove-ItemProperty; prefer HKCU over HKLM, and scope to the app hive.'; Message = 'Registry modification via reg.exe.' }
        @{ Id = 'RA229'; Severity = 'ERROR';   Pattern = '(?i)-EncodedCommand\b|-enc\s+[A-Za-z0-9+/=]{20,}';                          Remediation = 'Remove obfuscation; ship plaintext script blocks under source control.'; Message = 'Base64-encoded command - obfuscation/malware staging indicator.' }
        @{ Id = 'RA230'; Severity = 'INFO';    Pattern = '(?i)-WindowStyle\s+Hidden';                                                 Remediation = 'Only hide windows for legitimate scheduled tasks; document the reason.'; Message = 'Hidden window style - may conceal execution.' }

        @{ Id = 'RA301'; Severity = 'WARNING'; Pattern = '(?i)\b(strcpy|strcat|sprintf|vsprintf|gets)\s*\(';   Remediation = 'Use bounds-checked variants (snprintf, std::string, strlcpy) - these functions are the classic buffer-overflow primitives.'; Message = 'Legacy unsafe C/C++ function (buffer overflow risk).' }
        @{ Id = 'RA302'; Severity = 'INFO';    Pattern = '(?i)\bsystem\s*\(';                                  Remediation = 'Launch processes with validated, quoted arguments (execvp/CreateProcess); never pass untrusted input to system().'; Message = 'External process launch via system().' }
        @{ Id = 'RA306'; Severity = 'ERROR';   Pattern = '\[([A-Za-z0-9][A-Za-z0-9._\-]*)\]\(https?://\1(?=/|\))\)'; Remediation = 'Chat/markdown auto-linking pasted over the code. Run Invoke-RoslynFix to demangle automatically - it verifies the result.'; Message = 'Markdown auto-link corruption in source/config file (chat paste artifact).' }
        @{ Id = 'RA311'; Severity = 'WARNING'; Pattern = '\balloca\s*\(';                                      Remediation = 'Use a fixed-size buffer or heap allocation; never pass user-controlled sizes to alloca.'; Message = 'alloca allocates on the stack and can overflow it.' }
        @{ Id = 'RA312'; Severity = 'ERROR';   Pattern = '\bscanf\s*\([^)]*%s';                                 Remediation = 'Use fgets with an explicit size, or scanf with a width specifier (e.g. %31s).'; Message = 'scanf with %s has no bounds - classic buffer overflow.' }
        @{ Id = 'RA313'; Severity = 'WARNING'; Pattern = '\bprintf\s*\(\s*\w+\s*\)';                            Remediation = 'Use printf("%s", input) or puts(input); never pass user data as the format string.'; Message = 'printf with a non-literal format string - format-string vulnerability.' }
        @{ Id = 'RA314'; Severity = 'WARNING'; Pattern = '\bpopen\s*\(';                                       Remediation = 'Validate and quote all arguments; prefer posix_spawn/execvp with an explicit argv.'; Message = 'popen launches a shell - command injection risk.' }
        @{ Id = 'RA315'; Severity = 'INFO';    Pattern = '\b(exec[lv]p?e?|execl|execle|execlp|execv|execve|execvp)\s*\('; Remediation = 'Pass a fixed argv array; validate every user-influenced element.'; Message = 'Process replacement via exec* - verify argv and environment.' }
        @{ Id = 'RA316'; Severity = 'WARNING'; Pattern = '\b(setuid|setgid|seteuid|setegid|setreuid|setregid)\s*\('; Remediation = 'Drop privileges as early as possible and only after all privileged operations; verify the effective UID/GID.'; Message = 'Privilege change - must be audited carefully.' }
        @{ Id = 'RA317'; Severity = 'WARNING'; Pattern = '\bchmod\s*\([^,]+,\s*0?777\b';                        Remediation = 'Grant the minimum required permissions (e.g. 0644 or 0600).'; Message = 'World-writable permissions.' }
        @{ Id = 'RA318'; Severity = 'WARNING'; Pattern = '\b(mktemp|tmpnam|tempnam)\s*\(';                      Remediation = 'Use mkstemp/mkdtemp or the platform secure temp API.'; Message = 'mktemp/tmpnam are insecure (TOCTOU race).' }
        @{ Id = 'RA319'; Severity = 'INFO';    Pattern = '\bstrncpy\s*\(';                                      Remediation = 'Explicitly set the last byte to \\0, or use snprintf with a sized buffer.'; Message = 'strncpy does not guarantee null-termination.' }
        @{ Id = 'RA320'; Severity = 'INFO';    Pattern = '\bmemcpy\s*\([^,]+,[^,]+,\s*[a-zA-Z_]\w*\s*\)';      Remediation = 'Ensure the destination is at least len bytes; consider memcpy_s or a checked wrapper.'; Message = 'memcpy with a variable size - verify bounds.' }
        @{ Id = 'RA321'; Severity = 'INFO';    Pattern = '\b(\w+)\s*=\s*realloc\s*\(\s*\1\s*,';                 Remediation = 'Use a temporary: tmp = realloc(p, n); if (!tmp) { /* handle */ } p = tmp;'; Message = 'realloc to the same pointer leaks the original on failure.' }
        @{ Id = 'RA322'; Severity = 'INFO';    Pattern = '\bassert\s*\(';                                       Remediation = 'Use runtime checks (return codes, exceptions) for input validation; reserve assert for internal invariants.'; Message = 'assert is stripped in NDEBUG builds.' }

        @{ Id = 'RA303'; Severity = 'WARNING'; Pattern = '(?m)^\s*except\s*:';                                  Remediation = 'Catch specific exception types - a bare except hides programming errors and interrupts.'; Message = 'Python bare except clause swallows exceptions.' }
        @{ Id = 'RA304'; Severity = 'ERROR';   Pattern = '(?i)\b(eval|exec)\s*\(';                              Remediation = 'Use ast.literal_eval for trusted literals, or restructure with functions/dictionaries; eval/exec executes arbitrary code.'; Message = 'Python dynamic code execution (eval/exec).' }
        @{ Id = 'RA305'; Severity = 'WARNING'; Pattern = '(?i)\bpickle\.loads?\s*\(';                           Remediation = 'Use JSON/msgpack - pickle deserialization of untrusted data executes arbitrary code.'; Message = 'Python pickle deserialization of untrusted data.' }
        @{ Id = 'RA411'; Severity = 'ERROR';   Pattern = '\bos\.system\s*\(';                                   Remediation = 'Use subprocess.run([...], shell=False) with a validated argv list.'; Message = 'os.system launches a shell - command injection risk.' }
        @{ Id = 'RA412'; Severity = 'ERROR';   Pattern = '(?s)subprocess\.(call|run|Popen|check_call|check_output)\s*\(.{0,200}?shell\s*=\s*True'; Remediation = 'Pass shell=False and an argv list; never interpolate user data into a shell command.'; Message = 'subprocess with shell=True - command injection risk.' }
        @{ Id = 'RA413'; Severity = 'WARNING'; Pattern = 'subprocess\.Popen\s*\(\s*["'']';                     Remediation = 'Pass a list of arguments and shell=False.'; Message = 'subprocess.Popen with a string argument - fragile quoting.' }
        @{ Id = 'RA414'; Severity = 'WARNING'; Pattern = '\bos\.popen\s*\(';                                    Remediation = 'Use subprocess.run with shell=False.'; Message = 'os.popen is deprecated and shell-based.' }
        @{ Id = 'RA415'; Severity = 'WARNING'; Pattern = '\b__import__\s*\(|\bimportlib\.import_module\s*\(';   Remediation = 'Use explicit imports; if dynamic loading is required, allow-list module names.'; Message = 'Dynamic import - hard to audit; can load untrusted modules.' }
        @{ Id = 'RA416'; Severity = 'INFO';    Pattern = '\bgetattr\s*\(\s*[^,]+,\s*\w+\s*\)';                 Remediation = 'Allow-list attribute names; never pass user input directly to getattr.'; Message = 'getattr with a variable name - verify the input source.' }
        @{ Id = 'RA417'; Severity = 'INFO';    Pattern = '\bsetattr\s*\(\s*[^,]+,\s*\w+\s*,';                  Remediation = 'Allow-list attribute names; never pass user input directly to setattr.'; Message = 'setattr with a variable name - verify the input source.' }
        @{ Id = 'RA418'; Severity = 'INFO';    Pattern = '\b(globals|locals)\s*\(\s*\)';                        Remediation = 'Use explicit dictionaries or namespaces.'; Message = 'globals()/locals() usage - often indicates dynamic scope manipulation.' }
        @{ Id = 'RA419'; Severity = 'INFO';    Pattern = '\byaml\.load\s*\(';                                   Remediation = 'In PyYAML < 6, yaml.load without an explicit Loader defaults to the unsafe loader and can execute arbitrary objects. Use yaml.safe_load or pass Loader=yaml.SafeLoader. This rule fires on every yaml.load call - verify the Loader argument by hand.'; Message = 'yaml.load() called - verify Loader=SafeLoader is passed (or use yaml.safe_load).' }
        @{ Id = 'RA420'; Severity = 'WARNING'; Pattern = '\bmarshal\.loads?\s*\(';                              Remediation = 'Use JSON or another safe format; never unmarshal untrusted input.'; Message = 'marshal can execute arbitrary bytecode on load.' }
        @{ Id = 'RA421'; Severity = 'WARNING'; Pattern = '\bshelve\.open\s*\(';                                 Remediation = 'Use sqlite3 or JSON for persistent storage of untrusted data.'; Message = 'shelve uses pickle internally - unsafe for untrusted data.' }
        @{ Id = 'RA422'; Severity = 'WARNING'; Pattern = '\bdill\.loads?\s*\(';                                 Remediation = 'Use a safe format (JSON, msgpack); never deserialize untrusted pickle/dill payloads.'; Message = 'dill deserialization of untrusted data executes code.' }
        @{ Id = 'RA423'; Severity = 'ERROR';   Pattern = '\brequests\.\w+\s*\([^)]*verify\s*=\s*False';         Remediation = 'Remove verify=False and fix the certificate chain; if a custom CA is required, pass verify="/path/to/ca.pem".'; Message = 'TLS certificate verification disabled.' }
        @{ Id = 'RA424'; Severity = 'ERROR';   Pattern = 'ssl\._create_unverified_context\s*\(';                Remediation = 'Use ssl.create_default_context() and pass a proper CA bundle.'; Message = 'Unverified TLS context - disables certificate checks.' }
        @{ Id = 'RA425'; Severity = 'WARNING'; Pattern = '\bhashlib\.(md5|sha1)\s*\(';                          Remediation = 'Use hashlib.sha256 (or better) for integrity; use argon2/bcrypt/scrypt for passwords.'; Message = 'MD5/SHA-1 are cryptographically broken.' }
        @{ Id = 'RA426'; Severity = 'WARNING'; Pattern = '\brandom\.(random|randint|choice|shuffle|sample)\s*\('; Remediation = 'Use secrets.token_bytes / secrets.choice for security-sensitive values.'; Message = 'random module is not cryptographically secure.' }
        @{ Id = 'RA427'; Severity = 'WARNING'; Pattern = '\btempfile\.mktemp\s*\(';                             Remediation = 'Use tempfile.NamedTemporaryFile or tempfile.mkstemp.'; Message = 'tempfile.mktemp is insecure (TOCTOU race).' }
        @{ Id = 'RA428'; Severity = 'WARNING'; Pattern = '\bos\.chmod\s*\([^,]+,\s*0?o?777\b';                  Remediation = 'Use 0o644 / 0o600 unless world-write is explicitly required.'; Message = 'World-writable permissions.' }
        @{ Id = 'RA429'; Severity = 'WARNING'; Pattern = '\bos\.(setuid|setgid|seteuid|setegid)\s*\(';          Remediation = 'Drop privileges as early as possible; verify effective UID/GID after the call.'; Message = 'Privilege change - audit carefully.' }
        @{ Id = 'RA430'; Severity = 'ERROR';   Pattern = '\.execute\s*\(\s*f["''][^"'']*\{';                    Remediation = 'Use parameterized queries: cursor.execute("SELECT ... WHERE x = ?", (user_input,)).'; Message = 'SQL built with an f-string - SQL injection risk.' }

        @{ Id = 'RA501'; Severity = 'INFO';    Pattern = '(?i)\b(TODO|FIXME|HACK|XXX)\b\s*:';                   Remediation = 'Track in the issue tracker; remove before release or convert to a documented work item.'; Message = 'TODO/FIXME/HACK marker.' }
        @{ Id = 'RA503'; Severity = 'WARNING'; Pattern = '(?<!xmlns\s*=\s*)(?<!xmlns:[a-zA-Z]+\s*=\s*)["''\(]http://[a-zA-Z0-9]'; Remediation = 'Use https:// (or a vetted local protocol like file://, unix://).'; Message = 'Plain HTTP URL - no transport security.' }
        @{ Id = 'RA504'; Severity = 'INFO';    Pattern = '(?i)\b(?:host|ip|endpoint|address|server|url|target|gateway|dns)\s*[:=]\s*["'']?\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'; Remediation = 'Move to configuration; validate the address at startup.'; Message = 'Hardcoded IP address.' }
    )
    foreach ($r in $builtin) {
        $rules.Add([PSCustomObject]$r)
        $ruleIndex[$r.Id] = $rules.Count - 1
    }

    if (-not $PackPath -or -not (Test-Path -LiteralPath $PackPath)) {
        return $rules
    }

    try {
        $pack = Get-Content -LiteralPath $PackPath -Raw | ConvertFrom-Json
    }
    catch {
        throw ("Failed to parse rule pack '{0}': {1}" -f $PackPath, $_.Exception.Message)
    }

    if ($null -eq $pack) {
        Write-AuditLog ("Rule pack '{0}' contains null; no custom rules loaded." -f $PackPath) -Level WARNING
        return $rules
    }

    $packRules = @()
    if ($pack -is [System.Array]) {
        $packRules = @($pack)
    }
    elseif ($null -ne $pack.PSObject.Properties['Rules']) {
        $rulesValue = $pack.Rules
        if ($null -ne $rulesValue) { $packRules = @($rulesValue) }
    }
    else {
        $packRules = @($pack)
    }

    foreach ($rule in $packRules) {
        if ($null -eq $rule) { continue }

        $idProp          = $rule.PSObject.Properties['Id']
        $severityProp    = $rule.PSObject.Properties['Severity']
        $patternProp     = $rule.PSObject.Properties['Pattern']
        $messageProp     = $rule.PSObject.Properties['Message']
        $remediationProp = $rule.PSObject.Properties['Remediation']

        $id       = if ($null -ne $idProp)       { [string]$idProp.Value }       else { '' }
        $severity = if ($null -ne $severityProp) { [string]$severityProp.Value } else { '' }
        $pattern  = if ($null -ne $patternProp)  { [string]$patternProp.Value }  else { '' }
        $message  = if ($null -ne $messageProp)  { [string]$messageProp.Value }  else { '' }
        $remediation = if ($null -ne $remediationProp -and $remediationProp.Value) { [string]$remediationProp.Value } else { 'Review the matched line and apply the rule policy.' }

        if ([string]::IsNullOrWhiteSpace($id)) {
            Write-AuditLog ("Skipping rule pack entry with missing Id in '{0}'." -f $PackPath) -Level WARNING
            continue
        }
        if ([string]::IsNullOrWhiteSpace($pattern)) {
            Write-AuditLog ("Skipping rule '{0}' with missing Pattern." -f $id) -Level WARNING
            continue
        }
        if ($severity -notin $validSeverities) {
            throw ("Rule '{0}' has invalid Severity '{1}' (expected ERROR, WARNING, or INFO)." -f $id, $severity)
        }

        $entry = [PSCustomObject]@{
            Id          = $id
            Severity    = $severity
            Pattern     = $pattern
            Message     = $message
            Remediation = $remediation
        }

        if ($ruleIndex.ContainsKey($id)) {
            $rules[$ruleIndex[$id]] = $entry
        }
        else {
            $rules.Add($entry)
            $ruleIndex[$id] = $rules.Count - 1
        }
    }

    return $rules
}

$script:WorkerScript = @'
param ([string]$FilePath, $Rules, [string[]]$RoslynAssemblyPaths, [int]$RegexTimeoutMs, [string]$CxxCompiler, [string]$PythonExe)

if (-not ('Microsoft.CodeAnalysis.CSharp.CSharpSyntaxTree' -as [type])) {
    if ($RoslynAssemblyPaths) {
        foreach ($p in $RoslynAssemblyPaths) {
            try { Add-Type -Path $p -ErrorAction Stop }
            catch { }
        }
    }
}

$findings = New-Object System.Collections.Generic.List[object]

function Add-Finding {
    param ([string]$File, [int]$Line, [string]$Rule, [string]$Severity, [string]$Message, [string]$Remediation = '')
    $findings.Add([PSCustomObject]@{
        File        = $File
        Line        = $Line
        Rule        = $Rule
        Severity    = $Severity
        Message     = $Message
        Remediation = $Remediation
    })
}

function Get-LineFromOffset {
    param ([int]$Offset, [int[]]$LineStarts)
    $lo = 0
    $hi = $LineStarts.Length - 1
    while ($lo -lt $hi) {
        $mid = $lo + [int](($hi - $lo + 1) / 2)
        if ($LineStarts[$mid] -le $Offset) { $lo = $mid } else { $hi = $mid - 1 }
    }
    return $lo + 1
}

try {
    try {
        $text = [System.IO.File]::ReadAllText($FilePath)
    }
    catch {
        $text = Get-Content -LiteralPath $FilePath -Raw -ErrorAction Stop
    }

    if ($text -match '(?i)audit:disable-all') {
        return $findings
    }

    if ($FilePath -like '*.cs') {
        if ('Microsoft.CodeAnalysis.CSharp.CSharpSyntaxTree' -as [type]) {
            $tree = [Microsoft.CodeAnalysis.CSharp.CSharpSyntaxTree]::ParseText($text)
            foreach ($diag in $tree.GetDiagnostics()) {
                if ([int]$diag.Severity -ge 2) {
                    $line = $diag.Location.GetLineSpan().StartLinePosition.Line + 1
                    Add-Finding -File $FilePath -Line $line -Rule 'SYNTAX' -Severity ([string]$diag.Severity).ToUpper() -Message ("Roslyn syntax diagnostic ({0}): {1}" -f $diag.Id, $diag.GetMessage()) -Remediation 'Fix the syntax error at the indicated line; dotnet build shows the full context.'
                }
            }
        }
        else {
            Add-Finding -File $FilePath -Line 1 -Rule 'AUDIT-CS-UNAVAILABLE' -Severity 'WARNING' -Message 'C# Roslyn types unavailable in this runspace; syntax diagnostics skipped (regex rules still applied).' -Remediation 'Supply Roslyn assemblies via -LocalAssemblyPath or run on a host with Roslyn loaded to enable C# syntax diagnostics.'
        }
    }
    elseif ($FilePath -like '*.vb') {
        if ('Microsoft.CodeAnalysis.VisualBasic.VisualBasicSyntaxTree' -as [type]) {
            $tree = [Microsoft.CodeAnalysis.VisualBasic.VisualBasicSyntaxTree]::ParseText($text)
            foreach ($diag in $tree.GetDiagnostics()) {
                if ([int]$diag.Severity -ge 2) {
                    $line = $diag.Location.GetLineSpan().StartLinePosition.Line + 1
                    Add-Finding -File $FilePath -Line $line -Rule 'SYNTAX' -Severity ([string]$diag.Severity).ToUpper() -Message ("Roslyn syntax diagnostic ({0}): {1}" -f $diag.Id, $diag.GetMessage()) -Remediation 'Fix the syntax error at the indicated line; dotnet build shows the full context.'
                }
            }
        }
        else {
            Add-Finding -File $FilePath -Line 1 -Rule 'AUDIT-VB-UNAVAILABLE' -Severity 'WARNING' -Message 'VB Roslyn types unavailable in this runspace (typical on PowerShell 7 hosts); syntax diagnostics skipped (regex rules still applied).' -Remediation 'Run on Windows PowerShell 5.1 (full Roslyn bootstrap) or supply VisualBasic assemblies to enable VB syntax diagnostics.'
        }
    }
    elseif ($FilePath -like '*.ps1' -or $FilePath -like '*.psm1') {
        $tokens = $null
        $parseErrors = $null
        $null = [System.Management.Automation.Language.Parser]::ParseFile($FilePath, [ref]$tokens, [ref]$parseErrors)
        foreach ($err in $parseErrors) {
            Add-Finding -File $FilePath -Line $err.Extent.StartLineNumber -Rule 'SYNTAX' -Severity 'ERROR' -Message ("PowerShell parse error ({0}): {1}" -f $err.ErrorId, $err.Message)
        }
    }
    elseif ($FilePath -match '\.(cpp|cxx|cc|c|hpp|hxx|hh|h)$') {
        if ($CxxCompiler) {
            $cxxOutput = @()
            try {
                $cxxOutput = & $CxxCompiler -fsyntax-only -x c++ $FilePath 2>&1
            }
            catch {
                Add-Finding -File $FilePath -Line 1 -Rule 'AUDIT-CPP-ERR' -Severity 'WARNING' -Message ("C++ syntax check failed to run: {0}" -f $_.Exception.Message) -Remediation 'Verify the detected C++ compiler works on this host.'
            }
            foreach ($cxxLine in $cxxOutput) {
                if ("$cxxLine" -match ':\s*(\d+):\d+:\s*(?:fatal\s+)?error:\s*(.+)$') {
                    Add-Finding -File $FilePath -Line ([int]$Matches[1]) -Rule 'SYNTAX' -Severity 'ERROR' -Message ("C++ compiler diagnostic: {0}" -f $Matches[2]) -Remediation 'Fix the syntax error at the indicated line; the compiler message gives the full context.'
                }
            }
        }
        else {
            Add-Finding -File $FilePath -Line 1 -Rule 'AUDIT-CPP-UNAVAILABLE' -Severity 'WARNING' -Message 'No C++ compiler (clang++/g++/gcc) available; syntax diagnostics skipped (regex rules still applied).' -Remediation 'Install clang++/g++/gcc and re-run to enable C/C++ syntax diagnostics.'
        }
    }
    elseif ($FilePath -like '*.py') {
        if ($PythonExe) {
            $pyCode = 'import ast,sys
try:
    ast.parse(open(sys.argv[1], "rb").read().decode("utf-8", "replace"), filename=sys.argv[1])
except SyntaxError as e:
    print("PYAUDIT:" + str(e.lineno) + ":" + str(e.msg))
    sys.exit(1)'
            $pyOutput = & $PythonExe -c $pyCode $FilePath 2>&1
            $pyText = $pyOutput -join "`n"
            if ($LASTEXITCODE -ne 0 -and $pyText -match 'PYAUDIT:(\d+):(.*)') {
                Add-Finding -File $FilePath -Line ([int]$Matches[1]) -Rule 'SYNTAX' -Severity 'ERROR' -Message ("Python syntax error: {0}" -f $Matches[2]) -Remediation 'Fix the syntax error at the indicated line; python reports the offending line.'
            }
            elseif ($LASTEXITCODE -ne 0) {
                Add-Finding -File $FilePath -Line 1 -Rule 'AUDIT-PY-ERR' -Severity 'WARNING' -Message ("Python syntax check failed: {0}" -f $pyText) -Remediation 'Verify the detected Python interpreter works on this host.'
            }
        }
        else {
            Add-Finding -File $FilePath -Line 1 -Rule 'AUDIT-PY-UNAVAILABLE' -Severity 'WARNING' -Message 'No Python interpreter available; syntax diagnostics skipped (regex rules still applied).' -Remediation 'Install Python 3 and re-run to enable Python syntax diagnostics.'
        }
    }

    $lineStarts = New-Object System.Collections.Generic.List[int]
    $lineStarts.Add(0)
    for ($i = 0; $i -lt $text.Length; $i++) {
        if ($text[$i] -eq [char]10) { $lineStarts.Add($i + 1) }
    }
    $lineStartsArr = $lineStarts.ToArray()
    $lines = [regex]::Split($text, "\r?\n")

    $timeout = [TimeSpan]::FromMilliseconds($RegexTimeoutMs)

    foreach ($rule in $Rules) {
        $ruleRemediation = [string]$rule.Remediation
        $regexMatches = $null
        try {
            $regexMatches = [regex]::Matches($text, $rule.Pattern, [System.Text.RegularExpressions.RegexOptions]::None, $timeout)
        }
        catch {
            Add-Finding -File $FilePath -Line 1 -Rule 'AUDIT-RULE-ERR' -Severity 'WARNING' -Message ("Rule {0} pattern failed: {1}" -f $rule.Id, $_.Exception.Message) -Remediation 'Review the rule pattern (invalid regex or timeout); fix the rule entry.'
            continue
        }

        foreach ($m in $regexMatches) {
            $lineNum = Get-LineFromOffset -Offset $m.Index -LineStarts $lineStartsArr
            $currentLine = if ($lineNum -ge 1 -and $lineNum -le $lines.Length) { $lines[$lineNum - 1] } else { "" }

            if ($currentLine -match '(?i)audit:disable-line|\[SuppressMessage') { continue }
            if ($currentLine -match ('(?i)audit:disable\s+' + [regex]::Escape($rule.Id))) { continue }

            Add-Finding -File $FilePath -Line $lineNum -Rule $rule.Id -Severity $rule.Severity -Message $rule.Message -Remediation $ruleRemediation
        }
    }
}
catch {
    Add-Finding -File $FilePath -Line 1 -Rule 'AUDIT-ERR' -Severity 'WARNING' -Message ("File could not be audited: {0}" -f $_.Exception.Message) -Remediation 'Inspect the file encoding, size, and permissions; the file could not be read or audited.'
}

return $findings
'@

function Get-FirstAvailableCommand {
    param ([string[]]$Names)
    foreach ($n in $Names) {
        $c = Get-Command -Name $n -ErrorAction SilentlyContinue
        if ($c) { return [string]$c.Source }
    }
    return ''
}

function Get-ChildPowerShell {
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

function Invoke-SourceAudit {
    param (
        [System.Collections.Generic.List[string]]$Files,
        [object]$Rules,
        [int]$Threads,
        [int]$Timeout,
        [string[]]$RoslynPaths,
        [string]$CxxCompiler,
        [string]$PythonExe
    )

    $allFindings = New-Object System.Collections.Generic.List[object]
    $allErrors   = New-Object System.Collections.Generic.List[string]
    $timedOut    = $false
    $completed   = 0

    $pool = [runspacefactory]::CreateRunspacePool(1, $Threads)
    $pool.Open()

    $queue   = New-Object System.Collections.Generic.Queue[string]
    foreach ($f in $Files) { $queue.Enqueue($f) }

    $pending  = New-Object System.Collections.Generic.List[object]
    $capacity = [Math]::Min([Math]::Max($Threads * 2, 4), 60)

    $rulesArray = @($Rules)
    $regexTimeoutMs = 5000
    $workerBlock = [scriptblock]::Create($script:WorkerScript)

    function Submit-Next {
        param ($Queue, $Pending, $Pool, $WorkerBlock, $RulesArr, $RoslynP, $RegexMs, $CxxP, $PyP)

        $nextFile = $Queue.Dequeue()
        $ps = [powershell]::Create()
        $ps.RunspacePool = $Pool
        try {
            $null = $ps.AddScript($WorkerBlock).AddArgument($nextFile).AddArgument($RulesArr).AddArgument($RoslynP).AddArgument($RegexMs).AddArgument($CxxP).AddArgument($PyP)
            $handle = $ps.BeginInvoke()
            $Pending.Add(@{ PS = $ps; Handle = $handle; File = $nextFile })
        }
        catch {
            $ps.Dispose()
            throw
        }
    }

    try {
        while ($pending.Count -lt $capacity -and $queue.Count -gt 0) {
            Submit-Next -Queue $queue -Pending $pending -Pool $pool -WorkerBlock $workerBlock -RulesArr $rulesArray -RoslynP $RoslynPaths -RegexMs $regexTimeoutMs -CxxP $CxxCompiler -PyP $PythonExe
        }

        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

        while ($pending.Count -gt 0) {
            if ($Timeout -gt 0 -and $stopwatch.Elapsed.TotalSeconds -ge $Timeout) {
                Write-AuditLog ("Audit timeout ({0}s) reached; terminating in-flight jobs and returning partial results." -f $Timeout) -Level WARNING
                $timedOut = $true
                break
            }

            $handles  = @($pending | ForEach-Object { $_.Handle.AsyncWaitHandle })
            $signaled = [System.Threading.WaitHandle]::WaitAny($handles, 500)

            if ($signaled -eq [System.Threading.WaitHandle]::WaitTimeout) {
                continue
            }

            $done = $pending[$signaled]
            $pending.RemoveAt($signaled)

            try {
                $results = $done.PS.EndInvoke($done.Handle)
                foreach ($item in $results) { $allFindings.Add($item) }
                $completed++
            }
            catch {
                $allErrors.Add($done.File)
            }
            finally {
                try { $done.PS.Dispose() } catch { Write-Verbose ("Runspace dispose failed: {0}" -f $_) }
            }

            while ($pending.Count -lt $capacity -and $queue.Count -gt 0) {
                Submit-Next -Queue $queue -Pending $pending -Pool $pool -WorkerBlock $workerBlock -RulesArr $rulesArray -RoslynP $RoslynPaths -RegexMs $regexTimeoutMs -CxxP $CxxCompiler -PyP $PythonExe
            }
        }
    }
    finally {
        $stoppedAtTeardown = $pending.Count
        foreach ($item in $pending.ToArray()) {
            try { $item.PS.Stop() }    catch { Write-Verbose ("Runspace stop failed during teardown: {0}" -f $_) }
            try { $item.PS.Dispose() } catch { Write-Verbose ("Runspace dispose failed during teardown: {0}" -f $_) }
        }
        $pending.Clear()
        try { $pool.Close() }   catch { Write-Verbose ("Runspace pool close failed: {0}" -f $_) }
        try { $pool.Dispose() } catch { Write-Verbose ("Runspace pool dispose failed: {0}" -f $_) }

        if ($timedOut) {
            $script:AuditStoppedFiles = $queue.Count + $stoppedAtTeardown
        }
        else {
            $script:AuditStoppedFiles = 0
        }
    }

    return [PSCustomObject]@{
        Findings       = $allFindings
        Errors         = $allErrors
        TimedOut       = $timedOut
        CompletedCount = $completed
        StoppedCount   = $script:AuditStoppedFiles
    }
}

#endregion Audit Engine & AST Syntax Walkers

#region SARIF 2.1.0 Reporting

function Get-SeverityRank {
    param ([string]$Severity)
    switch ($Severity) {
        'ERROR'   { return 3 }
        'WARNING' { return 2 }
        'INFO'    { return 1 }
        default   {
            Write-Verbose ("Unknown severity '{0}'; treating as ERROR for gate purposes." -f $Severity)
            return 3
        }
    }
}

function Get-SarifRoot {
    param ([string]$BasePath)
    $root = Get-GitRepoRoot -StartPath $BasePath
    if ($root) { return $root }
    return $BasePath
}

function Get-SarifArtifactUri {
    param ([string]$FilePath, [string]$RootPath)
    $fullFile = [System.IO.Path]::GetFullPath($FilePath)
    if ($RootPath) {
        $fullRoot = [System.IO.Path]::GetFullPath($RootPath)
        $rootWithSep = if ($fullRoot.EndsWith([System.IO.Path]::DirectorySeparatorChar)) { $fullRoot } else { $fullRoot + [System.IO.Path]::DirectorySeparatorChar }
        $comparison  = if (Test-IsWindowsHost) { [System.StringComparison]::OrdinalIgnoreCase } else { [System.StringComparison]::Ordinal }
        if ($fullFile.StartsWith($rootWithSep, $comparison)) {
            $relative = $fullFile.Substring($rootWithSep.Length).Replace('\', '/')
            $segments = $relative -split '/'
            $encoded  = ($segments | ForEach-Object { [System.Uri]::EscapeDataString($_) }) -join '/'
            return $encoded
        }
    }
    return [System.Uri]::new($fullFile).AbsoluteUri
}

function Export-SarifReport {
    param ([object]$Result, [string]$OutputPath, [string]$RootPath, $RuleSet)

    $sarifResults = New-Object System.Collections.Generic.List[object]

    foreach ($f in $Result.Findings) {
        $level = switch ($f.Severity) {
            'ERROR'   { 'error' }
            'WARNING' { 'warning' }
            default   { 'note' }
        }

        $safeLine = [Math]::Max(1, [int]$f.Line)

        $sarifResults.Add(@{
            ruleId  = $f.Rule
            level   = $level
            message = @{ text = (ConvertTo-RedactedText -Value $f.Message) }
            locations = @(
                @{
                    physicalLocation = @{
                        artifactLocation = @{ uri = (Get-SarifArtifactUri -FilePath $f.File -RootPath $RootPath) }
                        region           = @{ startLine = $safeLine }
                    }
                }
            )
        })
    }

    $rulesById = @{}
    if ($RuleSet) {
        foreach ($r in $RuleSet) { $rulesById[$r.Id] = $r }
    }
    $rulesList = New-Object System.Collections.Generic.List[object]
    $seenRules = New-Object System.Collections.Generic.HashSet[string]
    foreach ($f in $Result.Findings) {
        if (-not $seenRules.Add([string]$f.Rule)) { continue }
        $entry = @{ id = [string]$f.Rule }
        if ($rulesById.ContainsKey([string]$f.Rule)) {
            $ruleMeta = $rulesById[[string]$f.Rule]
            $entry['shortDescription'] = @{ text = $ruleMeta.Message }
            $remProp = $ruleMeta.PSObject.Properties['Remediation']
            if ($remProp -and $remProp.Value) {
                $entry['fullDescription'] = @{ text = ('Recommended correction: ' + [string]$remProp.Value) }
            }
            $entry['defaultConfiguration'] = @{ level = switch ($rulesById[[string]$f.Rule].Severity) {
                'ERROR'   { 'error' }
                'WARNING' { 'warning' }
                default   { 'note' }
            } }
        }
        $rulesList.Add($entry)
    }

    $driver = @{
        name           = 'Invoke-RoslynAudit'
        informationUri = 'https://github.com/Invoke-RoslynAudit'
        version        = '2.1.0'
        rules          = $rulesList
    }

    $sarifLog = @{
        '$schema' = 'https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json'
        version   = '2.1.0'
        runs      = @(
            @{
                tool    = @{ driver = $driver }
                results = $sarifResults
            }
        )
    }

    $json = $sarifLog | ConvertTo-Json -Depth 12
    [System.IO.File]::WriteAllText($OutputPath, $json, [System.Text.UTF8Encoding]::new($false))
    Write-AuditLog ("SARIF 2.1.0 report successfully written to '{0}'" -f $OutputPath) -Level INFO
}

#endregion SARIF 2.1.0 Reporting

#region Cleanup

function Remove-ExtractionWorkspace {
    [CmdletBinding(SupportsShouldProcess)]
    param ([bool]$Keep)

    if ($Keep) { return }
    if (-not $PSCmdlet.ShouldProcess($script:ExtractPath, 'Remove extracted-archive scratch directory')) { return }

    try {
        if (Test-Path -LiteralPath $script:ExtractPath) {
            Remove-Item -LiteralPath $script:ExtractPath -Recurse -Force -ErrorAction Stop
        }
    }
    catch {
        Write-Verbose ("Workspace cleanup failed (best-effort, ignored): {0}" -f $_)
    }
}

function New-OutputDirectory {
    [CmdletBinding(SupportsShouldProcess)]
    param ([string]$FilePath)
    if (-not $FilePath) { return }
    $dir = Split-Path -Path $FilePath -Parent -ErrorAction SilentlyContinue
    if ($dir -and -not (Test-Path -LiteralPath $dir)) {
        if ($PSCmdlet.ShouldProcess($dir, 'Create report output directory')) {
            New-Item -Path $dir -ItemType Directory -Force -ErrorAction Stop | Out-Null
        }
    }
}

#endregion Cleanup

#region Main

Write-AuditLog ("Audit started. Target: '{0}'  Threads: {1}  Timeout: {2}s" -f $Path, $MaxThreads, $TimeoutSeconds) -Level INFO

if ($Sarif -and -not $ReportPath) {
    Write-AuditLog '-Sarif was specified without -ReportPath; SARIF output is only produced when -ReportPath is set.' -Level WARNING
}

try {
    $ErrorActionPreference = 'Stop'
    Initialize-Roslyn -LocalPath $LocalAssemblyPath -ExpectedHash $NugetHash -ReuseCachedNuget ([bool]$ReuseCachedNuget)

    $target = Get-AuditTarget
    $targetDir = if (Test-Path -LiteralPath $target -PathType Container) { $target } else { Split-Path $target -Parent }

    $ignoreList = Get-AuditIgnoreList -IgnorePath $AuditIgnorePath -RootPath $targetDir
    $fileList   = @(Get-SourceFile -Root $target -GitOnly:$GitDiffOnly -IgnoreList $ignoreList)

    if ($fileList.Count -eq 0) {
        if ($GitDiffOnly) {
            Write-AuditLog 'No modified/untracked auditable files found (git work tree is clean).' -Level WARNING
        }
        else {
            Write-AuditLog 'No auditable files found matching criteria.' -Level WARNING
        }
        Complete-Audit 2
    }
    Write-AuditLog ("Discovered {0} target source file(s)." -f $fileList.Count) -Level INFO

    $ruleSet = Get-RuleSet -PackPath $RulePackPath
    $roslynPaths = $script:ResolvedRoslynPaths.ToArray()
    $cxxCompiler = Get-FirstAvailableCommand -Names @('clang++', 'clang', 'g++', 'c++', 'gcc')
    $pythonExe   = Get-FirstAvailableCommand -Names @('python3', 'python')
    if ($cxxCompiler) { Write-AuditLog ("C++ syntax check enabled via '{0}'." -f $cxxCompiler) -Level VERBOSE }
    else { Write-AuditLog 'No C++ compiler found (clang++/g++/gcc); C/C++ files get heuristic rules only.' -Level VERBOSE }
    if ($pythonExe) { Write-AuditLog ("Python syntax check enabled via '{0}'." -f $pythonExe) -Level VERBOSE }
    else { Write-AuditLog 'No Python interpreter found; .py files get heuristic rules only.' -Level VERBOSE }

    $audit   = Invoke-SourceAudit -Files $fileList -Rules $ruleSet -Threads $MaxThreads -Timeout $TimeoutSeconds -RoslynPaths $roslynPaths -CxxCompiler $cxxCompiler -PythonExe $pythonExe

    $errorCount   = @($audit.Findings | Where-Object { $_.Severity -eq 'ERROR' }).Count
    $warningCount = @($audit.Findings | Where-Object { $_.Severity -eq 'WARNING' }).Count
    $infoCount    = @($audit.Findings | Where-Object { $_.Severity -eq 'INFO' }).Count
    $byRule = [ordered]@{}
    foreach ($f in $audit.Findings) {
        if ($byRule.Contains($f.Rule)) { $byRule[$f.Rule]++ } else { $byRule[$f.Rule] = 1 }
    }
    $filesWithFindings = @($audit.Findings | ForEach-Object { $_.File } | Select-Object -Unique).Count

    $summary = [PSCustomObject]@{
        TargetFiles       = $fileList.Count
        AuditedFiles      = $audit.CompletedCount
        WorkerErrors      = $audit.Errors.Count
        TimedOut          = $audit.TimedOut
        StoppedFiles      = $audit.StoppedCount
        TotalFindings     = $audit.Findings.Count
        BySeverity        = @{ ERROR = $errorCount; WARNING = $warningCount; INFO = $infoCount }
        ByRule            = $byRule
        FilesWithFindings = $filesWithFindings
    }

    $result = [PSCustomObject]@{
        Summary  = $summary
        Findings = $audit.Findings
    }

    Write-AuditLog ("Audit finished: {0}/{1} file(s) audited, {2} finding(s) - {3} error, {4} warning, {5} info." -f
        $audit.CompletedCount, $fileList.Count, $result.Findings.Count, $errorCount, $warningCount, $infoCount) -Level INFO

    if (-not $PassThru) {
        foreach ($f in $result.Findings) {
            $level = switch ($f.Severity) {
                'ERROR'   { 'ERROR' }
                'WARNING' { 'WARNING' }
                default   { 'INFO' }
            }
            Write-AuditLog ("{0}  {1}({2})  {3}: {4}" -f $f.Severity, $f.File, $f.Line, $f.Rule, $f.Message) -Level $level
        }

        Write-AuditLog 'Findings by rule (with recommended corrections):' -Level INFO
        $result.Findings |
            Group-Object -Property Rule |
            Sort-Object Name |
            ForEach-Object {
                $first = $_.Group[0]
                Write-AuditLog ("  {0} x{1}  [{2}]  Fix: {3}" -f $_.Name, $_.Count, $first.Severity, $first.Remediation) -Level INFO
            }
    }

    if ($ReportPath) {
        New-OutputDirectory -FilePath $ReportPath
        if ($Sarif -or $ReportPath.EndsWith('.sarif', [System.StringComparison]::OrdinalIgnoreCase)) {
            $sarifBase = if (Test-Path -LiteralPath $target -PathType Container) { $target } else { Split-Path -Path $target -Parent }
            Export-SarifReport -Result $result -OutputPath $ReportPath -RootPath (Get-SarifRoot -BasePath $sarifBase) -RuleSet $ruleSet
        }
        else {
            $jsonContent = $result | ConvertTo-Json -Depth 6
            [System.IO.File]::WriteAllText($ReportPath, $jsonContent, [System.Text.UTF8Encoding]::new($false))
            Write-AuditLog ("JSON report written to '{0}'." -f $ReportPath) -Level INFO
        }
    }

    if ($PassThru) { $result }

    if ($AutoFix) {
        $scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
        $fixerScript = Join-Path $scriptDir 'Invoke-RoslynFix.ps1'
        if (-not (Test-Path -LiteralPath $fixerScript)) {
            Write-AuditLog ("AutoFix requested but Invoke-RoslynFix.ps1 was not found next to this script ('{0}')." -f $scriptDir) -Level ERROR
            Complete-Audit 1
        }
        if ($result.Findings.Count -eq 0) {
            Write-AuditLog 'AutoFix skipped: the audit found no findings to correct.' -Level INFO
        }
        else {
            $autoFixReportIsTemp = $false
            if ($ReportPath) {
                $autoFixReport = $ReportPath
            }
            else {
                $autoFixReport = Join-Path ([System.IO.Path]::GetTempPath()) ("RoslynAudit_AutoFix_{0:yyyyMMdd_HHmmss}.json" -f (Get-Date))
                $autoFixReportIsTemp = $true
                $jsonContent = $result | ConvertTo-Json -Depth 6
                [System.IO.File]::WriteAllText($autoFixReport, $jsonContent, [System.Text.UTF8Encoding]::new($false))
                Write-AuditLog ("AutoFix report written to '{0}'." -f $autoFixReport) -Level INFO
            }
            Write-AuditLog 'AutoFix: invoking Invoke-RoslynFix on the audit report...' -Level INFO
            & (Get-ChildPowerShell) -NoProfile -File $fixerScript $autoFixReport
            $fixerExit = $LASTEXITCODE
            if ($fixerExit -ne 0) {
                Write-AuditLog ("AutoFix run ended with exit code {0}; see the fix output above and FixReport.json in the corrected tree." -f $fixerExit) -Level ERROR
                if ($fixerExit -eq 1) { Complete-Audit 1 }
            }
            if ($autoFixReportIsTemp -and $fixerExit -eq 0) {
                Remove-Item -LiteralPath $autoFixReport -Force -ErrorAction SilentlyContinue
                Write-AuditLog 'AutoFix temp report cleaned up.' -Level VERBOSE
            }
        }
    }

    if ($FailOn) {
        $threshold = Get-SeverityRank -Severity $FailOn
        $breaches  = @($result.Findings | Where-Object { (Get-SeverityRank -Severity $_.Severity) -ge $threshold })
        if ($breaches.Count -gt 0) {
            Write-AuditLog ("Severity gate failed: {0} finding(s) at or above {1} severity." -f $breaches.Count, $FailOn) -Level ERROR
            Complete-Audit 3
        }
        Write-AuditLog ("Severity gate passed: no findings at or above {0} severity." -f $FailOn) -Level INFO
    }
}
catch {
    $ex = $_.Exception
    if ($ex -and $ex.Data -and $ex.Data.Contains($script:AuditSentinelKey) -and $ex.Data[$script:AuditSentinelKey]) {
        $script:ExitCode = [int]$ex.Data[$script:AuditExitCodeKey]
        Write-Verbose ("Audit exit code {0} signaled." -f $script:ExitCode)
    }
    else {
        Write-AuditLog ("Audit failed: {0}" -f $_) -Level ERROR
        $script:ExitCode = 1
    }
}
finally {
    Remove-ExtractionWorkspace -Keep ([bool]$KeepWorkspace)
    Close-LogWriter
}

if ($script:WasDotSourced) {
    if ($script:ExitCode -ne 0) {
        Write-Warning ("Script was dot-sourced; exit code {0} suppressed." -f $script:ExitCode)
    }
    return
}
exit $script:ExitCode

#endregion Main