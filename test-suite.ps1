# Full regression test suite for Invoke-RoslynAudit.ps1
param (
    [ValidateSet('pwsh', 'powershell')]
    [string]$TargetShell = 'pwsh'
)

$ErrorActionPreference = 'Continue'
# Fixed AUD-03: Resolve-Path chokes on bracketed paths. $PSCommandPath is already fully qualified.
$scriptDir = Split-Path -Parent $PSCommandPath
$target    = Join-Path $scriptDir 'Invoke-RoslynAudit.ps1'
$root      = Join-Path $scriptDir 'audit-suite'
$pass = 0; $fail = 0; $failures = @()

function New-Case([string]$name, [scriptblock]$check) {
    try {
        $ok = & $check
        if ($ok -isnot [bool]) { throw "case returned '$($ok.GetType().Name)' instead of bool" }
        if ($ok) { Write-Host "PASS  $name" -ForegroundColor Green; $script:pass++ }
        else     { Write-Host "FAIL  $name" -ForegroundColor Red;   $script:fail++; $script:failures += $name }
    }
    catch {
        Write-Host "FAIL  $name  (harness exception: $($_.Exception.Message))" -ForegroundColor Red
        $script:fail++; $script:failures += $name
    }
}

function Run-Script {
    param([string[]]$AuditArgs = @())
    $psiArgs = @('-NoProfile', '-File', $target) + $AuditArgs
    $output = & $TargetShell @psiArgs 2>&1 | ForEach-Object { "$_" }
    return [PSCustomObject]@{ Output = ($output -join "`n"); ExitCode = $LASTEXITCODE }
}

function Get-Json([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { throw "report missing: $Path" }
    return (Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json)
}

function Get-WorkspaceExtractPath {
    $userKey = if ($env:USERNAME) { $env:USERNAME } else { [System.Environment]::UserName }
    if ([string]::IsNullOrWhiteSpace($userKey)) { $userKey = 'default' }
    $userKey = ($userKey -replace '[^A-Za-z0-9_\-]', '_')
    if ([string]::IsNullOrWhiteSpace($userKey)) { $userKey = 'default' }
    return Join-Path (Join-Path ([System.IO.Path]::GetTempPath()) "RoslynAuditWorkspace_$userKey") 'Extracted'
}

# --- fixtures ----------------------------------------------------------------
if (Test-Path -LiteralPath $root) { Remove-Item -LiteralPath $root -Recurse -Force }
New-Item -ItemType Directory -Path $root | Out-Null

$proj = Join-Path $root 'proj'
New-Item -ItemType Directory -Path $proj | Out-Null

@'
using System;
using System.Threading;
using System.Net.Http;
public class Bad {
    public static void Run() {
        try { int x = 1; } catch (Exception ex) { }
        Thread.Sleep(100);
        string password = "SuperSecret123!";
        var hash = MD5.Create();
        var t = Task.Run(() => 1); var r = t.Result;
    }
    unsafe void Ptr() { int x = 1; int* p = &x; }
    void Go() { throw new Exception(); }
    void Go2(Exception ex) { try { } catch (Exception) { throw ex; } }
    void Go3() { Environment.Exit(0); }
    void Go4() { var wc = new System.Net.WebClient(); }
    void Go5() { System.Threading.Thread.Abort(); }
    void Go6() { var hc = new HttpClient(); }
}
'@ | Set-Content (Join-Path $proj 'Bad.cs') -Encoding UTF8

@'
using System;
public class Good { public int Add(int a, int b) => a + b; }
'@ | Set-Content (Join-Path $proj 'Good.cs') -Encoding UTF8

@'
$iex = 'Write-Host hi'
Invoke-Expression $iex
Set-ExecutionPolicy Unrestricted -Force
Add-Type -TypeDefinition 'public class X {}'
'@ | Set-Content (Join-Path $proj 'Bad.ps1') -Encoding UTF8

@'
function Broken {
    if ($true) {
'@ | Set-Content (Join-Path $proj 'Broken.psm1') -Encoding UTF8

@'
Module Bad
    Sub Main(
        Console.WriteLine("hi")
    End Sub
End Module
'@ | Set-Content (Join-Path $proj 'Bad.vb') -Encoding UTF8

@'
public class Suppressed {
    static void Go() {
        GC.Collect(); // audit:disable-line
    }
    static void Go2() { // audit:disable-all
        Thread.Sleep(50);
    }
}
'@ | Set-Content (Join-Path $proj 'Suppressed.cs') -Encoding UTF8

@'
public class Ignored { static void Go() { Thread.Sleep(1); } }
'@ | Set-Content (Join-Path $proj 'Ignored.cs') -Encoding UTF8

@'
import os, subprocess, yaml, hashlib
os.system("ls " + input())
subprocess.call("ls " + input(), shell=True)
data = yaml.load(open("f").read())
h = hashlib.md5()
try:
    pass
except:
    pass
r = eval("1+1")
'@ | Set-Content (Join-Path $proj 'Bad.py') -Encoding UTF8

@'
#include <string.h>
#include <stdio.h>
int main() { char b[4]; strcpy(b, "toolong"); char s[4]; scanf("%s", s); return 0; }
'@ | Set-Content (Join-Path $proj 'Bad.cpp') -Encoding UTF8

Set-Content (Join-Path $proj '.auditignore') ".auditignore`n*.auditignore`nIgnored.cs" -Encoding UTF8

$report = Join-Path $root 'report.json'
$sarif  = Join-Path $root 'report.sarif'

$passThruHelper = Join-Path $root 'passthru-helper.ps1'
@'
param ([string]$Target, [string]$File, [string[]]$Rest = @())
& $Target $File @Rest -PassThru 6>$null | ConvertTo-Json -Depth 6
'@ | Set-Content $passThruHelper -Encoding UTF8

# --- cases ---------------------------------------------------------------------

New-Case 'Parse: script parses with zero syntax errors' {
    $t = $null; $e = $null
    $null = [System.Management.Automation.Language.Parser]::ParseFile($target, [ref]$t, [ref]$e)
    return ($e.Count -eq 0)
}

$r1 = $null
New-Case 'Full-project audit: exit 0, report written' {
    $script:r1 = Run-Script @($proj, '-ReportPath', $report)
    return ($script:r1.ExitCode -eq 0) -and (Test-Path -LiteralPath $report)
}

New-Case 'Full-project audit: expected classic rules fire (RA001 RA003 RA006 RA007 RA009 RA201)' {
    $j = Get-Json $report
    $rules = @($j.Findings | ForEach-Object { $_.Rule } | Sort-Object -Unique)
    return ('RA001','RA003','RA006','RA007','RA009','RA201' | Where-Object { $rules -notcontains $_ }).Count -eq 0
}

New-Case 'Full-project audit: expected NEW rules fire (RA011 RA013 RA014 RA019 RA022 RA027 RA219 RA217 RA411 RA412 RA419 RA425 RA312)' {
    $j = Get-Json $report
    $rules = @($j.Findings | ForEach-Object { $_.Rule } | Sort-Object -Unique)
    $expected = 'RA011','RA013','RA014','RA019','RA022','RA027','RA219','RA217','RA411','RA412','RA419','RA425','RA312'
    $missing = @($expected | Where-Object { $rules -notcontains $_ })
    if ($missing.Count -gt 0) { Write-Host "  missing: $($missing -join ', ')" -ForegroundColor Yellow }
    return ($missing.Count -eq 0)
}

New-Case 'Fixture breadth: >=15 distinct rules fire on the fixture (rule-engine liveness)' {
    $j = Get-Json $report
    $rules = @($j.Findings | ForEach-Object { $_.Rule } | Sort-Object -Unique)
    return ($rules.Count -ge 15)
}

New-Case 'Full-project audit: summary counts plausible (>=8 files, 0 worker errors)' {
    $j = Get-Json $report
    return ($j.Summary.TargetFiles -ge 8) -and
           ($j.Summary.WorkerErrors -eq 0) -and
           ($j.Summary.TimedOut -eq $false)
}

New-Case 'Inline suppressions: audit:disable-line / audit:disable-all honored' {
    $j = Get-Json $report
    return (@($j.Findings | Where-Object { $_.File -like '*Suppressed.cs' }).Count -eq 0)
}

New-Case '.auditignore: Ignored.cs excluded from scan' {
    $j = Get-Json $report
    return (@($j.Findings | Where-Object { $_.File -like '*Ignored.cs' }).Count -eq 0)
}

New-Case 'Single-file audit: exit 0 (StrictMode unroll regression)' {
    $r = Run-Script @((Join-Path $proj 'Bad.cs'), '-ReportPath', (Join-Path $root 'single.json'))
    return ($r.ExitCode -eq 0)
}

New-Case 'Empty target: exit 2 with warning' {
    $empty = Join-Path $root 'empty'
    New-Item -ItemType Directory -Path $empty | Out-Null
    $r = Run-Script @($empty)
    return ($r.ExitCode -eq 2) -and ($r.Output -match 'No auditable files')
}

New-Case 'Severity gate: -FailOn ERROR with errors present exits 3' {
    $r = Run-Script @($proj, '-FailOn', 'ERROR')
    return ($r.ExitCode -eq 3)
}

New-Case 'Severity gate: -FailOn ERROR on clean file exits 0' {
    $r = Run-Script @((Join-Path $proj 'Good.cs'), '-FailOn', 'ERROR')
    return ($r.ExitCode -eq 0)
}

New-Case 'Severity gate: -FailOn WARNING with warnings present exits 3' {
    $r = Run-Script @($proj, '-FailOn', 'WARNING')
    return ($r.ExitCode -eq 3)
}

New-Case 'Severity gate: -FailOn INFO with any findings exits 3' {
    $r = Run-Script @($proj, '-FailOn', 'INFO')
    return ($r.ExitCode -eq 3)
}

New-Case 'LogPath: log file written with start and finish markers' {
    $logFile = Join-Path $root 'audit.log'
    if (Test-Path -LiteralPath $logFile) { Remove-Item -Force -LiteralPath $logFile }
    $r = Run-Script @((Join-Path $proj 'Bad.cs'), '-LogPath', $logFile)
    if (-not (Test-Path -LiteralPath $logFile)) { return $false }
    $content = Get-Content -LiteralPath $logFile -Raw
    return ($r.ExitCode -eq 0) -and ($content -match 'Audit started') -and ($content -match 'Audit finished')
}

New-Case 'KeepWorkspace: extracted archive scratch dir retained on exit' {
    $zip = Join-Path $root 'keep-ws.zip'
    $zipsrc = Join-Path $root 'keep-ws-src'
    New-Item -ItemType Directory -Path $zipsrc -Force | Out-Null
    "public class X { void G() { System.Threading.Thread.Sleep(1); } }" | Set-Content (Join-Path $zipsrc 'X.cs')
    if (Test-Path -LiteralPath $zip) { Remove-Item -Force -LiteralPath $zip }
    Compress-Archive -Path (Join-Path $zipsrc '*') -DestinationPath $zip -Force
    $extract = Get-WorkspaceExtractPath
    if (Test-Path -LiteralPath $extract) { Remove-Item -Recurse -Force -LiteralPath $extract -ErrorAction SilentlyContinue }
    $r = Run-Script @($zip, '-KeepWorkspace')
    return ($r.ExitCode -eq 0) -and (Test-Path -LiteralPath $extract)
}

New-Case 'LocalAssemblyPath: nonexistent path falls through to bootstrap and audit succeeds' {
    $nonexistent = Join-Path $root 'no-such-asm-dir'
    if (Test-Path -LiteralPath $nonexistent) { Remove-Item -Recurse -Force -LiteralPath $nonexistent }
    $r = Run-Script @((Join-Path $proj 'Good.cs'), '-LocalAssemblyPath', $nonexistent, '-ReportPath', (Join-Path $root 'localasm.json'))
    return ($r.ExitCode -eq 0)
}

New-Case 'NugetHash: parameter declared in the audit script (structural)' {
    $scriptText = Get-Content -LiteralPath $target -Raw
    return ($scriptText -match '\[string\]\$NugetHash') -and ($scriptText -match 'function Get-NugetExe')
}

New-Case 'SARIF: valid 2.1.0 log with OASIS schema, driver, results, rule metadata' {
    $r = Run-Script @($proj, '-Sarif', '-ReportPath', $sarif)
    $j = Get-Json $sarif
    $run = @($j.runs)[0]
    $badLevels = @($run.results | Where-Object { $_.level -notin 'error','warning','note' })
    return ($r.ExitCode -eq 0) -and
           ($j.version -eq '2.1.0') -and
           ($j.'$schema' -match '^https://docs\.oasis-open\.org/') -and
           ($run.tool.driver.name -eq 'Invoke-RoslynAudit') -and
           (@($run.results).Count -gt 0) -and
           (@($run.tool.driver.rules).Count -gt 0) -and
           ($badLevels.Count -eq 0)
}

New-Case 'Console UX: summary and findings printed when no -ReportPath' {
    $r = Run-Script @($proj)
    return ($r.ExitCode -eq 0) -and
           ($r.Output -match 'Audit finished: \d+/\d+ file\(s\) audited') -and
           ($r.Output -match 'RA001')
}

New-Case 'Console UX: per-finding dump suppressed when -PassThru is used' {
    $r = Run-Script @($proj, '-PassThru')
    return ($r.ExitCode -eq 0) -and
           ($r.Output -match 'Audit finished:') -and
           ($r.Output -notmatch [regex]::Escape('  RA001:'))
}

New-Case 'Remediation: findings carry correction guidance; summary breaks down by severity/rule' {
    $j = Get-Json $report
    $ra1 = @($j.Findings | Where-Object { $_.Rule -eq 'RA001' })
    return ($ra1.Count -ge 1) -and
           ($null -ne $ra1[0].Remediation -and $ra1[0].Remediation.Length -gt 10) -and
           ($j.Summary.ByRule.RA001 -ge 1) -and
           ($j.Summary.BySeverity.ERROR -ge 1) -and
           ($j.Summary.FilesWithFindings -ge 1)
}

New-Case 'Remediation: console shows per-rule breakdown with recommended corrections' {
    $r = Run-Script @($proj)
    return ($r.ExitCode -eq 0) -and
           ($r.Output -match 'Findings by rule') -and
           ($r.Output -match 'Fix: Handle the exception')
}

New-Case 'VB handling: SYNTAX finding or AUDIT-VB-UNAVAILABLE (never silent)' {
    $j = Get-Json $report
    $hit = @($j.Findings | Where-Object { $_.File -like '*Bad.vb' -and ($_.Rule -eq 'AUDIT-VB-UNAVAILABLE' -or $_.Rule -eq 'SYNTAX') })
    return ($hit.Count -ge 1)
}

New-Case 'Rule pack: custom rule fires; duplicate id overrides builtin severity' {
    $pack = Join-Path $root 'rules.json'
    @'
[
  { "Id": "RA001", "Severity": "INFO", "Pattern": "catch\\s*(\\([^)]*\\))?\\s*\\{\\s{0,200}\\}", "Message": "Custom override." },
  { "Id": "RA999", "Severity": "WARNING", "Pattern": "Thread\\.Sleep", "Message": "Custom no-sleep rule." }
]
'@ | Set-Content $pack -Encoding UTF8
    $rep2 = Join-Path $root 'report-pack.json'
    $r = Run-Script @($proj, '-RulePackPath', $pack, '-ReportPath', $rep2)
    $j = Get-Json $rep2
    $ra001 = @($j.Findings | Where-Object { $_.Rule -eq 'RA001' })
    $ra999 = @($j.Findings | Where-Object { $_.Rule -eq 'RA999' })
    return ($r.ExitCode -eq 0) -and ($ra001.Count -gt 0) -and ($ra001[0].Severity -eq 'INFO') -and ($ra999.Count -gt 0)
}

New-Case 'Rule pack: invalid severity rejected with exit 1' {
    $pack = Join-Path $root 'badrules.json'
    @'
[ { "Id": "RX001", "Severity": "FATAL", "Pattern": "x", "Message": "m" } ]
'@ | Set-Content $pack -Encoding UTF8
    $r = Run-Script @($proj, '-RulePackPath', $pack)
    return ($r.ExitCode -eq 1)
}

New-Case 'Git diff mode: only modified/untracked files audited' {
    $repo = Join-Path $root 'repo'
    New-Item -ItemType Directory -Path $repo | Out-Null
    Push-Location $repo
    git init -q .
    git config user.email t@t.t; git config user.name t
    "public class Committed { static void Go() { System.Threading.Thread.Sleep(1); } }" | Set-Content (Join-Path $repo 'Committed.cs')
    git add -A 2>$null | Out-Null
    git commit -qm init 2>$null
    "public class Modified { static void Go() { System.Threading.Thread.Sleep(1); } }" | Set-Content (Join-Path $repo 'Modified.cs')
    Pop-Location
    $rep3 = Join-Path $root 'report-git.json'
    $r = Run-Script @($repo, '-GitDiffOnly', '-ReportPath', $rep3)
    $j = Get-Json $rep3
    $files = @($j.Findings | ForEach-Object { [IO.Path]::GetFileName($_.File) } | Sort-Object -Unique)
    return ($r.ExitCode -eq 0) -and ($files.Count -eq 1) -and ($files -contains 'Modified.cs')
}

New-Case 'Git diff mode: modified .cpp/.py included (GitDiffOnly extension fix)' {
    $repo = Join-Path $root 'repo-multi'
    New-Item -ItemType Directory -Path $repo | Out-Null
    Push-Location $repo
    git init -q .
    git config user.email t@t.t; git config user.name t
    "#include <string.h>`nint main() { return 0; }" | Set-Content (Join-Path $repo 'main.cpp')
    git add -A 2>$null | Out-Null
    git commit -qm init 2>$null
    "#include <string.h>`nint main() { char b[4]; strcpy(b, 'x'); return 0; }" | Set-Content (Join-Path $repo 'main.cpp')
    "import os`nos.system('ls')" | Set-Content (Join-Path $repo 'a.py')
    Pop-Location
    $rep4 = Join-Path $root 'report-git-multi.json'
    $r = Run-Script @($repo, '-GitDiffOnly', '-ReportPath', $rep4)
    $j = Get-Json $rep4
    $files = @($j.Findings | ForEach-Object { [IO.Path]::GetFileName($_.File) } | Sort-Object -Unique)
    return ($r.ExitCode -eq 0) -and ($files -contains 'main.cpp') -and ($files -contains 'a.py')
}

New-Case 'Git diff mode: clean work tree exits 2 (unroll regression)' {
    $repo = Join-Path $root 'repo'
    Push-Location $repo
    git add -A 2>$null | Out-Null
    git commit -qm second 2>$null
    Pop-Location
    $r = Run-Script @($repo, '-GitDiffOnly')
    return ($r.ExitCode -eq 2)
}

New-Case 'Zip archive input: contents audited' {
    $zip = Join-Path $root 'src.zip'
    $zipsrc = Join-Path $root 'zipsrc'
    New-Item -ItemType Directory -Path $zipsrc | Out-Null
    "public class Zipped { static void Go() { Thread.Sleep(1); } }" | Set-Content (Join-Path $zipsrc 'Zipped.cs')
    Compress-Archive -Path (Join-Path $zipsrc '*') -DestinationPath $zip -Force
    $rep5 = Join-Path $root 'report-zip.json'
    $r = Run-Script @($zip, '-ReportPath', $rep5)
    $j = Get-Json $rep5
    $hit = @($j.Findings | Where-Object { $_.File -like '*Zipped.cs' -and $_.Rule -eq 'RA003' })
    return ($r.ExitCode -eq 0) -and ($hit.Count -gt 0)
}

New-Case 'Zip-slip defense: path traversal entry blocked with exit 1, nothing escaped' {
    $malZip = Join-Path $root 'evil.zip'
    Add-Type -AssemblyName System.IO.Compression, System.IO.Compression.FileSystem -ErrorAction SilentlyContinue
    
    # Fixed AUD-01: Use proper try/finally for unmanaged file lock prevention
    $fs = [System.IO.File]::Create($malZip)
    try {
        $z = New-Object System.IO.Compression.ZipArchive($fs, [System.IO.Compression.ZipArchiveMode]::Create)
        try {
            $entry = $z.CreateEntry('../../escaped.txt')
            $w = New-Object System.IO.StreamWriter($entry.Open())
            try { $w.Write('pwned') } finally { $w.Dispose() }
        } finally {
            $z.Dispose()
        }
    } finally {
        $fs.Dispose()
    }
    
    $r = Run-Script @($malZip)
    $escaped = @(
        (Join-Path $root 'escaped.txt'),
        (Join-Path ([IO.Path]::GetTempPath()) 'RoslynAuditWorkspace_root/escaped.txt'),
        (Join-Path ([IO.Path]::GetTempPath()) 'RoslynAuditWorkspace_root/Extracted/escaped.txt')
    ) | Where-Object { Test-Path -LiteralPath $_ }
    
    return ($r.ExitCode -eq 1) -and ($escaped.Count -eq 0)
}

New-Case 'PassThru: emits Summary + Findings object (exit code still 0)' {
    $json = & $TargetShell -NoProfile -File $passThruHelper -Target $target -File (Join-Path $proj 'Bad.cs') 2>&1
    $obj = ($json -join "`n") | ConvertFrom-Json
    return ($null -ne $obj) -and
           ($null -ne $obj.Summary) -and
           (@($obj.Findings).Count -gt 0) -and
           ($LASTEXITCODE -eq 0)
}

New-Case 'Timeout: wall-clock budget returns partial results with TimedOut=true' {
    $heavy = Join-Path $root 'heavy'
    New-Item -ItemType Directory -Path $heavy | Out-Null
    $redos = ('x' * 30000)
    1..3 | ForEach-Object { Set-Content (Join-Path $heavy "H$_.cs") $redos -Encoding UTF8 }
    $pack = Join-Path $root 'redos.json'
    '[{ "Id": "RX001", "Severity": "WARNING", "Pattern": "(x+x+)+y", "Message": "redos" }]' | Set-Content $pack -Encoding UTF8
    $rep6 = Join-Path $root 'report-timeout.json'
    $r = Run-Script @($heavy, '-TimeoutSeconds', '1', '-MaxThreads', '1', '-RulePackPath', $pack, '-ReportPath', $rep6)
    $j = Get-Json $rep6
    return ($r.ExitCode -eq 0) -and ($j.Summary.TimedOut -eq $true)
}

# --- fixer cases -----------------------------------------------------------------

$fixerPath = Join-Path (Split-Path -Path $target -Parent) 'Invoke-RoslynFix.ps1'

function Get-FixedTreeFromOutput {
    param ([string]$Text)
    if ($Text -match "Corrected tree written to '(.+?)'\.") { return $Matches[1] }
    return $null
}

function Remove-FixedTree {
    param ([string]$Path)
    if ($Path -and (Test-Path -LiteralPath $Path)) {
        Remove-Item -Recurse -Force -LiteralPath $Path -ErrorAction SilentlyContinue
    }
    $vrf = Join-Path (Split-Path -Parent $Path) 'FixVerifyReport.json'
    if ($Path -and (Test-Path -LiteralPath $vrf)) { Remove-Item -Force -LiteralPath $vrf -ErrorAction SilentlyContinue }
}

function Clear-DefaultAssetsLeaf {
    param ([string]$Leaf)
    $desktop = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::Desktop)
    if ([string]::IsNullOrWhiteSpace($desktop)) { $desktop = Join-Path $HOME 'Desktop' }
    Remove-FixedTree -Path (Join-Path (Join-Path $desktop 'Assets') $Leaf)
}

New-Case 'RoslynFix: demangles corrupted files into a new folder; originals untouched' {
    Clear-DefaultAssetsLeaf -Leaf 'src'
    $fxRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("RF_demangle_" + [guid]::NewGuid().ToString('N'))
    New-Item -Path (Join-Path $fxRoot 'src') -ItemType Directory -Force | Out-Null
    $app = Join-Path $fxRoot 'src' 'App.cs'
    'var x = [System.Com](https://System.Com)ponentModel;' | Set-Content -Path $app -Encoding UTF8
    $before = (Get-FileHash $app -Algorithm SHA256).Hash
    $report = Join-Path $fxRoot 'audit.json'
    $null = Run-Script @((Join-Path $fxRoot 'src'), '-ReportPath', $report)
    $out = & $TargetShell -NoProfile -File $fixerPath $report 2>&1 | ForEach-Object { "$_" }
    $exit = $LASTEXITCODE
    $after = (Get-FileHash $app -Algorithm SHA256).Hash
    $text = $out -join "`n"
    $dest = Get-FixedTreeFromOutput -Text $text
    $fixedOk = $false
    if ($dest) {
        $fixedText = Get-Content -Raw (Join-Path $dest 'App.cs')
        $fixedOk = ($fixedText -match 'System\.ComponentModel')
        Remove-FixedTree -Path $dest
    }
    Remove-Item -Recurse -Force $fxRoot -ErrorAction SilentlyContinue
    return ($exit -eq 0) -and ($dest -ne $null) -and
           ($text -match 'Verification: findings \d+ -> 0') -and
           ($before -eq $after) -and $fixedOk
}

New-Case 'RoslynFix: -RedactSecrets redacts RA006; semantic findings stay manual' {
    Clear-DefaultAssetsLeaf -Leaf 'src'
    $fxRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("RF_redact_" + [guid]::NewGuid().ToString('N'))
    New-Item -Path (Join-Path $fxRoot 'src') -ItemType Directory -Force | Out-Null
    $cs = Join-Path $fxRoot 'src' 'Config.cs'
    @'
namespace X;
public class Config {
    private string password = "hunter2secret";
    public static void Run() { System.Threading.Thread.Sleep(100); }
}
'@ | Set-Content -Path $cs -Encoding UTF8
    $before = (Get-FileHash $cs -Algorithm SHA256).Hash
    $report = Join-Path $fxRoot 'audit.json'
    $null = Run-Script @((Join-Path $fxRoot 'src'), '-ReportPath', $report)
    $out = & $TargetShell -NoProfile -File $fixerPath $report -RedactSecrets 2>&1 | ForEach-Object { "$_" }
    $exit = $LASTEXITCODE
    $after = (Get-FileHash $cs -Algorithm SHA256).Hash
    $dest = Get-FixedTreeFromOutput -Text ($out -join "`n")
    $fixedOk = $false
    $manualOk = $false
    if ($dest) {
        $fixedText = Get-Content -Raw (Join-Path $dest 'Config.cs')
        $fixReport = Get-Content -Raw (Join-Path $dest 'FixReport.json') | ConvertFrom-Json
        $manualRules = @($fixReport.ManualReview | ForEach-Object { $_.Rule })
        $fixedOk = ($fixedText -match '__REDACTED_SECRET__') -and ($fixedText -notmatch 'hunter2secret')
        $manualOk = ($manualRules -contains 'RA003')
        Remove-FixedTree -Path $dest
    }
    Remove-Item -Recurse -Force $fxRoot -ErrorAction SilentlyContinue
    return ($exit -eq 0) -and ($before -eq $after) -and $fixedOk -and $manualOk
}

New-Case 'RoslynFix: accepts a source directory directly (auto-generates the audit report)' {
    Clear-DefaultAssetsLeaf -Leaf 'src'
    $fxRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("RF_autodir_" + [guid]::NewGuid().ToString('N'))
    New-Item -Path (Join-Path $fxRoot 'src') -ItemType Directory -Force | Out-Null
    $app = Join-Path $fxRoot 'src' 'App.cs'
    'var x = [System.Com](https://System.Com)ponentModel;' | Set-Content -Path $app -Encoding UTF8
    $before = (Get-FileHash $app -Algorithm SHA256).Hash
    $out = & $TargetShell -NoProfile -File $fixerPath (Join-Path $fxRoot 'src') 2>&1 | ForEach-Object { "$_" }
    $exit = $LASTEXITCODE
    $after = (Get-FileHash $app -Algorithm SHA256).Hash
    $text = $out -join "`n"
    $dest = Get-FixedTreeFromOutput -Text $text
    $fixedOk = $false
    if ($dest) {
        $fixedOk = ((Get-Content -Raw (Join-Path $dest 'App.cs')) -match 'System\.ComponentModel')
        Remove-FixedTree -Path $dest
    }
    $gen = Get-ChildItem -Path $fxRoot -Filter 'RoslynFixInput_*.json' -ErrorAction SilentlyContinue
    Remove-Item -Recurse -Force $fxRoot -ErrorAction SilentlyContinue
    return ($exit -eq 0) -and
           ($text -match 'generating an audit report') -and
           ($text -match 'Verification: findings \d+ -> 0') -and
           ($before -eq $after) -and $fixedOk -and ($null -ne $gen)
}

New-Case 'Multi-language audit: C++/Python rules fire and syntax checks engage' {
    $mlRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("RF_multi_" + [guid]::NewGuid().ToString('N'))
    New-Item -Path $mlRoot -ItemType Directory -Force | Out-Null
    @'
#include <string.h>
int main() { char b[4]; strcpy(b, "toolong"); return 0 }
'@ | Set-Content -Path (Join-Path $mlRoot 'bad.cpp') -Encoding UTF8
    @'
try:
    pass
except:
    pass
def broken(:
    pass
r = eval("1+1")
'@ | Set-Content -Path (Join-Path $mlRoot 'bad.py') -Encoding UTF8
    $report = Join-Path $mlRoot 'report.json'
    $null = Run-Script @($mlRoot, '-ReportPath', $report)
    $j = Get-Json $report
    $rules = @($j.Findings | ForEach-Object { $_.Rule })
    $cppSyntaxEngaged = @($j.Findings | Where-Object { $_.File -like '*bad.cpp' -and $_.Rule -in @('SYNTAX','AUDIT-CPP-UNAVAILABLE','AUDIT-CPP-ERR') }).Count -ge 1
    $cppOk = ($rules -contains 'RA301') -and $cppSyntaxEngaged
    $pyOk  = ($rules -contains 'RA303') -and ($rules -contains 'RA304') -and
             ((($j.Findings | Where-Object File -like '*bad.py') | Where-Object Rule -eq 'SYNTAX').Count -ge 1 -or ($rules -contains 'AUDIT-PY-UNAVAILABLE'))
    Remove-Item -Recurse -Force $mlRoot -ErrorAction SilentlyContinue
    return $cppOk -and $pyOk
}

New-Case 'AutoFix: audit -AutoFix chains into the fixer and writes the corrected tree' {
    $afRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("RF_autofix_" + [guid]::NewGuid().ToString('N'))
    New-Item -Path $afRoot -ItemType Directory -Force | Out-Null
    $app = Join-Path $afRoot 'App.cs'
    'var x = [System.Com](https://System.Com)ponentModel;' | Set-Content -Path $app -Encoding UTF8
    $before = (Get-FileHash $app -Algorithm SHA256).Hash
    $out = & $TargetShell -NoProfile -File $target $afRoot -AutoFix 2>&1 | ForEach-Object { "$_" }
    $exit = $LASTEXITCODE
    $after = (Get-FileHash $app -Algorithm SHA256).Hash
    $text = $out -join "`n"
    $dest = Get-FixedTreeFromOutput -Text $text
    $fixedOk = $false
    if ($dest) {
        $fixedOk = (Test-Path -LiteralPath (Join-Path $dest 'FixReport.json')) -and
                   ((Get-Content -Raw (Join-Path $dest 'App.cs')) -match 'System\.ComponentModel')
        Remove-FixedTree -Path $dest
    }
    Remove-Item -Recurse -Force $afRoot -ErrorAction SilentlyContinue
    return ($exit -eq 0) -and
           ($text -match 'AutoFix: invoking Invoke-RoslynFix') -and
           ($dest -ne $null) -and $fixedOk -and ($before -eq $after)
}

New-Case 'AutoFix: skipped with a clean target (no findings to correct)' {
    $skRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("RF_skip_" + [guid]::NewGuid().ToString('N'))
    New-Item -Path $skRoot -ItemType Directory -Force | Out-Null
    'Write-Host "clean"' | Set-Content -Path (Join-Path $skRoot 'ok.ps1') -Encoding UTF8
    $out = & $TargetShell -NoProfile -File $target $skRoot -AutoFix 2>&1 | ForEach-Object { "$_" }
    $exit = $LASTEXITCODE
    Remove-Item -Recurse -Force $skRoot -ErrorAction SilentlyContinue
    return ($exit -eq 0) -and (($out -join "`n") -match 'AutoFix skipped: the audit found no findings')
}

New-Case 'RA306: corruption caught in XAML/csproj and code comments; fixed and XML-verified' {
    $rfRoot = Join-Path ([System.IO.Path]::GetTempPath()) ("RF_ra306_" + [guid]::NewGuid().ToString('N'))
    New-Item -Path (Join-Path $rfRoot 'src') -ItemType Directory -Force | Out-Null
    @'
<Application x:Class="[NEMESIS.Wpf.App](https://NEMESIS.Wpf.App)"
             xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml">
    <[ResourceDictionary.Me](https://ResourceDictionary.Me)rgedDictionaries />
</Application>
'@ | Set-Content -Path (Join-Path $rfRoot 'src' 'App.xaml') -Encoding UTF8
    '<Project Sdk="[Microsoft.NET](https://Microsoft.NET).Sdk"><PropertyGroup /></Project>' |
        Set-Content -Path (Join-Path $rfRoot 'src' 'Proj.csproj') -Encoding UTF8
    @'
namespace X;
public class Doc {
    /// See <see cref="[System.Com](https://System.Com)ponentModel"/> docs.
    public void M() { }
}
'@ | Set-Content -Path (Join-Path $rfRoot 'src' 'Doc.cs') -Encoding UTF8
    $report = Join-Path $rfRoot 'report.json'
    $null = Run-Script @((Join-Path $rfRoot 'src'), '-ReportPath', $report)
    $j = Get-Json $report
    $ra306 = @($j.Findings | Where-Object Rule -eq 'RA306')
    $docClean = (($j.Findings | Where-Object File -like '*Doc.cs') | Where-Object Rule -eq 'SYNTAX').Count -eq 0
    $out = & $TargetShell -NoProfile -File $fixerPath $report -OutputPath (Join-Path $rfRoot 'fixed') 2>&1 | ForEach-Object { "$_" }
    $exit = $LASTEXITCODE
    $text = $out -join "`n"
    $fixReport = Get-Content -Raw (Join-Path $rfRoot 'fixed' 'FixReport.json') | ConvertFrom-Json
    $manualCount = @($fixReport.ManualReview).Count
    $fixedXaml = Get-Content -Raw (Join-Path $rfRoot 'fixed' 'App.xaml')
    $fixedCsproj = Get-Content -Raw (Join-Path $rfRoot 'fixed' 'Proj.csproj')
    $fixedDoc = Get-Content -Raw (Join-Path $rfRoot 'fixed' 'Doc.cs')
    $xamlOk = $false
    try { $probe = New-Object System.Xml.XmlDocument; $probe.LoadXml($fixedXaml); $xamlOk = $true } catch { $xamlOk = $false }
    Remove-Item -Recurse -Force $rfRoot -ErrorAction SilentlyContinue
    return ($ra306.Count -eq 4) -and $docClean -and ($exit -eq 0) -and
           ($text -match 'Verification: findings 4 -> 0') -and ($manualCount -eq 0) -and
           $xamlOk -and
           ($fixedCsproj -match 'Sdk="Microsoft\.NET\.Sdk"') -and
           ($fixedDoc -match 'System\.Windows\.ComponentModel|System\.ComponentModel')
}

Write-Host ""
Write-Host ("RESULT: {0} passed, {1} failed" -f $pass, $fail) -ForegroundColor $(if ($fail -eq 0) { 'Green' } else { 'Red' })
if ($failures) { Write-Host "Failed: $($failures -join ' | ')" -ForegroundColor Red }
exit $(if ($fail -eq 0) { 0 } else { 1 })