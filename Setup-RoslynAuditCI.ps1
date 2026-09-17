param (
    [Parameter(Mandatory=$true, HelpMessage="The full URL to the Git repository.")]
    [string]$RepositoryUrl,
    
    [Parameter(Mandatory=$false, HelpMessage="Local folder to clone into.")]
    [string]$LocalPath = ".\RoslynAuditRepo"
)

$ErrorActionPreference = 'Stop'

Write-Host "Cloning $RepositoryUrl into $LocalPath..." -ForegroundColor Cyan
git clone $RepositoryUrl $LocalPath

$workflowDir = Join-Path $LocalPath ".github\workflows"
Write-Host "Creating workflow directory at $workflowDir..." -ForegroundColor Cyan
New-Item -ItemType Directory -Force -Path $workflowDir | Out-Null

$yamlContent = @'
name: RoslynAudit CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  analyze:
    name: PSScriptAnalyzer gate
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run PSScriptAnalyzer
        shell: pwsh
        run: |
          Set-StrictMode -Version 3.0
          Install-Module PSScriptAnalyzer -Scope CurrentUser -Force
          $files = @('./Invoke-RoslynAudit.ps1', './Invoke-RoslynFix.ps1', './test-suite.ps1') | Where-Object { Test-Path $_ }
          $findings = @(Invoke-ScriptAnalyzer -Path $files)
          if ($findings.Count -gt 0) { throw "PSScriptAnalyzer reported $($findings.Count) finding(s)." }

  regression:
    name: Regression suite
    runs-on: windows-latest
    steps:
      - uses: actions/checkout@v4
      - name: Test suite
        shell: pwsh
        run: ./test-suite.ps1

  code-scanning:
    name: Upload SARIF to GitHub code scanning
    runs-on: ubuntu-latest
    needs: regression
    permissions:
      security-events: write
    steps:
      - uses: actions/checkout@v4
      - name: Run Invoke-RoslynAudit
        shell: pwsh
        run: ./Invoke-RoslynAudit.ps1 . -Sarif -ReportPath ./roslyn-audit.sarif -FailOn ERROR
        continue-on-error: true
      - name: Upload SARIF
        if: hashFiles('roslyn-audit.sarif') != ''
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ./roslyn-audit.sarif
'@

$workflowPath = Join-Path $workflowDir "roslyn-audit-ci.yml"
Write-Host "Writing workflow file to $workflowPath..." -ForegroundColor Cyan
Set-Content -Path $workflowPath -Value $yamlContent -Encoding UTF8

Write-Host "Committing changes to a new branch..." -ForegroundColor Cyan
Push-Location $LocalPath
git checkout -b setup-roslyn-ci
git add .github/workflows/roslyn-audit-ci.yml
git commit -m "ci: add native RoslynAudit GitHub Actions workflow"
Pop-Location

Write-Host "`nSetup complete! Navigate to the folder and push your branch:" -ForegroundColor Green
Write-Host "  cd $LocalPath"
Write-Host "  git push -u origin setup-roslyn-ci"