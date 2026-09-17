# Rythorian's Invoke-RoslynAudit

**Enterprise Roslyn SAST and code-quality analyzer for PowerShell.**
Bootstraps the .NET Compiler Platform ("Roslyn") at runtime and audits C#, Visual
Basic, PowerShell, C/C++, and Python source for syntax errors and
security/quality anti-patterns — in parallel, across platforms, with JSON or
SARIF 2.1.0 reporting.

- **Author:** Justin Ross (Farmington, Maine) 2026
- **Rules:** 95 built-in regex rules across five language series
- **Verification:** run `pwsh -NoProfile -File ./test-suite.ps1` (40 cases) and `Invoke-ScriptAnalyzer` on the three scripts to reproduce. CI in `.github/workflows/roslyn-audit-ci.yml` enforces both.

---

## 1. What does this application do?

`Invoke-RoslynAudit.ps1` is a single-file static-analysis tool. Given a file, a
directory, or a `.zip` archive, it:

1. **Bootstraps Roslyn** — on Windows PowerShell 5.1 it downloads `nuget.exe`
   and installs pinned Roslyn 4.5.0 packages; on PowerShell 7 (Linux/macOS/Windows)
   it downloads the packages from nuget.org directly. Hosts that already bundle
   Roslyn assemblies use them without any download.
2. **Discovers source files** — `.cs`, `.vb`, `.ps1`, `.psm1`, `.cpp`, `.cxx`,
   `.cc`, `.c`, `.hpp`, `.hxx`, `.hh`, `.h`, `.py`, plus markup/project files
   (`.xaml`, `.csproj`, `.props`, `.targets`, `.xml`, `.config`) — respecting a
   `.auditignore` exclusion file, or (with `-GitDiffOnly`) only files changed
   or added relative to git HEAD.
3. **Parses every file in Parallel** — real compiler syntax trees for C#/VB
   (Roslyn), the PowerShell AST parser for `.ps1/.psm1`, the host `g++`/`clang++`
   for C/C++, and the host Python interpreter for `.py`, via a runspace pool.
4. **Applies heuristic security/quality rules** — 95 built-in regex rules
   covering C#/.NET, PowerShell, C/C++, Python, and cross-language patterns
   (empty catch blocks, hardcoded secrets, weak crypto, `Invoke-Expression`,
   sync-over-async, unsafe C functions, `eval`/`exec`, YAML/pickle
   deserialization, disabled TLS verification, and more), plus optional custom
   rule packs.
5. **Reports** — My findings with file, line, rule ID, severity, message, and
   remediation guidance; to console, log file, and/or a JSON or SARIF 2.1.0
   report file. A severity gate (`-FailOn`) makes it CI-ready by exiting
   non-zero when thresholds are breached.

---

## 2. Requirements:

| Host | Minimum version | Notes |
|------|----------------|-------|
| Windows | Windows PowerShell 5.1 | Bootstraps via nuget.exe (auto-downloaded) |
| Any OS | PowerShell 7+ | Cross-platform; direct package download, no nuget.exe |
| clang++ / g++ / gcc (optional) | Path | Enables C/C++ syntax diagnostics; absent → explicit AUDIT-CPP-UNAVAILABLE finding, heuristic rules still apply |
| Python 3 (optional) | Path | Enables .py syntax diagnostics; absent → explicit AUDIT-PY-UNAVAILABLE finding, heuristic rules still apply |

- Internet access on first run (package bootstrap), **or** use
  `-LocalAssemblyPath` for air-gapped hosts.
- `git` on PATH when using `-GitDiffOnly`.
- .NET Framework 4.5.2+ (Windows) / .NET 8 (PowerShell 7.x hosts).

## 3. Installation — step by step

1. Copy `Invoke-RoslynAudit.ps1` and `Invoke-RoslynFix.ps1` to a working
   location, e.g. `C:\Tools\RoslynAudit\`.
2. If scripts are restricted, unblock the files once:
   `Unblock-File .\Invoke-RoslynAudit.ps1, .\Invoke-RoslynFix.ps1`
3. Optionally copy `.github/workflows/roslyn-audit-ci.yml` into your repository
   for CI (see §13).
4. Run it. The first invocation creates a per-user workspace
   (`%TEMP%\RoslynAuditWorkspace_<user>`) and bootstraps Roslyn there; later runs
   reuse the cached packages automatically.

```powershell
# First run against a project
pwsh -NoProfile -File C:\Tools\RoslynAudit\Invoke-RoslynAudit.ps1 C:\src\MyProject
