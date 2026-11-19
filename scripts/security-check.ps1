<#
.SYNOPSIS
  Runs NetHelper's full security suite and writes a report.

.DESCRIPTION
  One command for every security check (see docs/development.md, "Security
  review gate"). Runs under PowerShell 7 (pwsh) or Windows PowerShell 5.1.

  Checks, in order:
    1. ruff                 - code-quality lint (unused code, likely bugs)
    2. bandit               - Python security linter (SAST) over nethelper/.
                              Every "# nosec" suppression is listed in the
                              report (bandit --show-ignored style summary).
    3. semgrep              - OWASP/Python rulesets (SAST), if installed
    4. PSScriptAnalyzer     - PowerShell linter over scripts/, if installed
                              (PSAvoidUsingWriteHost excluded: coloured console
                              output is intended in an interactive script)
    5. pip-audit            - known vulnerabilities in the dev/test toolchain
                              (NetHelper itself has NO runtime dependencies)
    6. gitleaks             - secrets in the working tree and the staged diff
    7. pytest (Windows)     - all tests, including the security tests
    8. pytest (Linux/WSL)   - the same suite on Linux, if WSL is available
    9. outdated dev tools   - informational, never fails the run

  Tools are run from the project's .venv (create it with:
    python -m venv .venv; .venv\Scripts\pip install -r requirements-dev.txt).
  A tool that can't run is reported NOT RUN with the reason - never silently
  skipped or shown as passing.

  Output: a summary table on screen plus a full Markdown report in
  security-reports/ (gitignored - reports describe unfixed weaknesses).
  Exit code 0 only if every check that ran passed.

  Read-only apart from writing the report file.

.EXAMPLE
  pwsh ./scripts/security-check.ps1
#>
$ErrorActionPreference = 'Continue'
Set-Location (Join-Path $PSScriptRoot '..')

# Version comes from the single source of truth in nethelper/__init__.py.
$version = (Select-String -Path nethelper/__init__.py -Pattern '__version__ = "([^"]+)"').Matches[0].Groups[1].Value
$commit = (git rev-parse --short HEAD 2>$null)
if (-not $commit) { $commit = 'uncommitted' }
$porcelain = git status --porcelain 2>$null  # lists uncommitted changes, if any
$dirty = if ($porcelain) { ' (+ uncommitted changes)' } else { '' }
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$venvBin = if (Test-Path .venv/Scripts) { '.venv/Scripts' } else { '.venv/bin' }
$py = Join-Path $venvBin 'python'

# Each check records: name, status (PASS/FAIL/NOT RUN), a one-line summary,
# and its full output for the report.
$results = [System.Collections.Generic.List[object]]::new()

function Invoke-Check {
  <#
    Runs one check. The check PASSES when the last native command exits 0,
    unless the optional $Pass script block decides otherwise.
  #>
  param([string]$Name, [scriptblock]$Script, [scriptblock]$Pass)
  Write-Host "-> $Name" -ForegroundColor Cyan
  $out = & $Script 2>&1 | Out-String
  $code = $LASTEXITCODE
  $ok = if ($Pass) { & $Pass $out $code } else { $code -eq 0 }
  $status = if ($ok) { 'PASS' } else { 'FAIL' }
  $summary = ($out.Trim() -split "`n" | Where-Object { $_.Trim() } | Select-Object -Last 1)
  $results.Add([pscustomobject]@{ Check = $Name; Status = $status; Summary = "$summary".Trim(); Output = $out })
}

function Add-NotRun {
  <# Records a check that could not run, with the reason. #>
  param([string]$Name, [string]$Reason)
  Write-Host "-> $Name : NOT RUN ($Reason)" -ForegroundColor Yellow
  $results.Add([pscustomobject]@{ Check = $Name; Status = 'NOT RUN'; Summary = $Reason; Output = '' })
}

if (-not (Test-Path $py) -and -not (Test-Path "$py.exe")) {
  Write-Host 'No .venv found. Create it: python -m venv .venv; then install requirements-dev.txt' -ForegroundColor Red
  exit 2
}

# 1. Code-quality lint.
Invoke-Check 'ruff (lint)' { & $py -m ruff check nethelper tests }

# 2. Python security linter. Any finding fails; suppressions are listed separately.
Invoke-Check 'bandit (SAST)' { & $py -m bandit -c pyproject.toml -r nethelper -f txt }
$suppressed = Select-String -Path nethelper/*.py, nethelper/*/*.py -Pattern '# nosec' | ForEach-Object {
  $prev = (Get-Content $_.Path)[$_.LineNumber - 2].Trim()
  "$($_.Path | Resolve-Path -Relative):$($_.LineNumber)  $($_.Line.Trim())`n    justification: $prev"
} | Out-String
$results.Add([pscustomobject]@{ Check = 'bandit suppressions (info)'; Status = 'PASS';
    Summary = "$(([regex]::Matches($suppressed, '# nosec')).Count) justified # nosec line(s) - review in report"; Output = $suppressed })

# 3. semgrep (optional external tool).
if (Get-Command semgrep -ErrorAction SilentlyContinue) {
  Invoke-Check 'semgrep (OWASP/Python)' { semgrep scan --config p/python --config p/owasp-top-ten --error --quiet nethelper }
} else { Add-NotRun 'semgrep (OWASP/Python)' 'semgrep is not installed (pip install semgrep; Linux/macOS/WSL)' }

# 4. PowerShell linter over this repo's scripts.
if (Get-Module -ListAvailable PSScriptAnalyzer) {
  Invoke-Check 'PSScriptAnalyzer (scripts)' {
    $found = Invoke-ScriptAnalyzer -Path scripts -Recurse -Severity Warning, Error -ExcludeRule PSAvoidUsingWriteHost
    $found | Format-Table RuleName, Severity, ScriptName, Line, Message -AutoSize -Wrap | Out-String -Width 200
    "PSScriptAnalyzer findings: $(@($found).Count)"
  } { param($o) $o -match 'PSScriptAnalyzer findings: 0\b' }
} else { Add-NotRun 'PSScriptAnalyzer (scripts)' 'module not installed (Install-Module PSScriptAnalyzer -Scope CurrentUser)' }

# 5. Dependency vulnerabilities (dev toolchain; the app has no runtime deps).
Invoke-Check 'pip-audit (dev deps)' { & $py -m pip_audit -r requirements-dev.txt --progress-spinner off }

# 6. Secret scanning.
if (Get-Command gitleaks -ErrorAction SilentlyContinue) {
  Invoke-Check 'gitleaks (working tree)' { gitleaks dir . --no-banner --redact }
  $gitDir = git rev-parse --git-dir 2>$null  # empty when this isn't a git repository
  if ($gitDir) {
    Invoke-Check 'gitleaks (staged diff)' { gitleaks git --pre-commit --staged --no-banner --redact . }
  } else { Add-NotRun 'gitleaks (staged diff)' 'not a git repository yet' }
} else {
  Add-NotRun 'gitleaks (working tree)' 'gitleaks is not installed (winget install gitleaks / brew install gitleaks)'
  Add-NotRun 'gitleaks (staged diff)' 'gitleaks is not installed'
}

# 7. Tests on this OS (each security test documents the attack it blocks).
$os = if ($IsLinux) { 'Linux' } elseif ($IsMacOS) { 'macOS' } else { 'Windows' }
Invoke-Check "pytest ($os)" { & $py -m pytest -q -p no:cacheprovider }

# 8. Same suite on Linux via WSL (pytest is pure Python, so the venv's copy is reused).
if ($os -eq 'Windows' -and (Get-Command wsl -ErrorAction SilentlyContinue)) {
  $wslPath = (wsl wslpath -a ((Get-Location).Path -replace '\\', '/')) 2>$null
  if ($wslPath) {
    Invoke-Check 'pytest (Linux via WSL)' {
      wsl -e bash -lc "cd '$wslPath' && PYTHONPATH=.venv/Lib/site-packages python3 -m pytest -q -p no:cacheprovider"
    }
  } else { Add-NotRun 'pytest (Linux via WSL)' 'WSL present but no distribution responded' }
} elseif ($os -eq 'Windows') { Add-NotRun 'pytest (Linux via WSL)' 'WSL not installed - run the suite on a Linux host' }

# 9. Outdated dev tools: informational, never fails the run.
Write-Host '-> outdated dev tools' -ForegroundColor Cyan
$outdated = & $py -m pip list --outdated 2>&1 | Out-String
$results.Add([pscustomobject]@{ Check = 'outdated dev tools (info)'; Status = 'PASS';
    Summary = $(if ($outdated -match '\S+\s+\S+\s+\S+\s+wheel') { 'updates available - see report' } else { 'all current' }); Output = $outdated })

# ---- Report ----
$table = $results | ForEach-Object { "| $($_.Check) | **$($_.Status)** | $($_.Summary -replace '\|', '/') |" }
$md = @"
# NetHelper security report

- Version: $version
- Commit: $commit$dirty
- Date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss zzz')
- Host OS: $os

## Summary

| Check | Status | Summary |
|---|---|---|
$($table -join "`n")

## Findings / full output

$(($results | ForEach-Object { "### $($_.Check) - $($_.Status)`n`n``````text`n$($_.Output.Trim())`n```````n" }) -join "`n")

## Accepted risks

(none recorded)
"@
New-Item -ItemType Directory -Force security-reports | Out-Null
$file = "security-reports/v$version-$commit-$stamp.md"
Set-Content -Path $file -Value $md -Encoding utf8

Write-Host ''
$results | Format-Table Check, Status, Summary -AutoSize -Wrap | Out-String -Width 160 | Write-Host
Write-Host "Report: $file"
if ($results.Status -contains 'FAIL') { exit 1 }
exit 0
