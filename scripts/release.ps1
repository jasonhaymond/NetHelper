<#
.SYNOPSIS
  Publishes a NetHelper version as a GitHub Release with the single-file
  nethelper.pyz and its SHA-256 checksum.

.DESCRIPTION
  Every NetHelper release ships a GitHub Release carrying dist/nethelper.pyz
  (the whole program in one file, for USB sticks and client PCs) plus
  nethelper.pyz.sha256. A pushed tag without that download is an incomplete
  release.

  Run this AFTER the version has been committed, tagged (with the
  security-review approval line) and pushed. See docs/development.md,
  section 8 "Releasing a version". It runs under PowerShell 7 (pwsh) on
  Windows, macOS or Linux (version 7.3 or newer) and needs git, Python 3.11+ and the GitHub CLI
  (`gh`, signed in with `gh auth login`).

  What it does, in order:
    1. Refuses unless the tag vX.Y.Z exists as an annotated tag whose message
       contains "Security review: approved", and the tag has been pushed to
       origin. This makes the tooling enforce the security gate, rather than
       relying on someone remembering it.
    2. Checks out that exact tag into a temporary, separate folder. This is a
       "git worktree": a second checkout that shares this repo's history. The
       .pyz is therefore built from the tagged commit, never from whatever
       happens to be in your working folder (uncommitted edits included). The
       folder has a random name, and on Linux/macOS only you can open it, so
       other users of the machine can't tamper with the build.
    3. Runs that checkout's own scripts/build.py, writes the SHA-256 checksum
       file, and runs the built .pyz to confirm it reports the expected
       version.
    4. Creates the GitHub Release "NetHelper X.Y.Z" for the tag. The release
       notes are download/verify instructions followed by that version's
       CHANGELOG.md section. It then uploads the .pyz and the checksum.
    5. Removes the temporary checkout.

  Safety:
    - It never creates or moves tags and never pushes commits.
    - It refuses to touch a release that already exists unless -Replace is
      given; -Replace re-uploads the two files, overwriting the same-named
      ones.
    - -DryRun does steps 1-3 and shows what would be published, without
      contacting GitHub.

  It writes only inside the temporary checkout (deleted at the end) and, on
  a real run, to the GitHub Release.

.PARAMETER Version
  The version to release, e.g. 1.0.1. Default: the __version__ in
  nethelper/__init__.py of the current checkout.

.PARAMETER Python
  The Python interpreter used to build and test the .pyz. Default: `python`
  on Windows, `python3` elsewhere.

.PARAMETER DryRun
  Build and verify only, then print what would be uploaded.

.PARAMETER Replace
  Allow re-uploading the files to an existing release for this tag.

.EXAMPLE
  pwsh ./scripts/release.ps1 -DryRun
  pwsh ./scripts/release.ps1
  pwsh ./scripts/release.ps1 -Version 1.0.1
#>
[CmdletBinding()]
param(
  [string]$Version,
  [string]$Python,
  [switch]$DryRun,
  [switch]$Replace
)
$ErrorActionPreference = 'Stop'
# Work from the project root (the folder above scripts/), whatever folder the
# script was started from.
Set-Location (Join-Path $PSScriptRoot '..')

<#
  Fail prints a message in red and stops the script with exit code 1.
  Input: the message to show. It never returns.
#>
function Fail([string]$Message) {
  Write-Host "release: $Message" -ForegroundColor Red
  exit 1
}

# ---- Which version, and which Python ----
if (-not $Version) {
  # Read the version string from the line `__version__ = "1.0.1"`.
  $Version = (Select-String -Path nethelper/__init__.py -Pattern '__version__ = "([^"]+)"').Matches[0].Groups[1].Value
}
# Regex: three dot-separated numbers, e.g. 1.0.1 (no "v" prefix). Anything
# else is refused before it reaches a git or gh command line.
if ($Version -notmatch '^\d+\.\d+\.\d+$') { Fail "version '$Version' is not in X.Y.Z form" }
$tag = "v$Version"
if (-not $Python) { $Python = if ($IsWindows) { 'python' } else { 'python3' } }
if (-not (Get-Command $Python -ErrorAction SilentlyContinue)) { Fail "Python interpreter '$Python' not found. Pass -Python <path>." }
Write-Host "Releasing NetHelper $Version ($tag)" -ForegroundColor Cyan

# ---- 1. Gate checks ----
# "<tag>^{tag}" resolves only for an ANNOTATED tag. Lightweight tags carry no
# message, so they can't carry the approval line.
git rev-parse --verify --quiet "$tag^{tag}" *> $null
if ($LASTEXITCODE -ne 0) { Fail "$tag is not an annotated tag in this repo. Tag the approved commit first (docs/development.md section 8)." }
$tagMessage = git tag -l --format='%(contents)' $tag | Out-String
if ($tagMessage -notmatch 'Security review: approved') {
  Fail "$tag's message has no 'Security review: approved' line - the security gate has not been recorded for this version."
}
# The tag must already be on GitHub; otherwise the release would point at a
# commit nobody else can see.
$remote = git ls-remote --tags origin "refs/tags/$tag"
if (-not $remote) { Fail "$tag has not been pushed to origin. Run: git push origin $tag" }
$commit = git rev-list -n 1 $tag
Write-Host "  tag OK: $tag -> $($commit.Substring(0,7)), security approval recorded, pushed"

if (-not $DryRun) {
  gh auth status *> $null
  if ($LASTEXITCODE -ne 0) { Fail "GitHub CLI is not signed in. Run: gh auth login" }
  # `gh release view` exits 0 only if a release for this tag already exists.
  gh release view $tag *> $null
  $exists = $LASTEXITCODE -eq 0
  if ($exists -and -not $Replace) { Fail "a GitHub Release for $tag already exists. Use -Replace to re-upload its files." }
}

# ---- 2. Temporary checkout of the tag ----
# Security: the checkout goes inside a brand-new folder with a random name.
# CreateTempSubdirectory (.NET 7+, PowerShell 7.3+) creates that folder; on
# Linux/macOS only the current user can open it (mode 0700). With a fixed,
# guessable name in a shared temp folder (/tmp on Linux), another local user
# could create the folder first, then swap scripts/build.py between the
# checkout and the build, and so get a tampered .pyz published.
if ($PSVersionTable.PSVersion -lt [version]'7.3') { Fail "PowerShell 7.3 or newer is required (this is $($PSVersionTable.PSVersion))." }
$tmpRoot = [IO.Directory]::CreateTempSubdirectory('nethelper-release-').FullName
$wt = Join-Path $tmpRoot 'checkout'
git worktree add --detach --quiet $wt $tag
if ($LASTEXITCODE -ne 0) {
  Remove-Item -Recurse -Force $tmpRoot -ErrorAction SilentlyContinue
  Fail "could not check out $tag into $wt"
}
try {
  # ---- 3. Build and verify ----
  # -I = isolated mode: Python ignores PYTHON* environment variables and the
  # user's site-packages, so nothing outside the tagged checkout can change
  # what gets built.
  & $Python -I (Join-Path $wt 'scripts/build.py')
  if ($LASTEXITCODE -ne 0) { Fail 'build failed' }
  $pyz = Join-Path $wt 'dist/nethelper.pyz'
  if (-not (Test-Path $pyz)) { Fail "build did not produce $pyz" }

  # Run the built file itself and check it reports this exact version.
  $reported = (& $Python -I $pyz --version | Out-String).Trim()
  if ($reported -ne "NetHelper $Version") { Fail "built .pyz reports '$reported', expected 'NetHelper $Version'" }
  Write-Host "  build OK: $reported"

  # Checksum file in the standard `sha256sum` format ("<hash>  <file name>"),
  # so Linux/macOS users can check it with `sha256sum -c nethelper.pyz.sha256`.
  # LF line ending and no BOM, so `sha256sum -c` reads it on every platform.
  $hash = (Get-FileHash -Algorithm SHA256 $pyz).Hash.ToLowerInvariant()
  $shaFile = Join-Path $wt 'dist/nethelper.pyz.sha256'
  [IO.File]::WriteAllText($shaFile, "$hash  nethelper.pyz`n")
  Write-Host "  sha256: $hash"

  # Release notes = how to download and verify, then this version's
  # CHANGELOG.md section from the tagged commit. The regex takes everything
  # after the "## [X.Y.Z]" heading up to the next "## [" heading (or the end).
  $changelog = Get-Content (Join-Path $wt 'CHANGELOG.md') -Raw
  $pattern = '(?ms)^## \[' + [regex]::Escape($Version) + '\][^\n]*\n(.*?)(?=^## \[|\z)'
  $m = [regex]::Match($changelog, $pattern)
  if (-not $m.Success) { Fail "CHANGELOG.md at $tag has no section for $Version" }
  $notes = @"
## Download

``nethelper.pyz`` is the whole program in one file. It needs Python 3.11 or newer and nothing else:

``````
python nethelper.pyz            # interactive menu
python nethelper.pyz quick      # 10-30 s health check
``````

Verify the download against ``nethelper.pyz.sha256``:

- Windows (PowerShell): ``(Get-FileHash nethelper.pyz -Algorithm SHA256).Hash`` and compare it with the hash in the file
- Linux/macOS: ``sha256sum -c nethelper.pyz.sha256``

The build is repeatable. Running ``python scripts/build.py`` on a checkout of tag ``$tag`` (any OS, any Python 3.11+) produces a byte-identical file with the same hash.

See the [user guide](https://github.com/jasonhaymond/NetHelper/blob/$tag/docs/user-guide.md).

## Changes in $Version

$($m.Groups[1].Value.Trim())
"@
  $notesFile = Join-Path $wt 'release-notes.md'
  Set-Content -Path $notesFile -Value $notes -Encoding utf8

  $files = @(Get-Item $pyz, $shaFile)
  if ($DryRun) {
    Write-Host "`nDRY RUN - nothing published. Would upload to GitHub Release '$tag':" -ForegroundColor Yellow
    $files | ForEach-Object { '  {0,-24} {1,8:N0} KB' -f $_.Name, ($_.Length / 1KB) } | Write-Host
    Write-Host "`nRelease notes:`n$notes"
    exit 0
  }

  # ---- 4. Publish ----
  $paths = $files.FullName
  if ($exists) {
    # --clobber: replace the same-named files already on the release.
    gh release upload $tag @paths --clobber
  } else {
    # --verify-tag: refuse rather than let gh create a missing tag itself.
    gh release create $tag @paths --title "NetHelper $Version" --notes-file $notesFile --verify-tag
  }
  if ($LASTEXITCODE -ne 0) { Fail 'GitHub upload failed' }
  $url = gh release view $tag --json url -q .url
  Write-Host "`nPublished: $url" -ForegroundColor Green
}
finally {
  # ---- 5. Clean up the temporary checkout ----
  git worktree remove --force $wt *> $null
  git worktree prune *> $null # forget the checkout even if its folder was already deleted
  Remove-Item -Recurse -Force $tmpRoot -ErrorAction SilentlyContinue # and the random parent folder
}
