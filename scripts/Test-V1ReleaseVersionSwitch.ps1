[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Utf8NoBom = New-Object System.Text.UTF8Encoding($false, $true)
$Git = (Get-Command git -CommandType Application | Select-Object -First 1).Source
$Cargo = (Get-Command cargo -CommandType Application | Select-Object -First 1).Source
$SourceRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$TestRoot = Join-Path $SourceRoot ('target/version-switch-selftest-' + [Guid]::NewGuid().ToString('N'))
$OwnerToken = [Guid]::NewGuid().ToString('N')

function Assert-Test {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if (-not $Condition) {
        throw "version switch self-test failed: $Message"
    }
}

function Write-Utf8 {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Content
    )
    $parent = [System.IO.Path]::GetDirectoryName($Path)
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        [System.IO.Directory]::CreateDirectory($parent) | Out-Null
    }
    [System.IO.File]::WriteAllText($Path, $Content, $script:Utf8NoBom)
}

function Invoke-GitFixture {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )
    Push-Location -LiteralPath $Root
    try {
        $savedPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            $output = @(& $script:Git @Arguments 2>&1)
            $exitCode = $LASTEXITCODE
        }
        finally {
            $ErrorActionPreference = $savedPreference
        }
        if ($exitCode -ne 0) {
            throw 'fixture git command failed'
        }
        return $output
    }
    finally {
        Pop-Location
    }
}

function New-Fixture {
    param([Parameter(Mandatory = $true)][string]$Name)
    $root = Join-Path $script:TestRoot $Name
    [System.IO.Directory]::CreateDirectory($root) | Out-Null
    Write-Utf8 (Join-Path $root '.serctl-version-switch-test-fixture') "SERCTL_VERSION_SWITCH_TEST_FIXTURE_V1`n"
    Write-Utf8 (Join-Path $root 'Cargo.toml') @'
[workspace]
resolver = "2"
members = ["crates/serctl-a", "crates/serctl-b"]

[workspace.package]
version = "0.3.0-beta.2"
edition = "2021"
license = "Apache-2.0"
repository = "https://github.com/example/serctl-fixture"

[workspace.dependencies]
serctl-a = { version = "=0.3.0-beta.2", path = "crates/serctl-a" }
'@
    Write-Utf8 (Join-Path $root 'crates/serctl-a/Cargo.toml') @'
[package]
name = "serctl-a"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true
'@
    Write-Utf8 (Join-Path $root 'crates/serctl-a/src/lib.rs') "pub fn a() {}`n"
    Write-Utf8 (Join-Path $root 'crates/serctl-b/Cargo.toml') @'
[package]
name = "serctl-b"
version.workspace = true
edition.workspace = true
license.workspace = true
repository.workspace = true

[dependencies]
serctl-a.workspace = true
'@
    Write-Utf8 (Join-Path $root 'crates/serctl-b/src/lib.rs') "pub fn b() { serctl_a::a(); }`n"
    Write-Utf8 (Join-Path $root 'CHANGELOG.md') @'
# Changelog

## v1.0.0-beta - Unreleased

> **Candidate state**: current workspace and release marker remain `v0.3.0-beta.2` until exact-tag gates pass.

## v0.3.0-beta.2 - 2026-08-31

Predecessor history.
'@
    Write-Utf8 (Join-Path $root 'README.md') @'
# fixture

Current rewrite prerelease **v0.3.0-beta.2** remains test-only.
<!-- release-marker: v0.3.0-beta.2 -->

> Workspace **v1.0.0-beta candidate** is pending; the current marker remains v0.3.0-beta.2.

Current release `v0.3.0-beta.2`; worktree `v1.0.0-beta` remains a candidate.
'@
    Write-Utf8 (Join-Path $root 'docs/serctl-user-guide.md') @'
# Guide

Applicable version: `v0.3.0-beta.2` (prerelease)
<!-- applicable-version: v0.3.0-beta.2 -->

> Current marker v0.3.0-beta.2; v1.0.0-beta is pending.

The v1.0.0-beta capability does not rewrite current v0.3.0-beta.2.
'@
    Write-Utf8 (Join-Path $root 'docs/serctl-architecture-security.html') @'
<!doctype html><html><body>
<span data-release-candidate="v1.0.0-beta">Candidate: <code>v1.0.0-beta</code> (pending)</span>
<span data-release-predecessor="v0.3.0-beta.2">Predecessor: <code>v0.3.0-beta.2</code></span>
</body></html>
'@
    # Copy the actual document shapes.  These contain many historical beta
    # references; only their unique HTML machine marker may advance.
    foreach ($document in @(
        'docs/v1-beta-release-contract.md',
        'docs/v1-beta-agent-jsonl.md',
        'docs/v1-beta-acceptance-matrix.md'
    )) {
        Copy-Item `
            -LiteralPath (Join-Path $script:SourceRoot $document) `
            -Destination (Join-Path $root $document)
    }
    Copy-Item `
        -LiteralPath (Join-Path $script:SourceRoot 'SECURITY.md') `
        -Destination (Join-Path $root 'SECURITY.md')
    Write-Utf8 (Join-Path $root 'scripts/Test-V1BetaDocumentation.ps1') "Set-StrictMode -Version Latest`n`$ErrorActionPreference = 'Stop'`nWrite-Output 'fixture docs PASS'`n"
    Copy-Item -LiteralPath (Join-Path $script:SourceRoot 'scripts/Set-V1ReleaseVersion.ps1') -Destination (Join-Path $root 'scripts/Set-V1ReleaseVersion.ps1')
    Copy-Item -LiteralPath (Join-Path $script:SourceRoot 'scripts/Verify-ReleaseConsistency.ps1') -Destination (Join-Path $root 'scripts/Verify-ReleaseConsistency.ps1')

    Push-Location -LiteralPath $root
    try {
        $savedPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            & $script:Cargo generate-lockfile --offline
            $cargoExitCode = $LASTEXITCODE
        }
        finally {
            $ErrorActionPreference = $savedPreference
        }
        Assert-Test ($cargoExitCode -eq 0) 'fixture cargo generate-lockfile failed'
    }
    finally {
        Pop-Location
    }
    Invoke-GitFixture $root @('init') | Out-Null
    Invoke-GitFixture $root @('config', 'user.name', 'serctl fixture') | Out-Null
    Invoke-GitFixture $root @('config', 'user.email', 'fixture@example.invalid') | Out-Null
    Invoke-GitFixture $root @('add', '--all') | Out-Null
    Invoke-GitFixture $root @('commit', '-m', 'fixture baseline') | Out-Null
    return $root
}

function Prepare-NextBetaFixture {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$CurrentTag,
        [Parameter(Mandatory = $true)][string]$TargetTag
    )
    $changelogPath = Join-Path $Root 'CHANGELOG.md'
    $changelog = [IO.File]::ReadAllText($changelogPath, $script:Utf8NoBom)
    $heading = "# Changelog`r`n`r`n"
    if (-not $changelog.StartsWith($heading)) { $heading = "# Changelog`n`n" }
    Assert-Test $changelog.StartsWith($heading) 'fixture changelog prefix changed'
    $newline = if ($heading.Contains("`r")) { "`r`n" } else { "`n" }
    $history = $changelog.Substring($heading.Length)
    Write-Utf8 $changelogPath (
        $heading + "## $TargetTag - Unreleased$newline$newline" +
        "> **Candidate state**: current workspace and release marker remain ``$CurrentTag`` until exact-tag gates pass.$newline$newline" +
        $history
    )
    Write-Utf8 (Join-Path $Root 'README.md') @"
# fixture

Current rewrite prerelease **$CurrentTag** remains test-only.
<!-- release-marker: $CurrentTag -->

> Next **$TargetTag candidate** is pending; the current marker remains $CurrentTag.

Current release ``$CurrentTag``; worktree ``$TargetTag`` remains a candidate.
"@
    Write-Utf8 (Join-Path $Root 'docs/serctl-user-guide.md') @"
# Guide

Applicable version: ``$CurrentTag`` (prerelease)
<!-- applicable-version: $CurrentTag -->

> Current marker $CurrentTag; $TargetTag is pending.

The $TargetTag capability does not rewrite current $CurrentTag.
"@
    Write-Utf8 (Join-Path $Root 'docs/serctl-architecture-security.html') @"
<!doctype html><html><body>
<span data-release-candidate="$TargetTag">Candidate: <code>$TargetTag</code> (pending)</span>
<span data-release-predecessor="$CurrentTag">Predecessor: <code>$CurrentTag</code></span>
</body></html>
"@
}

function Assert-VersionSwitchRejected {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Version,
        [Parameter(Mandatory = $true)][string]$Description
    )
    $rejected = $false
    try {
        & (Join-Path $Root 'scripts/Set-V1ReleaseVersion.ps1') `
            -Version $Version -WhatIf -ReleaseDate 2026-09-02 -TestFixture | Out-Null
    }
    catch { $rejected = $true }
    Assert-Test $rejected "$Description was accepted"
}

function Get-MachineMarkerNeutralDocument {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$RelativePath,
        [Parameter(Mandatory = $true)][string]$MarkerName
    )
    $text = [IO.File]::ReadAllText((Join-Path $Root $RelativePath), $script:Utf8NoBom)
    $pattern = '<!--\s*' + [regex]::Escape($MarkerName) + ':\s*[^\s]+\s*-->'
    $matches = [regex]::Matches($text, $pattern)
    Assert-Test ($matches.Count -eq 1) "$RelativePath lacks one machine marker"
    return [regex]::Replace($text, $pattern, "<!-- ${MarkerName}: __VERSION__ -->")
}

function Get-CurrentSecurityLineNeutralDocument {
    param([Parameter(Mandatory = $true)][string]$Root)
    $path = Join-Path $Root 'SECURITY.md'
    $text = [IO.File]::ReadAllText($path, $script:Utf8NoBom)
    $pattern = '(?m)^\| `v1\.0\.0-beta(?:\.[1-9][0-9]*)?` \| Supported after its tagged acceptance workflow publishes the attested prerelease; fixes are delivered as a new immutable prerelease tag\. \|$'
    Assert-Test ([regex]::Matches($text, $pattern).Count -eq 1) (
        'SECURITY does not contain exactly one current supported prerelease line'
    )
    return [regex]::Replace(
        $text,
        $pattern,
        '| `__CURRENT_BETA__` | Supported after its tagged acceptance workflow publishes the attested prerelease; fixes are delivered as a new immutable prerelease tag. |'
    )
}

function Get-TrackedHashes {
    param([Parameter(Mandatory = $true)][string]$Root)
    $result = @{}
    foreach ($relative in @(Invoke-GitFixture $Root @('ls-files'))) {
        $path = Join-Path $Root ([string]$relative)
        $result[[string]$relative] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    }
    return $result
}

[System.IO.Directory]::CreateDirectory($TestRoot) | Out-Null
Write-Utf8 (Join-Path $TestRoot 'owner-token') $OwnerToken
try {
    $success = New-Fixture 'success'
    $baselineHead = ([string](Invoke-GitFixture $success @('rev-parse', 'HEAD'))).Trim()
    $baselineTree = ([string](Invoke-GitFixture $success @('rev-parse', 'HEAD^{tree}'))).Trim()

    & (Join-Path $success 'scripts/Set-V1ReleaseVersion.ps1') -Version 1.0.0-beta -WhatIf -ReleaseDate 2026-09-01 -TestFixture | Out-Null
    Assert-Test (@(Invoke-GitFixture $success @('status', '--porcelain=v1', '--untracked-files=all')).Count -eq 0) 'WhatIf changed the fixture'

    & (Join-Path $success 'scripts/Set-V1ReleaseVersion.ps1') -Version 1.0.0-beta -Apply -ReleaseDate 2026-09-01 -TestFixture | Out-Null
    & (Join-Path $success 'scripts/Verify-ReleaseConsistency.ps1') -Tag v1.0.0-beta | Out-Null
    Assert-Test ($LASTEXITCODE -eq 0) 'post-Apply Verify-ReleaseConsistency failed'
    Assert-Test (([string](Invoke-GitFixture $success @('rev-parse', 'HEAD'))).Trim() -ceq $baselineHead) 'Apply changed HEAD'
    Assert-Test (([string](Invoke-GitFixture $success @('rev-parse', 'HEAD^{tree}'))).Trim() -ceq $baselineTree) 'Apply changed HEAD tree'
    $successStatus = @(Invoke-GitFixture $success @('status', '--porcelain=v1', '--untracked-files=all'))
    Assert-Test ($successStatus.Count -eq 6) 'Apply did not leave the exact six approved source changes'
    Invoke-GitFixture $success @('add', '--all') | Out-Null
    Invoke-GitFixture $success @('commit', '-m', 'freeze initial beta') | Out-Null

    $neutralGovernance = [ordered]@{}
    foreach ($binding in @(
        @('docs/v1-beta-release-contract.md', 'release-tag'),
        @('docs/v1-beta-agent-jsonl.md', 'target-release'),
        @('docs/v1-beta-acceptance-matrix.md', 'normative-release')
    )) {
        $neutralGovernance[[string]$binding[0]] = Get-MachineMarkerNeutralDocument `
            $success ([string]$binding[0]) ([string]$binding[1])
    }
    $neutralSecurity = Get-CurrentSecurityLineNeutralDocument $success
    $rollbackPredecessorLine = '| `v0.3.0-beta.2` | Rollback predecessor during the v1 beta compatibility window; critical fixes only until the v1 beta line is superseded. |'

    $betaHistory = ([IO.File]::ReadAllText(
        (Join-Path $success 'CHANGELOG.md'), $Utf8NoBom
    ) -split '(?m)(?=^## v1\.0\.0-beta - )', 2)[1]
    Prepare-NextBetaFixture $success 'v1.0.0-beta' 'v1.0.0-beta.1'
    Invoke-GitFixture $success @('add', '--all') | Out-Null
    Invoke-GitFixture $success @('commit', '-m', 'prepare beta one') | Out-Null
    & (Join-Path $success 'scripts/Set-V1ReleaseVersion.ps1') `
        -Version 1.0.0-beta.1 -Apply -ReleaseDate 2026-09-02 -TestFixture | Out-Null
    & (Join-Path $success 'scripts/Verify-ReleaseConsistency.ps1') `
        -Tag v1.0.0-beta.1 | Out-Null
    Assert-Test ($LASTEXITCODE -eq 0) 'beta -> beta.1 consistency verification failed'
    $afterBetaOne = [IO.File]::ReadAllText((Join-Path $success 'CHANGELOG.md'), $Utf8NoBom)
    Assert-Test ($afterBetaOne.EndsWith($betaHistory)) (
        'beta -> beta.1 modified the prior dated release record'
    )
    foreach ($binding in @(
        @('docs/v1-beta-release-contract.md', 'release-tag'),
        @('docs/v1-beta-agent-jsonl.md', 'target-release'),
        @('docs/v1-beta-acceptance-matrix.md', 'normative-release')
    )) {
        Assert-Test (
            (Get-MachineMarkerNeutralDocument $success $binding[0] $binding[1]) -ceq
                [string]$neutralGovernance[[string]$binding[0]]
        ) "beta -> beta.1 modified historical prose in $($binding[0])"
    }
    $betaOneSecurity = [IO.File]::ReadAllText(
        (Join-Path $success 'SECURITY.md'), $Utf8NoBom
    )
    Assert-Test (
        (Get-CurrentSecurityLineNeutralDocument $success) -ceq $neutralSecurity -and
        $betaOneSecurity.Contains($rollbackPredecessorLine)
    ) 'beta -> beta.1 modified SECURITY history or its rollback predecessor'
    Assert-Test (
        @(Invoke-GitFixture $success @('status', '--porcelain=v1', '--untracked-files=all')).Count -eq 10
    ) 'beta -> beta.1 did not leave the exact ten approved identity changes'
    Invoke-GitFixture $success @('add', '--all') | Out-Null
    Invoke-GitFixture $success @('commit', '-m', 'freeze beta one') | Out-Null

    $betaOneHistory = ($afterBetaOne -split '(?m)(?=^## v1\.0\.0-beta\.1 - )', 2)[1]
    Prepare-NextBetaFixture $success 'v1.0.0-beta.1' 'v1.0.0-beta.2'
    Invoke-GitFixture $success @('add', '--all') | Out-Null
    Invoke-GitFixture $success @('commit', '-m', 'prepare beta two') | Out-Null
    & (Join-Path $success 'scripts/Set-V1ReleaseVersion.ps1') `
        -Version 1.0.0-beta.2 -Apply -ReleaseDate 2026-09-03 -TestFixture | Out-Null
    & (Join-Path $success 'scripts/Verify-ReleaseConsistency.ps1') `
        -Tag v1.0.0-beta.2 | Out-Null
    Assert-Test ($LASTEXITCODE -eq 0) 'beta.N -> beta.(N+1) consistency verification failed'
    $afterBetaTwo = [IO.File]::ReadAllText((Join-Path $success 'CHANGELOG.md'), $Utf8NoBom)
    Assert-Test ($afterBetaTwo.EndsWith($betaOneHistory)) (
        'beta.N -> beta.(N+1) modified an earlier release record'
    )
    foreach ($binding in @(
        @('docs/v1-beta-release-contract.md', 'release-tag'),
        @('docs/v1-beta-agent-jsonl.md', 'target-release'),
        @('docs/v1-beta-acceptance-matrix.md', 'normative-release')
    )) {
        Assert-Test (
            (Get-MachineMarkerNeutralDocument $success $binding[0] $binding[1]) -ceq
                [string]$neutralGovernance[[string]$binding[0]]
        ) "beta.N transition modified historical prose in $($binding[0])"
    }
    $betaTwoSecurity = [IO.File]::ReadAllText(
        (Join-Path $success 'SECURITY.md'), $Utf8NoBom
    )
    Assert-Test (
        (Get-CurrentSecurityLineNeutralDocument $success) -ceq $neutralSecurity -and
        $betaTwoSecurity.Contains($rollbackPredecessorLine)
    ) 'beta.N transition modified SECURITY history or its rollback predecessor'
    Invoke-GitFixture $success @('add', '--all') | Out-Null
    Invoke-GitFixture $success @('commit', '-m', 'freeze beta two') | Out-Null

    Assert-VersionSwitchRejected $success '1.0.0-beta.2' 'same beta version'
    Assert-VersionSwitchRejected $success '1.0.0-beta.1' 'beta downgrade'
    Assert-VersionSwitchRejected $success '1.0.0-beta.4' 'beta ordinal jump'
    Assert-VersionSwitchRejected $success '1.0.0-beta.0' 'beta zero ordinal'
    Assert-VersionSwitchRejected $success '1.0.0-beta.03' 'beta leading-zero ordinal'
    $verifyBetaZeroRejected = $false
    try {
        & (Join-Path $success 'scripts/Verify-ReleaseConsistency.ps1') `
            -Tag v1.0.0-beta.0 | Out-Null
    }
    catch { $verifyBetaZeroRejected = $true }
    Assert-Test $verifyBetaZeroRejected 'release verifier accepted beta.0'

    $initialSkip = New-Fixture 'initial-skip'
    Assert-VersionSwitchRejected $initialSkip '1.0.0-beta.1' '0.3 to beta.1 skip'

    $failure = New-Fixture 'failure'
    $failureHashes = Get-TrackedHashes $failure
    $failed = $false
    try {
        & (Join-Path $failure 'scripts/Set-V1ReleaseVersion.ps1') -Version 1.0.0-beta -Apply -ReleaseDate 2026-09-01 -TestFixture -InjectFailureAfterWrites 3 | Out-Null
    }
    catch {
        $failed = $true
    }
    Assert-Test $failed 'failure injection unexpectedly succeeded'
    Assert-Test (@(Invoke-GitFixture $failure @('status', '--porcelain=v1', '--untracked-files=all')).Count -eq 0) 'failure injection did not restore clean status'
    $restoredHashes = Get-TrackedHashes $failure
    Assert-Test ($restoredHashes.Count -eq $failureHashes.Count) 'rollback changed the tracked file set'
    foreach ($relative in $failureHashes.Keys) {
        Assert-Test ([string]$restoredHashes[$relative] -ceq [string]$failureHashes[$relative]) "rollback changed bytes for $relative"
    }

    Add-Content -LiteralPath (Join-Path $failure 'README.md') -Value '<!-- release-marker: v0.3.0-beta.2 -->' -Encoding utf8
    Invoke-GitFixture $failure @('add', 'README.md') | Out-Null
    Invoke-GitFixture $failure @('commit', '-m', 'duplicate marker fixture') | Out-Null
    $duplicateRejected = $false
    try {
        & (Join-Path $failure 'scripts/Set-V1ReleaseVersion.ps1') -Version 1.0.0-beta -WhatIf -ReleaseDate 2026-09-01 -TestFixture | Out-Null
    }
    catch {
        $duplicateRejected = $true
    }
    Assert-Test $duplicateRejected 'duplicate old current marker was not rejected'

    Write-Output 'V1 release version switch synthetic self-test: PASS'
}
finally {
    if (Test-Path -LiteralPath $TestRoot -PathType Container) {
        $tokenPath = Join-Path $TestRoot 'owner-token'
        if ((Test-Path -LiteralPath $tokenPath -PathType Leaf) -and
            ([System.IO.File]::ReadAllText($tokenPath, $Utf8NoBom) -ceq $OwnerToken)) {
            Remove-Item -LiteralPath $TestRoot -Recurse -Force
        }
    }
}
