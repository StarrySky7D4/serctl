[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'V1BetaLocalGate.Core.ps1')

function Assert-LocalGateTest {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if (-not $Condition) {
        throw "v1 beta local-gate self-test failed: $Message"
    }
}

function Invoke-ExpectedThrow {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Action,
        [Parameter(Mandatory = $true)][string]$Description
    )

    $threw = $false
    try {
        & $Action
    }
    catch {
        $threw = $true
    }
    Assert-LocalGateTest $threw "$Description did not fail closed"
}

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$placeholderTemporary = Join-Path ([System.IO.Path]::GetTempPath()) 'serctl-gate-plan-placeholder'
$plan = @(Get-V1BetaLocalGatePlan `
    -RepositoryRoot $repositoryRoot `
    -TemporaryDirectory $placeholderTemporary)

$expectedNames = @(
    'git-diff-check',
    'rustfmt',
    'locked-metadata',
    'fuzz-locked-metadata',
    'protocol-corpus-transfer',
    'protocol-corpus-remote',
    'protocol-corpus-policy',
    'runtime-dependency-boundary',
    'documentation-governance',
    'cargo-deny',
    'workspace-check',
    'strict-clippy',
    'serial-tests',
    'build-script-cli',
    'build-script-daemon',
    'build-script-xfer',
    'build-script-remote'
)
Assert-LocalGateTest (
    (($plan.Name -join ',') -ceq ($expectedNames -join ','))
) 'step ordering or command inventory drifted'

$expectedCommandPrefixes = [ordered]@{
    'git-diff-check' = 'git diff --check'
    'rustfmt' = 'cargo fmt --all -- --check'
    'locked-metadata' = 'cargo metadata --locked --format-version 1'
    'fuzz-locked-metadata' = 'cargo metadata --manifest-path fuzz/Cargo.toml --locked --format-version 1'
    'protocol-corpus-transfer' = 'cargo test --locked -p serctl-transfer-protocol --lib'
    'protocol-corpus-remote' = 'cargo test --locked -p serctl-remote-protocol --lib'
    'protocol-corpus-policy' = 'cargo test --locked -p serctl-policy --lib'
    'runtime-dependency-boundary' = 'pwsh -NoProfile -File '
    'documentation-governance' = 'pwsh -NoProfile -File '
    'cargo-deny' = 'cargo deny --locked check bans licenses sources'
    'workspace-check' = 'cargo check --locked --workspace --all-targets --all-features'
    'strict-clippy' = 'cargo clippy --locked --workspace --all-targets --all-features -- -D warnings'
    'serial-tests' = 'cargo test --locked --workspace --all-targets --all-features -- --test-threads=1'
    'build-script-cli' = 'rustc --edition=2021 --test crates/serctl_cli/build.rs -o '
    'build-script-daemon' = 'rustc --edition=2021 --test crates/serctl_daemon/build.rs -o '
    'build-script-xfer' = 'rustc --edition=2021 --test crates/serctl_xfer/build.rs -o '
    'build-script-remote' = 'rustc --edition=2021 --test crates/serctl_remote/build.rs -o '
}
foreach ($step in $plan) {
    $prefix = $expectedCommandPrefixes[$step.Name]
    Assert-LocalGateTest (-not [string]::IsNullOrWhiteSpace($prefix)) (
        "no expected command registered for '$($step.Name)'"
    )
    Assert-LocalGateTest ($step.DisplayCommand.StartsWith(
        $prefix,
        [System.StringComparison]::Ordinal
    )) "command for '$($step.Name)' drifted: $($step.DisplayCommand)"
}

$quickSkipNames = @($plan | Where-Object SkipInQuick | ForEach-Object Name)
Assert-LocalGateTest (
    (($quickSkipNames -join ',') -ceq 'workspace-check,strict-clippy,serial-tests')
) 'Quick mode must skip exactly check, Clippy and serial tests'

$called = [System.Collections.Generic.List[string]]::new()
$failureRunner = {
    param($step)
    $called.Add([string]$step.Name) | Out-Null
    $code = if ($step.Name -ceq 'locked-metadata') { 41 } else { 0 }
    return [pscustomobject]@{ exit_code = $code }
}.GetNewClosure()
$failureResult = Invoke-V1BetaLocalGatePlan `
    -Steps $plan `
    -Runner $failureRunner `
    -OnRecord { param($record) }
Assert-LocalGateTest (-not $failureResult.success) 'simulated command failure was not propagated'
Assert-LocalGateTest ($failureResult.failed_step -ceq 'locked-metadata') (
    'failure was attributed to the wrong step'
)
Assert-LocalGateTest (
    (($called -join ',') -ceq 'git-diff-check,rustfmt,locked-metadata')
) 'steps continued after the first command failure'
Assert-LocalGateTest ($failureResult.records.Count -eq 3) (
    'failure result did not stop recording at the failed command'
)

$noisyRunner = {
    param($step)
    "native stdout for $($step.Name)"
    return [pscustomobject]@{ exit_code = 0 }
}
$noisyResult = Invoke-V1BetaLocalGatePlan `
    -Steps @($plan[0]) `
    -Runner $noisyRunner `
    -OnRecord { param($record) }
Assert-LocalGateTest $noisyResult.success (
    'operator-visible native stdout contaminated the structured runner result'
)
Assert-LocalGateTest ($noisyResult.records[0].exit_code -eq 0) (
    'noisy runner did not preserve its final structured exit code'
)

$quickCalled = [System.Collections.Generic.List[string]]::new()
$successRunner = {
    param($step)
    $quickCalled.Add([string]$step.Name) | Out-Null
    return [pscustomobject]@{ exit_code = 0 }
}.GetNewClosure()
$quickResult = Invoke-V1BetaLocalGatePlan `
    -Steps $plan `
    -Runner $successRunner `
    -OnRecord { param($record) } `
    -Quick
Assert-LocalGateTest $quickResult.success 'simulated Quick plan unexpectedly failed'
Assert-LocalGateTest ($quickResult.records.Count -eq $expectedNames.Count) (
    'Quick plan did not record every passed or skipped step'
)
Assert-LocalGateTest (
    (@($quickResult.records | Where-Object status -eq 'skipped')).Count -eq 3
) 'Quick plan did not record exactly three skipped long steps'
foreach ($skippedName in $quickSkipNames) {
    Assert-LocalGateTest (-not $quickCalled.Contains($skippedName)) (
        "Quick runner executed skipped step '$skippedName'"
    )
}
foreach ($fixtureName in @(
    'build-script-cli',
    'build-script-daemon',
    'build-script-xfer',
    'build-script-remote'
)) {
    Assert-LocalGateTest $quickCalled.Contains($fixtureName) (
        "Quick mode incorrectly skipped standalone fixture '$fixtureName'"
    )
}
foreach ($corpusName in @(
    'protocol-corpus-transfer',
    'protocol-corpus-remote',
    'protocol-corpus-policy'
)) {
    Assert-LocalGateTest $quickCalled.Contains($corpusName) (
        "Quick mode incorrectly skipped deterministic corpus '$corpusName'"
    )
}

$selfTestRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'serctl-v1-beta-local-gate-selftest-' + [System.Guid]::NewGuid().ToString('N')
)
New-Item -ItemType Directory -Path $selfTestRoot -ErrorAction Stop | Out-Null
try {
    $insideRepository = Join-Path $repositoryRoot (
        'target/v1-beta-gate-evidence-' + [System.Guid]::NewGuid().ToString('N')
    )
    Invoke-ExpectedThrow -Description 'repository-contained evidence path' -Action {
        New-V1BetaEvidenceDirectory `
            -RepositoryRoot $repositoryRoot `
            -RequestedPath $insideRepository | Out-Null
    }
    Assert-LocalGateTest (-not (Test-Path -LiteralPath $insideRepository)) (
        'repository-contained evidence directory was created before rejection'
    )

    $existing = Join-Path $selfTestRoot 'already-exists'
    New-Item -ItemType Directory -Path $existing -ErrorAction Stop | Out-Null
    Invoke-ExpectedThrow -Description 'existing evidence directory' -Action {
        New-V1BetaEvidenceDirectory `
            -RepositoryRoot $repositoryRoot `
            -RequestedPath $existing | Out-Null
    }

    $newEvidence = Join-Path $selfTestRoot 'new-evidence'
    $createdEvidence = New-V1BetaEvidenceDirectory `
        -RepositoryRoot $repositoryRoot `
        -RequestedPath $newEvidence
    Assert-LocalGateTest (Test-Path -LiteralPath $createdEvidence -PathType Container) (
        'create-new evidence directory was not created outside the repository'
    )
    Assert-LocalGateTest (-not (Test-V1BetaPathWithin `
        -Path $createdEvidence `
        -Root $repositoryRoot)) 'evidence path boundary accepted a repository path'

    $entryScript = Get-Content -LiteralPath (
        Join-Path $PSScriptRoot 'Invoke-V1BetaLocalGate.ps1'
    ) -Raw -Encoding utf8
    Assert-LocalGateTest ($entryScript.Contains('[System.IO.FileMode]::CreateNew')) (
        'evidence file is not opened with create-new semantics'
    )
    $headA = ('a' * 40) -join ''
    $headB = ('b' * 40) -join ''
    $stableSource = Get-V1BetaFinalSourceState `
        -InitialHead $headA `
        -InitialDirty $false `
        -FinalHeadBeforeStatus $headA `
        -FinalHeadAfterStatus $headA `
        -FinalDirty $false
    Assert-LocalGateTest $stableSource.source_snapshot_stable (
        'unchanged clean source snapshot was rejected'
    )
    $changedHead = Get-V1BetaFinalSourceState `
        -InitialHead $headA `
        -InitialDirty $false `
        -FinalHeadBeforeStatus $headA `
        -FinalHeadAfterStatus $headB `
        -FinalDirty $false
    Assert-LocalGateTest (-not $changedHead.source_snapshot_stable) (
        'HEAD change during final status was not rejected'
    )
    $finalDirty = Get-V1BetaFinalSourceState `
        -InitialHead $headA `
        -InitialDirty $false `
        -FinalHeadBeforeStatus $headA `
        -FinalHeadAfterStatus $headA `
        -FinalDirty $true
    Assert-LocalGateTest (-not $finalDirty.source_snapshot_stable) (
        'final dirty worktree was not rejected'
    )
    $initialDirty = Get-V1BetaFinalSourceState `
        -InitialHead $headA `
        -InitialDirty $true `
        -FinalHeadBeforeStatus $headA `
        -FinalHeadAfterStatus $headA `
        -FinalDirty $false
    Assert-LocalGateTest (-not $initialDirty.source_snapshot_stable) (
        'initial dirty worktree was incorrectly made eligible by later cleanup'
    )

    Assert-LocalGateTest (
        (Get-V1BetaLocalGateExitCode `
            -Success $false `
            -Quick $false `
            -SourceSnapshotStable $true) -eq 1
    ) 'failed commands do not produce exit code 1'
    Assert-LocalGateTest (
        (Get-V1BetaLocalGateExitCode `
            -Success $true `
            -Quick $true `
            -SourceSnapshotStable $true) -eq 2
    ) 'Quick results do not produce non-acceptance exit code 2'
    Assert-LocalGateTest (
        (Get-V1BetaLocalGateExitCode `
            -Success $true `
            -Quick $false `
            -SourceSnapshotStable $false) -eq 2
    ) 'changed/dirty source snapshots do not produce non-acceptance exit code 2'
    Assert-LocalGateTest (
        (Get-V1BetaLocalGateExitCode `
            -Success $true `
            -Quick $false `
            -SourceSnapshotStable $true) -eq 0
    ) 'clean full success does not produce exit code 0'

    $headReadMarker = "Invoke-ContextCommand -File 'git' -Arguments @('rev-parse', 'HEAD')"
    Assert-LocalGateTest (
        ([regex]::Matches($entryScript, [regex]::Escape($headReadMarker))).Count -ge 2
    ) 'entry script does not perform a final HEAD read'
    Assert-LocalGateTest (
        ([regex]::Matches(
            $entryScript,
            [regex]::Escape('git status --porcelain=v1 --untracked-files=all')
        )).Count -eq 2
    ) 'entry script does not perform exactly one initial and one final porcelain status read'
    foreach ($marker in @(
        "event = 'source_rechecked'",
        'final_head = $sourceState.final_head',
        'final_worktree_dirty = $finalWorktreeDirty',
        'source_snapshot_stable = $sourceSnapshotStable'
    )) {
        Assert-LocalGateTest ($entryScript.Contains($marker)) (
            "entry script omits final-source evidence marker '$marker'"
        )
    }
}
finally {
    $temporaryBase = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
    $resolvedSelfTestRoot = [System.IO.Path]::GetFullPath($selfTestRoot)
    Assert-LocalGateTest (
        (Test-V1BetaPathWithin -Path $resolvedSelfTestRoot -Root $temporaryBase) -and
        [System.IO.Path]::GetFileName($resolvedSelfTestRoot).StartsWith(
            'serctl-v1-beta-local-gate-selftest-',
            [System.StringComparison]::Ordinal
        )
    ) 'refusing to clean an unverified self-test directory'
    [System.IO.Directory]::Delete($resolvedSelfTestRoot, $true)
}

Write-Host 'V1 beta local-gate self-tests passed.'
