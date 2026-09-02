[CmdletBinding()]
param(
    [string]$RepositoryRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $RepositoryRoot = Join-Path $PSScriptRoot '..'
}

function Assert-ParserFuzzCondition {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )

    if (-not $Condition) {
        throw "parser fuzz boundary verification failed: $Message"
    }
}

function Read-BoundedUtf8File {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][long]$MaximumBytes
    )

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    Assert-ParserFuzzCondition (-not $item.PSIsContainer) "'$Path' is not a file"
    Assert-ParserFuzzCondition (
        ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0
    ) "'$Path' is a reparse point"
    Assert-ParserFuzzCondition (
        $item.Length -gt 0 -and $item.Length -le $MaximumBytes
    ) "'$Path' is empty or exceeds its $MaximumBytes-byte limit"

    $utf8 = [System.Text.UTF8Encoding]::new($false, $true)
    $reader = [System.IO.StreamReader]::new($item.FullName, $utf8, $true)
    try {
        return $reader.ReadToEnd()
    }
    finally {
        $reader.Dispose()
    }
}

function Assert-ContainsOnce {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Needle,
        [Parameter(Mandatory = $true)][string]$Description
    )

    Assert-ParserFuzzCondition (
        ([regex]::Matches($Source, [regex]::Escape($Needle))).Count -eq 1
    ) "$Description must contain exactly one '$Needle'"
}

$root = [System.IO.Path]::GetFullPath($RepositoryRoot)
$workflowPath = Join-Path $root '.github/workflows/parser-fuzz.yml'
$fuzzRoot = Join-Path $root 'fuzz'
$fuzzManifestPath = Join-Path $fuzzRoot 'Cargo.toml'
$fuzzLockPath = Join-Path $fuzzRoot 'Cargo.lock'
$rootManifestPath = Join-Path $root 'Cargo.toml'
$rootLockPath = Join-Path $root 'Cargo.lock'
$targetRoot = Join-Path $fuzzRoot 'fuzz_targets'

$workflow = Read-BoundedUtf8File $workflowPath (128 * 1024)
$fuzzManifest = Read-BoundedUtf8File $fuzzManifestPath (64 * 1024)
$fuzzLock = Read-BoundedUtf8File $fuzzLockPath (2 * 1024 * 1024)
$rootManifest = Read-BoundedUtf8File $rootManifestPath (1024 * 1024)
$rootLock = Read-BoundedUtf8File $rootLockPath (16 * 1024 * 1024)

Assert-ParserFuzzCondition (
    $workflow -match '(?m)^permissions:\r?$\n  contents: read\r?$'
) 'workflow permissions must be read-only'
Assert-ParserFuzzCondition (
    $workflow -match '(?m)^concurrency:\r?\n' +
        '  group: parser-fuzz-\$\{\{ github\.workflow \}\}-\$\{\{ github\.ref \}\}\r?\n' +
        '  cancel-in-progress: true\s*$'
) 'workflow concurrency is not isolated from the caller release group'
foreach ($forbiddenTrigger in @('push', 'pull_request')) {
    Assert-ParserFuzzCondition (
        -not [regex]::IsMatch(
            $workflow,
            '(?m)^  ' + [regex]::Escape($forbiddenTrigger) + ':\s*$'
        )
    ) (
        "workflow must not use the automatic trigger '$($forbiddenTrigger):'"
    )
}
foreach ($requiredTrigger in @('workflow_call', 'workflow_dispatch', 'schedule')) {
    Assert-ParserFuzzCondition (
        ([regex]::Matches(
            $workflow,
            '(?m)^  ' + [regex]::Escape($requiredTrigger) + ':\s*$'
        )).Count -eq 1
    ) "workflow must declare exact trigger '$requiredTrigger' once"
}
foreach ($requiredWorkflowMarker in @(
    'workflow_call:',
    'workflow_dispatch:',
    'schedule:',
    'runs-on: ubuntu-latest',
    'timeout-minutes: 15',
    'fail-fast: false',
    'persist-credentials: false',
    'rustup toolchain install nightly-2026-08-03 --profile minimal',
    "cargo install cargo-fuzz --version '=0.13.2' --locked",
    'cargo +nightly-2026-08-03 metadata',
    '--manifest-path fuzz/Cargo.toml',
    '--locked',
    'cargo +nightly-2026-08-03 fuzz run ${{ matrix.target }} --',
    '-max_total_time=180',
    '-max_len=${{ matrix.max_len }}',
    '-rss_limit_mb=2048',
    '-timeout=10',
    'ARTIFACT_DIR: fuzz/artifacts/${{ matrix.target }}',
    'MAX_ARTIFACT_BYTES: ${{ matrix.max_len }}',
    '[[ $count -le 4 ]]',
    '[[ $(stat -c %s -- "$artifact") -le $MAX_ARTIFACT_BYTES ]]',
    "if: failure() && steps.bound_failure_artifacts.outcome == 'success'",
    'if-no-files-found: ignore',
    'retention-days: 30'
    'Retain exact-tag fuzz success receipt'
    './scripts/New-ParserFuzzReceipt.ps1'
    './scripts/Test-ParserFuzzReceipt.ps1'
    'name: parser-fuzz-success-${{ inputs.commit }}-${{ github.run_id }}-${{ github.run_attempt }}'
    'if-no-files-found: error'
    'retention-days: 90'
    'artifact_id: ${{ steps.upload.outputs.artifact-id }}'
    'artifact_digest: ${{ steps.upload.outputs.artifact-digest }}'
    'receipt_sha256: ${{ steps.hash.outputs.receipt_sha256 }}'
)) {
    Assert-ParserFuzzCondition ($workflow.Contains($requiredWorkflowMarker)) (
        "workflow lacks '$requiredWorkflowMarker'"
    )
}
$normalizedWorkflow = [regex]::Replace($workflow, '\s+', ' ').Trim()
$isolatedLockStep = (
    'Verify the isolated fuzz dependency lock run: >- ' +
    'cargo +nightly-2026-08-03 metadata ' +
    '--manifest-path fuzz/Cargo.toml --locked --format-version 1 > /dev/null'
)
Assert-ParserFuzzCondition (
    ([regex]::Matches(
        $normalizedWorkflow,
        [regex]::Escape($isolatedLockStep)
    )).Count -eq 1
) 'isolated fuzz lock is not resolved by one exact locked metadata step'
Assert-ParserFuzzCondition (
    -not [regex]::IsMatch($workflow, '(?m)(?:\+|install\s+)nightly(?:\s|$)')
) 'workflow contains a floating nightly toolchain'

$expectedActions = [ordered]@{
    'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1' = 2
    'actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a' = 2
}
$actualActions = @{}
foreach ($match in [regex]::Matches($workflow, '(?m)^\s*uses:\s*(?<value>[^#\r\n]+)')) {
    $value = $match.Groups['value'].Value.Trim()
    Assert-ParserFuzzCondition ($value -match '^[^@\s]+@[0-9a-f]{40}$') (
        "action is not pinned to a full commit: '$value'"
    )
    Assert-ParserFuzzCondition ($expectedActions.Contains($value)) (
        "workflow uses an unapproved action: '$value'"
    )
    if (-not $actualActions.ContainsKey($value)) {
        $actualActions[$value] = 0
    }
    $actualActions[$value] += 1
}
foreach ($action in $expectedActions.Keys) {
    $count = if ($actualActions.ContainsKey($action)) { $actualActions[$action] } else { 0 }
    Assert-ParserFuzzCondition ($count -eq $expectedActions[$action]) (
        "action '$action' count is $count, expected $($expectedActions[$action])"
    )
}

$expectedRows = @(
    @('transfer_protocol', '1048644'),
    @('remote_protocol', '131092'),
    @('policy_json', '65537')
)
foreach ($row in $expectedRows) {
    $pattern = (
        '(?m)^\s*- target:\s*' + [regex]::Escape($row[0]) + '\s*\r?\n' +
        '(?:\s*#[^\r\n]*\r?\n)?' +
        '\s*max_len:\s*' + [regex]::Escape($row[1]) + '\s*$'
    )
    Assert-ParserFuzzCondition (([regex]::Matches($workflow, $pattern)).Count -eq 1) (
        "workflow lacks exact target/maximum row '$($row -join '/')'"
    )
}
Assert-ParserFuzzCondition (
    ([regex]::Matches($workflow, '(?m)^\s*- target:\s*')).Count -eq 3
) 'workflow must contain exactly three fuzz matrix rows'

Assert-ParserFuzzCondition (
    $fuzzManifest -match '(?ms)^\[workspace\]\s*\r?\nmembers\s*=\s*\["\."\]\s*$'
) 'fuzz manifest is not an isolated nested workspace'
foreach ($manifestMarker in @(
    'name = "serctl-parser-fuzz"',
    'publish = false',
    'cargo-fuzz = true',
    'futures-executor = "=0.3.32"',
    'libfuzzer-sys = "=0.4.13"',
    'sha2 = "=0.10.9"',
    'serctl-policy = { path = "../crates/serctl_policy" }',
    'serctl-remote-protocol = { path = "../crates/serctl_remote_protocol" }',
    'serctl-transfer-protocol = { path = "../crates/serctl_transfer_protocol" }'
)) {
    Assert-ContainsOnce $fuzzManifest $manifestMarker 'fuzz manifest'
}
foreach ($row in $expectedRows) {
    Assert-ContainsOnce $fuzzManifest "name = `"$($row[0])`"" 'fuzz manifest'
    Assert-ContainsOnce $fuzzManifest "path = `"fuzz_targets/$($row[0]).rs`"" 'fuzz manifest'
}
Assert-ParserFuzzCondition (
    ([regex]::Matches($fuzzManifest, '(?m)^\[\[bin\]\]\s*$')).Count -eq 3
) 'fuzz manifest must declare exactly three binaries'

$fuzzPackage = [regex]::Match(
    $fuzzLock,
    '(?ms)^\[\[package\]\]\s*\r?\nname = "serctl-parser-fuzz"\s*\r?\n(?<body>.*?)(?=^\[\[package\]\]|\z)'
)
Assert-ParserFuzzCondition $fuzzPackage.Success 'fuzz lock lacks the harness package'
foreach ($dependency in @(
    '"futures-executor"',
    '"libfuzzer-sys"',
    '"serctl-policy"',
    '"serctl-remote-protocol"',
    '"serctl-transfer-protocol"',
    '"sha2"'
)) {
    Assert-ContainsOnce $fuzzPackage.Groups['body'].Value $dependency 'fuzz lock harness package'
}
Assert-ParserFuzzCondition (-not $rootManifest.Contains('"fuzz"')) (
    'release workspace must not include the nested fuzz workspace'
)
foreach ($fuzzOnlyPackage in @('serctl-parser-fuzz', 'libfuzzer-sys')) {
    Assert-ParserFuzzCondition (
        -not [regex]::IsMatch(
            $rootLock,
            '(?m)^name\s*=\s*"' + [regex]::Escape($fuzzOnlyPackage) + '"\s*$'
        )
    ) "release lock unexpectedly contains fuzz-only package '$fuzzOnlyPackage'"
}

$expectedTargetFiles = @($expectedRows | ForEach-Object { "$($_[0]).rs" })
$actualTargetFiles = @(Get-ChildItem -LiteralPath $targetRoot -File -Force)
Assert-ParserFuzzCondition ($actualTargetFiles.Count -eq 3) (
    'fuzz_targets must contain exactly three regular files'
)
foreach ($item in $actualTargetFiles) {
    Assert-ParserFuzzCondition ($expectedTargetFiles -ccontains $item.Name) (
        "unexpected fuzz target '$($item.Name)'"
    )
}

$transfer = Read-BoundedUtf8File (Join-Path $targetRoot 'transfer_protocol.rs') (256 * 1024)
$remote = Read-BoundedUtf8File (Join-Path $targetRoot 'remote_protocol.rs') (256 * 1024)
$policy = Read-BoundedUtf8File (Join-Path $targetRoot 'policy_json.rs') (256 * 1024)
foreach ($source in @($transfer, $remote, $policy)) {
    Assert-ParserFuzzCondition ($source.Contains('#![no_main]')) 'target lacks no_main'
    Assert-ParserFuzzCondition ($source.Contains('#![forbid(unsafe_code)]')) (
        'target does not forbid unsafe code'
    )
    Assert-ParserFuzzCondition ($source.Contains('fuzz_target!')) 'target lacks libFuzzer entry'
}
foreach ($marker in @(
    'use serctl_transfer_protocol::{',
    'read_frame, FrameKind, MAGIC, MAX_CHUNK_BYTES, MAX_CONTROL_BYTES, VERSION',
    'block_on(read_frame(&mut input))',
    'FrameKind::Control as u8',
    'FrameKind::Data as u8',
    'Sha256::digest(payload)',
    'payload.len() <= MAX_CHUNK_BYTES'
)) {
    Assert-ParserFuzzCondition ($transfer.Contains($marker)) (
        "transfer target does not drive production boundary '$marker'"
    )
}
foreach ($marker in @(
    'use serctl_remote_protocol::{',
    'decode_exact(bytes)',
    'read_frame_from(&mut Cursor::new(bytes))',
    'payload.len() <= MAX_FRAME_PAYLOAD',
    'FrameKind::QueryReceipt'
)) {
    Assert-ParserFuzzCondition ($remote.Contains($marker)) (
        "remote target does not drive production boundary '$marker'"
    )
}
foreach ($marker in @(
    'use serctl_policy::compile_policy_json;',
    'compile_policy_json(data)',
    '.take(128)',
    "char::from(b'a' + (byte % 26))",
    '"base":"red"',
    '"kind":"program"',
    'compile_policy_json(structured.as_bytes())'
)) {
    Assert-ParserFuzzCondition ($policy.Contains($marker)) (
        "policy target does not drive production boundary '$marker'"
    )
}

Write-Host 'Parser fuzz boundary verification passed.'
