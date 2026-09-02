[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$Tag,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{40}$')][string]$TagObject,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{40}$')][string]$Commit,
    [Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')]
    [string]$Repository,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9]+$')][string]$RunId,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9]+$')][string]$RunAttempt,
    [string]$RepositoryRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ParserFuzzReceiptContract.ps1')

if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $RepositoryRoot = Join-Path $PSScriptRoot '..'
}

$root = [System.IO.Path]::GetFullPath($RepositoryRoot)
$destination = [System.IO.Path]::GetFullPath($Path)
if (Test-Path -LiteralPath $destination) {
    throw "parser fuzz receipt already exists: '$destination'"
}
$digestPaths = [ordered]@{
    parser_fuzz_workflow = '.github/workflows/parser-fuzz.yml'
    fuzz_lock = 'fuzz/Cargo.lock'
    transfer_protocol_target = 'fuzz/fuzz_targets/transfer_protocol.rs'
    remote_protocol_target = 'fuzz/fuzz_targets/remote_protocol.rs'
    policy_json_target = 'fuzz/fuzz_targets/policy_json.rs'
}
$digests = [ordered]@{}
foreach ($entry in $digestPaths.GetEnumerator()) {
    $source = Join-Path $root $entry.Value
    $item = Get-Item -LiteralPath $source -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $item.Length -le 0) {
        throw "parser fuzz receipt source is not a nonempty regular file: '$source'"
    }
    $digests[$entry.Key] = (
        Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256
    ).Hash.ToLowerInvariant()
}

$receipt = [ordered]@{
    schema_version = 1
    tag = $Tag
    tag_object = $TagObject
    commit = $Commit
    repository = $Repository
    workflow_ref = "$Repository/.github/workflows/parser-fuzz.yml@refs/tags/$Tag"
    run_id = $RunId
    run_attempt = $RunAttempt
    toolchain = [ordered]@{
        nightly = 'nightly-2026-08-03'
        cargo_fuzz = '0.13.2'
    }
    matrix = @(
        [ordered]@{ target = 'transfer_protocol'; max_len = 1048644 },
        [ordered]@{ target = 'remote_protocol'; max_len = 131092 },
        [ordered]@{ target = 'policy_json'; max_len = 65537 }
    )
    corpus_commands = @(
        'cargo +nightly-2026-08-03 fuzz run transfer_protocol -- -max_total_time=180 -max_len=1048644 -rss_limit_mb=2048 -timeout=10',
        'cargo +nightly-2026-08-03 fuzz run remote_protocol -- -max_total_time=180 -max_len=131092 -rss_limit_mb=2048 -timeout=10',
        'cargo +nightly-2026-08-03 fuzz run policy_json -- -max_total_time=180 -max_len=65537 -rss_limit_mb=2048 -timeout=10'
    )
    source_digests = $digests
    test_counts = [ordered]@{ passed = 3; failed = 0; skipped = 0; unknown = 0 }
}
$json = ($receipt | ConvertTo-Json -Depth 8).Replace("`r`n", "`n") + "`n"
$bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($json)
$null = Read-ValidatedParserFuzzReceipt `
    -Bytes $bytes -Tag $Tag -TagObject $TagObject -Commit $Commit `
    -Repository $Repository -RunId $RunId -RunAttempt $RunAttempt
$parent = [System.IO.Path]::GetDirectoryName($destination)
[System.IO.Directory]::CreateDirectory($parent) | Out-Null
$stream = [System.IO.FileStream]::new(
    $destination,
    [System.IO.FileMode]::CreateNew,
    [System.IO.FileAccess]::Write,
    [System.IO.FileShare]::None,
    4096,
    [System.IO.FileOptions]::WriteThrough
)
try {
    $stream.Write($bytes, 0, $bytes.Length)
    $stream.Flush($true)
}
finally { $stream.Dispose() }

Write-Host "Created exact-tag parser fuzz success receipt: $destination"
