[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Directory,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Version,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{40}$')]
    [string]$Commit,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Tag,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{40}$')]
    [string]$TagObject,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$ParserFuzzReceiptPath,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[1-9][0-9]*$')]
    [string]$ParserFuzzArtifactId,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{64}$')]
    [string]$ParserFuzzArtifactDigest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'ReleaseAssetContract.ps1')
. (Join-Path $PSScriptRoot 'ParserFuzzReceiptContract.ps1')

function Assert-ManifestCondition {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if (-not $Condition) {
        throw "release manifest check failed: $Message"
    }
}

function Get-CheckedManifestFiles {
    param([Parameter(Mandatory = $true)][string]$Root)

    $rootItem = Get-Item -LiteralPath $Root -Force -ErrorAction Stop
    Assert-ManifestCondition $rootItem.PSIsContainer (
        "release path '$Root' is not a directory"
    )
    Assert-ManifestCondition (
        ($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0
    ) "release directory '$Root' is a symbolic link or reparse point"

    $entries = @(Get-ChildItem -LiteralPath $Root -Force)
    $reparseEntries = @(
        $entries | Where-Object {
            ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0
        }
    )
    Assert-ManifestCondition ($reparseEntries.Count -eq 0) (
        'release directory contains a symbolic-link or reparse-point input'
    )
    $nestedDirectories = @($entries | Where-Object { $_.PSIsContainer })
    Assert-ManifestCondition ($nestedDirectories.Count -eq 0) (
        'release inputs must be regular files in the top-level release directory'
    )
    return @($entries | Where-Object { -not $_.PSIsContainer } | Sort-Object Name)
}

function Write-NewUtf8Text {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Text
    )

    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($Text)
    $stream = [System.IO.FileStream]::new(
        $Path,
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
    finally {
        $stream.Dispose()
    }
}

function Get-ManifestSnapshot {
    param([Parameter(Mandatory = $true)][System.IO.FileInfo[]]$Files)

    $snapshot = @{}
    foreach ($file in $Files) {
        Assert-ManifestCondition (-not $snapshot.ContainsKey($file.Name)) (
            "release input name '$($file.Name)' is duplicated"
        )
        $snapshot[$file.Name] = [pscustomobject]@{
            Length = [long]$file.Length
            Sha256 = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
    return $snapshot
}

function Assert-SnapshotUnchanged {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Expected,
        [Parameter(Mandatory = $true)][System.IO.FileInfo[]]$Files,
        [Parameter(Mandatory = $true)][string]$Context
    )

    foreach ($file in $Files) {
        if (-not $Expected.ContainsKey($file.Name)) {
            continue
        }
        $currentHash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        Assert-ManifestCondition (
            [long]$file.Length -eq [long]$Expected[$file.Name].Length -and
            $currentHash -ceq [string]$Expected[$file.Name].Sha256
        ) "release input '$($file.Name)' changed $Context"
    }
}

$canonicalTag = "v$Version"
Assert-ManifestCondition ($Tag -ceq $canonicalTag) (
    "tag '$Tag' does not equal '$canonicalTag'"
)
Assert-ManifestCondition ([regex]::IsMatch(
    $Version,
    '^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)-(?:alpha|beta|rc)(?:\.(?:0|[1-9][0-9]*))?$',
    [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
)) "version '$Version' is not canonical"

$root = [System.IO.Path]::GetFullPath($Directory)
Assert-ManifestCondition (Test-Path -LiteralPath $root -PathType Container) (
    "release directory '$root' does not exist"
)
$checksumPath = Join-Path $root 'SHA256SUMS'
$provenancePath = Join-Path $root 'release-provenance.json'
Assert-ManifestCondition (-not (Test-Path -LiteralPath $checksumPath)) (
    "refusing to overwrite '$checksumPath'"
)
Assert-ManifestCondition (-not (Test-Path -LiteralPath $provenancePath)) (
    "refusing to overwrite '$provenancePath'"
)

[string[]]$requiredEnvironment = @(
    'GITHUB_REPOSITORY',
    'GITHUB_WORKFLOW',
    'GITHUB_WORKFLOW_REF',
    'GITHUB_RUN_ID',
    'GITHUB_RUN_ATTEMPT',
    'GITHUB_EVENT_NAME',
    'GITHUB_REF',
    'SOURCE_DATE_EPOCH',
    'RUNNER_OS',
    'RUNNER_ARCH',
    'ImageOS',
    'ImageVersion'
)
foreach ($name in $requiredEnvironment) {
    Assert-ManifestCondition (-not [string]::IsNullOrWhiteSpace(
        [System.Environment]::GetEnvironmentVariable($name, 'Process')
    )) "required release environment '$name' is missing"
}
Assert-ManifestCondition ($env:GITHUB_EVENT_NAME -ceq 'push') (
    "formal release evidence requires a push event, found '$env:GITHUB_EVENT_NAME'"
)
Assert-ManifestCondition ($env:GITHUB_REF -ceq "refs/tags/$Tag") (
    "workflow ref '$env:GITHUB_REF' does not equal release tag ref 'refs/tags/$Tag'"
)
Assert-ManifestCondition ($env:GITHUB_RUN_ID -match '^[0-9]+$') 'GITHUB_RUN_ID is invalid'
Assert-ManifestCondition ($env:GITHUB_RUN_ATTEMPT -match '^[0-9]+$') (
    'GITHUB_RUN_ATTEMPT is invalid'
)
Assert-ManifestCondition ($env:SOURCE_DATE_EPOCH -match '^[0-9]+$') (
    'SOURCE_DATE_EPOCH must be an unsigned Unix timestamp'
)

$filesBeforeProvenance = @(Get-CheckedManifestFiles -Root $root)
Assert-ManifestCondition ($filesBeforeProvenance.Count -gt 0) 'release directory contains no files'
$actualReleaseFiles = @(
    $filesBeforeProvenance | ForEach-Object { $_.Name } | Sort-Object
)
$expectedReleaseFiles = @(Get-V1BetaReleaseInputNames -Version $Version)
Assert-ManifestCondition (
    ($actualReleaseFiles -join "`n") -ceq ($expectedReleaseFiles -join "`n")
) (
    "release input set differs from the exact v1 beta contract; expected " +
    "'$($expectedReleaseFiles -join ', ')', found '$($actualReleaseFiles -join ', ')'"
)
foreach ($file in $filesBeforeProvenance) {
    Assert-ManifestCondition ($file.Length -gt 0) (
        "release input '$($file.Name)' is empty"
    )
}
$inputSnapshot = Get-ManifestSnapshot -Files $filesBeforeProvenance
$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$headCommit = (& git -C $repositoryRoot rev-parse HEAD | Out-String).Trim().ToLowerInvariant()
Assert-ManifestCondition ($LASTEXITCODE -eq 0) 'cannot resolve release checkout HEAD'
Assert-ManifestCondition ($headCommit -ceq $Commit.ToLowerInvariant()) (
    "release checkout HEAD '$headCommit' does not equal requested commit '$Commit'"
)
$commitEpoch = (& git -C $repositoryRoot show -s --format=%ct HEAD | Out-String).Trim()
Assert-ManifestCondition ($LASTEXITCODE -eq 0) 'cannot read release commit timestamp'
Assert-ManifestCondition ($commitEpoch -ceq $env:SOURCE_DATE_EPOCH) (
    "SOURCE_DATE_EPOCH '$env:SOURCE_DATE_EPOCH' does not equal commit timestamp '$commitEpoch'"
)

$fuzzReceiptItem = Get-Item -LiteralPath $ParserFuzzReceiptPath -Force -ErrorAction Stop
Assert-ManifestCondition (
    -not $fuzzReceiptItem.PSIsContainer -and
    ($fuzzReceiptItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0 -and
    $fuzzReceiptItem.Length -gt 0 -and $fuzzReceiptItem.Length -le 65536
) 'parser fuzz success receipt is not one bounded regular file'
$fuzzReceiptBytes = [System.IO.File]::ReadAllBytes($fuzzReceiptItem.FullName)
$null = Read-ValidatedParserFuzzReceipt `
    -Bytes $fuzzReceiptBytes `
    -Tag $Tag `
    -TagObject ($TagObject.ToLowerInvariant()) `
    -Commit ($Commit.ToLowerInvariant()) `
    -Repository $env:GITHUB_REPOSITORY `
    -RunId $env:GITHUB_RUN_ID `
    -RunAttempt $env:GITHUB_RUN_ATTEMPT
$sha256 = [System.Security.Cryptography.SHA256]::Create()
try { $fuzzReceiptHashBytes = $sha256.ComputeHash($fuzzReceiptBytes) }
finally { $sha256.Dispose() }
$fuzzReceiptSha256 = (
    [System.BitConverter]::ToString($fuzzReceiptHashBytes).Replace('-', '').ToLowerInvariant()
)

$provenance = [ordered]@{
    schema_version = 1
    version = $Version
    tag = $Tag
    tag_object = $TagObject.ToLowerInvariant()
    commit = $Commit.ToLowerInvariant()
    repository = $env:GITHUB_REPOSITORY
    workflow = $env:GITHUB_WORKFLOW
    workflow_ref = $env:GITHUB_WORKFLOW_REF
    run_id = $env:GITHUB_RUN_ID
    run_attempt = $env:GITHUB_RUN_ATTEMPT
    event = $env:GITHUB_EVENT_NAME
    ref = $env:GITHUB_REF
    source_date_epoch = $env:SOURCE_DATE_EPOCH
    runner_os = $env:RUNNER_OS
    runner_arch = $env:RUNNER_ARCH
    runner_image = "$env:ImageOS-$env:ImageVersion"
    rustc = (& rustc --version --verbose | Out-String).Trim()
    cargo = (& cargo --version --verbose | Out-String).Trim()
    cargo_lock_sha256 = (
        Get-FileHash -LiteralPath (Join-Path $repositoryRoot 'Cargo.lock') -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    rust_toolchain_sha256 = (
        Get-FileHash -LiteralPath (
            Join-Path $repositoryRoot 'rust-toolchain.toml'
        ) -Algorithm SHA256
    ).Hash.ToLowerInvariant()
    release_files = @(
        $filesBeforeProvenance | ForEach-Object { $_.Name }
    )
    parser_fuzz = [ordered]@{
        artifact_id = $ParserFuzzArtifactId
        artifact_digest = $ParserFuzzArtifactDigest
        receipt_sha256 = $fuzzReceiptSha256
        receipt_base64 = [Convert]::ToBase64String($fuzzReceiptBytes)
    }
}
Write-NewUtf8Text `
    -Path $provenancePath `
    -Text (($provenance | ConvertTo-Json -Depth 8) + "`n")

$filesToHash = @(Get-CheckedManifestFiles -Root $root)
$expectedHashFiles = @(Get-V1BetaHashedReleaseNames -Version $Version)
$actualHashFiles = @($filesToHash | ForEach-Object { $_.Name } | Sort-Object)
Assert-ManifestCondition (
    ($actualHashFiles -join "`n") -ceq ($expectedHashFiles -join "`n")
) (
    "release directory changed while provenance was generated; expected " +
    "'$($expectedHashFiles -join ', ')', found '$($actualHashFiles -join ', ')'"
)
Assert-SnapshotUnchanged `
    -Expected $inputSnapshot `
    -Files $filesToHash `
    -Context 'while provenance was generated'
$lines = foreach ($file in $filesToHash) {
    $relative = $file.Name
    Assert-ManifestCondition (-not $relative.Contains("`n") -and -not $relative.Contains("`r")) (
        "release filename contains a line break: '$relative'"
    )
    $hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
    "$hash  $relative"
}
Write-NewUtf8Text -Path $checksumPath -Text (($lines -join "`n") + "`n")

$finalFiles = @(Get-CheckedManifestFiles -Root $root)
$expectedFinalFiles = @(Get-V1BetaFinalReleaseNames -Version $Version)
$actualFinalFiles = @($finalFiles | ForEach-Object { $_.Name } | Sort-Object)
Assert-ManifestCondition (
    ($actualFinalFiles -join "`n") -ceq ($expectedFinalFiles -join "`n")
) (
    "release directory changed while SHA256SUMS was written; expected " +
    "'$($expectedFinalFiles -join ', ')', found '$($actualFinalFiles -join ', ')'"
)
$hashedSnapshot = @{}
foreach ($index in 0..($filesToHash.Count - 1)) {
    $file = $filesToHash[$index]
    $hashedSnapshot[$file.Name] = [pscustomobject]@{
        Length = [long]$file.Length
        Sha256 = ([string]$lines[$index]).Substring(0, 64)
    }
}
Assert-SnapshotUnchanged `
    -Expected $hashedSnapshot `
    -Files $finalFiles `
    -Context 'while SHA256SUMS was written'

Write-Host "Created SHA-256 manifest for $($filesToHash.Count) release files."
