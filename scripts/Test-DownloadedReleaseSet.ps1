[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Directory,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)-(?:alpha|beta|rc)(?:\.(?:0|[1-9][0-9]*))?$')]
    [string]$Version,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$Commit,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Tag,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$TagObject,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')]
    [string]$Repository
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'ReleaseAssetContract.ps1')
. (Join-Path $PSScriptRoot 'ReleaseArchiveContract.ps1')
. (Join-Path $PSScriptRoot 'StrictJson.ps1')
. (Join-Path $PSScriptRoot 'ParserFuzzReceiptContract.ps1')
$vaultStorageContract = 'vault-storage read=v4..=v5 write=v5'

function Assert-DownloadedReleaseCondition {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )

    if (-not $Condition) {
        throw "downloaded release verification failed: $Message"
    }
}

function Get-CheckedReleaseEntries {
    param([Parameter(Mandatory = $true)][string]$Root)

    $rootItem = Get-Item -LiteralPath $Root -Force -ErrorAction Stop
    Assert-DownloadedReleaseCondition $rootItem.PSIsContainer (
        "release path '$Root' is not a directory"
    )
    Assert-DownloadedReleaseCondition (
        ($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0
    ) "release directory '$Root' is a reparse point"

    $entries = @(Get-ChildItem -LiteralPath $Root -Force)
    Assert-DownloadedReleaseCondition ($entries.Count -eq 14) (
        "release directory must contain exactly 14 entries, found $($entries.Count)"
    )
    $totalBytes = [long]0
    foreach ($entry in $entries) {
        Assert-DownloadedReleaseCondition (-not $entry.PSIsContainer) (
            "release entry '$($entry.Name)' is not a top-level regular file"
        )
        Assert-DownloadedReleaseCondition (
            ($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0
        ) "release entry '$($entry.Name)' is a reparse point"
        Assert-DownloadedReleaseCondition ($entry.Length -gt 0) (
            "release entry '$($entry.Name)' is empty"
        )
        $maximumBytes = if ($entry.Name -ceq 'SHA256SUMS') {
            4096
        }
        elseif ($entry.Name -cmatch '\.provenance\.json$') {
            262144
        }
        elseif ($entry.Name -cmatch '\.sbom\.cdx\.(?:json|xml)$') {
            67108864
        }
        else { 536870912 }
        Assert-DownloadedReleaseCondition ($entry.Length -le $maximumBytes) (
            "release entry '$($entry.Name)' exceeds its file-size bound"
        )
        $totalBytes += $entry.Length
        Assert-DownloadedReleaseCondition ($totalBytes -le 1073741824) (
            'release set exceeds the one-GiB total size bound'
        )
        Assert-DownloadedReleaseCondition (
            $entry.Name -ceq [System.IO.Path]::GetFileName($entry.Name) -and
            -not $entry.Name.Contains('/') -and
            -not $entry.Name.Contains('\') -and
            -not $entry.Name.Contains("`r") -and
            -not $entry.Name.Contains("`n")
        ) "release entry name '$($entry.Name)' is not a plain filename"
    }
    return @($entries | Sort-Object Name)
}

function Get-ReleaseSnapshot {
    param([Parameter(Mandatory = $true)][System.IO.FileInfo[]]$Files)

    $snapshot = @{}
    foreach ($file in $Files) {
        Assert-DownloadedReleaseCondition (-not $snapshot.ContainsKey($file.Name)) (
            "release filename '$($file.Name)' is duplicated"
        )
        $snapshot[$file.Name] = [pscustomobject]@{
            Length = [long]$file.Length
            Hash = (Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
    return $snapshot
}

function Assert-ClosedStringMap {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string[]]$ExpectedKeys,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][ValidateSet('hash', 'version')]
        [string]$ValueKind
    )

    Assert-DownloadedReleaseCondition (Test-StrictJsonObject $Value) (
        "$Label is not a JSON object"
    )
    $actualKeys = @($Value.PSObject.Properties.Name | Sort-Object)
    $expected = @($ExpectedKeys | Sort-Object)
    Assert-DownloadedReleaseCondition (
        ($actualKeys -join "`n") -ceq ($expected -join "`n")
    ) "$Label does not use the exact platform asset schema"
    $shortCommit = $Commit.Substring(0, 12)
    foreach ($key in $ExpectedKeys) {
        Assert-DownloadedReleaseCondition (Test-StrictJsonString $Value.$key) (
            "$Label value for '$key' is not a JSON string"
        )
        $text = [string]$Value.$key
        if ($ValueKind -ceq 'hash') {
            Assert-DownloadedReleaseCondition ($text -cmatch '^[0-9a-f]{64}$') (
                "$Label value for '$key' is not lowercase SHA-256"
            )
            continue
        }
        Assert-DownloadedReleaseCondition (
            -not [string]::IsNullOrWhiteSpace($text) -and
            $text.Length -le 512 -and
            -not $text.Contains("`r") -and
            -not $text.Contains("`n")
        ) "$Label value for '$key' is not one bounded version line"
        $versionPattern = [regex]::Escape($Version)
        $commitPattern = [regex]::Escape($shortCommit)
        $identityPattern = switch ($key) {
            'serctl_cli.exe' {
                '^serctl_cli ' + $versionPattern + ' \(git ' + $commitPattern + '; ' +
                    [regex]::Escape($vaultStorageContract) + '\)$'
            }
            'serctl_daemon.exe' {
                '^serctl_daemon ' + $versionPattern + ' \(git ' + $commitPattern +
                    '; IPC v9\.\.=v9; ' + [regex]::Escape($vaultStorageContract) + '\)$'
            }
            'serctl-xfer' {
                '^serctl-xfer ' + $versionPattern + ' \(git ' + $commitPattern +
                    '; transfer protocol v1\)$'
            }
            default { $null }
        }
        Assert-DownloadedReleaseCondition ($null -ne $identityPattern) (
            "$Label has no exact version grammar for '$key'"
        )
        Assert-DownloadedReleaseCondition ($text -cmatch $identityPattern) (
            "$Label value for '$key' is not the exact release identity"
        )
    }
}

function Get-ClosedBinaryComponents {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string[]]$ExpectedNames,
        [Parameter(Mandatory = $true)][string]$Label
    )

    Assert-DownloadedReleaseCondition (Test-StrictJsonArray $Value) (
        "$Label is not a JSON array"
    )
    $entries = @($Value)
    Assert-DownloadedReleaseCondition ($entries.Count -eq $ExpectedNames.Count) (
        "$Label does not contain the exact number of platform binaries"
    )
    $components = @{}
    $caseFolded = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    $shortCommit = $Commit.Substring(0, 12)
    foreach ($entry in $entries) {
        Assert-DownloadedReleaseCondition (Test-StrictJsonObject $entry) (
            "$Label contains a non-object component"
        )
        $expectedFields = @('binary_size', 'name', 'sha256', 'version') | Sort-Object
        $actualFields = @($entry.PSObject.Properties.Name | Sort-Object)
        Assert-DownloadedReleaseCondition (
            ($actualFields -join "`n") -ceq ($expectedFields -join "`n")
        ) "$Label component does not use the exact closed schema"
        Assert-DownloadedReleaseCondition (Test-StrictJsonString $entry.name) (
            "$Label component name is not a JSON string"
        )
        $name = [string]$entry.name
        Assert-DownloadedReleaseCondition (
            $ExpectedNames -ccontains $name -and
            $name -ceq [System.IO.Path]::GetFileName($name) -and
            -not $name.Contains('/') -and -not $name.Contains('\') -and
            $caseFolded.Add($name) -and -not $components.ContainsKey($name)
        ) "$Label component name '$name' is unknown, duplicated, or noncanonical"
        Assert-DownloadedReleaseCondition (
            (Test-StrictJsonInteger $entry.binary_size) -and
            [long]$entry.binary_size -gt 0 -and
            [long]$entry.binary_size -le 536870912
        ) "$Label binary_size for '$name' is not a positive bounded JSON integer"
        Assert-DownloadedReleaseCondition (
            (Test-StrictJsonString $entry.sha256) -and
            [string]$entry.sha256 -cmatch '^[0-9a-f]{64}$'
        ) "$Label SHA-256 for '$name' is not canonical"
        Assert-DownloadedReleaseCondition (
            (Test-StrictJsonString $entry.version) -and
            -not [string]::IsNullOrWhiteSpace([string]$entry.version) -and
            ([string]$entry.version).Length -le 512 -and
            -not ([string]$entry.version).Contains("`r") -and
            -not ([string]$entry.version).Contains("`n")
        ) "$Label version for '$name' is not one bounded string"
        $versionPattern = [regex]::Escape($Version)
        $commitPattern = [regex]::Escape($shortCommit)
        $identityPattern = switch ($name) {
            'serctl_cli.exe' {
                '^serctl_cli ' + $versionPattern + ' \(git ' + $commitPattern + '; ' +
                    [regex]::Escape($vaultStorageContract) + '\)$'
            }
            'serctl_daemon.exe' {
                '^serctl_daemon ' + $versionPattern + ' \(git ' + $commitPattern +
                    '; IPC v9\.\.=v9; ' + [regex]::Escape($vaultStorageContract) + '\)$'
            }
            'serctl-xfer' {
                '^serctl-xfer ' + $versionPattern + ' \(git ' + $commitPattern +
                    '; transfer protocol v1\)$'
            }
            default { $null }
        }
        Assert-DownloadedReleaseCondition (
            $null -ne $identityPattern -and [string]$entry.version -cmatch $identityPattern
        ) "$Label version for '$name' is not the exact release identity"
        $components[$name] = $entry
    }
    Assert-DownloadedReleaseCondition (
        (($components.Keys | Sort-Object) -join "`n") -ceq (($ExpectedNames | Sort-Object) -join "`n")
    ) "$Label names differ from the exact platform binary allowlist"
    return $components
}

function Assert-ProvenanceIdentity {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string[]]$ExpectedInputs
    )

    $provenanceItem = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    Assert-DownloadedReleaseCondition (
        -not $provenanceItem.PSIsContainer -and
        ($provenanceItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0 -and
        $provenanceItem.Length -gt 0 -and
        $provenanceItem.Length -le 262144
    ) 'release provenance is not one bounded regular file'
    try {
        $json = Read-StrictUtf8Text -Path $Path
        $provenance = ConvertFrom-StrictJson -Json $json -Label 'release provenance'
    }
    catch {
        throw "release provenance is not valid JSON: $($_.Exception.Message)"
    }
    Assert-DownloadedReleaseCondition ($null -ne $provenance) (
        'release provenance is null'
    )
    Assert-DownloadedReleaseCondition (Test-StrictJsonObject $provenance) (
        'release provenance is not a JSON object'
    )
    $expectedFields = @(
        'cargo',
        'cargo_lock_sha256',
        'commit',
        'event',
        'parser_fuzz',
        'ref',
        'release_files',
        'repository',
        'run_attempt',
        'run_id',
        'runner_arch',
        'runner_image',
        'runner_os',
        'rust_toolchain_sha256',
        'rustc',
        'schema_version',
        'source_date_epoch',
        'tag',
        'tag_object',
        'version',
        'workflow',
        'workflow_ref'
    ) | Sort-Object
    $actualFields = @($provenance.PSObject.Properties.Name | Sort-Object)
    Assert-DownloadedReleaseCondition (
        ($actualFields -join "`n") -ceq ($expectedFields -join "`n")
    ) 'release provenance does not use the exact closed schema'

    Assert-DownloadedReleaseCondition (
        (Test-StrictJsonInteger $provenance.schema_version) -and
        $provenance.schema_version -eq 1
    ) (
        'release provenance schema_version is not 1'
    )
    foreach ($field in @(
        'version', 'tag', 'tag_object', 'commit', 'repository', 'event', 'ref',
        'workflow_ref', 'workflow', 'runner_os', 'runner_arch', 'runner_image',
        'rustc', 'cargo', 'run_id', 'run_attempt', 'source_date_epoch',
        'cargo_lock_sha256', 'rust_toolchain_sha256'
    )) {
        Assert-DownloadedReleaseCondition (Test-StrictJsonString $provenance.$field) (
            "release provenance field '$field' is not a JSON string"
        )
    }
    Assert-DownloadedReleaseCondition (Test-StrictJsonArray $provenance.release_files) (
        'release provenance release_files is not a JSON array'
    )
    Assert-DownloadedReleaseCondition ([string]$provenance.version -ceq $Version) (
        'release provenance version does not match the requested release'
    )
    Assert-DownloadedReleaseCondition ([string]$provenance.tag -ceq $Tag) (
        'release provenance tag does not match the requested release'
    )
    Assert-DownloadedReleaseCondition ([string]$provenance.tag_object -ceq $TagObject) (
        'release provenance tag object does not match the requested release'
    )
    Assert-DownloadedReleaseCondition ([string]$provenance.commit -ceq $Commit) (
        'release provenance commit does not match the requested release'
    )
    Assert-DownloadedReleaseCondition ([string]$provenance.repository -ceq $Repository) (
        'release provenance repository does not match the publishing repository'
    )
    Assert-DownloadedReleaseCondition ([string]$provenance.event -ceq 'push') (
        'release provenance event is not push'
    )
    Assert-DownloadedReleaseCondition ([string]$provenance.ref -ceq "refs/tags/$Tag") (
        'release provenance ref does not match the release tag'
    )
    Assert-DownloadedReleaseCondition (
        [string]$provenance.workflow_ref -ceq (
            "$Repository/.github/workflows/release-v1-beta.yml@refs/tags/$Tag"
        )
    ) 'release provenance workflow_ref is not bound to the tagged release workflow'
    foreach ($field in @(
        'workflow', 'runner_os', 'runner_arch', 'runner_image', 'rustc', 'cargo'
    )) {
        Assert-DownloadedReleaseCondition (
            -not [string]::IsNullOrWhiteSpace([string]$provenance.$field)
        ) "release provenance field '$field' is empty"
    }
    foreach ($field in @('run_id', 'run_attempt', 'source_date_epoch')) {
        Assert-DownloadedReleaseCondition ([string]$provenance.$field -match '^[0-9]+$') (
            "release provenance field '$field' is not an unsigned integer"
        )
    }
    foreach ($field in @('cargo_lock_sha256', 'rust_toolchain_sha256')) {
        Assert-DownloadedReleaseCondition ([string]$provenance.$field -match '^[0-9a-f]{64}$') (
            "release provenance field '$field' is not lowercase SHA-256"
        )
    }

    Assert-DownloadedReleaseCondition (Test-StrictJsonObject $provenance.parser_fuzz) (
        'release provenance parser_fuzz is not an object'
    )
    $fuzzFields = @('artifact_digest', 'artifact_id', 'receipt_base64', 'receipt_sha256')
    Assert-DownloadedReleaseCondition (
        (($provenance.parser_fuzz.PSObject.Properties.Name | Sort-Object) -join "`n") -ceq
            (($fuzzFields | Sort-Object) -join "`n")
    ) 'release provenance parser_fuzz does not use the exact closed schema'
    foreach ($field in $fuzzFields) {
        Assert-DownloadedReleaseCondition (Test-StrictJsonString $provenance.parser_fuzz.$field) (
            "release provenance parser_fuzz.$field is not a JSON string"
        )
    }
    Assert-DownloadedReleaseCondition (
        [string]$provenance.parser_fuzz.artifact_id -cmatch '^[1-9][0-9]*$' -and
        [string]$provenance.parser_fuzz.artifact_digest -cmatch '^[0-9a-f]{64}$' -and
        [string]$provenance.parser_fuzz.receipt_sha256 -cmatch '^[0-9a-f]{64}$'
    ) 'release provenance parser fuzz artifact identity is noncanonical'
    $receiptBase64 = [string]$provenance.parser_fuzz.receipt_base64
    Assert-DownloadedReleaseCondition (
        $receiptBase64.Length -gt 0 -and $receiptBase64.Length -le 87384 -and
        $receiptBase64 -cmatch '^[A-Za-z0-9+/]+={0,2}$'
    ) 'release provenance parser fuzz receipt Base64 is noncanonical or oversized'
    try { $receiptBytes = [Convert]::FromBase64String($receiptBase64) }
    catch { throw 'downloaded release verification failed: parser fuzz receipt Base64 is invalid' }
    Assert-DownloadedReleaseCondition (
        [Convert]::ToBase64String($receiptBytes) -ceq $receiptBase64
    ) 'release provenance parser fuzz receipt Base64 is not canonical'
    $receiptSha = [System.Security.Cryptography.SHA256]::Create()
    try { $receiptHashBytes = $receiptSha.ComputeHash($receiptBytes) }
    finally { $receiptSha.Dispose() }
    $receiptHash = (
        [System.BitConverter]::ToString($receiptHashBytes).Replace('-', '').ToLowerInvariant()
    )
    Assert-DownloadedReleaseCondition (
        $receiptHash -ceq [string]$provenance.parser_fuzz.receipt_sha256
    ) 'release provenance embedded parser fuzz receipt SHA-256 mismatch'
    $null = Read-ValidatedParserFuzzReceipt `
        -Bytes $receiptBytes `
        -Tag $Tag `
        -TagObject $TagObject `
        -Commit $Commit `
        -Repository $Repository `
        -RunId ([string]$provenance.run_id) `
        -RunAttempt ([string]$provenance.run_attempt)

    $releaseFiles = @($provenance.release_files)
    $seenReleaseFiles = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal
    )
    foreach ($name in $releaseFiles) {
        Assert-DownloadedReleaseCondition (Test-StrictJsonString $name) (
            'release provenance release_files contains a non-string value'
        )
        Assert-DownloadedReleaseCondition (
            $seenReleaseFiles.Add([string]$name)
        ) "release provenance contains duplicate release file '$name'"
        Assert-DownloadedReleaseCondition (
            [string]$name -ceq [System.IO.Path]::GetFileName([string]$name) -and
            -not ([string]$name).Contains('/') -and
            -not ([string]$name).Contains('\')
        ) "release provenance contains a path instead of a filename: '$name'"
    }
    Assert-DownloadedReleaseCondition (
        (($releaseFiles | Sort-Object) -join "`n") -ceq ($ExpectedInputs -join "`n")
    ) 'release provenance release_files differs from the exact 12-input allowlist'
}

function Assert-PlatformProvenance {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][ValidateSet('linux-x86_64', 'windows-x86_64')]
        [string]$Platform
    )

    $provenanceItem = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    Assert-DownloadedReleaseCondition (
        -not $provenanceItem.PSIsContainer -and
        ($provenanceItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0 -and
        $provenanceItem.Length -gt 0 -and
        $provenanceItem.Length -le 262144
    ) "platform provenance '$Platform' is not one bounded regular file"
    try {
        $json = Read-StrictUtf8Text -Path $Path
        $provenance = ConvertFrom-StrictJson -Json $json -Label "platform provenance '$Platform'"
    }
    catch {
        throw "platform provenance is not valid JSON: $($_.Exception.Message)"
    }
    Assert-DownloadedReleaseCondition (Test-StrictJsonObject $provenance) (
        "platform provenance '$Platform' is not a JSON object"
    )
    $expectedFields = @(
        'binary_components',
        'cargo',
        'cargo_lock_sha256',
        'cargo_target_dir',
        'commit',
        'platform',
        'ref',
        'release_debug',
        'release_strip',
        'repository',
        'run_attempt',
        'run_id',
        'runner_arch',
        'runner_image',
        'runner_os',
        'runtime_abi',
        'rust_toolchain_sha256',
        'rustc',
        'schema_version',
        'source_date_epoch',
        'symbol_sha256',
        'tag',
        'tag_object',
        'version',
        'workflow',
        'workflow_ref'
    ) | Sort-Object
    $actualFields = @($provenance.PSObject.Properties.Name | Sort-Object)
    Assert-DownloadedReleaseCondition (
        ($actualFields -join "`n") -ceq ($expectedFields -join "`n")
    ) "platform provenance '$Platform' does not use the exact closed schema"
    Assert-DownloadedReleaseCondition (
        (Test-StrictJsonInteger $provenance.schema_version) -and
        $provenance.schema_version -eq 2
    ) (
        "platform provenance '$Platform' schema_version is not 2"
    )
    foreach ($field in @(
        'version', 'tag', 'tag_object', 'commit', 'platform', 'repository', 'ref',
        'workflow_ref', 'workflow', 'runner_os', 'runner_arch', 'runner_image',
        'rustc', 'cargo', 'run_id', 'run_attempt', 'source_date_epoch',
        'cargo_lock_sha256', 'rust_toolchain_sha256', 'release_debug',
        'release_strip', 'cargo_target_dir'
    )) {
        Assert-DownloadedReleaseCondition (Test-StrictJsonString $provenance.$field) (
            "platform provenance '$Platform' field '$field' is not a JSON string"
        )
    }
    Assert-DownloadedReleaseCondition ([string]$provenance.version -ceq $Version) (
        "platform provenance '$Platform' version mismatch"
    )
    Assert-DownloadedReleaseCondition ([string]$provenance.tag -ceq $Tag) (
        "platform provenance '$Platform' tag mismatch"
    )
    Assert-DownloadedReleaseCondition ([string]$provenance.tag_object -ceq $TagObject) (
        "platform provenance '$Platform' tag object mismatch"
    )
    Assert-DownloadedReleaseCondition ([string]$provenance.commit -ceq $Commit) (
        "platform provenance '$Platform' commit mismatch"
    )
    Assert-DownloadedReleaseCondition ([string]$provenance.platform -ceq $Platform) (
        "platform provenance '$Platform' platform mismatch"
    )
    Assert-DownloadedReleaseCondition ([string]$provenance.repository -ceq $Repository) (
        "platform provenance '$Platform' repository mismatch"
    )
    Assert-DownloadedReleaseCondition ([string]$provenance.ref -ceq "refs/tags/$Tag") (
        "platform provenance '$Platform' ref mismatch"
    )
    Assert-DownloadedReleaseCondition (
        [string]$provenance.workflow_ref -ceq (
            "$Repository/.github/workflows/release-v1-beta.yml@refs/tags/$Tag"
        )
    ) "platform provenance '$Platform' workflow_ref mismatch"

    if ($Platform -ceq 'windows-x86_64') {
        $binaryKeys = @('serctl_cli.exe', 'serctl_daemon.exe')
        $symbolKeys = @('serctl_cli.pdb', 'serctl_daemon.pdb')
    }
    else {
        $binaryKeys = @('serctl-xfer')
        $symbolKeys = @('serctl-xfer.debug')
    }
    $binaryComponents = Get-ClosedBinaryComponents `
        -Value $provenance.binary_components `
        -ExpectedNames $binaryKeys `
        -Label "platform provenance '$Platform' binary_components"
    Assert-ClosedStringMap `
        -Value $provenance.symbol_sha256 `
        -ExpectedKeys $symbolKeys `
        -Label "platform provenance '$Platform' symbol_sha256" `
        -ValueKind hash

    $runtimeAbi = $provenance.runtime_abi
    Assert-DownloadedReleaseCondition (Test-StrictJsonObject $runtimeAbi) (
        "platform provenance '$Platform' runtime ABI is not a JSON object"
    )
    if ($Platform -ceq 'windows-x86_64') {
        $expectedAbiFields = @('architecture', 'family')
        $actualAbiFields = @($runtimeAbi.PSObject.Properties.Name | Sort-Object)
        Assert-DownloadedReleaseCondition (
            ($actualAbiFields -join "`n") -ceq ($expectedAbiFields -join "`n")
        ) 'Windows runtime ABI evidence does not use the exact closed schema'
        foreach ($field in $expectedAbiFields) {
            Assert-DownloadedReleaseCondition (Test-StrictJsonString $runtimeAbi.$field) (
                "Windows runtime ABI field '$field' is not a JSON string"
            )
        }
        Assert-DownloadedReleaseCondition ([string]$runtimeAbi.family -ceq 'windows-msvc') (
            'Windows runtime ABI family is not windows-msvc'
        )
        Assert-DownloadedReleaseCondition ([string]$runtimeAbi.architecture -ceq 'x86_64') (
            'Windows runtime ABI architecture is not x86_64'
        )
    }
    else {
        $expectedAbiFields = @(
            'family', 'maximum_required', 'maximum_supported', 'verifier'
        ) | Sort-Object
        $actualAbiFields = @($runtimeAbi.PSObject.Properties.Name | Sort-Object)
        Assert-DownloadedReleaseCondition (
            ($actualAbiFields -join "`n") -ceq ($expectedAbiFields -join "`n")
        ) 'Linux runtime ABI evidence does not use the exact closed schema'
        foreach ($field in $expectedAbiFields) {
            Assert-DownloadedReleaseCondition (Test-StrictJsonString $runtimeAbi.$field) (
                "Linux runtime ABI field '$field' is not a JSON string"
            )
        }
        Assert-DownloadedReleaseCondition ([string]$runtimeAbi.family -ceq 'glibc') (
            'Linux runtime ABI family is not glibc'
        )
        Assert-DownloadedReleaseCondition (
            [string]$runtimeAbi.maximum_supported -ceq '2.35'
        ) 'Linux maximum supported GLIBC is not 2.35'
        $requiredText = [string]$runtimeAbi.maximum_required
        Assert-DownloadedReleaseCondition (
            $requiredText -match '^(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){1,3}$'
        ) 'Linux maximum required GLIBC is not a canonical version'
        $requiredVersion = $null
        Assert-DownloadedReleaseCondition (
            [Version]::TryParse($requiredText, [ref]$requiredVersion)
        ) 'Linux maximum required GLIBC is not a valid version'
        Assert-DownloadedReleaseCondition (
            $requiredVersion -le [Version]::Parse('2.35')
        ) 'Linux maximum required GLIBC exceeds 2.35'
        Assert-DownloadedReleaseCondition (
            [string]$runtimeAbi.verifier -ceq 'readelf --version-info --wide'
        ) 'Linux runtime ABI verifier identity is unexpected'
    }
    $provenance | Add-Member -NotePropertyName checked_binary_components -NotePropertyValue $binaryComponents
    return $provenance
}

$canonicalTag = "v$Version"
Assert-DownloadedReleaseCondition ($Tag -ceq $canonicalTag) (
    "tag '$Tag' does not equal '$canonicalTag'"
)
$root = [System.IO.Path]::GetFullPath($Directory)
Assert-DownloadedReleaseCondition (Test-Path -LiteralPath $root -PathType Container) (
    "release directory '$root' does not exist"
)

$expectedInputs = @(Get-V1BetaReleaseInputNames -Version $Version)
$expectedHashed = @(Get-V1BetaHashedReleaseNames -Version $Version)
$expectedFinal = @(Get-V1BetaFinalReleaseNames -Version $Version)
$files = @(Get-CheckedReleaseEntries -Root $root)
$actualNames = @($files | ForEach-Object { $_.Name } | Sort-Object)
Assert-DownloadedReleaseCondition (
    ($actualNames -join "`n") -ceq ($expectedFinal -join "`n")
) (
    "release set differs from the exact 14-file allowlist; expected " +
    "'$($expectedFinal -join ', ')', found '$($actualNames -join ', ')'"
)
$initialSnapshot = Get-ReleaseSnapshot -Files $files

$checksumPath = Join-Path $root 'SHA256SUMS'
$checksumItem = Get-Item -LiteralPath $checksumPath -Force -ErrorAction Stop
Assert-DownloadedReleaseCondition ($checksumItem.Length -le 4096) (
    'SHA256SUMS exceeds its pre-read size bound'
)
try { $checksumText = Read-StrictUtf8Text -Path $checksumPath }
catch { throw 'downloaded release verification failed: SHA256SUMS is not strict UTF-8' }
Assert-DownloadedReleaseCondition (
    $checksumText.EndsWith("`n", [StringComparison]::Ordinal) -and
    -not $checksumText.Contains("`r")
) 'SHA256SUMS is not canonical LF-terminated text'
$checksumLines = @($checksumText.Substring(0, $checksumText.Length - 1).Split([char]10))
Assert-DownloadedReleaseCondition ($checksumLines.Count -eq 13) (
    "SHA256SUMS must contain exactly 13 lines, found $($checksumLines.Count)"
)
$manifestEntries = @{}
foreach ($line in $checksumLines) {
    Assert-DownloadedReleaseCondition (
        $line -cmatch '^(?<hash>[0-9a-f]{64})  (?<name>[^\r\n]+)$'
    ) "SHA256SUMS contains a noncanonical line"
    $hash = $Matches['hash']
    $name = $Matches['name']
    Assert-DownloadedReleaseCondition (
        $name -ceq [System.IO.Path]::GetFileName($name) -and
        -not $name.Contains('/') -and
        -not $name.Contains('\') -and
        $name -cne '.' -and
        $name -cne '..'
    ) "SHA256SUMS contains a path instead of a filename: '$name'"
    Assert-DownloadedReleaseCondition ($name -cne 'SHA256SUMS') (
        'SHA256SUMS must not hash itself'
    )
    Assert-DownloadedReleaseCondition (-not $manifestEntries.ContainsKey($name)) (
        "SHA256SUMS contains duplicate entry '$name'"
    )
    $manifestEntries[$name] = $hash
}
$manifestNames = @($manifestEntries.Keys | Sort-Object)
Assert-DownloadedReleaseCondition (
    ($manifestNames -join "`n") -ceq ($expectedHashed -join "`n")
) 'SHA256SUMS entries differ from the exact 13-file hashed allowlist'
foreach ($name in $expectedHashed) {
    Assert-DownloadedReleaseCondition (
        [string]$manifestEntries[$name] -ceq [string]$initialSnapshot[$name].Hash
    ) "SHA256 mismatch for release file '$name'"
}

Assert-ProvenanceIdentity `
    -Path (Join-Path $root 'release-provenance.json') `
    -ExpectedInputs $expectedInputs
$linuxProvenance = Assert-PlatformProvenance `
    -Path (Join-Path $root "serctl-$Version-linux-x86_64.provenance.json") `
    -Platform 'linux-x86_64'
$windowsProvenance = Assert-PlatformProvenance `
    -Path (Join-Path $root "serctl-$Version-windows-x86_64.provenance.json") `
    -Platform 'windows-x86_64'

$governanceMembers = @(
    'LICENSE',
    'SECURITY.md',
    'v1-beta-agent-jsonl.md',
    'v1-beta-release-contract.md',
    'v1-beta-acceptance-matrix.md'
)
$windowsProvenanceName = "serctl-$Version-windows-x86_64.provenance.json"
$linuxProvenanceName = "serctl-$Version-linux-x86_64.provenance.json"
$windowsRuntime = Get-VerifiedReleaseArchiveMembers `
    -Path (Join-Path $root "serctl-$Version-windows-x86_64.zip") `
    -Format zip `
    -ExpectedNames (@('serctl_cli.exe', 'serctl_daemon.exe', $windowsProvenanceName) + $governanceMembers)
$windowsSymbols = Get-VerifiedReleaseArchiveMembers `
    -Path (Join-Path $root "serctl-$Version-windows-x86_64-symbols.zip") `
    -Format zip `
    -ExpectedNames @('serctl_cli.pdb', 'serctl_daemon.pdb')
$linuxRuntime = Get-VerifiedReleaseArchiveMembers `
    -Path (Join-Path $root "serctl-$Version-linux-x86_64-xfer.tar.gz") `
    -Format tar.gz `
    -ExpectedNames (@('serctl-xfer', $linuxProvenanceName) + $governanceMembers)
$linuxSymbols = Get-VerifiedReleaseArchiveMembers `
    -Path (Join-Path $root "serctl-$Version-linux-x86_64-xfer-symbols.tar.gz") `
    -Format tar.gz `
    -ExpectedNames @('serctl-xfer.debug')
foreach ($binding in @(
    @{ Snapshot = $windowsRuntime; Components = $windowsProvenance.checked_binary_components; Map = $null },
    @{ Snapshot = $windowsSymbols; Components = $null; Map = $windowsProvenance.symbol_sha256 },
    @{ Snapshot = $linuxRuntime; Components = $linuxProvenance.checked_binary_components; Map = $null },
    @{ Snapshot = $linuxSymbols; Components = $null; Map = $linuxProvenance.symbol_sha256 }
)) {
    if ($null -ne $binding.Components) {
        foreach ($name in $binding.Components.Keys) {
            $component = $binding.Components[$name]
            Assert-DownloadedReleaseCondition (
                $binding.Snapshot.ContainsKey($name) -and
                [long]$binding.Snapshot[$name].Length -eq [long]$component.binary_size -and
                [string]$binding.Snapshot[$name].Hash -ceq [string]$component.sha256
            ) "archive member size/digest does not match platform provenance"
        }
    }
    else {
        foreach ($property in $binding.Map.PSObject.Properties) {
            Assert-DownloadedReleaseCondition (
                $binding.Snapshot.ContainsKey($property.Name) -and
                [string]$binding.Snapshot[$property.Name].Hash -ceq [string]$property.Value
            ) "archive member digest does not match platform provenance"
        }
    }
}
foreach ($binding in @(
    @{ Snapshot = $windowsRuntime; Name = $windowsProvenanceName },
    @{ Snapshot = $linuxRuntime; Name = $linuxProvenanceName }
)) {
    Assert-DownloadedReleaseCondition (
        [string]$binding.Snapshot[$binding.Name].Hash -ceq [string]$initialSnapshot[$binding.Name].Hash
    ) 'runtime archive embeds a platform provenance file different from the released provenance'
}

$finalFiles = @(Get-CheckedReleaseEntries -Root $root)
$finalNames = @($finalFiles | ForEach-Object { $_.Name } | Sort-Object)
Assert-DownloadedReleaseCondition (
    ($finalNames -join "`n") -ceq ($expectedFinal -join "`n")
) 'release set changed during verification'
$finalSnapshot = Get-ReleaseSnapshot -Files $finalFiles
foreach ($name in $expectedFinal) {
    Assert-DownloadedReleaseCondition (
        [long]$finalSnapshot[$name].Length -eq [long]$initialSnapshot[$name].Length -and
        [string]$finalSnapshot[$name].Hash -ceq [string]$initialSnapshot[$name].Hash
    ) "release file '$name' changed during verification"
}

Write-Host (
    "Verified downloaded release set: 14 files, 13 SHA-256 entries, " +
    "version=$Version commit=$Commit tag=$Tag tag_object=$TagObject"
)
