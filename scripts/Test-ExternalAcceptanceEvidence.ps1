[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$AcceptanceRecordPath,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9A-F]{64}$')]
    [string]$AcceptanceRecordSha256,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$AcceptanceRecordUrl,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$EvidenceManifestPath,
    [string]$EvidenceArtifactDirectory,
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$ReleaseManifestPath,
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^v1\.0\.0-beta(?:\.(?:0|[1-9][0-9]*))?$')]
    [string]$Tag,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{40}$')][string]$Commit,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{40}$')][string]$TagObject,
    [switch]$EmitArtifactDownloadPlan
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'StrictJson.ps1')
. (Join-Path $PSScriptRoot 'ReleaseAssetContract.ps1')
. (Join-Path $PSScriptRoot 'ReleaseArchiveContract.ps1')

function Assert-EvidenceCondition {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if (-not $Condition) {
        throw "external acceptance evidence failed: $Message"
    }
}

function Get-ClosedJsonObject {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string[]]$Fields,
        [Parameter(Mandatory = $true)][int]$MaximumBytes,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][ValidatePattern('^[0-9A-F]{64}$')]
        [string]$ExpectedSha256
    )

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    Assert-EvidenceCondition (-not $item.PSIsContainer) "$Label is not a regular file"
    Assert-EvidenceCondition (
        ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0
    ) "$Label is a reparse point"
    Assert-EvidenceCondition ($item.Length -gt 0 -and $item.Length -le $MaximumBytes) (
        "$Label size is outside 1..$MaximumBytes bytes"
    )
    # Parse the exact byte array whose digest is checked. Hashing the path and
    # reopening it later would allow a local replacement race between identity
    # verification and JSON interpretation.
    $bytes = [System.IO.File]::ReadAllBytes($item.FullName)
    Assert-EvidenceCondition (
        $bytes.Length -gt 0 -and $bytes.Length -le $MaximumBytes
    ) "$Label byte count is outside 1..$MaximumBytes bytes"
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        $actualSha256 = (
            [System.BitConverter]::ToString($sha256.ComputeHash($bytes))
        ).Replace('-', '')
    }
    finally {
        $sha256.Dispose()
    }
    Assert-EvidenceCondition ($actualSha256 -ceq $ExpectedSha256) (
        "$Label SHA-256 mismatch"
    )
    try {
        $encoding = [System.Text.UTF8Encoding]::new($false, $true)
        $json = $encoding.GetString($bytes)
        $value = ConvertFrom-StrictJson -Json $json -Label $Label
    }
    catch {
        throw "external acceptance evidence failed: $Label is not valid JSON"
    }
    Assert-EvidenceCondition ($null -ne $value) "$Label is null"
    Assert-EvidenceCondition (Test-StrictJsonObject $value) "$Label is not a JSON object"
    $actualFields = @($value.PSObject.Properties.Name | Sort-Object)
    $expectedFields = @($Fields | Sort-Object)
    Assert-EvidenceCondition (
        ($actualFields -join "`n") -ceq ($expectedFields -join "`n")
    ) "$Label does not use the exact closed schema"
    return $value
}

function Get-Sha256HexFromBytes {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString($sha256.ComputeHash($Bytes))).Replace('-', '')
    }
    finally {
        $sha256.Dispose()
    }
}

function Get-ReleaseComponentHashes {
    param([Parameter(Mandatory = $true)][string]$ManifestPath)

    $manifestItem = Get-Item -LiteralPath $ManifestPath -Force -ErrorAction Stop
    Assert-EvidenceCondition (
        -not $manifestItem.PSIsContainer -and
        ($manifestItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0 -and
        $manifestItem.Length -gt 0 -and $manifestItem.Length -le 4096 -and
        $manifestItem.Name -ceq 'SHA256SUMS'
    ) 'release SHA256SUMS is not one bounded regular file with its canonical name'
    $root = $manifestItem.Directory.FullName
    $manifestBytes = [System.IO.File]::ReadAllBytes($manifestItem.FullName)
    Assert-EvidenceCondition (
        $manifestBytes.Length -gt 0 -and $manifestBytes.Length -le 4096
    ) 'release SHA256SUMS byte count is outside 1..4096 bytes'
    $manifestHash = Get-Sha256HexFromBytes -Bytes $manifestBytes
    try {
        $encoding = [System.Text.UTF8Encoding]::new($false, $true)
        $manifestText = $encoding.GetString($manifestBytes)
    }
    catch {
        throw 'external acceptance evidence failed: release SHA256SUMS is not strict UTF-8'
    }
    Assert-EvidenceCondition (
        $manifestText.EndsWith("`n", [StringComparison]::Ordinal) -and
        -not $manifestText.Contains("`r")
    ) 'release SHA256SUMS is not canonical LF-terminated text'
    $lines = @($manifestText.Substring(0, $manifestText.Length - 1).Split([char]10))
    $expectedNames = @(Get-V1BetaHashedReleaseNames -Version $Tag.Substring(1))
    Assert-EvidenceCondition ($lines.Count -eq $expectedNames.Count) (
        "release SHA256SUMS must contain exactly $($expectedNames.Count) entries"
    )
    $entries = [System.Collections.Generic.Dictionary[string,string]]::new(
        [System.StringComparer]::Ordinal
    )
    $caseFolded = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    foreach ($line in $lines) {
        Assert-EvidenceCondition (
            $line -cmatch '^(?<hash>[0-9a-f]{64})  (?<name>[^\r\n]+)$'
        ) 'release SHA256SUMS contains a noncanonical entry'
        $name = [string]$Matches['name']
        Assert-EvidenceCondition (
            $name -ceq [System.IO.Path]::GetFileName($name) -and
            -not $name.Contains('/') -and -not $name.Contains('\') -and
            $name -cne '.' -and $name -cne '..' -and $name -cne 'SHA256SUMS'
        ) "release SHA256SUMS contains a non-filename entry '$name'"
        Assert-EvidenceCondition ($caseFolded.Add($name) -and -not $entries.ContainsKey($name)) (
            "release SHA256SUMS contains a duplicate or case-colliding entry '$name'"
        )
        $entries.Add($name, [string]$Matches['hash'])
    }
    Assert-EvidenceCondition (
        (($entries.Keys | Sort-Object) -join "`n") -ceq (($expectedNames | Sort-Object) -join "`n")
    ) 'release SHA256SUMS entries differ from the exact hashed release allowlist'

    foreach ($name in $expectedNames) {
        $path = Join-Path $root $name
        $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        Assert-EvidenceCondition (
            -not $item.PSIsContainer -and
            ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0 -and
            $item.Length -gt 0
        ) "release file '$name' is not a nonempty regular file"
        Assert-EvidenceCondition (
            (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash.ToLowerInvariant() -ceq
                $entries[$name]
        ) "release file '$name' does not match SHA256SUMS"
    }

    $provenanceFields = @(
        'binary_components', 'cargo', 'cargo_lock_sha256',
        'cargo_target_dir', 'commit', 'platform', 'ref', 'release_debug',
        'release_strip', 'repository', 'run_attempt', 'run_id', 'runner_arch',
        'runner_image', 'runner_os', 'runtime_abi', 'rust_toolchain_sha256',
        'rustc', 'schema_version', 'source_date_epoch', 'symbol_sha256', 'tag',
        'tag_object', 'version', 'workflow', 'workflow_ref'
    )
    $componentIdentities = [ordered]@{}
    $releaseRepository = $null
    foreach ($platform in @('windows-x86_64', 'linux-x86_64')) {
        $provenanceName = "serctl-$($Tag.Substring(1))-$platform.provenance.json"
        $provenance = Get-ClosedJsonObject `
            -Path (Join-Path $root $provenanceName) `
            -Fields $provenanceFields `
            -MaximumBytes 262144 `
            -Label "release platform provenance '$platform'" `
            -ExpectedSha256 $entries[$provenanceName].ToUpperInvariant()
        Assert-EvidenceCondition (
            (Test-StrictJsonInteger $provenance.schema_version) -and
            $provenance.schema_version -eq 2 -and
            (Test-StrictJsonString $provenance.version) -and
            [string]$provenance.version -ceq $Tag.Substring(1) -and
            (Test-StrictJsonString $provenance.tag) -and [string]$provenance.tag -ceq $Tag -and
            (Test-StrictJsonString $provenance.tag_object) -and
            [string]$provenance.tag_object -ceq $TagObject -and
            (Test-StrictJsonString $provenance.commit) -and
            [string]$provenance.commit -ceq $Commit -and
            (Test-StrictJsonString $provenance.platform) -and
            [string]$provenance.platform -ceq $platform -and
            (Test-StrictJsonString $provenance.repository) -and
            [string]$provenance.repository -cmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$' -and
            (Test-StrictJsonString $provenance.ref) -and
            [string]$provenance.ref -ceq "refs/tags/$Tag" -and
            (Test-StrictJsonString $provenance.workflow_ref) -and
            [string]$provenance.workflow_ref -ceq (
                "$([string]$provenance.repository)/.github/workflows/release-v1-beta.yml@refs/tags/$Tag"
            )
        ) "release platform provenance '$platform' identity mismatch"
        if ($null -eq $releaseRepository) {
            $releaseRepository = [string]$provenance.repository
        }
        else {
            Assert-EvidenceCondition (
                [string]$provenance.repository -ceq $releaseRepository
            ) 'release platform provenance repository binding differs by platform'
        }
        $expectedBinaryNames = @(
            if ($platform -ceq 'windows-x86_64') {
                'serctl_cli.exe', 'serctl_daemon.exe'
            }
            else {
                'serctl-xfer'
            }
        )
        Assert-EvidenceCondition (Test-StrictJsonArray $provenance.binary_components) (
            "release platform provenance '$platform' binary_components is not an array"
        )
        $components = @($provenance.binary_components)
        Assert-EvidenceCondition ($components.Count -eq $expectedBinaryNames.Count) (
            "release platform provenance '$platform' binary component count is not exact"
        )
        $seenBinaryNames = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::OrdinalIgnoreCase
        )
        foreach ($component in $components) {
            Assert-EvidenceCondition (Test-StrictJsonObject $component) (
                "release platform provenance '$platform' binary component is not an object"
            )
            Assert-EvidenceCondition (
                (($component.PSObject.Properties.Name | Sort-Object) -join "`n") -ceq
                    ((@('binary_size', 'name', 'sha256', 'version') | Sort-Object) -join "`n")
            ) "release platform provenance '$platform' binary component schema is not closed"
            foreach ($field in @('name', 'sha256', 'version')) {
                Assert-EvidenceCondition (Test-StrictJsonString $component.$field) (
                    "release platform provenance '$platform' component.$field is not a string"
                )
            }
            $binaryName = [string]$component.name
            Assert-EvidenceCondition (
                $expectedBinaryNames -ccontains $binaryName -and
                $seenBinaryNames.Add($binaryName)
            ) "release platform provenance '$platform' binary name is unknown or duplicated"
            Assert-EvidenceCondition (
                (Test-StrictJsonInteger $component.binary_size) -and
                [long]$component.binary_size -gt 0 -and
                [long]$component.binary_size -le 536870912
            ) "release platform provenance size for '$binaryName' is not a positive bounded integer"
            Assert-EvidenceCondition (
                [string]$component.sha256 -cmatch '^[0-9a-f]{64}$'
            ) "release platform provenance hash for '$binaryName' is not canonical"
            Assert-EvidenceCondition (
                -not [string]::IsNullOrWhiteSpace([string]$component.version) -and
                ([string]$component.version).Length -le 512 -and
                -not ([string]$component.version).Contains("`r") -and
                -not ([string]$component.version).Contains("`n")
            ) "release platform provenance version for '$binaryName' is invalid"
            $versionPattern = [regex]::Escape($Tag.Substring(1))
            $commitPattern = [regex]::Escape($Commit.Substring(0, 12))
            $identityPattern = switch ($binaryName) {
                'serctl_cli.exe' {
                    '^serctl_cli ' + $versionPattern + ' \(git ' + $commitPattern +
                        '; vault-storage read=v4\.\.=v5 write=v5\)$'
                }
                'serctl_daemon.exe' {
                    '^serctl_daemon ' + $versionPattern + ' \(git ' + $commitPattern +
                        '; IPC v9\.\.=v9; vault-storage read=v4\.\.=v5 write=v5\)$'
                }
                'serctl-xfer' {
                    '^serctl-xfer ' + $versionPattern + ' \(git ' + $commitPattern +
                        '; transfer protocol v1\)$'
                }
                default { $null }
            }
            Assert-EvidenceCondition (
                $null -ne $identityPattern -and
                [string]$component.version -cmatch $identityPattern
            ) "release platform provenance version for '$binaryName' is not exact"
            $componentIdentities[$binaryName] = [pscustomobject][ordered]@{
                name = $binaryName
                binary_size = [long]$component.binary_size
                sha256 = ([string]$component.sha256).ToUpperInvariant()
                version = [string]$component.version
            }
        }
    }
    $governanceMembers = @(
        'LICENSE', 'SECURITY.md', 'v1-beta-agent-jsonl.md',
        'v1-beta-release-contract.md', 'v1-beta-acceptance-matrix.md'
    )
    $windowsProvenanceName = "serctl-$($Tag.Substring(1))-windows-x86_64.provenance.json"
    $linuxProvenanceName = "serctl-$($Tag.Substring(1))-linux-x86_64.provenance.json"
    $windowsRuntime = Get-VerifiedReleaseArchiveMembers `
        -Path (Join-Path $root "serctl-$($Tag.Substring(1))-windows-x86_64.zip") `
        -Format zip `
        -ExpectedNames (@('serctl_cli.exe', 'serctl_daemon.exe', $windowsProvenanceName) + $governanceMembers)
    $linuxRuntime = Get-VerifiedReleaseArchiveMembers `
        -Path (Join-Path $root "serctl-$($Tag.Substring(1))-linux-x86_64-xfer.tar.gz") `
        -Format tar.gz `
        -ExpectedNames (@('serctl-xfer', $linuxProvenanceName) + $governanceMembers)
    foreach ($binding in @(
        [pscustomobject]@{
            Snapshot = $windowsRuntime
            Names = @('serctl_cli.exe', 'serctl_daemon.exe')
        },
        [pscustomobject]@{
            Snapshot = $linuxRuntime
            Names = @('serctl-xfer')
        }
    )) {
        foreach ($name in $binding.Names) {
            $expected = $componentIdentities[$name]
            Assert-EvidenceCondition (
                $binding.Snapshot.ContainsKey($name) -and
                [long]$binding.Snapshot[$name].Length -eq [long]$expected.binary_size -and
                [string]$binding.Snapshot[$name].Hash -ceq
                    ([string]$expected.sha256).ToLowerInvariant()
            ) "release archive component '$name' bytes do not match platform provenance"
        }
    }
    foreach ($binding in @(
        [pscustomobject]@{ Snapshot = $windowsRuntime; Name = $windowsProvenanceName },
        [pscustomobject]@{ Snapshot = $linuxRuntime; Name = $linuxProvenanceName }
    )) {
        Assert-EvidenceCondition (
            [string]$binding.Snapshot[$binding.Name].Hash -ceq
                [string]$entries[$binding.Name]
        ) 'runtime archive embeds different platform provenance bytes'
    }
    return [pscustomobject]@{
        manifest_sha256 = $manifestHash
        repository = $releaseRepository
        components = $componentIdentities
    }
}

function Get-CheckedHttpsUri {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $uri = $null
    Assert-EvidenceCondition ([Uri]::TryCreate($Value, [UriKind]::Absolute, [ref]$uri)) (
        "$Label is not an absolute URL"
    )
    Assert-EvidenceCondition ($uri.Scheme -ceq 'https') "$Label is not HTTPS"
    Assert-EvidenceCondition (-not [string]::IsNullOrWhiteSpace($uri.DnsSafeHost)) (
        "$Label has no host"
    )
    Assert-EvidenceCondition ([string]::IsNullOrEmpty($uri.UserInfo)) (
        "$Label contains user information"
    )
    Assert-EvidenceCondition ([string]::IsNullOrEmpty($uri.Fragment)) (
        "$Label contains a fragment"
    )
    return $uri
}

function Get-CanonicalTimestamp {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $timestamp = [DateTimeOffset]::MinValue
    Assert-EvidenceCondition ([DateTimeOffset]::TryParseExact(
        $Value,
        'o',
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::RoundtripKind,
        [ref]$timestamp
    )) "$Label is not canonical round-trip time"
    return $timestamp
}

function Assert-ClosedEvidenceObject {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string[]]$Fields,
        [Parameter(Mandatory = $true)][string]$Label
    )
    Assert-EvidenceCondition (Test-StrictJsonObject $Value) "$Label is not a JSON object"
    $actual = @($Value.PSObject.Properties.Name | Sort-Object)
    $expected = @($Fields | Sort-Object)
    Assert-EvidenceCondition (($actual -join "`n") -ceq ($expected -join "`n")) (
        "$Label does not use the exact closed schema"
    )
}

function Assert-SafeEvidenceString {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string]$Label,
        [int]$MaximumLength = 512
    )
    Assert-EvidenceCondition (Test-StrictJsonString $Value) "$Label is not a JSON string"
    $text = [string]$Value
    Assert-EvidenceCondition (
        -not [string]::IsNullOrWhiteSpace($text) -and $text.Length -le $MaximumLength
    ) "$Label is empty or too long"
    Assert-EvidenceCondition ($text -notmatch '[\x00-\x1F\x7F]') (
        "$Label contains control characters"
    )
    Assert-EvidenceCondition (
        $text -notmatch '^[A-Za-z]:' -and
        $text -notmatch '^[\\/]' -and
        $text -notmatch '(^|[\\/])\.\.([\\/]|$)'
    ) "$Label contains a local or traversal-shaped path"
    Assert-EvidenceCondition (
        $text -notmatch '(?i)(authorization\s*:|bearer\s+|password|passphrase|' +
            'private.?key|api[_-]?key|access[_-]?token|refresh[_-]?token|' +
            'client[_-]?secret|credential)'
    ) "$Label contains a credential-bearing shape"
}

function Assert-TrueEvidenceField {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string]$Label
    )
    Assert-EvidenceCondition (
        (Test-StrictJsonBoolean $Value) -and $Value -eq $true
    ) "$Label is not JSON boolean true"
}

function Assert-EvidenceRunner {
    param(
        [Parameter(Mandatory = $true)]$Runner,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)]
        [ValidateSet('windows-x86_64', 'linux-x86_64')]
        [string]$ExpectedPlatform
    )
    Assert-ClosedEvidenceObject $Runner @('label', 'os', 'arch', 'rust_host') $Label
    foreach ($field in @('label', 'os', 'arch', 'rust_host')) {
        Assert-SafeEvidenceString $Runner.$field "$Label.$field" 128
    }
    Assert-EvidenceCondition (
        [string]$Runner.rust_host -match '^[a-z0-9_]+-[a-z0-9_.-]+$'
    ) "$Label.rust_host is not a canonical Rust host tuple"
    $expected = if ($ExpectedPlatform -ceq 'windows-x86_64') {
        @('Windows', 'X64', 'x86_64-pc-windows-msvc')
    }
    else {
        @('Linux', 'X64', 'x86_64-unknown-linux-gnu')
    }
    Assert-EvidenceCondition (
        [string]$Runner.os -ceq $expected[0] -and
        [string]$Runner.arch -ceq $expected[1] -and
        [string]$Runner.rust_host -ceq $expected[2]
    ) "$Label does not match the exact $ExpectedPlatform runner tuple"
}

function Assert-CleanInstallComponentIdentity {
    param(
        [Parameter(Mandatory = $true)]$Identity,
        [Parameter(Mandatory = $true)][string]$ExpectedComponent,
        [Parameter(Mandatory = $true)][ValidatePattern('^[0-9A-F]{64}$')]
        [string]$ExpectedSha256,
        [Parameter(Mandatory = $true)][string]$Label
    )
    Assert-ClosedEvidenceObject $Identity @(
        'component', 'version', 'commit', 'sha256', 'ipc_min', 'ipc_max',
        'storage_contract'
    ) $Label
    foreach ($field in @(
        'component', 'version', 'commit', 'sha256', 'storage_contract'
    )) {
        Assert-SafeEvidenceString $Identity.$field "$Label.$field" 128
    }
    Assert-EvidenceCondition (
        [string]$Identity.component -ceq $ExpectedComponent -and
        [string]$Identity.version -ceq $Tag.Substring(1) -and
        [string]$Identity.commit -ceq $Commit -and
        [string]$Identity.sha256 -cmatch '^[0-9A-F]{64}$' -and
        [string]$Identity.sha256 -ceq $ExpectedSha256 -and
        [string]$Identity.storage_contract -ceq
            'vault-storage read=v4..=v5 write=v5'
    ) "$Label is not bound to the exact release component identity"
    foreach ($field in @('ipc_min', 'ipc_max')) {
        Assert-EvidenceCondition (
            (Test-StrictJsonInteger $Identity.$field) -and $Identity.$field -eq 9
        ) "$Label.$field is not integer IPC v9"
    }
}

function Assert-EvidenceRemoteIdentity {
    param([Parameter(Mandatory = $true)]$Remote)
    $fields = @('os', 'arch', 'openssh_identity', 'helper_identity', 'scp_identity')
    Assert-ClosedEvidenceObject $Remote $fields 'evidence details.remote'
    foreach ($field in $fields) {
        Assert-SafeEvidenceString $Remote.$field "evidence details.remote.$field" 256
    }
}

function Assert-ExternalRuntimeComponents {
    param(
        [Parameter(Mandatory = $true)]$Components,
        [Parameter(Mandatory = $true)]$ExpectedReleaseComponents,
        [Parameter(Mandatory = $true)][string]$Label
    )

    Assert-ClosedEvidenceObject $Components @('cli', 'daemon', 'helper') $Label
    $bindings = @(
        [pscustomobject]@{
            Field = 'cli'; Name = 'serctl_cli.exe'
            Expected = $ExpectedReleaseComponents.'serctl_cli.exe'
        },
        [pscustomobject]@{
            Field = 'daemon'; Name = 'serctl_daemon.exe'
            Expected = $ExpectedReleaseComponents.'serctl_daemon.exe'
        },
        [pscustomobject]@{
            Field = 'helper'; Name = 'serctl-xfer'
            Expected = $ExpectedReleaseComponents.'serctl-xfer'
        }
    )
    foreach ($binding in $bindings) {
        $component = $Components.($binding.Field)
        Assert-ClosedEvidenceObject $component @(
            'binary_size', 'name', 'sha256', 'version'
        ) "$Label.$($binding.Field)"
        foreach ($field in @('name', 'sha256', 'version')) {
            Assert-SafeEvidenceString $component.$field (
                "$Label.$($binding.Field).$field"
            ) 512
        }
        Assert-EvidenceCondition (
            (Test-StrictJsonInteger $component.binary_size) -and
            [long]$component.binary_size -gt 0 -and
            [long]$component.binary_size -le 536870912 -and
            [string]$component.name -ceq [string]$binding.Name -and
            [string]$component.name -ceq [string]$binding.Expected.name -and
            [long]$component.binary_size -eq [long]$binding.Expected.binary_size -and
            [string]$component.sha256 -cmatch '^[0-9A-F]{64}$' -and
            [string]$component.sha256 -ceq [string]$binding.Expected.sha256 -and
            [string]$component.version -ceq [string]$binding.Expected.version
        ) "$Label.$($binding.Field) does not bind the exact downloaded name/size/hash/version"
    }
}

function Get-EvidenceBytesSha256 {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString($sha256.ComputeHash($Bytes))).Replace('-', '')
    }
    finally { $sha256.Dispose() }
}

function Get-ExternalRuntimeContextSha256 {
    param(
        [Parameter(Mandatory = $true)]$Document,
        [Parameter(Mandatory = $true)]$Runner,
        [Parameter(Mandatory = $true)]$Remote,
        [Parameter(Mandatory = $true)]$Components
    )
    $context = [ordered]@{
        tag = [string]$Document.tag
        tag_object = [string]$Document.tag_object
        commit = [string]$Document.commit
        runner = [ordered]@{
            label = [string]$Runner.label
            os = [string]$Runner.os
            arch = [string]$Runner.arch
            rust_host = [string]$Runner.rust_host
        }
        remote = [ordered]@{
            os = [string]$Remote.os
            arch = [string]$Remote.arch
            openssh_identity = [string]$Remote.openssh_identity
            helper_identity = [string]$Remote.helper_identity
            scp_identity = [string]$Remote.scp_identity
        }
        components = [ordered]@{
            cli = [ordered]@{
                name = [string]$Components.cli.name
                binary_size = [long]$Components.cli.binary_size
                sha256 = [string]$Components.cli.sha256
                version = [string]$Components.cli.version
            }
            daemon = [ordered]@{
                name = [string]$Components.daemon.name
                binary_size = [long]$Components.daemon.binary_size
                sha256 = [string]$Components.daemon.sha256
                version = [string]$Components.daemon.version
            }
            helper = [ordered]@{
                name = [string]$Components.helper.name
                binary_size = [long]$Components.helper.binary_size
                sha256 = [string]$Components.helper.sha256
                version = [string]$Components.helper.version
            }
        }
    }
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
        ($context | ConvertTo-Json -Depth 6 -Compress) + "`n"
    )
    return Get-EvidenceBytesSha256 -Bytes $bytes
}

function Assert-EmbeddedRuntimeObservationSet {
    param(
        [Parameter(Mandatory = $true)]$Entries,
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)]$ExpectedCaseResults,
        [Parameter(Mandatory = $true)][string]$ExpectedEvidenceContextSha256,
        [Parameter(Mandatory = $true)][string]$Label
    )
    Assert-EvidenceCondition (Test-StrictJsonArray $Entries) "$Label is not a JSON array"
    $seenCases = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $seenReceiptDigests = [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal
    )
    $seenOperationContexts = [System.Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal
    )
    Assert-EvidenceCondition (
        $ExpectedEvidenceContextSha256 -cmatch '^[0-9A-F]{64}$'
    ) "$Label aggregate evidence context is invalid"
    foreach ($entry in @($Entries)) {
        Assert-ClosedEvidenceObject $entry @(
            'case_id', 'operation_context_sha256', 'receipt_base64', 'receipt_sha256'
        ) "$Label entry"
        Assert-SafeEvidenceString $entry.case_id "$Label entry.case_id" 64
        Assert-EvidenceCondition (
            $ExpectedCaseResults.Contains([string]$entry.case_id) -and
            $seenCases.Add([string]$entry.case_id)
        ) "$Label case is unknown or duplicated"
        Assert-EvidenceCondition (
            (Test-StrictJsonString $entry.receipt_sha256) -and
            [string]$entry.receipt_sha256 -cmatch '^[0-9A-F]{64}$' -and
            $seenReceiptDigests.Add([string]$entry.receipt_sha256)
        ) "$Label receipt SHA-256 is invalid or reused"
        Assert-EvidenceCondition (
            (Test-StrictJsonString $entry.operation_context_sha256) -and
            [string]$entry.operation_context_sha256 -cmatch '^[0-9A-F]{64}$' -and
            [string]$entry.operation_context_sha256 -cne
                $ExpectedEvidenceContextSha256 -and
            $seenOperationContexts.Add([string]$entry.operation_context_sha256)
        ) "$Label operation context is invalid, aggregate, or reused"
        Assert-EvidenceCondition (
            (Test-StrictJsonString $entry.receipt_base64) -and
            [string]$entry.receipt_base64 -cmatch '^[A-Za-z0-9+/]+={0,2}$' -and
            ([string]$entry.receipt_base64).Length -le 87384 -and
            ([string]$entry.receipt_base64).Length % 4 -eq 0
        ) "$Label receipt bytes are not bounded canonical Base64"
        try {
            $receiptBytes = [Convert]::FromBase64String([string]$entry.receipt_base64)
        }
        catch {
            throw "external acceptance evidence failed: $Label receipt Base64 is invalid"
        }
        Assert-EvidenceCondition (
            $receiptBytes.Length -gt 0 -and $receiptBytes.Length -le 65536 -and
            [Convert]::ToBase64String($receiptBytes) -ceq [string]$entry.receipt_base64 -and
            (Get-EvidenceBytesSha256 -Bytes $receiptBytes) -ceq
                [string]$entry.receipt_sha256
        ) "$Label receipt bytes do not match their declared SHA-256"
        try {
            $receiptText = [System.Text.UTF8Encoding]::new($false, $true).GetString(
                $receiptBytes
            )
        }
        catch {
            throw "external acceptance evidence failed: $Label receipt is not strict UTF-8"
        }
        Assert-EvidenceCondition (
            $receiptText.EndsWith("`n") -and -not $receiptText.Contains("`r")
        ) "$Label receipt is not canonical newline-terminated JSON"
        $observation = ConvertFrom-StrictJson `
            -Json $receiptText `
            -Label "$Label protected case receipt" `
            -MaxChars 65536 `
            -MaxDepth 6 `
            -MaxKeyChars 64
        $receiptFields = @(
            'schema_version', 'category', 'case_id', 'context_sha256', 'command_sha256',
            'terminal_sha256', 'result_code', 'passed'
        )
        Assert-ClosedEvidenceObject $observation $receiptFields "$Label protected case receipt"
        Assert-EvidenceCondition (
            (@($observation.PSObject.Properties.Name) -join "`n") -ceq
                ($receiptFields -join "`n")
        ) "$Label protected case receipt field order is not canonical"
        Assert-EvidenceCondition (
            (Test-StrictJsonInteger $observation.schema_version) -and
            $observation.schema_version -eq 1 -and
            [string]$observation.category -ceq $Category -and
            [string]$observation.case_id -ceq [string]$entry.case_id -and
            [string]$observation.context_sha256 -ceq
                [string]$entry.operation_context_sha256 -and
            [string]$observation.result_code -ceq
                [string]$ExpectedCaseResults[[string]$entry.case_id]
        ) "$Label protected case receipt identity or terminal code is invalid"
        foreach ($field in @('category', 'case_id', 'result_code')) {
            Assert-SafeEvidenceString $observation.$field (
                "$Label protected case receipt.$field"
            ) 64
        }
        foreach ($field in @('context_sha256', 'command_sha256', 'terminal_sha256')) {
            Assert-EvidenceCondition (
                (Test-StrictJsonString $observation.$field) -and
                [string]$observation.$field -cmatch '^[0-9A-F]{64}$'
            ) "$Label protected case receipt.$field is invalid"
        }
        Assert-TrueEvidenceField $observation.passed "$Label protected case receipt.passed"
        $canonicalText = ($observation | ConvertTo-Json -Depth 6 -Compress) + "`n"
        Assert-EvidenceCondition ($canonicalText -ceq $receiptText) (
            "$Label protected case receipt bytes are not canonical JSON"
        )
    }
    Assert-EvidenceCondition (
        (($seenCases | Sort-Object) -join "`n") -ceq
            (($ExpectedCaseResults.Keys | Sort-Object) -join "`n")
    ) "$Label does not bind the exact protected case receipt set"
}

# Shared verifier for the exact ledger-owned subset emitted by
# Get-ExternalTransferInteropUnsealableProjection.  A formal artifact supplies
# runner/remote separately; this projection never makes those missing fields
# release-sealable by itself.
function Assert-ExternalInteropDetailsProjection {
    param(
        [Parameter(Mandatory = $true)]$Projection,
        [Parameter(Mandatory = $true)]$ExpectedReleaseComponents,
        [Parameter(Mandatory = $true)][string]$ExpectedEvidenceContextSha256
    )
    $fields = @('evidence_context_sha256', 'components', 'case_receipts')
    Assert-ClosedEvidenceObject $Projection $fields 'interop details projection'
    Assert-EvidenceCondition (
        (@($Projection.PSObject.Properties.Name) -join "`n") -ceq
            ($fields -join "`n")
    ) 'interop details projection field order is not canonical'
    Assert-EvidenceCondition (
        (Test-StrictJsonString $Projection.evidence_context_sha256) -and
        [string]$Projection.evidence_context_sha256 -cmatch '^[0-9A-F]{64}$' -and
        [string]$Projection.evidence_context_sha256 -ceq
            $ExpectedEvidenceContextSha256
    ) 'interop aggregate evidence context does not match its envelope'
    Assert-ExternalRuntimeComponents `
        -Components $Projection.components `
        -ExpectedReleaseComponents $ExpectedReleaseComponents `
        -Label 'interop runtime components'
    $interopResults = [ordered]@{
        OpenSSH_exec = 'completed'; OpenSSH_directory = 'completed'
        OpenSSH_tunnel_local = 'completed'; OpenSSH_tunnel_remote = 'completed'
        OpenSSH_tunnel_dynamic = 'completed'; OpenSSH_sftp = 'completed'
        OpenSSH_native = 'completed'; Dropbear_exec = 'completed'
        Dropbear_sftp = 'completed'; Dropbear_native = 'completed'
    }
    Assert-EmbeddedRuntimeObservationSet `
        -Entries $Projection.case_receipts `
        -Category 'openssh_dropbear_interop' `
        -ExpectedCaseResults $interopResults `
        -ExpectedEvidenceContextSha256 $ExpectedEvidenceContextSha256 `
        -Label 'interop protected case receipts'
}

function Assert-ExternalEvidenceDocument {
    param(
        [Parameter(Mandatory = $true)]$Document,
        [Parameter(Mandatory = $true)][string]$ExpectedCategory,
        [Parameter(Mandatory = $true)][DateTimeOffset]$ManifestCompleted,
        [Parameter(Mandatory = $true)][string]$ManifestOwner,
        [Parameter(Mandatory = $true)][string]$ReleaseManifestHash,
        [Parameter(Mandatory = $true)]$ExpectedReleaseComponents
    )

    $envelopeFields = @(
        'schema_version', 'category', 'status', 'tag', 'tag_object', 'commit',
        'release_manifest_sha256', 'evidence_owner', 'timestamps', 'test_counts',
        'limitations', 'details'
    )
    Assert-ClosedEvidenceObject $Document $envelopeFields "evidence artifact '$ExpectedCategory'"
    Assert-EvidenceCondition (
        (Test-StrictJsonInteger $Document.schema_version) -and $Document.schema_version -eq 1
    ) "evidence artifact '$ExpectedCategory' schema_version is not integer 1"
    foreach ($field in @(
        'category', 'status', 'tag', 'tag_object', 'commit',
        'release_manifest_sha256', 'evidence_owner'
    )) {
        Assert-SafeEvidenceString $Document.$field (
            "evidence artifact '$ExpectedCategory'.$field"
        ) 256
    }
    Assert-EvidenceCondition (
        [string]$Document.category -ceq $ExpectedCategory -and
        [string]$Document.status -ceq 'passed' -and
        [string]$Document.tag -ceq $Tag -and
        [string]$Document.tag_object -ceq $TagObject -and
        [string]$Document.commit -ceq $Commit -and
        [string]$Document.release_manifest_sha256 -ceq $ReleaseManifestHash -and
        [string]$Document.evidence_owner -ceq $ManifestOwner
    ) "evidence artifact '$ExpectedCategory' is not bound to the approved identity"

    Assert-ClosedEvidenceObject $Document.timestamps @('started_utc', 'completed_utc') (
        "evidence artifact '$ExpectedCategory'.timestamps"
    )
    foreach ($field in @('started_utc', 'completed_utc')) {
        Assert-EvidenceCondition (Test-StrictJsonString $Document.timestamps.$field) (
            "evidence artifact '$ExpectedCategory'.timestamps.$field is not a JSON string"
        )
    }
    $started = Get-CanonicalTimestamp ([string]$Document.timestamps.started_utc) (
        "evidence artifact '$ExpectedCategory' started_utc"
    )
    $completed = Get-CanonicalTimestamp ([string]$Document.timestamps.completed_utc) (
        "evidence artifact '$ExpectedCategory' completed_utc"
    )
    Assert-EvidenceCondition ($started -le $completed -and $completed -le $ManifestCompleted) (
        "evidence artifact '$ExpectedCategory' timestamps are out of order"
    )

    $counts = $Document.test_counts
    Assert-ClosedEvidenceObject $counts @(
        'total', 'passed', 'failed', 'skipped', 'ignored', 'unknown'
    ) (
        "evidence artifact '$ExpectedCategory'.test_counts"
    )
    foreach ($field in @('total', 'passed', 'failed', 'skipped', 'ignored', 'unknown')) {
        Assert-EvidenceCondition (
            (Test-StrictJsonInteger $counts.$field) -and $counts.$field -ge 0
        ) "evidence artifact '$ExpectedCategory'.test_counts.$field is invalid"
    }
    Assert-EvidenceCondition (
        $counts.passed -gt 0 -and $counts.failed -eq 0 -and
        $counts.skipped -eq 0 -and $counts.ignored -eq 0 -and $counts.unknown -eq 0 -and
        $counts.total -eq (
            $counts.passed + $counts.failed + $counts.skipped +
            $counts.ignored + $counts.unknown
        )
    ) "evidence artifact '$ExpectedCategory' test counts do not prove a complete pass"

    Assert-EvidenceCondition (Test-StrictJsonArray $Document.limitations) (
        "evidence artifact '$ExpectedCategory'.limitations is not a JSON array"
    )
    $limitations = @($Document.limitations)
    Assert-EvidenceCondition ($limitations.Count -le 16) (
        "evidence artifact '$ExpectedCategory' must declare at most 16 limitations"
    )
    foreach ($limitation in $limitations) {
        Assert-SafeEvidenceString $limitation (
            "evidence artifact '$ExpectedCategory' limitation"
        ) 512
    }

    $details = $Document.details
    switch ($ExpectedCategory) {
        'clean_install_smoke' {
            $fields = @(
                'runner', 'bundle_version', 'cli_identity', 'daemon_identity',
                'fresh_home', 'install_passed', 'status_passed',
                'grant_issue_passed', 'cleanup_passed', 'rollback_passed'
            )
            Assert-ClosedEvidenceObject $details $fields 'clean_install_smoke details'
            Assert-EvidenceRunner `
                $details.runner `
                'clean_install_smoke details.runner' `
                'windows-x86_64'
            Assert-SafeEvidenceString $details.bundle_version (
                'clean_install_smoke details.bundle_version'
            ) 64
            Assert-EvidenceCondition (
                [string]$details.bundle_version -ceq $Tag.Substring(1)
            ) 'clean_install_smoke bundle version does not match the exact tag'
            Assert-CleanInstallComponentIdentity `
                -Identity $details.cli_identity `
                -ExpectedComponent 'serctl_cli' `
                -ExpectedSha256 ([string]$ExpectedReleaseComponents.'serctl_cli.exe'.sha256) `
                -Label 'clean_install_smoke details.cli_identity'
            Assert-CleanInstallComponentIdentity `
                -Identity $details.daemon_identity `
                -ExpectedComponent 'serctl_daemon' `
                -ExpectedSha256 ([string]$ExpectedReleaseComponents.'serctl_daemon.exe'.sha256) `
                -Label 'clean_install_smoke details.daemon_identity'
            foreach ($field in @(
                'fresh_home', 'install_passed', 'status_passed', 'grant_issue_passed',
                'cleanup_passed', 'rollback_passed'
            )) { Assert-TrueEvidenceField $details.$field "clean_install_smoke details.$field" }
        }
        'native_transfer_real_host' {
            Assert-ClosedEvidenceObject $details @(
                'runner', 'remote', 'components', 'evidence_context_sha256',
                'cases', 'fault_cases',
                'registry_window', 'performance', 'runtime_observations'
            ) (
                'native_transfer_real_host details'
            )
            Assert-EvidenceRunner `
                $details.runner `
                'native_transfer_real_host details.runner' `
                'windows-x86_64'
            Assert-EvidenceRemoteIdentity $details.remote
            Assert-ExternalRuntimeComponents `
                -Components $details.components `
                -ExpectedReleaseComponents $ExpectedReleaseComponents `
                -Label 'native transfer runtime components'
            $computedEvidenceContextSha256 = Get-ExternalRuntimeContextSha256 `
                -Document $Document `
                -Runner $details.runner `
                -Remote $details.remote `
                -Components $details.components
            Assert-EvidenceCondition (
                (Test-StrictJsonString $details.evidence_context_sha256) -and
                [string]$details.evidence_context_sha256 -cmatch '^[0-9A-F]{64}$' -and
                [string]$details.evidence_context_sha256 -ceq
                    $computedEvidenceContextSha256
            ) 'native transfer aggregate evidence context does not match its envelope'
            Assert-EvidenceCondition (Test-StrictJsonArray $details.cases) (
                'native_transfer_real_host details.cases is not a JSON array'
            )
            $fixedCaseHashes = [ordered]@{
                '21' = '75AEE9DCC9FBE7DDC9394F5BC5D38D9F5AD361F0520F7CEAB59616E38F5950B5'
                '1298223' = '27C51BE520501C692C8981A8331DE45467D9B7A64B63DD4D3E2CFC2C134F0FAD'
                '67108864' = '5C8A41A9B8D7FC418BA77B0312EFC461DE86740EF476F4B53ADAB9313C4D1562'
                '1073741824' = 'E18E3F358B46EAE9266AC36A5FF6347F6BF09711DFF389597F237D5FE83111D8'
            }
            $caseKeys = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            foreach ($case in @($details.cases)) {
                Assert-ClosedEvidenceObject $case @('direction', 'size_bytes', 'sha256', 'passed') (
                    'native transfer case'
                )
                Assert-SafeEvidenceString $case.direction 'native transfer case.direction' 8
                Assert-EvidenceCondition (
                    [string]$case.direction -in @('push', 'pull')
                ) 'native transfer case.direction is invalid'
                Assert-EvidenceCondition (
                    (Test-StrictJsonInteger $case.size_bytes) -and $case.size_bytes -gt 0
                ) 'native transfer case.size_bytes is invalid'
                Assert-EvidenceCondition (
                    $caseKeys.Add("$($case.direction):$($case.size_bytes)")
                ) 'native transfer case is duplicated'
                Assert-EvidenceCondition (
                    (Test-StrictJsonString $case.sha256) -and
                    [string]$case.sha256 -cmatch '^[0-9A-F]{64}$' -and
                    $fixedCaseHashes.Contains([string]$case.size_bytes) -and
                    [string]$case.sha256 -ceq $fixedCaseHashes[[string]$case.size_bytes]
                ) 'native transfer case.sha256 is not the fixed deterministic payload digest'
                Assert-TrueEvidenceField $case.passed 'native transfer case.passed'
            }
            $requiredCases = foreach ($direction in @('push', 'pull')) {
                foreach ($size in @(21, 1298223, 67108864, 1073741824)) {
                    "${direction}:$size"
                }
            }
            Assert-EvidenceCondition (
                (($caseKeys | Sort-Object) -join "`n") -ceq (($requiredCases | Sort-Object) -join "`n")
            ) (
                'native transfer cases do not cover the exact push/pull size matrix'
            )
            Assert-EvidenceCondition (Test-StrictJsonArray $details.fault_cases) (
                'native transfer fault_cases is not a JSON array'
            )
            $expectedFaults = [ordered]@{
                resume_25 = @('completed', 25, 'complete')
                resume_75 = @('completed', 75, 'complete')
                lost_ack = @('outcome_unknown', 0, 'owned_partial_preserved')
                helper_crash = @('outcome_unknown', 0, 'owned_partial_preserved')
                disconnect = @('outcome_unknown', 0, 'owned_partial_preserved')
                daemon_restart = @('outcome_unknown', 0, 'owned_partial_preserved')
                disk_full = @('transfer_failed', 0, 'owned_partial_removed')
                permission_denied = @('transfer_failed', 0, 'owned_partial_removed')
                target_race = @('transfer_failed', 0, 'owned_partial_removed')
                target_symlink_or_reparse = @(
                    'transfer_failed', 0, 'no_owned_partial_created'
                )
                unknown_cleanup = @('cleanup_incomplete', 0, 'cleanup_incomplete')
            }
            $faultNames = [System.Collections.Generic.HashSet[string]]::new(
                [StringComparer]::Ordinal
            )
            foreach ($fault in @($details.fault_cases)) {
                Assert-ClosedEvidenceObject $fault @(
                    'scenario', 'result_code', 'resume_percent', 'cleanup_state',
                    'confirmed_advanced_without_ack', 'target_overwritten',
                    'foreign_partial_deleted', 'passed'
                ) 'native transfer fault case'
                foreach ($field in @('scenario', 'result_code', 'cleanup_state')) {
                    Assert-SafeEvidenceString $fault.$field "native fault case.$field" 64
                }
                $scenario = [string]$fault.scenario
                Assert-EvidenceCondition (
                    $expectedFaults.Contains($scenario) -and $faultNames.Add($scenario)
                ) 'native transfer fault case is unknown or duplicated'
                $expectedFault = $expectedFaults[$scenario]
                Assert-EvidenceCondition (
                    [string]$fault.result_code -ceq [string]$expectedFault[0] -and
                    (Test-StrictJsonInteger $fault.resume_percent) -and
                    [int64]$fault.resume_percent -eq [int64]$expectedFault[1] -and
                    [string]$fault.cleanup_state -ceq [string]$expectedFault[2]
                ) 'native transfer fault case terminal classification mismatch'
                foreach ($field in @(
                    'confirmed_advanced_without_ack', 'target_overwritten',
                    'foreign_partial_deleted'
                )) {
                    Assert-EvidenceCondition (
                        (Test-StrictJsonBoolean $fault.$field) -and -not $fault.$field
                    ) "native transfer fault case.$field is not false"
                }
                Assert-TrueEvidenceField $fault.passed 'native transfer fault case.passed'
            }
            Assert-EvidenceCondition (
                (($faultNames | Sort-Object) -join "`n") -ceq
                    (($expectedFaults.Keys | Sort-Object) -join "`n")
            ) 'native transfer fault matrix is incomplete'
            $nativeObservationResults = [ordered]@{
                push_21 = 'completed'; push_1298223 = 'completed'
                push_67108864 = 'completed'; push_1073741824 = 'completed'
                pull_21 = 'completed'; pull_1298223 = 'completed'
                pull_67108864 = 'completed'; pull_1073741824 = 'completed'
                resume_25 = 'completed'; resume_75 = 'completed'
                lost_ack = 'outcome_unknown'; helper_crash = 'outcome_unknown'
                disconnect = 'outcome_unknown'; daemon_restart = 'outcome_unknown'
                disk_full = 'transfer_failed'; permission_denied = 'transfer_failed'
                target_race = 'transfer_failed'
                target_symlink_or_reparse = 'transfer_failed'
                unknown_cleanup = 'cleanup_incomplete'
                registry_window = 'completed'
            }
            Assert-EmbeddedRuntimeObservationSet `
                -Entries $details.runtime_observations `
                -Category 'native_transfer_real_host' `
                -ExpectedCaseResults $nativeObservationResults `
                -ExpectedEvidenceContextSha256 ([string]$details.evidence_context_sha256) `
                -Label 'native runtime observations'

            $registry = $details.registry_window
            $registryFields = @(
                'active_per_profile', 'active_global', 'terminal_per_profile',
                'terminal_global', 'retention_max_seconds', 'sftp_write_bytes',
                'sftp_inflight_writes', 'native_chunk_bytes', 'native_ack_window_bytes',
                'profile_isolation_passed', 'control_frame_bound_passed',
                'confirmed_before_ack'
            )
            Assert-ClosedEvidenceObject $registry $registryFields 'native registry/window evidence'
            $expectedRegistry = [ordered]@{
                active_per_profile = 8
                active_global = 48
                terminal_per_profile = 16
                terminal_global = 256
                retention_max_seconds = 900
                sftp_write_bytes = 2048
                sftp_inflight_writes = 1
                native_chunk_bytes = 32768
                native_ack_window_bytes = 32768
            }
            foreach ($field in $expectedRegistry.Keys) {
                Assert-EvidenceCondition (
                    (Test-StrictJsonInteger $registry.$field) -and
                    [int64]$registry.$field -eq [int64]$expectedRegistry[$field]
                ) "native registry/window evidence.$field mismatch"
            }
            foreach ($field in @('profile_isolation_passed', 'control_frame_bound_passed')) {
                Assert-TrueEvidenceField $registry.$field "native registry/window evidence.$field"
            }
            Assert-EvidenceCondition (
                (Test-StrictJsonBoolean $registry.confirmed_before_ack) -and
                -not $registry.confirmed_before_ack
            ) 'native registry/window evidence advanced confirmation before ACK'
            $performance = $details.performance
            $performanceFields = @(
                'native_p50_bytes_per_second', 'native_p95_bytes_per_second',
                'scp_bytes_per_second', 'throughput_ratio_percent', 'cpu_basis_points',
                'peak_rss_bytes', 'rtt_microseconds', 'chunk_bytes', 'window_bytes',
                'native_samples', 'scp_samples'
            )
            Assert-ClosedEvidenceObject $performance $performanceFields 'native transfer performance'
            foreach ($field in @(
                'native_p50_bytes_per_second', 'native_p95_bytes_per_second',
                'scp_bytes_per_second', 'throughput_ratio_percent', 'cpu_basis_points',
                'peak_rss_bytes', 'rtt_microseconds', 'chunk_bytes', 'window_bytes'
            )) {
                Assert-EvidenceCondition (
                    (Test-StrictJsonInteger $performance.$field) -and $performance.$field -gt 0
                ) "native transfer performance.$field is invalid"
            }
            $sampleFields = @(
                'sample_index', 'size_bytes', 'elapsed_microseconds', 'cpu_basis_points',
                'peak_rss_bytes', 'rtt_microseconds'
            )
            $sampleRates = [ordered]@{}
            foreach ($kind in @('native', 'scp')) {
                $field = "${kind}_samples"
                Assert-EvidenceCondition (Test-StrictJsonArray $performance.$field) (
                    "native transfer performance.$field is not a JSON array"
                )
                $samples = @($performance.$field)
                Assert-EvidenceCondition ($samples.Count -eq 5) (
                    "native transfer performance.$field does not contain exactly five raw samples"
                )
                $rates = @()
                for ($index = 0; $index -lt $samples.Count; $index++) {
                    $sample = $samples[$index]
                    Assert-ClosedEvidenceObject $sample $sampleFields (
                        "native transfer performance.$field sample"
                    )
                    foreach ($sampleField in $sampleFields) {
                        Assert-EvidenceCondition (
                            (Test-StrictJsonInteger $sample.$sampleField) -and
                            [int64]$sample.$sampleField -gt 0
                        ) "native transfer performance.$field.$sampleField is invalid"
                    }
                    Assert-EvidenceCondition (
                        [int64]$sample.sample_index -eq ($index + 1) -and
                        [int64]$sample.size_bytes -eq 67108864 -and
                        [int64]$sample.cpu_basis_points -le 10000 -and
                        [int64]$sample.peak_rss_bytes -le 16777216
                    ) "native transfer performance.$field sample is outside the fixed envelope"
                    try {
                        $rates += [decimal]::Floor(
                            ([decimal]$sample.size_bytes * [decimal]1000000) /
                            [decimal]$sample.elapsed_microseconds
                        )
                    }
                    catch {
                        throw (
                            'external acceptance evidence failed: native transfer raw ' +
                            'performance arithmetic overflowed'
                        )
                    }
                }
                $sampleRates[$kind] = @($rates | Sort-Object)
            }
            $nativeRates = @($sampleRates.native)
            $scpRates = @($sampleRates.scp)
            $nativeSamples = @($performance.native_samples)
            $expectedCpu = [int64](
                ($nativeSamples.cpu_basis_points | Measure-Object -Maximum).Maximum
            )
            $expectedRss = [int64](
                ($nativeSamples.peak_rss_bytes | Measure-Object -Maximum).Maximum
            )
            $expectedRtt = [int64](@($nativeSamples.rtt_microseconds | Sort-Object)[2])
            Assert-EvidenceCondition (
                [decimal]$performance.native_p50_bytes_per_second -eq [decimal]$nativeRates[2] -and
                [decimal]$performance.native_p95_bytes_per_second -eq [decimal]$nativeRates[4] -and
                [decimal]$performance.scp_bytes_per_second -eq [decimal]$scpRates[2] -and
                [int64]$performance.cpu_basis_points -eq $expectedCpu -and
                [int64]$performance.peak_rss_bytes -eq $expectedRss -and
                [int64]$performance.rtt_microseconds -eq $expectedRtt
            ) 'native transfer performance summary is not derived from its raw samples'
            Assert-EvidenceCondition (
                $performance.chunk_bytes -eq 32768 -and
                $performance.window_bytes -eq 32768
            ) 'native transfer performance does not report the effective one-ACK window'
            try {
                $reportedRatio = [decimal]$performance.throughput_ratio_percent
                $computedRatio = [decimal]::Floor(
                    ([decimal]$performance.native_p50_bytes_per_second * [decimal]100) /
                    [decimal]$performance.scp_bytes_per_second
                )
            }
            catch {
                throw (
                    'external acceptance evidence failed: native transfer performance ' +
                    'ratio arithmetic overflowed'
                )
            }
            Assert-EvidenceCondition (
                $reportedRatio -eq $computedRatio -and $reportedRatio -ge [decimal]80 -and
                $performance.peak_rss_bytes -le 16777216 -and
                $performance.cpu_basis_points -le 10000 -and
                $performance.native_p95_bytes_per_second -ge
                    $performance.native_p50_bytes_per_second
            ) 'native transfer performance misses the acceptance floor'
            Assert-EvidenceCondition (
                $counts.total -eq 20 -and $counts.passed -eq 20
            ) 'native transfer evidence counts do not bind all 20 required cases'
        }
        'openssh_dropbear_interop' {
            Assert-ClosedEvidenceObject $details @(
                'runner', 'remote', 'components', 'evidence_context_sha256',
                'implementations', 'case_receipts'
            ) (
                'openssh_dropbear_interop details'
            )
            Assert-EvidenceRunner `
                $details.runner `
                'openssh_dropbear_interop details.runner' `
                'linux-x86_64'
            Assert-EvidenceRemoteIdentity $details.remote
            $computedEvidenceContextSha256 = Get-ExternalRuntimeContextSha256 `
                -Document $Document `
                -Runner $details.runner `
                -Remote $details.remote `
                -Components $details.components
            $detailsProjection = [pscustomobject][ordered]@{
                evidence_context_sha256 = $details.evidence_context_sha256
                components = $details.components
                case_receipts = $details.case_receipts
            }
            Assert-ExternalInteropDetailsProjection `
                -Projection $detailsProjection `
                -ExpectedReleaseComponents $ExpectedReleaseComponents `
                -ExpectedEvidenceContextSha256 $computedEvidenceContextSha256
            Assert-EvidenceCondition (Test-StrictJsonArray $details.implementations) (
                'interop implementations is not a JSON array'
            )
            $names = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
            foreach ($implementation in @($details.implementations)) {
                Assert-ClosedEvidenceObject $implementation @(
                    'name', 'identity', 'exec_passed', 'sftp_passed', 'native_passed'
                ) 'interop implementation'
                Assert-SafeEvidenceString $implementation.name 'interop implementation.name' 32
                Assert-SafeEvidenceString $implementation.identity 'interop implementation.identity' 256
                Assert-EvidenceCondition ($names.Add([string]$implementation.name)) (
                    'interop implementation is duplicated'
                )
                foreach ($field in @('exec_passed', 'sftp_passed', 'native_passed')) {
                    Assert-TrueEvidenceField $implementation.$field "interop implementation.$field"
                }
            }
            Assert-EvidenceCondition (
                @($details.implementations).Count -eq 2 -and
                (($names | Sort-Object) -join "`n") -ceq "Dropbear`nOpenSSH"
            ) 'interop evidence does not contain exactly OpenSSH and Dropbear'
            Assert-EvidenceCondition (
                $counts.total -eq 10 -and $counts.passed -eq 10
            ) 'interop evidence does not bind each OpenSSH/Dropbear case exactly once'
        }
        'whole_bundle_upgrade_rollback' {
            $fields = @(
                'runner', 'predecessor_version', 'candidate_version', 'upgrade_outcome',
                'rollback_outcome', 'predecessor_files', 'candidate_files',
                'descriptor_owner_pid', 'descriptor_daemon_identity',
                'descriptor_daemon_sha256',
                'whole_bundle_atomic', 'mixed_triples_tested', 'mixed_triples_rejected',
                'hash_substitutions_tested', 'hash_substitutions_rejected',
                'stale_descriptor_rejected', 'stale_grant_rejected',
                'matched_bundle_upgrade_verified', 'matched_bundle_rollback_verified',
                'audit_seed_key_package_verified',
                'vault_storage_v4_to_v5_upgrade_verified',
                'beta2_destructive_writer_blocked_before_mutation',
                'beta2_transient_runtime_activation_observed',
                'beta2_runtime_state_cleaned_after_rejection',
                'candidate_storage_marker_verified',
                'v8_unknown_audit_fields_rejected_before_write',
                'unknown_security_fields_not_dropped', 'vault_rollback_verified',
                'pre_upgrade_vault_backup_restored',
                'matching_recovery_media_restored', 'acl_owner_metadata_restored'
            )
            Assert-ClosedEvidenceObject $details $fields 'whole_bundle_upgrade_rollback details'
            Assert-EvidenceRunner `
                $details.runner `
                'whole_bundle_upgrade_rollback details.runner' `
                'windows-x86_64'
            foreach ($field in @(
                'predecessor_version', 'candidate_version', 'upgrade_outcome', 'rollback_outcome'
            )) { Assert-SafeEvidenceString $details.$field "whole bundle details.$field" 128 }
            Assert-EvidenceCondition (
                [string]$details.predecessor_version -ceq '0.3.0-beta.2' -and
                [string]$details.candidate_version -ceq $Tag.Substring(1) -and
                [string]$details.upgrade_outcome -ceq 'passed' -and
                [string]$details.rollback_outcome -ceq 'passed'
            ) 'whole-bundle upgrade or rollback outcome did not pass'
            foreach ($bundleName in @('predecessor_files', 'candidate_files')) {
                $bundle = $details.$bundleName
                Assert-ClosedEvidenceObject $bundle @(
                    'cli_sha256', 'daemon_sha256', 'xfer_sha256'
                ) "whole bundle details.$bundleName"
                foreach ($field in @('cli_sha256', 'daemon_sha256', 'xfer_sha256')) {
                    Assert-EvidenceCondition (
                        (Test-StrictJsonString $bundle.$field) -and
                        [string]$bundle.$field -cmatch '^[0-9A-F]{64}$'
                    ) "whole bundle details.$bundleName.$field is invalid"
                }
            }
            Assert-EvidenceCondition (
                [string]$details.candidate_files.cli_sha256 -ceq
                    [string]$ExpectedReleaseComponents.'serctl_cli.exe'.sha256 -and
                [string]$details.candidate_files.daemon_sha256 -ceq
                    [string]$ExpectedReleaseComponents.'serctl_daemon.exe'.sha256 -and
                [string]$details.candidate_files.xfer_sha256 -ceq
                    [string]$ExpectedReleaseComponents.'serctl-xfer'.sha256
            ) 'whole-bundle candidate hashes are not the downloaded release components'
            Assert-EvidenceCondition (
                (Test-StrictJsonInteger $details.descriptor_owner_pid) -and
                $details.descriptor_owner_pid -gt 0
            ) 'whole bundle descriptor owner PID is invalid'
            Assert-SafeEvidenceString $details.descriptor_daemon_identity (
                'whole bundle descriptor daemon identity'
            ) 256
            Assert-EvidenceCondition (
                [string]$details.descriptor_daemon_identity -ceq (
                    "serctl_daemon $($Tag.Substring(1)) " +
                    "(git $($Commit.Substring(0, 12)); IPC v9..=v9; " +
                    'vault-storage read=v4..=v5 write=v5)'
                )
            ) 'whole bundle descriptor daemon identity is not the exact candidate identity'
            Assert-EvidenceCondition (
                (Test-StrictJsonString $details.descriptor_daemon_sha256) -and
                [string]$details.descriptor_daemon_sha256 -cmatch '^[0-9A-F]{64}$' -and
                [string]$details.descriptor_daemon_sha256 -ceq
                    [string]$ExpectedReleaseComponents.'serctl_daemon.exe'.sha256
            ) 'whole bundle descriptor daemon SHA-256 is not the downloaded release daemon'
            foreach ($field in @(
                'mixed_triples_tested', 'mixed_triples_rejected'
            )) {
                Assert-EvidenceCondition (
                    (Test-StrictJsonInteger $details.$field) -and $details.$field -eq 6
                ) "whole bundle details.$field is not exactly 6"
            }
            foreach ($field in @(
                'hash_substitutions_tested', 'hash_substitutions_rejected'
            )) {
                Assert-EvidenceCondition (
                    (Test-StrictJsonInteger $details.$field) -and $details.$field -eq 3
                ) "whole bundle details.$field is not exactly 3"
            }
            foreach ($field in @(
                'whole_bundle_atomic', 'stale_descriptor_rejected', 'stale_grant_rejected',
                'matched_bundle_upgrade_verified', 'matched_bundle_rollback_verified',
                'audit_seed_key_package_verified',
                'vault_storage_v4_to_v5_upgrade_verified',
                'beta2_destructive_writer_blocked_before_mutation',
                'beta2_runtime_state_cleaned_after_rejection',
                'candidate_storage_marker_verified',
                'v8_unknown_audit_fields_rejected_before_write',
                'unknown_security_fields_not_dropped', 'vault_rollback_verified',
                'pre_upgrade_vault_backup_restored',
                'matching_recovery_media_restored', 'acl_owner_metadata_restored'
            )) { Assert-TrueEvidenceField $details.$field "whole bundle details.$field" }
            Assert-EvidenceCondition (
                Test-StrictJsonBoolean $details.beta2_transient_runtime_activation_observed
            ) (
                'whole bundle details.beta2_transient_runtime_activation_observed ' +
                'is not a JSON boolean'
            )
        }
        'windows_privileged_acl' {
            $fields = @(
                'runner', 'candidate_cli_sha256', 'owner_sid', 'observer_sid', 'distinct_sids',
                'parent_control_passed', 'observer_read_denied',
                'observer_write_denied', 'owner_reopen_passed', 'dacl_protected',
                'reparse_point_rejected', 'owner_rights_restricted',
                'system_full_control', 'administrators_full_control',
                'inheritance_protected', 'cleanup_passed'
            )
            Assert-ClosedEvidenceObject $details $fields 'windows_privileged_acl details'
            Assert-EvidenceRunner `
                $details.runner `
                'windows_privileged_acl details.runner' `
                'windows-x86_64'
            Assert-EvidenceCondition (
                (Test-StrictJsonString $details.candidate_cli_sha256) -and
                [string]$details.candidate_cli_sha256 -cmatch '^[0-9A-F]{64}$' -and
                [string]$details.candidate_cli_sha256 -ceq
                    [string]$ExpectedReleaseComponents.'serctl_cli.exe'.sha256
            ) 'Windows ACL candidate CLI SHA-256 is not the downloaded release CLI'
            foreach ($field in @('owner_sid', 'observer_sid')) {
                Assert-EvidenceCondition (
                    (Test-StrictJsonString $details.$field) -and
                    [string]$details.$field -match '^S-1-[0-9]+(?:-[0-9]+)+$'
                ) "windows ACL details.$field is not a SID"
            }
            Assert-EvidenceCondition (
                [string]$details.owner_sid -cne [string]$details.observer_sid
            ) 'windows ACL owner and observer SID are identical'
            foreach ($field in @(
                'distinct_sids', 'parent_control_passed', 'observer_read_denied',
                'observer_write_denied', 'owner_reopen_passed', 'dacl_protected',
                'reparse_point_rejected', 'owner_rights_restricted',
                'system_full_control', 'administrators_full_control',
                'inheritance_protected', 'cleanup_passed'
            )) { Assert-TrueEvidenceField $details.$field "windows ACL details.$field" }
        }
        default { throw "external acceptance evidence failed: unknown evidence category" }
    }
}

$recordPath = [System.IO.Path]::GetFullPath($AcceptanceRecordPath)
$evidencePath = [System.IO.Path]::GetFullPath($EvidenceManifestPath)
$evidenceArtifactRoot = $null
if (-not [string]::IsNullOrWhiteSpace($EvidenceArtifactDirectory)) {
    $evidenceArtifactRoot = Get-Item `
        -LiteralPath $EvidenceArtifactDirectory `
        -Force `
        -ErrorAction Stop
    Assert-EvidenceCondition ($evidenceArtifactRoot.PSIsContainer) (
        'evidence artifact directory is not a directory'
    )
    Assert-EvidenceCondition (
        ($evidenceArtifactRoot.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0
    ) 'evidence artifact directory is a reparse point'
}
$releaseBindings = Get-ReleaseComponentHashes -ManifestPath $ReleaseManifestPath
$releaseManifestHash = [string]$releaseBindings.manifest_sha256
$expectedReleaseComponents = $releaseBindings.components

Assert-EvidenceCondition (
    (Get-FileHash -LiteralPath $recordPath -Algorithm SHA256).Hash -ceq $AcceptanceRecordSha256
) 'acceptance record SHA-256 mismatch'
$recordFields = @(
    'schema_version',
    'accepted',
    'tag',
    'tag_object',
    'commit',
    'release_manifest_sha256',
    'acceptance_owner',
    'completed_utc',
    'evidence_manifest_url',
    'evidence_manifest_sha256'
)
$record = Get-ClosedJsonObject `
    -Path $recordPath `
    -Fields $recordFields `
    -MaximumBytes 65536 `
    -Label 'acceptance record' `
    -ExpectedSha256 $AcceptanceRecordSha256
Assert-EvidenceCondition (
    (Test-StrictJsonInteger $record.schema_version) -and $record.schema_version -eq 1
) 'acceptance record schema_version is not integer 1'
Assert-EvidenceCondition (
    (Test-StrictJsonBoolean $record.accepted) -and $record.accepted -eq $true
) (
    'acceptance record does not authorize publication'
)
foreach ($field in @(
    'tag', 'tag_object', 'commit', 'release_manifest_sha256',
    'acceptance_owner', 'completed_utc', 'evidence_manifest_url',
    'evidence_manifest_sha256'
)) {
    Assert-EvidenceCondition (Test-StrictJsonString $record.$field) (
        "acceptance record field '$field' is not a JSON string"
    )
}
Assert-EvidenceCondition (
    [string]$record.tag -ceq $Tag -and
    [string]$record.tag_object -ceq $TagObject -and
    [string]$record.commit -ceq $Commit
) 'acceptance record is bound to another release identity'
Assert-EvidenceCondition (
    [string]$record.release_manifest_sha256 -ceq $releaseManifestHash
) 'acceptance record does not bind the release SHA256SUMS'
Assert-EvidenceCondition (
    $null -ne $record.acceptance_owner
) 'acceptance record has no acceptance owner'
Assert-SafeEvidenceString $record.acceptance_owner 'acceptance record acceptance_owner' 128
$recordCompleted = Get-CanonicalTimestamp `
    -Value ([string]$record.completed_utc) `
    -Label 'acceptance record completed_utc'
$recordUri = Get-CheckedHttpsUri -Value $AcceptanceRecordUrl -Label 'acceptance record URL'
$evidenceUri = Get-CheckedHttpsUri `
    -Value ([string]$record.evidence_manifest_url) `
    -Label 'evidence manifest URL'
Assert-EvidenceCondition (
    [Uri]::Compare(
        $recordUri,
        $evidenceUri,
        [UriComponents]::AbsoluteUri,
        [UriFormat]::SafeUnescaped,
        [StringComparison]::OrdinalIgnoreCase
    ) -ne 0
) 'evidence manifest URL must be distinct from the acceptance record URL'
Assert-EvidenceCondition (
    [string]$record.evidence_manifest_sha256 -cmatch '^[0-9A-F]{64}$'
) 'evidence manifest SHA-256 is not canonical uppercase hex'
Assert-EvidenceCondition (
    (Get-FileHash -LiteralPath $evidencePath -Algorithm SHA256).Hash -ceq
        [string]$record.evidence_manifest_sha256
) 'evidence manifest SHA-256 mismatch'

$manifestFields = @(
    'schema_version',
    'tag',
    'tag_object',
    'commit',
    'release_manifest_sha256',
    'evidence_owner',
    'completed_utc',
    'categories'
)
$manifest = Get-ClosedJsonObject `
    -Path $evidencePath `
    -Fields $manifestFields `
    -MaximumBytes 262144 `
    -Label 'evidence manifest' `
    -ExpectedSha256 ([string]$record.evidence_manifest_sha256)
Assert-EvidenceCondition (
    (Test-StrictJsonInteger $manifest.schema_version) -and $manifest.schema_version -eq 1
) (
    'evidence manifest schema_version is not 1'
)
foreach ($field in @(
    'tag', 'tag_object', 'commit', 'release_manifest_sha256',
    'evidence_owner', 'completed_utc'
)) {
    Assert-EvidenceCondition (Test-StrictJsonString $manifest.$field) (
        "evidence manifest field '$field' is not a JSON string"
    )
}
Assert-EvidenceCondition (Test-StrictJsonArray $manifest.categories) (
    'evidence manifest categories is not a JSON array'
)
Assert-EvidenceCondition (
    [string]$manifest.tag -ceq $Tag -and
    [string]$manifest.tag_object -ceq $TagObject -and
    [string]$manifest.commit -ceq $Commit
) 'evidence manifest is bound to another release identity'
Assert-EvidenceCondition (
    [string]$manifest.release_manifest_sha256 -ceq $releaseManifestHash
) 'evidence manifest does not bind the release SHA256SUMS'
Assert-EvidenceCondition (
    $null -ne $manifest.evidence_owner
) 'evidence manifest has no evidence owner'
Assert-SafeEvidenceString $manifest.evidence_owner 'evidence manifest evidence_owner' 128
Assert-EvidenceCondition (
    [string]$record.acceptance_owner -cne [string]$manifest.evidence_owner
) 'acceptance owner and evidence owner must be independent identities'
$manifestCompleted = Get-CanonicalTimestamp `
    -Value ([string]$manifest.completed_utc) `
    -Label 'evidence manifest completed_utc'
Assert-EvidenceCondition ($manifestCompleted -le $recordCompleted) (
    'evidence manifest was completed after the acceptance record'
)

$requiredCategories = @(
    'clean_install_smoke',
    'native_transfer_real_host',
    'openssh_dropbear_interop',
    'whole_bundle_upgrade_rollback',
    'windows_privileged_acl'
) | Sort-Object
$categoryFields = @('artifact_sha256', 'artifact_url', 'category', 'status')
$seenCategories = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::Ordinal
)
$seenEvidenceUrls = [System.Collections.Generic.HashSet[string]]::new(
    [System.StringComparer]::OrdinalIgnoreCase
)
[void]$seenEvidenceUrls.Add($recordUri.AbsoluteUri)
[void]$seenEvidenceUrls.Add($evidenceUri.AbsoluteUri)
$actualCategories = [System.Collections.Generic.List[string]]::new()
foreach ($category in @($manifest.categories)) {
    Assert-EvidenceCondition (Test-StrictJsonObject $category) (
        'evidence category is not a JSON object'
    )
    $actualFields = @($category.PSObject.Properties.Name | Sort-Object)
    Assert-EvidenceCondition (
        ($actualFields -join "`n") -ceq (($categoryFields | Sort-Object) -join "`n")
    ) 'evidence category does not use the exact closed schema'
    foreach ($field in $categoryFields) {
        Assert-EvidenceCondition (Test-StrictJsonString $category.$field) (
            "evidence category field '$field' is not a JSON string"
        )
    }
    $name = [string]$category.category
    # Reject an untrusted category before it can reach an error message, URL
    # label, or evidence-artifact path. Only fixed allowlist values are safe to
    # use as filenames in the later artifact phase.
    Assert-EvidenceCondition ($requiredCategories -ccontains $name) (
        'evidence category name is not in the exact required allowlist'
    )
    Assert-EvidenceCondition ($seenCategories.Add($name)) (
        "evidence category '$name' is duplicated"
    )
    Assert-EvidenceCondition ([string]$category.status -ceq 'passed') (
        "evidence category '$name' did not pass"
    )
    $artifactUri = Get-CheckedHttpsUri `
        -Value ([string]$category.artifact_url) `
        -Label "evidence artifact URL for '$name'"
    Assert-EvidenceCondition ($seenEvidenceUrls.Add($artifactUri.AbsoluteUri)) (
        "evidence artifact URL for '$name' duplicates another evidence URL"
    )
    Assert-EvidenceCondition (
        [string]$category.artifact_sha256 -cmatch '^[0-9A-F]{64}$'
    ) "evidence artifact SHA-256 for '$name' is not canonical uppercase hex"
    if ($null -ne $evidenceArtifactRoot) {
        $artifactPath = Join-Path $evidenceArtifactRoot.FullName "$name.evidence"
        $artifact = Get-Item -LiteralPath $artifactPath -Force -ErrorAction Stop
        Assert-EvidenceCondition (-not $artifact.PSIsContainer) (
            "evidence artifact for '$name' is not a regular file"
        )
        Assert-EvidenceCondition (
            ($artifact.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0
        ) "evidence artifact for '$name' is a reparse point"
        Assert-EvidenceCondition (
            $artifact.Length -gt 0 -and $artifact.Length -le 8388608
        ) "evidence artifact for '$name' is outside 1..8388608 bytes"
        Assert-EvidenceCondition (
            (Get-FileHash -LiteralPath $artifact.FullName -Algorithm SHA256).Hash -ceq
                [string]$category.artifact_sha256
        ) "evidence artifact SHA-256 mismatch for '$name'"
        $document = Get-ClosedJsonObject `
            -Path $artifact.FullName `
            -Fields @(
                'schema_version', 'category', 'status', 'tag', 'tag_object', 'commit',
                'release_manifest_sha256', 'evidence_owner', 'timestamps', 'test_counts',
                'limitations', 'details'
            ) `
            -MaximumBytes 8388608 `
            -Label "evidence artifact '$name'" `
            -ExpectedSha256 ([string]$category.artifact_sha256)
        Assert-ExternalEvidenceDocument `
            -Document $document `
            -ExpectedCategory $name `
            -ManifestCompleted $manifestCompleted `
            -ManifestOwner ([string]$manifest.evidence_owner) `
            -ReleaseManifestHash $releaseManifestHash `
            -ExpectedReleaseComponents $expectedReleaseComponents
    }
    $actualCategories.Add($name)
}
Assert-EvidenceCondition (
    (($actualCategories.ToArray() | Sort-Object) -join "`n") -ceq
        ($requiredCategories -join "`n")
) 'evidence categories differ from the exact required set'

$verificationLevel = if ($null -eq $evidenceArtifactRoot) {
    'manifest'
}
else {
    'manifest-and-artifacts'
}
if ($EmitArtifactDownloadPlan) {
    Assert-EvidenceCondition ($null -eq $evidenceArtifactRoot) (
        'artifact download plan cannot be emitted after artifact verification'
    )
    $artifacts = @(
        $manifest.categories |
            Sort-Object category |
            ForEach-Object {
                [ordered]@{
                    category = [string]$_.category
                    artifact_url = [string]$_.artifact_url
                    artifact_sha256 = [string]$_.artifact_sha256
                }
            }
    )
    [ordered]@{
        schema_version = 1
        artifacts = $artifacts
    } | ConvertTo-Json -Depth 4 -Compress | Write-Output
}
else {
    Write-Host (
        "External acceptance evidence verified: level=$verificationLevel tag=$Tag " +
        "commit=$Commit tag_object=$TagObject categories=$($requiredCategories.Count)"
    )
}
