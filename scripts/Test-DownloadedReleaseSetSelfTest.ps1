[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'ReleaseAssetContract.ps1')

function Assert-DownloadedSetSelfTest {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )

    if (-not $Condition) {
        throw "downloaded release set self-test failed: $Message"
    }
}

function Write-Utf8Fixture {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Content
    )

    [System.IO.File]::WriteAllText(
        $Path,
        $Content,
        [System.Text.UTF8Encoding]::new($false)
    )
}

function Get-FixtureTextHash {
    param([Parameter(Mandatory = $true)][string]$Content)

    $bytes = [Text.UTF8Encoding]::new($false).GetBytes($Content)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function New-ZipFixture {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][object[]]$Entries
    )

    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $file = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite)
    $archive = [IO.Compression.ZipArchive]::new($file, [IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($definition in $Entries) {
            $entry = $archive.CreateEntry([string]$definition.Name)
            if ($definition.ContainsKey('ExternalAttributes')) {
                $entry.ExternalAttributes = [int]$definition.ExternalAttributes
            }
            $stream = $entry.Open()
            try {
                $bytes = [Text.UTF8Encoding]::new($false).GetBytes([string]$definition.Content)
                $stream.Write($bytes, 0, $bytes.Length)
            }
            finally { $stream.Dispose() }
        }
    }
    finally { $archive.Dispose(); $file.Dispose() }
}

function Set-TarField {
    param([byte[]]$Header, [int]$Offset, [int]$Length, [string]$Text)
    $bytes = [Text.Encoding]::ASCII.GetBytes($Text)
    Assert-DownloadedSetSelfTest ($bytes.Length -le $Length) 'tar fixture field overflow'
    [Array]::Copy($bytes, 0, $Header, $Offset, $bytes.Length)
}

function New-TarGzFixture {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][object[]]$Entries
    )

    $file = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write)
    $gzip = [IO.Compression.GZipStream]::new($file, [IO.Compression.CompressionMode]::Compress)
    try {
        foreach ($definition in $Entries) {
            $content = [Text.UTF8Encoding]::new($false).GetBytes([string]$definition.Content)
            $header = [byte[]]::new(512)
            Set-TarField $header 0 100 ([string]$definition.Name)
            $mode = if ($definition.ContainsKey('Mode')) {
                [string]$definition.Mode
            } else { '0000644' }
            Set-TarField $header 100 8 ($mode + "`0")
            Set-TarField $header 108 8 "0000000`0"
            Set-TarField $header 116 8 "0000000`0"
            Set-TarField $header 124 12 (([Convert]::ToString($content.Length, 8).PadLeft(11, '0')) + "`0")
            Set-TarField $header 136 12 "00000000000`0"
            for ($index = 148; $index -lt 156; $index++) { $header[$index] = 32 }
            $type = if ($definition.ContainsKey('Type')) { [string]$definition.Type } else { '0' }
            $header[156] = [byte][char]$type
            if ($definition.ContainsKey('LinkName')) {
                Set-TarField $header 157 100 ([string]$definition.LinkName)
            }
            Set-TarField $header 257 6 "ustar`0"
            Set-TarField $header 263 2 '00'
            $checksum = [long]0
            foreach ($byte in $header) { $checksum += $byte }
            Set-TarField $header 148 8 (([Convert]::ToString($checksum, 8).PadLeft(6, '0')) + "`0 ")
            $gzip.Write($header, 0, 512)
            if ($content.Length -gt 0) { $gzip.Write($content, 0, $content.Length) }
            $padding = (512 - ($content.Length % 512)) % 512
            if ($padding -gt 0) { $gzip.Write([byte[]]::new($padding), 0, $padding) }
        }
        $gzip.Write([byte[]]::new(1024), 0, 1024)
    }
    finally { $gzip.Dispose(); $file.Dispose() }
}

function New-ValidReleaseFixture {
    param([Parameter(Mandatory = $true)][string]$Root)

    [System.IO.Directory]::CreateDirectory($Root) | Out-Null
    $inputNames = @(Get-V1BetaReleaseInputNames -Version $script:version)
    foreach ($name in $inputNames) {
        if ($name -cmatch '\.(?:zip|tar\.gz)$') { continue }
        Write-Utf8Fixture -Path (Join-Path $Root $name) -Content "fixture:$name`n"
    }
    $linuxBinaryContent = "archive:serctl-xfer`n"
    $linuxSymbolContent = "archive:serctl-xfer.debug`n"
    $windowsCliContent = "archive:serctl_cli.exe`n"
    $windowsDaemonContent = "archive:serctl_daemon.exe`n"
    $windowsCliSymbolContent = "archive:serctl_cli.pdb`n"
    $windowsDaemonSymbolContent = "archive:serctl_daemon.pdb`n"
    $platformCommon = [ordered]@{
        schema_version = 2
        version = $script:version
        tag = $script:tag
        tag_object = $script:tagObject
        commit = $script:commit
        repository = $script:repository
        workflow = 'V1 beta release fixture'
        workflow_ref = "$($script:repository)/.github/workflows/release-v1-beta.yml@refs/tags/$($script:tag)"
        run_id = '123456'
        run_attempt = '1'
        ref = "refs/tags/$($script:tag)"
        source_date_epoch = '1700000000'
        runner_os = 'fixture'
        runner_arch = 'X64'
        runner_image = 'fixture'
        rustc = 'rustc fixture'
        cargo = 'cargo fixture'
        cargo_lock_sha256 = ('1' * 64)
        rust_toolchain_sha256 = ('2' * 64)
        release_debug = '1'
        release_strip = 'none'
        cargo_target_dir = 'target/v1-beta-release'
        binary_components = @()
        symbol_sha256 = [ordered]@{}
    }
    $linuxProvenance = [ordered]@{}
    foreach ($entry in $platformCommon.GetEnumerator()) {
        $linuxProvenance[$entry.Key] = $entry.Value
    }
    $linuxProvenance.platform = 'linux-x86_64'
    $linuxProvenance.binary_components = @(
        [pscustomobject][ordered]@{
            name = 'serctl-xfer'
            binary_size = [Text.UTF8Encoding]::new($false).GetByteCount($linuxBinaryContent)
            sha256 = Get-FixtureTextHash $linuxBinaryContent
            version = "serctl-xfer $($script:version) (git $($script:commit.Substring(0, 12)); transfer protocol v1)"
        }
    )
    $linuxProvenance.symbol_sha256 = [ordered]@{
        'serctl-xfer.debug' = Get-FixtureTextHash $linuxSymbolContent
    }
    $linuxProvenance.runtime_abi = [ordered]@{
        family = 'glibc'
        maximum_supported = '2.35'
        maximum_required = '2.34'
        verifier = 'readelf --version-info --wide'
    }
    Write-Utf8Fixture `
        -Path (Join-Path $Root "serctl-$($script:version)-linux-x86_64.provenance.json") `
        -Content (($linuxProvenance | ConvertTo-Json -Depth 10) + "`n")
    $windowsProvenance = [ordered]@{}
    foreach ($entry in $platformCommon.GetEnumerator()) {
        $windowsProvenance[$entry.Key] = $entry.Value
    }
    $windowsProvenance.platform = 'windows-x86_64'
    $windowsProvenance.binary_components = @(
        [pscustomobject][ordered]@{
            name = 'serctl_cli.exe'
            binary_size = [Text.UTF8Encoding]::new($false).GetByteCount($windowsCliContent)
            sha256 = Get-FixtureTextHash $windowsCliContent
            version = "serctl_cli $($script:version) (git $($script:commit.Substring(0, 12)); vault-storage read=v4..=v5 write=v5)"
        },
        [pscustomobject][ordered]@{
            name = 'serctl_daemon.exe'
            binary_size = [Text.UTF8Encoding]::new($false).GetByteCount($windowsDaemonContent)
            sha256 = Get-FixtureTextHash $windowsDaemonContent
            version = "serctl_daemon $($script:version) (git $($script:commit.Substring(0, 12)); IPC v9..=v9; vault-storage read=v4..=v5 write=v5)"
        }
    )
    $windowsProvenance.symbol_sha256 = [ordered]@{
        'serctl_cli.pdb' = Get-FixtureTextHash $windowsCliSymbolContent
        'serctl_daemon.pdb' = Get-FixtureTextHash $windowsDaemonSymbolContent
    }
    $windowsProvenance.runtime_abi = [ordered]@{
        family = 'windows-msvc'
        architecture = 'x86_64'
    }
    Write-Utf8Fixture `
        -Path (Join-Path $Root "serctl-$($script:version)-windows-x86_64.provenance.json") `
        -Content (($windowsProvenance | ConvertTo-Json -Depth 10) + "`n")

    $governanceNames = @(
        'LICENSE', 'SECURITY.md', 'v1-beta-agent-jsonl.md',
        'v1-beta-release-contract.md', 'v1-beta-acceptance-matrix.md'
    )
    $windowsRuntimeEntries = @(
        @{ Name = 'serctl_cli.exe'; Content = $windowsCliContent },
        @{ Name = 'serctl_daemon.exe'; Content = $windowsDaemonContent },
        @{
            Name = "serctl-$($script:version)-windows-x86_64.provenance.json"
            Content = [IO.File]::ReadAllText((Join-Path $Root "serctl-$($script:version)-windows-x86_64.provenance.json"))
        }
    )
    $linuxRuntimeEntries = @(
        @{ Name = './serctl-xfer'; Content = $linuxBinaryContent; Mode = '0000755' },
        @{
            Name = "./serctl-$($script:version)-linux-x86_64.provenance.json"
            Content = [IO.File]::ReadAllText((Join-Path $Root "serctl-$($script:version)-linux-x86_64.provenance.json"))
        }
    )
    foreach ($name in $governanceNames) {
        $windowsRuntimeEntries += @{ Name = $name; Content = "governance:$name`n" }
        $linuxRuntimeEntries += @{ Name = "./$name"; Content = "governance:$name`n" }
    }
    $windowsRuntimePath = Join-Path $Root "serctl-$($script:version)-windows-x86_64.zip"
    $windowsSymbolsPath = Join-Path $Root "serctl-$($script:version)-windows-x86_64-symbols.zip"
    $linuxRuntimePath = Join-Path $Root "serctl-$($script:version)-linux-x86_64-xfer.tar.gz"
    $linuxSymbolsPath = Join-Path $Root "serctl-$($script:version)-linux-x86_64-xfer-symbols.tar.gz"
    New-ZipFixture $windowsRuntimePath $windowsRuntimeEntries
    New-ZipFixture $windowsSymbolsPath @(
        @{ Name = 'serctl_cli.pdb'; Content = $windowsCliSymbolContent },
        @{ Name = 'serctl_daemon.pdb'; Content = $windowsDaemonSymbolContent }
    )
    New-TarGzFixture $linuxRuntimePath $linuxRuntimeEntries
    New-TarGzFixture $linuxSymbolsPath @(
        @{ Name = './serctl-xfer.debug'; Content = $linuxSymbolContent }
    )
    $fuzzReceipt = [ordered]@{
        schema_version = 1
        tag = $script:tag
        tag_object = $script:tagObject
        commit = $script:commit
        repository = $script:repository
        workflow_ref = "$($script:repository)/.github/workflows/parser-fuzz.yml@refs/tags/$($script:tag)"
        run_id = '123456'
        run_attempt = '1'
        toolchain = [ordered]@{ nightly = 'nightly-2026-08-03'; cargo_fuzz = '0.13.2' }
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
        source_digests = [ordered]@{
            parser_fuzz_workflow = ('3' * 64)
            fuzz_lock = ('4' * 64)
            transfer_protocol_target = ('5' * 64)
            remote_protocol_target = ('6' * 64)
            policy_json_target = ('7' * 64)
        }
        test_counts = [ordered]@{ passed = 3; failed = 0; skipped = 0; unknown = 0 }
    }
    $fuzzReceiptText = ($fuzzReceipt | ConvertTo-Json -Depth 10).Replace("`r`n", "`n") + "`n"
    $fuzzReceiptBytes = [Text.UTF8Encoding]::new($false).GetBytes($fuzzReceiptText)
    $provenance = [ordered]@{
        schema_version = 1
        version = $script:version
        tag = $script:tag
        tag_object = $script:tagObject
        commit = $script:commit
        repository = $script:repository
        workflow = 'V1 beta release'
        workflow_ref = "$($script:repository)/.github/workflows/release-v1-beta.yml@refs/tags/$($script:tag)"
        run_id = '123456'
        run_attempt = '1'
        event = 'push'
        ref = "refs/tags/$($script:tag)"
        source_date_epoch = '1700000000'
        runner_os = 'Linux'
        runner_arch = 'X64'
        runner_image = 'ubuntu24-fixture'
        rustc = 'rustc fixture'
        cargo = 'cargo fixture'
        cargo_lock_sha256 = ('1' * 64)
        rust_toolchain_sha256 = ('2' * 64)
        release_files = $inputNames
        parser_fuzz = [ordered]@{
            artifact_id = '987654'
            artifact_digest = ('8' * 64)
            receipt_sha256 = Get-FixtureTextHash $fuzzReceiptText
            receipt_base64 = [Convert]::ToBase64String($fuzzReceiptBytes)
        }
    }
    Write-Utf8Fixture `
        -Path (Join-Path $Root 'release-provenance.json') `
        -Content (($provenance | ConvertTo-Json -Depth 10) + "`n")

    $checksumLines = foreach ($name in Get-V1BetaHashedReleaseNames -Version $script:version) {
        $hash = (Get-FileHash -LiteralPath (Join-Path $Root $name) -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $name"
    }
    Write-Utf8Fixture `
        -Path (Join-Path $Root 'SHA256SUMS') `
        -Content (($checksumLines -join "`n") + "`n")
}

function Copy-ReleaseFixture {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    [System.IO.Directory]::CreateDirectory($Destination) | Out-Null
    foreach ($file in Get-ChildItem -LiteralPath $Source -File) {
        [System.IO.File]::Copy(
            $file.FullName,
            (Join-Path $Destination $file.Name),
            $false
        )
    }
}

function Get-WindowsRuntimeFixtureEntries {
    param([string]$Root)
    $entries = @(
        @{ Name = 'serctl_cli.exe'; Content = "archive:serctl_cli.exe`n" },
        @{ Name = 'serctl_daemon.exe'; Content = "archive:serctl_daemon.exe`n" },
        @{
            Name = "serctl-$($script:version)-windows-x86_64.provenance.json"
            Content = [IO.File]::ReadAllText((Join-Path $Root "serctl-$($script:version)-windows-x86_64.provenance.json"))
        }
    )
    foreach ($name in @('LICENSE', 'SECURITY.md', 'v1-beta-agent-jsonl.md', 'v1-beta-release-contract.md', 'v1-beta-acceptance-matrix.md')) {
        $entries += @{ Name = $name; Content = "governance:$name`n" }
    }
    return $entries
}

function Get-LinuxRuntimeFixtureEntries {
    param([string]$Root)
    $entries = @(
        @{ Name = './serctl-xfer'; Content = "archive:serctl-xfer`n"; Mode = '0000755' },
        @{
            Name = "./serctl-$($script:version)-linux-x86_64.provenance.json"
            Content = [IO.File]::ReadAllText((Join-Path $Root "serctl-$($script:version)-linux-x86_64.provenance.json"))
        }
    )
    foreach ($name in @('LICENSE', 'SECURITY.md', 'v1-beta-agent-jsonl.md', 'v1-beta-release-contract.md', 'v1-beta-acceptance-matrix.md')) {
        $entries += @{ Name = "./$name"; Content = "governance:$name`n" }
    }
    return $entries
}

function Replace-ZipFixture {
    param([string]$Root, [string]$Name, [object[]]$Entries)
    $path = Join-Path $Root $Name
    [IO.File]::Delete($path)
    New-ZipFixture $path $Entries
    Update-ChecksumForFile -Root $Root -Name $Name
}

function Replace-TarGzFixture {
    param([string]$Root, [string]$Name, [object[]]$Entries)
    $path = Join-Path $Root $Name
    [IO.File]::Delete($path)
    New-TarGzFixture $path $Entries
    Update-ChecksumForFile -Root $Root -Name $Name
}

function Set-PlatformBinaryVersionFixture {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][ValidateSet('windows-x86_64', 'linux-x86_64')]
        [string]$Platform,
        [Parameter(Mandatory = $true)][string]$BinaryName,
        [Parameter(Mandatory = $true)][string]$Identity
    )

    $provenanceName = "serctl-$($script:version)-$Platform.provenance.json"
    $provenancePath = Join-Path $Root $provenanceName
    $provenance = [System.IO.File]::ReadAllText($provenancePath) | ConvertFrom-Json
    $component = @($provenance.binary_components | Where-Object {
        [string]$_.name -ceq $BinaryName
    })
    Assert-DownloadedSetSelfTest ($component.Count -eq 1) (
        "fixture provenance has no binary version '$BinaryName'"
    )
    $component[0].version = $Identity
    Write-Utf8Fixture `
        -Path $provenancePath `
        -Content (($provenance | ConvertTo-Json -Depth 10) + "`n")
    Update-ChecksumForFile -Root $Root -Name $provenanceName

    if ($Platform -ceq 'windows-x86_64') {
        Replace-ZipFixture `
            -Root $Root `
            -Name "serctl-$($script:version)-windows-x86_64.zip" `
            -Entries @(Get-WindowsRuntimeFixtureEntries $Root)
    }
    else {
        Replace-TarGzFixture `
            -Root $Root `
            -Name "serctl-$($script:version)-linux-x86_64-xfer.tar.gz" `
            -Entries @(Get-LinuxRuntimeFixtureEntries $Root)
    }
}

function Invoke-DownloadedSetVerifier {
    param([Parameter(Mandatory = $true)][string]$Root)

    $arguments = @(
        '-NoProfile',
        '-File',
        $script:verifier,
        '-Directory',
        $Root,
        '-Version',
        $script:version,
        '-Commit',
        $script:commit,
        '-Tag',
        $script:tag,
        '-TagObject',
        $script:tagObject,
        '-Repository',
        $script:repository
    )
    $savedErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $script:lastVerifierOutput = @(& $script:powershell @arguments 2>&1)
        $childExit = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $savedErrorActionPreference
    }
    return $childExit
}

function Update-ChecksumForFile {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $hash = (Get-FileHash -LiteralPath (Join-Path $Root $Name) -Algorithm SHA256).Hash.ToLowerInvariant()
    $checksumPath = Join-Path $Root 'SHA256SUMS'
    $lines = @([System.IO.File]::ReadAllLines($checksumPath))
    for ($index = 0; $index -lt $lines.Count; $index++) {
        if ($lines[$index].EndsWith("  $Name", [System.StringComparison]::Ordinal)) {
            $lines[$index] = "$hash  $Name"
        }
    }
    Write-Utf8Fixture -Path $checksumPath -Content (($lines -join "`n") + "`n")
}

$version = '1.0.0-beta'
$tag = "v$version"
$commit = '0123456789abcdef0123456789abcdef01234567'
$tagObject = 'fedcba9876543210fedcba9876543210fedcba98'
$repository = 'example/serctl'
$verifier = Join-Path $PSScriptRoot 'Test-DownloadedReleaseSet.ps1'
$powershell = (Get-Process -Id $PID).Path
$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'serctl-downloaded-release-selftest-' + [System.Guid]::NewGuid().ToString('N')
)
[System.IO.Directory]::CreateDirectory($temporaryRoot) | Out-Null
$junctionPath = $null
try {
    $baseline = Join-Path $temporaryRoot 'baseline'
    New-ValidReleaseFixture -Root $baseline
    Assert-DownloadedSetSelfTest (
        (Invoke-DownloadedSetVerifier -Root $baseline) -eq 0
    ) ('valid 14-file release set was rejected: ' + ($script:lastVerifierOutput -join ' | '))

    $caseIndex = 0
    $negativeCases = @(
        @{
            Name = 'ZIP path traversal member'
            Mutate = {
                param($root)
                $entries = @(Get-WindowsRuntimeFixtureEntries $root)
                $entries += @{ Name = '../escape'; Content = 'escape' }
                Replace-ZipFixture $root "serctl-$version-windows-x86_64.zip" $entries
            }
        },
        @{
            Name = 'ZIP nested member'
            Mutate = {
                param($root)
                $entries = @(Get-WindowsRuntimeFixtureEntries $root)
                $entries += @{ Name = 'nested/extra'; Content = 'nested' }
                Replace-ZipFixture $root "serctl-$version-windows-x86_64.zip" $entries
            }
        },
        @{
            Name = 'ZIP duplicate member'
            Mutate = {
                param($root)
                $entries = @(Get-WindowsRuntimeFixtureEntries $root)
                $entries += @{ Name = 'serctl_cli.exe'; Content = 'duplicate' }
                Replace-ZipFixture $root "serctl-$version-windows-x86_64.zip" $entries
            }
        },
        @{
            Name = 'ZIP case-colliding member'
            Mutate = {
                param($root)
                $entries = @(Get-WindowsRuntimeFixtureEntries $root)
                $entries += @{ Name = 'SERCTL_CLI.EXE'; Content = 'collision' }
                Replace-ZipFixture $root "serctl-$version-windows-x86_64.zip" $entries
            }
        },
        @{
            Name = 'ZIP symbolic link member'
            Mutate = {
                param($root)
                $entries = @(Get-WindowsRuntimeFixtureEntries $root)
                $attributes = [BitConverter]::ToInt32(
                    [BitConverter]::GetBytes([uint32]2717843456), 0
                )
                $entries += @{
                    Name = 'linked-runtime'
                    Content = 'serctl_cli.exe'
                    ExternalAttributes = $attributes
                }
                Replace-ZipFixture $root "serctl-$version-windows-x86_64.zip" $entries
            }
        },
        @{
            Name = 'ZIP raw trailing bytes after EOCD'
            Mutate = {
                param($root)
                $name = "serctl-$version-windows-x86_64.zip"
                $path = Join-Path $root $name
                $stream = [IO.File]::Open($path, [IO.FileMode]::Append, [IO.FileAccess]::Write)
                try {
                    $bytes = [Text.Encoding]::ASCII.GetBytes('SMUGGLE')
                    $stream.Write($bytes, 0, $bytes.Length)
                }
                finally { $stream.Dispose() }
                Update-ChecksumForFile -Root $root -Name $name
            }
        },
        @{
            Name = 'ZIP DOS directory attribute'
            Mutate = {
                param($root)
                $entries = @(Get-WindowsRuntimeFixtureEntries $root)
                $entries[0].ExternalAttributes = 0x10
                Replace-ZipFixture $root "serctl-$version-windows-x86_64.zip" $entries
            }
        },
        @{
            Name = 'ZIP DOS reparse attribute'
            Mutate = {
                param($root)
                $entries = @(Get-WindowsRuntimeFixtureEntries $root)
                $entries[0].ExternalAttributes = 0x400
                Replace-ZipFixture $root "serctl-$version-windows-x86_64.zip" $entries
            }
        },
        @{
            Name = 'source-only archive member'
            Mutate = {
                param($root)
                $entries = @(Get-WindowsRuntimeFixtureEntries $root)
                $entries += @{ Name = 'serctl-remote'; Content = 'source-only' }
                Replace-ZipFixture $root "serctl-$version-windows-x86_64.zip" $entries
            }
        },
        @{
            Name = 'tar hard link member'
            Mutate = {
                param($root)
                $entries = @(Get-LinuxRuntimeFixtureEntries $root)
                $entries += @{ Name = './hard-link'; Type = '1'; LinkName = './serctl-xfer'; Content = '' }
                Replace-TarGzFixture $root "serctl-$version-linux-x86_64-xfer.tar.gz" $entries
            }
        },
        @{
            Name = 'tar symbolic link member'
            Mutate = {
                param($root)
                $entries = @(Get-LinuxRuntimeFixtureEntries $root)
                $entries += @{ Name = './symbolic-link'; Type = '2'; LinkName = './serctl-xfer'; Content = '' }
                Replace-TarGzFixture $root "serctl-$version-linux-x86_64-xfer.tar.gz" $entries
            }
        },
        @{
            Name = 'tar nested member'
            Mutate = {
                param($root)
                $entries = @(Get-LinuxRuntimeFixtureEntries $root)
                $entries += @{ Name = './nested/extra'; Content = 'nested' }
                Replace-TarGzFixture $root "serctl-$version-linux-x86_64-xfer.tar.gz" $entries
            }
        },
        @{
            Name = 'tar root directory header'
            Mutate = {
                param($root)
                $entries = @(@{ Name = './'; Type = '5'; Content = '' }) +
                    @(Get-LinuxRuntimeFixtureEntries $root)
                Replace-TarGzFixture $root "serctl-$version-linux-x86_64-xfer.tar.gz" $entries
            }
        },
        @{
            Name = 'tar runtime helper without execute mode'
            Mutate = {
                param($root)
                $entries = @(Get-LinuxRuntimeFixtureEntries $root)
                $entries[0].Mode = '0000644'
                Replace-TarGzFixture $root "serctl-$version-linux-x86_64-xfer.tar.gz" $entries
            }
        },
        @{
            Name = 'tar executable governance document'
            Mutate = {
                param($root)
                $entries = @(Get-LinuxRuntimeFixtureEntries $root)
                $document = @($entries | Where-Object { $_.Name -ceq './SECURITY.md' })[0]
                $document.Mode = '0000755'
                Replace-TarGzFixture $root "serctl-$version-linux-x86_64-xfer.tar.gz" $entries
            }
        },
        @{
            Name = 'tar.gz raw trailing bytes'
            Mutate = {
                param($root)
                $name = "serctl-$version-linux-x86_64-xfer.tar.gz"
                $path = Join-Path $root $name
                $stream = [IO.File]::Open($path, [IO.FileMode]::Append, [IO.FileAccess]::Write)
                try {
                    $bytes = [Text.Encoding]::ASCII.GetBytes('SMUGGLE')
                    $stream.Write($bytes, 0, $bytes.Length)
                }
                finally { $stream.Dispose() }
                Update-ChecksumForFile -Root $root -Name $name
            }
        },
        @{
            Name = 'tar.gz second gzip member'
            Mutate = {
                param($root)
                $name = "serctl-$version-linux-x86_64-xfer.tar.gz"
                $path = Join-Path $root $name
                $secondPath = Join-Path $root 'second-member.gz'
                $file = [IO.File]::Open(
                    $secondPath,
                    [IO.FileMode]::CreateNew,
                    [IO.FileAccess]::Write
                )
                $gzip = [IO.Compression.GZipStream]::new(
                    $file,
                    [IO.Compression.CompressionMode]::Compress
                )
                try {
                    $zeros = [byte[]]::new(4096)
                    $gzip.Write($zeros, 0, $zeros.Length)
                }
                finally { $gzip.Dispose(); $file.Dispose() }
                $member = [IO.File]::ReadAllBytes($secondPath)
                [IO.File]::Delete($secondPath)
                $stream = [IO.File]::Open($path, [IO.FileMode]::Append, [IO.FileAccess]::Write)
                try { $stream.Write($member, 0, $member.Length) }
                finally { $stream.Dispose() }
                Update-ChecksumForFile -Root $root -Name $name
            }
        },
        @{
            Name = 'archive binary digest differs from provenance'
            Mutate = {
                param($root)
                $entries = @(Get-WindowsRuntimeFixtureEntries $root)
                $entries[0].Content = 'changed-binary'
                Replace-ZipFixture $root "serctl-$version-windows-x86_64.zip" $entries
            }
        },
        @{
            Name = 'archive symbol digest differs from provenance'
            Mutate = {
                param($root)
                Replace-ZipFixture $root "serctl-$version-windows-x86_64-symbols.zip" @(
                    @{ Name = 'serctl_cli.pdb'; Content = 'changed-symbol' },
                    @{ Name = 'serctl_daemon.pdb'; Content = "archive:serctl_daemon.pdb`n" }
                )
            }
        },
        @{
            Name = 'embedded provenance differs from released provenance'
            Mutate = {
                param($root)
                $entries = @(Get-WindowsRuntimeFixtureEntries $root)
                $entries[2].Content = '{"different":true}'
                Replace-ZipFixture $root "serctl-$version-windows-x86_64.zip" $entries
            }
        },
        @{
            Name = 'extra file'
            Mutate = {
                param($root)
                Write-Utf8Fixture -Path (Join-Path $root 'extra.bin') -Content 'extra'
            }
        },
        @{
            Name = 'missing file'
            Mutate = {
                param($root)
                [System.IO.File]::Delete((Join-Path $root "serctl-$version-windows-x86_64.zip"))
            }
        },
        @{
            Name = 'empty file'
            Mutate = {
                param($root)
                [System.IO.File]::WriteAllBytes(
                    (Join-Path $root "serctl-$version-windows-x86_64.zip"),
                    [byte[]]@()
                )
            }
        },
        @{
            Name = 'oversized ordinary asset before hashing'
            Mutate = {
                param($root)
                $path = Join-Path $root "serctl-$version-windows-x86_64.zip"
                $stream = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Write)
                try { $stream.SetLength(536870913) }
                finally { $stream.Dispose() }
            }
        },
        @{
            Name = 'oversized SBOM before parsing'
            Mutate = {
                param($root)
                $path = Join-Path $root "serctl-$version-serctl-cli.sbom.cdx.json"
                $stream = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Write)
                try { $stream.SetLength(67108865) }
                finally { $stream.Dispose() }
            }
        },
        @{
            Name = 'oversized aggregate release set before hashing'
            Mutate = {
                param($root)
                foreach ($name in @(
                    "serctl-$version-windows-x86_64.zip",
                    "serctl-$version-windows-x86_64-symbols.zip"
                )) {
                    $stream = [IO.File]::Open(
                        (Join-Path $root $name),
                        [IO.FileMode]::Open,
                        [IO.FileAccess]::Write
                    )
                    try { $stream.SetLength(536870912) }
                    finally { $stream.Dispose() }
                }
            }
        },
        @{
            Name = 'asset hash mismatch'
            Mutate = {
                param($root)
                [System.IO.File]::AppendAllText(
                    (Join-Path $root "serctl-$version-linux-x86_64-xfer.tar.gz"),
                    'tampered'
                )
            }
        },
        @{
            Name = 'checksum self entry'
            Mutate = {
                param($root)
                $path = Join-Path $root 'SHA256SUMS'
                [System.IO.File]::AppendAllText($path, (('0' * 64) + "  SHA256SUMS`n"))
            }
        },
        @{
            Name = 'checksum duplicate entry'
            Mutate = {
                param($root)
                $path = Join-Path $root 'SHA256SUMS'
                $lines = @([System.IO.File]::ReadAllLines($path))
                $lines[1] = $lines[0]
                Write-Utf8Fixture -Path $path -Content (($lines -join "`n") + "`n")
            }
        },
        @{
            Name = 'oversized SHA256SUMS before whole-file read'
            Mutate = {
                param($root)
                $path = Join-Path $root 'SHA256SUMS'
                $stream = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Write)
                try { $stream.SetLength(4097) }
                finally { $stream.Dispose() }
            }
        },
        @{
            Name = 'checksum path entry'
            Mutate = {
                param($root)
                $path = Join-Path $root 'SHA256SUMS'
                $lines = @([System.IO.File]::ReadAllLines($path))
                $firstName = $lines[0].Substring(66)
                $lines[0] = $lines[0].Substring(0, 66) + "nested/$firstName"
                Write-Utf8Fixture -Path $path -Content (($lines -join "`n") + "`n")
            }
        },
        @{
            Name = 'provenance identity drift'
            Mutate = {
                param($root)
                $path = Join-Path $root 'release-provenance.json'
                $value = [System.IO.File]::ReadAllText($path) | ConvertFrom-Json
                $value.commit = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                Write-Utf8Fixture -Path $path -Content (($value | ConvertTo-Json -Depth 10) + "`n")
                Update-ChecksumForFile -Root $root -Name 'release-provenance.json'
            }
        },
        @{
            Name = 'embedded parser fuzz receipt digest drift'
            Mutate = {
                param($root)
                $path = Join-Path $root 'release-provenance.json'
                $value = [System.IO.File]::ReadAllText($path) | ConvertFrom-Json
                $value.parser_fuzz.receipt_sha256 = 'a' * 64
                Write-Utf8Fixture -Path $path -Content (($value | ConvertTo-Json -Depth 12) + "`n")
                Update-ChecksumForFile -Root $root -Name 'release-provenance.json'
            }
        },
        @{
            Name = 'embedded parser fuzz receipt commit drift with matching inner digest'
            Mutate = {
                param($root)
                $path = Join-Path $root 'release-provenance.json'
                $value = [System.IO.File]::ReadAllText($path) | ConvertFrom-Json
                $receiptBytes = [Convert]::FromBase64String(
                    [string]$value.parser_fuzz.receipt_base64
                )
                $receipt = [Text.UTF8Encoding]::new($false, $true).GetString($receiptBytes) |
                    ConvertFrom-Json
                $receipt.commit = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                $receiptText = ($receipt | ConvertTo-Json -Depth 12).Replace("`r`n", "`n") + "`n"
                $value.parser_fuzz.receipt_base64 = [Convert]::ToBase64String(
                    [Text.UTF8Encoding]::new($false).GetBytes($receiptText)
                )
                $value.parser_fuzz.receipt_sha256 = Get-FixtureTextHash $receiptText
                Write-Utf8Fixture -Path $path -Content (($value | ConvertTo-Json -Depth 12) + "`n")
                Update-ChecksumForFile -Root $root -Name 'release-provenance.json'
            }
        },
        @{
            Name = 'provenance string schema version'
            Mutate = {
                param($root)
                $path = Join-Path $root 'release-provenance.json'
                $value = [System.IO.File]::ReadAllText($path) | ConvertFrom-Json
                $value.schema_version = '1'
                Write-Utf8Fixture -Path $path -Content (($value | ConvertTo-Json -Depth 10) + "`n")
                Update-ChecksumForFile -Root $root -Name 'release-provenance.json'
            }
        },
        @{
            Name = 'provenance scalar release files'
            Mutate = {
                param($root)
                $path = Join-Path $root 'release-provenance.json'
                $value = [System.IO.File]::ReadAllText($path) | ConvertFrom-Json
                $value.release_files = [string]$value.release_files[0]
                Write-Utf8Fixture -Path $path -Content (($value | ConvertTo-Json -Depth 10) + "`n")
                Update-ChecksumForFile -Root $root -Name 'release-provenance.json'
            }
        },
        @{
            Name = 'provenance invalid UTF-8'
            Mutate = {
                param($root)
                $path = Join-Path $root 'release-provenance.json'
                [System.IO.File]::WriteAllBytes(
                    $path,
                    [byte[]](0x7B, 0x22, 0x78, 0x22, 0x3A, 0x22, 0xC3, 0x28, 0x22, 0x7D)
                )
                Update-ChecksumForFile -Root $root -Name 'release-provenance.json'
            }
        },
        @{
            Name = 'provenance duplicate file'
            Mutate = {
                param($root)
                $path = Join-Path $root 'release-provenance.json'
                $value = [System.IO.File]::ReadAllText($path) | ConvertFrom-Json
                $value.release_files[1] = $value.release_files[0]
                Write-Utf8Fixture -Path $path -Content (($value | ConvertTo-Json -Depth 10) + "`n")
                Update-ChecksumForFile -Root $root -Name 'release-provenance.json'
            }
        },
        @{
            Name = 'provenance duplicate JSON key'
            Mutate = {
                param($root)
                $path = Join-Path $root 'release-provenance.json'
                $json = [System.IO.File]::ReadAllText($path).TrimEnd()
                $closingBrace = $json.LastIndexOf('}')
                $json = $json.Insert(
                    $closingBrace,
                    ',"commit":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"'
                )
                Write-Utf8Fixture -Path $path -Content ($json + "`n")
                Update-ChecksumForFile -Root $root -Name 'release-provenance.json'
            }
        },
        @{
            Name = 'oversized provenance JSON'
            Mutate = {
                param($root)
                $path = Join-Path $root 'release-provenance.json'
                $stream = [System.IO.File]::OpenWrite($path)
                try {
                    $stream.SetLength(262145)
                }
                finally {
                    $stream.Dispose()
                }
                Update-ChecksumForFile -Root $root -Name 'release-provenance.json'
            }
        },
        @{
            Name = 'platform tag object drift'
            Mutate = {
                param($root)
                $name = "serctl-$version-linux-x86_64.provenance.json"
                $path = Join-Path $root $name
                $value = [System.IO.File]::ReadAllText($path) | ConvertFrom-Json
                $value.tag_object = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                Write-Utf8Fixture -Path $path -Content (($value | ConvertTo-Json -Depth 10) + "`n")
                Update-ChecksumForFile -Root $root -Name $name
            }
        },
        @{
            Name = 'platform provenance unknown field'
            Mutate = {
                param($root)
                $name = "serctl-$version-linux-x86_64.provenance.json"
                $path = Join-Path $root $name
                $value = [System.IO.File]::ReadAllText($path) | ConvertFrom-Json
                $value | Add-Member -NotePropertyName unexpected_identity -NotePropertyValue 'drift'
                Write-Utf8Fixture -Path $path -Content (($value | ConvertTo-Json -Depth 10) + "`n")
                Update-ChecksumForFile -Root $root -Name $name
            }
        },
        @{
            Name = 'platform binary map unknown key'
            Mutate = {
                param($root)
                $name = "serctl-$version-linux-x86_64.provenance.json"
                $path = Join-Path $root $name
                $value = [System.IO.File]::ReadAllText($path) | ConvertFrom-Json
                $value.binary_components += [pscustomobject]@{
                    name = 'unexpected-helper'
                    binary_size = 1
                    sha256 = ('3' * 64)
                    version = "unexpected $version (git $($commit.Substring(0, 12)))"
                }
                Write-Utf8Fixture -Path $path -Content (($value | ConvertTo-Json -Depth 10) + "`n")
                Update-ChecksumForFile -Root $root -Name $name
            }
        },
        @{
            Name = 'platform binary map missing key'
            Mutate = {
                param($root)
                $name = "serctl-$version-windows-x86_64.provenance.json"
                $path = Join-Path $root $name
                $value = [System.IO.File]::ReadAllText($path) | ConvertFrom-Json
                $value.binary_components = @($value.binary_components | Where-Object {
                    [string]$_.name -cne 'serctl_daemon.exe'
                })
                Write-Utf8Fixture -Path $path -Content (($value | ConvertTo-Json -Depth 10) + "`n")
                Update-ChecksumForFile -Root $root -Name $name
            }
        },
        @{
            Name = 'platform binary size missing'
            Mutate = {
                param($root)
                $name = "serctl-$version-linux-x86_64.provenance.json"
                $path = Join-Path $root $name
                $value = [System.IO.File]::ReadAllText($path) | ConvertFrom-Json
                $value.binary_components[0].PSObject.Properties.Remove('binary_size')
                Write-Utf8Fixture -Path $path -Content (($value | ConvertTo-Json -Depth 10) + "`n")
                Update-ChecksumForFile -Root $root -Name $name
            }
        },
        @{
            Name = 'platform binary size negative'
            Mutate = {
                param($root)
                $name = "serctl-$version-linux-x86_64.provenance.json"
                $path = Join-Path $root $name
                $value = [System.IO.File]::ReadAllText($path) | ConvertFrom-Json
                $value.binary_components[0].binary_size = -1
                Write-Utf8Fixture -Path $path -Content (($value | ConvertTo-Json -Depth 10) + "`n")
                Update-ChecksumForFile -Root $root -Name $name
            }
        },
        @{
            Name = 'platform binary size type confusion'
            Mutate = {
                param($root)
                $name = "serctl-$version-linux-x86_64.provenance.json"
                $path = Join-Path $root $name
                $value = [System.IO.File]::ReadAllText($path) | ConvertFrom-Json
                $value.binary_components[0].binary_size = '22'
                Write-Utf8Fixture -Path $path -Content (($value | ConvertTo-Json -Depth 10) + "`n")
                Update-ChecksumForFile -Root $root -Name $name
            }
        },
        @{
            Name = 'platform binary size differs from archive bytes'
            Mutate = {
                param($root)
                $name = "serctl-$version-linux-x86_64.provenance.json"
                $path = Join-Path $root $name
                $value = [System.IO.File]::ReadAllText($path) | ConvertFrom-Json
                $value.binary_components[0].binary_size = [long]$value.binary_components[0].binary_size + 1
                Write-Utf8Fixture -Path $path -Content (($value | ConvertTo-Json -Depth 10) + "`n")
                Update-ChecksumForFile -Root $root -Name $name
            }
        },
        @{
            Name = 'platform binary hash differs from archive bytes'
            Mutate = {
                param($root)
                $name = "serctl-$version-linux-x86_64.provenance.json"
                $path = Join-Path $root $name
                $value = [System.IO.File]::ReadAllText($path) | ConvertFrom-Json
                $value.binary_components[0].sha256 = ('3' * 64)
                Write-Utf8Fixture -Path $path -Content (($value | ConvertTo-Json -Depth 10) + "`n")
                Update-ChecksumForFile -Root $root -Name $name
            }
        },
        @{
            Name = 'CLI identity missing vault storage contract'
            Mutate = {
                param($root)
                Set-PlatformBinaryVersionFixture `
                    -Root $root `
                    -Platform windows-x86_64 `
                    -BinaryName 'serctl_cli.exe' `
                    -Identity "serctl_cli $version (git $($commit.Substring(0, 12)))"
            }
        },
        @{
            Name = 'daemon identity missing vault storage contract'
            Mutate = {
                param($root)
                Set-PlatformBinaryVersionFixture `
                    -Root $root `
                    -Platform windows-x86_64 `
                    -BinaryName 'serctl_daemon.exe' `
                    -Identity "serctl_daemon $version (git $($commit.Substring(0, 12)); IPC v9..=v9)"
            }
        },
        @{
            Name = 'helper identity falsely claims vault storage contract'
            Mutate = {
                param($root)
                Set-PlatformBinaryVersionFixture `
                    -Root $root `
                    -Platform linux-x86_64 `
                    -BinaryName 'serctl-xfer' `
                    -Identity "serctl-xfer $version (git $($commit.Substring(0, 12)); transfer protocol v1; vault-storage read=v4..=v5 write=v5)"
            }
        },
        @{
            Name = 'platform binary map composite value'
            Mutate = {
                param($root)
                $name = "serctl-$version-linux-x86_64.provenance.json"
                $path = Join-Path $root $name
                $value = [System.IO.File]::ReadAllText($path) | ConvertFrom-Json
                $value.binary_components[0].sha256 = [pscustomobject]@{ digest = ('3' * 64) }
                Write-Utf8Fixture -Path $path -Content (($value | ConvertTo-Json -Depth 10) + "`n")
                Update-ChecksumForFile -Root $root -Name $name
            }
        },
        @{
            Name = 'platform binary map duplicate key'
            Mutate = {
                param($root)
                $name = "serctl-$version-linux-x86_64.provenance.json"
                $path = Join-Path $root $name
                $json = [System.IO.File]::ReadAllText($path)
                $value = $json | ConvertFrom-Json
                $digest = [string]$value.symbol_sha256.'serctl-xfer.debug'
                $pattern = '("serctl-xfer\.debug"\s*:\s*"' + [regex]::Escape($digest) + '")'
                $replacement = '$1,"serctl-xfer.debug":"' + $digest + '"'
                $mutated = [regex]::Replace($json, $pattern, $replacement, 1)
                Assert-DownloadedSetSelfTest ($mutated -cne $json) (
                    'duplicate-key fixture did not locate symbol_sha256'
                )
                Write-Utf8Fixture -Path $path -Content $mutated
                Update-ChecksumForFile -Root $root -Name $name
            }
        },
        @{
            Name = 'platform binary component duplicate field'
            Mutate = {
                param($root)
                $name = "serctl-$version-linux-x86_64.provenance.json"
                $path = Join-Path $root $name
                $json = [System.IO.File]::ReadAllText($path)
                $value = $json | ConvertFrom-Json
                $digest = [string]$value.binary_components[0].sha256
                $pattern = '("sha256"\s*:\s*"' + [regex]::Escape($digest) + '")'
                $replacement = '$1,"sha256":"' + $digest + '"'
                $mutated = [regex]::Replace($json, $pattern, $replacement, 1)
                Assert-DownloadedSetSelfTest ($mutated -cne $json) (
                    'duplicate-field fixture did not locate binary component sha256'
                )
                Write-Utf8Fixture -Path $path -Content $mutated
                Update-ChecksumForFile -Root $root -Name $name
            }
        },
        @{
            Name = 'Linux GLIBC ceiling exceeded'
            Mutate = {
                param($root)
                $name = "serctl-$version-linux-x86_64.provenance.json"
                $path = Join-Path $root $name
                $value = [System.IO.File]::ReadAllText($path) | ConvertFrom-Json
                $value.runtime_abi.maximum_required = '2.36'
                Write-Utf8Fixture -Path $path -Content (($value | ConvertTo-Json -Depth 10) + "`n")
                Update-ChecksumForFile -Root $root -Name $name
            }
        },
        @{
            Name = 'Windows ABI identity drift'
            Mutate = {
                param($root)
                $name = "serctl-$version-windows-x86_64.provenance.json"
                $path = Join-Path $root $name
                $value = [System.IO.File]::ReadAllText($path) | ConvertFrom-Json
                $value.runtime_abi.family = 'gnu'
                Write-Utf8Fixture -Path $path -Content (($value | ConvertTo-Json -Depth 10) + "`n")
                Update-ChecksumForFile -Root $root -Name $name
            }
        }
    )
    foreach ($case in $negativeCases) {
        $caseIndex++
        $caseRoot = Join-Path $temporaryRoot "negative-$caseIndex"
        Copy-ReleaseFixture -Source $baseline -Destination $caseRoot
        & $case.Mutate $caseRoot
        Assert-DownloadedSetSelfTest (
            (Invoke-DownloadedSetVerifier -Root $caseRoot) -ne 0
        ) "$($case.Name) did not fail closed"
    }

    $reparseRoot = Join-Path $temporaryRoot 'negative-reparse'
    Copy-ReleaseFixture -Source $baseline -Destination $reparseRoot
    $reparseName = "serctl-$version-windows-x86_64.zip"
    $reparsePath = Join-Path $reparseRoot $reparseName
    [System.IO.File]::Delete($reparsePath)
    $reparseCreated = $false
    try {
        New-Item `
            -ItemType SymbolicLink `
            -Path $reparsePath `
            -Target (Join-Path $baseline $reparseName) `
            -ErrorAction Stop | Out-Null
        $reparseCreated = $true
    }
    catch {
        $junctionPath = Join-Path $temporaryRoot 'negative-root-junction'
        try {
            New-Item `
                -ItemType Junction `
                -Path $junctionPath `
                -Target $baseline `
                -ErrorAction Stop | Out-Null
            Assert-DownloadedSetSelfTest (
                (Invoke-DownloadedSetVerifier -Root $junctionPath) -ne 0
            ) 'reparse-point release root did not fail closed'
            $reparseCreated = $true
        }
        catch {
            Write-Warning 'Symbolic-link and junction fixtures unavailable; reparse guard remains statically enforced.'
        }
    }
    if ($reparseCreated -and (Test-Path -LiteralPath $reparsePath)) {
        Assert-DownloadedSetSelfTest (
            (Invoke-DownloadedSetVerifier -Root $reparseRoot) -ne 0
        ) 'reparse-point release asset did not fail closed'
    }
}
finally {
    if (-not [string]::IsNullOrWhiteSpace($junctionPath) -and
        (Test-Path -LiteralPath $junctionPath)) {
        (Get-Item -LiteralPath $junctionPath -Force).Delete()
    }
    if (Test-Path -LiteralPath $temporaryRoot -PathType Container) {
        [System.IO.Directory]::Delete($temporaryRoot, $true)
    }
}

Write-Host 'Downloaded release set self-tests passed.'
