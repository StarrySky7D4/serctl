[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ReleaseAssetContract.ps1')
. (Join-Path $PSScriptRoot 'ExternalTransferRuntimeReceiptContract.ps1')
$script:receiptContractModule = @(
    Get-Module 'Serctl.ExternalTransferRuntimeReceiptContract' -All
)[-1]

function Get-SelfTestTextSha256 {
    param([Parameter(Mandatory = $true)][string]$Text)
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '') }
    finally { $sha.Dispose() }
}

$script:releaseCliContent = "formal component bytes:serctl_cli.exe`n"
$script:releaseDaemonContent = "formal component bytes:serctl_daemon.exe`n"
$script:releaseXferContent = "formal component bytes:serctl-xfer`n"
$script:releaseCliSha256 = Get-SelfTestTextSha256 $script:releaseCliContent
$script:releaseDaemonSha256 = Get-SelfTestTextSha256 $script:releaseDaemonContent
$script:releaseXferSha256 = Get-SelfTestTextSha256 $script:releaseXferContent
$script:releaseCliSize = [System.Text.UTF8Encoding]::new($false).GetByteCount($script:releaseCliContent)
$script:releaseDaemonSize = [System.Text.UTF8Encoding]::new($false).GetByteCount($script:releaseDaemonContent)
$script:releaseXferSize = [System.Text.UTF8Encoding]::new($false).GetByteCount($script:releaseXferContent)

function Assert-SelfTestCondition {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if (-not $Condition) {
        throw "external acceptance evidence self-test failed: $Message"
    }
}

function Write-JsonFixture {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$Value
    )
    [System.IO.File]::WriteAllText(
        $Path,
        ($Value | ConvertTo-Json -Depth 12) + "`n",
        [System.Text.UTF8Encoding]::new($false)
    )
}

function New-ExternalZipFixture {
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

function Set-ExternalTarField {
    param([byte[]]$Header, [int]$Offset, [int]$Length, [string]$Text)
    $bytes = [Text.Encoding]::ASCII.GetBytes($Text)
    Assert-SelfTestCondition ($bytes.Length -le $Length) 'tar fixture field overflow'
    [Array]::Copy($bytes, 0, $Header, $Offset, $bytes.Length)
}

function New-ExternalTarGzFixture {
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
            Set-ExternalTarField $header 0 100 ([string]$definition.Name)
            $mode = if ($definition.Name -ceq './serctl-xfer') { '0000755' } else { '0000644' }
            Set-ExternalTarField $header 100 8 ($mode + "`0")
            Set-ExternalTarField $header 108 8 "0000000`0"
            Set-ExternalTarField $header 116 8 "0000000`0"
            Set-ExternalTarField $header 124 12 (([Convert]::ToString($content.Length, 8).PadLeft(11, '0')) + "`0")
            Set-ExternalTarField $header 136 12 "00000000000`0"
            for ($index = 148; $index -lt 156; $index++) { $header[$index] = 32 }
            $header[156] = [byte][char]'0'
            Set-ExternalTarField $header 257 6 "ustar`0"
            Set-ExternalTarField $header 263 2 '00'
            $checksum = [long]0
            foreach ($byte in $header) { $checksum += $byte }
            Set-ExternalTarField $header 148 8 (([Convert]::ToString($checksum, 8).PadLeft(6, '0')) + "`0 ")
            $gzip.Write($header, 0, 512)
            if ($content.Length -gt 0) { $gzip.Write($content, 0, $content.Length) }
            $padding = (512 - ($content.Length % 512)) % 512
            if ($padding -gt 0) { $gzip.Write([byte[]]::new($padding), 0, $padding) }
        }
        $gzip.Write([byte[]]::new(1024), 0, 1024)
    }
    finally { $gzip.Dispose(); $file.Dispose() }
}

function New-RuntimeObservationFixture {
    param(
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$CaseId,
        [Parameter(Mandatory = $true)][string]$ResultCode,
        [Parameter(Mandatory = $true)][string]$ContextSha256
    )
    $observation = [ordered]@{
        schema_version = 1
        category = $Category
        case_id = $CaseId
        context_sha256 = $ContextSha256
        command_sha256 = ('A' * 63) + (($CaseId.Length % 10).ToString())
        terminal_sha256 = ('B' * 63) + (($CaseId.Length % 10).ToString())
        result_code = $ResultCode
        passed = $true
    }
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
        ($observation | ConvertTo-Json -Depth 6 -Compress) + "`n"
    )
    return [ordered]@{
        case_id = $CaseId
        operation_context_sha256 = $ContextSha256
        receipt_base64 = [Convert]::ToBase64String($bytes)
        receipt_sha256 = (Get-FileHashFromBytes -Bytes $bytes)
    }
}

function Get-FileHashFromBytes {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    $sha256 = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha256.ComputeHash($Bytes))).Replace('-', '')
    }
    finally { $sha256.Dispose() }
}

function Get-OperationContextFixtureSha256 {
    param(
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$CaseId
    )
    $bytes = [Text.UTF8Encoding]::new($false).GetBytes(
        "serctl-operation-context-v1`0$Category`0$CaseId`0"
    )
    return Get-FileHashFromBytes -Bytes $bytes
}

function Get-RuntimeContextFixtureSha256 {
    param(
        [Parameter(Mandatory = $true)]$Runner,
        [Parameter(Mandatory = $true)]$Remote,
        [Parameter(Mandatory = $true)]$Components
    )
    $context = [ordered]@{
        tag = $script:tag
        tag_object = $script:tagObject
        commit = $script:commit
        runner = $Runner
        remote = $Remote
        components = $Components
    }
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
        ($context | ConvertTo-Json -Depth 6 -Compress) + "`n"
    )
    return Get-FileHashFromBytes -Bytes $bytes
}

function New-PlatformProvenanceFixture {
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('windows-x86_64', 'linux-x86_64')]
        [string]$Platform
    )

    if ($Platform -ceq 'windows-x86_64') {
        $binaryComponents = @(
            [pscustomobject][ordered]@{
                name = 'serctl_cli.exe'
                binary_size = $script:releaseCliSize
                sha256 = $script:releaseCliSha256.ToLowerInvariant()
                version = "serctl_cli 1.0.0-beta (git $($script:commit.Substring(0, 12)); vault-storage read=v4..=v5 write=v5)"
            },
            [pscustomobject][ordered]@{
                name = 'serctl_daemon.exe'
                binary_size = $script:releaseDaemonSize
                sha256 = $script:releaseDaemonSha256.ToLowerInvariant()
                version = "serctl_daemon 1.0.0-beta (git $($script:commit.Substring(0, 12)); IPC v9..=v9; vault-storage read=v4..=v5 write=v5)"
            }
        )
        $symbolHashes = [ordered]@{
            'serctl_cli.pdb' = '1' * 64
            'serctl_daemon.pdb' = '2' * 64
        }
        $runtimeAbi = [ordered]@{ architecture = 'x86_64'; family = 'windows-msvc' }
        $runnerOs = 'Windows'
        $runnerArch = 'X64'
    }
    else {
        $binaryComponents = @(
            [pscustomobject][ordered]@{
                name = 'serctl-xfer'
                binary_size = $script:releaseXferSize
                sha256 = $script:releaseXferSha256.ToLowerInvariant()
                version = "serctl-xfer 1.0.0-beta (git $($script:commit.Substring(0, 12)); transfer protocol v1)"
            }
        )
        $symbolHashes = [ordered]@{ 'serctl-xfer.debug' = '3' * 64 }
        $runtimeAbi = [ordered]@{
            family = 'glibc'
            maximum_required = 'GLIBC_2.35'
            maximum_supported = 'GLIBC_2.35'
            verifier = 'readelf --version-info --wide'
        }
        $runnerOs = 'Linux'
        $runnerArch = 'X64'
    }
    return [ordered]@{
        schema_version = 2
        version = '1.0.0-beta'
        tag = $script:tag
        tag_object = $script:tagObject
        commit = $script:commit
        platform = $Platform
        repository = 'example/serctl'
        workflow = 'v1 beta tagged release'
        workflow_ref = "example/serctl/.github/workflows/release-v1-beta.yml@refs/tags/$($script:tag)"
        run_id = '12345'
        run_attempt = '1'
        ref = "refs/tags/$($script:tag)"
        source_date_epoch = '1788220800'
        runner_os = $runnerOs
        runner_arch = $runnerArch
        runner_image = 'fixture-image'
        runtime_abi = $runtimeAbi
        rustc = 'rustc 1.91.0'
        cargo = 'cargo 1.91.0'
        cargo_lock_sha256 = '4' * 64
        rust_toolchain_sha256 = '5' * 64
        release_debug = 'line-tables-only'
        release_strip = 'none'
        cargo_target_dir = 'target/v1-beta-release'
        binary_components = $binaryComponents
        symbol_sha256 = $symbolHashes
    }
}

function New-RuntimeComponentsFixture {
    return [ordered]@{
        cli = [ordered]@{
            name = 'serctl_cli.exe'
            binary_size = $script:releaseCliSize
            sha256 = $script:releaseCliSha256
            version = "serctl_cli 1.0.0-beta (git $($script:commit.Substring(0, 12)); vault-storage read=v4..=v5 write=v5)"
        }
        daemon = [ordered]@{
            name = 'serctl_daemon.exe'
            binary_size = $script:releaseDaemonSize
            sha256 = $script:releaseDaemonSha256
            version = "serctl_daemon 1.0.0-beta (git $($script:commit.Substring(0, 12)); IPC v9..=v9; vault-storage read=v4..=v5 write=v5)"
        }
        helper = [ordered]@{
            name = 'serctl-xfer'
            binary_size = $script:releaseXferSize
            sha256 = $script:releaseXferSha256
            version = "serctl-xfer 1.0.0-beta (git $($script:commit.Substring(0, 12)); transfer protocol v1)"
        }
    }
}

function New-InteropLedgerProjectionFixture {
    param(
        [Parameter(Mandatory = $true)]$Components,
        [Parameter(Mandatory = $true)][string]$EvidenceContextSha256
    )
    $exactComponents = (
        ($Components | ConvertTo-Json -Compress -Depth 8) | ConvertFrom-Json
    )
    $ledger = New-ExternalTransferRuntimeLedger -Category 'openssh_dropbear_interop'
    & $script:receiptContractModule {
        param($Ledger, $ExactComponents, $EvidenceContext)
        Set-IsolatedOwnerExpectedBindingInternal `
            (Resolve-LedgerState $Ledger) $ExactComponents $EvidenceContext
    } $ledger $exactComponents $EvidenceContextSha256
    $componentBytes = & $script:receiptContractModule {
        param($ExactComponents)
        Get-CanonicalRuntimeComponentBytesInternal $ExactComponents
    } $exactComponents
    $caseIds = @(
        'OpenSSH_exec', 'OpenSSH_directory', 'OpenSSH_tunnel_local',
        'OpenSSH_tunnel_remote', 'OpenSSH_tunnel_dynamic',
        'OpenSSH_sftp', 'OpenSSH_native',
        'Dropbear_exec', 'Dropbear_sftp', 'Dropbear_native'
    )
    $caseReceipts = @(
        foreach ($caseId in $caseIds) {
            New-RuntimeObservationFixture `
                -Category 'openssh_dropbear_interop' `
                -CaseId $caseId `
                -ResultCode 'completed' `
                -ContextSha256 (Get-OperationContextFixtureSha256 `
                    -Category 'openssh_dropbear_interop' `
                    -CaseId $caseId)
        }
    )
    $ownerReceipt = [pscustomobject][ordered]@{
        schema_version = 2
        owner_contract = 'serctl-isolated-formal-owner-receipt-v2'
        category = 'openssh_dropbear_interop'
        evidence_context_sha256 = $EvidenceContextSha256
        component_set_sha256 = Get-FileHashFromBytes $componentBytes
        component_set_base64 = [Convert]::ToBase64String($componentBytes)
        case_receipts = $caseReceipts
    }
    $ownerBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes(
        ($ownerReceipt | ConvertTo-Json -Compress -Depth 12) + "`n"
    )
    Import-ExternalTransferIsolatedOwnerReceiptV2 `
        -Ledger $ledger -OwnerReceiptBytes $ownerBytes | Out-Null
    $projectionBytes = Get-ExternalTransferInteropUnsealableProjection -Ledger $ledger
    try {
        $projection = (
            [Text.UTF8Encoding]::new($false, $true).GetString($projectionBytes)
        ).TrimEnd("`n") | ConvertFrom-Json
        Assert-SelfTestCondition (
            $projection.projection_contract -ceq
                'serctl-openssh-dropbear-interop-details-projection-v1' -and
            $projection.release_sealable -eq $false -and
            (@($projection.missing_formal_fields) -join ',') -ceq
                'runner,remote,implementations,exact_tag_envelope' -and
            (@($projection.details.case_receipts).Count -eq 10)
        ) 'contract interop projection did not round-trip into the external fixture'
        return $projection.details
    }
    finally {
        [Array]::Clear($componentBytes, 0, $componentBytes.Length)
        [Array]::Clear($projectionBytes, 0, $projectionBytes.Length)
    }
}

function New-EvidenceFixture {
    param(
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$ReleaseHash
    )
    $windowsRunner = [ordered]@{
        label = 'windows-2025'
        os = 'Windows'
        arch = 'X64'
        rust_host = 'x86_64-pc-windows-msvc'
    }
    $linuxRunner = [ordered]@{
        label = 'ubuntu-22.04'
        os = 'Linux'
        arch = 'X64'
        rust_host = 'x86_64-unknown-linux-gnu'
    }
    $macX64Runner = [ordered]@{
        label = 'macos-15-intel'
        os = 'macOS'
        arch = 'X64'
        rust_host = 'x86_64-apple-darwin'
    }
    $macArmRunner = [ordered]@{
        label = 'macos-15'
        os = 'macOS'
        arch = 'ARM64'
        rust_host = 'aarch64-apple-darwin'
    }
    $remote = [ordered]@{
        os = 'Ubuntu 22.04.5 LTS'
        arch = 'x86_64'
        openssh_identity = 'OpenSSH_9.6p1'
        helper_identity = 'serctl-xfer 1.0.0-beta transfer-v1'
        scp_identity = 'OpenSSH scp 9.6p1'
    }
    switch ($Category) {
        'clean_install_smoke' {
            $details = [ordered]@{
                runner = $windowsRunner
                bundle_version = '1.0.0-beta'
                cli_identity = [ordered]@{
                    component = 'serctl_cli'
                    version = '1.0.0-beta'
                    commit = $script:commit
                    sha256 = $script:releaseCliSha256
                    ipc_min = 9
                    ipc_max = 9
                    storage_contract = 'vault-storage read=v4..=v5 write=v5'
                }
                daemon_identity = [ordered]@{
                    component = 'serctl_daemon'
                    version = '1.0.0-beta'
                    commit = $script:commit
                    sha256 = $script:releaseDaemonSha256
                    ipc_min = 9
                    ipc_max = 9
                    storage_contract = 'vault-storage read=v4..=v5 write=v5'
                }
                fresh_home = $true
                install_passed = $true
                status_passed = $true
                grant_issue_passed = $true
                cleanup_passed = $true
                rollback_passed = $true
            }
        }
        'native_transfer_real_host' {
            $fixedHashes = [ordered]@{
                '21' = '75AEE9DCC9FBE7DDC9394F5BC5D38D9F5AD361F0520F7CEAB59616E38F5950B5'
                '1298223' = '27C51BE520501C692C8981A8331DE45467D9B7A64B63DD4D3E2CFC2C134F0FAD'
                '67108864' = '5C8A41A9B8D7FC418BA77B0312EFC461DE86740EF476F4B53ADAB9313C4D1562'
                '1073741824' = 'E18E3F358B46EAE9266AC36A5FF6347F6BF09711DFF389597F237D5FE83111D8'
            }
            $cases = foreach ($direction in @('push', 'pull')) {
                foreach ($size in @(21, 1298223, 67108864, 1073741824)) {
                    [ordered]@{
                        direction = $direction
                        size_bytes = $size
                        sha256 = $fixedHashes[[string]$size]
                        passed = $true
                    }
                }
            }
            $nativeElapsed = @(800000, 750000, 700000, 650000, 600000)
            $scpElapsed = @(780000, 720000, 660000, 600000, 540000)
            $nativeSamples = for ($sampleIndex = 0; $sampleIndex -lt 5; $sampleIndex++) {
                [ordered]@{
                    sample_index = $sampleIndex + 1
                    size_bytes = 67108864
                    elapsed_microseconds = $nativeElapsed[$sampleIndex]
                    cpu_basis_points = 4100 + ($sampleIndex * 100)
                    peak_rss_bytes = 7340032 + ($sampleIndex * 262144)
                    rtt_microseconds = 800 + ($sampleIndex * 100)
                }
            }
            $scpSamples = for ($sampleIndex = 0; $sampleIndex -lt 5; $sampleIndex++) {
                [ordered]@{
                    sample_index = $sampleIndex + 1
                    size_bytes = 67108864
                    elapsed_microseconds = $scpElapsed[$sampleIndex]
                    cpu_basis_points = 3000 + ($sampleIndex * 100)
                    peak_rss_bytes = 6291456 + ($sampleIndex * 262144)
                    rtt_microseconds = 800 + ($sampleIndex * 100)
                }
            }
            $nativeRates = @($nativeSamples | ForEach-Object {
                [int64][decimal]::Floor(
                    ([decimal]$_.size_bytes * [decimal]1000000) /
                    [decimal]$_.elapsed_microseconds
                )
            } | Sort-Object)
            $scpRates = @($scpSamples | ForEach-Object {
                [int64][decimal]::Floor(
                    ([decimal]$_.size_bytes * [decimal]1000000) /
                    [decimal]$_.elapsed_microseconds
                )
            } | Sort-Object)
            $runtimeComponents = New-RuntimeComponentsFixture
            $runtimeContextSha256 = Get-RuntimeContextFixtureSha256 `
                -Runner $windowsRunner `
                -Remote $remote `
                -Components $runtimeComponents
            $details = [ordered]@{
                runner = $windowsRunner
                remote = $remote
                components = $runtimeComponents
                evidence_context_sha256 = $runtimeContextSha256
                cases = @($cases)
                fault_cases = @(
                    [ordered]@{ scenario = 'resume_25'; result_code = 'completed'; resume_percent = 25; cleanup_state = 'complete'; confirmed_advanced_without_ack = $false; target_overwritten = $false; foreign_partial_deleted = $false; passed = $true },
                    [ordered]@{ scenario = 'resume_75'; result_code = 'completed'; resume_percent = 75; cleanup_state = 'complete'; confirmed_advanced_without_ack = $false; target_overwritten = $false; foreign_partial_deleted = $false; passed = $true },
                    [ordered]@{ scenario = 'lost_ack'; result_code = 'outcome_unknown'; resume_percent = 0; cleanup_state = 'owned_partial_preserved'; confirmed_advanced_without_ack = $false; target_overwritten = $false; foreign_partial_deleted = $false; passed = $true },
                    [ordered]@{ scenario = 'helper_crash'; result_code = 'outcome_unknown'; resume_percent = 0; cleanup_state = 'owned_partial_preserved'; confirmed_advanced_without_ack = $false; target_overwritten = $false; foreign_partial_deleted = $false; passed = $true },
                    [ordered]@{ scenario = 'disconnect'; result_code = 'outcome_unknown'; resume_percent = 0; cleanup_state = 'owned_partial_preserved'; confirmed_advanced_without_ack = $false; target_overwritten = $false; foreign_partial_deleted = $false; passed = $true },
                    [ordered]@{ scenario = 'daemon_restart'; result_code = 'outcome_unknown'; resume_percent = 0; cleanup_state = 'owned_partial_preserved'; confirmed_advanced_without_ack = $false; target_overwritten = $false; foreign_partial_deleted = $false; passed = $true },
                    [ordered]@{ scenario = 'disk_full'; result_code = 'transfer_failed'; resume_percent = 0; cleanup_state = 'owned_partial_removed'; confirmed_advanced_without_ack = $false; target_overwritten = $false; foreign_partial_deleted = $false; passed = $true },
                    [ordered]@{ scenario = 'permission_denied'; result_code = 'transfer_failed'; resume_percent = 0; cleanup_state = 'owned_partial_removed'; confirmed_advanced_without_ack = $false; target_overwritten = $false; foreign_partial_deleted = $false; passed = $true },
                    [ordered]@{ scenario = 'target_race'; result_code = 'transfer_failed'; resume_percent = 0; cleanup_state = 'owned_partial_removed'; confirmed_advanced_without_ack = $false; target_overwritten = $false; foreign_partial_deleted = $false; passed = $true },
                    [ordered]@{ scenario = 'target_symlink_or_reparse'; result_code = 'transfer_failed'; resume_percent = 0; cleanup_state = 'no_owned_partial_created'; confirmed_advanced_without_ack = $false; target_overwritten = $false; foreign_partial_deleted = $false; passed = $true },
                    [ordered]@{ scenario = 'unknown_cleanup'; result_code = 'cleanup_incomplete'; resume_percent = 0; cleanup_state = 'cleanup_incomplete'; confirmed_advanced_without_ack = $false; target_overwritten = $false; foreign_partial_deleted = $false; passed = $true }
                )
                registry_window = [ordered]@{
                    active_per_profile = 8
                    active_global = 48
                    terminal_per_profile = 16
                    terminal_global = 256
                    retention_max_seconds = 900
                    sftp_write_bytes = 2048
                    sftp_inflight_writes = 1
                    native_chunk_bytes = 32768
                    native_ack_window_bytes = 32768
                    profile_isolation_passed = $true
                    control_frame_bound_passed = $true
                    confirmed_before_ack = $false
                }
                performance = [ordered]@{
                    native_p50_bytes_per_second = $nativeRates[2]
                    native_p95_bytes_per_second = $nativeRates[4]
                    scp_bytes_per_second = $scpRates[2]
                    throughput_ratio_percent = [int64][decimal]::Floor(
                        ([decimal]$nativeRates[2] * [decimal]100) / [decimal]$scpRates[2]
                    )
                    cpu_basis_points = 4500
                    peak_rss_bytes = 8388608
                    rtt_microseconds = 1000
                    chunk_bytes = 32768
                    window_bytes = 32768
                    native_samples = @($nativeSamples)
                    scp_samples = @($scpSamples)
                }
                runtime_observations = @(
                    foreach ($caseId in @(
                        'push_21', 'push_1298223', 'push_67108864', 'push_1073741824',
                        'pull_21', 'pull_1298223', 'pull_67108864', 'pull_1073741824',
                        'resume_25', 'resume_75', 'lost_ack', 'helper_crash', 'disconnect',
                        'daemon_restart', 'disk_full', 'permission_denied', 'target_race',
                        'target_symlink_or_reparse', 'unknown_cleanup', 'registry_window'
                    )) {
                        $resultCode = if ($caseId -in @(
                            'lost_ack', 'helper_crash', 'disconnect', 'daemon_restart'
                        )) {
                            'outcome_unknown'
                        } elseif ($caseId -in @(
                            'disk_full', 'permission_denied', 'target_race',
                            'target_symlink_or_reparse'
                        )) {
                            'transfer_failed'
                        } elseif ($caseId -ceq 'unknown_cleanup') {
                            'cleanup_incomplete'
                        } else { 'completed' }
                        New-RuntimeObservationFixture `
                            -Category 'native_transfer_real_host' `
                            -CaseId $caseId `
                            -ResultCode $resultCode `
                            -ContextSha256 (Get-OperationContextFixtureSha256 `
                                -Category 'native_transfer_real_host' `
                                -CaseId $caseId)
                    }
                )
            }
        }
        'openssh_dropbear_interop' {
            $runtimeComponents = New-RuntimeComponentsFixture
            $runtimeContextSha256 = Get-RuntimeContextFixtureSha256 `
                -Runner $linuxRunner `
                -Remote $remote `
                -Components $runtimeComponents
            $ledgerProjection = New-InteropLedgerProjectionFixture `
                -Components $runtimeComponents `
                -EvidenceContextSha256 $runtimeContextSha256
            $details = [ordered]@{
                runner = $linuxRunner
                remote = $remote
                components = $ledgerProjection.components
                evidence_context_sha256 = $ledgerProjection.evidence_context_sha256
                implementations = @(
                    [ordered]@{
                        name = 'OpenSSH'
                        identity = 'OpenSSH_9.6p1'
                        exec_passed = $true
                        sftp_passed = $true
                        native_passed = $true
                    },
                    [ordered]@{
                        name = 'Dropbear'
                        identity = 'Dropbear v2024.85'
                        exec_passed = $true
                        sftp_passed = $true
                        native_passed = $true
                    }
                )
                case_receipts = $ledgerProjection.case_receipts
            }
        }
        'whole_bundle_upgrade_rollback' {
            $details = [ordered]@{
                runner = $windowsRunner
                predecessor_version = '0.3.0-beta.2'
                candidate_version = '1.0.0-beta'
                upgrade_outcome = 'passed'
                rollback_outcome = 'passed'
                predecessor_files = [ordered]@{
                    cli_sha256 = ('A' * 64)
                    daemon_sha256 = ('B' * 64)
                    xfer_sha256 = ('C' * 64)
                }
                candidate_files = [ordered]@{
                    cli_sha256 = $script:releaseCliSha256
                    daemon_sha256 = $script:releaseDaemonSha256
                    xfer_sha256 = $script:releaseXferSha256
                }
                descriptor_owner_pid = 4242
                descriptor_daemon_identity = (
                    "serctl_daemon 1.0.0-beta " +
                    "(git $($script:commit.Substring(0, 12)); IPC v9..=v9; " +
                    'vault-storage read=v4..=v5 write=v5)'
                )
                descriptor_daemon_sha256 = $script:releaseDaemonSha256
                whole_bundle_atomic = $true
                mixed_triples_tested = 6
                mixed_triples_rejected = 6
                hash_substitutions_tested = 3
                hash_substitutions_rejected = 3
                stale_descriptor_rejected = $true
                stale_grant_rejected = $true
                matched_bundle_upgrade_verified = $true
                matched_bundle_rollback_verified = $true
                audit_seed_key_package_verified = $true
                vault_storage_v4_to_v5_upgrade_verified = $true
                beta2_destructive_writer_blocked_before_mutation = $true
                beta2_transient_runtime_activation_observed = $false
                beta2_runtime_state_cleaned_after_rejection = $true
                candidate_storage_marker_verified = $true
                v8_unknown_audit_fields_rejected_before_write = $true
                unknown_security_fields_not_dropped = $true
                vault_rollback_verified = $true
                pre_upgrade_vault_backup_restored = $true
                matching_recovery_media_restored = $true
                acl_owner_metadata_restored = $true
            }
        }
        'windows_privileged_acl' {
            $details = [ordered]@{
                runner = $windowsRunner
                candidate_cli_sha256 = $script:releaseCliSha256
                owner_sid = 'S-1-5-21-1000-1001-1002-1003'
                observer_sid = 'S-1-5-21-2000-2001-2002-2003'
                distinct_sids = $true
                parent_control_passed = $true
                observer_read_denied = $true
                observer_write_denied = $true
                owner_reopen_passed = $true
                dacl_protected = $true
                reparse_point_rejected = $true
                owner_rights_restricted = $true
                system_full_control = $true
                administrators_full_control = $true
                inheritance_protected = $true
                cleanup_passed = $true
            }
        }
        default { throw "unknown fixture evidence category: $Category" }
    }
    $requiredPassCount = switch ($Category) {
        'native_transfer_real_host' { 20 }
        'openssh_dropbear_interop' { 10 }
        default { 4 }
    }
    return [ordered]@{
        schema_version = 1
        category = $Category
        status = 'passed'
        tag = $script:tag
        tag_object = $script:tagObject
        commit = $script:commit
        release_manifest_sha256 = $ReleaseHash
        evidence_owner = 'independent-evidence-owner'
        timestamps = [ordered]@{
            started_utc = '2026-08-31T23:55:00.0000000+00:00'
            completed_utc = '2026-08-31T23:59:00.0000000+00:00'
        }
        test_counts = [ordered]@{
            total = $requiredPassCount
            passed = $requiredPassCount
            failed = 0
            skipped = 0
            ignored = 0
            unknown = 0
        }
        limitations = @('Synthetic fixture; it proves parser behavior only.')
        details = $details
    }
}

function New-FixtureSet {
    param([Parameter(Mandatory = $true)][string]$Root)

    [System.IO.Directory]::CreateDirectory($Root) | Out-Null
    $version = $script:tag.Substring(1)
    $windowsProvenanceName = "serctl-$version-windows-x86_64.provenance.json"
    $linuxProvenanceName = "serctl-$version-linux-x86_64.provenance.json"
    Write-JsonFixture `
        -Path (Join-Path $Root $windowsProvenanceName) `
        -Value (New-PlatformProvenanceFixture -Platform 'windows-x86_64')
    Write-JsonFixture `
        -Path (Join-Path $Root $linuxProvenanceName) `
        -Value (New-PlatformProvenanceFixture -Platform 'linux-x86_64')
    $expectedReleaseFiles = @(Get-V1BetaHashedReleaseNames -Version $version)
    $windowsRuntimeName = "serctl-$version-windows-x86_64.zip"
    $linuxRuntimeName = "serctl-$version-linux-x86_64-xfer.tar.gz"
    foreach ($name in $expectedReleaseFiles) {
        $path = Join-Path $Root $name
        if ($name -in @($windowsRuntimeName, $linuxRuntimeName)) { continue }
        if (-not (Test-Path -LiteralPath $path)) {
            [System.IO.File]::WriteAllText(
                $path,
                "fixture release file $name`n",
                [System.Text.UTF8Encoding]::new($false)
            )
        }
    }
    $governanceNames = @(
        'LICENSE', 'SECURITY.md', 'v1-beta-agent-jsonl.md',
        'v1-beta-release-contract.md', 'v1-beta-acceptance-matrix.md'
    )
    $windowsEntries = @(
        [pscustomobject]@{ Name = 'serctl_cli.exe'; Content = $script:releaseCliContent },
        [pscustomobject]@{ Name = 'serctl_daemon.exe'; Content = $script:releaseDaemonContent },
        [pscustomobject]@{
            Name = $windowsProvenanceName
            Content = [IO.File]::ReadAllText((Join-Path $Root $windowsProvenanceName))
        }
    ) + @($governanceNames | ForEach-Object {
        [pscustomobject]@{
            Name = $_
            Content = "fixture governance:$_`n"
        }
    })
    New-ExternalZipFixture `
        -Path (Join-Path $Root $windowsRuntimeName) `
        -Entries $windowsEntries
    $linuxEntries = @(
        [pscustomobject]@{ Name = './serctl-xfer'; Content = $script:releaseXferContent },
        [pscustomobject]@{
            Name = "./$linuxProvenanceName"
            Content = [IO.File]::ReadAllText((Join-Path $Root $linuxProvenanceName))
        }
    ) + @($governanceNames | ForEach-Object {
        [pscustomobject]@{
            Name = "./$_"
            Content = "fixture governance:$_`n"
        }
    })
    New-ExternalTarGzFixture `
        -Path (Join-Path $Root $linuxRuntimeName) `
        -Entries $linuxEntries
    $releaseManifestPath = Join-Path $Root 'SHA256SUMS'
    $releaseLines = foreach ($name in $expectedReleaseFiles) {
        $hash = (
            Get-FileHash -LiteralPath (Join-Path $Root $name) -Algorithm SHA256
        ).Hash.ToLowerInvariant()
        "$hash  $name"
    }
    [System.IO.File]::WriteAllText(
        $releaseManifestPath,
        (($releaseLines -join "`n") + "`n"),
        [System.Text.UTF8Encoding]::new($false)
    )
    $releaseHash = (Get-FileHash -LiteralPath $releaseManifestPath -Algorithm SHA256).Hash
    $categories = foreach ($name in @(
        'clean_install_smoke',
        'native_transfer_real_host',
        'openssh_dropbear_interop',
        'whole_bundle_upgrade_rollback',
        'windows_privileged_acl'
    )) {
        $artifactPath = Join-Path $Root "$name.evidence"
        Write-JsonFixture `
            -Path $artifactPath `
            -Value (New-EvidenceFixture -Category $name -ReleaseHash $releaseHash)
        [ordered]@{
            category = $name
            status = 'passed'
            artifact_url = "https://evidence.example/$name.json"
            artifact_sha256 = (
                Get-FileHash -LiteralPath $artifactPath -Algorithm SHA256
            ).Hash
        }
    }
    $manifest = [ordered]@{
        schema_version = 1
        tag = $script:tag
        tag_object = $script:tagObject
        commit = $script:commit
        release_manifest_sha256 = $releaseHash
        evidence_owner = 'independent-evidence-owner'
        completed_utc = '2026-09-01T00:00:00.0000000+00:00'
        categories = @($categories)
    }
    $evidencePath = Join-Path $Root 'evidence-manifest.json'
    Write-JsonFixture -Path $evidencePath -Value $manifest
    $evidenceHash = (Get-FileHash -LiteralPath $evidencePath -Algorithm SHA256).Hash
    $record = [ordered]@{
        schema_version = 1
        accepted = $true
        tag = $script:tag
        tag_object = $script:tagObject
        commit = $script:commit
        release_manifest_sha256 = $releaseHash
        acceptance_owner = 'independent-acceptance-owner'
        completed_utc = '2026-09-01T00:01:00.0000000+00:00'
        evidence_manifest_url = $script:evidenceUrl
        evidence_manifest_sha256 = $evidenceHash
    }
    $recordPath = Join-Path $Root 'acceptance-record.json'
    Write-JsonFixture -Path $recordPath -Value $record
    return [pscustomobject]@{
        Root = $Root
        RecordPath = $recordPath
        EvidencePath = $evidencePath
        ReleaseManifestPath = $releaseManifestPath
    }
}

function Copy-FixtureSet {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination
    )
    [System.IO.Directory]::CreateDirectory($Destination) | Out-Null
    foreach ($file in Get-ChildItem -LiteralPath $Source -File) {
        [System.IO.File]::Copy($file.FullName, (Join-Path $Destination $file.Name), $false)
    }
    return [pscustomobject]@{
        Root = $Destination
        RecordPath = Join-Path $Destination 'acceptance-record.json'
        EvidencePath = Join-Path $Destination 'evidence-manifest.json'
        ReleaseManifestPath = Join-Path $Destination 'SHA256SUMS'
    }
}

function Update-FixtureBindings {
    param(
        [Parameter(Mandatory = $true)]$Fixture,
        [Parameter(Mandatory = $true)][string]$Category
    )
    $manifest = Get-Content -LiteralPath $Fixture.EvidencePath -Raw -Encoding utf8 |
        ConvertFrom-Json
    $entry = @($manifest.categories | Where-Object { $_.category -ceq $Category })
    Assert-SelfTestCondition ($entry.Count -eq 1) 'fixture category binding is ambiguous'
    $entry[0].artifact_sha256 = (
        Get-FileHash -LiteralPath (Join-Path $Fixture.Root "$Category.evidence") -Algorithm SHA256
    ).Hash
    Write-JsonFixture -Path $Fixture.EvidencePath -Value $manifest
    $record = Get-Content -LiteralPath $Fixture.RecordPath -Raw -Encoding utf8 |
        ConvertFrom-Json
    $record.evidence_manifest_sha256 = (
        Get-FileHash -LiteralPath $Fixture.EvidencePath -Algorithm SHA256
    ).Hash
    Write-JsonFixture -Path $Fixture.RecordPath -Value $record
}

function Update-AllReleaseBindings {
    param([Parameter(Mandatory = $true)]$Fixture)
    $version = $script:tag.Substring(1)
    $expectedNames = @(Get-V1BetaHashedReleaseNames -Version $version)
    $lines = foreach ($name in $expectedNames) {
        $hash = (Get-FileHash -LiteralPath (Join-Path $Fixture.Root $name) -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $name"
    }
    [IO.File]::WriteAllText(
        $Fixture.ReleaseManifestPath,
        (($lines -join "`n") + "`n"),
        [Text.UTF8Encoding]::new($false)
    )
    $releaseHash = (Get-FileHash -LiteralPath $Fixture.ReleaseManifestPath -Algorithm SHA256).Hash
    $categories = @(
        'clean_install_smoke', 'native_transfer_real_host',
        'openssh_dropbear_interop', 'whole_bundle_upgrade_rollback',
        'windows_privileged_acl'
    )
    foreach ($category in $categories) {
        $path = Join-Path $Fixture.Root "$category.evidence"
        $document = Get-Content -LiteralPath $path -Raw -Encoding utf8 | ConvertFrom-Json
        $document.release_manifest_sha256 = $releaseHash
        Write-JsonFixture -Path $path -Value $document
    }
    $manifest = Get-Content -LiteralPath $Fixture.EvidencePath -Raw -Encoding utf8 | ConvertFrom-Json
    $manifest.release_manifest_sha256 = $releaseHash
    foreach ($entry in @($manifest.categories)) {
        $entry.artifact_sha256 = (
            Get-FileHash -LiteralPath (Join-Path $Fixture.Root "$($entry.category).evidence") -Algorithm SHA256
        ).Hash
    }
    Write-JsonFixture -Path $Fixture.EvidencePath -Value $manifest
    $record = Get-Content -LiteralPath $Fixture.RecordPath -Raw -Encoding utf8 | ConvertFrom-Json
    $record.release_manifest_sha256 = $releaseHash
    $record.evidence_manifest_sha256 = (
        Get-FileHash -LiteralPath $Fixture.EvidencePath -Algorithm SHA256
    ).Hash
    Write-JsonFixture -Path $Fixture.RecordPath -Value $record
}

function Invoke-Verifier {
    param([Parameter(Mandatory = $true)]$Fixture)

    $recordHash = (Get-FileHash -LiteralPath $Fixture.RecordPath -Algorithm SHA256).Hash
    & $script:verifier `
        -AcceptanceRecordPath $Fixture.RecordPath `
        -AcceptanceRecordSha256 $recordHash `
        -AcceptanceRecordUrl $script:recordUrl `
        -EvidenceManifestPath $Fixture.EvidencePath `
        -EvidenceArtifactDirectory $Fixture.Root `
        -ReleaseManifestPath $Fixture.ReleaseManifestPath `
        -Tag $script:tag `
        -Commit $script:commit `
        -TagObject $script:tagObject *> $null
}

function Assert-Rejected {
    param(
        [Parameter(Mandatory = $true)]$Fixture,
        [Parameter(Mandatory = $true)][string]$Description
    )
    $rejected = $false
    try {
        Invoke-Verifier -Fixture $Fixture
    }
    catch {
        $rejected = $true
    }
    Assert-SelfTestCondition $rejected "$Description was accepted"
}

$tag = 'v1.0.0-beta'
$commit = '0123456789abcdef0123456789abcdef01234567'
$tagObject = 'fedcba9876543210fedcba9876543210fedcba98'
$recordUrl = 'https://acceptance.example/v1.0.0-beta.json'
$evidenceUrl = 'https://evidence.example/v1.0.0-beta-manifest.json'
$verifier = Join-Path $PSScriptRoot 'Test-ExternalAcceptanceEvidence.ps1'
$planScript = Join-Path $PSScriptRoot 'Get-ExternalAcceptanceDownloadPlan.ps1'
$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'serctl-external-evidence-selftest-' + [System.Guid]::NewGuid().ToString('N')
)
[System.IO.Directory]::CreateDirectory($temporaryRoot) | Out-Null
try {
    $baseline = New-FixtureSet -Root (Join-Path $temporaryRoot 'baseline')
    Invoke-Verifier -Fixture $baseline

    $archiveByteDrift = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'archive-component-byte-drift')
    $version = $script:tag.Substring(1)
    $provenanceName = "serctl-$version-windows-x86_64.provenance.json"
    $archivePath = Join-Path $archiveByteDrift.Root "serctl-$version-windows-x86_64.zip"
    [IO.File]::Delete($archivePath)
    $governanceNames = @(
        'LICENSE', 'SECURITY.md', 'v1-beta-agent-jsonl.md',
        'v1-beta-release-contract.md', 'v1-beta-acceptance-matrix.md'
    )
    $entries = @(
        [pscustomobject]@{ Name = 'serctl_cli.exe'; Content = "mutated component bytes`n" },
        [pscustomobject]@{ Name = 'serctl_daemon.exe'; Content = $script:releaseDaemonContent },
        [pscustomobject]@{
            Name = $provenanceName
            Content = [IO.File]::ReadAllText((Join-Path $archiveByteDrift.Root $provenanceName))
        }
    ) + @($governanceNames | ForEach-Object {
        [pscustomobject]@{ Name = $_; Content = "fixture governance:$_`n" }
    })
    New-ExternalZipFixture -Path $archivePath -Entries $entries
    Update-AllReleaseBindings -Fixture $archiveByteDrift
    Assert-Rejected `
        -Fixture $archiveByteDrift `
        -Description 'release archive component actual byte/hash drift'
    $recordHash = (Get-FileHash -LiteralPath $baseline.RecordPath -Algorithm SHA256).Hash
    $manifestPlan = & $planScript `
        -Phase manifest `
        -AcceptanceRecordPath $baseline.RecordPath `
        -AcceptanceRecordSha256 $recordHash `
        -AcceptanceRecordUrl $recordUrl `
        -ReleaseManifestPath $baseline.ReleaseManifestPath `
        -Tag $tag `
        -Commit $commit `
        -TagObject $tagObject | ConvertFrom-Json
    Assert-SelfTestCondition (
        [string]$manifestPlan.manifest_url -ceq $evidenceUrl -and
        [string]$manifestPlan.manifest_sha256 -ceq (
            Get-FileHash -LiteralPath $baseline.EvidencePath -Algorithm SHA256
        ).Hash
    ) 'strict manifest download plan did not preserve the approved identity'
    $artifactPlan = & $planScript `
        -Phase artifacts `
        -AcceptanceRecordPath $baseline.RecordPath `
        -AcceptanceRecordSha256 $recordHash `
        -AcceptanceRecordUrl $recordUrl `
        -EvidenceManifestPath $baseline.EvidencePath `
        -ReleaseManifestPath $baseline.ReleaseManifestPath `
        -Tag $tag `
        -Commit $commit `
        -TagObject $tagObject | ConvertFrom-Json
    Assert-SelfTestCondition (@($artifactPlan.artifacts).Count -eq 5) (
        'strict artifact download plan did not return the exact category set'
    )

    $stringBoolean = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'string-boolean')
    $record = Get-Content -LiteralPath $stringBoolean.RecordPath -Raw -Encoding utf8 |
        ConvertFrom-Json
    $record.accepted = 'true'
    Write-JsonFixture -Path $stringBoolean.RecordPath -Value $record
    Assert-Rejected -Fixture $stringBoolean -Description 'string acceptance boolean'

    $invalidUtf8 = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'invalid-utf8')
    [System.IO.File]::WriteAllBytes(
        $invalidUtf8.RecordPath,
        [byte[]](0x7B, 0x22, 0x78, 0x22, 0x3A, 0x22, 0xC3, 0x28, 0x22, 0x7D)
    )
    Assert-Rejected -Fixture $invalidUtf8 -Description 'invalid UTF-8 acceptance record'

    $missingCategory = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'missing-category')
    $manifest = Get-Content -LiteralPath $missingCategory.EvidencePath -Raw -Encoding utf8 |
        ConvertFrom-Json
    $manifest.categories = @($manifest.categories | Select-Object -First 4)
    Write-JsonFixture -Path $missingCategory.EvidencePath -Value $manifest
    $record = Get-Content -LiteralPath $missingCategory.RecordPath -Raw -Encoding utf8 |
        ConvertFrom-Json
    $record.evidence_manifest_sha256 = (
        Get-FileHash -LiteralPath $missingCategory.EvidencePath -Algorithm SHA256
    ).Hash
    Write-JsonFixture -Path $missingCategory.RecordPath -Value $record
    Assert-Rejected -Fixture $missingCategory -Description 'missing required category'

    $categoryTraversal = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'category-path-traversal')
    $manifest = Get-Content -LiteralPath $categoryTraversal.EvidencePath -Raw -Encoding utf8 |
        ConvertFrom-Json
    $manifest.categories[0].category = '..\outside'
    Write-JsonFixture -Path $categoryTraversal.EvidencePath -Value $manifest
    $record = Get-Content -LiteralPath $categoryTraversal.RecordPath -Raw -Encoding utf8 |
        ConvertFrom-Json
    $record.evidence_manifest_sha256 = (
        Get-FileHash -LiteralPath $categoryTraversal.EvidencePath -Algorithm SHA256
    ).Hash
    Write-JsonFixture -Path $categoryTraversal.RecordPath -Value $record
    Assert-Rejected `
        -Fixture $categoryTraversal `
        -Description 'category path traversal before artifact lookup'

    $unsafeAcceptanceOwner = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'unsafe-acceptance-owner')
    $record = Get-Content `
        -LiteralPath $unsafeAcceptanceOwner.RecordPath `
        -Raw `
        -Encoding utf8 | ConvertFrom-Json
    $record.acceptance_owner = 'C:\private\acceptance-owner'
    Write-JsonFixture -Path $unsafeAcceptanceOwner.RecordPath -Value $record
    Assert-Rejected `
        -Fixture $unsafeAcceptanceOwner `
        -Description 'unsafe acceptance owner absolute path'

    $oversizedAcceptanceOwner = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'oversized-acceptance-owner')
    $record = Get-Content `
        -LiteralPath $oversizedAcceptanceOwner.RecordPath `
        -Raw `
        -Encoding utf8 | ConvertFrom-Json
    $record.acceptance_owner = 'o' * 129
    Write-JsonFixture -Path $oversizedAcceptanceOwner.RecordPath -Value $record
    Assert-Rejected `
        -Fixture $oversizedAcceptanceOwner `
        -Description 'oversized acceptance owner identity'

    $unsafeEvidenceOwner = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'unsafe-evidence-owner')
    $manifest = Get-Content `
        -LiteralPath $unsafeEvidenceOwner.EvidencePath `
        -Raw `
        -Encoding utf8 | ConvertFrom-Json
    $manifest.evidence_owner = "evidence`nowner"
    Write-JsonFixture -Path $unsafeEvidenceOwner.EvidencePath -Value $manifest
    $record = Get-Content `
        -LiteralPath $unsafeEvidenceOwner.RecordPath `
        -Raw `
        -Encoding utf8 | ConvertFrom-Json
    $record.evidence_manifest_sha256 = (
        Get-FileHash -LiteralPath $unsafeEvidenceOwner.EvidencePath -Algorithm SHA256
    ).Hash
    Write-JsonFixture -Path $unsafeEvidenceOwner.RecordPath -Value $record
    Assert-Rejected `
        -Fixture $unsafeEvidenceOwner `
        -Description 'unsafe evidence owner control character'

    $sameOwnerIdentity = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'same-owner-identity')
    $record = Get-Content `
        -LiteralPath $sameOwnerIdentity.RecordPath `
        -Raw `
        -Encoding utf8 | ConvertFrom-Json
    $record.acceptance_owner = 'independent-evidence-owner'
    Write-JsonFixture -Path $sameOwnerIdentity.RecordPath -Value $record
    Assert-Rejected `
        -Fixture $sameOwnerIdentity `
        -Description 'same acceptance and evidence owner identity'

    $identityDrift = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'identity-drift')
    $manifest = Get-Content -LiteralPath $identityDrift.EvidencePath -Raw -Encoding utf8 |
        ConvertFrom-Json
    $manifest.commit = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    Write-JsonFixture -Path $identityDrift.EvidencePath -Value $manifest
    $record = Get-Content -LiteralPath $identityDrift.RecordPath -Raw -Encoding utf8 |
        ConvertFrom-Json
    $record.evidence_manifest_sha256 = (
        Get-FileHash -LiteralPath $identityDrift.EvidencePath -Algorithm SHA256
    ).Hash
    Write-JsonFixture -Path $identityDrift.RecordPath -Value $record
    Assert-Rejected -Fixture $identityDrift -Description 'evidence identity drift'

    $extraField = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'extra-field')
    $record = Get-Content -LiteralPath $extraField.RecordPath -Raw -Encoding utf8 |
        ConvertFrom-Json
    $record | Add-Member -NotePropertyName unexpected -NotePropertyValue $true
    Write-JsonFixture -Path $extraField.RecordPath -Value $record
    Assert-Rejected -Fixture $extraField -Description 'acceptance record extra field'

    $duplicateKey = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'duplicate-key')
    $duplicateJson = [System.IO.File]::ReadAllText($duplicateKey.RecordPath).TrimEnd()
    $closingBrace = $duplicateJson.LastIndexOf('}')
    $duplicateJson = $duplicateJson.Insert($closingBrace, ',"accepted":false')
    [System.IO.File]::WriteAllText(
        $duplicateKey.RecordPath,
        $duplicateJson + "`n",
        [System.Text.UTF8Encoding]::new($false)
    )
    Assert-Rejected -Fixture $duplicateKey -Description 'acceptance record duplicate JSON key'
    $duplicatePlanRejected = $false
    try {
        & $planScript `
            -Phase manifest `
            -AcceptanceRecordPath $duplicateKey.RecordPath `
            -AcceptanceRecordSha256 (
                Get-FileHash -LiteralPath $duplicateKey.RecordPath -Algorithm SHA256
            ).Hash `
            -AcceptanceRecordUrl $recordUrl `
            -ReleaseManifestPath $duplicateKey.ReleaseManifestPath `
            -Tag $tag `
            -Commit $commit `
            -TagObject $tagObject *> $null
    }
    catch {
        $duplicatePlanRejected = $true
    }
    Assert-SelfTestCondition $duplicatePlanRejected (
        'manifest download plan accepted a duplicate-key record before the next GET'
    )

    $nonHttps = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'non-https')
    $manifest = Get-Content -LiteralPath $nonHttps.EvidencePath -Raw -Encoding utf8 |
        ConvertFrom-Json
    $manifest.categories[0].artifact_url = 'http://evidence.example/not-https.json'
    Write-JsonFixture -Path $nonHttps.EvidencePath -Value $manifest
    $record = Get-Content -LiteralPath $nonHttps.RecordPath -Raw -Encoding utf8 |
        ConvertFrom-Json
    $record.evidence_manifest_sha256 = (
        Get-FileHash -LiteralPath $nonHttps.EvidencePath -Algorithm SHA256
    ).Hash
    Write-JsonFixture -Path $nonHttps.RecordPath -Value $record
    Assert-Rejected -Fixture $nonHttps -Description 'non-HTTPS evidence artifact'

    $duplicateArtifactUrl = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'duplicate-artifact-url')
    $manifest = Get-Content `
        -LiteralPath $duplicateArtifactUrl.EvidencePath `
        -Raw `
        -Encoding utf8 | ConvertFrom-Json
    $manifest.categories[1].artifact_url = $manifest.categories[0].artifact_url
    Write-JsonFixture -Path $duplicateArtifactUrl.EvidencePath -Value $manifest
    $record = Get-Content `
        -LiteralPath $duplicateArtifactUrl.RecordPath `
        -Raw `
        -Encoding utf8 | ConvertFrom-Json
    $record.evidence_manifest_sha256 = (
        Get-FileHash `
            -LiteralPath $duplicateArtifactUrl.EvidencePath `
            -Algorithm SHA256
    ).Hash
    Write-JsonFixture -Path $duplicateArtifactUrl.RecordPath -Value $record
    Assert-Rejected `
        -Fixture $duplicateArtifactUrl `
        -Description 'duplicate evidence artifact URL'
    $duplicateArtifactPlanRejected = $false
    try {
        & $planScript `
            -Phase artifacts `
            -AcceptanceRecordPath $duplicateArtifactUrl.RecordPath `
            -AcceptanceRecordSha256 (
                Get-FileHash `
                    -LiteralPath $duplicateArtifactUrl.RecordPath `
                    -Algorithm SHA256
            ).Hash `
            -AcceptanceRecordUrl $recordUrl `
            -EvidenceManifestPath $duplicateArtifactUrl.EvidencePath `
            -ReleaseManifestPath $duplicateArtifactUrl.ReleaseManifestPath `
            -Tag $tag `
            -Commit $commit `
            -TagObject $tagObject *> $null
    }
    catch {
        $duplicateArtifactPlanRejected = $true
    }
    Assert-SelfTestCondition $duplicateArtifactPlanRejected (
        'artifact download plan accepted a duplicate evidence URL'
    )

    $tamperedManifest = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'tampered-manifest')
    [System.IO.File]::AppendAllText($tamperedManifest.EvidencePath, " ")
    Assert-Rejected -Fixture $tamperedManifest -Description 'evidence manifest hash mismatch'

    $missingArtifact = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'missing-artifact')
    [System.IO.File]::Delete(
        (Join-Path $missingArtifact.Root 'clean_install_smoke.evidence')
    )
    Assert-Rejected -Fixture $missingArtifact -Description 'missing evidence artifact'

    $artifactDigestMismatch = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'artifact-digest-mismatch')
    [System.IO.File]::AppendAllText(
        (Join-Path $artifactDigestMismatch.Root 'native_transfer_real_host.evidence'),
        'tampered'
    )
    Assert-Rejected `
        -Fixture $artifactDigestMismatch `
        -Description 'evidence artifact digest mismatch'

    $artifactUnknownField = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'artifact-unknown-field')
    $categoryName = 'clean_install_smoke'
    $artifactPath = Join-Path $artifactUnknownField.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $document.details | Add-Member -NotePropertyName password -NotePropertyValue 'forbidden'
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $artifactUnknownField -Category $categoryName
    Assert-Rejected -Fixture $artifactUnknownField -Description 'evidence secret field expansion'

    $cleanInstallWrongHost = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'clean-install-wrong-host')
    $categoryName = 'clean_install_smoke'
    $artifactPath = Join-Path $cleanInstallWrongHost.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $document.details.runner.os = 'Linux'
    $document.details.runner.rust_host = 'x86_64-unknown-linux-gnu'
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $cleanInstallWrongHost -Category $categoryName
    Assert-Rejected -Fixture $cleanInstallWrongHost -Description 'unsupported clean-install runtime host'

    $cleanInstallVersionDrift = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'clean-install-version-drift')
    $categoryName = 'clean_install_smoke'
    $artifactPath = Join-Path $cleanInstallVersionDrift.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $document.details.cli_identity.version = '0.3.0-beta.2'
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $cleanInstallVersionDrift -Category $categoryName
    Assert-Rejected -Fixture $cleanInstallVersionDrift -Description 'clean-install CLI version drift'

    $cleanInstallByteDrift = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'clean-install-byte-drift')
    $categoryName = 'clean_install_smoke'
    $artifactPath = Join-Path $cleanInstallByteDrift.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $document.details.cli_identity.sha256 = 'D' * 64
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $cleanInstallByteDrift -Category $categoryName
    Assert-Rejected `
        -Fixture $cleanInstallByteDrift `
        -Description 'clean-install CLI bytes not present in release provenance'

    $cleanInstallDaemonByteDrift = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'clean-install-daemon-byte-drift')
    $categoryName = 'clean_install_smoke'
    $artifactPath = Join-Path $cleanInstallDaemonByteDrift.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $document.details.daemon_identity.sha256 = 'D' * 64
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $cleanInstallDaemonByteDrift -Category $categoryName
    Assert-Rejected `
        -Fixture $cleanInstallDaemonByteDrift `
        -Description 'clean-install daemon bytes not present in release provenance'

    $cleanInstallProtocolMismatch = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'clean-install-protocol-mismatch')
    $categoryName = 'clean_install_smoke'
    $artifactPath = Join-Path $cleanInstallProtocolMismatch.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $document.details.daemon_identity.ipc_min = 8
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $cleanInstallProtocolMismatch -Category $categoryName
    Assert-Rejected -Fixture $cleanInstallProtocolMismatch -Description 'clean-install IPC mismatch'

    $cleanInstallStorageMismatch = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'clean-install-storage-mismatch')
    $categoryName = 'clean_install_smoke'
    $artifactPath = Join-Path $cleanInstallStorageMismatch.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $document.details.cli_identity.storage_contract = 'vault-storage read=v4 write=v4'
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $cleanInstallStorageMismatch -Category $categoryName
    Assert-Rejected `
        -Fixture $cleanInstallStorageMismatch `
        -Description 'clean-install storage contract mismatch'

    $cleanInstallCleanupGap = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'clean-install-cleanup-gap')
    $categoryName = 'clean_install_smoke'
    $artifactPath = Join-Path $cleanInstallCleanupGap.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $document.details.cleanup_passed = $false
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $cleanInstallCleanupGap -Category $categoryName
    Assert-Rejected -Fixture $cleanInstallCleanupGap -Description 'clean-install cleanup gap'

    $artifactTypeConfusion = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'artifact-type-confusion')
    $categoryName = 'native_transfer_real_host'
    $artifactPath = Join-Path $artifactTypeConfusion.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $document.test_counts.passed = '4'
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $artifactTypeConfusion -Category $categoryName
    Assert-Rejected -Fixture $artifactTypeConfusion -Description 'evidence count type confusion'

    $nativeMatrixGap = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'native-matrix-gap')
    $categoryName = 'native_transfer_real_host'
    $artifactPath = Join-Path $nativeMatrixGap.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $document.details.cases = @($document.details.cases | Select-Object -First 7)
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $nativeMatrixGap -Category $categoryName
    Assert-Rejected -Fixture $nativeMatrixGap -Description 'incomplete native size matrix'

    $nativeFaultGap = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'native-fault-gap')
    $categoryName = 'native_transfer_real_host'
    $artifactPath = Join-Path $nativeFaultGap.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $document.details.fault_cases = @($document.details.fault_cases | Select-Object -First 10)
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $nativeFaultGap -Category $categoryName
    Assert-Rejected -Fixture $nativeFaultGap -Description 'incomplete native fault matrix'

    $nativeResumeDrift = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'native-resume-drift')
    $artifactPath = Join-Path $nativeResumeDrift.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $document.details.fault_cases[0].resume_percent = 24
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $nativeResumeDrift -Category $categoryName
    Assert-Rejected -Fixture $nativeResumeDrift -Description 'native resume percentage drift'

    $nativeLostAckLie = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'native-lost-ack-lie')
    $artifactPath = Join-Path $nativeLostAckLie.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $lostAck = @($document.details.fault_cases | Where-Object { $_.scenario -ceq 'lost_ack' })[0]
    $lostAck.confirmed_advanced_without_ack = $true
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $nativeLostAckLie -Category $categoryName
    Assert-Rejected -Fixture $nativeLostAckLie -Description 'lost ACK advanced confirmation'

    $nativeUnknownCleanupLie = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'native-unknown-cleanup-lie')
    $artifactPath = Join-Path $nativeUnknownCleanupLie.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $unknownCleanup = @(
        $document.details.fault_cases |
            Where-Object { $_.scenario -ceq 'unknown_cleanup' }
    )[0]
    $unknownCleanup.result_code = 'transfer_failed'
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $nativeUnknownCleanupLie -Category $categoryName
    Assert-Rejected -Fixture $nativeUnknownCleanupLie -Description 'unknown cleanup misclassified'

    foreach ($terminalMutation in @(
        [ordered]@{
            name = 'native-disconnect-misclassified'
            scenario = 'disconnect'
            field = 'result_code'
            value = 'transfer_failed'
        },
        [ordered]@{
            name = 'native-daemon-restart-cleanup-drift'
            scenario = 'daemon_restart'
            field = 'cleanup_state'
            value = 'owned_partial_removed'
        },
        [ordered]@{
            name = 'native-target-link-cleanup-drift'
            scenario = 'target_symlink_or_reparse'
            field = 'cleanup_state'
            value = 'owned_partial_removed'
        }
    )) {
        $mutatedFixture = Copy-FixtureSet `
            -Source $baseline.Root `
            -Destination (Join-Path $temporaryRoot $terminalMutation.name)
        $artifactPath = Join-Path $mutatedFixture.Root "$categoryName.evidence"
        $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 |
            ConvertFrom-Json
        $fault = @(
            $document.details.fault_cases |
                Where-Object { $_.scenario -ceq $terminalMutation.scenario }
        )[0]
        $fault.($terminalMutation.field) = $terminalMutation.value
        Write-JsonFixture -Path $artifactPath -Value $document
        Update-FixtureBindings -Fixture $mutatedFixture -Category $categoryName
        Assert-Rejected `
            -Fixture $mutatedFixture `
            -Description "$($terminalMutation.scenario) terminal classification drift"
    }

    $nativeRegistryDrift = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'native-registry-drift')
    $artifactPath = Join-Path $nativeRegistryDrift.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $document.details.registry_window.active_global = 49
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $nativeRegistryDrift -Category $categoryName
    Assert-Rejected -Fixture $nativeRegistryDrift -Description 'native registry limit drift'

    $nativeHelperByteDrift = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'native-helper-byte-drift')
    $categoryName = 'native_transfer_real_host'
    $artifactPath = Join-Path $nativeHelperByteDrift.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $document.details.components.helper.sha256 = 'D' * 64
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $nativeHelperByteDrift -Category $categoryName
    Assert-Rejected `
        -Fixture $nativeHelperByteDrift `
        -Description 'native helper bytes not present in release provenance'

    $nativeCliByteDrift = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'native-cli-byte-drift')
    $artifactPath = Join-Path $nativeCliByteDrift.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $document.details.components.cli.sha256 = 'D' * 64
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $nativeCliByteDrift -Category $categoryName
    Assert-Rejected `
        -Fixture $nativeCliByteDrift `
        -Description 'native CLI bytes not present in release provenance'

    $nativeHelperSizeDrift = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'native-helper-size-drift')
    $artifactPath = Join-Path $nativeHelperSizeDrift.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $document.details.components.helper.binary_size = (
        [long]$document.details.components.helper.binary_size + 1
    )
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $nativeHelperSizeDrift -Category $categoryName
    Assert-Rejected `
        -Fixture $nativeHelperSizeDrift `
        -Description 'native helper size not present in release provenance'

    $nativeCliSizeTypeConfusion = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'native-cli-size-type-confusion')
    $artifactPath = Join-Path $nativeCliSizeTypeConfusion.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $document.details.components.cli.binary_size = "$($script:releaseCliSize)"
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $nativeCliSizeTypeConfusion -Category $categoryName
    Assert-Rejected `
        -Fixture $nativeCliSizeTypeConfusion `
        -Description 'native CLI size type confusion'

    $nativeDaemonSizeMissing = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'native-daemon-size-missing')
    $artifactPath = Join-Path $nativeDaemonSizeMissing.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $document.details.components.daemon.PSObject.Properties.Remove('binary_size')
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $nativeDaemonSizeMissing -Category $categoryName
    Assert-Rejected `
        -Fixture $nativeDaemonSizeMissing `
        -Description 'native daemon size missing'

    $nativeCliSizeNegative = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'native-cli-size-negative')
    $artifactPath = Join-Path $nativeCliSizeNegative.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $document.details.components.cli.binary_size = -1
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $nativeCliSizeNegative -Category $categoryName
    Assert-Rejected `
        -Fixture $nativeCliSizeNegative `
        -Description 'native CLI size negative'

    $nativeHelperNameDrift = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'native-helper-name-drift')
    $artifactPath = Join-Path $nativeHelperNameDrift.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $document.details.components.helper.name = 'SERCTL-XFER'
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $nativeHelperNameDrift -Category $categoryName
    Assert-Rejected `
        -Fixture $nativeHelperNameDrift `
        -Description 'native helper name drift'

    $nativeDaemonIdentityDrift = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'native-daemon-identity-drift')
    $artifactPath = Join-Path $nativeDaemonIdentityDrift.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $document.details.components.daemon.version = (
        [string]$document.details.components.daemon.version
    ).Replace('IPC v9..=v9', 'IPC v8..=v8')
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $nativeDaemonIdentityDrift -Category $categoryName
    Assert-Rejected `
        -Fixture $nativeDaemonIdentityDrift `
        -Description 'native daemon identity protocol drift'

    $fixedPayloadDigestDrift = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'native-fixed-payload-digest-drift')
    $artifactPath = Join-Path $fixedPayloadDigestDrift.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $document.details.cases[0].sha256 = 'F' * 64
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $fixedPayloadDigestDrift -Category $categoryName
    Assert-Rejected `
        -Fixture $fixedPayloadDigestDrift `
        -Description 'native fixed payload digest drift'

    $nativeRunnerDrift = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'native-runner-tuple-drift')
    $categoryName = 'native_transfer_real_host'
    $artifactPath = Join-Path $nativeRunnerDrift.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $document.details.runner.rust_host = 'x86_64-pc-windows-gnu'
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $nativeRunnerDrift -Category $categoryName
    Assert-Rejected -Fixture $nativeRunnerDrift -Description 'native runner tuple drift'

    $fabricatedPerformanceRatio = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'fabricated-performance-ratio')
    $categoryName = 'native_transfer_real_host'
    $artifactPath = Join-Path $fabricatedPerformanceRatio.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $document.details.performance.throughput_ratio_percent = 91
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $fabricatedPerformanceRatio -Category $categoryName
    Assert-Rejected `
        -Fixture $fabricatedPerformanceRatio `
        -Description 'fabricated native performance ratio'

    $nonIntegerPerformanceRatio = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'non-integer-performance-ratio')
    $categoryName = 'native_transfer_real_host'
    $artifactPath = Join-Path $nonIntegerPerformanceRatio.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $document.details.performance.throughput_ratio_percent = 'NaN'
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $nonIntegerPerformanceRatio -Category $categoryName
    Assert-Rejected `
        -Fixture $nonIntegerPerformanceRatio `
        -Description 'non-integer native performance ratio'

    $overflowPerformanceInput = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'overflow-performance-input')
    $categoryName = 'native_transfer_real_host'
    $artifactPath = Join-Path $overflowPerformanceInput.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $document.details.performance.native_p50_bytes_per_second = [decimal]::MaxValue
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $overflowPerformanceInput -Category $categoryName
    Assert-Rejected `
        -Fixture $overflowPerformanceInput `
        -Description 'overflow-shaped native performance input'

    $rawPerformanceSummaryDrift = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'native-raw-performance-summary-drift')
    $artifactPath = Join-Path $rawPerformanceSummaryDrift.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $document.details.performance.native_samples[2].elapsed_microseconds = 900000
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $rawPerformanceSummaryDrift -Category $categoryName
    Assert-Rejected `
        -Fixture $rawPerformanceSummaryDrift `
        -Description 'native raw performance summary mismatch'

    $wholeBundleMatrixGap = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'whole-bundle-matrix-gap')
    $categoryName = 'whole_bundle_upgrade_rollback'
    $artifactPath = Join-Path $wholeBundleMatrixGap.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $document.details.mixed_triples_rejected = 5
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $wholeBundleMatrixGap -Category $categoryName
    Assert-Rejected -Fixture $wholeBundleMatrixGap -Description 'incomplete mixed-bundle rejection matrix'

    foreach ($component in @('cli_sha256', 'daemon_sha256', 'xfer_sha256')) {
        $wholeBundleByteDrift = Copy-FixtureSet `
            -Source $baseline.Root `
            -Destination (Join-Path $temporaryRoot "whole-bundle-$component-byte-drift")
        $categoryName = 'whole_bundle_upgrade_rollback'
        $artifactPath = Join-Path $wholeBundleByteDrift.Root "$categoryName.evidence"
        $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
        $document.details.candidate_files.$component = '9' * 64
        Write-JsonFixture -Path $artifactPath -Value $document
        Update-FixtureBindings -Fixture $wholeBundleByteDrift -Category $categoryName
        Assert-Rejected `
            -Fixture $wholeBundleByteDrift `
            -Description "whole-bundle candidate $component not present in release provenance"
    }

    $wholeBundleRunnerDrift = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'whole-bundle-runner-tuple-drift')
    $categoryName = 'whole_bundle_upgrade_rollback'
    $artifactPath = Join-Path $wholeBundleRunnerDrift.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $document.details.runner.os = 'Linux'
    $document.details.runner.rust_host = 'x86_64-unknown-linux-gnu'
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $wholeBundleRunnerDrift -Category $categoryName
    Assert-Rejected `
        -Fixture $wholeBundleRunnerDrift `
        -Description 'whole-bundle runner tuple drift'

    $wholeBundlePredecessorDrift = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'whole-bundle-predecessor-version-drift')
    $categoryName = 'whole_bundle_upgrade_rollback'
    $artifactPath = Join-Path $wholeBundlePredecessorDrift.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $document.details.predecessor_version = '0.3.0-beta.1'
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $wholeBundlePredecessorDrift -Category $categoryName
    Assert-Rejected `
        -Fixture $wholeBundlePredecessorDrift `
        -Description 'whole-bundle predecessor version drift'

    $wholeBundleCandidateDrift = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'whole-bundle-candidate-version-drift')
    $categoryName = 'whole_bundle_upgrade_rollback'
    $artifactPath = Join-Path $wholeBundleCandidateDrift.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $document.details.candidate_version = '1.0.0-beta.1'
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $wholeBundleCandidateDrift -Category $categoryName
    Assert-Rejected `
        -Fixture $wholeBundleCandidateDrift `
        -Description 'whole-bundle candidate version drift'

    $wholeBundleDescriptorIdentityDrift = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'whole-bundle-descriptor-identity-drift')
    $categoryName = 'whole_bundle_upgrade_rollback'
    $artifactPath = Join-Path $wholeBundleDescriptorIdentityDrift.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $document.details.descriptor_daemon_identity = 'serctl_daemon 1.0.0-beta IPC v9'
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $wholeBundleDescriptorIdentityDrift -Category $categoryName
    Assert-Rejected `
        -Fixture $wholeBundleDescriptorIdentityDrift `
        -Description 'whole-bundle descriptor identity drift'

    $wholeBundleDescriptorShaDrift = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'whole-bundle-descriptor-sha-drift')
    $categoryName = 'whole_bundle_upgrade_rollback'
    $artifactPath = Join-Path $wholeBundleDescriptorShaDrift.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $document.details.descriptor_daemon_sha256 = '9' * 64
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $wholeBundleDescriptorShaDrift -Category $categoryName
    Assert-Rejected `
        -Fixture $wholeBundleDescriptorShaDrift `
        -Description 'whole-bundle descriptor daemon SHA drift'

    $wholeBundleStorageGap = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'whole-bundle-storage-gap')
    $categoryName = 'whole_bundle_upgrade_rollback'
    $artifactPath = Join-Path $wholeBundleStorageGap.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $document.details.v8_unknown_audit_fields_rejected_before_write = $false
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $wholeBundleStorageGap -Category $categoryName
    Assert-Rejected `
        -Fixture $wholeBundleStorageGap `
        -Description 'v8 audit-field rejection without writeback was not proven'

    $wholeBundleActivationObservationMissing = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'whole-bundle-activation-observation-missing')
    $categoryName = 'whole_bundle_upgrade_rollback'
    $artifactPath = Join-Path $wholeBundleActivationObservationMissing.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $document.details.PSObject.Properties.Remove('beta2_transient_runtime_activation_observed')
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $wholeBundleActivationObservationMissing -Category $categoryName
    Assert-Rejected `
        -Fixture $wholeBundleActivationObservationMissing `
        -Description 'missing beta-2 transient runtime activation observation'

    $wholeBundleActivationObservationReplaced = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'whole-bundle-activation-observation-replaced')
    $categoryName = 'whole_bundle_upgrade_rollback'
    $artifactPath = Join-Path $wholeBundleActivationObservationReplaced.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $document.details.beta2_transient_runtime_activation_observed = 'false'
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $wholeBundleActivationObservationReplaced -Category $categoryName
    Assert-Rejected `
        -Fixture $wholeBundleActivationObservationReplaced `
        -Description 'non-boolean beta-2 transient runtime activation observation'

    $wholeBundleRuntimeCleanupGap = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'whole-bundle-runtime-cleanup-gap')
    $categoryName = 'whole_bundle_upgrade_rollback'
    $artifactPath = Join-Path $wholeBundleRuntimeCleanupGap.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $document.details.beta2_runtime_state_cleaned_after_rejection = $false
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $wholeBundleRuntimeCleanupGap -Category $categoryName
    Assert-Rejected `
        -Fixture $wholeBundleRuntimeCleanupGap `
        -Description 'beta-2 rejection left residual descriptor or activation secret state'

    $wholeBundleOuterGateGap = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'whole-bundle-outer-gate-gap')
    $categoryName = 'whole_bundle_upgrade_rollback'
    $artifactPath = Join-Path $wholeBundleOuterGateGap.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $document.details.beta2_destructive_writer_blocked_before_mutation = $false
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $wholeBundleOuterGateGap -Category $categoryName
    Assert-Rejected `
        -Fixture $wholeBundleOuterGateGap `
        -Description 'beta-2 destructive writer was not blocked by the outer format gate'

    $wholeBundleStorageMarkerGap = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'whole-bundle-storage-marker-gap')
    $categoryName = 'whole_bundle_upgrade_rollback'
    $artifactPath = Join-Path $wholeBundleStorageMarkerGap.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $document.details.candidate_storage_marker_verified = $false
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $wholeBundleStorageMarkerGap -Category $categoryName
    Assert-Rejected `
        -Fixture $wholeBundleStorageMarkerGap `
        -Description 'candidate embedded storage marker was not verified'

    $wholeBundleRecoverySetGap = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'whole-bundle-recovery-set-gap')
    $categoryName = 'whole_bundle_upgrade_rollback'
    $artifactPath = Join-Path $wholeBundleRecoverySetGap.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $document.details.matching_recovery_media_restored = $false
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $wholeBundleRecoverySetGap -Category $categoryName
    Assert-Rejected `
        -Fixture $wholeBundleRecoverySetGap `
        -Description 'incomplete vault recovery set'

    $interopRunnerDrift = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'interop-runner-tuple-drift')
    $categoryName = 'openssh_dropbear_interop'
    $artifactPath = Join-Path $interopRunnerDrift.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $document.details.runner.os = 'Windows'
    $document.details.runner.rust_host = 'x86_64-pc-windows-msvc'
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $interopRunnerDrift -Category $categoryName
    Assert-Rejected -Fixture $interopRunnerDrift -Description 'interop runner tuple drift'

    $interopAggregateContextDrift = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'interop-aggregate-context-drift')
    $categoryName = 'openssh_dropbear_interop'
    $artifactPath = Join-Path $interopAggregateContextDrift.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $document.details.evidence_context_sha256 = 'D' * 64
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $interopAggregateContextDrift -Category $categoryName
    Assert-Rejected `
        -Fixture $interopAggregateContextDrift `
        -Description 'interop aggregate evidence context replacement'

    $interopOperationContextDrift = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'interop-operation-context-drift')
    $artifactPath = Join-Path $interopOperationContextDrift.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $document.details.case_receipts[0].operation_context_sha256 = 'E' * 64
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $interopOperationContextDrift -Category $categoryName
    Assert-Rejected `
        -Fixture $interopOperationContextDrift `
        -Description 'interop operation context replacement'

    $interopSummaryInjection = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'interop-summary-injection')
    $artifactPath = Join-Path $interopSummaryInjection.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $document.details | Add-Member -NotePropertyName summary -NotePropertyValue ([ordered]@{
        passed = $true; result = 'completed'
    })
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $interopSummaryInjection -Category $categoryName
    Assert-Rejected `
        -Fixture $interopSummaryInjection `
        -Description 'interop caller summary injection'

    $interopDuplicate = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'interop-duplicate')
    $categoryName = 'openssh_dropbear_interop'
    $artifactPath = Join-Path $interopDuplicate.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $document.details.implementations = @(
        $document.details.implementations[0],
        $document.details.implementations[1],
        $document.details.implementations[0]
    )
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $interopDuplicate -Category $categoryName
    Assert-Rejected `
        -Fixture $interopDuplicate `
        -Description 'duplicate OpenSSH interop implementation'

    $interopCaseGap = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'interop-case-gap')
    $artifactPath = Join-Path $interopCaseGap.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $document.details.case_receipts = @(
        $document.details.case_receipts |
            Where-Object { $_.case_id -cne 'OpenSSH_tunnel_dynamic' }
    )
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $interopCaseGap -Category $categoryName
    Assert-Rejected -Fixture $interopCaseGap -Description 'missing exact-once interop receipt'

    $interopExtraCase = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'interop-extra-case')
    $artifactPath = Join-Path $interopExtraCase.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $extraContextSha256 = Get-OperationContextFixtureSha256 `
        -Category 'openssh_dropbear_interop' `
        -CaseId 'OpenSSH_tunnel_extra'
    $document.details.case_receipts = @($document.details.case_receipts) + @(
        New-RuntimeObservationFixture `
            -Category 'openssh_dropbear_interop' `
            -CaseId 'OpenSSH_tunnel_extra' `
            -ResultCode 'completed' `
            -ContextSha256 $extraContextSha256
    )
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $interopExtraCase -Category $categoryName
    Assert-Rejected -Fixture $interopExtraCase -Description 'extra interop receipt'

    $interopTunnelMisclassified = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'interop-tunnel-misclassified')
    $artifactPath = Join-Path $interopTunnelMisclassified.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $entry = @(
        $document.details.case_receipts |
            Where-Object { $_.case_id -ceq 'OpenSSH_tunnel_dynamic' }
    )[0]
    $receiptBytes = [Convert]::FromBase64String([string]$entry.receipt_base64)
    $receipt = [System.Text.UTF8Encoding]::new($false, $true).GetString($receiptBytes) |
        ConvertFrom-Json
    $receipt.result_code = 'outcome_unknown'
    $receiptBytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
        ($receipt | ConvertTo-Json -Depth 6 -Compress) + "`n"
    )
    $entry.receipt_base64 = [Convert]::ToBase64String($receiptBytes)
    $entry.receipt_sha256 = Get-FileHashFromBytes -Bytes $receiptBytes
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $interopTunnelMisclassified -Category $categoryName
    Assert-Rejected `
        -Fixture $interopTunnelMisclassified `
        -Description 'OpenSSH dynamic tunnel terminal classification drift'

    $interopContextDrift = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'interop-child-context-drift')
    $artifactPath = Join-Path $interopContextDrift.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $entry = @(
        $document.details.case_receipts |
            Where-Object { $_.case_id -ceq 'OpenSSH_directory' }
    )[0]
    $receiptBytes = [Convert]::FromBase64String([string]$entry.receipt_base64)
    $receipt = [System.Text.UTF8Encoding]::new($false, $true).GetString($receiptBytes) |
        ConvertFrom-Json
    $receipt.context_sha256 = 'D' * 64
    $receiptBytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
        ($receipt | ConvertTo-Json -Depth 6 -Compress) + "`n"
    )
    $entry.receipt_base64 = [Convert]::ToBase64String($receiptBytes)
    $entry.receipt_sha256 = Get-FileHashFromBytes -Bytes $receiptBytes
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $interopContextDrift -Category $categoryName
    Assert-Rejected `
        -Fixture $interopContextDrift `
        -Description 'interop protected child execution context drift'

    $interopReceiptReuse = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'interop-receipt-reuse')
    $artifactPath = Join-Path $interopReceiptReuse.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $document.details.case_receipts[1].receipt_sha256 = (
        [string]$document.details.case_receipts[0].receipt_sha256
    )
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $interopReceiptReuse -Category $categoryName
    Assert-Rejected -Fixture $interopReceiptReuse -Description 'reused interop case receipt digest'

    $interopReceiptByteDrift = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'interop-protected-receipt-byte-drift')
    $artifactPath = Join-Path $interopReceiptByteDrift.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $document.details.case_receipts[0].receipt_base64 = (
        [string]$document.details.case_receipts[0].receipt_base64
    ).Substring(0, ([string]$document.details.case_receipts[0].receipt_base64).Length - 4) + 'AAAA'
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $interopReceiptByteDrift -Category $categoryName
    Assert-Rejected `
        -Fixture $interopReceiptByteDrift `
        -Description 'interop protected child receipt byte drift'

    $interopComponentDrift = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'interop-component-drift')
    $artifactPath = Join-Path $interopComponentDrift.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $document.details.components.helper.version = (
        [string]$document.details.components.helper.version
    ).Replace('transfer protocol v1', 'transfer protocol v2')
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $interopComponentDrift -Category $categoryName
    Assert-Rejected `
        -Fixture $interopComponentDrift `
        -Description 'interop component identity drift'

    $artifactAbsolutePath = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'artifact-absolute-path')
    $categoryName = 'openssh_dropbear_interop'
    $artifactPath = Join-Path $artifactAbsolutePath.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $document.details.runner.label = 'C:\\private\\runner'
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $artifactAbsolutePath -Category $categoryName
    Assert-Rejected -Fixture $artifactAbsolutePath -Description 'evidence absolute local path'

    $unsafeRetainedValues = [ordered]@{
        root_relative_path = '\Users\operator\secret.txt'
        drive_relative_path = 'C:relative\secret.txt'
        traversal_path = '..\private\secret.txt'
        bearer_secret = 'Authorization: Bearer abc123'
    }
    foreach ($unsafeName in $unsafeRetainedValues.Keys) {
        $unsafeFixture = Copy-FixtureSet `
            -Source $baseline.Root `
            -Destination (Join-Path $temporaryRoot "retained-$unsafeName")
        $artifactPath = Join-Path $unsafeFixture.Root 'openssh_dropbear_interop.evidence'
        $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
        $document.details.runner.label = [string]$unsafeRetainedValues[$unsafeName]
        Write-JsonFixture -Path $artifactPath -Value $document
        Update-FixtureBindings -Fixture $unsafeFixture -Category 'openssh_dropbear_interop'
        Assert-Rejected -Fixture $unsafeFixture -Description "unsafe retained value $unsafeName"
    }

    $artifactFalseOutcome = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'artifact-false-outcome')
    $categoryName = 'windows_privileged_acl'
    $artifactPath = Join-Path $artifactFalseOutcome.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $document.details.observer_read_denied = $false
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $artifactFalseOutcome -Category $categoryName
    Assert-Rejected -Fixture $artifactFalseOutcome -Description 'failed privileged ACL outcome'

    $aclCandidateByteDrift = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'acl-candidate-byte-drift')
    $categoryName = 'windows_privileged_acl'
    $artifactPath = Join-Path $aclCandidateByteDrift.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $document.details.candidate_cli_sha256 = 'D' * 64
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $aclCandidateByteDrift -Category $categoryName
    Assert-Rejected `
        -Fixture $aclCandidateByteDrift `
        -Description 'Windows ACL candidate CLI bytes not present in release provenance'

    $aclRunnerDrift = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'acl-runner-tuple-drift')
    $categoryName = 'windows_privileged_acl'
    $artifactPath = Join-Path $aclRunnerDrift.Root "$categoryName.evidence"
    $document = Get-Content -LiteralPath $artifactPath -Raw -Encoding utf8 | ConvertFrom-Json
    $document.details.runner.os = 'Linux'
    $document.details.runner.rust_host = 'x86_64-unknown-linux-gnu'
    Write-JsonFixture -Path $artifactPath -Value $document
    Update-FixtureBindings -Fixture $aclRunnerDrift -Category $categoryName
    Assert-Rejected -Fixture $aclRunnerDrift -Description 'ACL runner tuple drift'

    $artifactInvalidUtf8 = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'artifact-invalid-utf8')
    $categoryName = 'whole_bundle_upgrade_rollback'
    $artifactPath = Join-Path $artifactInvalidUtf8.Root "$categoryName.evidence"
    [System.IO.File]::WriteAllBytes(
        $artifactPath,
        [byte[]](0x7B, 0x22, 0x78, 0x22, 0x3A, 0x22, 0xC3, 0x28, 0x22, 0x7D)
    )
    Update-FixtureBindings -Fixture $artifactInvalidUtf8 -Category $categoryName
    Assert-Rejected -Fixture $artifactInvalidUtf8 -Description 'invalid UTF-8 evidence artifact'

    $oversizedArtifact = Copy-FixtureSet `
        -Source $baseline.Root `
        -Destination (Join-Path $temporaryRoot 'oversized-artifact')
    $oversizedPath = Join-Path $oversizedArtifact.Root 'openssh_dropbear_interop.evidence'
    $oversizedStream = [System.IO.File]::OpenWrite($oversizedPath)
    try {
        $oversizedStream.SetLength(8388609)
    }
    finally {
        $oversizedStream.Dispose()
    }
    Assert-Rejected -Fixture $oversizedArtifact -Description 'oversized evidence artifact'

    $invalidDownloadTarget = Join-Path $temporaryRoot 'invalid-download.json'
    $boundedDownloader = Join-Path $PSScriptRoot 'Save-BoundedHttpsFile.ps1'
    $invalidDownloadRejected = $false
    try {
        $global:LASTEXITCODE = 0
        & $boundedDownloader `
            -Url 'http://example.invalid/not-https' `
            -Destination $invalidDownloadTarget `
            -MaxBytes 64 *> $null
        $invalidDownloadRejected = $LASTEXITCODE -ne 0
    }
    catch {
        $invalidDownloadRejected = $true
    }
    Assert-SelfTestCondition $invalidDownloadRejected 'non-HTTPS download URL was accepted'
    Assert-SelfTestCondition (-not (Test-Path -LiteralPath $invalidDownloadTarget)) (
        'rejected download created its destination'
    )
}
finally {
    if (Test-Path -LiteralPath $temporaryRoot -PathType Container) {
        [System.IO.Directory]::Delete($temporaryRoot, $true)
    }
}

Write-Host 'External acceptance evidence self-tests passed.'
