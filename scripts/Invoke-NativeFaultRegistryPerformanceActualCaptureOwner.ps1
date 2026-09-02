[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$ReceiptPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$scriptRoot = Split-Path -Parent $PSCommandPath
. (Join-Path $scriptRoot 'StrictJson.ps1')
. (Join-Path $scriptRoot 'NativeFaultRegistryPerformanceActualCaptureLauncher.ps1')

function Assert-NativeFixtureOwner {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "native fixture actual-capture owner failed: $Message" }
}

function Assert-NativeFixtureClosedObject {
    param($Value, [string[]]$Names, [string]$Label)
    Assert-NativeFixtureOwner (Test-StrictJsonObject $Value) "$Label is not an object"
    $actual = @($Value.PSObject.Properties.Name | Sort-Object)
    $expected = @($Names | Sort-Object)
    Assert-NativeFixtureOwner (
        $actual.Count -eq $expected.Count -and
        (@(Compare-Object $actual $expected -CaseSensitive).Count -eq 0)
    ) "$Label has an open or incomplete schema"
}

function Get-NativeFixtureSha256 {
    param([byte[]]$Bytes)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Get-NativeFixturePercentile {
    param([long[]]$Values, [int]$Index)
    $sorted = @($Values | Sort-Object)
    return [long]$sorted[$Index]
}

$capture = $null
$stdout = $null
$stderr = $null
$receiptBytes = $null
$temporaryPath = $null
try {
    $capture = Invoke-NativeFixtureFixedPowerShellInternal -Role fixture -DeadlineMilliseconds 300000
    $stdout = [byte[]]$capture.stdout
    $stderr = [byte[]]$capture.stderr
    Assert-NativeFixtureOwner (
        $capture.exit_category -ceq 'completed_success' -and
        $capture.exit_code -eq 0 -and $capture.process_tree_exited -and
        $stderr.Length -eq 0
    ) 'fixed child did not produce a clean supervised terminal'
    Assert-NativeFixtureOwner ($stdout.Length -gt 0 -and $stdout.Length -le 4194304) (
        'fixed child stdout is outside its bound'
    )
    try { $text = [Text.UTF8Encoding]::new($false, $true).GetString($stdout) }
    catch { throw 'native fixture actual-capture owner failed: fixed child stdout is not strict UTF-8' }
    Assert-NativeFixtureOwner (
        $text.EndsWith("`n") -and -not $text.Contains("`r") -and
        $text.IndexOf("`n") -eq ($text.Length - 1)
    ) 'fixed child did not emit exactly one canonical JSON line'
    $raw = ConvertFrom-StrictJson $text.Substring(0, $text.Length - 1) 'native fixture raw facts'
    Assert-NativeFixtureClosedObject $raw @(
        'schema_version', 'fault_events', 'registry_events', 'performance_samples'
    ) 'raw facts'
    Assert-NativeFixtureOwner (
        (Test-StrictJsonString $raw.schema_version) -and
        [string]$raw.schema_version -ceq 'serctl-native-fixture-raw-v1'
    ) 'raw schema version is not fixed'

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
        target_symlink_or_reparse = @('transfer_failed', 0, 'no_owned_partial_created')
        unknown_cleanup = @('cleanup_incomplete', 0, 'cleanup_incomplete')
    }
    Assert-NativeFixtureOwner (
        (Test-StrictJsonArray $raw.fault_events) -and @($raw.fault_events).Count -eq 11
    ) 'fault fixture does not contain exactly eleven cases'
    $faultCases = @()
    $seenFaults = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($fault in @($raw.fault_events)) {
        Assert-NativeFixtureClosedObject $fault @(
            'scenario', 'resume_percent', 'terminal_event', 'acknowledged_offset',
            'confirmed_offset', 'owned_partial_created', 'owned_partial_removed',
            'foreign_partial_touched', 'target_replaced', 'cleanup_attempted',
            'cleanup_confirmed'
        ) 'fault event'
        $scenario = [string]$fault.scenario
        Assert-NativeFixtureOwner ($expectedFaults.Contains($scenario) -and $seenFaults.Add($scenario)) (
            'fault case set is not exact'
        )
        $terminal = switch ([string]$fault.terminal_event) {
            'completed' { 'completed' }
            'unknown' { 'outcome_unknown' }
            'failed' { 'transfer_failed' }
            'cleanup_incomplete' { 'cleanup_incomplete' }
            default { throw 'native fixture actual-capture owner failed: unknown fault terminal event' }
        }
        $cleanupState = if ([bool]$fault.owned_partial_removed -and [bool]$fault.cleanup_confirmed) {
            'owned_partial_removed'
        } elseif (-not [bool]$fault.owned_partial_created) {
            'no_owned_partial_created'
        } elseif ([bool]$fault.cleanup_attempted -and -not [bool]$fault.cleanup_confirmed) {
            'cleanup_incomplete'
        } else {
            'owned_partial_preserved'
        }
        if ($terminal -ceq 'completed') { $cleanupState = 'complete' }
        $expected = $expectedFaults[$scenario]
        $confirmedWithoutAck = [long]$fault.confirmed_offset -gt [long]$fault.acknowledged_offset
        $safe = -not $confirmedWithoutAck -and -not [bool]$fault.target_replaced -and
            -not [bool]$fault.foreign_partial_touched
        Assert-NativeFixtureOwner (
            $terminal -ceq [string]$expected[0] -and
            [int]$fault.resume_percent -eq [int]$expected[1] -and
            $cleanupState -ceq [string]$expected[2] -and $safe
        ) "fault case '$scenario' violated its fixed semantics"
        $faultCases += [pscustomobject][ordered]@{
            scenario = $scenario
            result_code = $terminal
            resume_percent = [int]$fault.resume_percent
            cleanup_state = $cleanupState
            confirmed_advanced_without_ack = $confirmedWithoutAck
            target_overwritten = [bool]$fault.target_replaced
            foreign_partial_deleted = [bool]$fault.foreign_partial_touched
            passed = $safe
        }
    }

    $registry = $raw.registry_events
    Assert-NativeFixtureClosedObject $registry @(
        'active_attempts', 'terminal_attempts', 'retention_seconds_observed',
        'ack_trace', 'control_frame_lengths', 'negotiated'
    ) 'registry events'
    $active = @($registry.active_attempts)
    $terminal = @($registry.terminal_attempts)
    Assert-NativeFixtureOwner ($active.Count -eq 54 -and $terminal.Count -eq 272) (
        'registry attempt cardinality changed'
    )
    $activeAccepted = @($active | Where-Object { [bool]$_.accepted })
    $terminalRetained = @($terminal | Where-Object { [bool]$_.retained })
    $activePerProfile = [long](($activeAccepted | Group-Object profile | ForEach-Object Count |
        Measure-Object -Maximum).Maximum)
    $terminalPerProfile = [long](($terminalRetained | Group-Object profile | ForEach-Object Count |
        Measure-Object -Maximum).Maximum)
    $profileIsolation = @($active + $terminal | Where-Object {
        [string]$_.profile -cne [string]$_.visible_to_profile
    }).Count -eq 0
    $confirmedBeforeAck = @($registry.ack_trace | Where-Object {
        [long]$_.confirmed -gt [long]$_.acknowledged
    }).Count -gt 0
    $controlFrameBound = [long](($registry.control_frame_lengths | Measure-Object -Maximum).Maximum) -le 1048576
    $negotiated = $registry.negotiated
    Assert-NativeFixtureClosedObject $negotiated @(
        'sftp_write_bytes', 'sftp_inflight_writes', 'native_chunk_bytes',
        'native_ack_window_bytes'
    ) 'registry negotiated event'
    $registryWindow = [pscustomobject][ordered]@{
        active_per_profile = $activePerProfile
        active_global = [long]$activeAccepted.Count
        terminal_per_profile = $terminalPerProfile
        terminal_global = [long]$terminalRetained.Count
        retention_max_seconds = [long](($registry.retention_seconds_observed | Measure-Object -Maximum).Maximum)
        sftp_write_bytes = [int]$negotiated.sftp_write_bytes
        sftp_inflight_writes = [int]$negotiated.sftp_inflight_writes
        native_chunk_bytes = [int]$negotiated.native_chunk_bytes
        native_ack_window_bytes = [int]$negotiated.native_ack_window_bytes
        profile_isolation_passed = $profileIsolation
        control_frame_bound_passed = $controlFrameBound
        confirmed_before_ack = $confirmedBeforeAck
    }
    Assert-NativeFixtureOwner (
        $activePerProfile -eq 8 -and $activeAccepted.Count -eq 48 -and
        $terminalPerProfile -eq 16 -and $terminalRetained.Count -eq 256 -and
        $registryWindow.retention_max_seconds -eq 900 -and $profileIsolation -and
        $controlFrameBound -and -not $confirmedBeforeAck -and
        $registryWindow.sftp_write_bytes -eq 2048 -and
        $registryWindow.sftp_inflight_writes -eq 1 -and
        $registryWindow.native_chunk_bytes -eq 32768 -and
        $registryWindow.native_ack_window_bytes -eq 32768
    ) 'registry/window facts did not reproduce their fixed bounds'

    Assert-NativeFixtureClosedObject $raw.performance_samples @('native', 'scp') 'performance facts'
    $performanceByBackend = [ordered]@{}
    foreach ($backend in @('native', 'scp')) {
        $samples = @($raw.performance_samples.$backend)
        Assert-NativeFixtureOwner ($samples.Count -eq 5) "$backend sample count is not five"
        $normalized = @()
        foreach ($sample in $samples) {
            Assert-NativeFixtureClosedObject $sample @(
                'backend', 'sample_index', 'size_bytes', 'work_repetitions', 'elapsed_microseconds',
                'cpu_microseconds', 'peak_working_set_bytes', 'rtt_microseconds', 'checksum'
            ) "$backend performance sample"
            Assert-NativeFixtureOwner (
                [string]$sample.backend -ceq $backend -and
                [long]$sample.size_bytes -eq 67108864 -and
                [int]$sample.work_repetitions -eq 16 -and
                [long]$sample.elapsed_microseconds -gt 0 -and
                [long]$sample.cpu_microseconds -gt 0 -and
                [long]$sample.peak_working_set_bytes -gt 0 -and
                [long]$sample.rtt_microseconds -gt 0
            ) "$backend performance sample is invalid"
            $cpuBasisPoints = [long][Math]::Floor(
                ([decimal][long]$sample.cpu_microseconds * 10000) /
                [decimal][long]$sample.elapsed_microseconds
            )
            $normalized += [pscustomobject][ordered]@{
                sample_index = [int]$sample.sample_index
                size_bytes = [long]$sample.size_bytes
                work_repetitions = [int]$sample.work_repetitions
                elapsed_microseconds = [long]$sample.elapsed_microseconds
                bytes_per_second = [long][Math]::Floor(
                    ([decimal][long]$sample.size_bytes *
                        [decimal][int]$sample.work_repetitions * 1000000) /
                    [decimal][long]$sample.elapsed_microseconds
                )
                cpu_basis_points = $cpuBasisPoints
                peak_rss_bytes = [long]$sample.peak_working_set_bytes
                rtt_microseconds = [long]$sample.rtt_microseconds
            }
        }
        Assert-NativeFixtureOwner (
            @($normalized.sample_index | Sort-Object -Unique).Count -eq 5 -and
            @($normalized.sample_index | Sort-Object) -join ',' -ceq '1,2,3,4,5'
        ) "$backend sample indexes are not exact"
        $performanceByBackend[$backend] = $normalized
    }
    Assert-NativeFixtureOwner (
        @($performanceByBackend.native | Where-Object {
            $_.elapsed_microseconds -le 0 -or $_.bytes_per_second -le 0 -or
            $_.cpu_basis_points -le 0
        }).Count -eq 0 -and
        @($performanceByBackend.scp | Where-Object {
            $_.elapsed_microseconds -le 0 -or $_.bytes_per_second -le 0 -or
            $_.cpu_basis_points -le 0
        }).Count -eq 0
    ) 'fixed workload did not cross the positive timing and CPU accounting boundary'
    $nativeRates = [long[]]@($performanceByBackend.native.bytes_per_second)
    $scpRates = [long[]]@($performanceByBackend.scp.bytes_per_second)
    $nativeP50 = Get-NativeFixturePercentile $nativeRates 2
    $nativeP95 = Get-NativeFixturePercentile $nativeRates 4
    $scpMedian = Get-NativeFixturePercentile $scpRates 2
    $ratioPercent = [long][Math]::Floor(([decimal]$nativeP50 * 100) / [decimal]$scpMedian)
    Assert-NativeFixtureOwner ($ratioPercent -ge 80) 'fixed local workload ratio fell below its fixture guard'
    $performance = [pscustomobject][ordered]@{
        evidence_kind = 'local_copy_workload_not_network_throughput'
        native_samples = $performanceByBackend.native
        scp_samples = $performanceByBackend.scp
        native_p50_bytes_per_second = $nativeP50
        native_p95_bytes_per_second = $nativeP95
        scp_median_bytes_per_second = $scpMedian
        native_to_scp_ratio_percent = $ratioPercent
        native_cpu_basis_points = [long](($performanceByBackend.native.cpu_basis_points | Measure-Object -Maximum).Maximum)
        native_peak_rss_bytes = [long](($performanceByBackend.native.peak_rss_bytes | Measure-Object -Maximum).Maximum)
        native_median_rtt_microseconds = Get-NativeFixturePercentile ([long[]]@(
            $performanceByBackend.native.rtt_microseconds
        )) 2
    }

    $receipt = [pscustomobject][ordered]@{
        schema_version = 1
        owner_contract = 'serctl-native-fixture-actual-capture-owner-v1'
        category = 'native_fault_registry_performance_fixture'
        sealability = 'unsealable_fixture_only'
        formal_complete_allowed = $false
        evidence_source = 'repository_fixed_local_child_process'
        limitations = @('not_real_remote', 'not_exact_tag', 'not_release_provenance', 'not_network_performance')
        child_script_sha256 = [string]$capture.script_sha256
        child_capture = [pscustomobject][ordered]@{
            exit_category = [string]$capture.exit_category
            exit_code = [int]$capture.exit_code
            elapsed_ms = [long]$capture.elapsed_ms
            deadline_ms = [long]$capture.deadline_ms
            process_tree_exited = [bool]$capture.process_tree_exited
            raw_stdout_sha256 = Get-NativeFixtureSha256 $stdout
            raw_stdout_base64 = [Convert]::ToBase64String($stdout)
        }
        fault_cases = $faultCases
        registry_window = $registryWindow
        performance = $performance
    }
    $receiptBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes(
        (($receipt | ConvertTo-Json -Compress -Depth 12) + "`n")
    )
    $receiptFullPath = [IO.Path]::GetFullPath($ReceiptPath)
    $parent = Split-Path -Parent $receiptFullPath
    $parentItem = Get-Item -LiteralPath $parent -Force -ErrorAction Stop
    Assert-NativeFixtureOwner (
        $parentItem.PSIsContainer -and
        ($parentItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 -and
        -not (Test-Path -LiteralPath $receiptFullPath)
    ) 'receipt destination is not create-new in a regular directory'
    $temporaryPath = Join-Path $parent (
        '.' + [IO.Path]::GetFileName($receiptFullPath) + '.serctl-owner-' + [Guid]::NewGuid().ToString('N')
    )
    $stream = [IO.File]::Open(
        $temporaryPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None
    )
    try {
        $stream.Write($receiptBytes, 0, $receiptBytes.Length)
        $stream.Flush($true)
    }
    finally { $stream.Dispose() }
    [IO.File]::Move($temporaryPath, $receiptFullPath)
    $temporaryPath = $null
}
finally {
    if ($null -ne $temporaryPath -and [IO.File]::Exists($temporaryPath)) {
        [IO.File]::Delete($temporaryPath)
    }
    if ($null -ne $receiptBytes) { [Array]::Clear($receiptBytes, 0, $receiptBytes.Length) }
    if ($null -ne $stdout) { [Array]::Clear($stdout, 0, $stdout.Length) }
    if ($null -ne $stderr) { [Array]::Clear($stderr, 0, $stderr.Length) }
}
