[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# This is a repository-fixed, local-only fault fixture. It emits raw events and
# measurements only; it never emits a pass bit, formal summary, or seal.
function New-FaultFact {
    param(
        [string]$Scenario,
        [int]$ResumePercent,
        [string]$TerminalEvent,
        [long]$AcknowledgedOffset,
        [long]$ConfirmedOffset,
        [bool]$OwnedPartialCreated,
        [bool]$OwnedPartialRemoved,
        [bool]$ForeignPartialTouched,
        [bool]$TargetReplaced,
        [bool]$CleanupAttempted,
        [bool]$CleanupConfirmed
    )
    [pscustomobject][ordered]@{
        scenario = $Scenario
        resume_percent = $ResumePercent
        terminal_event = $TerminalEvent
        acknowledged_offset = $AcknowledgedOffset
        confirmed_offset = $ConfirmedOffset
        owned_partial_created = $OwnedPartialCreated
        owned_partial_removed = $OwnedPartialRemoved
        foreign_partial_touched = $ForeignPartialTouched
        target_replaced = $TargetReplaced
        cleanup_attempted = $CleanupAttempted
        cleanup_confirmed = $CleanupConfirmed
    }
}

function Measure-FixedCopyWorkload {
    param([string]$Backend, [int]$SampleIndex)

    # One 64 MiB pass was shorter than the process CPU accounting quantum on
    # some Windows/PowerShell combinations.  Measure sixteen identical logical
    # passes and report that repetition count so every downstream rate uses the
    # same byte/time unit without inventing a minimum elapsed value.
    $workRepetitions = 16
    $source = [byte[]]::new(65536)
    $target = [byte[]]::new(65536)
    $scratch = [byte[]]::new(65536)
    for ($index = 0; $index -lt $source.Length; $index += 4096) {
        $source[$index] = [byte](($index + $SampleIndex) % 251)
    }
    $process = [Diagnostics.Process]::GetCurrentProcess()
    $process.Refresh()
    $cpuStart = $process.TotalProcessorTime.Ticks
    $timer = [Diagnostics.Stopwatch]::StartNew()
    $checksum = 0
    for ($repetition = 0; $repetition -lt $workRepetitions; $repetition++) {
        for ($iteration = 0; $iteration -lt 1024; $iteration++) {
            [Buffer]::BlockCopy($source, 0, $target, 0, $source.Length)
            if ($Backend -ceq 'scp') {
                # The comparison fixture deliberately models extra framing/copying.
                # It is not a network or scp benchmark and is therefore unsealable.
                [Buffer]::BlockCopy($target, 0, $scratch, 0, $target.Length)
                [Buffer]::BlockCopy($scratch, 0, $target, 0, $target.Length)
                [Buffer]::BlockCopy($target, 0, $scratch, 0, $target.Length)
            }
            $checksum = ($checksum + $target[($iteration * 4096) % $target.Length]) % 2147483647
        }
    }
    $timer.Stop()
    $process.Refresh()
    $cpuTicks = [Math]::Max(1L, $process.TotalProcessorTime.Ticks - $cpuStart)
    $elapsedMicroseconds = [Math]::Max(
        1L,
        [long][Math]::Floor(($timer.ElapsedTicks * 1000000.0) / [Diagnostics.Stopwatch]::Frequency)
    )

    $rttTimer = [Diagnostics.Stopwatch]::StartNew()
    [Threading.Thread]::SpinWait(5000 + ($SampleIndex * 101))
    $rttTimer.Stop()
    $rttMicroseconds = [Math]::Max(
        1L,
        [long][Math]::Floor(($rttTimer.ElapsedTicks * 1000000.0) / [Diagnostics.Stopwatch]::Frequency)
    )
    [pscustomobject][ordered]@{
        backend = $Backend
        sample_index = $SampleIndex
        size_bytes = 67108864L
        work_repetitions = $workRepetitions
        elapsed_microseconds = $elapsedMicroseconds
        cpu_microseconds = [Math]::Max(1L, [long][Math]::Floor($cpuTicks / 10.0))
        peak_working_set_bytes = [long]$process.PeakWorkingSet64
        rtt_microseconds = $rttMicroseconds
        checksum = [long]$checksum
    }
}

$faults = @(
    New-FaultFact 'resume_25' 25 'completed' 67108864 67108864 $true $true $false $false $true $true
    New-FaultFact 'resume_75' 75 'completed' 67108864 67108864 $true $true $false $false $true $true
    New-FaultFact 'lost_ack' 0 'unknown' 0 0 $true $false $false $false $false $false
    New-FaultFact 'helper_crash' 0 'unknown' 0 0 $true $false $false $false $false $false
    New-FaultFact 'disconnect' 0 'unknown' 0 0 $true $false $false $false $false $false
    New-FaultFact 'daemon_restart' 0 'unknown' 0 0 $true $false $false $false $false $false
    New-FaultFact 'disk_full' 0 'failed' 0 0 $true $true $false $false $true $true
    New-FaultFact 'permission_denied' 0 'failed' 0 0 $true $true $false $false $true $true
    New-FaultFact 'target_race' 0 'failed' 0 0 $true $true $false $false $true $true
    New-FaultFact 'target_symlink_or_reparse' 0 'failed' 0 0 $false $false $false $false $false $false
    New-FaultFact 'unknown_cleanup' 0 'cleanup_incomplete' 0 0 $true $false $false $false $true $false
)

$activeAttempts = @()
for ($profile = 0; $profile -lt 6; $profile++) {
    for ($slot = 1; $slot -le 9; $slot++) {
        $activeAttempts += [pscustomobject][ordered]@{
            profile = ('profile-' + $profile)
            slot = $slot
            accepted = ($slot -le 8)
            visible_to_profile = ('profile-' + $profile)
        }
    }
}
$terminalAttempts = @()
for ($profile = 0; $profile -lt 16; $profile++) {
    for ($slot = 1; $slot -le 17; $slot++) {
        $terminalAttempts += [pscustomobject][ordered]@{
            profile = ('profile-' + $profile)
            slot = $slot
            retained = ($slot -le 16)
            visible_to_profile = ('profile-' + $profile)
        }
    }
}

$nativeSamples = @()
$scpSamples = @()
for ($sample = 1; $sample -le 5; $sample++) {
    $nativeSamples += Measure-FixedCopyWorkload 'native' $sample
    $scpSamples += Measure-FixedCopyWorkload 'scp' $sample
}

$raw = [pscustomobject][ordered]@{
    schema_version = 'serctl-native-fixture-raw-v1'
    fault_events = $faults
    registry_events = [pscustomobject][ordered]@{
        active_attempts = $activeAttempts
        terminal_attempts = $terminalAttempts
        retention_seconds_observed = @(0, 300, 899, 900)
        ack_trace = @(
            [pscustomobject][ordered]@{ queued = 2048L; acknowledged = 0L; confirmed = 0L },
            [pscustomobject][ordered]@{ queued = 2048L; acknowledged = 2048L; confirmed = 2048L }
        )
        control_frame_lengths = @(64, 128, 512, 1024)
        negotiated = [pscustomobject][ordered]@{
            sftp_write_bytes = 2048
            sftp_inflight_writes = 1
            native_chunk_bytes = 32768
            native_ack_window_bytes = 32768
        }
    }
    performance_samples = [pscustomobject][ordered]@{
        native = $nativeSamples
        scp = $scpSamples
    }
}

$json = $raw | ConvertTo-Json -Compress -Depth 10
$outputBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes($json + "`n")
$output = [Console]::OpenStandardOutput()
$output.Write($outputBytes, 0, $outputBytes.Length)
$output.Flush()
[Array]::Clear($outputBytes, 0, $outputBytes.Length)
