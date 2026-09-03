[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Assert-NativeOwnerTest {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "native fixture actual-capture self-test failed: $Message" }
}

function Get-NativeOwnerTestSha256 {
    param([byte[]]$Bytes)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

$fixturePath = Join-Path $PSScriptRoot 'NativeFaultRegistryPerformanceFixture.ps1'
$ownerPath = Join-Path $PSScriptRoot 'Invoke-NativeFaultRegistryPerformanceActualCaptureOwner.ps1'
$launcherPath = Join-Path $PSScriptRoot 'NativeFaultRegistryPerformanceActualCaptureLauncher.ps1'
foreach ($path in @($fixturePath, $ownerPath, $launcherPath)) {
    $tokens = $null
    $errors = $null
    [void][Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
    Assert-NativeOwnerTest (@($errors).Count -eq 0) "$path does not parse"
}

. $launcherPath
$launcherCommand = Get-Command Invoke-NativeFaultRegistryPerformanceActualCaptureOwnerInternal
Assert-NativeOwnerTest (
    (@($launcherCommand.Parameters.Keys | Where-Object {
        $_ -cin @('Raw', 'Summary', 'Passed', 'FixturePath', 'Hash', 'Result', 'Transcript')
    }).Count -eq 0)
) 'launcher exposes caller-controlled evidence input'
$ownerCommand = Get-Command $ownerPath
Assert-NativeOwnerTest (
    (@($ownerCommand.Parameters.Keys | Where-Object {
        $_ -cin @('Raw', 'Summary', 'Passed', 'FixturePath', 'Hash', 'Result', 'Transcript')
    }).Count -eq 0)
) 'owner exposes caller-controlled evidence input'

$hostIsWindows = [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
    [Runtime.InteropServices.OSPlatform]::Windows
)
if (-not $hostIsWindows) {
    Write-Host (
        'native fault/registry/performance actual-capture static contract self-test: PASS; ' +
        'Windows runtime fixture skipped on non-Windows host.'
    )
    return
}

$testRoot = Join-Path (
    Join-Path ([IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))) 'target'
) ('native-fixture-owner-selftest-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($testRoot) | Out-Null
try {
    $receiptPath = Join-Path $testRoot 'capture.json'
    $capture = Invoke-NativeFaultRegistryPerformanceActualCaptureOwnerInternal `
        -ReceiptPath $receiptPath -DeadlineMilliseconds 300000
    try {
        Assert-NativeOwnerTest (
            $capture.exit_category -ceq 'completed_success' -and
            $capture.exit_code -eq 0 -and $capture.process_tree_exited -and
            $capture.stderr.Length -eq 0 -and $capture.stdout.Length -eq 0
        ) 'owner process did not terminate cleanly without an injectable result stream'
    }
    finally {
        [Array]::Clear($capture.stdout, 0, $capture.stdout.Length)
        [Array]::Clear($capture.stderr, 0, $capture.stderr.Length)
    }
    $receiptBytes = [IO.File]::ReadAllBytes($receiptPath)
    try {
        $receiptText = [Text.UTF8Encoding]::new($false, $true).GetString($receiptBytes)
        Assert-NativeOwnerTest (
            $receiptText.EndsWith("`n") -and -not $receiptText.Contains("`r")
        ) 'receipt is not canonical LF JSON'
        $receipt = $receiptText.Substring(0, $receiptText.Length - 1) | ConvertFrom-Json
        Assert-NativeOwnerTest (
            $receipt.owner_contract -ceq 'serctl-native-fixture-actual-capture-owner-v1' -and
            $receipt.category -ceq 'native_fault_registry_performance_fixture' -and
            $receipt.sealability -ceq 'unsealable_fixture_only' -and
            $receipt.formal_complete_allowed -is [bool] -and
            -not [bool]$receipt.formal_complete_allowed -and
            @($receipt.limitations).Count -eq 4 -and
            @($receipt.limitations) -contains 'not_real_remote' -and
            @($receipt.limitations) -contains 'not_exact_tag'
        ) 'receipt could be mistaken for formal real-host evidence'
        Assert-NativeOwnerTest (@($receipt.fault_cases).Count -eq 11) (
            'receipt fault set is not exact'
        )
        $expectedFaults = @(
            'resume_25', 'resume_75', 'lost_ack', 'helper_crash', 'disconnect',
            'daemon_restart', 'disk_full', 'permission_denied', 'target_race',
            'target_symlink_or_reparse', 'unknown_cleanup'
        )
        Assert-NativeOwnerTest (
            ((@($receipt.fault_cases.scenario | Sort-Object) -join ',') -ceq
                (@($expectedFaults | Sort-Object) -join ',')) -and
            @($receipt.fault_cases | Where-Object result_code -eq 'completed').Count -eq 2 -and
            @($receipt.fault_cases | Where-Object result_code -eq 'outcome_unknown').Count -eq 4 -and
            @($receipt.fault_cases | Where-Object result_code -eq 'transfer_failed').Count -eq 4 -and
            @($receipt.fault_cases | Where-Object result_code -eq 'cleanup_incomplete').Count -eq 1 -and
            @($receipt.fault_cases | Where-Object {
                $_.confirmed_advanced_without_ack -or $_.target_overwritten -or
                $_.foreign_partial_deleted -or -not $_.passed
            }).Count -eq 0
        ) 'fault terminals or safety derivation changed'
        $registry = $receipt.registry_window
        Assert-NativeOwnerTest (
            $registry.active_per_profile -eq 8 -and $registry.active_global -eq 48 -and
            $registry.terminal_per_profile -eq 16 -and $registry.terminal_global -eq 256 -and
            $registry.retention_max_seconds -eq 900 -and
            $registry.profile_isolation_passed -and $registry.control_frame_bound_passed -and
            -not $registry.confirmed_before_ack -and
            $registry.native_chunk_bytes -eq 32768 -and
            $registry.native_ack_window_bytes -eq 32768
        ) 'registry/window summary was not recomputed from the fixed raw trace'
        $performance = $receipt.performance
        Assert-NativeOwnerTest (
            $performance.evidence_kind -ceq 'local_copy_workload_not_network_throughput' -and
            @($performance.native_samples).Count -eq 5 -and
            @($performance.scp_samples).Count -eq 5 -and
            @($performance.native_samples + $performance.scp_samples | Where-Object {
                $_.work_repetitions -ne 16 -or $_.elapsed_microseconds -le 0 -or
                $_.bytes_per_second -le 0 -or $_.cpu_basis_points -le 0
            }).Count -eq 0
        ) 'performance fixture sample set is not exact'
        $nativeRates = @($performance.native_samples.bytes_per_second | Sort-Object)
        $scpRates = @($performance.scp_samples.bytes_per_second | Sort-Object)
        $ratio = [long][Math]::Floor(([decimal][long]$nativeRates[2] * 100) / [decimal][long]$scpRates[2])
        Assert-NativeOwnerTest (
            [long]$performance.native_p50_bytes_per_second -eq [long]$nativeRates[2] -and
            [long]$performance.native_p95_bytes_per_second -eq [long]$nativeRates[4] -and
            [long]$performance.scp_median_bytes_per_second -eq [long]$scpRates[2] -and
            [long]$performance.native_to_scp_ratio_percent -eq $ratio -and $ratio -ge 80
        ) 'performance ratio/percentiles were not derived from the captured samples'

        $rawBytes = [Convert]::FromBase64String([string]$receipt.child_capture.raw_stdout_base64)
        try {
            Assert-NativeOwnerTest (
                (Get-NativeOwnerTestSha256 $rawBytes) -ceq
                    [string]$receipt.child_capture.raw_stdout_sha256
            ) 'captured raw child stream digest does not match its bytes'
            $rawText = [Text.UTF8Encoding]::new($false, $true).GetString($rawBytes)
            $raw = $rawText.Substring(0, $rawText.Length - 1) | ConvertFrom-Json
            Assert-NativeOwnerTest (
                @($raw.fault_events).Count -eq 11 -and
                @($raw.performance_samples.native).Count -eq 5 -and
                @($raw.performance_samples.scp).Count -eq 5 -and
                @($raw.performance_samples.native + $raw.performance_samples.scp |
                    Where-Object {
                        $_.work_repetitions -ne 16 -or $_.elapsed_microseconds -le 0
                    }).Count -eq 0 -and
                $null -eq $raw.PSObject.Properties['passed'] -and
                $null -eq $raw.PSObject.Properties['summary']
            ) 'raw child facts contain a caller-like verdict or incomplete case set'
        }
        finally { [Array]::Clear($rawBytes, 0, $rawBytes.Length) }

        # The formal contract admits these canonical bytes only into its
        # unsealable fixture projection.  It must not complete a real-host case.
        . (Join-Path $PSScriptRoot 'ExternalTransferRuntimeReceiptContract.ps1')
        $ledger = New-ExternalTransferRuntimeLedger -Category native_transfer_real_host
        $importStatus = Import-NativeFaultRegistryPerformanceFixtureReceipt `
            -Ledger $ledger -OwnerReceiptBytes $receiptBytes
        $rejected = $false
        try { Complete-ExternalTransferRuntimeLedger -Ledger $ledger | Out-Null }
        catch { $rejected = $true }
        $status = Get-ExternalTransferRuntimeLedgerStatus -Ledger $ledger
        Assert-NativeOwnerTest (
            $rejected -and -not $status.sealed -and $status.completed -eq 0 -and
            $status.blocked -eq $status.expected -and
            $importStatus.completed -eq 0 -and $importStatus.blocked -eq 20
        ) 'fixture-only capture altered or completed the formal ledger'
    }
    finally { [Array]::Clear($receiptBytes, 0, $receiptBytes.Length) }

    # Caller evidence-shaped parameters must fail before a child starts or any
    # destination becomes visible.
    $forbiddenReceipt = Join-Path $testRoot 'forbidden.json'
    $rejected = $false
    try {
        Invoke-NativeFaultRegistryPerformanceActualCaptureOwnerInternal `
            -ReceiptPath $forbiddenReceipt -Raw '{"passed":true}' | Out-Null
    }
    catch { $rejected = $true }
    Assert-NativeOwnerTest ($rejected -and -not (Test-Path -LiteralPath $forbiddenReceipt)) (
        'caller raw evidence was accepted or produced a partial receipt'
    )

    $before = (Get-FileHash -LiteralPath $receiptPath -Algorithm SHA256).Hash
    $duplicate = Invoke-NativeFaultRegistryPerformanceActualCaptureOwnerInternal `
        -ReceiptPath $receiptPath -DeadlineMilliseconds 300000
    try {
        Assert-NativeOwnerTest (
            $duplicate.exit_category -ne 'completed_success' -and
            (Get-FileHash -LiteralPath $receiptPath -Algorithm SHA256).Hash -ceq $before
        ) 'create-new rejection overwrote the complete receipt'
    }
    finally {
        [Array]::Clear($duplicate.stdout, 0, $duplicate.stdout.Length)
        [Array]::Clear($duplicate.stderr, 0, $duplicate.stderr.Length)
    }
    Assert-NativeOwnerTest (
        @(Get-ChildItem -LiteralPath $testRoot -Force | Where-Object {
            $_.Name -like '*.serctl-owner-*'
        }).Count -eq 0
    ) 'failed receipt publication left an owned partial'
}
finally {
    if ([IO.Directory]::Exists($testRoot)) {
        [IO.Directory]::Delete($testRoot, $true)
    }
}

'native fault/registry/performance actual-capture owner self-test: PASS'
