[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-ContractCondition {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if (-not $Condition) {
        throw "external transfer runtime receipt contract self-test failed: $Message"
    }
}

function Assert-Rejected {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Action,
        [Parameter(Mandatory = $true)][string]$Description
    )
    $rejected = $false
    try { & $Action | Out-Null }
    catch { $rejected = $true }
    Assert-ContractCondition $rejected "$Description was accepted"
}

$contractPath = Join-Path $PSScriptRoot 'ExternalTransferRuntimeReceiptContract.ps1'
$source = Get-Content -LiteralPath $contractPath -Raw -Encoding utf8
$tokens = $null
$parseErrors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile(
    $contractPath,
    [ref]$tokens,
    [ref]$parseErrors
)
Assert-ContractCondition (@($parseErrors).Count -eq 0) 'contract source does not parse'

foreach ($marker in @(
    "-Name 'Serctl.ExternalTransferRuntimeReceiptContract'",
    '$script:LedgerStates',
    'runtime ledger handle does not use the exact opaque schema',
    'Invoke-SerctlFormalRuntimeAdapter',
    'Invoke-ExternalTransferFormalOwnerCase',
    'Invoke-ExternalTransferFormalOwnerConcurrentTransferCase',
    'Import-ExternalTransferIsolatedOwnerReceiptV2',
    'Get-ExternalTransferInteropUnsealableProjection',
    'Import-NativeFaultRegistryPerformanceFixtureReceipt',
    'Get-ExternalTransferNativeFixtureUnsealableProjection',
    'serctl-native-fixture-unsealable-projection-v1',
    'unsealable_fixture_only',
    'not_real_remote',
    'not_exact_tag',
    'Set-IsolatedOwnerExpectedBindingInternal',
    'serctl-isolated-formal-owner-receipt-v2',
    'evidence_context_sha256',
    'operation_context_sha256_by_case',
    'expected_helper_identity = $expectedHelperIdentity',
    'Assert-SerctlFormalComponentSetInternal $components $VerifiedComponentPaths',
    'copied only from the exact Linux',
    '$script:NativeFixedTransferCases',
    '$script:InteropTransferCases',
    '$script:NativeFaultCases',
    'Add-NativeFaultActualObservationInternal',
    'Set-NativeRegistryWindowActualObservationInternal',
    'Set-NativePerformanceActualMeasurementsInternal',
    'private_actual_capture_v1',
    'confirmed_bytes_before_first_ack',
    'native_samples', 'scp_samples',
    'serctl-transfer-receipt-prerequisites-v1',
    'immutable_transfer_cases',
    'release seal refused',
    'PowerShell module-private state',
    'It accepts no result, pass Boolean',
    'Accept-ExternalTransferRuntimeAdapterObservation',
    'serctl-runtime-adapter-observation-v1',
    'every real case remains BLOCKED',
    '. $SupervisorPath',
    '. $AdapterPath',
    'Callers never supply a Receipt/details/result object',
    '[System.IO.FileMode]::CreateNew',
    '[System.IO.FileShare]::None',
    '[System.IO.FileOptions]::WriteThrough',
    'authorization\s*:',
    'bearer\s+',
    '(?i)^-(i|oidentityfile)$',
    "'^[A-Za-z]:'",
    "'^[\\/]'",
    '(^|[\\/])\.\.([\\/]|$)',
    "'disconnect'", "'daemon_restart'", "'target_symlink_or_reparse'",
    "'OpenSSH_directory'", "'OpenSSH_tunnel_local'",
    "'OpenSSH_tunnel_remote'", "'OpenSSH_tunnel_dynamic'"
)) {
    Assert-ContractCondition $source.Contains($marker) "contract omits '$marker'"
}

foreach ($forbidden in @(
    'ExternalTransferRuntimeLedgerToken',
    'Add-ExternalTransferRuntimeObservation',
    '[bool]$Passed',
    '$StructuredResult',
    '[ValidateNotNull()]$Receipt',
    'InputJson',
    'ResultJson',
    'DetailsPath',
    'Prewritten',
    'ConvertFrom-Json',
    'Invoke-Expression'
)) {
    Assert-ContractCondition (-not $source.Contains($forbidden)) (
        "contract still permits injected evidence or public mutable state via '$forbidden'"
    )
}

Get-Module 'Serctl.ExternalTransferRuntimeReceiptContract' -All |
    Remove-Module -Force -ErrorAction Stop
. $contractPath
$contractModules = @(Get-Module 'Serctl.ExternalTransferRuntimeReceiptContract' -All)
Assert-ContractCondition ($contractModules.Count -eq 1) 'contract module load is ambiguous'
$contractModule = $contractModules[0]

foreach ($ownerCommand in @(
    (Get-Command Invoke-ExternalTransferFormalOwnerCase),
    (Get-Command Invoke-ExternalTransferFormalOwnerConcurrentTransferCase),
    (Get-Command Import-ExternalTransferIsolatedOwnerReceiptV2),
    (Get-Command Import-NativeFaultRegistryPerformanceFixtureReceipt)
)) {
    foreach ($forbiddenParameter in @(
        'Passed', 'Result', 'StructuredResult', 'ResultJson', 'Receipt', 'ReceiptBytes',
        'ExpectedStdout', 'ExpectedTranscript', 'Executable', 'ArgumentList', 'GrantPath'
    )) {
        Assert-ContractCondition (-not $ownerCommand.Parameters.ContainsKey($forbiddenParameter)) (
            "formal owner exposes forbidden parameter '$forbiddenParameter'"
        )
    }
}
$importCommand = Get-Command Import-ExternalTransferIsolatedOwnerReceiptV2
foreach ($projectionCommand in @(
    $importCommand,
    (Get-Command Get-ExternalTransferInteropUnsealableProjection),
    (Get-Command Import-NativeFaultRegistryPerformanceFixtureReceipt),
    (Get-Command Get-ExternalTransferNativeFixtureUnsealableProjection)
)) {
    foreach ($forbiddenParameter in @(
        'Summary', 'Passed', 'Path', 'Hash', 'Sha256', 'ComponentPaths',
        'ExpectedContext', 'HelperIdentity', 'Components', 'Result', 'Details',
        'Runner', 'Remote', 'Envelope', 'Raw', 'RawFacts', 'ReceiptPath'
    )) {
        Assert-ContractCondition (
            -not $projectionCommand.Parameters.ContainsKey($forbiddenParameter)
        ) (
            "formal projection API exposes forbidden parameter '$forbiddenParameter'"
        )
    }
}

$ledger = New-ExternalTransferRuntimeLedger -Category 'openssh_dropbear_interop'
$handleFields = @($ledger.PSObject.Properties.Name | Sort-Object)
Assert-ContractCondition (
    ($handleFields -join "`n") -ceq ((@(
        'category', 'contract_version', 'ledger_id'
    ) | Sort-Object) -join "`n")
) 'ledger handle exposes mutable runtime state or a token'
$status = Get-ExternalTransferRuntimeLedgerStatus -Ledger $ledger
Assert-ContractCondition (
    $status.expected -eq 10 -and $status.completed -eq 0 -and
    $status.blocked -eq 10 -and -not $status.sealed
) 'new interop ledger is not fail-closed and fully blocked'

$forged = [pscustomobject]@{
    contract_version = 2
    ledger_id = [Guid]::NewGuid().ToString('N')
    category = 'openssh_dropbear_interop'
}
Assert-Rejected `
    -Action { Get-ExternalTransferRuntimeLedgerStatus -Ledger $forged } `
    -Description 'forged random ledger handle'

$stolenTokenShape = [pscustomobject]@{
    contract_version = 2
    ledger_id = [string]$ledger.ledger_id
    category = [string]$ledger.category
    token = [object]::new()
    seen_case_ids = @('OpenSSH_exec')
    sealed = $true
    details = [ordered]@{ fabricated = $true }
}
Assert-Rejected `
    -Action { Get-ExternalTransferRuntimeLedgerStatus -Ledger $stolenTokenShape } `
    -Description 'stolen-token-shaped mutable ledger'

$originalCategory = [string]$ledger.category
$ledger.category = 'native_transfer_real_host'
Assert-Rejected `
    -Action { Get-ExternalTransferRuntimeLedgerStatus -Ledger $ledger } `
    -Description 'modified opaque ledger handle'
$ledger.category = $originalCategory
$status = Get-ExternalTransferRuntimeLedgerStatus -Ledger $ledger
Assert-ContractCondition (
    $status.completed -eq 0 -and $status.blocked -eq 10 -and -not $status.sealed
) 'handle modification changed module-private ledger state'

Assert-Rejected `
    -Action {
        Invoke-ExternalTransferRuntimeCase `
            -Ledger $ledger `
            -CaseId 'OpenSSH_exec' `
            -Executable '/usr/bin/true' `
            -Passed $true `
            -StructuredResult ([pscustomobject]@{ result_code = 'completed' })
    } `
    -Description 'caller-supplied fake command and result'
Assert-Rejected `
    -Action {
        Invoke-ExternalTransferRuntimeCase -Ledger $ledger -CaseId 'OpenSSH_exec'
    } `
    -Description 'interop case while the controlled adapter prerequisites remain blocked'
Assert-Rejected `
    -Action { Complete-ExternalTransferRuntimeLedger -Ledger $ledger } `
    -Description 'zero-observation ledger seal'

$nativeLedger = New-ExternalTransferRuntimeLedger -Category 'native_transfer_real_host'
$nativeStatus = Get-ExternalTransferRuntimeLedgerStatus -Ledger $nativeLedger
Assert-ContractCondition (
    $nativeStatus.expected -eq 20 -and $nativeStatus.completed -eq 0 -and
    $nativeStatus.blocked -eq 20 -and -not $nativeStatus.sealed
) 'expanded native runtime ledger is not fail-closed and fully blocked'
Assert-Rejected `
    -Action {
        Invoke-ExternalTransferRuntimeCase `
            -Ledger $nativeLedger `
            -CaseId 'target_symlink_or_reparse'
    } `
    -Description 'expanded native case without a real product adapter'
Assert-Rejected `
    -Action { Complete-ExternalTransferRuntimeLedger -Ledger $nativeLedger } `
    -Description 'expanded zero-observation native ledger seal'

# Exercise the repository-fixed four-script local capture chain once.  Its
# receipt is admitted only as an explicitly unsealable parser projection; it
# must leave all twenty real-host cases blocked.
$hostIsWindows = [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
    [Runtime.InteropServices.OSPlatform]::Windows
)
if ($hostIsWindows) {
$nativeOwnerPath = Join-Path ([IO.Path]::GetTempPath()) (
    'serctl-native-fixture-owner-' + [Guid]::NewGuid().ToString('N') + '.json'
)
$nativeOwnerBytes = $null
try {
    & (Join-Path $PSScriptRoot 'Invoke-NativeFaultRegistryPerformanceActualCaptureOwner.ps1') `
        -ReceiptPath $nativeOwnerPath
    $nativeOwnerBytes = [IO.File]::ReadAllBytes($nativeOwnerPath)
}
finally {
    if (Test-Path -LiteralPath $nativeOwnerPath) {
        Remove-Item -LiteralPath $nativeOwnerPath -Force
    }
}
Assert-ContractCondition (
    $null -ne $nativeOwnerBytes -and $nativeOwnerBytes.Length -gt 0
) 'native fixture owner did not emit canonical receipt bytes'

function Get-NativeFixtureTestSha256Lower {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally { $sha.Dispose() }
}

function New-NativeFixtureOwnerVariant {
    param(
        [scriptblock]$OwnerMutation,
        [scriptblock]$RawMutation
    )
    $utf8 = [Text.UTF8Encoding]::new($false, $true)
    $ownerText = $utf8.GetString($nativeOwnerBytes)
    $owner = $ownerText.Substring(0, $ownerText.Length - 1) | ConvertFrom-Json
    if ($null -ne $RawMutation) {
        $rawBytes = [Convert]::FromBase64String([string]$owner.child_capture.raw_stdout_base64)
        try {
            $rawText = $utf8.GetString($rawBytes)
            $raw = $rawText.Substring(0, $rawText.Length - 1) | ConvertFrom-Json
            & $RawMutation $raw
            $changedRawBytes = $utf8.GetBytes(
                ($raw | ConvertTo-Json -Compress -Depth 12) + "`n"
            )
            $owner.child_capture.raw_stdout_base64 = [Convert]::ToBase64String($changedRawBytes)
            $owner.child_capture.raw_stdout_sha256 =
                Get-NativeFixtureTestSha256Lower $changedRawBytes
        }
        finally { [Array]::Clear($rawBytes, 0, $rawBytes.Length) }
    }
    if ($null -ne $OwnerMutation) { & $OwnerMutation $owner }
    return ,$utf8.GetBytes(($owner | ConvertTo-Json -Compress -Depth 12) + "`n")
}

function Assert-NativeFixtureImportRejected {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][string]$Description
    )
    $candidate = New-ExternalTransferRuntimeLedger -Category native_transfer_real_host
    Assert-Rejected -Action {
        Import-NativeFaultRegistryPerformanceFixtureReceipt `
            -Ledger $candidate -OwnerReceiptBytes $Bytes
    } -Description $Description
}

$tamperedReceipt = [byte[]]$nativeOwnerBytes.Clone()
$tamperedReceipt[0] = $tamperedReceipt[0] -bxor 1
Assert-NativeFixtureImportRejected $tamperedReceipt 'native fixture receipt byte tamper'
$summaryInjection = New-NativeFixtureOwnerVariant -OwnerMutation {
    param($Owner)
    $Owner | Add-Member -NotePropertyName summary -NotePropertyValue 'passed'
} -RawMutation $null
Assert-NativeFixtureImportRejected $summaryInjection 'native fixture caller summary injection'
$terminalTypeDrift = New-NativeFixtureOwnerVariant -OwnerMutation $null -RawMutation {
    param($Raw)
    $Raw.fault_events[0].terminal_event = 7
}
Assert-NativeFixtureImportRejected $terminalTypeDrift 'native fixture terminal type confusion'
$shortPerformance = New-NativeFixtureOwnerVariant -OwnerMutation $null -RawMutation {
    param($Raw)
    $Raw.performance_samples.native = @($Raw.performance_samples.native | Select-Object -First 4)
}
Assert-NativeFixtureImportRejected $shortPerformance 'native fixture incomplete performance samples'
$crossProfileRegistry = New-NativeFixtureOwnerVariant -OwnerMutation $null -RawMutation {
    param($Raw)
    $Raw.registry_events.active_attempts[0].visible_to_profile = 'profile-1'
}
Assert-NativeFixtureImportRejected $crossProfileRegistry 'native fixture cross-profile registry visibility'
$preAckConfirmation = New-NativeFixtureOwnerVariant -OwnerMutation $null -RawMutation {
    param($Raw)
    $Raw.registry_events.ack_trace[0].confirmed = 1
}
Assert-NativeFixtureImportRejected $preAckConfirmation 'native fixture confirmation before ACK'
$missingRemoteLimitation = New-NativeFixtureOwnerVariant -OwnerMutation {
    param($Owner)
    $Owner.limitations = @('not_exact_tag', 'not_release_provenance', 'not_network_performance')
} -RawMutation $null
Assert-NativeFixtureImportRejected $missingRemoteLimitation 'native fixture missing not-real-remote marker'

$nativeFixtureLedger = New-ExternalTransferRuntimeLedger -Category native_transfer_real_host
$nativeFixtureStatus = Import-NativeFaultRegistryPerformanceFixtureReceipt `
    -Ledger $nativeFixtureLedger -OwnerReceiptBytes $nativeOwnerBytes
Assert-ContractCondition (
    $nativeFixtureStatus.expected -eq 20 -and $nativeFixtureStatus.completed -eq 0 -and
    $nativeFixtureStatus.blocked -eq 20 -and -not $nativeFixtureStatus.sealed
) 'native fixture import changed formal real-host completion state'
$nativeProjectionBytes = Get-ExternalTransferNativeFixtureUnsealableProjection $nativeFixtureLedger
$nativeProjectionSha = Get-NativeFixtureTestSha256Lower $nativeProjectionBytes
$nativeProjectionText = [Text.UTF8Encoding]::new($false, $true).GetString($nativeProjectionBytes)
$nativeProjection = $nativeProjectionText.Substring(0, $nativeProjectionText.Length - 1) |
    ConvertFrom-Json
Assert-ContractCondition (
    $nativeProjection.projection_contract -ceq
        'serctl-native-fixture-unsealable-projection-v1' -and
    $nativeProjection.category -ceq 'native_transfer_real_host' -and
    $nativeProjection.release_sealable -eq $false -and
    $nativeProjection.formal_complete_allowed -eq $false -and
    $nativeProjection.sealability -ceq 'unsealable_fixture_only' -and
    (@($nativeProjection.limitations) -join ',') -ceq
        'not_real_remote,not_exact_tag,not_release_provenance,not_network_performance' -and
    @($nativeProjection.fault_cases).Count -eq 11 -and
    @($nativeProjection.performance.native_samples).Count -eq 5 -and
    @($nativeProjection.performance.scp_samples).Count -eq 5 -and
    $nativeProjection.registry_window.profile_isolation_passed -eq $true -and
    $nativeProjection.registry_window.confirmed_before_ack -eq $false -and
    -not ($nativeProjection.PSObject.Properties.Name -contains 'summary') -and
    -not ($nativeProjection.PSObject.Properties.Name -contains 'passed')
) 'native fixture projection changed its exact unsealable fact boundary'
$nativeProjectionBytes[0] = $nativeProjectionBytes[0] -bxor 1
$nativeProjectionAgain = Get-ExternalTransferNativeFixtureUnsealableProjection $nativeFixtureLedger
Assert-ContractCondition (
    (Get-NativeFixtureTestSha256Lower $nativeProjectionAgain) -ceq $nativeProjectionSha
) 'caller mutation changed immutable native fixture projection state'
Assert-Rejected `
    -Action { Complete-ExternalTransferRuntimeLedger -Ledger $nativeFixtureLedger } `
    -Description 'local native fixture receipt formal seal'
[Array]::Clear($nativeProjectionBytes, 0, $nativeProjectionBytes.Length)
[Array]::Clear($nativeProjectionAgain, 0, $nativeProjectionAgain.Length)
[Array]::Clear($nativeOwnerBytes, 0, $nativeOwnerBytes.Length)
}
else {
    Write-Host (
        'Native actual-capture receipt import fixture skipped on non-Windows host; ' +
        'portable receipt contract checks remain active.'
    )
}

$fixtureComponents = [pscustomobject][ordered]@{
    cli = [pscustomobject][ordered]@{
        name = 'serctl_cli.exe'; binary_size = [long]101; sha256 = ('A' * 64)
        version = 'serctl_cli 1.0.0-beta (git 0123456789ab; vault-storage read=v4..=v5 write=v5)'
    }
    daemon = [pscustomobject][ordered]@{
        name = 'serctl_daemon.exe'; binary_size = [long]202; sha256 = ('B' * 64)
        version = 'serctl_daemon 1.0.0-beta (git 0123456789ab; IPC v9..=v9; vault-storage read=v4..=v5 write=v5)'
    }
    helper = [pscustomobject][ordered]@{
        name = 'serctl-xfer'; binary_size = [long]303; sha256 = ('C' * 64)
        version = 'serctl-xfer 1.0.0-beta (git 0123456789ab; transfer protocol v1)'
    }
}
$fixtureContextSha256 = 'D' * 64
function Get-TestSha256 {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '') }
    finally { $sha.Dispose() }
}

function ConvertTo-TestCanonicalBytes {
    param([Parameter(Mandatory = $true)]$Value)
    return ,([Text.UTF8Encoding]::new($false, $true).GetBytes(
        ($Value | ConvertTo-Json -Compress -Depth 12) + "`n"
    ))
}

function Copy-TestJsonObject {
    param([Parameter(Mandatory = $true)]$Value)
    return (($Value | ConvertTo-Json -Compress -Depth 12) | ConvertFrom-Json)
}

$interopOwnerCaseIds = @(
    'OpenSSH_exec', 'Dropbear_exec', 'OpenSSH_directory',
    'OpenSSH_tunnel_local', 'OpenSSH_tunnel_remote', 'OpenSSH_tunnel_dynamic',
    'OpenSSH_sftp', 'OpenSSH_native', 'Dropbear_sftp', 'Dropbear_native'
)
$fixtureEvidenceContextSha256 = 'D' * 64
$ownerComponentBytes = & $contractModule {
    param($Components)
    Get-CanonicalRuntimeComponentBytesInternal $Components
} $fixtureComponents
$ownerComponentSha256 = Get-TestSha256 $ownerComponentBytes
$ownerCaseReceipts = @()
for ($index = 0; $index -lt $interopOwnerCaseIds.Count; $index++) {
    $caseId = [string]$interopOwnerCaseIds[$index]
    $operationContext = ('{0:X64}' -f ([uint64]($index + 1)))
    $child = [pscustomobject][ordered]@{
        schema_version = 1
        category = 'openssh_dropbear_interop'
        case_id = $caseId
        context_sha256 = $operationContext
        command_sha256 = ('{0:X64}' -f ([uint64]($index + 101)))
        terminal_sha256 = ('{0:X64}' -f ([uint64]($index + 201)))
        result_code = 'completed'
        passed = $true
    }
    $childBytes = ConvertTo-TestCanonicalBytes $child
    $ownerCaseReceipts += [pscustomobject][ordered]@{
        case_id = $caseId
        operation_context_sha256 = $operationContext
        receipt_base64 = [Convert]::ToBase64String($childBytes)
        receipt_sha256 = Get-TestSha256 $childBytes
    }
    [Array]::Clear($childBytes, 0, $childBytes.Length)
}
$baseOwnerV2 = [pscustomobject][ordered]@{
    schema_version = 2
    owner_contract = 'serctl-isolated-formal-owner-receipt-v2'
    category = 'openssh_dropbear_interop'
    evidence_context_sha256 = $fixtureEvidenceContextSha256
    component_set_sha256 = $ownerComponentSha256
    component_set_base64 = [Convert]::ToBase64String($ownerComponentBytes)
    case_receipts = $ownerCaseReceipts
}

function New-PreparedInteropOwnerLedger {
    $prepared = New-ExternalTransferRuntimeLedger -Category 'openssh_dropbear_interop'
    & $contractModule {
        param($Ledger, $Components, $EvidenceContext)
        Set-IsolatedOwnerExpectedBindingInternal `
            (Resolve-LedgerState $Ledger) $Components $EvidenceContext
    } $prepared $fixtureComponents $fixtureEvidenceContextSha256
    return $prepared
}

function Assert-OwnerV2Rejected {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Mutate,
        [Parameter(Mandatory = $true)][string]$Description
    )
    $document = Copy-TestJsonObject $baseOwnerV2
    & $Mutate $document
    $bytes = ConvertTo-TestCanonicalBytes $document
    $prepared = New-PreparedInteropOwnerLedger
    Assert-Rejected -Action {
        Import-ExternalTransferIsolatedOwnerReceiptV2 `
            -Ledger $prepared -OwnerReceiptBytes $bytes
    } -Description $Description
    Assert-ContractCondition (
        @($bytes | Where-Object { $_ -ne 0 }).Count -eq 0
    ) "$Description retained owner receipt bytes"
    $rejectedStatus = Get-ExternalTransferRuntimeLedgerStatus $prepared
    Assert-ContractCondition (
        $rejectedStatus.completed -eq 0 -and $rejectedStatus.blocked -eq 10 -and
        -not $rejectedStatus.sealed
    ) "$Description partially mutated the formal ledger"
}

$unboundOwnerBytes = ConvertTo-TestCanonicalBytes $baseOwnerV2
$unboundLedger = New-ExternalTransferRuntimeLedger -Category 'openssh_dropbear_interop'
Assert-Rejected -Action {
    Import-ExternalTransferIsolatedOwnerReceiptV2 `
        -Ledger $unboundLedger -OwnerReceiptBytes $unboundOwnerBytes
} -Description 'isolated owner v2 receipt without protected component/context binding'
Assert-ContractCondition (
    @($unboundOwnerBytes | Where-Object { $_ -ne 0 }).Count -eq 0
) 'unbound isolated owner v2 receipt bytes were retained'

Assert-OwnerV2Rejected -Description 'caller summary field' -Mutate {
    param($Document)
    $Document | Add-Member -NotePropertyName summary -NotePropertyValue 'passed'
}
Assert-OwnerV2Rejected -Description 'caller pass field' -Mutate {
    param($Document)
    $Document | Add-Member -NotePropertyName passed -NotePropertyValue $true
}
Assert-OwnerV2Rejected -Description 'caller receipt path field' -Mutate {
    param($Document)
    $Document | Add-Member -NotePropertyName receipt_path -NotePropertyValue 'C:\fake.json'
}
Assert-OwnerV2Rejected -Description 'aggregate evidence context drift' -Mutate {
    param($Document)
    $Document.evidence_context_sha256 = 'E' * 64
}
Assert-OwnerV2Rejected -Description 'component-set digest drift' -Mutate {
    param($Document)
    $Document.component_set_sha256 = 'A' * 64
}
Assert-OwnerV2Rejected -Description 'duplicated case identity' -Mutate {
    param($Document)
    $Document.case_receipts[1].case_id = $Document.case_receipts[0].case_id
}
Assert-OwnerV2Rejected -Description 'operation context drift' -Mutate {
    param($Document)
    $Document.case_receipts[0].operation_context_sha256 = 'F' * 64
}
Assert-OwnerV2Rejected -Description 'child receipt digest drift' -Mutate {
    param($Document)
    $Document.case_receipts[0].receipt_sha256 = 'F' * 64
}
Assert-OwnerV2Rejected -Description 'child terminal result injection' -Mutate {
    param($Document)
    $entry = $Document.case_receipts[0]
    $childBytes = [Convert]::FromBase64String([string]$entry.receipt_base64)
    $childText = [Text.UTF8Encoding]::new($false, $true).GetString($childBytes)
    $child = $childText.TrimEnd("`n") | ConvertFrom-Json
    $child.result_code = 'failed'
    $changed = ConvertTo-TestCanonicalBytes $child
    $entry.receipt_base64 = [Convert]::ToBase64String($changed)
    $entry.receipt_sha256 = Get-TestSha256 $changed
    [Array]::Clear($childBytes, 0, $childBytes.Length)
    [Array]::Clear($changed, 0, $changed.Length)
}
Assert-OwnerV2Rejected -Description 'component helper identity drift' -Mutate {
    param($Document)
    $componentBytes = [Convert]::FromBase64String([string]$Document.component_set_base64)
    $componentText = [Text.UTF8Encoding]::new($false, $true).GetString($componentBytes)
    $componentSet = $componentText.TrimEnd("`n") | ConvertFrom-Json
    $componentSet.helper.version =
        'serctl-xfer 1.0.0-beta (git ffffffffffff; transfer protocol v1)'
    $changed = ConvertTo-TestCanonicalBytes $componentSet
    $Document.component_set_base64 = [Convert]::ToBase64String($changed)
    $Document.component_set_sha256 = Get-TestSha256 $changed
    [Array]::Clear($componentBytes, 0, $componentBytes.Length)
    [Array]::Clear($changed, 0, $changed.Length)
}

$importLedger = New-PreparedInteropOwnerLedger
$ownerV2Bytes = ConvertTo-TestCanonicalBytes $baseOwnerV2
$importStatus = Import-ExternalTransferIsolatedOwnerReceiptV2 `
    -Ledger $importLedger -OwnerReceiptBytes $ownerV2Bytes
Assert-ContractCondition (
    $importStatus.completed -eq 10 -and $importStatus.blocked -eq 0 -and
    -not $importStatus.sealed -and
    @($ownerV2Bytes | Where-Object { $_ -ne 0 }).Count -eq 0
) 'isolated owner v2 exact receipt set was not imported without sealing'
$importedBinding = & $contractModule {
    param($Ledger)
    $state = Resolve-LedgerState $Ledger
    [pscustomobject]@{
        aggregate = [string]$state.bound_evidence_context_sha256
        operation_contexts = @($state.operation_context_sha256_by_case.Values)
        component_sha = [string]$state.bound_component_set_sha256
        transfer_details = [byte[]]$state.immutable_transfer_details
        exact_components_cleared = $null -eq $state.exact_release_components
        expected_context_cleared = $null -eq $state.expected_evidence_context_sha256
    }
} $importLedger
Assert-ContractCondition (
    $importedBinding.aggregate -ceq $fixtureEvidenceContextSha256 -and
    @($importedBinding.operation_contexts).Count -eq 10 -and
    @($importedBinding.operation_contexts | Select-Object -Unique).Count -eq 10 -and
    -not ($importedBinding.operation_contexts -contains $importedBinding.aggregate) -and
    $importedBinding.component_sha -ceq $ownerComponentSha256 -and
    $importedBinding.transfer_details -is [byte[]] -and
    $importedBinding.exact_components_cleared -and
    $importedBinding.expected_context_cleared
) 'aggregate evidence context was conflated with per-operation contexts'
$projectionBytes = Get-ExternalTransferInteropUnsealableProjection -Ledger $importLedger
$projectionSha256 = Get-TestSha256 $projectionBytes
$projectionText = [Text.UTF8Encoding]::new($false, $true).GetString($projectionBytes)
$projection = $projectionText.TrimEnd("`n") | ConvertFrom-Json
Assert-ContractCondition (
    (@($projection.PSObject.Properties.Name) -join "`n") -ceq
        "schema_version`nprojection_contract`ncategory`nrelease_sealable`nmissing_formal_fields`ndetails" -and
    $projection.projection_contract -ceq
        'serctl-openssh-dropbear-interop-details-projection-v1' -and
    $projection.category -ceq 'openssh_dropbear_interop' -and
    $projection.release_sealable -eq $false -and
    (@($projection.missing_formal_fields) -join ',') -ceq
        'runner,remote,implementations,exact_tag_envelope' -and
    (@($projection.details.PSObject.Properties.Name) -join "`n") -ceq
        "evidence_context_sha256`ncomponents`ncase_receipts" -and
    $projection.details.evidence_context_sha256 -ceq
        $fixtureEvidenceContextSha256 -and
    @($projection.details.case_receipts).Count -eq 10 -and
    @($projection.details.case_receipts.operation_context_sha256 |
        Select-Object -Unique).Count -eq 10 -and
    -not ($projection.PSObject.Properties.Name -contains 'summary') -and
    -not ($projection.details.PSObject.Properties.Name -contains 'passed')
) 'interop unsealable projection is not the exact deterministic external-details subset'
foreach ($entry in @($projection.details.case_receipts)) {
    $receiptBytes = [Convert]::FromBase64String([string]$entry.receipt_base64)
    $receipt = ([Text.UTF8Encoding]::new($false, $true).GetString(
        $receiptBytes
    )).TrimEnd("`n") | ConvertFrom-Json
    Assert-ContractCondition (
        (Get-TestSha256 $receiptBytes) -ceq [string]$entry.receipt_sha256 -and
        [string]$receipt.case_id -ceq [string]$entry.case_id -and
        [string]$receipt.context_sha256 -ceq
            [string]$entry.operation_context_sha256 -and
        [string]$entry.operation_context_sha256 -cne
            [string]$projection.details.evidence_context_sha256
    ) "projection case '$($entry.case_id)' did not round-trip its operation context"
    [Array]::Clear($receiptBytes, 0, $receiptBytes.Length)
}
$projectionBytes[0] = $projectionBytes[0] -bxor 1
$projectionBytesAgain = Get-ExternalTransferInteropUnsealableProjection -Ledger $importLedger
Assert-ContractCondition (
    (Get-TestSha256 $projectionBytesAgain) -ceq $projectionSha256
) 'caller mutation of returned projection bytes changed the ledger projection'
[Array]::Clear($projectionBytes, 0, $projectionBytes.Length)
[Array]::Clear($projectionBytesAgain, 0, $projectionBytesAgain.Length)
$importSealError = $null
try { Complete-ExternalTransferRuntimeLedger -Ledger $importLedger }
catch { $importSealError = $_.Exception.Message }
Assert-ContractCondition (
    $importSealError -like '*formal runner and remote projections remain unavailable*' -and
    $importSealError -like '*release seal refused*' -and
    -not (Get-ExternalTransferRuntimeLedgerStatus $importLedger).sealed
) 'isolated owner v2 import bypassed the remaining actual-capture seal blocker'
[Array]::Clear($ownerComponentBytes, 0, $ownerComponentBytes.Length)

function New-TransferPrerequisiteFixture {
    param(
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string[]]$CaseIds
    )
    $componentBytes = & $contractModule {
        param($Components)
        Get-CanonicalRuntimeComponentBytesInternal $Components
    } $fixtureComponents
    $componentSha256 = Get-TestSha256 $componentBytes
    $state = [pscustomobject]@{
        category = $Category
        bound_evidence_context_sha256 = $fixtureContextSha256
        bound_component_set_sha256 = $componentSha256
        bound_component_bytes = $componentBytes
        immutable_transfer_cases = [ordered]@{}
        immutable_transfer_details = $null
    }
    $index = 0
    foreach ($caseId in $CaseIds) {
        $receipt = [pscustomobject][ordered]@{
            context_sha256 = $fixtureContextSha256
            command_sha256 = ('{0:X64}' -f ([uint64]($index + 1)))
            terminal_sha256 = ('{0:X64}' -f ([uint64]($index + 101)))
            result_code = 'completed'
            passed = $true
        }
        $receiptSha256 = ('{0:X64}' -f ([uint64]($index + 201)))
        $caseBytes = & $contractModule {
            param($Category, $CaseId, $Receipt, $ReceiptSha, $ComponentSha, $Helper)
            New-ImmutableTransferCaseBytesInternal `
                $Category $CaseId $Receipt $ReceiptSha $ComponentSha $Helper
        } $Category $caseId $receipt $receiptSha256 $componentSha256 $fixtureComponents.helper
        Assert-ContractCondition ($caseBytes -is [byte[]]) (
            "fixed transfer case '$caseId' did not produce immutable bytes"
        )
        $state.immutable_transfer_cases[$caseId] = [pscustomobject][ordered]@{
            sha256 = Get-TestSha256 $caseBytes
            bytes = $caseBytes
        }
        $receipt.command_sha256 = 'F' * 64
        Assert-ContractCondition (
            (Get-TestSha256 $caseBytes) -ceq [string]$state.immutable_transfer_cases[$caseId].sha256
        ) "fixed transfer case '$caseId' retained a mutable receipt reference"
        $index++
    }
    & $contractModule {
        param($State)
        Update-ImmutableTransferPrerequisiteDetailsInternal $State
    } $state
    return $state
}

$nativeFixedIds = @(
    'push_21', 'push_1298223', 'push_67108864', 'push_1073741824',
    'pull_21', 'pull_1298223', 'pull_67108864', 'pull_1073741824'
)
$nativeFixtureState = New-TransferPrerequisiteFixture `
    -Category 'native_transfer_real_host' `
    -CaseIds $nativeFixedIds
$nativeDetails = ([Text.UTF8Encoding]::new($false, $true).GetString(
    $nativeFixtureState.immutable_transfer_details
)).TrimEnd("`n") | ConvertFrom-Json
Assert-ContractCondition (
    $nativeDetails.contract -ceq 'serctl-transfer-receipt-prerequisites-v1' -and
    $nativeDetails.release_sealable -eq $false -and
    @($nativeDetails.cases).Count -eq 8
) 'native fixed transfer prerequisite details are not closed and unsealable'
foreach ($entry in @($nativeDetails.cases)) {
    $caseStateBytes = [Convert]::FromBase64String([string]$entry.state_base64)
    $caseState = ([Text.UTF8Encoding]::new($false, $true).GetString(
        $caseStateBytes
    )).TrimEnd("`n") | ConvertFrom-Json
    Assert-ContractCondition (
        $caseState.kind -ceq 'fixed_payload' -and
        $caseState.implementation -ceq 'native' -and
        $caseState.expected_helper_identity.name -ceq 'serctl-xfer' -and
        $caseState.expected_helper_identity.binary_size -eq 303 -and
        $caseState.expected_helper_identity.sha256 -ceq ('c' * 64) -and
        $caseState.expected_helper_identity.version -ceq
            [string]$fixtureComponents.helper.version
    ) "native fixed case '$($entry.case_id)' lost its exact helper identity"
}

$interopFixtureState = New-TransferPrerequisiteFixture `
    -Category 'openssh_dropbear_interop' `
    -CaseIds @('OpenSSH_sftp', 'OpenSSH_native', 'Dropbear_sftp', 'Dropbear_native')
$interopDetails = ([Text.UTF8Encoding]::new($false, $true).GetString(
    $interopFixtureState.immutable_transfer_details
)).TrimEnd("`n") | ConvertFrom-Json
Assert-ContractCondition (
    $interopDetails.release_sealable -eq $false -and @($interopDetails.cases).Count -eq 4
) 'interop transfer prerequisite details are not closed and unsealable'
foreach ($entry in @($interopDetails.cases)) {
    $caseState = ([Text.UTF8Encoding]::new($false, $true).GetString(
        [Convert]::FromBase64String([string]$entry.state_base64)
    )).TrimEnd("`n") | ConvertFrom-Json
    if ($caseState.backend -ceq 'native') {
        Assert-ContractCondition ($null -ne $caseState.expected_helper_identity) (
            "interop native case '$($entry.case_id)' lost its helper identity"
        )
    }
    else {
        Assert-ContractCondition ($null -eq $caseState.expected_helper_identity) (
            "interop SFTP case '$($entry.case_id)' invented a helper identity"
        )
    }
}

$syntheticSealLedger = New-ExternalTransferRuntimeLedger -Category 'native_transfer_real_host'
& $contractModule {
    param($Ledger, $FixtureState)
    $state = Resolve-LedgerState $Ledger
    foreach ($caseId in $state.expected_case_ids) {
        $state.observations[$caseId] = [pscustomobject]@{ synthetic = $true }
    }
    $state.blocked_case_ids.Clear()
    $state.bound_evidence_context_sha256 =
        $FixtureState.bound_evidence_context_sha256
    $state.bound_component_set_sha256 = $FixtureState.bound_component_set_sha256
    $state.bound_component_bytes = $FixtureState.bound_component_bytes
    $state.immutable_transfer_cases = $FixtureState.immutable_transfer_cases
    $state.immutable_transfer_details = $FixtureState.immutable_transfer_details
} $syntheticSealLedger $nativeFixtureState
$nativeSealError = $null
try { Complete-ExternalTransferRuntimeLedger -Ledger $syntheticSealLedger }
catch { $nativeSealError = $_.Exception.Message }
Assert-ContractCondition (
    $nativeSealError -like '*native fault actual observations are incomplete*'
) 'missing native fault observations were not identified before seal'

$rawHelperIdentity = [pscustomobject][ordered]@{
    name = 'serctl-xfer'; binary_size = [long]303; sha256 = ('c' * 64)
    version = [string]$fixtureComponents.helper.version
}
$faultDefinitions = [ordered]@{
    resume_25 = @('completed', 25, 'complete', 1, 0)
    resume_75 = @('completed', 75, 'complete', 1, 0)
    lost_ack = @('outcome_unknown', 0, 'owned_partial_preserved', 0, 1)
    helper_crash = @('outcome_unknown', 0, 'owned_partial_preserved', 0, 1)
    disconnect = @('outcome_unknown', 0, 'owned_partial_preserved', 0, 1)
    daemon_restart = @('outcome_unknown', 0, 'owned_partial_preserved', 0, 1)
    disk_full = @('transfer_failed', 0, 'owned_partial_removed', 0, 0)
    permission_denied = @('transfer_failed', 0, 'owned_partial_removed', 0, 0)
    target_race = @('transfer_failed', 0, 'owned_partial_removed', 0, 0)
    target_symlink_or_reparse = @('transfer_failed', 0, 'no_owned_partial_created', 0, 0)
    unknown_cleanup = @('cleanup_incomplete', 0, 'cleanup_incomplete', 0, 1)
}
function New-NativeFaultRawFixture {
    param([Parameter(Mandatory = $true)][string]$CaseId)
    $definition = $faultDefinitions[$CaseId]
    $ackEvents = if ($CaseId -ceq 'lost_ack') { [int64]0 } else { [int64]1 }
    return [pscustomobject][ordered]@{
        schema_version = 1; source = 'private_actual_capture_v1'; case_id = $CaseId
        context_sha256 = $fixtureContextSha256
        component_set_sha256 = $nativeFixtureState.bound_component_set_sha256
        helper_identity = $rawHelperIdentity
        terminal_result_code = [string]$definition[0]
        resume_percent_observed = [int64]$definition[1]
        cleanup_state_observed = [string]$definition[2]
        ack_events = $ackEvents
        confirmed_bytes_before_first_ack = [int64]0
        target_identity_before_sha256 = ('E' * 64)
        target_identity_after_sha256 = ('E' * 64)
        foreign_partial_before_sha256 = ('F' * 64)
        foreign_partial_after_sha256 = ('F' * 64)
        owned_partial_count_before = [int64]$definition[3]
        owned_partial_count_after = [int64]$definition[4]
    }
}
function Add-TestNativeFaultRaw {
    param($Raw)
    & $contractModule {
        param($Ledger, $Raw)
        Add-NativeFaultActualObservationInternal (Resolve-LedgerState $Ledger) $Raw
    } $syntheticSealLedger $Raw
}
$invalidFaultAck = New-NativeFaultRawFixture 'resume_25'
$invalidFaultAck.confirmed_bytes_before_first_ack = [int64]1
Assert-Rejected -Action { Add-TestNativeFaultRaw $invalidFaultAck } `
    -Description 'native fault pre-ACK confirmation'
$invalidFaultType = New-NativeFaultRawFixture 'resume_25'
$invalidFaultType.resume_percent_observed = '25'
Assert-Rejected -Action { Add-TestNativeFaultRaw $invalidFaultType } `
    -Description 'native fault type-confused resume percent'
$invalidFaultUnknown = New-NativeFaultRawFixture 'resume_25'
$invalidFaultUnknown | Add-Member -NotePropertyName future -NotePropertyValue $true
Assert-Rejected -Action { Add-TestNativeFaultRaw $invalidFaultUnknown } `
    -Description 'native fault unknown field'
foreach ($caseId in $faultDefinitions.Keys) {
    Add-TestNativeFaultRaw (New-NativeFaultRawFixture $caseId)
}
$nativeSealError = $null
try { Complete-ExternalTransferRuntimeLedger -Ledger $syntheticSealLedger }
catch { $nativeSealError = $_.Exception.Message }
Assert-ContractCondition (
    $nativeSealError -like '*native registry/window actual observation is missing*'
) 'missing native registry/window observation was not identified before seal'

$registryRaw = [pscustomobject][ordered]@{
    schema_version = 1; source = 'private_actual_capture_v1'; case_id = 'registry_window'
    context_sha256 = $fixtureContextSha256
    component_set_sha256 = $nativeFixtureState.bound_component_set_sha256
    helper_identity = $rawHelperIdentity
    active_per_profile = [int64]8; active_global = [int64]48
    terminal_per_profile = [int64]16; terminal_global = [int64]256
    retention_max_seconds = [int64]900; sftp_write_bytes = [int64]2048
    sftp_inflight_writes = [int64]1; native_chunk_bytes = [int64]32768
    native_ack_window_bytes = [int64]32768; cross_profile_visible_count = [int64]0
    oversize_control_frames_accepted = [int64]0
    confirmed_bytes_before_first_ack = [int64]0
}
$invalidRegistry = $registryRaw.PSObject.Copy()
$invalidRegistry.cross_profile_visible_count = [int64]1
Assert-Rejected -Action {
    & $contractModule {
        param($Ledger, $Raw)
        Set-NativeRegistryWindowActualObservationInternal (Resolve-LedgerState $Ledger) $Raw
    } $syntheticSealLedger $invalidRegistry
} -Description 'native registry cross-profile visibility'
& $contractModule {
    param($Ledger, $Raw)
    Set-NativeRegistryWindowActualObservationInternal (Resolve-LedgerState $Ledger) $Raw
} $syntheticSealLedger $registryRaw
$nativeSealError = $null
try { Complete-ExternalTransferRuntimeLedger -Ledger $syntheticSealLedger }
catch { $nativeSealError = $_.Exception.Message }
Assert-ContractCondition (
    $nativeSealError -like '*native performance raw measurements are missing*'
) 'missing native performance measurements were not identified before seal'

function New-PerformanceSamples {
    param([int64]$BaseElapsed)
    return @(1..5 | ForEach-Object {
        [pscustomobject][ordered]@{
            sample_index = [int64]$_; size_bytes = [int64]67108864
            elapsed_microseconds = [int64]($BaseElapsed + ($_ * 1000))
            cpu_basis_points = [int64](2000 + $_)
            peak_rss_bytes = [int64](8000000 + $_)
            rtt_microseconds = [int64](100 + $_)
        }
    })
}
$performanceRaw = [pscustomobject][ordered]@{
    schema_version = 1; source = 'private_actual_capture_v1'
    context_sha256 = $fixtureContextSha256
    component_set_sha256 = $nativeFixtureState.bound_component_set_sha256
    helper_identity = $rawHelperIdentity
    chunk_bytes = [int64]32768; window_bytes = [int64]32768
    native_samples = New-PerformanceSamples 700000
    scp_samples = New-PerformanceSamples 800000
}
$invalidPerformance = $performanceRaw.PSObject.Copy()
$invalidPerformance.native_samples = @($invalidPerformance.native_samples | Select-Object -First 4)
Assert-Rejected -Action {
    & $contractModule {
        param($Ledger, $Raw)
        Set-NativePerformanceActualMeasurementsInternal (Resolve-LedgerState $Ledger) $Raw
    } $syntheticSealLedger $invalidPerformance
} -Description 'native performance incomplete raw sample set'
& $contractModule {
    param($Ledger, $Raw)
    Set-NativePerformanceActualMeasurementsInternal (Resolve-LedgerState $Ledger) $Raw
} $syntheticSealLedger $performanceRaw
$nativeSealError = $null
try { Complete-ExternalTransferRuntimeLedger -Ledger $syntheticSealLedger }
catch { $nativeSealError = $_.Exception.Message }
Assert-ContractCondition (
    $nativeSealError -like '*private raw structures cannot substitute for an isolated actual-capture owner*' -and
    $nativeSealError -like '*release seal refused*'
) 'synthetic complete native raw structures reached or bypassed the final seal refusal'
$syntheticSealStatus = Get-ExternalTransferRuntimeLedgerStatus $syntheticSealLedger
Assert-ContractCondition (-not $syntheticSealStatus.sealed) (
    'synthetic transfer prerequisite changed the formal seal bit'
)

$syntheticInteropSealLedger = New-ExternalTransferRuntimeLedger `
    -Category 'openssh_dropbear_interop'
& $contractModule {
    param($Ledger, $FixtureState)
    $state = Resolve-LedgerState $Ledger
    foreach ($caseId in $state.expected_case_ids) {
        $state.observations[$caseId] = [pscustomobject]@{ synthetic = $true }
    }
    $state.blocked_case_ids.Clear()
    $state.bound_evidence_context_sha256 =
        $FixtureState.bound_evidence_context_sha256
    $state.bound_component_set_sha256 = $FixtureState.bound_component_set_sha256
    $state.bound_component_bytes = $FixtureState.bound_component_bytes
    $state.immutable_transfer_cases = $FixtureState.immutable_transfer_cases
    $state.immutable_transfer_details = $FixtureState.immutable_transfer_details
} $syntheticInteropSealLedger $interopFixtureState
$interopSealError = $null
try { Complete-ExternalTransferRuntimeLedger -Ledger $syntheticInteropSealLedger }
catch { $interopSealError = $_.Exception.Message }
Assert-ContractCondition (
    $interopSealError -like '*formal runner and remote projections remain unavailable*' -and
    $interopSealError -like '*release seal refused*' -and
    -not (Get-ExternalTransferRuntimeLedgerStatus $syntheticInteropSealLedger).sealed
) 'synthetic complete interop prerequisite did not reach the intended seal refusal'
Assert-Rejected `
    -Action {
        Write-ProtectedExternalTransferRuntimeReceipt `
            -Ledger $ledger `
            -Path (Join-Path ([System.IO.Path]::GetTempPath()) 'must-not-exist.evidence')
    } `
    -Description 'unsealed ledger receipt write'

foreach ($badVector in @(
    @('true', 'Authorization: Bearer abc123'),
    @('true', 'Bearer abc123'),
    @('true', '-i', 'id_ed25519'),
    @('true', 'C:\Users\operator\.ssh\id_ed25519'),
    @('true', '\Users\operator\.ssh\id_ed25519'),
    @('true', 'C:relative\id_ed25519'),
    @('true', '..\private\id_ed25519'),
    @('true', 'client_secret=abc123')
)) {
    Assert-Rejected `
        -Action {
            Test-ExternalTransferRuntimeArgumentVector -ArgumentVector $badVector
        } `
        -Description 'credential/path-shaped controlled argument vector'
}
Assert-ContractCondition (
    Test-ExternalTransferRuntimeArgumentVector -ArgumentVector @('true', 'safe-fixture')
) 'bounded safe argument vector was rejected'

Write-Host 'External transfer runtime receipt contract self-test passed (formal evidence BLOCKED).'
