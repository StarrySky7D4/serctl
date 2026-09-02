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
        throw "whole-bundle runtime receipt contract self-test failed: $Message"
    }
}

$harnessPath = Join-Path $PSScriptRoot 'Invoke-WholeBundleUpgradeRollbackHarness.ps1'
$verifierPath = Join-Path $PSScriptRoot 'Test-ExternalAcceptanceEvidence.ps1'
$source = Get-Content -LiteralPath $harnessPath -Raw -Encoding utf8
$verifier = Get-Content -LiteralPath $verifierPath -Raw -Encoding utf8
$tokens = $null
$parseErrors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile(
    $harnessPath,
    [ref]$tokens,
    [ref]$parseErrors
)
Assert-ContractCondition (@($parseErrors).Count -eq 0) 'runtime harness does not parse'

foreach ($marker in @(
    "ParameterSetName = 'Runtime'",
    'Invoke-WholeBundleRuntimeGates',
    'Write-WholeBundleAcceptanceReceipt',
    '-RuntimeResult $runtime',
    '[System.IO.FileMode]::CreateNew',
    '[System.IO.FileShare]::None',
    '[System.IO.FileOptions]::WriteThrough',
    'whole-bundle receipt post-write hash or identity check failed',
    "category = 'whole_bundle_upgrade_rollback'",
    'release_manifest_sha256 = $ReleaseManifestSha256',
    'predecessor_version = $predecessorVersion',
    'candidate_version = $candidateVersion',
    'descriptor_daemon_sha256',
    'SERCTL_PROFILE_PASSPHRASE',
    'candidate CLI accepted the live predecessor daemon',
    'predecessor CLI accepted the live candidate daemon',
    'candidate accepted a predecessor runtime descriptor',
    'pre-restart OperationGrant was accepted by the new daemon instance',
    'beta2-rejected-grant.json',
    '-RuntimeStateDirectory $runDirectory',
    'beta-2 rejection reached its grant output writer',
    'beta-2 rejection changed upgraded vault or matching recovery bytes',
    'transient_runtime_activation_observed',
    'beta-2 rejection left a runtime descriptor or activation secret after command exit',
    'Assert-Beta2RuntimeRejectionObservation',
    'Wait-Beta2RuntimeStateCleanup',
    'Assert-CompleteRecoverySetEvidence',
    'Assert-RuntimeRecoverySetRestored',
    'binary-only rollback is forbidden',
    'exact pre-upgrade recovery set',
    'runtime recovery set'
)) {
    Assert-ContractCondition ($source.Contains($marker)) "runtime harness omits '$marker'"
}
Assert-ContractCondition (
    -not $source.Contains('beta-2 rejection reached daemon activation before the storage gate')
) 'runtime harness still treats final absence as proof of no transient activation'

$detailFields = @(
    'runner', 'predecessor_version', 'candidate_version', 'upgrade_outcome',
    'rollback_outcome', 'predecessor_files', 'candidate_files',
    'descriptor_owner_pid', 'descriptor_daemon_identity', 'descriptor_daemon_sha256',
    'whole_bundle_atomic', 'mixed_triples_tested', 'mixed_triples_rejected',
    'hash_substitutions_tested', 'hash_substitutions_rejected',
    'stale_descriptor_rejected', 'stale_grant_rejected',
    'matched_bundle_upgrade_verified', 'matched_bundle_rollback_verified',
    'audit_seed_key_package_verified', 'vault_storage_v4_to_v5_upgrade_verified',
    'beta2_destructive_writer_blocked_before_mutation',
    'beta2_transient_runtime_activation_observed',
    'beta2_runtime_state_cleaned_after_rejection',
    'candidate_storage_marker_verified',
    'v8_unknown_audit_fields_rejected_before_write',
    'unknown_security_fields_not_dropped', 'vault_rollback_verified',
    'pre_upgrade_vault_backup_restored', 'matching_recovery_media_restored',
    'acl_owner_metadata_restored'
)
foreach ($field in $detailFields) {
    Assert-ContractCondition (
        $source.Contains("$field =") -and $verifier.Contains("'$field'")
    ) "runtime receipt/verifier closed details drift at '$field'"
}

foreach ($forbidden in @(
    'RuntimeResultPath',
    'AcceptanceGatesPath',
    'Import-Clixml',
    'accepted = $true'
)) {
    Assert-ContractCondition (-not $source.Contains($forbidden)) (
        "runtime harness permits a synthetic acceptance shortcut '$forbidden'"
    )
}

$runtimeIndex = $source.LastIndexOf('Invoke-WholeBundleRuntimeGates')
$receiptIndex = $source.LastIndexOf('Write-WholeBundleAcceptanceReceipt')
Assert-ContractCondition (
    $runtimeIndex -ge 0 -and $receiptIndex -gt $runtimeIndex
) 'receipt can be written before the same-process runtime gates finish'

Write-Host 'Whole-bundle runtime receipt contract self-test passed.'
