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
        throw "Windows ACL receipt contract self-test failed: $Message"
    }
}

$gatePath = Join-Path $PSScriptRoot 'Test-WindowsMultiAccountAcl.ps1'
$verifierPath = Join-Path $PSScriptRoot 'Test-ExternalAcceptanceEvidence.ps1'
$source = Get-Content -LiteralPath $gatePath -Raw -Encoding utf8
$verifier = Get-Content -LiteralPath $verifierPath -Raw -Encoding utf8
$tokens = $null
$errors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile(
    $gatePath,
    [ref]$tokens,
    [ref]$errors
)
Assert-ContractCondition (@($errors).Count -eq 0) 'gate script does not parse'

foreach ($marker in @(
    'Write-ProtectedCreateNewReceipt',
    '[System.IO.FileMode]::CreateNew',
    '[System.IO.FileShare]::None',
    '[System.IO.FileOptions]::WriteThrough',
    'SetAccessRuleProtection($true, $false)',
    'protected receipt bytes do not match the same-process receipt digest',
    'Write-AclEvidenceReceipt',
    '-Details $gateResult',
    "category = 'windows_privileged_acl'",
    'release_manifest_sha256 = $ReleaseManifestSha256',
    'candidate_cli_sha256 = $candidateCliSha256',
    "os = 'Windows'",
    "arch = 'X64'",
    "rust_host = 'x86_64-pc-windows-msvc'",
    'reparse_point_rejected = $true',
    'cleanup_passed = $true',
    'captured output withheld',
    'Format-ReleaseLogRecord'
)) {
    Assert-ContractCondition ($source.Contains($marker)) "gate omits '$marker'"
}

$detailFields = @(
    'runner',
    'candidate_cli_sha256',
    'owner_sid',
    'observer_sid',
    'distinct_sids',
    'parent_control_passed',
    'observer_read_denied',
    'observer_write_denied',
    'owner_reopen_passed',
    'dacl_protected',
    'reparse_point_rejected',
    'owner_rights_restricted',
    'system_full_control',
    'administrators_full_control',
    'inheritance_protected',
    'cleanup_passed'
)
foreach ($field in $detailFields) {
    Assert-ContractCondition (
        $source.Contains("$field =") -and $verifier.Contains("'$field'")
    ) "gate/verifier closed details drift at '$field'"
}

foreach ($forbidden in @(
    'ConvertFrom-Json',
    'GateResultPath',
    'ResultPath',
    '$cliOutput',
    '$_.Exception.Message',
    'Write-Error $_'
)) {
    Assert-ContractCondition (-not $source.Contains($forbidden)) (
        "gate permits untrusted result input or unsafe failure logging '$forbidden'"
    )
}

Write-Host 'Windows ACL receipt contract self-test passed.'
