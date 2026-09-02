Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$harnessPath = Join-Path $PSScriptRoot 'Invoke-CleanInstallSmokeHarness.ps1'
$verifierPath = Join-Path $PSScriptRoot 'Test-ExternalAcceptanceEvidence.ps1'

function Assert-CleanInstallContract {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if (-not $Condition) {
        throw "clean-install smoke harness contract self-test failed: $Message"
    }
}

foreach ($path in @($harnessPath, $verifierPath)) {
    Assert-CleanInstallContract (Test-Path -LiteralPath $path -PathType Leaf) (
        "required script '$([System.IO.Path]::GetFileName($path))' is absent"
    )
    $tokens = $null
    $errors = $null
    [void][System.Management.Automation.Language.Parser]::ParseFile(
        $path,
        [ref]$tokens,
        [ref]$errors
    )
    Assert-CleanInstallContract ($errors.Count -eq 0) (
        "required script '$([System.IO.Path]::GetFileName($path))' does not parse"
    )
}

$source = Get-Content -LiteralPath $harnessPath -Raw -Encoding utf8
$verifier = Get-Content -LiteralPath $verifierPath -Raw -Encoding utf8

foreach ($marker in @(
    "ParameterSetName = 'Runtime'",
    '[string]$CandidateDirectory',
    '[string]$PredecessorDirectory',
    '[string]$PredecessorCommit',
    '[string]$ScratchParent',
    'Invoke-CleanInstallRuntime',
    'Write-CleanInstallAcceptanceReceipt',
    'Write-ProtectedCleanInstallReceipt',
    '[System.IO.FileMode]::CreateNew',
    '[System.IO.FileShare]::None',
    '[System.IO.FileOptions]::WriteThrough',
    'bytes do not match the same-process digest',
    'HOME = $Home',
    'USERPROFILE = $Home',
    'LOCALAPPDATA',
    "'status', `$profileName",
    "'grant-issue', `$profileName",
    "'down', `$profileName",
    "'192.0.2.1'",
    'runtime descriptor PID is not the installed candidate daemon',
    'running daemon bytes differ from the downloaded candidate daemon',
    'isolated runtime descriptor or activation secret remained after shutdown',
    'restored predecessor did not open a fresh rollback home',
    'formal clean-install runtime requires a disposable GitHub-hosted runner scratch root',
    'Open-PinnedCleanInstallFile',
    '[SerctlCleanInstallNative]::FILE_FLAG_OPEN_REPARSE_POINT',
    'Update-CleanInstallDaemonOwner',
    'Find-CleanInstallOwnedDaemon',
    'Stop-CleanInstallOwnedDaemon',
    '$owned.process.Kill()',
    'descriptor_identity',
    'secret_identity',
    'ExpectedBinaryRecord',
    '$stdoutBuffer.Length -le 1048576',
    'Read-CleanInstallGrantMetadata',
    'Assert-CleanInstallAgentConsumption',
    "'daemon.status'",
    "'agent.operation_failed'",
    "'agent', '--grant', `$grantPath",
    '-StandardInputText $agentInput',
    'consumed OperationGrant file remained after bounded cleanup',
    'matched predecessor IPC v8 status failed; output withheld',
    'predecessor daemon ownership or descriptor identity was not captured',
    'predecessor runtime descriptor or activation secret remained after shutdown',
    'Get-CleanInstallFailureLogRecord',
    "category=clean_install_runtime_failed; file='clean-install.evidence'; bytes=0",
    'Remove-OwnedCleanInstallRoot',
    'isolated daemon ownership is ambiguous; refusing PID-based cleanup',
    "category = 'clean_install_smoke'",
    "storage_contract = `$candidateStorageContract",
    'cleanup_passed = $true'
)) {
    Assert-CleanInstallContract ($source.Contains($marker)) "missing marker: $marker"
}

foreach ($forbidden in @(
    'RuntimeResultPath',
    'AcceptanceResultPath',
    'Import-Clixml',
    'Invoke-Expression',
    'Start-Process',
    'Stop-Process',
    'ReadToEndAsync',
    '$_.Exception',
    'ssh.exec',
    'serctl-xfer'
)) {
    Assert-CleanInstallContract (-not $source.Contains($forbidden)) (
        "forbidden result injection or remote-operation marker is present: $forbidden"
    )
}

$runtimeCall = $source.LastIndexOf('$runtimeResult = Invoke-CleanInstallRuntime')
$receiptCall = $source.LastIndexOf('Write-CleanInstallAcceptanceReceipt')
Assert-CleanInstallContract (
    $runtimeCall -ge 0 -and $receiptCall -gt $runtimeCall
) 'formal receipt is not emitted strictly after the same-process runtime result'

foreach ($marker in @(
    "'storage_contract'",
    "'cleanup_passed'",
    "'vault-storage read=v4..=v5 write=v5'",
    "clean_install_smoke details.cli_identity",
    "clean_install_smoke details.daemon_identity"
)) {
    Assert-CleanInstallContract ($verifier.Contains($marker)) (
        "external verifier lacks the producer contract marker: $marker"
    )
}

& $harnessPath -SelfTest

Write-Output 'Clean-install smoke harness contract self-test passed.'
