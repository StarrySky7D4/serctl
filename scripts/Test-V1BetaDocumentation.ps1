[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'StrictJson.ps1')

function Assert-DocumentationCondition {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if (-not $Condition) {
        throw "v1 beta documentation check failed: $Message"
    }
}

function Read-RequiredText {
    param([Parameter(Mandatory = $true)][string]$RelativePath)

    $path = Join-Path $repositoryRoot $RelativePath
    Assert-DocumentationCondition (Test-Path -LiteralPath $path -PathType Leaf) (
        "required file '$RelativePath' is missing"
    )
    return Get-Content -LiteralPath $path -Raw -Encoding utf8
}

function Read-RequiredStrictUtf8Text {
    param([Parameter(Mandatory = $true)][string]$RelativePath)

    $path = Join-Path $repositoryRoot $RelativePath
    Assert-DocumentationCondition (Test-Path -LiteralPath $path -PathType Leaf) (
        "required file '$RelativePath' is missing"
    )
    try {
        return Read-StrictUtf8Text -Path $path
    }
    catch {
        throw "v1 beta documentation check failed: '$RelativePath' is not strict UTF-8"
    }
}

function Assert-ClosedFixtureObject {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][string[]]$Fields,
        [Parameter(Mandatory = $true)][string]$Label
    )
    Assert-DocumentationCondition (Test-StrictJsonObject $Value) "$Label is not a JSON object"
    $actual = @($Value.PSObject.Properties.Name | Sort-Object)
    $expected = @($Fields | Sort-Object)
    Assert-DocumentationCondition (($actual -join "`n") -ceq ($expected -join "`n")) (
        "$Label does not use the exact closed schema"
    )
}

function Get-UniqueMatches {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][string]$Pattern,
        [Parameter(Mandatory = $true)][string]$Group
    )

    return @(
        [regex]::Matches(
            $Text,
            $Pattern,
            [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
        ) |
            ForEach-Object { $_.Groups[$Group].Value } |
            Sort-Object -Unique
    )
}

function Test-SourcePattern {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][string]$Pattern
    )

    return [regex]::IsMatch(
        $Text,
        $Pattern,
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
}

function Get-SourceRegion {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][string]$StartMarker,
        [Parameter(Mandatory = $true)][string]$EndMarker,
        [Parameter(Mandatory = $true)][string]$Description
    )

    $comparison = [System.StringComparison]::Ordinal
    $start = $Text.IndexOf($StartMarker, $comparison)
    Assert-DocumentationCondition ($start -ge 0) "cannot isolate $Description start"
    $end = $Text.IndexOf($EndMarker, $start + $StartMarker.Length, $comparison)
    Assert-DocumentationCondition ($end -gt $start) "cannot isolate $Description end"
    return $Text.Substring($start, $end - $start)
}

function Assert-SourcePattern {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][string]$Pattern,
        [Parameter(Mandatory = $true)][string]$Description
    )

    Assert-DocumentationCondition (Test-SourcePattern -Text $Text -Pattern $Pattern) (
        "$Description is missing"
    )
}

function Assert-SourceOrder {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][string]$FunctionMarker,
        [Parameter(Mandatory = $true)][string]$GuardMarker,
        [Parameter(Mandatory = $true)][string[]]$LaterMarkers,
        [Parameter(Mandatory = $true)][string]$Operation
    )

    $comparison = [System.StringComparison]::Ordinal
    $functionIndex = $Text.IndexOf($FunctionMarker, $comparison)
    Assert-DocumentationCondition ($functionIndex -ge 0) "cannot find Agent $Operation function"
    $guardIndex = $Text.IndexOf($GuardMarker, $functionIndex, $comparison)
    Assert-DocumentationCondition ($guardIndex -ge $functionIndex) (
        "Agent $Operation has no exact-scope guard"
    )
    foreach ($marker in $LaterMarkers) {
        $laterIndex = $Text.IndexOf($marker, $functionIndex, $comparison)
        Assert-DocumentationCondition ($laterIndex -gt $guardIndex) (
            "Agent $Operation scope guard does not precede '$marker'"
        )
    }
}

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$main = Read-RequiredText 'crates/serctl_cli/src/main.rs'
$client = Read-RequiredText 'crates/serctl_cli/src/client.rs'
$auditRecovery = Read-RequiredText 'crates/serctl_cli/src/audit_recovery.rs'
$daemon = Read-RequiredText 'crates/serctl_daemon/src/daemon.rs'
$wire = Read-RequiredText 'crates/serctl_protocol/src/v6.rs'
$recovery = Read-RequiredText 'crates/serctl_core/src/recovery.rs'
$agentContract = Read-RequiredText 'docs/v1-beta-agent-jsonl.md'
$readme = Read-RequiredText 'README.md'
$guide = Read-RequiredText 'docs/serctl-user-guide.md'
$releaseContract = Read-RequiredText 'docs/v1-beta-release-contract.md'
$matrix = Read-RequiredText 'docs/v1-beta-acceptance-matrix.md'
$runtimeAdapter = Read-RequiredText 'scripts/ExternalTransferRuntimeAdapter.ps1'
$security = Read-RequiredText 'SECURITY.md'
$changelog = Read-RequiredText 'CHANGELOG.md'
$architecture = Read-RequiredText 'docs/serctl-architecture-security.html'
$upgradeRollback = Read-RequiredText 'docs/v1-beta-upgrade-rollback-harness.md'
$sshPreauthDiagnostics = Read-RequiredText 'docs/ssh-preauth-diagnostics.md'
$sshPreauthEvidenceTemplate = Read-RequiredText 'docs/ssh-preauth-server-evidence.template.json'
$sshPreauthEvidenceVerifier = Read-RequiredText 'scripts/Test-SshPreAuthServerEvidence.ps1'
$sshPreauthEvidenceSelfTest = Read-RequiredText 'scripts/Test-SshPreAuthServerEvidenceSelfTest.ps1'
$cliHelpFixture = Read-RequiredText 'crates/serctl_cli/tests/fixtures/cli-help-v1.txt'
$cliContractFixture = Read-RequiredStrictUtf8Text 'crates/serctl_cli/tests/fixtures/cli-contract-v1.json'
$cliHelpTreeFixture = Read-RequiredText 'crates/serctl_cli/tests/fixtures/cli-help-tree-v1.txt'
$cliCommandTreeFixture = Read-RequiredStrictUtf8Text 'crates/serctl_cli/tests/fixtures/cli-command-tree-v1.json'
$agentResultFixture = Read-RequiredStrictUtf8Text 'crates/serctl_cli/tests/fixtures/agent-result-v1.jsonl'
$transferProgressFixture = Read-RequiredStrictUtf8Text 'crates/serctl_cli/tests/fixtures/transfer-progress-v1.jsonl'

Assert-DocumentationCondition ($client -match '(?m)^pub const AGENT_SCHEMA_VERSION: u16 = 1;\s*$') (
    'Agent source does not declare schema version 1'
)
Assert-DocumentationCondition ($wire -match '(?m)^pub const IPC_PROTOCOL_VERSION_V9: u16 = 9;\s*$') (
    'wire source does not declare IPC v9'
)
Assert-DocumentationCondition (
    $wire -match '(?m)^pub const IPC_PROTOCOL_VERSION_V6: u16 = IPC_PROTOCOL_VERSION_V9;\s*$'
) 'the compatibility constant is not bound to IPC v9'

$requestEnum = [regex]::Match(
    $client,
    '(?s)enum AgentRequest\s*\{(?<body>.*?)\r?\n\}\r?\n\r?\nimpl AgentRequest'
)
Assert-DocumentationCondition $requestEnum.Success 'cannot isolate AgentRequest enum'
$requestBody = $requestEnum.Groups['body'].Value
$grantable = [regex]::Match(
    $daemon,
    '(?s)const GRANTABLE_OPERATION_KINDS:\s*&\[&str\]\s*=\s*&\[(?<body>.*?)\];'
)
Assert-DocumentationCondition $grantable.Success 'cannot isolate daemon grantable-operation list'
$grantableBody = $grantable.Groups['body'].Value

$agentOperationMappings = @(
    @{ Variant = 'Exec'; Operation = 'ssh.exec' },
    @{ Variant = 'Status'; Operation = 'daemon.status' },
    @{ Variant = 'ListDir'; Operation = 'sftp.list' },
    @{ Variant = 'CreateDir'; Operation = 'sftp.write' },
    @{ Variant = 'TransferPush'; Operation = 'transfer.write' },
    @{ Variant = 'TransferPull'; Operation = 'transfer.read' },
    @{ Variant = 'TransferStatus'; Operation = 'transfer.status' },
    @{ Variant = 'TransferCancel'; Operation = 'transfer.cancel' },
    @{ Variant = 'ForwardLocalOpen'; Operation = 'forward.local/open' },
    @{ Variant = 'ForwardRemoteOpen'; Operation = 'forward.remote/open' },
    @{ Variant = 'ForwardDynamicOpen'; Operation = 'forward.dynamic/open' },
    @{ Variant = 'ForwardStatus'; Operation = 'forward.status' },
    @{ Variant = 'ForwardCancel'; Operation = 'forward.cancel' },
    @{ Variant = 'SshConnectionIdentity'; Operation = 'ssh.connection-identity' }
)
Assert-DocumentationCondition ($agentOperationMappings.Count -eq 14) (
    'Agent request-to-scope golden count is not 14'
)
foreach ($mapping in $agentOperationMappings) {
    Assert-DocumentationCondition (
        $requestBody -match "\b$([regex]::Escape($mapping.Variant))\s*\{"
    ) "Agent handler '$($mapping.Variant)' is missing"
    Assert-DocumentationCondition (
        $grantableBody.Contains("`"$($mapping.Operation)`"")
    ) "Agent handler '$($mapping.Variant)' has no daemon issuance entry '$($mapping.Operation)'"
}
$issuedAgentOperations = Get-UniqueMatches `
    -Text $grantableBody `
    -Pattern '"(?<kind>[a-z0-9./-]+)"' `
    -Group 'kind'
$expectedAgentOperations = @(
    $agentOperationMappings | ForEach-Object { $_.Operation } | Sort-Object -Unique
)
Assert-DocumentationCondition (
    (($issuedAgentOperations -join ',') -ceq ($expectedAgentOperations -join ','))
) (
    "daemon issuance operations '$($issuedAgentOperations -join ',')' differ from Agent handlers '$($expectedAgentOperations -join ',')'"
)

$hasStatusHandler = $requestBody -match '\bTransferStatus\s*\{'
$hasCancelHandler = $requestBody -match '\bTransferCancel\s*\{'
$issuesStatus = $grantableBody.Contains('"transfer.status"')
$issuesCancel = $grantableBody.Contains('"transfer.cancel"')
Assert-DocumentationCondition ($hasStatusHandler -eq $issuesStatus) (
    'transfer.status handler and daemon issuance list are split'
)
Assert-DocumentationCondition ($hasCancelHandler -eq $issuesCancel) (
    'transfer.cancel handler and daemon issuance list are split'
)
$expectedReadiness = if (
    $hasStatusHandler -and $hasCancelHandler -and $issuesStatus -and $issuesCancel
) {
    'implemented-unreleased'
}
else {
    'pending-handler-and-grant-list'
}
$readiness = [regex]::Match(
    $agentContract,
    '(?m)^Agent transfer/tunnel/connection-identity source readiness: `(?<value>[^`]+)`\s*$'
)
Assert-DocumentationCondition $readiness.Success 'Agent contract has no source-readiness marker'
Assert-DocumentationCondition ($readiness.Groups['value'].Value -ceq $expectedReadiness) (
    "Agent contract readiness '$($readiness.Groups['value'].Value)' does not match source '$expectedReadiness'"
)

$sourceMappings = @(
    'Frame::Exec { .. } => "ssh.exec"',
    'Frame::ConnectionIdentity { .. } => "ssh.connection-identity"',
    'Frame::Status => "daemon.status"',
    'Frame::ListDir { .. } => "sftp.list"',
    'Frame::CreateDir { .. } => "sftp.write"',
    '"transfer.write"',
    'Frame::Download { .. } => "transfer.read"',
    'Frame::TransferStatus { .. } => "transfer.status"',
    'Frame::TransferCancel { .. } => "transfer.cancel"',
    '"forward.local/open"',
    '"forward.remote/open"',
    '"forward.dynamic/open"',
    'Frame::ManagedTunnelStatus { .. } => "forward.status"',
    'Frame::ManagedTunnelCancel { .. } => "forward.cancel"'
)
foreach ($mapping in $sourceMappings) {
    Assert-DocumentationCondition ($wire.Contains($mapping)) "wire mapping '$mapping' is missing"
}
$documentMappings = @(
    '`status` | `daemon.status`',
    '`exec` | `ssh.exec`',
    '`list-dir` | `sftp.list`',
    '`create-dir` | `sftp.write`',
    '`transfer-push` | `transfer.write`',
    '`transfer-pull` | `transfer.read`',
    '`transfer-status` | `transfer.status`',
    '`transfer-cancel` | `transfer.cancel`',
    '`forward-local-open` | `forward.local/open`',
    '`forward-remote-open` | `forward.remote/open`',
    '`forward-dynamic-open` | `forward.dynamic/open`',
    '`forward-status` | `forward.status`',
    '`forward-cancel` | `forward.cancel`',
    '`ssh-connection-identity` | `ssh.connection-identity`'
)
foreach ($mapping in $documentMappings) {
    Assert-DocumentationCondition ($agentContract.Contains($mapping)) (
        "Agent contract mapping '$mapping' is missing"
    )
}

$scopeOrderChecks = @(
    @{
        Operation = 'exec'
        Function = 'pub(crate) async fn agent_exec_until('
        Guard = 'require_agent_operation_scope(grant, AGENT_EXEC_OPERATION)?;'
        Later = @('validate_remote_command(cmd)?;', 'connect_grant_request_until(grant, signing, &request, timeout).await?')
    }
    @{
        Operation = 'list-dir'
        Function = 'pub(crate) async fn agent_list_until('
        Guard = 'require_agent_operation_scope(grant, AGENT_LIST_OPERATION)?;'
        Later = @('validate_remote_path(path, false)?;', 'connect_grant_request_until(grant, signing, &request, timeout).await?')
    },
    @{
        Operation = 'create-dir'
        Function = 'async fn agent_create_dir_until('
        Guard = 'require_agent_operation_scope(grant, AGENT_CREATE_DIR_OPERATION)?;'
        Later = @('validate_remote_path(path, false)?;', 'connect_grant_request_until(grant, signing, &request, timeout).await?')
    },
    @{
        Operation = 'transfer-push'
        Function = 'pub(crate) async fn agent_transfer_push_until('
        Guard = 'require_agent_transfer_write_scope(grant)?;'
        Later = @('validate_upload_remote_path(remote)?;', 'open_local_upload_source(local, deadline, &cancellation, idle_timeout_ms).await?')
    },
    @{
        Operation = 'transfer-pull'
        Function = 'pub(crate) async fn agent_transfer_pull_until('
        Guard = 'require_agent_transfer_read_scope(grant)?;'
        Later = @('validate_remote_path(remote, false)?;', 'let local = std::path::absolute(local).context("resolve local transfer target identity")?;', 'tokio::fs::try_exists(&local)')
    },
    @{
        Operation = 'transfer-status'
        Function = 'pub(crate) async fn agent_transfer_status_until('
        Guard = 'require_agent_transfer_status_scope(grant)?;'
        Later = @('let request = ipc::Frame::TransferStatus {', 'connect_grant_request_until(grant, signing, &request, timeout).await?')
    },
    @{
        Operation = 'transfer-cancel'
        Function = 'pub(crate) async fn agent_transfer_cancel_until('
        Guard = 'require_agent_transfer_cancel_scope(grant)?;'
        Later = @('let request = ipc::Frame::TransferCancel {', 'connect_grant_request_until(grant, signing, &request, timeout).await?')
    },
    @{
        Operation = 'forward-open'
        Function = 'async fn agent_forward_open_deferred_until('
        Guard = 'require_agent_operation_scope(grant, operation_kind)?;'
        Later = @('let bind_port = deferred.bind_port.parse("bind_port")?;', 'agent_forward_open_until(')
    },
    @{
        Operation = 'forward-status'
        Function = 'async fn agent_forward_status_until('
        Guard = 'require_agent_operation_scope(grant, AGENT_FORWARD_STATUS_OPERATION)?;'
        Later = @('let request = ipc::Frame::ManagedTunnelStatus {', 'connect_grant_request_at_deadline(grant, signing, &request, deadline_unix_ms).await?')
    },
    @{
        Operation = 'forward-cancel'
        Function = 'async fn agent_forward_cancel_until('
        Guard = 'require_agent_operation_scope(grant, AGENT_FORWARD_CANCEL_OPERATION)?;'
        Later = @('let request = ipc::Frame::ManagedTunnelCancel {', 'connect_grant_request_at_deadline(grant, signing, &request, deadline_unix_ms).await?')
    },
    @{
        Operation = 'ssh-connection-identity'
        Function = 'async fn agent_connection_identity_until('
        Guard = 'require_agent_operation_scope(grant, AGENT_CONNECTION_IDENTITY_OPERATION)?;'
        Later = @('let request = ipc::Frame::ConnectionIdentity {', 'connect_grant_request_until(grant, signing, &request, timeout).await?')
    },
    @{
        Operation = 'status'
        Function = 'pub(crate) async fn agent_status_until('
        Guard = 'require_agent_operation_scope(grant, AGENT_STATUS_OPERATION)?;'
        Later = @('let request = ipc::Frame::Status;', 'connect_grant_request_until(grant, signing, &request, timeout).await?')
    }
)
foreach ($check in $scopeOrderChecks) {
    Assert-SourceOrder `
        -Text $client `
        -FunctionMarker $check.Function `
        -GuardMarker $check.Guard `
        -LaterMarkers $check.Later `
        -Operation $check.Operation
}
Assert-DocumentationCondition (
    $client.Contains('"invalid request (diagnostic detail withheld)"') -and
    $client.Contains('anyhow!("{operation} failed (diagnostic detail withheld)")')
) 'Agent generic invalid/operation error redaction is missing'
foreach ($operation in @(
    'exec', 'list-dir', 'create-dir', 'forward-local-open',
    'forward-remote-open', 'forward-dynamic-open', 'forward-status',
    'forward-cancel', 'ssh-connection-identity', 'status'
)) {
    Assert-DocumentationCondition (
        $client.Contains("agent_visible_operation_error(`"$operation`", error)")
    ) "Agent $operation does not use the generic visible-error redactor"
}
foreach ($redactor in @(
    'agent_visible_transfer_push_error',
    'agent_visible_transfer_pull_error',
    'agent_visible_transfer_status_error',
    'agent_visible_transfer_cancel_error'
)) {
    Assert-DocumentationCondition ($client.Contains(".map_err($redactor)")) (
        "Agent transfer dispatch does not use $redactor"
    )
}
Assert-DocumentationCondition ($agentContract.Contains('all 14 operations')) (
    'Agent contract does not state the 14-operation exact-scope preflight'
)
Assert-DocumentationCondition (
    Test-SourcePattern `
        -Text $guide `
        -Pattern '14[^\r\n]{1,96}operation-specific gate'
) (
    'user guide does not state the 14-operation exact-scope preflight'
)
foreach ($document in @(
    @{ Name = 'Agent contract'; Text = $agentContract },
    @{ Name = 'user guide'; Text = $guide }
)) {
    Assert-DocumentationCondition (
        $document.Text.Contains('invalid request (diagnostic detail withheld)') -and
        $document.Text.Contains('diagnostic detail withheld')
    ) "$($document.Name) omits Agent parser/operation redaction"
}

foreach ($document in @(
    @{ Name = 'README'; Text = $readme },
    @{ Name = 'CHANGELOG'; Text = $changelog },
    @{ Name = 'Agent contract'; Text = $agentContract },
    @{ Name = 'user guide'; Text = $guide },
    @{ Name = 'release contract'; Text = $releaseContract },
    @{ Name = 'acceptance matrix'; Text = $matrix }
)) {
    foreach ($token in @(
        'transfer-pull',
        'transfer.read',
        'CREATE_NEW',
        'no-overwrite'
    )) {
        Assert-DocumentationCondition ($document.Text.Contains($token)) (
            "$($document.Name) omits grant-backed pull token '$token'"
        )
    }
}
foreach ($document in @(
    @{ Name = 'README'; Text = $readme },
    @{ Name = 'CHANGELOG'; Text = $changelog },
    @{ Name = 'Agent contract'; Text = $agentContract },
    @{ Name = 'user guide'; Text = $guide },
    @{ Name = 'release contract'; Text = $releaseContract },
    @{ Name = 'acceptance matrix'; Text = $matrix }
)) {
    Assert-DocumentationCondition (
        ($document.Text -match '(?i)terminal-only') -and
        $document.Text.Contains('transfer-status') -and
        $document.Text.Contains('transfer.status')
    ) "$($document.Name) omits the terminal-only pull and independent status-progress boundary"
}
foreach ($stalePullGap in @(
    'Agent has no grant-backed `transfer-pull`',
    'Agent also still lacks grant-backed `transfer-pull`',
    '`transfer.read`, `sftp.read` and every `job.*` operation are not Agent capabilities'
)) {
    foreach ($document in @($readme, $changelog, $agentContract, $guide, $releaseContract, $matrix)) {
        Assert-DocumentationCondition (-not $document.Contains($stalePullGap)) (
            "documentation retains stale grant-backed pull gap '$stalePullGap'"
        )
    }
}
Assert-DocumentationCondition (
    $client.Contains('const DOMAIN: &[u8] = b"serctl/agent/transfer-pull/local-target/v1\0";') -and
    $client.Contains('local_target_sha256: Some(local_target_sha256)') -and
    $client.Contains('fn agent_transfer_pull_schema_is_closed_and_canonical()')
) 'Agent transfer-pull does not bind the redacted local-target commitment into the root request'
Assert-DocumentationCondition ($agentContract.Contains('`transfer-pull` has a closed request schema')) (
    'Agent contract does not state the closed transfer-pull request schema'
)

foreach ($document in @(
    @{ Name = 'README'; Text = $readme },
    @{ Name = 'Agent contract'; Text = $agentContract },
    @{ Name = 'user guide'; Text = $guide },
    @{ Name = 'release contract'; Text = $releaseContract },
    @{ Name = 'acceptance matrix'; Text = $matrix }
)) {
    foreach ($token in @('transfer_id', 'operation_context_id', 'revision')) {
        Assert-DocumentationCondition ($document.Text.Contains($token)) (
            "$($document.Name) omits transfer operation-context token '$token'"
        )
    }
}
foreach ($token in @(
    'caller-predeclared',
    'first lookup',
    'later lookup',
    'cancel always requires it',
    'Successful `status`, `ssh-connection-identity`, `exec`, `list-dir` and `create-dir` terminals',
    'exactly `revision=1`',
    'managed tunnels',
    'no-SSH-transport'
)) {
    Assert-DocumentationCondition ($agentContract.Contains($token)) (
        "Agent contract omits operation-context rule '$token'"
    )
}
foreach ($token in @(
    "'operation_context_id'", "'revision'", "'accepted'",
    'adapter runtime path is wired to the controlled supervisor',
    'all formal operation contexts have deterministic local parser coverage',
    'one-shot revision is not exactly 1',
    'substituted another accepted root operation context',
    'verified Linux provenance binds native helper identity'
)) {
    Assert-DocumentationCondition ($runtimeAdapter.Contains($token)) (
        "external runtime adapter omits current boundary '$token'"
    )
}
foreach ($staleBlocker in @(
    'Windows supervisor has no STARTUPINFOEX inherited-handle allowlist',
    'Unix supervisor has a child-start to setpgid process-group race',
    'supervisor environment filtering is denylist-based instead of an explicit allowlist',
    'supervisor does not yet provide bounded stdin plus a private captured-output channel',
    'Agent transfer id is disclosed only by the terminal result'
)) {
    foreach ($document in @($runtimeAdapter, $releaseContract, $matrix)) {
        Assert-DocumentationCondition (-not $document.Contains($staleBlocker)) (
            "formal boundary retains resolved blocker '$staleBlocker'"
        )
    }
}

foreach ($sourceToken in @(
    'enum AuditCommand',
    'ResolveUnknown',
    'acknowledge_unknown_outcome',
    'anchor_output'
)) {
    Assert-DocumentationCondition ($main.Contains($sourceToken)) (
        "CLI audit source token '$sourceToken' is missing"
    )
}
$rustfmtSplitCall = "ledger`r`n    .resolve_pending_as_unknown(now_unix_ms()?, anchor)"
$resolveCallPattern = 'ledger\s*\.\s*resolve_pending_as_unknown\s*\('
Assert-DocumentationCondition (
    Test-SourcePattern -Text $rustfmtSplitCall -Pattern $resolveCallPattern
) 'audit recovery source-pattern self-test rejects a rustfmt-split method call'
Assert-DocumentationCondition (-not (
    Test-SourcePattern `
        -Text 'ledger.reconcile_pending_as_success(now_unix_ms()?, anchor)' `
        -Pattern $resolveCallPattern
)) 'audit recovery source-pattern self-test accepts a different recovery operation'

$leaseRegion = Get-SourceRegion `
    -Text $auditRecovery `
    -StartMarker 'fn with_profile_audit_ledger<T>(' `
    -EndMarker 'struct CompletedAuditOperation<T>' `
    -Description 'audit recovery lease helper'
Assert-SourcePattern `
    -Text $leaseRegion `
    -Pattern 'vault\s*::\s*acquire_runtime_lease\s*\(\s*profile\s*\)' `
    -Description 'exclusive profile lease acquisition in the audit recovery helper'
Assert-SourcePattern `
    -Text $leaseRegion `
    -Pattern 'vault\s*::\s*derive_profile_audit_recovery_key_with_lock_timeout\s*\(\s*&lease\s*,' `
    -Description 'lease-bound audit-recovery key derivation inside the exclusive audit recovery lease'
Assert-SourcePattern `
    -Text $leaseRegion `
    -Pattern 'operation\s*\(\s*&ledger\s*,\s*anchor\.as_ref\s*\(\s*\)\s*\)' `
    -Description 'audit operation execution inside the exclusive lease helper'
Assert-DocumentationCondition (
    $recovery.Contains('beta2_strict_reader_rejects_upgraded_audit_fields_without_writing_or_mutating_input') -and
    $auditRecovery.Contains('high_level_audit_recovery_contract_uses_only_isolated_state') -and
    $auditRecovery.Contains('derive_profile_audit_recovery_key_with_lock_timeout')
) 'documentation governance omits the high-level pending-Intent audit recovery contract'

$resolveRegion = Get-SourceRegion `
    -Text $auditRecovery `
    -StartMarker 'pub(crate) fn resolve_profile_audit_as_unknown(' `
    -EndMarker '/// Export only the authenticated checkpoint' `
    -Description 'Unknown audit resolution operation'
Assert-SourcePattern `
    -Text $resolveRegion `
    -Pattern 'ledger\s*\.\s*inspect\s*\(\s*anchor\s*\)' `
    -Description 'authenticated pre-resolution inspection'
Assert-SourcePattern `
    -Text $resolveRegion `
    -Pattern $resolveCallPattern `
    -Description 'explicit pending-to-Unknown resolution API call'
Assert-SourcePattern `
    -Text $resolveRegion `
    -Pattern 'zero or more Unknown outcomes may already be durable' `
    -Description 'partial Unknown-resolution ambiguity warning'
Assert-SourcePattern `
    -Text $resolveRegion `
    -Pattern 'resolved\s*==\s*expected' `
    -Description 'resolved-count verification against the authenticated preflight'
Assert-SourcePattern `
    -Text $auditRecovery `
    -Pattern 'options\s*\.\s*read\s*\(\s*true\s*\)\s*\.\s*write\s*\(\s*true\s*\)\s*\.\s*create_new\s*\(\s*true\s*\)' `
    -Description 'read/write CREATE_NEW audit-anchor output open'
foreach ($document in @(
    @{ Name = 'README'; Text = $readme },
    @{ Name = 'user guide'; Text = $guide },
    @{ Name = 'CHANGELOG'; Text = $changelog },
    @{ Name = 'SECURITY'; Text = $security },
    @{ Name = 'acceptance matrix'; Text = $matrix }
)) {
    Assert-DocumentationCondition (
        $document.Text.Contains('audit status') -and
        $document.Text.Contains('audit resolve-unknown') -and
        $document.Text.Contains('Unknown')
    ) "$($document.Name) omits the audit inspection/Unknown-recovery interface"
    Assert-DocumentationCondition (
        ($document.Text -match '(?i)OperationGrant.{0,40}root|Grant-root') -and
        ($document.Text -match '(?i)create-new') -and
        $document.Text.Contains('external trust domain')
    ) "$($document.Name) overstates the Grant-root/manual-anchor audit boundary"
}

$sourceErrorCodes = Get-UniqueMatches `
    -Text $client `
    -Pattern '"(?<code>agent\.[a-z0-9_.-]+)"' `
    -Group 'code'
$documentedErrorCodes = Get-UniqueMatches `
    -Text $agentContract `
    -Pattern '`(?<code>agent\.[a-z0-9_.-]+)`' `
    -Group 'code'
Assert-DocumentationCondition ($sourceErrorCodes.Count -gt 0) 'Agent source has no stable error-code literals'
Assert-DocumentationCondition (
    (($sourceErrorCodes -join ',') -ceq ($documentedErrorCodes -join ','))
) (
    "source error codes '$($sourceErrorCodes -join ',')' differ from documented codes '$($documentedErrorCodes -join ',')'"
)
foreach ($fixtureMarker in @(
    'fn v1_cli_help_and_contract_match_golden_fixtures()',
    'include_str!("../tests/fixtures/cli-help-v1.txt")',
    'include_str!("../tests/fixtures/cli-contract-v1.json")',
    'fn v1_recursive_cli_help_defaults_and_required_args_match_golden_fixtures()',
    'include_str!("../tests/fixtures/cli-help-tree-v1.txt")',
    'include_str!("../tests/fixtures/cli-command-tree-v1.json")',
    'super::client::AGENT_ERROR_CODES'
)) {
    Assert-DocumentationCondition ($main.Contains($fixtureMarker)) (
        "CLI golden-contract test marker '$fixtureMarker' is missing"
    )
}
Assert-DocumentationCondition (
    $client.Contains('fn agent_result_ndjson_matches_the_v1_golden_fixture()') -and
    $client.Contains('include_str!("../tests/fixtures/agent-result-v1.jsonl")')
) 'Agent result NDJSON golden test is missing'
Assert-DocumentationCondition (
    $main.Contains('fn transfer_progress_ndjson_matches_the_v1_golden_fixture()') -and
    $main.Contains('include_str!("../tests/fixtures/transfer-progress-v1.jsonl")')
) 'transfer progress NDJSON golden test is missing'
foreach ($helpToken in @('audit', 'transfer', 'grant-issue', 'agent')) {
    Assert-DocumentationCondition ($cliHelpFixture -match "(?m)^\s+$([regex]::Escape($helpToken))\s") (
        "CLI help fixture omits '$helpToken'"
    )
}
try {
    $cliCommandTree = ConvertFrom-StrictJson `
        -Json $cliCommandTreeFixture `
        -Label 'recursive CLI command fixture'
}
catch {
    throw 'v1 beta documentation check failed: recursive CLI command fixture is not valid JSON'
}
$expectedCliCommandPaths = @(
    'serctl_cli',
    'serctl_cli add',
    'serctl_cli admin',
    'serctl_cli admin change-password',
    'serctl_cli admin init',
    'serctl_cli admin status',
    'serctl_cli admin verify',
    'serctl_cli agent',
    'serctl_cli audit',
    'serctl_cli audit resolve-unknown',
    'serctl_cli audit status',
    'serctl_cli down',
    'serctl_cli download',
    'serctl_cli exec',
    'serctl_cli grant-issue',
    'serctl_cli list',
    'serctl_cli profile-password',
    'serctl_cli profile-password admin-reset',
    'serctl_cli profile-password change',
    'serctl_cli profile-password rotate-random',
    'serctl_cli recovery',
    'serctl_cli recovery init',
    'serctl_cli recovery migrate-v2',
    'serctl_cli recovery rotate',
    'serctl_cli remove',
    'serctl_cli shell',
    'serctl_cli status',
    'serctl_cli transfer',
    'serctl_cli transfer cancel',
    'serctl_cli transfer pull',
    'serctl_cli transfer push',
    'serctl_cli transfer status',
    'serctl_cli tunnel',
    'serctl_cli tunnel dynamic',
    'serctl_cli tunnel local',
    'serctl_cli tunnel remote',
    'serctl_cli ui',
    'serctl_cli up',
    'serctl_cli upload'
) | Sort-Object
Assert-ClosedFixtureObject $cliCommandTree @('commands', 'schema_version') (
    'recursive CLI command fixture'
)
Assert-DocumentationCondition (
    (Test-StrictJsonInteger $cliCommandTree.schema_version) -and
    $cliCommandTree.schema_version -eq 1
) (
    'recursive CLI command fixture schema version is not 1'
)
Assert-DocumentationCondition (Test-StrictJsonArray $cliCommandTree.commands) (
    'recursive CLI command fixture commands is not a JSON array'
)
foreach ($command in @($cliCommandTree.commands)) {
    Assert-ClosedFixtureObject $command @(
        'defaults', 'path', 'required', 'subcommand_required'
    ) 'recursive CLI command entry'
    Assert-DocumentationCondition (
        (Test-StrictJsonObject $command.defaults) -and
        (Test-StrictJsonString $command.path) -and
        (Test-StrictJsonArray $command.required) -and
        (Test-StrictJsonBoolean $command.subcommand_required)
    ) 'recursive CLI command entry contains a wrong JSON type'
}
$actualCliCommandPaths = @(
    $cliCommandTree.commands | ForEach-Object { [string]$_.path } | Sort-Object
)
Assert-DocumentationCondition (
    ($actualCliCommandPaths -join "`n") -ceq ($expectedCliCommandPaths -join "`n")
) 'recursive CLI command fixture differs from the exact current command tree'
foreach ($commandPath in $expectedCliCommandPaths) {
    $header = "===== $commandPath ====="
    Assert-DocumentationCondition (
        ([regex]::Matches(
            $cliHelpTreeFixture,
            '(?m)^' + [regex]::Escape($header) + '$'
        )).Count -eq 1
    ) "recursive CLI help fixture does not contain exactly one '$header' section"
}
foreach ($criticalPath in @(
    'serctl_cli transfer push',
    'serctl_cli transfer pull',
    'serctl_cli transfer status',
    'serctl_cli transfer cancel',
    'serctl_cli audit status',
    'serctl_cli audit resolve-unknown',
    'serctl_cli grant-issue',
    'serctl_cli agent'
)) {
    $entry = @($cliCommandTree.commands | Where-Object { [string]$_.path -ceq $criticalPath })
    Assert-DocumentationCondition ($entry.Count -eq 1) (
        "recursive CLI command fixture omits critical path '$criticalPath'"
    )
}
try {
    $cliContract = ConvertFrom-StrictJson -Json $cliContractFixture -Label 'CLI contract fixture'
}
catch {
    throw 'v1 beta documentation check failed: CLI contract fixture is not valid JSON'
}
Assert-ClosedFixtureObject $cliContract @(
    'contract_version', 'defaults', 'error_categories', 'exit_codes', 'schemas'
) 'CLI contract fixture'
Assert-DocumentationCondition (
    (Test-StrictJsonInteger $cliContract.contract_version) -and
    $cliContract.contract_version -eq 1
) (
    'CLI contract fixture version is not 1'
)
Assert-ClosedFixtureObject $cliContract.schemas @(
    'agent_jsonl', 'audit_checkpoint', 'ipc', 'transfer_progress_ndjson'
) 'CLI contract fixture schemas'
Assert-DocumentationCondition (
    (Test-StrictJsonInteger $cliContract.schemas.agent_jsonl) -and
    $cliContract.schemas.agent_jsonl -eq 1 -and
    (Test-StrictJsonInteger $cliContract.schemas.audit_checkpoint) -and
    $cliContract.schemas.audit_checkpoint -eq 1 -and
    (Test-StrictJsonInteger $cliContract.schemas.ipc) -and
    $cliContract.schemas.ipc -eq 9 -and
    (Test-StrictJsonInteger $cliContract.schemas.transfer_progress_ndjson) -and
    $cliContract.schemas.transfer_progress_ndjson -eq 1
) 'CLI contract fixture schema markers are stale'
Assert-DocumentationCondition (Test-StrictJsonArray $cliContract.error_categories) (
    'CLI contract fixture error_categories is not a JSON array'
)
$fixtureErrorCodes = @($cliContract.error_categories | ForEach-Object { [string]$_ } | Sort-Object)
Assert-DocumentationCondition (
    (($fixtureErrorCodes -join ',') -ceq ($sourceErrorCodes -join ','))
) (
    "CLI fixture error codes '$($fixtureErrorCodes -join ',')' differ from source '$($sourceErrorCodes -join ',')'"
)
$agentResultLines = @($agentResultFixture -split '\r?\n' | Where-Object { $_.Length -gt 0 })
Assert-DocumentationCondition ($agentResultLines.Count -eq 8) (
    'Agent result NDJSON fixture must contain four successes and four typed failures'
)
$fixtureResultErrorCodes = @()
$fixtureSuccessCount = 0
foreach ($line in $agentResultLines) {
    try {
        $result = ConvertFrom-StrictJson -Json $line -Label 'Agent result NDJSON fixture record'
    }
    catch {
        throw 'v1 beta documentation check failed: invalid Agent result NDJSON fixture record'
    }
    Assert-DocumentationCondition (
        (Test-StrictJsonInteger $result.schema_version) -and
        $result.schema_version -eq 1
    ) (
        'Agent result NDJSON fixture has a stale schema version'
    )
    Assert-DocumentationCondition (Test-StrictJsonBoolean $result.ok) (
        'Agent result NDJSON fixture ok is not a JSON boolean'
    )
    if ($result.ok) {
        $fixtureSuccessCount++
        Assert-ClosedFixtureObject $result @('schema_version', 'request_id', 'ok', 'data') (
            'successful Agent result NDJSON fixture record'
        )
        Assert-DocumentationCondition (Test-StrictJsonObject $result.data) (
            'successful Agent result NDJSON fixture data is not a JSON object'
        )
    }
    else {
        Assert-ClosedFixtureObject $result @(
            'schema_version', 'request_id', 'ok', 'error_code', 'error'
        ) 'failed Agent result NDJSON fixture record'
        Assert-DocumentationCondition (
            (Test-StrictJsonString $result.error_code) -and
            (Test-StrictJsonString $result.error)
        ) 'failed Agent result NDJSON fixture error fields have wrong JSON types'
        $fixtureResultErrorCodes += [string]$result.error_code
    }
}
Assert-DocumentationCondition ($fixtureSuccessCount -eq 4) (
    'Agent result NDJSON fixture must contain exactly four successful records'
)
$fixtureResultErrorCodes = @($fixtureResultErrorCodes | Sort-Object -Unique)
Assert-DocumentationCondition (
    (($fixtureResultErrorCodes -join ',') -ceq ($sourceErrorCodes -join ','))
) (
    "Agent result fixture error codes '$($fixtureResultErrorCodes -join ',')' differ from source '$($sourceErrorCodes -join ',')'"
)
$pullTerminalLine = @(
    $agentResultLines | Where-Object { $_ -match '"request_id":8' }
)
Assert-DocumentationCondition ($pullTerminalLine.Count -eq 1) (
    'Agent result NDJSON fixture must contain exactly one transfer-pull terminal'
)
$pullTerminal = ConvertFrom-StrictJson `
    -Json $pullTerminalLine[0] `
    -Label 'Agent transfer-pull terminal fixture'
Assert-ClosedFixtureObject $pullTerminal @('schema_version', 'request_id', 'ok', 'data') (
    'Agent transfer-pull terminal fixture'
)
Assert-ClosedFixtureObject $pullTerminal.data @(
    'backend', 'backend_requested', 'bytes', 'chunk_bytes', 'operation_context_id',
    'revision', 'transfer_id', 'window_bytes'
) 'Agent transfer-pull terminal data'
Assert-DocumentationCondition (
    $pullTerminal.ok -eq $true -and
    (Test-StrictJsonInteger $pullTerminal.data.bytes) -and
    (Test-StrictJsonInteger $pullTerminal.data.chunk_bytes) -and
    (Test-StrictJsonInteger $pullTerminal.data.revision) -and
    [uint64]$pullTerminal.data.revision -gt 0 -and
    (Test-StrictJsonInteger $pullTerminal.data.window_bytes) -and
    (Test-StrictJsonString $pullTerminal.data.transfer_id) -and
    (Test-StrictJsonString $pullTerminal.data.operation_context_id) -and
    [string]$pullTerminal.data.operation_context_id -cmatch '^[0-9a-f]{64}$' -and
    (Test-StrictJsonString $pullTerminal.data.backend) -and
    (Test-StrictJsonString $pullTerminal.data.backend_requested)
) 'Agent transfer-pull terminal fixture has wrong field types'
$transferProgressLines = @(
    $transferProgressFixture -split '\r?\n' | Where-Object { $_.Length -gt 0 }
)
Assert-DocumentationCondition ($transferProgressLines.Count -eq 1) (
    'transfer progress NDJSON fixture must contain exactly one record'
)
try {
    $transferProgress = ConvertFrom-StrictJson `
        -Json $transferProgressLines[0] `
        -Label 'transfer progress NDJSON fixture record'
}
catch {
    throw 'v1 beta documentation check failed: transfer progress NDJSON fixture is invalid'
}
Assert-ClosedFixtureObject $transferProgress @(
    'schema_version', 'event', 'transfer_id', 'direction', 'stage', 'total_bytes',
    'confirmed_bytes', 'durable_bytes', 'window_bps', 'average_bps', 'eta_ms',
    'backend', 'chunk_bytes', 'window_bytes', 'updated_unix_ms'
) 'transfer progress NDJSON fixture record'
Assert-DocumentationCondition (
    (Test-StrictJsonInteger $transferProgress.schema_version) -and
    $transferProgress.schema_version -eq 1
) (
    'transfer progress NDJSON fixture has a stale schema version'
)

foreach ($document in @(
    @{ Name = 'Agent contract'; Text = $agentContract },
    @{ Name = 'user guide'; Text = $guide }
)) {
    $requestLines = @(
        $document.Text -split '\r?\n' |
            Where-Object { $_ -match '^\{"op":' }
    )
    Assert-DocumentationCondition ($requestLines.Count -gt 0) "$($document.Name) has no Agent request examples"
    foreach ($line in $requestLines) {
        try {
            $request = ConvertFrom-StrictJson -Json $line -Label "$($document.Name) Agent request"
        }
        catch {
            throw "v1 beta documentation check failed: $($document.Name) contains invalid Agent request JSON"
        }
        Assert-DocumentationCondition (
            (Test-StrictJsonObject $request) -and
            $null -ne $request.schema_version -and
            (Test-StrictJsonInteger $request.schema_version) -and
            $request.schema_version -eq 1
        ) "$($document.Name) request example omits integer schema_version=1"
    }
}

foreach ($document in @(
    @{ Name = 'README'; Text = $readme },
    @{ Name = 'user guide'; Text = $guide },
    @{ Name = 'Agent contract'; Text = $agentContract },
    @{ Name = 'release contract'; Text = $releaseContract },
    @{ Name = 'acceptance matrix'; Text = $matrix },
    @{ Name = 'architecture'; Text = $architecture }
)) {
    Assert-DocumentationCondition ($document.Text.Contains('IPC v9')) (
        "$($document.Name) does not state the candidate IPC v9 boundary"
    )
    Assert-DocumentationCondition (
        $document.Text.Contains('serctl-remote') -and
        ($document.Text -match '(?i)experimental')
    ) "$($document.Name) does not mark serctl-remote as experimental"
    Assert-DocumentationCondition (
        ($document.Text -match '(?i)source-only') -and
        ($document.Text -match '(?i)unshipped|not shipped|not published|does not .*publish|published assets contain no|no shipped binary')
    ) "$($document.Name) does not keep serctl-remote source-only and unshipped"
}

foreach ($document in @(
    @{ Name = 'README'; Text = $readme },
    @{ Name = 'user guide'; Text = $guide },
    @{ Name = 'Agent contract'; Text = $agentContract },
    @{ Name = 'release contract'; Text = $releaseContract },
    @{ Name = 'acceptance matrix'; Text = $matrix },
    @{ Name = 'SECURITY'; Text = $security },
    @{ Name = 'architecture'; Text = $architecture }
)) {
    Assert-DocumentationCondition ($document.Text.Contains('job.*')) (
        "$($document.Name) omits the unsupported job.* boundary"
    )
}

Assert-DocumentationCondition (
    $architecture.Contains('data-release-candidate="v1.0.0-beta"') -and
    $architecture.Contains('data-release-predecessor="v0.3.0-beta.2"') -and
    $architecture.Contains('<code>v0.3.0-beta.2</code> / IPC v8')
) 'architecture does not distinguish the v1/IPC v9 candidate from the v0.3/IPC v8 predecessor'

foreach ($nativeMacMarker in @(
    'macOS arm64',
    'macOS x86_64',
    'runner.arch',
    'Rust host tuple'
)) {
    Assert-DocumentationCondition ($matrix.Contains($nativeMacMarker)) (
        "acceptance matrix omits native macOS marker '$nativeMacMarker'"
    )
    Assert-DocumentationCondition ($releaseContract.Contains($nativeMacMarker)) (
        "release contract omits native macOS marker '$nativeMacMarker'"
    )
}
foreach ($windowsAclMarker in @(
    'scripts/Test-WindowsMultiAccountAcl.ps1',
    'two temporary non-administrator accounts',
    'Owner Rights/SYSTEM/Administrators DACL',
    'hard failure, never a skip'
)) {
    Assert-DocumentationCondition ($matrix.Contains($windowsAclMarker)) (
        "acceptance matrix omits Windows multi-account marker '$windowsAclMarker'"
    )
}
Assert-DocumentationCondition (
    $releaseContract.Contains('scripts/Test-WindowsMultiAccountAcl.ps1') -and
    $releaseContract.Contains('not reported as a pass or skip')
) 'release contract permits an unexecuted Windows multi-account gate to look accepted'
foreach ($receiptBindingMarker in @(
    'helper_sha256',
    'candidate_cli_sha256',
    'downloaded release components',
    'downloaded Windows platform provenance',
    'downloaded Linux platform provenance'
)) {
    Assert-DocumentationCondition ($releaseContract.Contains($receiptBindingMarker)) (
        "release contract omits external receipt byte binding '$receiptBindingMarker'"
    )
}
foreach ($receiptBindingMarker in @(
    'helper_sha256',
    'candidate_cli_sha256',
    'downloaded release components',
    'downloaded Windows platform provenance',
    'downloaded Linux platform provenance'
)) {
    Assert-DocumentationCondition ($matrix.Contains($receiptBindingMarker)) (
        "acceptance matrix omits external receipt byte binding '$receiptBindingMarker'"
    )
}
foreach ($receiptHardeningMarker in @(
    'distinct acceptance and evidence owners',
    'x86_64-pc-windows-msvc',
    'x86_64-unknown-linux-gnu',
    'exactly once each',
    'descriptor_daemon_sha256',
    'floor(100 * native_p50_bytes_per_second / scp_bytes_per_second)'
)) {
    Assert-DocumentationCondition ($releaseContract.Contains($receiptHardeningMarker)) (
        "release contract omits external receipt hardening '$receiptHardeningMarker'"
    )
    Assert-DocumentationCondition ($matrix.Contains($receiptHardeningMarker)) (
        "acceptance matrix omits external receipt hardening '$receiptHardeningMarker'"
    )
}
foreach ($expandedExternalCaseMarker in @(
    'exactly 20 passed tests',
    'exactly 10 passed tests',
    'disconnect',
    'daemon_restart',
    'target_symlink_or_reparse',
    'no_owned_partial_created',
    'OpenSSH_directory',
    'OpenSSH_tunnel_local',
    'OpenSSH_tunnel_remote',
    'OpenSSH_tunnel_dynamic',
    'context_sha256'
)) {
    Assert-DocumentationCondition ($releaseContract.Contains($expandedExternalCaseMarker)) (
        "release contract omits expanded external case '$expandedExternalCaseMarker'"
    )
    Assert-DocumentationCondition ($matrix.Contains($expandedExternalCaseMarker)) (
        "acceptance matrix omits expanded external case '$expandedExternalCaseMarker'"
    )
}
foreach ($staleCurrentMarker in @(
    '>9. IPC v8 ',
    '<h2>9. IPC v8',
    'current v8 route'
)) {
    Assert-DocumentationCondition (-not $architecture.Contains($staleCurrentMarker)) (
        "architecture retains stale current marker '$staleCurrentMarker'"
    )
}

foreach ($token in @(
    'target/staging-v0.3/release',
    '8b555f7',
    '100,000,000',
    '4.70',
    '5.67'
)) {
    Assert-DocumentationCondition ($readme.Contains($token)) "README lacks predecessor evidence token '$token'"
    Assert-DocumentationCondition ($changelog.Contains($token)) "CHANGELOG lacks predecessor evidence token '$token'"
    Assert-DocumentationCondition ($matrix.Contains($token)) "acceptance matrix lacks predecessor evidence token '$token'"
}
Assert-DocumentationCondition (
    $readme.Contains('mixed v0.2/v7-era binaries') -and
    $releaseContract.Contains('mixed v0.2/v7-era binaries')
) 'mixed target/release must be explicitly excluded from v1 packaging'

$directionalStorageTokens = @(
    'audit_seed directionally incompatible',
    'unknown fields must not be dropped',
    'binary-only rollback is forbidden',
    'exact pre-upgrade vault backup'
)
foreach ($document in @(
    @{ Name = 'README'; Text = $readme },
    @{ Name = 'CHANGELOG'; Text = $changelog },
    @{ Name = 'release contract'; Text = $releaseContract },
    @{ Name = 'acceptance matrix'; Text = $matrix },
    @{ Name = 'upgrade rollback harness'; Text = $upgradeRollback }
)) {
    foreach ($token in $directionalStorageTokens) {
        Assert-DocumentationCondition ($document.Text.Contains($token)) (
            "$($document.Name) omits directional storage token '$token'"
        )
    }
}
$storageGenerationTokens = @(
    'KeyPackage-only',
    'admin_reset_profile',
    'vault-storage read=v4..=v5 write=v5',
    'destructive writer',
    'full `HEAD`'
)
foreach ($document in @(
    @{ Name = 'release contract'; Text = $releaseContract },
    @{ Name = 'acceptance matrix'; Text = $matrix },
    @{ Name = 'upgrade rollback harness'; Text = $upgradeRollback }
)) {
    foreach ($token in $storageGenerationTokens) {
        Assert-DocumentationCondition ($document.Text.Contains($token)) (
            "$($document.Name) omits storage-generation token '$token'"
        )
    }
}
foreach ($runtimeObservationToken in @(
    'beta2_transient_runtime_activation_observed',
    'beta2_runtime_state_cleaned_after_rejection',
    'treated as proof that the fixed predecessor did not transiently activate'
)) {
    Assert-DocumentationCondition ($upgradeRollback.Contains($runtimeObservationToken)) (
        "upgrade rollback harness omits runtime-observation token '$runtimeObservationToken'"
    )
}
Assert-DocumentationCondition (
    -not $upgradeRollback.Contains('proves no daemon descriptor or activation secret was created')
) 'upgrade rollback documentation still treats final runtime absence as proof of no activation'
foreach ($sourceToken in @(
    'struct Beta2StrictKeyPackage',
    'fn beta2_strict_read_then_write',
    'fn current_audit_fields_round_trip_without_normalization',
    'fn future_security_fields_and_impossible_audit_state_fail_closed',
    'validate_security_state',
    'unknown field `audit_seed`',
    'assert_eq!(writer_calls, 0)',
    'assert_eq!(fixture, before)'
)) {
    Assert-DocumentationCondition ($recovery.Contains($sourceToken)) (
        "recovery compatibility fixture omits '$sourceToken'"
    )
}

foreach ($document in @(
    @{ Name = 'README'; Text = $readme },
    @{ Name = 'SECURITY'; Text = $security },
    @{ Name = 'release contract'; Text = $releaseContract },
    @{ Name = 'acceptance matrix'; Text = $matrix }
)) {
    Assert-DocumentationCondition (
        ($document.Text -match '(?i)external anchor') -and
        ($document.Text -match '(?i)checkpoint') -and
        ($document.Text -match '(?i)rollback')
    ) "$($document.Name) omits the local audit synchronized-rollback boundary"
}

Assert-DocumentationCondition (
    $readme.Contains('docs/ssh-preauth-diagnostics.md')
) 'README does not bind silent pre-identification failures to the diagnostic runbook'
Assert-DocumentationCondition (
    $matrix.Contains('(ssh-preauth-diagnostics.md)') -and
    $matrix.Contains('undetermined_path_or_listener') -and
    $matrix.Contains('(ssh-preauth-server-evidence.template.json)') -and
    $matrix.Contains('Test-SshPreAuthServerEvidence.ps1')
) 'acceptance matrix does not bind real-host SSH evidence to the diagnostic runbook'
foreach ($token in @(
    'client_identification_sent_server_silent',
    'undetermined_path_or_listener',
    'sshd_pre_auth_admission_control',
    'ssh_kex_stall_or_failure',
    'not proof that the full client identification was written',
    'It does not mean the pin was accepted',
    'SSH server identification phase',
    'Retain never the configured listen address, banner path, banner content',
    'Never capture or retain payload bytes'
)) {
    Assert-DocumentationCondition ($sshPreauthDiagnostics.Contains($token)) (
        "SSH pre-authentication diagnostic runbook lacks '$token'"
    )
}
foreach ($token in @(
    'evidence_status=template',
    'Duplicate or case-colliding keys',
    'events` must remain a JSON array',
    'not server, network, OpenSSH, Dropbear, exact-tag or release evidence'
)) {
    Assert-DocumentationCondition ($sshPreauthDiagnostics.Contains($token)) (
        "SSH pre-authentication diagnostic runbook lacks evidence boundary '$token'"
    )
}
foreach ($token in @(
    '"evidence_status": "template"',
    '"connection_binding": "ambiguous"',
    '"classification": "undetermined_path_or_listener"'
)) {
    Assert-DocumentationCondition ($sshPreauthEvidenceTemplate.Contains($token)) (
        "SSH pre-authentication evidence template lacks '$token'"
    )
}
foreach ($token in @('StrictJson.ps1', 'events.array', 'classification.kex-event')) {
    Assert-DocumentationCondition ($sshPreauthEvidenceVerifier.Contains($token)) (
        "SSH pre-authentication evidence verifier lacks '$token'"
    )
}
foreach ($token in @('duplicate JSON key', 'case-colliding JSON key', 'synthetic')) {
    Assert-DocumentationCondition ($sshPreauthEvidenceSelfTest.Contains($token)) (
        "SSH pre-authentication evidence self-test lacks '$token'"
    )
}
Assert-DocumentationCondition (
    $readme.Contains('same-UID path race') -and
    $readme.Contains('advisory lock') -and
    $readme.Contains('last-instruction window') -and
    $changelog.Contains('same-UID path race') -and
    $changelog.Contains('advisory lock') -and
    $changelog.Contains('last-instruction window')
) 'native helper lock boundary does not distinguish closed cooperative races from malicious same-UID advisory-lock bypass'

Write-Host (
    "V1 beta documentation checks passed (Agent transfer control: $expectedReadiness; " +
    "error codes: $($sourceErrorCodes -join ', '))."
)
