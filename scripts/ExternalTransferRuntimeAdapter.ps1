Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Dot-sourced by the receipt-contract module. Module-private PowerShell state is
# not a security boundary against arbitrary same-process script, so no parser
# result below has the shape accepted by the formal receipt ledger.
$script:SerctlRuntimeAdapterRecipes = [ordered]@{
    native_transfer_real_host = [ordered]@{
        push_21 = @('ssh-connection-identity', 'transfer-push', 'transfer-status')
        push_1298223 = @('ssh-connection-identity', 'transfer-push', 'transfer-status')
        push_67108864 = @('ssh-connection-identity', 'transfer-push', 'transfer-status')
        push_1073741824 = @('ssh-connection-identity', 'transfer-push', 'transfer-status')
        pull_21 = @('ssh-connection-identity', 'transfer-pull', 'transfer-status')
        pull_1298223 = @('ssh-connection-identity', 'transfer-pull', 'transfer-status')
        pull_67108864 = @('ssh-connection-identity', 'transfer-pull', 'transfer-status')
        pull_1073741824 = @('ssh-connection-identity', 'transfer-pull', 'transfer-status')
        resume_25 = @('ssh-connection-identity', 'transfer-push', 'transfer-status')
        resume_75 = @('ssh-connection-identity', 'transfer-push', 'transfer-status')
        lost_ack = @('ssh-connection-identity', 'transfer-push', 'transfer-status')
        helper_crash = @('ssh-connection-identity', 'transfer-push', 'transfer-status')
        disconnect = @('ssh-connection-identity', 'transfer-push', 'transfer-status')
        daemon_restart = @('ssh-connection-identity', 'transfer-push', 'transfer-status')
        disk_full = @('ssh-connection-identity', 'transfer-push', 'transfer-status')
        permission_denied = @('ssh-connection-identity', 'transfer-push', 'transfer-status')
        target_race = @('ssh-connection-identity', 'transfer-push', 'transfer-status')
        target_symlink_or_reparse = @('ssh-connection-identity', 'transfer-push', 'transfer-status')
        unknown_cleanup = @('ssh-connection-identity', 'transfer-push', 'transfer-status')
        registry_window = @('ssh-connection-identity', 'transfer-push', 'transfer-status')
    }
    openssh_dropbear_interop = [ordered]@{
        OpenSSH_exec = @('ssh-connection-identity', 'exec')
        OpenSSH_directory = @('ssh-connection-identity', 'list-dir')
        OpenSSH_tunnel_local = @(
            'ssh-connection-identity', 'forward-local-open', 'forward-status', 'forward-cancel'
        )
        OpenSSH_tunnel_remote = @(
            'ssh-connection-identity', 'forward-remote-open', 'forward-status', 'forward-cancel'
        )
        OpenSSH_tunnel_dynamic = @(
            'ssh-connection-identity', 'forward-dynamic-open', 'forward-status', 'forward-cancel'
        )
        OpenSSH_sftp = @('ssh-connection-identity', 'transfer-push', 'transfer-status')
        OpenSSH_native = @('ssh-connection-identity', 'transfer-push', 'transfer-status')
        Dropbear_exec = @('ssh-connection-identity', 'exec')
        Dropbear_sftp = @('ssh-connection-identity', 'transfer-push', 'transfer-status')
        Dropbear_native = @('ssh-connection-identity', 'transfer-push', 'transfer-status')
    }
}
$script:SerctlRuntimeSupervisorScriptPath = Join-Path $PSScriptRoot 'ExternalRuntimeProcessSupervisor.ps1'
$script:SerctlRuntimeAdapterScriptPath = $PSCommandPath

$script:SerctlRuntimeAdapterBlockers = @(
    'adapter runtime path is wired to the controlled supervisor and trusted owner, but no exact-tag downloaded component set, protected real Grant handles, or named remote has been exercised',
    'the independently authorized concurrent transfer-status path has only deterministic local process evidence, not exact-tag real-host evidence',
    'Linux supervisor and Agent runtime behavior has not been proven on an exact-tag native Linux runner',
    'macOS runtime remains unsupported and fail-closed',
    'all formal operation contexts have deterministic local parser coverage but no exact-tag real-host evidence',
    'verified Linux provenance binds native helper identity into the local formal root intent, but no exact-tag real-host HelperHello has been observed',
    'PowerShell module-private functions and state are not a trust boundary against same-process scripts'
)
$script:SerctlAgentOperations = @(
    'status', 'ssh-connection-identity', 'exec', 'list-dir', 'create-dir',
    'forward-local-open', 'forward-remote-open', 'forward-dynamic-open',
    'forward-status', 'forward-cancel', 'transfer-push', 'transfer-pull', 'transfer-status',
    'transfer-cancel'
)
$script:SerctlSensitiveCanaries = @(
    'DO_NOT_PARSE', 'DO_NOT_ECHO', 'DO_NOT_LEAK', 'PATH_CANARY',
    'CREDENTIAL_CANARY', 'PASSWORD_CANARY', 'SERCTL_PROFILE_PASSPHRASE',
    'credential-material'
)
$script:SerctlTransferStages = @(
    'preflight', 'hash', 'negotiating', 'transferring', 'verifying',
    'committing', 'cleanup', 'completed', 'failed', 'cancelled', 'stalled'
)
$script:SerctlTransferEvents = @(
    'accepted', 'preflight', 'hash', 'progress', 'resumed', 'stalled',
    'completed', 'failed', 'cancelled'
)
$script:SerctlTransferBackends = @('auto', 'native', 'sftp', 'sftp_fallback')
$script:SerctlTunnelModes = @('local', 'remote', 'dynamic')
$script:SerctlTunnelStages = @('ready', 'cancelling', 'closed', 'unknown')

function Assert-SerctlRuntimeAdapter {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "serctl external runtime adapter failed: $Message" }
}

function Get-SerctlRuntimeAdapterRecipe {
    param([string]$Category, [string]$CaseId)
    Assert-SerctlRuntimeAdapter $script:SerctlRuntimeAdapterRecipes.Contains($Category) (
        'category is outside the fixed formal recipe set'
    )
    $cases = $script:SerctlRuntimeAdapterRecipes[$Category]
    Assert-SerctlRuntimeAdapter $cases.Contains($CaseId) 'case is outside the fixed formal recipe set'
    return [string[]]@($cases[$CaseId])
}

function Get-SerctlRuntimeAdapterSha256 {
    param([AllowEmptyCollection()][byte[]]$Bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '') }
    finally { $sha.Dispose() }
}

function Assert-SerctlClosedObject {
    param($Value, [string[]]$Fields, [string]$Label)
    Assert-SerctlRuntimeAdapter (Test-StrictJsonObject $Value) "$Label is not an object"
    $actual = @($Value.PSObject.Properties.Name | Sort-Object)
    $expected = @($Fields | Sort-Object)
    Assert-SerctlRuntimeAdapter (($actual -join "`n") -ceq ($expected -join "`n")) (
        "$Label does not use its exact closed schema"
    )
}

function Test-SerctlContainsSensitiveCanary {
    param([string]$Text)
    foreach ($canary in $script:SerctlSensitiveCanaries) {
        if ($Text.IndexOf($canary, [StringComparison]::OrdinalIgnoreCase) -ge 0) { return $true }
    }
    return $false
}

function Assert-SerctlBoundedString {
    param($Value, [int]$MaximumLength, [string]$Label)
    Assert-SerctlRuntimeAdapter (Test-StrictJsonString $Value) "$Label is not a JSON string"
    $text = [string]$Value
    Assert-SerctlRuntimeAdapter (
        $text.Length -le $MaximumLength -and
        -not @($text.ToCharArray() | Where-Object { [char]::IsControl($_) }).Count
    ) "$Label is outside its string bound"
    Assert-SerctlRuntimeAdapter (-not (Test-SerctlContainsSensitiveCanary $text)) (
        "$Label contains a secret or path canary"
    )
}

function Get-SerctlUnsignedInteger {
    param($Value, [uint64]$Maximum, [string]$Label, [switch]$NonZero)
    Assert-SerctlRuntimeAdapter (Test-StrictJsonInteger $Value) "$Label is not an integer"
    try { $converted = [uint64]$Value }
    catch { throw "serctl external runtime adapter failed: $Label is not unsigned" }
    Assert-SerctlRuntimeAdapter ($converted -le $Maximum) "$Label exceeds its integer bound"
    if ($NonZero) { Assert-SerctlRuntimeAdapter ($converted -gt 0) "$Label must be non-zero" }
    return $converted
}

function Test-SerctlJsonNumber {
    param($Value)
    return (
        (Test-StrictJsonInteger $Value) -or $Value -is [single] -or
        $Value -is [double] -or $Value -is [decimal]
    )
}

function Assert-SerctlAgentContext {
    param($ExpectedContext)
    Assert-SerctlClosedObject $ExpectedContext @(
        'profile_id', 'profile_generation', 'observed_host_key_sha256',
        'server_identification', 'transport_attempt_id', 'context_sha256'
    ) 'expected Agent context'
    foreach ($field in @(
        'profile_id', 'observed_host_key_sha256', 'server_identification',
        'transport_attempt_id', 'context_sha256'
    )) { Assert-SerctlBoundedString $ExpectedContext.$field 128 "expected Agent context.$field" }
    $generation = Get-SerctlUnsignedInteger $ExpectedContext.profile_generation (
        [uint64]::MaxValue
    ) 'expected Agent context.profile_generation' -NonZero
    Assert-SerctlRuntimeAdapter (
        [string]$ExpectedContext.profile_id -cmatch '^[0-9a-f]{32}$' -and
        $generation -gt 0 -and
        [string]$ExpectedContext.observed_host_key_sha256 -cmatch '^SHA256:[A-Za-z0-9+/]{43}$' -and
        [string]$ExpectedContext.server_identification -cmatch '^SSH-(2\.0|1\.99)-[\x21-\x7E]{1,120}$' -and
        [string]$ExpectedContext.transport_attempt_id -cmatch '^[0-9A-F]{32}$' -and
        [string]$ExpectedContext.context_sha256 -cmatch '^[0-9A-F]{64}$'
    ) 'expected Agent context violates its closed value bounds'
}

function ConvertFrom-SerctlAgentResultLine {
    param([string]$Json, [uint64]$RequestId, [string]$Operation)
    Assert-SerctlRuntimeAdapter ($script:SerctlAgentOperations -ccontains $Operation) (
        'Agent operation is outside the fixed parser vocabulary'
    )
    Assert-SerctlRuntimeAdapter (-not (Test-SerctlContainsSensitiveCanary $Json)) (
        'Agent result contains a secret or path canary'
    )
    $terminal = ConvertFrom-StrictJson -Json $Json -Label "Agent $Operation result"
    Assert-SerctlRuntimeAdapter (Test-StrictJsonBoolean $terminal.ok) (
        "Agent $Operation result has no Boolean terminal state"
    )
    if ([bool]$terminal.ok) {
        Assert-SerctlClosedObject $terminal @('schema_version', 'request_id', 'ok', 'data') (
            "Agent $Operation success"
        )
    }
    else {
        Assert-SerctlClosedObject $terminal @(
            'schema_version', 'request_id', 'ok', 'error_code', 'error'
        ) "Agent $Operation failure"
        Assert-SerctlBoundedString $terminal.error_code 64 "Agent $Operation error_code"
        Assert-SerctlBoundedString $terminal.error 1024 "Agent $Operation error"
        Assert-SerctlRuntimeAdapter (
            [string]$terminal.error_code -cmatch '^agent\.[a-z_]{1,48}$'
        ) "Agent $Operation error_code is outside the public vocabulary"
    }
    Assert-SerctlRuntimeAdapter (
        (Test-StrictJsonInteger $terminal.schema_version) -and
        [int]$terminal.schema_version -eq 1 -and
        (Test-StrictJsonInteger $terminal.request_id) -and
        [uint64]$terminal.request_id -eq $RequestId
    ) "Agent $Operation result request identity is invalid"
    return $terminal
}

function Assert-SerctlAgentConnectionIdentity {
    param($Identity, $ExpectedContext)
    Assert-SerctlClosedObject $Identity @(
        'profile_id', 'profile_generation', 'observed_host_key_sha256',
        'pin_match', 'server_identification', 'transport_attempt_id',
        'operation_context_id', 'revision'
    ) 'SSH connection identity'
    foreach ($field in @(
        'profile_id', 'observed_host_key_sha256', 'server_identification', 'transport_attempt_id'
    )) { Assert-SerctlBoundedString $Identity.$field 128 "SSH connection identity.$field" }
    $generation = Get-SerctlUnsignedInteger $Identity.profile_generation (
        [uint64]::MaxValue
    ) 'SSH connection identity.profile_generation' -NonZero
    Assert-SerctlRuntimeAdapter (
        [string]$Identity.profile_id -cmatch '^[0-9a-f]{32}$' -and
        $generation -gt 0 -and
        [string]$Identity.observed_host_key_sha256 -cmatch '^SHA256:[A-Za-z0-9+/]{43}$' -and
        (Test-StrictJsonBoolean $Identity.pin_match) -and [bool]$Identity.pin_match -and
        [string]$Identity.server_identification -cmatch '^SSH-(2\.0|1\.99)-[\x21-\x7E]{1,120}$' -and
        [string]$Identity.transport_attempt_id -cmatch '^[0-9A-F]{32}$'
    ) 'SSH connection identity violates its closed value bounds'
    Assert-SerctlRuntimeAdapter (
        [string]$Identity.profile_id -ceq [string]$ExpectedContext.profile_id -and
        $generation -eq [uint64]$ExpectedContext.profile_generation -and
        [string]$Identity.observed_host_key_sha256 -ceq [string]$ExpectedContext.observed_host_key_sha256 -and
        [string]$Identity.server_identification -ceq [string]$ExpectedContext.server_identification -and
        [string]$Identity.transport_attempt_id -ceq [string]$ExpectedContext.transport_attempt_id
    ) 'SSH connection identity does not match the fixed transcript context'
    Assert-SerctlOneShotOperationContext $Identity 'SSH connection identity' $null
}

function Assert-SerctlOneShotOperationContext {
    param($Data, [string]$Label, [AllowNull()][string]$ForbiddenOperationContextId)
    Assert-SerctlBoundedString $Data.operation_context_id 64 "$Label.operation_context_id"
    Assert-SerctlRuntimeAdapter (
        [string]$Data.operation_context_id -cmatch '^[0-9a-f]{64}$'
    ) "$Label operation context is not lowercase 64-hex"
    $revision = Get-SerctlUnsignedInteger $Data.revision ([uint64]::MaxValue) (
        "$Label.revision"
    ) -NonZero
    Assert-SerctlRuntimeAdapter ($revision -eq [uint64]1) (
        "$Label one-shot revision is not exactly 1"
    )
    if ($null -ne $ForbiddenOperationContextId) {
        Assert-SerctlRuntimeAdapter (
            [string]$Data.operation_context_id -cne $ForbiddenOperationContextId
        ) "$Label substituted another accepted root operation context"
    }
}

function Assert-SerctlCanonicalBase64 {
    param($Value, [string]$Label)
    Assert-SerctlBoundedString $Value 16777216 $Label
    try { $decoded = [Convert]::FromBase64String([string]$Value) }
    catch { throw "serctl external runtime adapter failed: $Label is not Base64" }
    try {
        Assert-SerctlRuntimeAdapter (
            [Convert]::ToBase64String($decoded) -ceq [string]$Value
        ) "$Label is not canonical Base64"
        try {
            $decodedText = [Text.UTF8Encoding]::new($false, $true).GetString($decoded)
            Assert-SerctlRuntimeAdapter (
                -not (Test-SerctlContainsSensitiveCanary $decodedText)
            ) "$Label decodes to a secret or path canary"
        }
        catch [Text.DecoderFallbackException] { }
    }
    finally { [Array]::Clear($decoded, 0, $decoded.Length) }
}

function Assert-SerctlExecData {
    param($Data, [AllowNull()][string]$ForbiddenOperationContextId)
    Assert-SerctlClosedObject $Data @(
        'stdout', 'stderr', 'code', 'operation_context_id', 'revision'
    ) 'Agent exec data'
    Assert-SerctlCanonicalBase64 $Data.stdout 'Agent exec stdout'
    Assert-SerctlCanonicalBase64 $Data.stderr 'Agent exec stderr'
    if ($null -ne $Data.code) {
        Assert-SerctlRuntimeAdapter (Test-StrictJsonInteger $Data.code) 'Agent exec code is not an integer'
        $code = [int64]$Data.code
        Assert-SerctlRuntimeAdapter (
            $code -ge [int32]::MinValue -and $code -le [int32]::MaxValue
        ) 'Agent exec code exceeds the i32 range'
    }
    Assert-SerctlOneShotOperationContext $Data 'Agent exec data' $ForbiddenOperationContextId
}

function Assert-SerctlListDirData {
    param($Data, [AllowNull()][string]$ForbiddenOperationContextId)
    Assert-SerctlClosedObject $Data @(
        'path', 'entries', 'operation_context_id', 'revision'
    ) 'Agent list-dir data'
    Assert-SerctlBoundedString $Data.path 4096 'Agent list-dir path'
    Assert-SerctlRuntimeAdapter (Test-StrictJsonArray $Data.entries) 'Agent list-dir entries is not an array'
    Assert-SerctlRuntimeAdapter (@($Data.entries).Count -le 65536) 'Agent list-dir entries exceeds its count bound'
    foreach ($entry in @($Data.entries)) {
        Assert-SerctlClosedObject $entry @(
            'name', 'path', 'is_dir', 'is_symlink', 'size', 'modified_unix'
        ) 'Agent list-dir entry'
        Assert-SerctlBoundedString $entry.name 1024 'Agent list-dir entry.name'
        Assert-SerctlBoundedString $entry.path 4096 'Agent list-dir entry.path'
        Assert-SerctlRuntimeAdapter (
            (Test-StrictJsonBoolean $entry.is_dir) -and (Test-StrictJsonBoolean $entry.is_symlink)
        ) 'Agent list-dir entry flags have the wrong type'
        [void](Get-SerctlUnsignedInteger $entry.size ([uint64]::MaxValue) 'Agent list-dir entry.size')
        if ($null -ne $entry.modified_unix) {
            [void](Get-SerctlUnsignedInteger $entry.modified_unix ([uint32]::MaxValue) (
                'Agent list-dir entry.modified_unix'
            ))
        }
    }
    Assert-SerctlOneShotOperationContext $Data 'Agent list-dir data' $ForbiddenOperationContextId
}

function Assert-SerctlDaemonStatusData {
    param($Data, [AllowNull()][string]$ForbiddenOperationContextId)
    Assert-SerctlClosedObject $Data @(
        'profile', 'host', 'user', 'started_unix', 'operation_context_id', 'revision'
    ) 'Agent daemon status data'
    foreach ($field in @('profile', 'host', 'user')) {
        Assert-SerctlBoundedString $Data.$field 1024 "Agent daemon status data.$field"
    }
    Assert-SerctlRuntimeAdapter (Test-StrictJsonInteger $Data.started_unix) (
        'Agent daemon status data.started_unix is not an integer'
    )
    Assert-SerctlOneShotOperationContext `
        $Data 'Agent daemon status data' $ForbiddenOperationContextId
}

function Assert-SerctlCreateDirData {
    param($Data, [AllowNull()][string]$ForbiddenOperationContextId)
    Assert-SerctlClosedObject $Data @(
        'created', 'operation_context_id', 'revision'
    ) 'Agent create-dir data'
    Assert-SerctlBoundedString $Data.created 4096 'Agent create-dir data.created'
    Assert-SerctlOneShotOperationContext `
        $Data 'Agent create-dir data' $ForbiddenOperationContextId
}

function Assert-SerctlTunnelSnapshot {
    param($Snapshot, [AllowNull()][string]$TunnelId, [AllowNull()][string]$Mode,
        [string]$Phase, [AllowNull()][Nullable[uint64]]$Deadline,
        [AllowNull()][string]$OperationContextId, [uint64]$MinimumRevision,
        [AllowNull()][string]$ForbiddenOperationContextId,
        [switch]$RequireRevisionAdvance)
    Assert-SerctlClosedObject $Snapshot @(
        'tunnel_id', 'mode', 'stage', 'bind_host', 'bind_port', 'deadline_unix_ms',
        'operation_context_id', 'revision'
    ) 'Agent tunnel snapshot'
    foreach ($field in @('tunnel_id', 'mode', 'stage', 'bind_host')) {
        Assert-SerctlBoundedString $Snapshot.$field 64 "Agent tunnel snapshot.$field"
    }
    Assert-SerctlRuntimeAdapter (
        [string]$Snapshot.tunnel_id -cmatch '^[0-9a-f]{32}$' -and
        $script:SerctlTunnelModes -ccontains [string]$Snapshot.mode -and
        $script:SerctlTunnelStages -ccontains [string]$Snapshot.stage -and
        [string]$Snapshot.bind_host -ceq '127.0.0.1'
    ) 'Agent tunnel snapshot violates its closed vocabulary'
    [void](Get-SerctlUnsignedInteger $Snapshot.bind_port ([uint16]::MaxValue) (
        'Agent tunnel snapshot.bind_port'
    ) -NonZero)
    $actualDeadline = Get-SerctlUnsignedInteger $Snapshot.deadline_unix_ms (
        [uint64]::MaxValue
    ) 'Agent tunnel snapshot.deadline_unix_ms' -NonZero
    if (-not [string]::IsNullOrEmpty($TunnelId)) {
        Assert-SerctlRuntimeAdapter ([string]$Snapshot.tunnel_id -ceq $TunnelId) (
            'Agent tunnel id changed across transcript phases'
        )
    }
    if (-not [string]::IsNullOrEmpty($Mode)) {
        Assert-SerctlRuntimeAdapter ([string]$Snapshot.mode -ceq $Mode) (
            'Agent tunnel mode changed across transcript phases'
        )
    }
    if ($null -ne $Deadline) {
        Assert-SerctlRuntimeAdapter ($actualDeadline -eq [uint64]$Deadline) (
            'Agent tunnel deadline changed across transcript phases'
        )
    }
    $allowedStages = switch ($Phase) {
        'open' { @('ready') }
        'status' { @('ready', 'cancelling') }
        'cancel' { @('closed', 'unknown') }
        default { throw 'serctl external runtime adapter failed: internal tunnel phase is invalid' }
    }
    Assert-SerctlRuntimeAdapter ($allowedStages -ccontains [string]$Snapshot.stage) (
        "Agent tunnel $Phase has an invalid stage"
    )
    Assert-SerctlBoundedString $Snapshot.operation_context_id 64 (
        'Agent tunnel snapshot.operation_context_id'
    )
    Assert-SerctlRuntimeAdapter (
        [string]$Snapshot.operation_context_id -cmatch '^[0-9a-f]{64}$'
    ) 'Agent tunnel operation context is not lowercase 64-hex'
    if (-not [string]::IsNullOrEmpty($OperationContextId)) {
        Assert-SerctlRuntimeAdapter (
            [string]$Snapshot.operation_context_id -ceq $OperationContextId
        ) 'Agent tunnel operation context changed across transcript phases'
    }
    if (-not [string]::IsNullOrEmpty($ForbiddenOperationContextId)) {
        Assert-SerctlRuntimeAdapter (
            [string]$Snapshot.operation_context_id -cne $ForbiddenOperationContextId
        ) 'Agent tunnel substituted another accepted root operation context'
    }
    $revision = Get-SerctlUnsignedInteger $Snapshot.revision ([uint64]::MaxValue) (
        'Agent tunnel snapshot.revision'
    ) -NonZero
    Assert-SerctlRuntimeAdapter ($revision -ge $MinimumRevision) (
        'Agent tunnel snapshot revision rolled back'
    )
    if ($RequireRevisionAdvance) {
        Assert-SerctlRuntimeAdapter ($revision -gt $MinimumRevision) (
            'Agent tunnel terminal revision did not advance'
        )
    }
}

function Assert-SerctlTransferProgress {
    param(
        $Progress,
        [string]$TransferId,
        [string]$Direction,
        [string]$OperationContextId,
        [uint64]$MinimumRevision,
        $Prior
    )
    Assert-SerctlClosedObject $Progress @(
        'schema_version', 'event', 'transfer_id', 'operation_context_id', 'revision',
        'direction', 'stage',
        'total_bytes', 'confirmed_bytes', 'durable_bytes', 'window_bps',
        'average_bps', 'eta_ms', 'backend', 'chunk_bytes', 'window_bytes',
        'updated_unix_ms'
    ) 'Agent transfer progress'
    foreach ($field in @(
        'event', 'transfer_id', 'operation_context_id', 'direction', 'stage', 'backend'
    )) {
        Assert-SerctlBoundedString $Progress.$field 64 "Agent transfer progress.$field"
    }
    Assert-SerctlRuntimeAdapter (
        (Test-StrictJsonInteger $Progress.schema_version) -and [int]$Progress.schema_version -eq 1 -and
        [string]$Progress.transfer_id -ceq $TransferId -and
        [string]$Progress.operation_context_id -ceq $OperationContextId -and
        [string]$Progress.operation_context_id -cmatch '^[0-9a-f]{64}$' -and
        [string]$Progress.direction -ceq $Direction -and
        $script:SerctlTransferStages -ccontains [string]$Progress.stage -and
        $script:SerctlTransferEvents -ccontains [string]$Progress.event -and
        $script:SerctlTransferBackends -ccontains [string]$Progress.backend
    ) 'Agent transfer progress violates its closed vocabulary'
    $revision = Get-SerctlUnsignedInteger $Progress.revision ([uint64]::MaxValue) (
        'Agent transfer progress.revision'
    ) -NonZero
    Assert-SerctlRuntimeAdapter ($revision -ge $MinimumRevision) (
        'Agent transfer progress revision precedes its accepted terminal revision'
    )
    $total = Get-SerctlUnsignedInteger $Progress.total_bytes ([uint64]::MaxValue) (
        'Agent transfer progress.total_bytes'
    )
    $confirmed = Get-SerctlUnsignedInteger $Progress.confirmed_bytes ([uint64]::MaxValue) (
        'Agent transfer progress.confirmed_bytes'
    )
    $durable = Get-SerctlUnsignedInteger $Progress.durable_bytes ([uint64]::MaxValue) (
        'Agent transfer progress.durable_bytes'
    )
    $updated = Get-SerctlUnsignedInteger $Progress.updated_unix_ms ([uint64]::MaxValue) (
        'Agent transfer progress.updated_unix_ms'
    ) -NonZero
    [void](Get-SerctlUnsignedInteger $Progress.chunk_bytes ([uint32]::MaxValue) (
        'Agent transfer progress.chunk_bytes'
    ))
    [void](Get-SerctlUnsignedInteger $Progress.window_bytes ([uint32]::MaxValue) (
        'Agent transfer progress.window_bytes'
    ))
    Assert-SerctlRuntimeAdapter ($confirmed -le $total -and $durable -le $confirmed) (
        'Agent transfer acknowledgement counters are invalid'
    )
    foreach ($field in @('window_bps', 'average_bps')) {
        Assert-SerctlRuntimeAdapter (Test-SerctlJsonNumber $Progress.$field) (
            "Agent transfer progress.$field is not numeric"
        )
        try { $rate = [double]$Progress.$field }
        catch { throw "serctl external runtime adapter failed: Agent transfer progress.$field is not numeric" }
        Assert-SerctlRuntimeAdapter (
            -not [double]::IsNaN($rate) -and -not [double]::IsInfinity($rate) -and $rate -ge 0
        ) "Agent transfer progress.$field is invalid"
    }
    if ($null -ne $Progress.eta_ms) {
        [void](Get-SerctlUnsignedInteger $Progress.eta_ms ([uint64]::MaxValue) (
            'Agent transfer progress.eta_ms'
        ))
    }
    if ($null -ne $Prior.total_bytes) {
        $stageRanks = @{
            preflight = 0; hash = 1; negotiating = 2; transferring = 3; stalled = 3
            verifying = 4; committing = 5; cleanup = 6; completed = 7
            failed = 7; cancelled = 7
        }
        Assert-SerctlRuntimeAdapter (
            $total -eq [uint64]$Prior.total_bytes -and
            $confirmed -ge [uint64]$Prior.confirmed_bytes -and
            $durable -ge [uint64]$Prior.durable_bytes -and
            $updated -ge [uint64]$Prior.updated_unix_ms -and
            $revision -ge [uint64]$Prior.revision -and
            $stageRanks[[string]$Progress.stage] -ge $stageRanks[[string]$Prior.stage] -and
            -not [bool]$Prior.terminal
        ) 'Agent transfer progress is duplicate, out of order, or follows a terminal'
    }
    $terminal = [string]$Progress.stage -cin @('completed', 'failed', 'cancelled')
    if ([string]$Progress.stage -ceq 'completed') {
        Assert-SerctlRuntimeAdapter (
            $confirmed -eq $total -and $durable -eq $total -and
            [string]$Progress.event -ceq 'completed'
        ) 'Agent completed transfer is not fully confirmed and durable'
    }
    $Prior.total_bytes = $total
    $Prior.confirmed_bytes = $confirmed
    $Prior.durable_bytes = $durable
    $Prior.updated_unix_ms = $updated
    $Prior.revision = $revision
    $Prior.stage = [string]$Progress.stage
    $Prior.terminal = $terminal
}

function ConvertFrom-SerctlAgentTranscript {
    param([byte[]]$Bytes, [string]$Category, [string]$CaseId, $ExpectedContext)
    Assert-SerctlRuntimeAdapter ($Bytes.Length -gt 0 -and $Bytes.Length -le 16777216) (
        'Agent transcript is outside its byte bound'
    )
    Assert-SerctlAgentContext $ExpectedContext
    $recipe = Get-SerctlRuntimeAdapterRecipe $Category $CaseId
    try { $text = [Text.UTF8Encoding]::new($false, $true).GetString($Bytes) }
    catch { throw 'serctl external runtime adapter failed: Agent transcript is not strict UTF-8' }
    Assert-SerctlRuntimeAdapter (-not $text.Contains("`r")) 'Agent transcript contains CR bytes'
    Assert-SerctlRuntimeAdapter ($text.EndsWith("`n")) 'Agent transcript has no final LF'
    $lines = @($text.Substring(0, $text.Length - 1) -split "`n")
    Assert-SerctlRuntimeAdapter (
        $lines.Count -gt 0 -and $lines.Count -le $recipe.Count
    ) 'Agent transcript line count is outside its fixed recipe'

    $tunnelId = $null
    $tunnelMode = $null
    $tunnelOperationContextId = $null
    [uint64]$tunnelRevision = 0
    [Nullable[uint64]]$tunnelDeadline = $null
    $transferId = $null
    $transferOperationContextId = $null
    [uint64]$transferRevision = 0
    $transferDirection = $null
    [Nullable[uint64]]$transferBytes = $null
    $identityOperationContextId = $null
    $prior = [pscustomobject]@{
        total_bytes = $null; confirmed_bytes = 0; durable_bytes = 0
        updated_unix_ms = 0; stage = $null; terminal = $false
        revision = 0
    }
    $allSucceeded = $true
    for ($index = 0; $index -lt $lines.Count; $index++) {
        $operation = [string]$recipe[$index]
        $terminal = ConvertFrom-SerctlAgentResultLine $lines[$index] ([uint64]($index + 1)) $operation
        if (-not [bool]$terminal.ok) {
            Assert-SerctlRuntimeAdapter ($index -eq $lines.Count - 1) (
                'Agent transcript continues after a failure terminal'
            )
            $allSucceeded = $false
            continue
        }
        switch ($operation) {
            'ssh-connection-identity' {
                Assert-SerctlAgentConnectionIdentity $terminal.data $ExpectedContext
                $identityOperationContextId = [string]$terminal.data.operation_context_id
            }
            'exec' { Assert-SerctlExecData $terminal.data $identityOperationContextId }
            'list-dir' { Assert-SerctlListDirData $terminal.data $identityOperationContextId }
            { $_ -cin @('forward-local-open', 'forward-remote-open', 'forward-dynamic-open') } {
                $mode = switch ($operation) {
                    'forward-local-open' { 'local' }
                    'forward-remote-open' { 'remote' }
                    default { 'dynamic' }
                }
                Assert-SerctlTunnelSnapshot `
                    $terminal.data $null $mode 'open' $null $null 1 `
                    $identityOperationContextId
                $tunnelId = [string]$terminal.data.tunnel_id
                $tunnelMode = [string]$terminal.data.mode
                $tunnelOperationContextId = [string]$terminal.data.operation_context_id
                $tunnelRevision = [uint64]$terminal.data.revision
                $tunnelDeadline = [uint64]$terminal.data.deadline_unix_ms
            }
            'forward-status' {
                Assert-SerctlClosedObject $terminal.data @('tunnels') 'Agent forward-status data'
                Assert-SerctlRuntimeAdapter (
                    (Test-StrictJsonArray $terminal.data.tunnels) -and
                    @($terminal.data.tunnels).Count -eq 1
                ) 'Agent forward-status did not return exactly one bound tunnel'
                $statusSnapshot = @($terminal.data.tunnels)[0]
                Assert-SerctlTunnelSnapshot `
                    $statusSnapshot $tunnelId $tunnelMode 'status' $tunnelDeadline `
                    $tunnelOperationContextId $tunnelRevision $identityOperationContextId
                $tunnelRevision = [uint64]$statusSnapshot.revision
            }
            'forward-cancel' {
                Assert-SerctlTunnelSnapshot `
                    $terminal.data $tunnelId $tunnelMode 'cancel' $tunnelDeadline `
                    $tunnelOperationContextId $tunnelRevision $identityOperationContextId `
                    -RequireRevisionAdvance
                $tunnelRevision = [uint64]$terminal.data.revision
            }
            { $_ -cin @('transfer-push', 'transfer-pull') } {
                Assert-SerctlClosedObject $terminal.data @(
                    'transfer_id', 'operation_context_id', 'revision', 'bytes',
                    'backend_requested', 'backend', 'chunk_bytes', 'window_bytes'
                ) 'Agent transfer terminal data'
                foreach ($field in @(
                    'transfer_id', 'operation_context_id', 'backend_requested', 'backend'
                )) {
                    Assert-SerctlBoundedString $terminal.data.$field 64 "Agent transfer terminal data.$field"
                }
                Assert-SerctlRuntimeAdapter (
                    [string]$terminal.data.transfer_id -cmatch '^[0-9a-f]{32}$' -and
                    [string]$terminal.data.operation_context_id -cmatch '^[0-9a-f]{64}$' -and
                    $script:SerctlTransferBackends -ccontains [string]$terminal.data.backend_requested -and
                    $script:SerctlTransferBackends -ccontains [string]$terminal.data.backend
                ) 'Agent transfer terminal data violates its closed vocabulary'
                $transferId = [string]$terminal.data.transfer_id
                $transferOperationContextId = [string]$terminal.data.operation_context_id
                $transferRevision = Get-SerctlUnsignedInteger $terminal.data.revision (
                    [uint64]::MaxValue
                ) 'Agent transfer terminal data.revision' -NonZero
                $transferDirection = if ($operation -ceq 'transfer-push') { 'push' } else { 'pull' }
                $transferBytes = Get-SerctlUnsignedInteger $terminal.data.bytes (
                    [uint64]::MaxValue
                ) 'Agent transfer terminal data.bytes'
                [void](Get-SerctlUnsignedInteger $terminal.data.chunk_bytes (
                    [uint32]::MaxValue
                ) 'Agent transfer terminal data.chunk_bytes')
                [void](Get-SerctlUnsignedInteger $terminal.data.window_bytes (
                    [uint32]::MaxValue
                ) 'Agent transfer terminal data.window_bytes')
            }
            'transfer-status' {
                Assert-SerctlClosedObject $terminal.data @('transfers') 'Agent transfer-status data'
                Assert-SerctlRuntimeAdapter (
                    (Test-StrictJsonArray $terminal.data.transfers) -and
                    @($terminal.data.transfers).Count -eq 1
                ) 'Agent transfer-status did not return exactly one bound transfer'
                $progress = @($terminal.data.transfers)[0]
                Assert-SerctlTransferProgress $progress $transferId $transferDirection `
                    $transferOperationContextId $transferRevision $prior
                Assert-SerctlRuntimeAdapter (
                    [uint64]$progress.total_bytes -eq [uint64]$transferBytes
                ) 'Agent transfer status total differs from transfer-push terminal bytes'
            }
            default { throw 'serctl external runtime adapter failed: internal recipe operation is invalid' }
        }
    }
    Assert-SerctlRuntimeAdapter (-not $allSucceeded -or $lines.Count -eq $recipe.Count) (
        'successful Agent transcript is an incomplete recipe prefix'
    )
    if ($allSucceeded -and $recipe -ccontains 'transfer-status') {
        Assert-SerctlRuntimeAdapter ([bool]$prior.terminal) (
            'successful Agent transfer transcript has no terminal status snapshot'
        )
    }
    return [pscustomobject]@{
        schema_version = 1
        parser_outcome = 'accepted'
        synthetic_only = $true
        sealable = $false
        operation_count = $lines.Count
        all_operations_succeeded = $allSucceeded
        context_sha256 = [string]$ExpectedContext.context_sha256
        transcript_sha256 = Get-SerctlRuntimeAdapterSha256 $Bytes
    }
}

function Assert-SerctlFormalAgentRequestInternal {
    param(
        $Request,
        [string]$Operation,
        [uint64]$RequestId,
        [string]$CaseId,
        [AllowNull()][string]$ExpectedTunnelId,
        [AllowNull()][string]$ExpectedOperationContextId,
        [AllowNull()][Nullable[uint64]]$ExpectedDeadlineUnixMs
    )
    $fields = switch -CaseSensitive ($Operation) {
        'ssh-connection-identity' { @('schema_version', 'request_id', 'op'); break }
        'exec' { @('schema_version', 'request_id', 'op', 'cmd', 'timeout_ms'); break }
        'list-dir' { @('schema_version', 'request_id', 'op', 'path', 'timeout_ms'); break }
        { $_ -cin @('forward-local-open', 'forward-remote-open') } {
            @(
                'schema_version', 'request_id', 'op', 'bind_port', 'target_port',
                'max_connections', 'deadline_unix_ms'
            )
            break
        }
        'forward-dynamic-open' {
            @(
                'schema_version', 'request_id', 'op', 'bind_port',
                'max_connections', 'deadline_unix_ms'
            )
            break
        }
        { $_ -cin @('forward-status', 'forward-cancel') } {
            @(
                'schema_version', 'request_id', 'op', 'tunnel_id',
                'operation_context_id', 'deadline_unix_ms'
            )
            break
        }
        default {
            throw 'serctl external runtime adapter failed: formal request operation is unsupported'
        }
    }
    Assert-SerctlClosedObject $Request $fields 'formal Agent request'
    Assert-SerctlRuntimeAdapter (
        (Test-StrictJsonInteger $Request.schema_version) -and
        [int]$Request.schema_version -eq 1 -and
        (Test-StrictJsonInteger $Request.request_id) -and
        [uint64]$Request.request_id -eq $RequestId -and
        (Test-StrictJsonString $Request.op) -and
        [string]$Request.op -ceq $Operation
    ) 'formal Agent request envelope differs from its fixed recipe'
    switch -CaseSensitive ($Operation) {
        'ssh-connection-identity' { }
        'exec' {
            Assert-SerctlRuntimeAdapter (
                (Test-StrictJsonString $Request.cmd) -and
                [string]$Request.cmd -ceq '/usr/bin/true' -and
                (Get-SerctlUnsignedInteger $Request.timeout_ms ([uint64]30000) (
                    'formal exec timeout_ms'
                ) -NonZero) -eq [uint64]30000
            ) 'formal exec request differs from the fixed no-side-effect probe'
        }
        'list-dir' {
            Assert-SerctlRuntimeAdapter (
                (Test-StrictJsonString $Request.path) -and
                [string]$Request.path -ceq '/tmp' -and
                (Get-SerctlUnsignedInteger $Request.timeout_ms ([uint64]30000) (
                    'formal list-dir timeout_ms'
                ) -NonZero) -eq [uint64]30000
            ) 'formal directory request differs from the fixed read-only probe'
        }
        { $_ -cin @('forward-local-open', 'forward-remote-open', 'forward-dynamic-open') } {
            $expectedOperation = switch -CaseSensitive ($CaseId) {
                'OpenSSH_tunnel_local' { 'forward-local-open'; break }
                'OpenSSH_tunnel_remote' { 'forward-remote-open'; break }
                'OpenSSH_tunnel_dynamic' { 'forward-dynamic-open'; break }
                default { '' }
            }
            Assert-SerctlRuntimeAdapter ($Operation -ceq $expectedOperation) (
                'formal tunnel open operation differs from its fixed case'
            )
            $bindPort = Get-SerctlUnsignedInteger $Request.bind_port ([uint16]::MaxValue) (
                'formal tunnel bind_port'
            )
            $maximum = Get-SerctlUnsignedInteger $Request.max_connections ([uint16]::MaxValue) (
                'formal tunnel max_connections'
            ) -NonZero
            $deadline = Get-SerctlUnsignedInteger $Request.deadline_unix_ms (
                [uint64]::MaxValue
            ) 'formal tunnel deadline_unix_ms' -NonZero
            Assert-SerctlRuntimeAdapter ($bindPort -eq 0 -and $maximum -eq 32) (
                'formal tunnel open request widens the fixed listener policy'
            )
            if ($null -ne $ExpectedDeadlineUnixMs) {
                Assert-SerctlRuntimeAdapter ($deadline -eq [uint64]$ExpectedDeadlineUnixMs) (
                    'formal tunnel open deadline differs from the protected value'
                )
            }
            if ($Operation -cne 'forward-dynamic-open') {
                $expectedTarget = if ($Operation -ceq 'forward-local-open') { 5432 } else { 8080 }
                Assert-SerctlRuntimeAdapter (
                    (Get-SerctlUnsignedInteger $Request.target_port ([uint16]::MaxValue) (
                        'formal tunnel target_port'
                    ) -NonZero) -eq [uint64]$expectedTarget
                ) 'formal tunnel target differs from its fixed loopback probe'
            }
        }
        { $_ -cin @('forward-status', 'forward-cancel') } {
            Assert-SerctlBoundedString $Request.tunnel_id 32 'formal tunnel request.tunnel_id'
            Assert-SerctlBoundedString $Request.operation_context_id 64 (
                'formal tunnel request.operation_context_id'
            )
            $deadline = Get-SerctlUnsignedInteger $Request.deadline_unix_ms (
                [uint64]::MaxValue
            ) 'formal tunnel request.deadline_unix_ms' -NonZero
            Assert-SerctlRuntimeAdapter (
                [string]$Request.tunnel_id -cmatch '^[0-9a-f]{32}$' -and
                [string]$Request.operation_context_id -cmatch '^[0-9a-f]{64}$' -and
                -not [string]::IsNullOrEmpty($ExpectedTunnelId) -and
                [string]$Request.tunnel_id -ceq $ExpectedTunnelId -and
                -not [string]::IsNullOrEmpty($ExpectedOperationContextId) -and
                [string]$Request.operation_context_id -ceq $ExpectedOperationContextId -and
                $null -ne $ExpectedDeadlineUnixMs -and
                $deadline -eq [uint64]$ExpectedDeadlineUnixMs
            ) 'formal tunnel control request is not bound to the accepted object'
        }
    }
}

function Assert-SerctlFormalRuntimeRequestBytesInternal {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][string]$Category,
        [Parameter(Mandatory = $true)][string]$CaseId
    )

    Assert-SerctlRuntimeAdapter ($Bytes.Length -gt 0 -and $Bytes.Length -le 1048576) (
        'protected formal request input is outside its byte bound'
    )
    $utf8 = [Text.UTF8Encoding]::new($false, $true)
    try { $text = $utf8.GetString($Bytes) }
    catch { throw 'serctl external runtime adapter failed: protected formal request input is not strict UTF-8' }
    Assert-SerctlRuntimeAdapter (
        $text.EndsWith("`n") -and -not $text.Contains("`r") -and
        -not (Test-SerctlContainsSensitiveCanary $text)
    ) 'protected formal request input is not canonical safe JSONL'
    $lines = @($text.Substring(0, $text.Length - 1) -split "`n")
    $recipe = Get-SerctlRuntimeAdapterRecipe $Category $CaseId
    Assert-SerctlRuntimeAdapter ($lines.Count -eq $recipe.Count) (
        'protected formal request input does not match the fixed recipe length'
    )
    for ($index = 0; $index -lt $lines.Count; $index++) {
        Assert-SerctlRuntimeAdapter (
            $lines[$index].Length -gt 0 -and $lines[$index].Length -le 1048576
        ) 'protected formal request line is outside its byte bound'
        $request = ConvertFrom-StrictJson `
            -Json $lines[$index] `
            -Label 'protected formal Agent request'
        Assert-SerctlFormalAgentRequestInternal `
            $request ([string]$recipe[$index]) ([uint64]($index + 1)) $CaseId
        $properties = @($request.PSObject.Properties.Name)
        foreach ($property in $properties) {
            Assert-SerctlRuntimeAdapter (
                $property -cmatch '^[a-z][a-z0-9_]{0,63}$' -and
                $property -notmatch '(?i)(password|passphrase|private|secret|credential|token)'
            ) 'protected formal Agent request contains a forbidden field name'
        }
    }
}

function New-SerctlFormalRuntimeRequestBytesInternal {
    param([string]$Category, [string]$CaseId)

    [void](Get-SerctlRuntimeAdapterRecipe $Category $CaseId)
    $requests = switch -CaseSensitive ($CaseId) {
        { $_ -in @('OpenSSH_exec', 'Dropbear_exec') } {
            @(
                [pscustomobject][ordered]@{
                    schema_version = 1; request_id = [uint64]1
                    op = 'ssh-connection-identity'
                },
                [pscustomobject][ordered]@{
                    schema_version = 1; request_id = [uint64]2
                    op = 'exec'; cmd = '/usr/bin/true'; timeout_ms = [uint64]30000
                }
            )
            break
        }
        'OpenSSH_directory' {
            @(
                [pscustomobject][ordered]@{
                    schema_version = 1; request_id = [uint64]1
                    op = 'ssh-connection-identity'
                },
                [pscustomobject][ordered]@{
                    schema_version = 1; request_id = [uint64]2
                    op = 'list-dir'; path = '/tmp'; timeout_ms = [uint64]30000
                }
            )
            break
        }
        default {
            throw (
                "serctl external runtime adapter failed: runtime case '$CaseId' remains BLOCKED; " +
                'its fixed formal request builder or operation context is unavailable'
            )
        }
    }
    $text = (($requests | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 8 }) -join "`n") + "`n"
    return ,([Text.UTF8Encoding]::new($false, $true).GetBytes($text))
}

function Get-SerctlFormalManagedTunnelCaseInternal {
    param([string]$Category, [string]$CaseId)
    Assert-SerctlRuntimeAdapter ($Category -ceq 'openssh_dropbear_interop') (
        'formal managed tunnel requires the interoperability category'
    )
    $binding = switch -CaseSensitive ($CaseId) {
        'OpenSSH_tunnel_local' {
            [pscustomobject][ordered]@{
                operation = 'forward-local-open'; mode = 'local'; target_port = [uint16]5432
            }
            break
        }
        'OpenSSH_tunnel_remote' {
            [pscustomobject][ordered]@{
                operation = 'forward-remote-open'; mode = 'remote'; target_port = [uint16]8080
            }
            break
        }
        'OpenSSH_tunnel_dynamic' {
            [pscustomobject][ordered]@{
                operation = 'forward-dynamic-open'; mode = 'dynamic'; target_port = $null
            }
            break
        }
        default {
            throw 'serctl external runtime adapter failed: case is not a formal managed tunnel'
        }
    }
    [void](Get-SerctlRuntimeAdapterRecipe $Category $CaseId)
    return $binding
}

function New-SerctlFormalManagedTunnelOpenRequestBytesInternal {
    param([string]$Category, [string]$CaseId, [uint64]$DeadlineUnixMs)
    $binding = Get-SerctlFormalManagedTunnelCaseInternal $Category $CaseId
    Assert-SerctlRuntimeAdapter ($DeadlineUnixMs -gt 0) (
        'formal managed tunnel deadline is invalid'
    )
    $open = [ordered]@{
        schema_version = 1; request_id = [uint64]2; op = [string]$binding.operation
        bind_port = [uint16]0; max_connections = [uint16]32
        deadline_unix_ms = $DeadlineUnixMs
    }
    if ($null -ne $binding.target_port) {
        # Preserve the exact Agent schema order only for readability. The strict
        # parser below binds by closed field set and canonical values.
        $open = [ordered]@{
            schema_version = 1; request_id = [uint64]2; op = [string]$binding.operation
            bind_port = [uint16]0; target_port = [uint16]$binding.target_port
            max_connections = [uint16]32; deadline_unix_ms = $DeadlineUnixMs
        }
    }
    $requests = @(
        [ordered]@{
            schema_version = 1; request_id = [uint64]1
            op = 'ssh-connection-identity'
        },
        $open
    )
    $text = (($requests | ForEach-Object {
        [pscustomobject]$_ | ConvertTo-Json -Compress -Depth 8
    }) -join "`n") + "`n"
    $bytes = [Text.UTF8Encoding]::new($false, $true).GetBytes($text)
    Assert-SerctlFormalManagedTunnelRequestSegmentInternal `
        $bytes $Category $CaseId 'open' $null $null $DeadlineUnixMs
    return ,$bytes
}

function New-SerctlFormalManagedTunnelControlRequestBytesInternal {
    param(
        [string]$Category,
        [string]$CaseId,
        [ValidateSet('status', 'cancel')][string]$Phase,
        [string]$TunnelId,
        [string]$OperationContextId,
        [uint64]$DeadlineUnixMs
    )
    [void](Get-SerctlFormalManagedTunnelCaseInternal $Category $CaseId)
    Assert-SerctlRuntimeAdapter (
        $TunnelId -cmatch '^[0-9a-f]{32}$' -and
        $OperationContextId -cmatch '^[0-9a-f]{64}$' -and
        $DeadlineUnixMs -gt 0
    ) 'formal managed tunnel control binding is invalid'
    $operation = if ($Phase -ceq 'status') { 'forward-status' } else { 'forward-cancel' }
    $requestId = if ($Phase -ceq 'status') { [uint64]3 } else { [uint64]4 }
    $request = [pscustomobject][ordered]@{
        schema_version = 1; request_id = $requestId; op = $operation
        tunnel_id = $TunnelId; operation_context_id = $OperationContextId
        deadline_unix_ms = $DeadlineUnixMs
    }
    $bytes = [Text.UTF8Encoding]::new($false, $true).GetBytes(
        (($request | ConvertTo-Json -Compress -Depth 8) + "`n")
    )
    Assert-SerctlFormalManagedTunnelRequestSegmentInternal `
        $bytes $Category $CaseId $Phase $TunnelId $OperationContextId $DeadlineUnixMs
    return ,$bytes
}

function Assert-SerctlFormalManagedTunnelRequestSegmentInternal {
    param(
        [byte[]]$Bytes,
        [string]$Category,
        [string]$CaseId,
        [ValidateSet('open', 'status', 'cancel')][string]$Phase,
        [AllowNull()][string]$TunnelId,
        [AllowNull()][string]$OperationContextId,
        [uint64]$DeadlineUnixMs
    )
    $binding = Get-SerctlFormalManagedTunnelCaseInternal $Category $CaseId
    Assert-SerctlRuntimeAdapter ($Bytes.Length -gt 0 -and $Bytes.Length -le 1048576) (
        'formal managed tunnel request segment is outside its byte bound'
    )
    try { $text = [Text.UTF8Encoding]::new($false, $true).GetString($Bytes) }
    catch { throw 'serctl external runtime adapter failed: tunnel request is not strict UTF-8' }
    Assert-SerctlRuntimeAdapter (
        $text.EndsWith("`n") -and -not $text.Contains("`r") -and
        -not (Test-SerctlContainsSensitiveCanary $text)
    ) 'formal managed tunnel request is not canonical safe JSONL'
    $lines = @($text.Substring(0, $text.Length - 1) -split "`n")
    [string[]]$expectedOperations = if ($Phase -ceq 'open') {
        @('ssh-connection-identity', [string]$binding.operation)
    }
    elseif ($Phase -ceq 'status') { @('forward-status') }
    else { @('forward-cancel') }
    $firstRequestId = if ($Phase -ceq 'open') { [uint64]1 }
        elseif ($Phase -ceq 'status') { [uint64]3 } else { [uint64]4 }
    Assert-SerctlRuntimeAdapter ($lines.Count -eq $expectedOperations.Count) (
        'formal managed tunnel request operation count is invalid'
    )
    for ($index = 0; $index -lt $lines.Count; $index++) {
        $request = ConvertFrom-StrictJson $lines[$index] 'formal managed tunnel request'
        Assert-SerctlFormalAgentRequestInternal `
            $request ([string]$expectedOperations[$index]) `
            ($firstRequestId + [uint64]$index) $CaseId `
            $TunnelId $OperationContextId $DeadlineUnixMs
    }
}

function Get-SerctlFormalCaptureLinesInternal {
    param($Capture, [uint64]$ExpectedCount, [string]$Label)
    Assert-SerctlRuntimeAdapter (
        [string]$Capture.exit_category -ceq 'completed_success' -and
        [int]$Capture.exit_code -eq 0 -and [bool]$Capture.process_tree_exited -and
        $Capture.stderr -is [byte[]] -and $Capture.stderr.Length -eq 0 -and
        $Capture.stdout -is [byte[]] -and $Capture.stdout.Length -gt 0 -and
        $Capture.stdout.Length -le 16777216
    ) "$Label process did not terminate with a clean bounded terminal"
    try { $text = [Text.UTF8Encoding]::new($false, $true).GetString($Capture.stdout) }
    catch { throw "serctl external runtime adapter failed: $Label stdout is not strict UTF-8" }
    Assert-SerctlRuntimeAdapter (
        $text.EndsWith("`n") -and -not $text.Contains("`r") -and
        -not (Test-SerctlContainsSensitiveCanary $text)
    ) "$Label stdout is not canonical safe JSONL"
    $lines = @($text.Substring(0, $text.Length - 1) -split "`n")
    Assert-SerctlRuntimeAdapter ($lines.Count -eq $ExpectedCount) (
        "$Label stdout line count differs from its fixed recipe"
    )
    return ,$lines
}

function Get-SerctlFormalManagedTunnelOpenBindingInternal {
    param($OpenCapture, [string]$Category, [string]$CaseId, $ExpectedContext)
    $case = Get-SerctlFormalManagedTunnelCaseInternal $Category $CaseId
    Assert-SerctlAgentContext $ExpectedContext
    $lines = Get-SerctlFormalCaptureLinesInternal $OpenCapture 2 'formal tunnel open'
    $identity = ConvertFrom-SerctlAgentResultLine $lines[0] 1 'ssh-connection-identity'
    Assert-SerctlRuntimeAdapter ([bool]$identity.ok) 'formal tunnel identity failed'
    Assert-SerctlAgentConnectionIdentity $identity.data $ExpectedContext
    $open = ConvertFrom-SerctlAgentResultLine $lines[1] 2 ([string]$case.operation)
    Assert-SerctlRuntimeAdapter ([bool]$open.ok) 'formal tunnel open failed'
    Assert-SerctlTunnelSnapshot `
        $open.data $null ([string]$case.mode) 'open' $null $null 1 `
        ([string]$identity.data.operation_context_id)
    return [pscustomobject][ordered]@{
        tunnel_id = [string]$open.data.tunnel_id
        mode = [string]$open.data.mode
        operation_context_id = [string]$open.data.operation_context_id
        revision = [uint64]$open.data.revision
        deadline_unix_ms = [uint64]$open.data.deadline_unix_ms
        identity_operation_context_id = [string]$identity.data.operation_context_id
    }
}

function ConvertFrom-SerctlFormalManagedTunnelCapturesInternal {
    param(
        $OpenCapture,
        $StatusCapture,
        $CancelCapture,
        [string]$Category,
        [string]$CaseId,
        $ExpectedContext
    )
    $binding = Get-SerctlFormalManagedTunnelOpenBindingInternal `
        $OpenCapture $Category $CaseId $ExpectedContext
    $statusLines = Get-SerctlFormalCaptureLinesInternal $StatusCapture 1 'formal tunnel status'
    $status = ConvertFrom-SerctlAgentResultLine $statusLines[0] 3 'forward-status'
    Assert-SerctlRuntimeAdapter ([bool]$status.ok) 'formal tunnel status failed'
    Assert-SerctlClosedObject $status.data @('tunnels') 'formal tunnel status data'
    Assert-SerctlRuntimeAdapter (
        (Test-StrictJsonArray $status.data.tunnels) -and
        @($status.data.tunnels).Count -eq 1
    ) 'formal tunnel status did not return exactly one object'
    $statusSnapshot = @($status.data.tunnels)[0]
    Assert-SerctlTunnelSnapshot `
        $statusSnapshot $binding.tunnel_id $binding.mode 'status' `
        ([uint64]$binding.deadline_unix_ms) $binding.operation_context_id `
        ([uint64]$binding.revision) $binding.identity_operation_context_id
    $cancelLines = Get-SerctlFormalCaptureLinesInternal $CancelCapture 1 'formal tunnel cancel'
    $cancel = ConvertFrom-SerctlAgentResultLine $cancelLines[0] 4 'forward-cancel'
    Assert-SerctlRuntimeAdapter ([bool]$cancel.ok) 'formal tunnel cancel failed'
    Assert-SerctlTunnelSnapshot `
        $cancel.data $binding.tunnel_id $binding.mode 'cancel' `
        ([uint64]$binding.deadline_unix_ms) $binding.operation_context_id `
        ([uint64]$statusSnapshot.revision) $binding.identity_operation_context_id `
        -RequireRevisionAdvance
    return [pscustomobject][ordered]@{
        tunnel_id = [string]$binding.tunnel_id
        operation_context_id = [string]$binding.operation_context_id
        open_revision = [uint64]$binding.revision
        status_revision = [uint64]$statusSnapshot.revision
        terminal_revision = [uint64]$cancel.data.revision
        terminal_stage = [string]$cancel.data.stage
    }
}

function Get-SerctlFormalInteropTransferCaseInternal {
    param([string]$Category, [string]$CaseId)
    Assert-SerctlRuntimeAdapter ($Category -ceq 'openssh_dropbear_interop') (
        'formal interop transfer requires the interoperability category'
    )
    $binding = switch -CaseSensitive ($CaseId) {
        'OpenSSH_sftp' { [pscustomobject]@{ implementation = 'OpenSSH'; backend = 'sftp' }; break }
        'OpenSSH_native' { [pscustomobject]@{ implementation = 'OpenSSH'; backend = 'native' }; break }
        'Dropbear_sftp' { [pscustomobject]@{ implementation = 'Dropbear'; backend = 'sftp' }; break }
        'Dropbear_native' { [pscustomobject]@{ implementation = 'Dropbear'; backend = 'native' }; break }
        default { throw 'serctl external runtime adapter failed: case is not a formal interop transfer' }
    }
    [void](Get-SerctlRuntimeAdapterRecipe $Category $CaseId)
    return $binding
}

function Assert-SerctlFormalExpectedHelperIdentityInternal {
    param($Identity, $ExpectedComponent)
    Assert-SerctlClosedObject $Identity @('name', 'binary_size', 'sha256', 'version') (
        'formal native expected helper identity'
    )
    Assert-SerctlBoundedString $Identity.name 64 'formal native helper name'
    Assert-SerctlBoundedString $Identity.sha256 64 'formal native helper sha256'
    Assert-SerctlBoundedString $Identity.version 512 'formal native helper version'
    $size = Get-SerctlUnsignedInteger $Identity.binary_size ([uint64]::MaxValue) (
        'formal native helper binary_size'
    ) -NonZero
    Assert-SerctlRuntimeAdapter (
        [string]$Identity.name -ceq 'serctl-xfer' -and
        [string]$Identity.sha256 -cmatch '^[0-9a-f]{64}$' -and
        $null -ne $ExpectedComponent -and
        [string]$Identity.name -ceq [string]$ExpectedComponent.name -and
        $size -eq [uint64]$ExpectedComponent.binary_size -and
        [string]$Identity.sha256 -ceq ([string]$ExpectedComponent.sha256).ToLowerInvariant() -and
        [string]$Identity.version -ceq [string]$ExpectedComponent.version
    ) 'formal native helper identity differs from verified component provenance'
}

function Assert-SerctlFormalInteropTransferRequestSegmentsInternal {
    param(
        [byte[]]$PrimaryBytes,
        [byte[]]$StatusBytes,
        [string]$Category,
        [string]$CaseId,
        [string]$TransferId,
        [uint64]$DeadlineMilliseconds,
        $ExpectedHelperComponent
    )
    $case = Get-SerctlFormalInteropTransferCaseInternal $Category $CaseId
    Assert-SerctlRuntimeAdapter ($TransferId -cmatch '^[0-9a-f]{32}$') (
        'formal interop transfer id is invalid'
    )
    foreach ($segment in @(
        @($PrimaryBytes, [uint64]2, 'formal interop transfer primary'),
        @($StatusBytes, [uint64]1, 'formal interop transfer status')
    )) {
        $bytes = [byte[]]$segment[0]
        Assert-SerctlRuntimeAdapter ($bytes.Length -gt 0 -and $bytes.Length -le 1048576) (
            "$($segment[2]) request is outside its byte bound"
        )
        try { $text = [Text.UTF8Encoding]::new($false, $true).GetString($bytes) }
        catch { throw "serctl external runtime adapter failed: $($segment[2]) is not strict UTF-8" }
        Assert-SerctlRuntimeAdapter (
            $text.EndsWith("`n") -and -not $text.Contains("`r") -and
            -not (Test-SerctlContainsSensitiveCanary $text)
        ) "$($segment[2]) is not canonical safe JSONL"
        $lines = @($text.Substring(0, $text.Length - 1) -split "`n")
        Assert-SerctlRuntimeAdapter ($lines.Count -eq [uint64]$segment[1]) (
            "$($segment[2]) line count differs from its fixed recipe"
        )
        if ($segment[2] -ceq 'formal interop transfer primary') { $primaryLines = $lines }
        else { $statusLines = $lines }
    }
    $identity = ConvertFrom-StrictJson $primaryLines[0] 'formal interop identity request'
    Assert-SerctlFormalAgentRequestInternal `
        $identity 'ssh-connection-identity' 1 $CaseId
    $transfer = ConvertFrom-StrictJson $primaryLines[1] 'formal interop transfer request'
    $transferFields = @(
        'schema_version', 'request_id', 'op', 'transfer_id', 'local', 'remote',
        'backend', 'resume', 'idle_timeout_ms', 'deadline_ms'
    )
    if ([string]$case.backend -ceq 'native') { $transferFields += 'expected_helper_identity' }
    Assert-SerctlClosedObject $transfer $transferFields 'formal interop transfer request'
    foreach ($field in @('op', 'transfer_id', 'local', 'remote', 'backend', 'resume')) {
        Assert-SerctlBoundedString $transfer.$field 4096 "formal interop transfer request.$field"
    }
    $expectedRemote = '/tmp/serctl-v1-beta-' + $CaseId.ToLowerInvariant() + '-target-21.bin'
    Assert-SerctlRuntimeAdapter (
        (Test-StrictJsonInteger $transfer.schema_version) -and [int]$transfer.schema_version -eq 1 -and
        (Test-StrictJsonInteger $transfer.request_id) -and [uint64]$transfer.request_id -eq 2 -and
        [string]$transfer.op -ceq 'transfer-push' -and
        [string]$transfer.transfer_id -ceq $TransferId -and
        [string]$transfer.local -ceq '/tmp/serctl-v1-beta-interop-source-21.bin' -and
        [string]$transfer.remote -ceq $expectedRemote -and
        [string]$transfer.backend -ceq [string]$case.backend -and
        [string]$transfer.resume -ceq 'never' -and
        (Get-SerctlUnsignedInteger $transfer.idle_timeout_ms ([uint64]30000) (
            'formal interop transfer idle_timeout_ms'
        ) -NonZero) -eq [uint64]30000 -and
        (Get-SerctlUnsignedInteger $transfer.deadline_ms ([uint64]::MaxValue) (
            'formal interop transfer deadline_ms'
        ) -NonZero) -eq $DeadlineMilliseconds
    ) 'formal interop transfer request differs from its fixed recipe'
    if ([string]$case.backend -ceq 'native') {
        Assert-SerctlFormalExpectedHelperIdentityInternal `
            $transfer.expected_helper_identity $ExpectedHelperComponent
    }
    else {
        Assert-SerctlRuntimeAdapter ($null -eq $ExpectedHelperComponent) (
            'formal SFTP request unexpectedly depends on helper identity'
        )
    }
    $status = ConvertFrom-StrictJson $statusLines[0] 'formal interop status request'
    Assert-SerctlClosedObject $status @(
        'schema_version', 'request_id', 'op', 'transfer_id'
    ) 'formal interop status request'
    Assert-SerctlRuntimeAdapter (
        (Test-StrictJsonInteger $status.schema_version) -and [int]$status.schema_version -eq 1 -and
        (Test-StrictJsonInteger $status.request_id) -and [uint64]$status.request_id -eq 3 -and
        (Test-StrictJsonString $status.op) -and [string]$status.op -ceq 'transfer-status' -and
        (Test-StrictJsonString $status.transfer_id) -and
        [string]$status.transfer_id -ceq $TransferId
    ) 'formal interop status request differs from its fixed discovery recipe'
}

function New-SerctlFormalInteropTransferRequestSegmentsInternal {
    param(
        [string]$Category,
        [string]$CaseId,
        [string]$TransferId,
        [uint64]$DeadlineMilliseconds,
        $ExpectedHelperComponent
    )
    $case = Get-SerctlFormalInteropTransferCaseInternal $Category $CaseId
    Assert-SerctlRuntimeAdapter (
        $TransferId -cmatch '^[0-9a-f]{32}$' -and $DeadlineMilliseconds -gt 0
    ) 'formal interop transfer binding is invalid'
    $request = [ordered]@{
        schema_version = 1; request_id = [uint64]2; op = 'transfer-push'
        transfer_id = $TransferId
        local = '/tmp/serctl-v1-beta-interop-source-21.bin'
        remote = '/tmp/serctl-v1-beta-' + $CaseId.ToLowerInvariant() + '-target-21.bin'
        backend = [string]$case.backend; resume = 'never'
        idle_timeout_ms = [uint64]30000; deadline_ms = $DeadlineMilliseconds
    }
    if ([string]$case.backend -ceq 'native') {
        $helper = [pscustomobject][ordered]@{
            name = [string]$ExpectedHelperComponent.name
            binary_size = [long]$ExpectedHelperComponent.binary_size
            sha256 = ([string]$ExpectedHelperComponent.sha256).ToLowerInvariant()
            version = [string]$ExpectedHelperComponent.version
        }
        Assert-SerctlFormalExpectedHelperIdentityInternal $helper $ExpectedHelperComponent
        $request['expected_helper_identity'] = $helper
    }
    else {
        Assert-SerctlRuntimeAdapter ($null -eq $ExpectedHelperComponent) (
            'formal SFTP builder was given helper identity'
        )
    }
    $primary = @(
        [pscustomobject][ordered]@{
            schema_version = 1; request_id = [uint64]1
            op = 'ssh-connection-identity'
        },
        [pscustomobject]$request
    )
    $status = [pscustomobject][ordered]@{
        schema_version = 1; request_id = [uint64]3
        op = 'transfer-status'; transfer_id = $TransferId
    }
    $primaryBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes(
        (($primary | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 8 }) -join "`n") + "`n"
    )
    $statusBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes(
        (($status | ConvertTo-Json -Compress -Depth 8) + "`n")
    )
    try {
        Assert-SerctlFormalInteropTransferRequestSegmentsInternal `
            $primaryBytes $statusBytes $Category $CaseId $TransferId `
            $DeadlineMilliseconds $ExpectedHelperComponent
        return [pscustomobject][ordered]@{ primary = $primaryBytes; status = $statusBytes }
    }
    catch {
        [Array]::Clear($primaryBytes, 0, $primaryBytes.Length)
        [Array]::Clear($statusBytes, 0, $statusBytes.Length)
        throw
    }
}

function Get-SerctlFormalComponentsFromVerifiedProvenanceInternal {
    param(
        [Parameter(Mandatory = $true)][byte[]]$WindowsProvenanceBytes,
        [Parameter(Mandatory = $true)][byte[]]$LinuxProvenanceBytes
    )

    $records = [ordered]@{}
    foreach ($binding in @(
        @('windows-x86_64', $WindowsProvenanceBytes, @('serctl_cli.exe', 'serctl_daemon.exe')),
        @('linux-x86_64', $LinuxProvenanceBytes, @('serctl-xfer'))
    )) {
        $bytes = [byte[]]$binding[1]
        Assert-SerctlRuntimeAdapter ($bytes.Length -gt 0 -and $bytes.Length -le 262144) (
            'verified platform provenance bytes are outside their bound'
        )
        try { $json = [Text.UTF8Encoding]::new($false, $true).GetString($bytes) }
        catch { throw 'serctl external runtime adapter failed: verified platform provenance is not strict UTF-8' }
        $document = ConvertFrom-StrictJson -Json $json -Label 'verified platform provenance'
        Assert-SerctlRuntimeAdapter (
            (Test-StrictJsonInteger $document.schema_version) -and
            [int]$document.schema_version -eq 2 -and
            (Test-StrictJsonString $document.platform) -and
            [string]$document.platform -ceq [string]$binding[0] -and
            (Test-StrictJsonArray $document.binary_components)
        ) 'verified platform provenance identity is invalid'
        $expected = [string[]]$binding[2]
        $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($component in @($document.binary_components)) {
            Assert-SerctlClosedObject $component @('name', 'binary_size', 'sha256', 'version') (
                'verified platform provenance component'
            )
            $name = [string]$component.name
            Assert-SerctlRuntimeAdapter (
                $expected -ccontains $name -and $seen.Add($name)
            ) 'verified platform provenance component is unknown or duplicated'
            $records[$name] = [pscustomobject][ordered]@{
                name = $name
                binary_size = [long]$component.binary_size
                sha256 = ([string]$component.sha256).ToUpperInvariant()
                version = [string]$component.version
            }
        }
        Assert-SerctlRuntimeAdapter ($seen.Count -eq $expected.Count) (
            'verified platform provenance component set is incomplete'
        )
    }
    return [pscustomobject][ordered]@{
        cli = $records['serctl_cli.exe']
        daemon = $records['serctl_daemon.exe']
        helper = $records['serctl-xfer']
    }
}

function Get-SerctlFormalComponentSetDigestInternal {
    param([Parameter(Mandatory = $true)]$Components)
    $canonical = [pscustomobject][ordered]@{
        cli = [pscustomobject][ordered]@{
            name = [string]$Components.cli.name
            binary_size = [long]$Components.cli.binary_size
            sha256 = [string]$Components.cli.sha256
            version = [string]$Components.cli.version
        }
        daemon = [pscustomobject][ordered]@{
            name = [string]$Components.daemon.name
            binary_size = [long]$Components.daemon.binary_size
            sha256 = [string]$Components.daemon.sha256
            version = [string]$Components.daemon.version
        }
        helper = [pscustomobject][ordered]@{
            name = [string]$Components.helper.name
            binary_size = [long]$Components.helper.binary_size
            sha256 = [string]$Components.helper.sha256
            version = [string]$Components.helper.version
        }
    }
    $bytes = [Text.UTF8Encoding]::new($false, $true).GetBytes(
        ($canonical | ConvertTo-Json -Compress -Depth 6)
    )
    try { return Get-SerctlRuntimeAdapterSha256 $bytes }
    finally { [Array]::Clear($bytes, 0, $bytes.Length) }
}

function Get-SerctlFormalBoundDigestInternal {
    param([Parameter(Mandatory = $true)][string[]]$Parts)
    $text = [string]::Join([char]0, $Parts) + [char]0
    $bytes = [Text.UTF8Encoding]::new($false, $true).GetBytes($text)
    try { return Get-SerctlRuntimeAdapterSha256 $bytes }
    finally { [Array]::Clear($bytes, 0, $bytes.Length) }
}

function Assert-SerctlFormalComponentSetInternal {
    param(
        [Parameter(Mandatory = $true)]$Components,
        [Parameter(Mandatory = $true)]$ComponentPaths
    )

    Assert-SerctlClosedObject $Components @('cli', 'daemon', 'helper') (
        'protected exact release component set'
    )
    Assert-SerctlClosedObject $ComponentPaths @('cli', 'daemon', 'helper') (
        'protected exact release component paths'
    )
    $expectedNames = [ordered]@{
        cli = 'serctl_cli.exe'
        daemon = 'serctl_daemon.exe'
        helper = 'serctl-xfer'
    }
    $versionPatterns = [ordered]@{
        cli = '^serctl_cli 1\.0\.0-beta \(git [0-9a-f]{12}; vault-storage read=v4\.\.=v5 write=v5\)$'
        daemon = '^serctl_daemon 1\.0\.0-beta \(git [0-9a-f]{12}; IPC v9\.\.=v9; vault-storage read=v4\.\.=v5 write=v5\)$'
        helper = '^serctl-xfer 1\.0\.0-beta \(git [0-9a-f]{12}; transfer protocol v1\)$'
    }
    foreach ($role in @('cli', 'daemon', 'helper')) {
        $component = $Components.$role
        Assert-SerctlClosedObject $component @('name', 'binary_size', 'sha256', 'version') (
            "protected exact release component $role"
        )
        Assert-SerctlRuntimeAdapter (
            (Test-StrictJsonString $component.name) -and
            [string]$component.name -ceq [string]$expectedNames[$role] -and
            (Test-StrictJsonInteger $component.binary_size) -and
            [long]$component.binary_size -gt 0 -and
            [long]$component.binary_size -le 536870912 -and
            (Test-StrictJsonString $component.sha256) -and
            [string]$component.sha256 -cmatch '^[0-9A-F]{64}$' -and
            (Test-StrictJsonString $component.version) -and
            -not [string]::IsNullOrWhiteSpace([string]$component.version) -and
            ([string]$component.version).Length -le 512 -and
            [string]$component.version -cmatch [string]$versionPatterns[$role]
        ) "protected exact release component $role is invalid"

        $pathValue = $ComponentPaths.$role
        Assert-SerctlRuntimeAdapter (Test-StrictJsonString $pathValue) (
            "protected exact release component path $role is not a string"
        )
        $path = [IO.Path]::GetFullPath([string]$pathValue)
        Assert-SerctlRuntimeAdapter (
            [IO.Path]::IsPathRooted($path) -and
            [IO.Path]::GetFileName($path) -ceq [string]$expectedNames[$role]
        ) "protected exact release component path $role is not exact"
        $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
        Assert-SerctlRuntimeAdapter (
            -not $item.PSIsContainer -and
            ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0 -and
            [long]$item.Length -eq [long]$component.binary_size
        ) "protected exact release component bytes for $role are not pinned"
        $stream = [IO.File]::Open(
            $path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read
        )
        try {
            $sha = [Security.Cryptography.SHA256]::Create()
            try {
                $actualHash = ([BitConverter]::ToString($sha.ComputeHash($stream))).Replace('-', '')
            }
            finally { $sha.Dispose() }
        }
        finally { $stream.Dispose() }
        Assert-SerctlRuntimeAdapter ($actualHash -ceq [string]$component.sha256) (
            "protected exact release component digest for $role differs from its bytes"
        )
    }
}

# INTERNAL-ONLY formal process skeleton. The public receipt contract has no
# parameters that can provide these objects. A future isolated owner must place
# the protected configuration, three exact downloaded component identities and
# an already-open Grant handle into module-private ledger state. This function
# never opens a Grant path and never accepts a pass/result/receipt object.
function Invoke-SerctlFormalRuntimeProcessSkeletonInternal {
    param(
        [Parameter(Mandatory = $true)]$ProtectedFormalConfig,
        [Parameter(Mandatory = $true)]$ExactReleaseComponents
    )

    $stdinOwned = $null
    $capture = $null
    $receiptBytes = $null
    $receiptReleased = $false
    try {
        Assert-SerctlClosedObject $ProtectedFormalConfig @(
            'schema_version', 'category', 'case_id', 'component_paths',
            'request_bytes', 'expected_context', 'deadline_ms', 'grant_input_handle'
        ) 'protected formal runtime configuration'
        Assert-SerctlRuntimeAdapter (
            (Test-StrictJsonString $ProtectedFormalConfig.schema_version) -and
            [string]$ProtectedFormalConfig.schema_version -ceq
                'serctl-protected-formal-runtime-config-v1' -and
            (Test-StrictJsonString $ProtectedFormalConfig.category) -and
            (Test-StrictJsonString $ProtectedFormalConfig.case_id) -and
            (Test-StrictJsonInteger $ProtectedFormalConfig.deadline_ms) -and
            [int64]$ProtectedFormalConfig.deadline_ms -ge 1 -and
            [int64]$ProtectedFormalConfig.deadline_ms -le 3600000 -and
            $ProtectedFormalConfig.request_bytes -is [byte[]] -and
            $ProtectedFormalConfig.grant_input_handle -is
                [Runtime.InteropServices.SafeHandle]
        ) 'protected formal runtime configuration is incomplete'
        $category = [string]$ProtectedFormalConfig.category
        $caseId = [string]$ProtectedFormalConfig.case_id
        [void](Get-SerctlRuntimeAdapterRecipe $category $caseId)
        $stdinOwned = [byte[]]$ProtectedFormalConfig.request_bytes
        Assert-SerctlFormalRuntimeRequestBytesInternal $stdinOwned $category $caseId
        Assert-SerctlAgentContext $ProtectedFormalConfig.expected_context
        Assert-SerctlFormalComponentSetInternal `
            -Components $ExactReleaseComponents `
            -ComponentPaths $ProtectedFormalConfig.component_paths

        $grantHandle = $ProtectedFormalConfig.grant_input_handle
        Assert-SerctlRuntimeAdapter (
            -not $grantHandle.IsInvalid -and -not $grantHandle.IsClosed
        ) 'protected formal Grant handle is unavailable'
        $isWindows = [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
            [Runtime.InteropServices.OSPlatform]::Windows
        )
        $isLinux = [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
            [Runtime.InteropServices.OSPlatform]::Linux
        )
        Assert-SerctlRuntimeAdapter ($isWindows -or $isLinux) (
            'formal runtime process platform is unsupported'
        )
        $grantHandleArgument = if ($isWindows) {
            $grantHandle.DangerousGetHandle().ToInt64().ToString(
                [Globalization.CultureInfo]::InvariantCulture
            )
        }
        else {
            (Get-ExternalRuntimeInheritedChildFdInternal -Purpose 'grant_input').ToString(
                [Globalization.CultureInfo]::InvariantCulture
            )
        }
        $arguments = [string[]]@('agent', '--grant-handle', $grantHandleArgument)
        $capture = Invoke-ExternalRuntimeProcessCaptureInternal `
            -ApplicationPath ([string]$ProtectedFormalConfig.component_paths.cli) `
            -ArgumentList $arguments `
            -DeadlineMilliseconds ([int]$ProtectedFormalConfig.deadline_ms) `
            -StdoutLimitBytes 16777216 `
            -StderrLimitBytes 65536 `
            -StandardInputBytes $stdinOwned `
            -StdinLimitBytes 1048576 `
            -ForbiddenCanary $script:SerctlSensitiveCanaries `
            -EnvironmentVariables ([ordered]@{
                LANG = 'C'; LC_ALL = 'C'; NO_COLOR = '1'; TERM = 'dumb'; TZ = 'UTC'
            }) `
            -InheritedHandleByPurpose @{ grant_input = $grantHandle }
        Assert-SerctlRuntimeAdapter (
            [string]$capture.exit_category -ceq 'completed_success' -and
            [int]$capture.exit_code -eq 0 -and
            [bool]$capture.process_tree_exited -and
            $capture.stderr.Length -eq 0
        ) 'formal controlled Agent process did not terminate cleanly'
        $parsed = ConvertFrom-SerctlAgentTranscript `
            -Bytes $capture.stdout `
            -Category $category `
            -CaseId $caseId `
            -ExpectedContext $ProtectedFormalConfig.expected_context
        Assert-SerctlRuntimeAdapter ([bool]$parsed.all_operations_succeeded) (
            'formal controlled Agent transcript contains a failed operation'
        )
        # Re-open and re-hash all three component paths after the process exits.
        # This catches ordinary late mutation before any receipt leaves the
        # adapter. It does not claim resistance to hostile same-process code.
        Assert-SerctlFormalComponentSetInternal `
            -Components $ExactReleaseComponents `
            -ComponentPaths $ProtectedFormalConfig.component_paths
        $componentDigest = Get-SerctlFormalComponentSetDigestInternal $ExactReleaseComponents
        $requestDigest = Get-SerctlRuntimeAdapterSha256 $stdinOwned
        $commandDigest = Get-SerctlFormalBoundDigestInternal @(
            'serctl-formal-agent-command-v1', $componentDigest, $category, $caseId,
            $requestDigest, 'agent', '--grant-handle', 'purpose:grant_input'
        )
        $stdoutDigest = Get-SerctlRuntimeAdapterSha256 $capture.stdout
        $stderrDigest = Get-SerctlRuntimeAdapterSha256 $capture.stderr
        $terminalDigest = Get-SerctlFormalBoundDigestInternal @(
            'serctl-formal-agent-terminal-v1', [string]$capture.exit_category,
            [string]$capture.exit_code, [string]$capture.stdout.Length, $stdoutDigest,
            [string]$capture.stderr.Length, $stderrDigest, [string]$capture.elapsed_ms,
            [string]$ProtectedFormalConfig.deadline_ms, 'process_tree_exited:true'
        )
        $receipt = [pscustomobject][ordered]@{
            schema_version = 1
            category = $category
            case_id = $caseId
            context_sha256 = [string]$parsed.context_sha256
            command_sha256 = $commandDigest
            terminal_sha256 = $terminalDigest
            result_code = 'completed'
            passed = $true
        }
        $receiptBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes(
            (($receipt | ConvertTo-Json -Compress) + "`n")
        )
        Assert-SerctlRuntimeAdapter ($receiptBytes.Length -le 1048576) (
            'formal child receipt exceeds its byte bound'
        )
        $observation = [pscustomobject][ordered]@{
            internal_contract = 'serctl-runtime-adapter-observation-v1'
            category = $category
            case_id = $caseId
            context_sha256 = [string]$parsed.context_sha256
            command_sha256 = $commandDigest
            terminal_sha256 = $terminalDigest
            receipt_bytes = $receiptBytes
        }
        $receiptReleased = $true
        return $observation
    }
    finally {
        if ($null -ne $stdinOwned) { [Array]::Clear($stdinOwned, 0, $stdinOwned.Length) }
        if ($null -ne $capture) {
            [Array]::Clear($capture.stdout, 0, $capture.stdout.Length)
            [Array]::Clear($capture.stderr, 0, $capture.stderr.Length)
        }
        if ($null -ne $receiptBytes -and -not $receiptReleased) {
            [Array]::Clear($receiptBytes, 0, $receiptBytes.Length)
        }
    }
}

function Assert-SerctlFormalRequestSegmentInternal {
    param(
        [byte[]]$Bytes,
        [string[]]$Operations,
        [uint64]$FirstRequestId
    )
    Assert-SerctlRuntimeAdapter ($Bytes.Length -gt 0 -and $Bytes.Length -le 1048576) (
        'formal Agent request segment is outside its byte bound'
    )
    try { $text = [Text.UTF8Encoding]::new($false, $true).GetString($Bytes) }
    catch { throw 'serctl external runtime adapter failed: formal Agent request segment is not strict UTF-8' }
    Assert-SerctlRuntimeAdapter (
        $text.EndsWith("`n") -and -not $text.Contains("`r") -and
        -not (Test-SerctlContainsSensitiveCanary $text)
    ) 'formal Agent request segment is not canonical safe JSONL'
    $lines = @($text.Substring(0, $text.Length - 1) -split "`n")
    Assert-SerctlRuntimeAdapter ($lines.Count -eq $Operations.Count) (
        'formal Agent request segment operation count is invalid'
    )
    for ($index = 0; $index -lt $lines.Count; $index++) {
        $request = ConvertFrom-StrictJson $lines[$index] 'formal Agent request segment'
        Assert-SerctlRuntimeAdapter (
            (Test-StrictJsonObject $request) -and
            (Test-StrictJsonInteger $request.schema_version) -and
            [int]$request.schema_version -eq 1 -and
            (Test-StrictJsonInteger $request.request_id) -and
            [uint64]$request.request_id -eq ($FirstRequestId + [uint64]$index) -and
            (Test-StrictJsonString $request.op) -and
            [string]$request.op -ceq [string]$Operations[$index]
        ) 'formal Agent request segment differs from its fixed recipe'
    }
}

function Invoke-SerctlFormalAgentSegmentCaptureInternal {
    param(
        [string]$ApplicationPath,
        [byte[]]$RequestBytes,
        [Runtime.InteropServices.SafeHandle]$GrantInputHandle,
        [int]$DeadlineMilliseconds
    )
    $onWindows = [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [Runtime.InteropServices.OSPlatform]::Windows
    )
    $onLinux = [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [Runtime.InteropServices.OSPlatform]::Linux
    )
    Assert-SerctlRuntimeAdapter ($onWindows -or $onLinux) 'formal transfer platform is unsupported'
    Assert-SerctlRuntimeAdapter (
        $null -ne $GrantInputHandle -and -not $GrantInputHandle.IsInvalid -and
        -not $GrantInputHandle.IsClosed
    ) 'formal transfer Grant handle is unavailable'
    $grantArgument = if ($onWindows) {
        $GrantInputHandle.DangerousGetHandle().ToInt64().ToString(
            [Globalization.CultureInfo]::InvariantCulture
        )
    }
    else {
        (Get-ExternalRuntimeInheritedChildFdInternal 'grant_input').ToString(
            [Globalization.CultureInfo]::InvariantCulture
        )
    }
    return Invoke-ExternalRuntimeProcessCaptureInternal `
        -ApplicationPath $ApplicationPath `
        -ArgumentList @('agent', '--grant-handle', $grantArgument) `
        -DeadlineMilliseconds $DeadlineMilliseconds `
        -StdoutLimitBytes 16777216 `
        -StderrLimitBytes 65536 `
        -StandardInputBytes $RequestBytes `
        -StdinLimitBytes 1048576 `
        -ForbiddenCanary $script:SerctlSensitiveCanaries `
        -EnvironmentVariables ([ordered]@{
            LANG = 'C'; LC_ALL = 'C'; NO_COLOR = '1'; TERM = 'dumb'; TZ = 'UTC'
        }) `
        -InheritedHandleByPurpose @{ grant_input = $GrantInputHandle }
}

# INTERNAL-ONLY sequential managed-tunnel producer. The caller supplies three
# distinct, already-open, purpose-bound Grant handles. The adapter constructs
# every Agent request itself: status/cancel are emitted only after parsing the
# daemon-generated id/context from the accepted open terminal. No argv,
# transcript, result, pass Boolean, expected output or receipt is accepted.
function Invoke-SerctlFormalManagedTunnelInternal {
    param(
        $ProtectedTunnelConfig,
        $ExactReleaseComponents
    )
    $openBytes = $null
    $statusBytes = $null
    $cancelBytes = $null
    $openCapture = $null
    $statusCapture = $null
    $cancelCapture = $null
    $receiptBytes = $null
    $receiptReleased = $false
    try {
        Assert-SerctlClosedObject $ProtectedTunnelConfig @(
            'schema_version', 'category', 'case_id', 'component_paths',
            'expected_context', 'deadline_ms', 'open_grant_input_handle',
            'status_grant_input_handle', 'cancel_grant_input_handle'
        ) 'protected formal managed tunnel configuration'
        Assert-SerctlRuntimeAdapter (
            (Test-StrictJsonString $ProtectedTunnelConfig.schema_version) -and
            [string]$ProtectedTunnelConfig.schema_version -ceq
                'serctl-protected-formal-managed-tunnel-config-v1' -and
            (Test-StrictJsonString $ProtectedTunnelConfig.category) -and
            (Test-StrictJsonString $ProtectedTunnelConfig.case_id) -and
            (Test-StrictJsonInteger $ProtectedTunnelConfig.deadline_ms) -and
            [int64]$ProtectedTunnelConfig.deadline_ms -ge 1 -and
            [int64]$ProtectedTunnelConfig.deadline_ms -le 3600000
        ) 'protected formal managed tunnel configuration is incomplete'
        $category = [string]$ProtectedTunnelConfig.category
        $caseId = [string]$ProtectedTunnelConfig.case_id
        [void](Get-SerctlFormalManagedTunnelCaseInternal $category $caseId)
        Assert-SerctlAgentContext $ProtectedTunnelConfig.expected_context
        Assert-SerctlFormalComponentSetInternal `
            $ExactReleaseComponents $ProtectedTunnelConfig.component_paths
        $handles = @(
            $ProtectedTunnelConfig.open_grant_input_handle,
            $ProtectedTunnelConfig.status_grant_input_handle,
            $ProtectedTunnelConfig.cancel_grant_input_handle
        )
        foreach ($handle in $handles) {
            Assert-SerctlRuntimeAdapter (
                $null -ne $handle -and $handle -is [Runtime.InteropServices.SafeHandle] -and
                -not $handle.IsInvalid -and -not $handle.IsClosed
            ) 'formal managed tunnel Grant handle is unavailable'
        }
        $handleValues = @($handles | ForEach-Object {
            $_.DangerousGetHandle().ToInt64().ToString(
                [Globalization.CultureInfo]::InvariantCulture
            )
        })
        Assert-SerctlRuntimeAdapter (@($handleValues | Select-Object -Unique).Count -eq 3) (
            'formal managed tunnel requires three distinct Grant handles'
        )
        $deadlineMs = [int64]$ProtectedTunnelConfig.deadline_ms
        $lifetimeMs = [Math]::Max([int64]300000, ($deadlineMs * 3) + 60000)
        $nowMs = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
        Assert-SerctlRuntimeAdapter ($nowMs -ge 0 -and $nowMs -le ([int64]::MaxValue - $lifetimeMs)) (
            'formal managed tunnel clock cannot produce a bounded deadline'
        )
        $deadlineUnixMs = [uint64]($nowMs + $lifetimeMs)
        $openBytes = New-SerctlFormalManagedTunnelOpenRequestBytesInternal `
            $category $caseId $deadlineUnixMs
        $openCapture = Invoke-SerctlFormalAgentSegmentCaptureInternal `
            ([string]$ProtectedTunnelConfig.component_paths.cli) $openBytes $handles[0] `
            ([int]$deadlineMs)
        $binding = Get-SerctlFormalManagedTunnelOpenBindingInternal `
            $openCapture $category $caseId $ProtectedTunnelConfig.expected_context
        Assert-SerctlRuntimeAdapter (
            [uint64]$binding.deadline_unix_ms -eq $deadlineUnixMs
        ) 'formal managed tunnel open terminal changed its protected deadline'
        $statusBytes = New-SerctlFormalManagedTunnelControlRequestBytesInternal `
            $category $caseId 'status' $binding.tunnel_id `
            $binding.operation_context_id $deadlineUnixMs
        $statusCapture = Invoke-SerctlFormalAgentSegmentCaptureInternal `
            ([string]$ProtectedTunnelConfig.component_paths.cli) $statusBytes $handles[1] `
            ([int]$deadlineMs)
        $cancelBytes = New-SerctlFormalManagedTunnelControlRequestBytesInternal `
            $category $caseId 'cancel' $binding.tunnel_id `
            $binding.operation_context_id $deadlineUnixMs
        $cancelCapture = Invoke-SerctlFormalAgentSegmentCaptureInternal `
            ([string]$ProtectedTunnelConfig.component_paths.cli) $cancelBytes $handles[2] `
            ([int]$deadlineMs)
        $terminal = ConvertFrom-SerctlFormalManagedTunnelCapturesInternal `
            $openCapture $statusCapture $cancelCapture $category $caseId `
            $ProtectedTunnelConfig.expected_context
        Assert-SerctlFormalComponentSetInternal `
            $ExactReleaseComponents $ProtectedTunnelConfig.component_paths
        $componentDigest = Get-SerctlFormalComponentSetDigestInternal $ExactReleaseComponents
        $commandDigest = Get-SerctlFormalBoundDigestInternal @(
            'serctl-formal-managed-tunnel-command-v1', $componentDigest, $category, $caseId,
            (Get-SerctlRuntimeAdapterSha256 $openBytes),
            (Get-SerctlRuntimeAdapterSha256 $statusBytes),
            (Get-SerctlRuntimeAdapterSha256 $cancelBytes),
            'purpose:grant_input:open', 'purpose:grant_input:status',
            'purpose:grant_input:cancel'
        )
        $terminalDigest = Get-SerctlFormalBoundDigestInternal @(
            'serctl-formal-managed-tunnel-terminal-v1',
            (Get-SerctlRuntimeAdapterSha256 $openCapture.stdout),
            (Get-SerctlRuntimeAdapterSha256 $statusCapture.stdout),
            (Get-SerctlRuntimeAdapterSha256 $cancelCapture.stdout),
            [string]$terminal.operation_context_id, [string]$terminal.open_revision,
            [string]$terminal.status_revision, [string]$terminal.terminal_revision,
            [string]$terminal.terminal_stage
        )
        $receipt = [pscustomobject][ordered]@{
            schema_version = 1; category = $category; case_id = $caseId
            context_sha256 = [string]$ProtectedTunnelConfig.expected_context.context_sha256
            command_sha256 = $commandDigest; terminal_sha256 = $terminalDigest
            result_code = 'completed'; passed = $true
        }
        $receiptBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes(
            (($receipt | ConvertTo-Json -Compress) + "`n")
        )
        Assert-SerctlRuntimeAdapter ($receiptBytes.Length -le 1048576) (
            'formal managed tunnel receipt exceeds its byte bound'
        )
        $observation = [pscustomobject][ordered]@{
            internal_contract = 'serctl-runtime-adapter-observation-v1'
            category = $category; case_id = $caseId
            context_sha256 = [string]$ProtectedTunnelConfig.expected_context.context_sha256
            command_sha256 = $commandDigest; terminal_sha256 = $terminalDigest
            receipt_bytes = $receiptBytes
        }
        $receiptReleased = $true
        return $observation
    }
    finally {
        foreach ($bytes in @($openBytes, $statusBytes, $cancelBytes)) {
            if ($null -ne $bytes) { [Array]::Clear($bytes, 0, $bytes.Length) }
        }
        foreach ($capture in @($openCapture, $statusCapture, $cancelCapture)) {
            if ($null -ne $capture) {
                [Array]::Clear($capture.stdout, 0, $capture.stdout.Length)
                [Array]::Clear($capture.stderr, 0, $capture.stderr.Length)
            }
        }
        if ($null -ne $receiptBytes -and -not $receiptReleased) {
            [Array]::Clear($receiptBytes, 0, $receiptBytes.Length)
        }
    }
}

function ConvertFrom-SerctlConcurrentTransferCapturesInternal {
    param(
        $PrimaryCapture,
        $StatusCapture,
        [long]$PrimaryCompletedTicks,
        [long]$StatusCompletedTicks,
        [string]$Category,
        [string]$CaseId,
        [string]$TransferId,
        $ExpectedContext,
        [ValidateSet('native', 'sftp')][string]$ExpectedBackend = 'native'
    )
    Assert-SerctlRuntimeAdapter (
        $PrimaryCapture.exit_category -ceq 'completed_success' -and
        $StatusCapture.exit_category -ceq 'completed_success' -and
        $PrimaryCapture.stderr.Length -eq 0 -and $StatusCapture.stderr.Length -eq 0 -and
        $StatusCompletedTicks -le $PrimaryCompletedTicks
    ) 'formal transfer status was not captured before the primary terminal'
    foreach ($capture in @($PrimaryCapture, $StatusCapture)) {
        Assert-SerctlRuntimeAdapter (
            [bool]$capture.process_tree_exited -and $capture.stdout.Length -gt 0
        ) 'formal transfer process tree or output is incomplete'
    }
    $primaryText = [Text.UTF8Encoding]::new($false, $true).GetString($PrimaryCapture.stdout)
    $statusText = [Text.UTF8Encoding]::new($false, $true).GetString($StatusCapture.stdout)
    Assert-SerctlRuntimeAdapter (
        $primaryText.EndsWith("`n") -and $statusText.EndsWith("`n") -and
        -not $primaryText.Contains("`r") -and -not $statusText.Contains("`r")
    ) 'formal transfer captured output is not canonical JSONL'
    $primaryLines = @($primaryText.Substring(0, $primaryText.Length - 1) -split "`n")
    $statusLines = @($statusText.Substring(0, $statusText.Length - 1) -split "`n")
    Assert-SerctlRuntimeAdapter (
        $primaryLines.Count -eq 2 -and $statusLines.Count -eq 1
    ) 'formal concurrent transfer output line count is invalid'
    Assert-SerctlAgentContext $ExpectedContext
    $identity = ConvertFrom-SerctlAgentResultLine $primaryLines[0] 1 'ssh-connection-identity'
    Assert-SerctlRuntimeAdapter ([bool]$identity.ok) 'formal transfer identity failed'
    Assert-SerctlAgentConnectionIdentity $identity.data $ExpectedContext
    $direction = if ($CaseId.StartsWith('pull_', [StringComparison]::Ordinal)) { 'pull' } else { 'push' }
    $operation = if ($direction -ceq 'pull') { 'transfer-pull' } else { 'transfer-push' }
    $terminal = ConvertFrom-SerctlAgentResultLine $primaryLines[1] 2 $operation
    Assert-SerctlRuntimeAdapter ([bool]$terminal.ok) 'formal transfer primary terminal failed'
    Assert-SerctlClosedObject $terminal.data @(
        'transfer_id', 'operation_context_id', 'revision', 'bytes',
        'backend_requested', 'backend', 'chunk_bytes', 'window_bytes'
    ) 'formal transfer primary data'
    $contextId = [string]$terminal.data.operation_context_id
    $terminalRevision = Get-SerctlUnsignedInteger $terminal.data.revision ([uint64]::MaxValue) (
        'formal transfer primary revision'
    ) -NonZero
    $totalBytes = Get-SerctlUnsignedInteger $terminal.data.bytes ([uint64]::MaxValue) (
        'formal transfer primary bytes'
    )
    Assert-SerctlRuntimeAdapter (
        [string]$terminal.data.transfer_id -ceq $TransferId -and
        $contextId -cmatch '^[0-9a-f]{64}$' -and
        [string]$terminal.data.backend_requested -ceq $ExpectedBackend -and
        [string]$terminal.data.backend -ceq $ExpectedBackend
    ) 'formal transfer primary binding differs from the predeclared id'
    $status = ConvertFrom-SerctlAgentResultLine $statusLines[0] 3 'transfer-status'
    Assert-SerctlRuntimeAdapter ([bool]$status.ok) 'formal transfer status terminal failed'
    Assert-SerctlClosedObject $status.data @('transfers') 'formal transfer status data'
    Assert-SerctlRuntimeAdapter (
        (Test-StrictJsonArray $status.data.transfers) -and
        @($status.data.transfers).Count -eq 1
    ) 'formal transfer status did not return exactly one snapshot'
    $progress = @($status.data.transfers)[0]
    $prior = [pscustomobject]@{
        total_bytes = $null; confirmed_bytes = 0; durable_bytes = 0
        updated_unix_ms = 0; stage = $null; terminal = $false; revision = 0
    }
    Assert-SerctlTransferProgress $progress $TransferId $direction $contextId 1 $prior
    Assert-SerctlRuntimeAdapter (
        [uint64]$progress.total_bytes -eq $totalBytes -and
        [uint64]$progress.revision -le $terminalRevision -and
        [string]$progress.backend -ceq $ExpectedBackend
    ) 'formal transfer status revision or byte binding is impossible before the primary terminal'
    return [pscustomobject][ordered]@{
        transfer_id = $TransferId
        operation_context_id = $contextId
        status_revision = [uint64]$progress.revision
        terminal_revision = $terminalRevision
        status_stage = [string]$progress.stage
        total_bytes = $totalBytes
    }
}

# INTERNAL-ONLY two-process evidence path. The primary blocking transfer is
# launched in a separate in-process runspace; an independently authorized
# status Agent uses its own one-shot Grant handle. Only their actual supervisor
# captures are combined, and status must complete no later than the primary
# terminal. Expected transcript bytes are not an input.
function Invoke-SerctlFormalConcurrentTransferInternal {
    param(
        $PrimaryConfig,
        $StatusConfig,
        $ExactReleaseComponents,
        [string]$TransferId,
        $ExpectedContext,
        [ValidateSet('native', 'sftp')][string]$ExpectedBackend = 'native'
    )
    $primaryCapture = $null
    $statusCapture = $null
    $receiptBytes = $null
    $receiptReleased = $false
    $worker = $null
    $async = $null
    $ready = [Threading.ManualResetEventSlim]::new($false)
    try {
        Assert-SerctlFormalComponentSetInternal $ExactReleaseComponents $PrimaryConfig.component_paths
        $operation = if ([string]$PrimaryConfig.case_id -cmatch '^pull_') {
            'transfer-pull'
        } else { 'transfer-push' }
        Assert-SerctlFormalRequestSegmentInternal $PrimaryConfig.request_bytes `
            @('ssh-connection-identity', $operation) 1
        Assert-SerctlFormalRequestSegmentInternal $StatusConfig.request_bytes @('transfer-status') 3
        # The supervisor owns and clears both buffers. Bind their original
        # bytes before either child can consume them.
        $primaryRequestDigest = Get-SerctlRuntimeAdapterSha256 $PrimaryConfig.request_bytes
        $statusRequestDigest = Get-SerctlRuntimeAdapterSha256 $StatusConfig.request_bytes
        $worker = [Management.Automation.PowerShell]::Create()
        $workerScript = @'
param($StrictJsonPath,$SupervisorPath,$AdapterPath,$ApplicationPath,$RequestBytes,$GrantHandle,$Deadline,$Ready)
. $StrictJsonPath
. $SupervisorPath
. $AdapterPath
$Ready.Set()
$capture = Invoke-SerctlFormalAgentSegmentCaptureInternal $ApplicationPath $RequestBytes $GrantHandle $Deadline
[pscustomobject]@{ capture=$capture; completed_ticks=[Diagnostics.Stopwatch]::GetTimestamp() }
'@
        [void]$worker.AddScript($workerScript).AddArgument(
            (Join-Path $PSScriptRoot 'StrictJson.ps1')
        ).AddArgument($script:SerctlRuntimeSupervisorScriptPath).AddArgument(
            $script:SerctlRuntimeAdapterScriptPath
        ).AddArgument(
            [string]$PrimaryConfig.component_paths.cli
        ).AddArgument($PrimaryConfig.request_bytes).AddArgument(
            $PrimaryConfig.grant_input_handle
        ).AddArgument([int]$PrimaryConfig.deadline_ms).AddArgument($ready)
        $async = $worker.BeginInvoke()
        Assert-SerctlRuntimeAdapter ($ready.Wait(2000)) 'formal transfer primary worker did not start'
        Start-Sleep -Milliseconds 75
        $statusCapture = Invoke-SerctlFormalAgentSegmentCaptureInternal `
            ([string]$StatusConfig.component_paths.cli) `
            $StatusConfig.request_bytes `
            $StatusConfig.grant_input_handle `
            ([int]$StatusConfig.deadline_ms)
        $statusCompletedTicks = [Diagnostics.Stopwatch]::GetTimestamp()
        $primaryOutput = @($worker.EndInvoke($async))
        Assert-SerctlRuntimeAdapter (
            $worker.Streams.Error.Count -eq 0 -and $primaryOutput.Count -eq 1
        ) 'formal transfer primary worker failed closed'
        $primaryCapture = $primaryOutput[0].capture
        $primaryCompletedTicks = [long]$primaryOutput[0].completed_ticks
        $binding = ConvertFrom-SerctlConcurrentTransferCapturesInternal `
            $primaryCapture $statusCapture $primaryCompletedTicks $statusCompletedTicks `
            ([string]$PrimaryConfig.category) ([string]$PrimaryConfig.case_id) `
            $TransferId $ExpectedContext $ExpectedBackend
        Assert-SerctlFormalComponentSetInternal $ExactReleaseComponents $PrimaryConfig.component_paths
        $componentDigest = Get-SerctlFormalComponentSetDigestInternal $ExactReleaseComponents
        $commandDigest = Get-SerctlFormalBoundDigestInternal @(
            'serctl-formal-concurrent-transfer-command-v1', $componentDigest,
            [string]$PrimaryConfig.category, [string]$PrimaryConfig.case_id,
            $primaryRequestDigest, $statusRequestDigest,
            $TransferId, 'purpose:grant_input:primary', 'purpose:grant_input:status'
        )
        $terminalDigest = Get-SerctlFormalBoundDigestInternal @(
            'serctl-formal-concurrent-transfer-terminal-v1',
            (Get-SerctlRuntimeAdapterSha256 $primaryCapture.stdout),
            (Get-SerctlRuntimeAdapterSha256 $statusCapture.stdout),
            [string]$binding.operation_context_id, [string]$binding.status_revision,
            [string]$binding.terminal_revision, [string]$binding.status_stage,
            'status_completed_before_primary_terminal:true'
        )
        $receipt = [pscustomobject][ordered]@{
            schema_version = 1; category = [string]$PrimaryConfig.category
            case_id = [string]$PrimaryConfig.case_id
            context_sha256 = [string]$ExpectedContext.context_sha256
            command_sha256 = $commandDigest; terminal_sha256 = $terminalDigest
            result_code = 'completed'; passed = $true
        }
        $receiptBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes(
            (($receipt | ConvertTo-Json -Compress) + "`n")
        )
        $result = [pscustomobject][ordered]@{
            observation = [pscustomobject][ordered]@{
                internal_contract = 'serctl-runtime-adapter-observation-v1'
                category = [string]$PrimaryConfig.category
                case_id = [string]$PrimaryConfig.case_id
                context_sha256 = [string]$ExpectedContext.context_sha256
                command_sha256 = $commandDigest; terminal_sha256 = $terminalDigest
                receipt_bytes = $receiptBytes
            }
            binding = $binding
        }
        $receiptReleased = $true
        return $result
    }
    finally {
        $ready.Dispose()
        if ($null -ne $worker) {
            if ($null -ne $async -and -not $async.IsCompleted) {
                try { $worker.Stop() } catch { }
            }
            $worker.Dispose()
        }
        foreach ($capture in @($primaryCapture, $statusCapture)) {
            if ($null -ne $capture) {
                [Array]::Clear($capture.stdout, 0, $capture.stdout.Length)
                [Array]::Clear($capture.stderr, 0, $capture.stderr.Length)
            }
        }
        foreach ($config in @($PrimaryConfig, $StatusConfig)) {
            if ($null -ne $config -and $config.request_bytes -is [byte[]]) {
                [Array]::Clear($config.request_bytes, 0, $config.request_bytes.Length)
            }
        }
        if ($null -ne $receiptBytes -and -not $receiptReleased) {
            [Array]::Clear($receiptBytes, 0, $receiptBytes.Length)
        }
    }
}

# INTERNAL-ONLY exact four-case interop transfer producer. Paths, transfer id,
# request bytes and helper hash are derived inside the trusted adapter. The
# caller supplies only exact component provenance, expected connection context
# and two distinct already-open purpose-bound Grant handles.
function Invoke-SerctlFormalInteropTransferInternal {
    param(
        $ProtectedInteropConfig,
        $ExactReleaseComponents
    )
    $segments = $null
    $concurrent = $null
    try {
        Assert-SerctlClosedObject $ProtectedInteropConfig @(
            'schema_version', 'category', 'case_id', 'component_paths',
            'expected_context', 'deadline_ms', 'transfer_grant_input_handle',
            'status_grant_input_handle'
        ) 'protected formal interop transfer configuration'
        Assert-SerctlRuntimeAdapter (
            (Test-StrictJsonString $ProtectedInteropConfig.schema_version) -and
            [string]$ProtectedInteropConfig.schema_version -ceq
                'serctl-protected-formal-interop-transfer-config-v1' -and
            (Test-StrictJsonString $ProtectedInteropConfig.category) -and
            (Test-StrictJsonString $ProtectedInteropConfig.case_id) -and
            (Test-StrictJsonInteger $ProtectedInteropConfig.deadline_ms) -and
            [int64]$ProtectedInteropConfig.deadline_ms -ge 1 -and
            [int64]$ProtectedInteropConfig.deadline_ms -le 3600000
        ) 'protected formal interop transfer configuration is incomplete'
        $category = [string]$ProtectedInteropConfig.category
        $caseId = [string]$ProtectedInteropConfig.case_id
        # Resolve the exact case/backend before touching component or runtime
        # inputs. Unsupported operations therefore fail before paths, helper
        # identity, process launch or Grant consumption.
        $case = Get-SerctlFormalInteropTransferCaseInternal $category $caseId
        Assert-SerctlAgentContext $ProtectedInteropConfig.expected_context
        Assert-SerctlFormalComponentSetInternal `
            $ExactReleaseComponents $ProtectedInteropConfig.component_paths
        $handles = @(
            $ProtectedInteropConfig.transfer_grant_input_handle,
            $ProtectedInteropConfig.status_grant_input_handle
        )
        foreach ($handle in $handles) {
            Assert-SerctlRuntimeAdapter (
                $null -ne $handle -and $handle -is [Runtime.InteropServices.SafeHandle] -and
                -not $handle.IsInvalid -and -not $handle.IsClosed
            ) 'formal interop transfer Grant handle is unavailable'
        }
        Assert-SerctlRuntimeAdapter (
            $handles[0].DangerousGetHandle().ToInt64() -ne
                $handles[1].DangerousGetHandle().ToInt64()
        ) 'formal interop transfer requires distinct Grant handles'
        $helperComponent = if ([string]$case.backend -ceq 'native') {
            $ExactReleaseComponents.helper
        }
        else { $null }
        $random = [byte[]]::new(16)
        $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
        try { $rng.GetBytes($random) } finally { $rng.Dispose() }
        try {
            $transferId = ([BitConverter]::ToString($random)).Replace('-', '').ToLowerInvariant()
        }
        finally { [Array]::Clear($random, 0, $random.Length) }
        $deadlineMs = [uint64]$ProtectedInteropConfig.deadline_ms
        $segments = New-SerctlFormalInteropTransferRequestSegmentsInternal `
            $category $caseId $transferId $deadlineMs $helperComponent
        $primaryConfig = [pscustomobject][ordered]@{
            category = $category; case_id = $caseId
            component_paths = $ProtectedInteropConfig.component_paths
            request_bytes = $segments.primary
            grant_input_handle = $handles[0]
            deadline_ms = [int]$deadlineMs
        }
        $statusConfig = [pscustomobject][ordered]@{
            category = $category; case_id = $caseId
            component_paths = $ProtectedInteropConfig.component_paths
            request_bytes = $segments.status
            grant_input_handle = $handles[1]
            deadline_ms = [int][Math]::Min([uint64]30000, $deadlineMs)
        }
        $concurrent = Invoke-SerctlFormalConcurrentTransferInternal `
            $primaryConfig $statusConfig $ExactReleaseComponents $transferId `
            $ProtectedInteropConfig.expected_context ([string]$case.backend)
        return $concurrent.observation
    }
    finally {
        if ($null -ne $segments) {
            foreach ($bytes in @($segments.primary, $segments.status)) {
                if ($null -ne $bytes) { [Array]::Clear($bytes, 0, $bytes.Length) }
            }
        }
    }
}

function Invoke-SerctlFormalRuntimeAdapter {
    param(
        [string]$Category,
        [string]$CaseId,
        $ProtectedFormalConfig,
        $ExactReleaseComponents
    )
    [void](Get-SerctlRuntimeAdapterRecipe $Category $CaseId)
    if ($null -ne $ProtectedFormalConfig -and $null -ne $ExactReleaseComponents) {
        return Invoke-SerctlFormalRuntimeProcessSkeletonInternal `
            -ProtectedFormalConfig $ProtectedFormalConfig `
            -ExactReleaseComponents $ExactReleaseComponents
    }
    throw (
        "serctl external runtime adapter failed: runtime case '$CaseId' remains BLOCKED; " +
        ($script:SerctlRuntimeAdapterBlockers -join '; ')
    )
}

function Invoke-SerctlSyntheticRuntimeAdapterProbe {
    param(
        [string]$ApplicationPath, [string]$Category, [string]$CaseId,
        [ValidateSet('success', 'wrong-hash', 'deadline', 'process-tree-deadline', 'stdout-flood')]
        [string]$Scenario,
        [AllowEmptyCollection()][byte[]]$StandardInputBytes,
        $ExpectedContext
    )
    $arguments = switch ($Scenario) {
        'success' { @('success') }; 'wrong-hash' { @('wrong-hash') }
        'deadline' { @('hang') }; 'process-tree-deadline' { @('spawn-child-hang') }
        'stdout-flood' { @('flood') }
    }
    $deadline = if ($Scenario -in @('deadline', 'process-tree-deadline')) { 100 } else { 2000 }
    $stdoutLimit = if ($Scenario -eq 'stdout-flood') { 128 } else { 16777216 }
    $capture = $null
    try {
        $capture = Invoke-ExternalRuntimeProcessCaptureInternal `
            -ApplicationPath $ApplicationPath `
            -ArgumentList $arguments `
            -DeadlineMilliseconds $deadline `
            -StdoutLimitBytes $stdoutLimit `
            -StderrLimitBytes 1024 `
            -StandardInputBytes $StandardInputBytes `
            -StdinLimitBytes 1048576 `
            -ForbiddenCanary $script:SerctlSensitiveCanaries `
            -EnvironmentVariables ([ordered]@{ NO_COLOR = '1'; TERM = 'dumb'; TZ = 'UTC' })
        Assert-SerctlRuntimeAdapter (
            $capture.exit_category -ceq 'completed_success' -and
            [bool]$capture.process_tree_exited
        ) (
            "synthetic controlled process did not produce a successful transcript ($($capture.exit_category))"
        )
        return ConvertFrom-SerctlAgentTranscript `
            -Bytes $capture.stdout `
            -Category $Category `
            -CaseId $CaseId `
            -ExpectedContext $ExpectedContext
    }
    finally {
        if ($null -ne $capture) {
            [Array]::Clear($capture.stdout, 0, $capture.stdout.Length)
            [Array]::Clear($capture.stderr, 0, $capture.stderr.Length)
        }
    }
}
