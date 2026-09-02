[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][long]$DownloadedSetRecordHandleRaw,
    [Parameter(Mandatory = $true)][long]$WindowsCliHandleRaw,
    [Parameter(Mandatory = $true)][long]$WindowsDaemonHandleRaw,
    [Parameter(Mandatory = $true)][long]$LinuxHelperHandleRaw,
    [Parameter(Mandatory = $true)][long]$ReceiptOutputHandleRaw,
    [Parameter(Mandatory = $true)][long]$OpenSshExecGrantHandleRaw,
    [Parameter(Mandatory = $true)][long]$DropbearExecGrantHandleRaw,
    [Parameter(Mandatory = $true)][long]$OpenSshDirectoryGrantHandleRaw,
    [Parameter(Mandatory = $true)][long]$OpenSshTunnelLocalOpenGrantHandleRaw,
    [Parameter(Mandatory = $true)][long]$OpenSshTunnelLocalStatusGrantHandleRaw,
    [Parameter(Mandatory = $true)][long]$OpenSshTunnelLocalCancelGrantHandleRaw,
    [Parameter(Mandatory = $true)][long]$OpenSshTunnelRemoteOpenGrantHandleRaw,
    [Parameter(Mandatory = $true)][long]$OpenSshTunnelRemoteStatusGrantHandleRaw,
    [Parameter(Mandatory = $true)][long]$OpenSshTunnelRemoteCancelGrantHandleRaw,
    [Parameter(Mandatory = $true)][long]$OpenSshTunnelDynamicOpenGrantHandleRaw,
    [Parameter(Mandatory = $true)][long]$OpenSshTunnelDynamicStatusGrantHandleRaw,
    [Parameter(Mandatory = $true)][long]$OpenSshTunnelDynamicCancelGrantHandleRaw,
    [Parameter(Mandatory = $true)][long]$OpenSshSftpTransferGrantHandleRaw,
    [Parameter(Mandatory = $true)][long]$OpenSshSftpStatusGrantHandleRaw,
    [Parameter(Mandatory = $true)][long]$OpenSshNativeTransferGrantHandleRaw,
    [Parameter(Mandatory = $true)][long]$OpenSshNativeStatusGrantHandleRaw,
    [Parameter(Mandatory = $true)][long]$DropbearSftpTransferGrantHandleRaw,
    [Parameter(Mandatory = $true)][long]$DropbearSftpStatusGrantHandleRaw,
    [Parameter(Mandatory = $true)][long]$DropbearNativeTransferGrantHandleRaw,
    [Parameter(Mandatory = $true)][long]$DropbearNativeStatusGrantHandleRaw
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

# This is a process entry point, not a module API. Its only formal case set is
# fixed here. The calling process cannot supply requests, results, expected
# output, child receipts, pass bits, or a mutable ledger.
$scriptRoot = Split-Path -Parent $PSCommandPath
foreach ($dependency in @(
    'StrictJson.ps1', 'ExternalRuntimeProcessSupervisor.ps1',
    'ExternalTransferRuntimeAdapter.ps1', 'ExternalTransferRuntimeReceiptContract.ps1',
    'ExternalTransferOfficialComponentAnchor.ps1'
)) {
    try { . (Join-Path $scriptRoot $dependency) }
    catch {
        throw "isolated owner dependency '$dependency' failed in $($ExecutionContext.SessionState.LanguageMode) mode: $($_.Exception.Message)"
    }
}

function Assert-IsolatedOwner {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) {
        throw "isolated external transfer formal owner failed: $Message"
    }
}

function Read-IsolatedOwnerStandardInput {
    param([ValidateRange(1, 1048576)][int]$MaximumBytes = 1048576)
    $inputStream = [Console]::OpenStandardInput()
    $buffer = [byte[]]::new(8192)
    $memory = [IO.MemoryStream]::new()
    try {
        while ($true) {
            $read = $inputStream.Read($buffer, 0, $buffer.Length)
            if ($read -eq 0) { break }
            Assert-IsolatedOwner ($memory.Length + $read -le $MaximumBytes) (
                'protected configuration exceeds its byte bound'
            )
            $memory.Write($buffer, 0, $read)
        }
        return ,$memory.ToArray()
    }
    finally {
        [Array]::Clear($buffer, 0, $buffer.Length)
        $memory.Dispose()
    }
}

function ConvertFrom-IsolatedOwnerBase64 {
    param([string]$Value, [string]$Label)
    Assert-IsolatedOwner (
        -not [string]::IsNullOrWhiteSpace($Value) -and $Value.Length -le 349528 -and
        $Value -cmatch '^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$'
    ) "$Label is not bounded canonical Base64"
    try { $bytes = [Convert]::FromBase64String($Value) }
    catch { throw "isolated external transfer formal owner failed: $Label is invalid" }
    Assert-IsolatedOwner (
        $bytes.Length -gt 0 -and $bytes.Length -le 262144 -and
        [Convert]::ToBase64String($bytes) -ceq $Value
    ) "$Label is not canonical"
    return ,$bytes
}

function New-IsolatedOwnerCapturedReceiptRecord {
    param([byte[]]$Bytes, [string]$CaseId)
    Assert-IsolatedOwner (
        $null -ne $Bytes -and $Bytes.Length -gt 0 -and $Bytes.Length -le 1048576
    ) "captured child receipt '$CaseId' is outside its byte bound"
    try { $text = [Text.UTF8Encoding]::new($false, $true).GetString($Bytes) }
    catch { throw "isolated external transfer formal owner failed: child receipt '$CaseId' is not strict UTF-8" }
    Assert-IsolatedOwner (
        $text.EndsWith("`n") -and -not $text.Contains("`r") -and
        -not (Test-SerctlContainsSensitiveCanary $text)
    ) "captured child receipt '$CaseId' is not one canonical safe JSON line"
    $receipt = ConvertFrom-StrictJson `
        $text.Substring(0, $text.Length - 1) "captured child receipt '$CaseId'"
    Assert-SerctlClosedObject $receipt @(
        'schema_version', 'category', 'case_id', 'context_sha256',
        'command_sha256', 'terminal_sha256', 'result_code', 'passed'
    ) "captured child receipt '$CaseId'"
    Assert-IsolatedOwner (
        (Test-StrictJsonInteger $receipt.schema_version) -and
        [int]$receipt.schema_version -eq 1 -and
        (Test-StrictJsonString $receipt.case_id) -and
        [string]$receipt.case_id -ceq $CaseId -and
        $receipt.passed -is [bool] -and [bool]$receipt.passed -and
        (Test-StrictJsonString $receipt.result_code) -and
        [string]$receipt.result_code -ceq 'completed'
    ) "captured child receipt '$CaseId' is not a successful fixed-case terminal"
    return [pscustomobject][ordered]@{
        case_id = $CaseId
        operation_context_sha256 = [string]$receipt.context_sha256
        receipt_base64 = [Convert]::ToBase64String($Bytes)
        receipt_sha256 = Get-SerctlRuntimeAdapterSha256 $Bytes
    }
}

function Get-IsolatedOwnerStreamSha256 {
    param([IO.FileStream]$Stream)
    $position = $Stream.Position
    $sha = [Security.Cryptography.SHA256]::Create()
    try {
        $Stream.Position = 0
        return ([BitConverter]::ToString($sha.ComputeHash($Stream))).Replace('-', '')
    }
    finally {
        $sha.Dispose()
        $Stream.Position = $position
    }
}

function Invoke-IsolatedOwnerInteropTransfer {
    param($Config, $Components, $ComponentPaths, $Payload, [string]$CaseId, $TransferHandle, $StatusHandle)
    $backend = if ($CaseId.EndsWith('_native', [StringComparison]::Ordinal)) {
        'native'
    } else { 'sftp' }
    $transferId = [Guid]::NewGuid().ToString('N')
    $remotePath = '/tmp/serctl-v1-beta-' + $CaseId.ToLowerInvariant() + '-' +
        [Guid]::NewGuid().ToString('N') + '-target-21.bin'
    $request = [ordered]@{
        schema_version = 1; request_id = [uint64]2; op = 'transfer-push'
        transfer_id = $transferId; local = [string]$Payload.path; remote = $remotePath
        backend = $backend; resume = 'never'; idle_timeout_ms = [uint64]30000
        deadline_ms = [uint64]$Config.deadline_ms
    }
    if ($backend -ceq 'native') {
        $request['expected_helper_identity'] = [pscustomobject][ordered]@{
            name = [string]$Components.helper.name
            binary_size = [long]$Components.helper.binary_size
            sha256 = ([string]$Components.helper.sha256).ToLowerInvariant()
            version = [string]$Components.helper.version
        }
        Assert-SerctlFormalExpectedHelperIdentityInternal `
            $request.expected_helper_identity $Components.helper
    }
    $primaryBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes((@(
        ([pscustomobject][ordered]@{
            schema_version = 1; request_id = [uint64]1; op = 'ssh-connection-identity'
        } | ConvertTo-Json -Compress),
        ([pscustomobject]$request | ConvertTo-Json -Compress -Depth 8)
    ) -join "`n") + "`n")
    $statusBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes((
        [pscustomobject][ordered]@{
            schema_version = 1; request_id = [uint64]3
            op = 'transfer-status'; transfer_id = $transferId
        } | ConvertTo-Json -Compress
    ) + "`n")
    $result = $null
    try {
        $primary = [pscustomobject][ordered]@{
            category = 'openssh_dropbear_interop'; case_id = $CaseId
            component_paths = $ComponentPaths; request_bytes = $primaryBytes
            grant_input_handle = $TransferHandle; deadline_ms = [int]$Config.deadline_ms
        }
        $status = [pscustomobject][ordered]@{
            category = 'openssh_dropbear_interop'; case_id = $CaseId
            component_paths = $ComponentPaths; request_bytes = $statusBytes
            grant_input_handle = $StatusHandle
            deadline_ms = [int][Math]::Min([uint64]30000, [uint64]$Config.deadline_ms)
        }
        $result = Invoke-SerctlFormalConcurrentTransferInternal `
            $primary $status $Components $transferId $Config.expected_contexts.$CaseId $backend
        Assert-IsolatedOwner (
            [uint64]$result.binding.total_bytes -eq [uint64]$Payload.size -and
            (Get-IsolatedOwnerStreamSha256 $Payload.stream) -ceq [string]$Payload.sha256
        ) "fixed payload binding changed during '$CaseId'"
        return $result.observation
    }
    finally {
        [Array]::Clear($primaryBytes, 0, $primaryBytes.Length)
        [Array]::Clear($statusBytes, 0, $statusBytes.Length)
    }
}

$configBytes = $null
$windowsProvenance = $null
$linuxProvenance = $null
$ownerReceiptBytes = $null
$componentSetBytes = $null
$payloadBytes = $null
$payloadStream = $null
$payloadScratchPath = $null
$payloadPath = $null
$grantHandles = [Collections.Generic.List[Microsoft.Win32.SafeHandles.SafeFileHandle]]::new()
$officialHandles = [Collections.Generic.List[Microsoft.Win32.SafeHandles.SafeFileHandle]]::new()
$componentPinStreams = [Collections.Generic.List[IO.FileStream]]::new()
try {
    $rawOfficialHandles=@($DownloadedSetRecordHandleRaw,$WindowsCliHandleRaw,$WindowsDaemonHandleRaw,$LinuxHelperHandleRaw,$ReceiptOutputHandleRaw)
    $rawGrantHandles = @(
        $OpenSshExecGrantHandleRaw,
        $DropbearExecGrantHandleRaw,
        $OpenSshDirectoryGrantHandleRaw,
        $OpenSshTunnelLocalOpenGrantHandleRaw,
        $OpenSshTunnelLocalStatusGrantHandleRaw,
        $OpenSshTunnelLocalCancelGrantHandleRaw,
        $OpenSshTunnelRemoteOpenGrantHandleRaw,
        $OpenSshTunnelRemoteStatusGrantHandleRaw,
        $OpenSshTunnelRemoteCancelGrantHandleRaw,
        $OpenSshTunnelDynamicOpenGrantHandleRaw,
        $OpenSshTunnelDynamicStatusGrantHandleRaw,
        $OpenSshTunnelDynamicCancelGrantHandleRaw,
        $OpenSshSftpTransferGrantHandleRaw,
        $OpenSshSftpStatusGrantHandleRaw,
        $OpenSshNativeTransferGrantHandleRaw,
        $OpenSshNativeStatusGrantHandleRaw,
        $DropbearSftpTransferGrantHandleRaw,
        $DropbearSftpStatusGrantHandleRaw,
        $DropbearNativeTransferGrantHandleRaw,
        $DropbearNativeStatusGrantHandleRaw
    )
    Assert-IsolatedOwner (
        @($rawOfficialHandles+$rawGrantHandles | Where-Object { $_ -le 0 }).Count -eq 0 -and
        @($rawOfficialHandles+$rawGrantHandles | Select-Object -Unique).Count -eq 25
    ) 'twenty-five distinct purpose handles are required'
    $configBytes = Read-IsolatedOwnerStandardInput
    try { $configText = [Text.UTF8Encoding]::new($false, $true).GetString($configBytes) }
    catch { throw 'isolated external transfer formal owner failed: configuration is not strict UTF-8' }
    Assert-IsolatedOwner (
        $configText.EndsWith("`n") -and -not $configText.Contains("`r") -and
        -not (Test-SerctlContainsSensitiveCanary $configText)
    ) 'configuration is not one canonical safe JSON line'
    $config = ConvertFrom-StrictJson `
        -Json $configText.Substring(0, $configText.Length - 1) `
        -Label 'isolated formal owner configuration'
    Assert-SerctlClosedObject $config @(
        'schema_version', 'owner_contract','expected_contexts',
        'evidence_context_sha256', 'deadline_ms'
    ) 'isolated formal owner configuration'
    Assert-IsolatedOwner (
        (Test-StrictJsonInteger $config.schema_version) -and
        [int]$config.schema_version -eq 1 -and
        (Test-StrictJsonString $config.owner_contract) -and
        [string]$config.owner_contract -ceq 'serctl-isolated-formal-owner-input-v1' -and
        (Test-StrictJsonObject $config.expected_contexts) -and
        (Test-StrictJsonString $config.evidence_context_sha256) -and
        [string]$config.evidence_context_sha256 -cmatch '^[0-9A-F]{64}$' -and
        (Test-StrictJsonInteger $config.deadline_ms) -and
        [uint64]$config.deadline_ms -ge 1 -and [uint64]$config.deadline_ms -le 3600000
    ) 'configuration identity or deadline is invalid'
    Assert-SerctlClosedObject $config.expected_contexts @(
        'OpenSSH_exec', 'Dropbear_exec', 'OpenSSH_directory',
        'OpenSSH_tunnel_local', 'OpenSSH_tunnel_remote', 'OpenSSH_tunnel_dynamic',
        'OpenSSH_sftp', 'OpenSSH_native', 'Dropbear_sftp', 'Dropbear_native'
    ) 'isolated formal owner expected contexts'
    foreach ($caseId in @(
        'OpenSSH_exec', 'Dropbear_exec', 'OpenSSH_directory',
        'OpenSSH_tunnel_local', 'OpenSSH_tunnel_remote', 'OpenSSH_tunnel_dynamic',
        'OpenSSH_sftp', 'OpenSSH_native', 'Dropbear_sftp', 'Dropbear_native'
    )) {
        Assert-IsolatedOwner (Test-StrictJsonObject $config.expected_contexts.$caseId) (
            "expected context for '$caseId' is not an object"
        )
        Assert-SerctlAgentContext $config.expected_contexts.$caseId
    }
    foreach($raw in $rawOfficialHandles){$h=[Microsoft.Win32.SafeHandles.SafeFileHandle]::new([IntPtr]$raw,$false);[void]$officialHandles.Add($h)}
    $binding=Get-ExternalTransferOfficialComponentBindingInternal $officialHandles[0] $officialHandles[1] $officialHandles[2] $officialHandles[3]
    $components=$binding.components;$componentPaths=$binding.component_paths
    foreach($key in @('cli','daemon','helper')){
        $pin=[IO.File]::Open([string]$componentPaths.$key,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
        Assert-IsolatedOwner ([Serctl.OfficialAnchor.Native]::Identity($pin.SafeFileHandle)-ceq [string]$binding.component_identities.$key) "component '$key' path identity changed"
        [void]$componentPinStreams.Add($pin)
    }
    Assert-SerctlFormalComponentSetInternal $components $componentPaths
    $canonicalComponents = [pscustomobject][ordered]@{
        cli = $components.cli; daemon = $components.daemon; helper = $components.helper
    }
    $componentSetBytes=[Convert]::FromBase64String([string]$binding.anchor.component_set_base64)
    $componentSetSha256 = Get-SerctlRuntimeAdapterSha256 $componentSetBytes

    Assert-IsolatedOwner ([Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [Runtime.InteropServices.OSPlatform]::Windows
    )) 'fixed payload owner is not proven on this platform'
    $payloadScratchPath = Join-Path ([IO.Path]::GetTempPath()) (
        'serctl-isolated-owner-payload-' + [Guid]::NewGuid().ToString('N')
    )
    [IO.Directory]::CreateDirectory($payloadScratchPath) | Out-Null
    $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $directoryAcl = [Security.AccessControl.DirectorySecurity]::new()
    $directoryAcl.SetOwner($currentSid)
    $directoryAcl.SetAccessRuleProtection($true, $false)
    [void]$directoryAcl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new(
        $currentSid, [Security.AccessControl.FileSystemRights]::FullControl,
        [Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
            [Security.AccessControl.InheritanceFlags]::ObjectInherit,
        [Security.AccessControl.PropagationFlags]::None,
        [Security.AccessControl.AccessControlType]::Allow
    ))
    Set-Acl -LiteralPath $payloadScratchPath -AclObject $directoryAcl -ErrorAction Stop
    $payloadPath = Join-Path $payloadScratchPath 'source-21.bin'
    $payloadBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes("serctl-fixed-payload`n")
    Assert-IsolatedOwner ($payloadBytes.Length -eq 21) 'fixed payload recipe changed'
    $payloadWriter = [IO.FileStream]::new(
        $payloadPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::ReadWrite,
        [IO.FileShare]::None, 4096, [IO.FileOptions]::WriteThrough
    )
    try {
        $payloadWriter.Write($payloadBytes, 0, $payloadBytes.Length)
        $payloadWriter.Flush($true)
    }
    finally { $payloadWriter.Dispose() }
    # The long-lived read handle permits child reads but denies every writer
    # and delete/rename attempt until all four transfer cases are complete.
    $payloadStream = [IO.FileStream]::new(
        $payloadPath, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        [IO.FileShare]::Read, 4096, [IO.FileOptions]::SequentialScan
    )
    $payload = [pscustomobject][ordered]@{
        path = $payloadPath; stream = $payloadStream; size = [uint64]$payloadStream.Length
        sha256 = Get-IsolatedOwnerStreamSha256 $payloadStream
    }

    foreach ($raw in $rawGrantHandles) {
        $handle = [Microsoft.Win32.SafeHandles.SafeFileHandle]::new([IntPtr]$raw, $false)
        Assert-IsolatedOwner (-not $handle.IsInvalid -and -not $handle.IsClosed) (
            'Grant handle is unavailable'
        )
        [void]$grantHandles.Add($handle)
    }
    $fixedCaseIds = @(
        'OpenSSH_exec', 'OpenSSH_directory',
        'OpenSSH_tunnel_local', 'OpenSSH_tunnel_remote', 'OpenSSH_tunnel_dynamic',
        'OpenSSH_sftp', 'OpenSSH_native', 'Dropbear_exec',
        'Dropbear_sftp', 'Dropbear_native'
    )
    $caseReceipts = [Collections.Generic.List[object]]::new()
    $contextBindings = [Collections.Generic.List[object]]::new()
    $seenReceiptDigests = [Collections.Generic.HashSet[string]]::new(
        [StringComparer]::Ordinal
    )
    foreach ($runtimeCase in @(
        @('OpenSSH_exec', 0), @('Dropbear_exec', 1), @('OpenSSH_directory', 2)
    )) {
        $caseId = [string]$runtimeCase[0]
        $index = [int]$runtimeCase[1]
        $requestBytes = $null
        $childReceiptBytes = $null
        try {
            $requestBytes = New-SerctlFormalRuntimeRequestBytesInternal `
                'openssh_dropbear_interop' $caseId
            $protectedConfig = [pscustomobject][ordered]@{
                schema_version = 'serctl-protected-formal-runtime-config-v1'
                category = 'openssh_dropbear_interop'
                case_id = $caseId
                component_paths = $componentPaths
                request_bytes = $requestBytes
                expected_context = $config.expected_contexts.$caseId
                deadline_ms = [int]$config.deadline_ms
                grant_input_handle = $grantHandles[$index]
            }
            $observation = Invoke-SerctlFormalRuntimeProcessSkeletonInternal `
                $protectedConfig $components
            Assert-IsolatedOwner (
                [string]$observation.internal_contract -ceq
                    'serctl-runtime-adapter-observation-v1' -and
                [string]$observation.category -ceq 'openssh_dropbear_interop' -and
                [string]$observation.case_id -ceq $caseId -and
                [string]$observation.context_sha256 -ceq
                    [string]$config.expected_contexts.$caseId.context_sha256 -and
                $observation.receipt_bytes -is [byte[]]
            ) "actual child capture did not produce fixed case '$caseId'"
            $childReceiptBytes = [byte[]]$observation.receipt_bytes
            $childReceiptRecord = New-IsolatedOwnerCapturedReceiptRecord `
                $childReceiptBytes $caseId
            Assert-IsolatedOwner ($seenReceiptDigests.Add($childReceiptRecord.receipt_sha256)) (
                'fixed cases produced a reused child receipt digest'
            )
            [void]$caseReceipts.Add($childReceiptRecord)
            [void]$contextBindings.Add([pscustomobject][ordered]@{
                case_id = $caseId
                context_sha256 = [string]$config.expected_contexts.$caseId.context_sha256
            })
        }
        finally {
            if ($null -ne $requestBytes) {
                [Array]::Clear($requestBytes, 0, $requestBytes.Length)
            }
            if ($null -ne $childReceiptBytes) {
                [Array]::Clear($childReceiptBytes, 0, $childReceiptBytes.Length)
            }
        }
    }
    $tunnelCases = @(
        @('OpenSSH_tunnel_local', 3, 4, 5),
        @('OpenSSH_tunnel_remote', 6, 7, 8),
        @('OpenSSH_tunnel_dynamic', 9, 10, 11)
    )
    foreach ($tunnelCase in $tunnelCases) {
        $caseId = [string]$tunnelCase[0]
        $childReceiptBytes = $null
        try {
            $protectedTunnelConfig = [pscustomobject][ordered]@{
                schema_version = 'serctl-protected-formal-managed-tunnel-config-v1'
                category = 'openssh_dropbear_interop'
                case_id = $caseId
                component_paths = $componentPaths
                expected_context = $config.expected_contexts.$caseId
                deadline_ms = [int]$config.deadline_ms
                open_grant_input_handle = $grantHandles[[int]$tunnelCase[1]]
                status_grant_input_handle = $grantHandles[[int]$tunnelCase[2]]
                cancel_grant_input_handle = $grantHandles[[int]$tunnelCase[3]]
            }
            $observation = Invoke-SerctlFormalManagedTunnelInternal `
                $protectedTunnelConfig $components
            Assert-IsolatedOwner (
                [string]$observation.internal_contract -ceq
                    'serctl-runtime-adapter-observation-v1' -and
                [string]$observation.category -ceq 'openssh_dropbear_interop' -and
                [string]$observation.case_id -ceq $caseId -and
                [string]$observation.context_sha256 -ceq
                    [string]$config.expected_contexts.$caseId.context_sha256 -and
                $observation.receipt_bytes -is [byte[]]
            ) "actual managed tunnel capture did not produce fixed case '$caseId'"
            $childReceiptBytes = [byte[]]$observation.receipt_bytes
            $childReceiptRecord = New-IsolatedOwnerCapturedReceiptRecord `
                $childReceiptBytes $caseId
            Assert-IsolatedOwner ($seenReceiptDigests.Add($childReceiptRecord.receipt_sha256)) (
                'fixed cases produced a reused child receipt digest'
            )
            [void]$caseReceipts.Add($childReceiptRecord)
            [void]$contextBindings.Add([pscustomobject][ordered]@{
                case_id = $caseId
                context_sha256 = [string]$config.expected_contexts.$caseId.context_sha256
            })
        }
        finally {
            if ($null -ne $childReceiptBytes) {
                [Array]::Clear($childReceiptBytes, 0, $childReceiptBytes.Length)
            }
        }
    }
    $transferCases = @(
        @('OpenSSH_sftp', 12, 13),
        @('OpenSSH_native', 14, 15),
        @('Dropbear_sftp', 16, 17),
        @('Dropbear_native', 18, 19)
    )
    foreach ($transferCase in $transferCases) {
        $caseId = [string]$transferCase[0]
        $childReceiptBytes = $null
        try {
            $protectedInteropConfig = [pscustomobject][ordered]@{
                schema_version = 'serctl-protected-formal-interop-transfer-config-v1'
                category = 'openssh_dropbear_interop'
                case_id = $caseId
                component_paths = $componentPaths
                expected_context = $config.expected_contexts.$caseId
                deadline_ms = [int]$config.deadline_ms
                transfer_grant_input_handle = $grantHandles[[int]$transferCase[1]]
                status_grant_input_handle = $grantHandles[[int]$transferCase[2]]
            }
            $observation = Invoke-IsolatedOwnerInteropTransfer `
                $config $components $componentPaths $payload $caseId `
                $protectedInteropConfig.transfer_grant_input_handle `
                $protectedInteropConfig.status_grant_input_handle
            Assert-IsolatedOwner (
                [string]$observation.internal_contract -ceq
                    'serctl-runtime-adapter-observation-v1' -and
                [string]$observation.category -ceq 'openssh_dropbear_interop' -and
                [string]$observation.case_id -ceq $caseId -and
                [string]$observation.context_sha256 -ceq
                    [string]$config.expected_contexts.$caseId.context_sha256 -and
                $observation.receipt_bytes -is [byte[]]
            ) "actual concurrent transfer capture did not produce fixed case '$caseId'"
            $childReceiptBytes = [byte[]]$observation.receipt_bytes
            $childReceiptRecord = New-IsolatedOwnerCapturedReceiptRecord `
                $childReceiptBytes $caseId
            Assert-IsolatedOwner ($seenReceiptDigests.Add($childReceiptRecord.receipt_sha256)) (
                'fixed cases produced a reused child receipt digest'
            )
            [void]$caseReceipts.Add($childReceiptRecord)
            [void]$contextBindings.Add([pscustomobject][ordered]@{
                case_id = $caseId
                context_sha256 = [string]$config.expected_contexts.$caseId.context_sha256
            })
        }
        finally {
            if ($null -ne $childReceiptBytes) {
                [Array]::Clear($childReceiptBytes, 0, $childReceiptBytes.Length)
            }
        }
    }
    Assert-IsolatedOwner (
        $caseReceipts.Count -eq $fixedCaseIds.Count -and
        $contextBindings.Count -eq $fixedCaseIds.Count
    ) 'fixed case state machine is incomplete'
    $orderedCaseReceipts = @($fixedCaseIds | ForEach-Object {
        $wanted = $_
        $matches = @($caseReceipts | Where-Object { $_.case_id -ceq $wanted })
        Assert-IsolatedOwner ($matches.Count -eq 1) "case receipt '$wanted' is not unique"
        $matches[0]
    })
    $orderedContextBindings = @($fixedCaseIds | ForEach-Object {
        $wanted = $_
        $matches = @($contextBindings | Where-Object { $_.case_id -ceq $wanted })
        Assert-IsolatedOwner ($matches.Count -eq 1) "context binding '$wanted' is not unique"
        $matches[0]
    })
    Assert-SerctlFormalComponentSetInternal $components $componentPaths
    Assert-IsolatedOwner (
        $payloadStream.Length -eq [uint64]$payload.size -and
        (Get-IsolatedOwnerStreamSha256 $payloadStream) -ceq [string]$payload.sha256
    ) 'fixed payload changed before owner completion'
    $payloadStream.Dispose()
    $payloadStream = $null
    [IO.File]::Delete($payloadPath)
    [IO.Directory]::Delete($payloadScratchPath, $false)
    $payloadPath = $null
    $payloadScratchPath = $null
    # Complete is reachable only after every member of this fixed vertical
    # slice set has an actual child receipt. This sealed owner receipt is
    # deliberately not a full release-category receipt.
    $ownerReceipt = [pscustomobject][ordered]@{
        schema_version = 2
        owner_contract = 'serctl-isolated-formal-owner-receipt-v2'
        category = 'openssh_dropbear_interop'
        evidence_context_sha256 = [string]$config.evidence_context_sha256
        component_set_sha256 = $componentSetSha256
        component_set_base64 = [Convert]::ToBase64String($componentSetBytes)
        case_receipts = $orderedCaseReceipts
    }
    try {
        $ownerReceiptBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes(
            (($ownerReceipt | ConvertTo-Json -Compress -Depth 8) + "`n")
        )
        Assert-IsolatedOwner ($ownerReceiptBytes.Length -le 1048576) (
            'owner receipt exceeds its byte bound'
        )
        # The isolated owner performs the create-new protected write itself.
        # No caller-supplied receipt or mutable ledger enters this process.
        Write-ExternalTransferOfficialReceiptHandleInternal $officialHandles[4] $ownerReceiptBytes
    }
    finally { }
}
finally {
    foreach ($bytes in @(
        $configBytes, $windowsProvenance, $linuxProvenance, $ownerReceiptBytes,
        $componentSetBytes
    )) {
        if ($null -ne $bytes -and $bytes -is [byte[]]) {
            [Array]::Clear($bytes, 0, $bytes.Length)
        }
    }
    foreach ($grantHandle in $grantHandles) { $grantHandle.Dispose() }
    foreach ($handle in $officialHandles) { $handle.Dispose() }
    foreach ($stream in $componentPinStreams) { $stream.Dispose() }
    if ($null -ne $payloadStream) { $payloadStream.Dispose() }
    if ($null -ne $payloadPath -and (Test-Path -LiteralPath $payloadPath -PathType Leaf)) {
        try { [IO.File]::Delete($payloadPath) } catch { }
    }
    if ($null -ne $payloadScratchPath -and
        (Test-Path -LiteralPath $payloadScratchPath -PathType Container)) {
        try { [IO.Directory]::Delete($payloadScratchPath, $false) } catch { }
    }
    if ($null -ne $payloadBytes) { [Array]::Clear($payloadBytes, 0, $payloadBytes.Length) }
}
