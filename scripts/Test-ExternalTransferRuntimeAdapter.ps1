[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-AdapterTest {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "external transfer runtime adapter self-test failed: $Message" }
}

function Assert-AdapterRejected {
    param([scriptblock]$Action, [string]$Description)
    $rejected = $false
    try { & $Action *> $null }
    catch { $rejected = $true }
    Assert-AdapterTest $rejected "$Description was accepted"
}

function ConvertTo-NdjsonBytes {
    param([object[]]$Values)
    $text = (($Values | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 16 }) -join "`n") + "`n"
    return [Text.UTF8Encoding]::new($false, $true).GetBytes($text)
}

function New-AgentSuccess {
    param([uint64]$RequestId, $Data)
    return [ordered]@{ schema_version = 1; request_id = $RequestId; ok = $true; data = $Data }
}

function New-SyntheticCapture {
    param([byte[]]$Stdout)
    return [pscustomobject][ordered]@{
        exit_category = 'completed_success'; exit_code = 0; process_tree_exited = $true
        stdout = $Stdout; stderr = [byte[]]::new(0); elapsed_ms = [uint64]1
    }
}

$adapterPath = Join-Path $PSScriptRoot 'ExternalTransferRuntimeAdapter.ps1'
$contractPath = Join-Path $PSScriptRoot 'ExternalTransferRuntimeReceiptContract.ps1'
foreach ($path in @($adapterPath, $contractPath)) {
    $tokens = $null
    $errors = $null
    [void][Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
    Assert-AdapterTest (@($errors).Count -eq 0) "$path does not parse"
}

$adapterSource = Get-Content -LiteralPath $adapterPath -Raw -Encoding utf8
foreach ($marker in @(
    '$script:SerctlRuntimeAdapterRecipes', "'ssh-connection-identity'", "'exec'", "'list-dir'",
    "'forward-local-open'", "'forward-status'", "'forward-cancel'", "'transfer-push'",
    "'transfer-status'", "'transfer-cancel'", "'transfer-pull'",
    'operation_context_id', 'revision',
    'PowerShell module-private functions and state are not a trust boundary',
    'Invoke-ExternalRuntimeProcessCaptureInternal', 'ConvertFrom-StrictJson',
    'Invoke-SerctlFormalRuntimeProcessSkeletonInternal',
    'parser_outcome', 'synthetic_only', 'sealable = $false'
)) { Assert-AdapterTest $adapterSource.Contains($marker) "adapter omits '$marker'" }
foreach ($forbidden in @(
    '[bool]$Passed', '$StructuredResult', '$ResultJson', '$Details',
    'Invoke-Expression', 'Start-Process', 'SERCTL_PROFILE_PASSPHRASE='
)) {
    Assert-AdapterTest (-not $adapterSource.Contains($forbidden)) (
        "adapter exposes forbidden evidence or execution input '$forbidden'"
    )
}

Get-Module 'Serctl.ExternalTransferRuntimeReceiptContract' -All |
    Remove-Module -Force -ErrorAction Stop
. $contractPath
$contractModules = @(Get-Module 'Serctl.ExternalTransferRuntimeReceiptContract' -All)
Assert-AdapterTest ($contractModules.Count -eq 1) 'contract module load is ambiguous'
$contractModule = $contractModules[0]
$invokeCommand = Get-Command Invoke-ExternalTransferRuntimeCase
$invokeParameters = @(
    $invokeCommand.Parameters.Keys |
        Where-Object { $_ -notin [Management.Automation.Cmdlet]::CommonParameters }
)
Assert-AdapterTest (
    @($invokeParameters | Where-Object { $_ -notin @('Ledger', 'CaseId') }).Count -eq 0
) 'formal invocation exposes executable, result, secret, or receipt injection'
$ownerCommand = Get-Command Invoke-ExternalTransferFormalOwnerCase
foreach ($ownerEntry in @(
    $ownerCommand,
    (Get-Command Invoke-ExternalTransferFormalOwnerConcurrentTransferCase)
)) {
    foreach ($forbiddenParameter in @(
        'Passed', 'Result', 'StructuredResult', 'ResultJson', 'Receipt', 'ReceiptBytes',
        'ExpectedStdout', 'ExpectedTranscript', 'Executable', 'ArgumentList', 'GrantPath'
    )) {
        Assert-AdapterTest (-not $ownerEntry.Parameters.ContainsKey($forbiddenParameter)) (
            "formal owner exposes forbidden parameter '$forbiddenParameter'"
        )
    }
}

$fixtureRoot = Join-Path (
    Join-Path ([IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))) 'target'
) ('external-transfer-adapter-selftest-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($fixtureRoot) | Out-Null
$ownerToken = [Guid]::NewGuid().ToString('N')
$ownerPath = Join-Path $fixtureRoot '.owner'
[IO.File]::WriteAllText($ownerPath, $ownerToken, [Text.UTF8Encoding]::new($false))

$profileId = '0123456789abcdef0123456789abcdef'
$hostKey = 'SHA256:' + ('A' * 43)
$attemptId = 'B' * 32
$context = [pscustomobject][ordered]@{
    profile_id = $profileId
    profile_generation = [uint64]7
    observed_host_key_sha256 = $hostKey
    server_identification = 'SSH-2.0-OpenSSH_synthetic'
    transport_attempt_id = $attemptId
    context_sha256 = 'C' * 64
}
$identity = [ordered]@{
    profile_id = $profileId
    profile_generation = [uint64]7
    observed_host_key_sha256 = $hostKey
    pin_match = $true
    server_identification = 'SSH-2.0-OpenSSH_synthetic'
    transport_attempt_id = $attemptId
    operation_context_id = ('11' * 32)
    revision = [uint64]1
}
$identityLine = New-AgentSuccess 1 $identity
$tunnelId = 'fedcba9876543210fedcba9876543210'
$tunnelOperationContextId = ('44' * 32)
$deadline = [uint64]1900000000000
$tunnelReady = [ordered]@{
    tunnel_id = $tunnelId; mode = 'local'; stage = 'ready'; bind_host = '127.0.0.1'
    bind_port = 15432; deadline_unix_ms = $deadline
    operation_context_id = $tunnelOperationContextId; revision = [uint64]1
}
$tunnelClosed = [ordered]@{
    tunnel_id = $tunnelId; mode = 'local'; stage = 'closed'; bind_host = '127.0.0.1'
    bind_port = 15432; deadline_unix_ms = $deadline
    operation_context_id = $tunnelOperationContextId; revision = [uint64]3
}
$tunnelBytes = ConvertTo-NdjsonBytes @(
    $identityLine,
    (New-AgentSuccess 2 $tunnelReady),
    (New-AgentSuccess 3 ([ordered]@{ tunnels = @($tunnelReady) })),
    (New-AgentSuccess 4 $tunnelClosed)
)
$tunnelRequestBytes = ConvertTo-NdjsonBytes @(
    [ordered]@{ schema_version = 1; request_id = 1; op = 'ssh-connection-identity' },
    [ordered]@{
        schema_version = 1; request_id = 2; op = 'forward-local-open'
        bind_port = 0; target_port = 5432; max_connections = 32
        deadline_unix_ms = $deadline
    },
    [ordered]@{
        schema_version = 1; request_id = 3; op = 'forward-status'
        tunnel_id = $tunnelId; operation_context_id = $tunnelOperationContextId
        deadline_unix_ms = $deadline
    },
    [ordered]@{
        schema_version = 1; request_id = 4; op = 'forward-cancel'
        tunnel_id = $tunnelId; operation_context_id = $tunnelOperationContextId
        deadline_unix_ms = $deadline
    }
)
$execBytes = ConvertTo-NdjsonBytes @(
    $identityLine,
    (New-AgentSuccess 2 ([ordered]@{
        stdout = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("ok`n"))
        stderr = ''; code = 0; operation_context_id = ('22' * 32); revision = [uint64]1
    }))
)
$execRequestBytes = ConvertTo-NdjsonBytes @(
    [ordered]@{ schema_version = 1; request_id = 1; op = 'ssh-connection-identity' },
    [ordered]@{
        schema_version = 1; request_id = 2; op = 'exec'
        cmd = '/usr/bin/true'; timeout_ms = [uint64]30000
    }
)
$directoryBytes = ConvertTo-NdjsonBytes @(
    $identityLine,
    (New-AgentSuccess 2 ([ordered]@{
        path = '/tmp'; entries = @([ordered]@{
            name = 'artifact.bin'; path = '/tmp/artifact.bin'; is_dir = $false
            is_symlink = $false; size = [uint64]21; modified_unix = [uint32]123
        })
        operation_context_id = ('33' * 32); revision = [uint64]1
    }))
)
$directoryRequestBytes = ConvertTo-NdjsonBytes @(
    [ordered]@{ schema_version = 1; request_id = 1; op = 'ssh-connection-identity' },
    [ordered]@{
        schema_version = 1; request_id = 2; op = 'list-dir'
        path = '/tmp'; timeout_ms = [uint64]30000
    }
)
$dropbearContext = [pscustomobject][ordered]@{
    profile_id = $profileId
    profile_generation = [uint64]7
    observed_host_key_sha256 = $hostKey
    server_identification = 'SSH-2.0-dropbear_synthetic'
    transport_attempt_id = 'D' * 32
    context_sha256 = 'E' * 64
}
$dropbearIdentity = [ordered]@{
    profile_id = $profileId; profile_generation = [uint64]7
    observed_host_key_sha256 = $hostKey; pin_match = $true
    server_identification = 'SSH-2.0-dropbear_synthetic'
    transport_attempt_id = 'D' * 32
    operation_context_id = ('55' * 32); revision = [uint64]1
}
$dropbearExecBytes = ConvertTo-NdjsonBytes @(
    (New-AgentSuccess 1 $dropbearIdentity),
    (New-AgentSuccess 2 ([ordered]@{
        stdout = ''; stderr = ''; code = 0
        operation_context_id = ('66' * 32); revision = [uint64]1
    }))
)
$remoteTunnelId = '11112222333344445555666677778888'
$remoteTunnelContextId = ('88' * 32)
$remoteTunnelReady = [ordered]@{
    tunnel_id = $remoteTunnelId; mode = 'remote'; stage = 'ready'; bind_host = '127.0.0.1'
    bind_port = 18080; deadline_unix_ms = $deadline
    operation_context_id = $remoteTunnelContextId; revision = [uint64]1
}
$remoteTunnelClosed = [ordered]@{
    tunnel_id = $remoteTunnelId; mode = 'remote'; stage = 'closed'; bind_host = '127.0.0.1'
    bind_port = 18080; deadline_unix_ms = $deadline
    operation_context_id = $remoteTunnelContextId; revision = [uint64]2
}
$remoteTunnelBytes = ConvertTo-NdjsonBytes @(
    $identityLine,
    (New-AgentSuccess 2 $remoteTunnelReady),
    (New-AgentSuccess 3 ([ordered]@{ tunnels = @($remoteTunnelReady) })),
    (New-AgentSuccess 4 $remoteTunnelClosed)
)
$dynamicTunnelId = '9999aaaabbbbccccddddeeeeffff0000'
$dynamicTunnelContextId = ('99' * 32)
$dynamicTunnelReady = [ordered]@{
    tunnel_id = $dynamicTunnelId; mode = 'dynamic'; stage = 'ready'; bind_host = '127.0.0.1'
    bind_port = 11080; deadline_unix_ms = $deadline
    operation_context_id = $dynamicTunnelContextId; revision = [uint64]1
}
$dynamicTunnelClosed = [ordered]@{
    tunnel_id = $dynamicTunnelId; mode = 'dynamic'; stage = 'unknown'; bind_host = '127.0.0.1'
    bind_port = 11080; deadline_unix_ms = $deadline
    operation_context_id = $dynamicTunnelContextId; revision = [uint64]2
}
$dynamicTunnelBytes = ConvertTo-NdjsonBytes @(
    $identityLine,
    (New-AgentSuccess 2 $dynamicTunnelReady),
    (New-AgentSuccess 3 ([ordered]@{ tunnels = @($dynamicTunnelReady) })),
    (New-AgentSuccess 4 $dynamicTunnelClosed)
)
$transferId = '00112233445566778899aabbccddeeff'
$operationContextId = ('ab' * 32)
$transferBytes = ConvertTo-NdjsonBytes @(
    $identityLine,
    (New-AgentSuccess 2 ([ordered]@{
        transfer_id = $transferId; operation_context_id = $operationContextId
        revision = [uint64]4; bytes = [uint64]21; backend_requested = 'auto'
        backend = 'sftp_fallback'; chunk_bytes = [uint32]2048; window_bytes = [uint32]2048
    })),
    (New-AgentSuccess 3 ([ordered]@{ transfers = @([ordered]@{
        schema_version = 1; event = 'completed'; transfer_id = $transferId
        operation_context_id = $operationContextId; revision = [uint64]4
        direction = 'push'; stage = 'completed'; total_bytes = [uint64]21
        confirmed_bytes = [uint64]21; durable_bytes = [uint64]21
        window_bps = 1.0; average_bps = 1.0; eta_ms = $null
        backend = 'sftp_fallback'; chunk_bytes = [uint32]2048
        window_bytes = [uint32]2048; updated_unix_ms = [uint64]1800000000000
    }) }))
)
$pullBytes = [Text.UTF8Encoding]::new($false).GetBytes(
    [Text.UTF8Encoding]::new($false).GetString($transferBytes).Replace(
        '"direction":"push"', '"direction":"pull"'
    )
)
$concurrentPlaceholderId = '00000000000000000000000000000000'
$concurrentPrimaryBytes = ConvertTo-NdjsonBytes @(
    $identityLine,
    (New-AgentSuccess 2 ([ordered]@{
        transfer_id = $concurrentPlaceholderId; operation_context_id = $operationContextId
        revision = [uint64]4; bytes = [uint64]21; backend_requested = 'native'
        backend = 'native'; chunk_bytes = [uint32]2048; window_bytes = [uint32]2048
    }))
)
$concurrentStatusBytes = ConvertTo-NdjsonBytes @(
    (New-AgentSuccess 3 ([ordered]@{ transfers = @([ordered]@{
        schema_version = 1; event = 'progress'; transfer_id = $concurrentPlaceholderId
        operation_context_id = $operationContextId; revision = [uint64]3
        direction = 'push'; stage = 'transferring'; total_bytes = [uint64]21
        confirmed_bytes = [uint64]10; durable_bytes = [uint64]8
        window_bps = 1.0; average_bps = 1.0; eta_ms = [uint64]11000
        backend = 'native'; chunk_bytes = [uint32]2048
        window_bytes = [uint32]2048; updated_unix_ms = [uint64]1800000000000
    }) }))
)

try {
    foreach ($probe in @(
        @('openssh_dropbear_interop', 'OpenSSH_exec', $execBytes, 2, $context),
        @('openssh_dropbear_interop', 'OpenSSH_directory', $directoryBytes, 2, $context),
        @('openssh_dropbear_interop', 'Dropbear_exec', $dropbearExecBytes, 2, $dropbearContext),
        @('openssh_dropbear_interop', 'OpenSSH_tunnel_local', $tunnelBytes, 4, $context),
        @(
            'openssh_dropbear_interop', 'OpenSSH_tunnel_remote',
            $remoteTunnelBytes, 4, $context
        ),
        @(
            'openssh_dropbear_interop', 'OpenSSH_tunnel_dynamic',
            $dynamicTunnelBytes, 4, $context
        ),
        @('native_transfer_real_host', 'push_21', $transferBytes, 3, $context),
        @('native_transfer_real_host', 'pull_21', $pullBytes, 3, $context)
    )) {
        $parsed = & $contractModule {
            param($Bytes, $Category, $CaseId, $Context)
            ConvertFrom-SerctlAgentTranscript $Bytes $Category $CaseId $Context
        } $probe[2] $probe[0] $probe[1] $probe[4]
        Assert-AdapterTest (
            $parsed.parser_outcome -ceq 'accepted' -and $parsed.synthetic_only -and
            -not $parsed.sealable -and $parsed.operation_count -eq $probe[3] -and
            $parsed.all_operations_succeeded
        ) "synthetic $($probe[1]) transcript did not pass its closed parser"
        $fields = @($parsed.PSObject.Properties.Name | Sort-Object)
        Assert-AdapterTest (
            ($fields -join ',') -ceq (
                @('all_operations_succeeded', 'context_sha256', 'operation_count',
                    'parser_outcome', 'schema_version', 'sealable', 'synthetic_only',
                    'transcript_sha256') -join ','
            )
        ) 'synthetic parser summary exposes formal receipt-shaped state'
    }

    foreach ($fixedCase in @(
        @('OpenSSH_exec', $execRequestBytes),
        @('Dropbear_exec', $execRequestBytes),
        @('OpenSSH_directory', $directoryRequestBytes)
    )) {
        $built = & $contractModule {
            param($CaseId)
            New-SerctlFormalRuntimeRequestBytesInternal `
                'openssh_dropbear_interop' $CaseId
        } $fixedCase[0]
        try {
            Assert-AdapterTest (
                [Convert]::ToBase64String($built) -ceq
                    [Convert]::ToBase64String([byte[]]$fixedCase[1])
            ) "formal $($fixedCase[0]) producer changed its fixed request"
        }
        finally { [Array]::Clear($built, 0, $built.Length) }
    }

    foreach ($tunnelCase in @(
        @('OpenSSH_tunnel_local', $tunnelId, $tunnelOperationContextId, $tunnelBytes),
        @(
            'OpenSSH_tunnel_remote', $remoteTunnelId, $remoteTunnelContextId,
            $remoteTunnelBytes
        ),
        @(
            'OpenSSH_tunnel_dynamic', $dynamicTunnelId, $dynamicTunnelContextId,
            $dynamicTunnelBytes
        )
    )) {
        $segments = & $contractModule {
            param($CaseId, $TunnelId, $OperationContextId, $Deadline)
            $open = New-SerctlFormalManagedTunnelOpenRequestBytesInternal `
                'openssh_dropbear_interop' $CaseId $Deadline
            $status = New-SerctlFormalManagedTunnelControlRequestBytesInternal `
                'openssh_dropbear_interop' $CaseId 'status' $TunnelId `
                $OperationContextId $Deadline
            $cancel = New-SerctlFormalManagedTunnelControlRequestBytesInternal `
                'openssh_dropbear_interop' $CaseId 'cancel' $TunnelId `
                $OperationContextId $Deadline
            return ,@($open, $status, $cancel)
        } $tunnelCase[0] $tunnelCase[1] $tunnelCase[2] $deadline
        try {
            Assert-AdapterTest (
                $segments.Count -eq 3 -and
                [Text.UTF8Encoding]::new($false, $true).GetString($segments[0]).Contains(
                    '"request_id":2'
                ) -and
                [Text.UTF8Encoding]::new($false, $true).GetString($segments[1]).Contains(
                    '"request_id":3'
                ) -and
                [Text.UTF8Encoding]::new($false, $true).GetString($segments[2]).Contains(
                    '"request_id":4'
                )
            ) "formal $($tunnelCase[0]) producer did not create the fixed phase sequence"
            foreach ($bytes in $segments) {
                $requestText = [Text.UTF8Encoding]::new($false, $true).GetString($bytes)
                Assert-AdapterTest (
                    -not ($requestText -match '(?i)(argv|result|passed|password|passphrase)')
                ) "formal $($tunnelCase[0]) producer exposed an injected execution field"
            }
        }
        finally {
            foreach ($bytes in $segments) { [Array]::Clear($bytes, 0, $bytes.Length) }
        }

        $transcriptText = [Text.UTF8Encoding]::new($false, $true).GetString(
            [byte[]]$tunnelCase[3]
        ).TrimEnd("`n")
        $transcriptLines = @($transcriptText -split "`n")
        $openCaptureBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes(
            (($transcriptLines[0..1] -join "`n") + "`n")
        )
        $statusCaptureBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes(
            ($transcriptLines[2] + "`n")
        )
        $cancelCaptureBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes(
            ($transcriptLines[3] + "`n")
        )
        $binding = & $contractModule {
            param($Open, $Status, $Cancel, $CaseId, $Context)
            ConvertFrom-SerctlFormalManagedTunnelCapturesInternal `
                $Open $Status $Cancel 'openssh_dropbear_interop' $CaseId $Context
        } (New-SyntheticCapture $openCaptureBytes) `
            (New-SyntheticCapture $statusCaptureBytes) `
            (New-SyntheticCapture $cancelCaptureBytes) $tunnelCase[0] $context
        Assert-AdapterTest (
            $binding.tunnel_id -ceq $tunnelCase[1] -and
            $binding.operation_context_id -ceq $tunnelCase[2] -and
            [uint64]$binding.open_revision -eq 1 -and
            [uint64]$binding.status_revision -ge [uint64]$binding.open_revision -and
            [uint64]$binding.terminal_revision -gt [uint64]$binding.status_revision -and
            [string]$binding.terminal_stage -cin @('closed', 'unknown')
        ) "formal $($tunnelCase[0]) capture state machine lost its exact binding"
        foreach ($bytes in @($openCaptureBytes, $statusCaptureBytes, $cancelCaptureBytes)) {
            [Array]::Clear($bytes, 0, $bytes.Length)
        }
    }

    $managedTunnelCommand = & $contractModule {
        Get-Command Invoke-SerctlFormalManagedTunnelInternal
    }
    foreach ($forbiddenParameter in @(
        'ArgumentList', 'Argv', 'Result', 'Passed', 'Transcript', 'ExpectedStdout',
        'Receipt', 'RequestBytes', 'GrantPath'
    )) {
        Assert-AdapterTest (
            -not $managedTunnelCommand.Parameters.ContainsKey($forbiddenParameter)
        ) "formal managed tunnel producer exposes '$forbiddenParameter'"
    }
    $interopTransferCommand = & $contractModule {
        Get-Command Invoke-SerctlFormalInteropTransferInternal
    }
    foreach ($forbiddenParameter in @(
        'LocalPath', 'RemotePath', 'PayloadSha256', 'Hash', 'RequestBytes',
        'ArgumentList', 'Argv', 'Result', 'Passed', 'Transcript', 'ExpectedStdout',
        'Receipt', 'GrantPath'
    )) {
        Assert-AdapterTest (
            -not $interopTransferCommand.Parameters.ContainsKey($forbiddenParameter)
        ) "formal interop transfer producer exposes '$forbiddenParameter'"
    }

    $helperPath = Join-Path $fixtureRoot 'serctl_cli.exe'
    $sourcePath = Join-Path $fixtureRoot 'serctl-adapter-fixture.cs'
    $good = [Convert]::ToBase64String($tunnelBytes)
    $expectedInput = [Convert]::ToBase64String($tunnelRequestBytes)
    $execOutput = [Convert]::ToBase64String($execBytes)
    $expectedExecInput = [Convert]::ToBase64String($execRequestBytes)
    $directoryOutput = [Convert]::ToBase64String($directoryBytes)
    $expectedDirectoryInput = [Convert]::ToBase64String($directoryRequestBytes)
    $concurrentPrimaryOutput = [Convert]::ToBase64String($concurrentPrimaryBytes)
    $concurrentStatusOutput = [Convert]::ToBase64String($concurrentStatusBytes)
    $expectedGrant = [Convert]::ToBase64String(
        [Text.UTF8Encoding]::new($false).GetBytes('non-secret-grant-fixture')
    )
    $wrong = [byte[]]$tunnelBytes.Clone()
    $wrong[$wrong.Length - 4] = [byte][char]'X'
    $bad = [Convert]::ToBase64String($wrong)
    [Array]::Clear($wrong, 0, $wrong.Length)
    $source = @"
using System;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Microsoft.Win32.SafeHandles;
public static class Fixture {
  static readonly byte[] Good = Convert.FromBase64String("$good");
  static readonly byte[] Wrong = Convert.FromBase64String("$bad");
  static readonly byte[] ExpectedInput = Convert.FromBase64String("$expectedInput");
  static readonly byte[] ExecOutput = Convert.FromBase64String("$execOutput");
  static readonly byte[] ExpectedExecInput = Convert.FromBase64String("$expectedExecInput");
  static readonly byte[] DirectoryOutput = Convert.FromBase64String("$directoryOutput");
  static readonly byte[] ExpectedDirectoryInput = Convert.FromBase64String("$expectedDirectoryInput");
  static readonly byte[] ConcurrentPrimaryOutput = Convert.FromBase64String("$concurrentPrimaryOutput");
  static readonly byte[] ConcurrentStatusOutput = Convert.FromBase64String("$concurrentStatusOutput");
  static readonly byte[] ExpectedGrant = Convert.FromBase64String("$expectedGrant");
  static byte[] ReadAll(Stream s) { using(var m=new MemoryStream()) { s.CopyTo(m); return m.ToArray(); } }
  static bool Same(byte[] a, byte[] b) { if(a.Length!=b.Length)return false; for(int i=0;i<a.Length;i++)if(a[i]!=b[i])return false; return true; }
  static string Sha256(string p) { using(var f=File.OpenRead(p)) using(var h=SHA256.Create()) return BitConverter.ToString(h.ComputeHash(f)).Replace("-","").ToLowerInvariant(); }
  public static int Main(string[] a) {
    if (a.Length == 3 && a[0] == "agent" && a[1] == "--grant-handle") {
      File.AppendAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"formal-child-launched.marker"),"1");
      var input=ReadAll(Console.OpenStandardInput()); bool tunnel=Same(input,ExpectedInput); bool exec=Same(input,ExpectedExecInput); bool directory=Same(input,ExpectedDirectoryInput);
      string inputText=Encoding.UTF8.GetString(input); bool primary=inputText.Contains("\"op\":\"transfer-push\""); bool status=inputText.Contains("\"op\":\"transfer-status\""); if(!tunnel&&!exec&&!directory&&!primary&&!status) return 92;
      long raw; if(!long.TryParse(a[2],NumberStyles.None,CultureInfo.InvariantCulture,out raw)) return 93;
      using(var h=new SafeFileHandle(new IntPtr(raw),true)) using(var f=new FileStream(h,FileAccess.Read)) {
        var grant=ReadAll(f); if(!Same(grant,ExpectedGrant)) return 94;
      }
      if(directory) File.AppendAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"serctl_daemon.exe"),"late-mutation");
      if(primary||status) {
        bool native=inputText.Contains("\"backend\":\"native\""); bool sftp=inputText.Contains("\"backend\":\"sftp\"");
        if(primary && native==sftp) return 97;
        if(primary) { string helper=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"serctl-xfer"); string expected="\"expected_helper_identity\":{\"name\":\"serctl-xfer\",\"binary_size\":"+new FileInfo(helper).Length.ToString(CultureInfo.InvariantCulture)+",\"sha256\":\""+Sha256(helper)+"\",\"version\":\"serctl-xfer 1.0.0-beta (git 0123456789ab; transfer protocol v1)\"}"; if(native&&!inputText.Contains(expected)) return 97; if(sftp&&inputText.Contains("expected_helper_identity")) return 98; }
        Match m=Regex.Match(inputText,"\\\"transfer_id\\\":\\\"([0-9a-f]{32})\\\""); if(!m.Success) return 95; string id=m.Groups[1].Value;
        string marker=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,id+".scenario");
        if(primary) {
          string scenario=inputText.Contains("context-mismatch")?"context-mismatch":(inputText.Contains("revision-ahead")?"revision-ahead":(inputText.Contains("late-status")?"late-status":"normal"));
          File.WriteAllText(marker,scenario+"|"+(native?"native":"sftp")); if(scenario!="late-status") Thread.Sleep(600);
          string text=Encoding.UTF8.GetString(ConcurrentPrimaryOutput).Replace("00000000000000000000000000000000",id); if(sftp) text=text.Replace("\"backend_requested\":\"native\",\"backend\":\"native\"","\"backend_requested\":\"sftp\",\"backend\":\"sftp\""); if(inputText.Contains("dropbear_")) text=text.Replace("SSH-2.0-OpenSSH_synthetic","SSH-2.0-dropbear_synthetic").Replace("\"transport_attempt_id\":\"BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\"","\"transport_attempt_id\":\"DDDDDDDDDDDDDDDDDDDDDDDDDDDDDDDD\"").Replace("\"operation_context_id\":\"1111111111111111111111111111111111111111111111111111111111111111\"","\"operation_context_id\":\"5555555555555555555555555555555555555555555555555555555555555555\""); byte[] dynamicOutput=Encoding.UTF8.GetBytes(text); Console.OpenStandardOutput().Write(dynamicOutput,0,dynamicOutput.Length); return 0;
        }
        for(int i=0;i<20&&!File.Exists(marker);i++) Thread.Sleep(10); if(!File.Exists(marker)) return 96; string[] markerParts=File.ReadAllText(marker).Split('|'); string mode=markerParts[0]; string backend=markerParts[1];
        string statusText=Encoding.UTF8.GetString(ConcurrentStatusOutput).Replace("00000000000000000000000000000000",id);
        if(backend=="sftp") statusText=statusText.Replace("\"backend\":\"native\"","\"backend\":\"sftp\"");
        if(mode=="context-mismatch") statusText=statusText.Replace("$operationContextId",new string('c',64));
        if(mode=="revision-ahead") statusText=statusText.Replace("\"revision\":3","\"revision\":5");
        if(mode=="late-status") Thread.Sleep(700);
        byte[] statusOutput=Encoding.UTF8.GetBytes(statusText); Console.OpenStandardOutput().Write(statusOutput,0,statusOutput.Length); return 0;
      }
      var output=tunnel?Good:(exec?ExecOutput:DirectoryOutput); Console.OpenStandardOutput().Write(output,0,output.Length); return 0;
    }
    if (a.Length != 1) return 90;
    if (a[0] == "success") { var input=ReadAll(Console.OpenStandardInput()); if(!Same(input,ExpectedInput)) return 92; Console.OpenStandardOutput().Write(Good,0,Good.Length); return 0; }
    if (a[0] == "wrong-hash") { var input=ReadAll(Console.OpenStandardInput()); if(!Same(input,ExpectedInput)) return 92; Console.OpenStandardOutput().Write(Wrong,0,Wrong.Length); return 0; }
    if (a[0] == "hang") { Thread.Sleep(10000); return 0; }
    if (a[0] == "leaf-hang") { Thread.Sleep(10000); return 0; }
    if (a[0] == "spawn-child-hang") {
      var start=new ProcessStartInfo(Process.GetCurrentProcess().MainModule.FileName,"leaf-hang"); start.UseShellExecute=false; Process.Start(start); Thread.Sleep(10000); return 0;
    }
    if (a[0] == "flood") { byte[] b=new byte[8192]; for(int i=0;i<128;i++) Console.OpenStandardOutput().Write(b,0,b.Length); return 0; }
    return 91;
  }
}
"@
    [IO.File]::WriteAllText($sourcePath, $source, [Text.UTF8Encoding]::new($false))
    $compiler = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    Assert-AdapterTest (Test-Path -LiteralPath $compiler -PathType Leaf) 'fixed compiler is unavailable'
    & $compiler '/nologo' '/target:exe' ('/out:' + $helperPath) $sourcePath
    Assert-AdapterTest ($LASTEXITCODE -eq 0) 'synthetic helper compilation failed'

    $daemonFixturePath = Join-Path $fixtureRoot 'serctl_daemon.exe'
    $xferFixturePath = Join-Path $fixtureRoot 'serctl-xfer'
    [IO.File]::Copy($helperPath, $daemonFixturePath, $false)
    [IO.File]::Copy($helperPath, $xferFixturePath, $false)
    $componentSize = (Get-Item -LiteralPath $helperPath).Length
    $componentHash = (Get-FileHash -LiteralPath $helperPath -Algorithm SHA256).Hash
    $components = [pscustomobject][ordered]@{
        cli = [pscustomobject][ordered]@{
            name = 'serctl_cli.exe'; binary_size = [long]$componentSize
            sha256 = $componentHash
            version = 'serctl_cli 1.0.0-beta (git 0123456789ab; vault-storage read=v4..=v5 write=v5)'
        }
        daemon = [pscustomobject][ordered]@{
            name = 'serctl_daemon.exe'; binary_size = [long]$componentSize
            sha256 = $componentHash
            version = 'serctl_daemon 1.0.0-beta (git 0123456789ab; IPC v9..=v9; vault-storage read=v4..=v5 write=v5)'
        }
        helper = [pscustomobject][ordered]@{
            name = 'serctl-xfer'; binary_size = [long]$componentSize
            sha256 = $componentHash
            version = 'serctl-xfer 1.0.0-beta (git 0123456789ab; transfer protocol v1)'
        }
    }
    $componentPaths = [pscustomobject][ordered]@{
        cli = $helperPath; daemon = $daemonFixturePath; helper = $xferFixturePath
    }
    if ($null -eq ('Serctl.AdapterRuntimeSelfTest.Native' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace Serctl.AdapterRuntimeSelfTest {
  public static class Native {
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetHandleInformation(IntPtr h, uint mask, uint flags);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern SafeFileHandle CreateFile(string n,uint a,uint s,IntPtr sa,uint c,uint f,IntPtr t);
    public static void MakeInheritable(IntPtr h) { if(!SetHandleInformation(h,1,1)) throw new Win32Exception(); }
    public static SafeFileHandle OpenDirectory(string p) { var h=CreateFile(p,0x80000000,7,IntPtr.Zero,3,0x02000080,IntPtr.Zero); if(h.IsInvalid) throw new Win32Exception(); MakeInheritable(h.DangerousGetHandle()); return h; }
  }
}
'@
    }
    $fixedInteropTransferId = '1234567890abcdef1234567890abcdef'
    foreach ($interopCase in @(
        @('OpenSSH_sftp', 'sftp'), @('OpenSSH_native', 'native'),
        @('Dropbear_sftp', 'sftp'), @('Dropbear_native', 'native')
    )) {
        $helperComponent = if ($interopCase[1] -ceq 'native') { $components.helper } else { $null }
        $segments = & $contractModule {
            param($CaseId, $TransferId, $Helper)
            New-SerctlFormalInteropTransferRequestSegmentsInternal `
                'openssh_dropbear_interop' $CaseId $TransferId 30000 $Helper
        } $interopCase[0] $fixedInteropTransferId $helperComponent
        try {
            $recipe = & $contractModule {
                param($CaseId)
                Get-SerctlRuntimeAdapterRecipe 'openssh_dropbear_interop' $CaseId
            } $interopCase[0]
            Assert-AdapterTest (
                ($recipe -join ',') -ceq
                    'ssh-connection-identity,transfer-push,transfer-status'
            ) "formal $($interopCase[0]) scope/operation order changed"
            $primaryText = [Text.UTF8Encoding]::new($false, $true).GetString($segments.primary)
            $statusText = [Text.UTF8Encoding]::new($false, $true).GetString($segments.status)
            Assert-AdapterTest (
                $primaryText.Contains('"backend":"' + $interopCase[1] + '"') -and
                $primaryText.Contains('/tmp/serctl-v1-beta-interop-source-21.bin') -and
                $primaryText.Contains(
                    '/tmp/serctl-v1-beta-' + $interopCase[0].ToLowerInvariant() +
                        '-target-21.bin'
                ) -and
                $statusText.Contains('"op":"transfer-status"') -and
                $statusText.Contains($fixedInteropTransferId) -and
                -not ($primaryText -match '(?i)(argv|result|passed|password|passphrase)')
            ) "formal $($interopCase[0]) fixed request is incomplete"
            if ($interopCase[1] -ceq 'native') {
                Assert-AdapterTest $primaryText.Contains('"expected_helper_identity"') (
                    "formal $($interopCase[0]) omitted verified helper identity"
                )
                $helperHash = ([string]$components.helper.sha256).ToLowerInvariant()
                $helperSubstitution = [Text.UTF8Encoding]::new($false, $true).GetBytes(
                    $primaryText.Replace($helperHash, ('0' * 64))
                )
                Assert-AdapterRejected `
                    -Description "$($interopCase[0]) helper identity substitution" `
                    -Action {
                    & $contractModule {
                        param($Primary, $Status, $CaseId, $TransferId, $Helper)
                        Assert-SerctlFormalInteropTransferRequestSegmentsInternal `
                            $Primary $Status 'openssh_dropbear_interop' $CaseId `
                            $TransferId 30000 $Helper
                    } $helperSubstitution $segments.status $interopCase[0] `
                        $fixedInteropTransferId $helperComponent
                }
                [Array]::Clear($helperSubstitution, 0, $helperSubstitution.Length)
            }
            else {
                Assert-AdapterTest (-not $primaryText.Contains('expected_helper_identity')) (
                    "formal $($interopCase[0]) invented helper identity"
                )
            }
            $wrongBackend = if ($interopCase[1] -ceq 'native') { 'sftp' } else { 'native' }
            $substituted = [Text.UTF8Encoding]::new($false, $true).GetBytes(
                $primaryText.Replace(
                    '"backend":"' + $interopCase[1] + '"',
                    '"backend":"' + $wrongBackend + '"'
                )
            )
            Assert-AdapterRejected -Description "$($interopCase[0]) backend substitution" -Action {
                & $contractModule {
                    param($Primary, $Status, $CaseId, $TransferId, $Helper)
                    Assert-SerctlFormalInteropTransferRequestSegmentsInternal `
                        $Primary $Status 'openssh_dropbear_interop' $CaseId `
                        $TransferId 30000 $Helper
                } $substituted $segments.status $interopCase[0] `
                    $fixedInteropTransferId $helperComponent
            }
            [Array]::Clear($substituted, 0, $substituted.Length)
        }
        finally {
            [Array]::Clear($segments.primary, 0, $segments.primary.Length)
            [Array]::Clear($segments.status, 0, $segments.status.Length)
        }
    }
    $grantPath = Join-Path $fixtureRoot 'grant-input.bin'
    [IO.File]::WriteAllBytes(
        $grantPath,
        [Text.UTF8Encoding]::new($false).GetBytes('non-secret-grant-fixture')
    )
    $grantStream = [IO.File]::Open(
        $grantPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read
    )
    try {
        [Serctl.AdapterRuntimeSelfTest.Native]::MakeInheritable(
            $grantStream.SafeFileHandle.DangerousGetHandle()
        )
        $formalRequestOwned = [byte[]]$execRequestBytes.Clone()
        $formalConfig = [pscustomobject][ordered]@{
            schema_version = 'serctl-protected-formal-runtime-config-v1'
            category = 'openssh_dropbear_interop'; case_id = 'OpenSSH_exec'
            component_paths = $componentPaths; request_bytes = $formalRequestOwned
            expected_context = $context; deadline_ms = 2000
            grant_input_handle = $grantStream.SafeFileHandle
        }
        $formalObservation = & $contractModule {
            param($Config, $Components)
            Invoke-SerctlFormalRuntimeProcessSkeletonInternal $Config $Components
        } $formalConfig $components
        try {
            Assert-AdapterTest (
                $formalObservation.internal_contract -ceq
                    'serctl-runtime-adapter-observation-v1' -and
                $formalObservation.category -ceq 'openssh_dropbear_interop' -and
                $formalObservation.case_id -ceq 'OpenSSH_exec' -and
                $formalObservation.context_sha256 -ceq $context.context_sha256 -and
                $formalObservation.receipt_bytes -is [byte[]]
            ) 'protected formal process skeleton did not bind the captured JSONL context'
            $receiptText = [Text.UTF8Encoding]::new($false, $true).GetString(
                [byte[]]$formalObservation.receipt_bytes
            )
            $receipt = $receiptText.TrimEnd("`n") | ConvertFrom-Json
            Assert-AdapterTest (
                $receipt.passed -eq $true -and $receipt.result_code -ceq 'completed' -and
                $receipt.context_sha256 -ceq $context.context_sha256
            ) 'formal child receipt was not derived from the successful captured terminal'
            Assert-AdapterTest (
                @($formalObservation.PSObject.Properties.Name | Where-Object {
                    $_ -in @('result', 'stdout', 'stderr', 'expected_stdout')
                }).Count -eq 0
            ) 'protected formal process skeleton exposed injected result or raw output'
        }
        finally {
            [Array]::Clear(
                [byte[]]$formalObservation.receipt_bytes,
                0,
                ([byte[]]$formalObservation.receipt_bytes).Length
            )
        }
        Assert-AdapterTest (
            @($formalRequestOwned | Where-Object { $_ -ne 0 }).Count -eq 0
        ) 'protected formal JSONL stdin was not cleared after process completion'

        $badComponents = $components.PSObject.Copy()
        $badComponents.cli = $components.cli.PSObject.Copy()
        $badComponents.cli.sha256 = 'D' * 64
        $badRequestOwned = [byte[]]$execRequestBytes.Clone()
        $badConfig = $formalConfig.PSObject.Copy()
        $badConfig.request_bytes = $badRequestOwned
        Assert-AdapterRejected -Description 'exact release component identity substitution' -Action {
            & $contractModule {
                param($Config, $Components)
                Invoke-SerctlFormalRuntimeProcessSkeletonInternal $Config $Components
            } $badConfig $badComponents
        }
        Assert-AdapterTest (
            @($badRequestOwned | Where-Object { $_ -ne 0 }).Count -eq 0
        ) 'rejected formal JSONL stdin was not cleared'
    }
    finally { $grantStream.Dispose() }

    foreach ($interopCase in @(
        'OpenSSH_sftp', 'OpenSSH_native', 'Dropbear_sftp', 'Dropbear_native'
    )) {
        $transferStream = [IO.File]::Open(
            $grantPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read
        )
        $statusStream = [IO.File]::Open(
            $grantPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read
        )
        try {
            foreach ($stream in @($transferStream, $statusStream)) {
                [Serctl.AdapterRuntimeSelfTest.Native]::MakeInheritable(
                    $stream.SafeFileHandle.DangerousGetHandle()
                )
            }
            $expectedInteropContext = if ($interopCase.StartsWith(
                'Dropbear', [StringComparison]::Ordinal
            )) { $dropbearContext } else { $context }
            $config = [pscustomobject][ordered]@{
                schema_version = 'serctl-protected-formal-interop-transfer-config-v1'
                category = 'openssh_dropbear_interop'; case_id = $interopCase
                component_paths = $componentPaths; expected_context = $expectedInteropContext
                deadline_ms = 2000
                transfer_grant_input_handle = $transferStream.SafeFileHandle
                status_grant_input_handle = $statusStream.SafeFileHandle
            }
            $observation = & $contractModule {
                param($Config, $Components)
                Invoke-SerctlFormalInteropTransferInternal $Config $Components
            } $config $components
            try {
                Assert-AdapterTest (
                    $observation.internal_contract -ceq
                        'serctl-runtime-adapter-observation-v1' -and
                    $observation.category -ceq 'openssh_dropbear_interop' -and
                    $observation.case_id -ceq $interopCase -and
                    $observation.context_sha256 -ceq $expectedInteropContext.context_sha256 -and
                    $observation.receipt_bytes -is [byte[]]
                ) "formal $interopCase producer did not return a derived observation"
            }
            finally {
                [Array]::Clear(
                    $observation.receipt_bytes, 0, $observation.receipt_bytes.Length
                )
            }
        }
        finally {
            $transferStream.Dispose()
            $statusStream.Dispose()
        }
    }

    $windowsProvenanceBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes((
        [pscustomobject][ordered]@{
            schema_version = 2; platform = 'windows-x86_64'
            binary_components = @($components.cli, $components.daemon)
        } | ConvertTo-Json -Compress -Depth 6
    ))
    $linuxProvenanceBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes((
        [pscustomobject][ordered]@{
            schema_version = 2; platform = 'linux-x86_64'
            binary_components = @($components.helper)
        } | ConvertTo-Json -Compress -Depth 6
    ))
    $ownerGrantPath = Join-Path $fixtureRoot 'owner-grant-input.bin'
    [IO.File]::WriteAllBytes(
        $ownerGrantPath,
        [Text.UTF8Encoding]::new($false).GetBytes('non-secret-grant-fixture')
    )

    function Invoke-ConcurrentOwnerFixture {
        param(
            [Parameter(Mandatory = $true)][string]$Scenario,
            [Parameter(Mandatory = $true)][bool]$ShouldSucceed
        )
        $transferGrant = [IO.File]::Open(
            $ownerGrantPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read
        )
        $statusGrant = [IO.File]::Open(
            $ownerGrantPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read
        )
        $transferHandle = $transferGrant.SafeFileHandle
        $statusHandle = $statusGrant.SafeFileHandle
        [Serctl.AdapterRuntimeSelfTest.Native]::MakeInheritable(
            $transferHandle.DangerousGetHandle()
        )
        [Serctl.AdapterRuntimeSelfTest.Native]::MakeInheritable(
            $statusHandle.DangerousGetHandle()
        )
        $windowsBytes = [byte[]]$windowsProvenanceBytes.Clone()
        $linuxBytes = [byte[]]$linuxProvenanceBytes.Clone()
        $ledger = New-ExternalTransferRuntimeLedger -Category 'native_transfer_real_host'
        $actualSucceeded = $false
        $result = $null
        try {
            try {
                $result = Invoke-ExternalTransferFormalOwnerConcurrentTransferCase `
                    -Ledger $ledger `
                    -CaseId 'push_21' `
                    -VerifiedWindowsProvenanceBytes $windowsBytes `
                    -VerifiedLinuxProvenanceBytes $linuxBytes `
                    -VerifiedComponentPaths $componentPaths `
                    -ExpectedContext $context `
                    -LocalPath 'C:\synthetic\source-21.bin' `
                    -RemotePath ("/tmp/$Scenario.bin") `
                    -TransferGrantInputHandle $transferHandle `
                    -StatusGrantInputHandle $statusHandle `
                    -TransferDeadlineMilliseconds 3000 `
                    -StatusDeadlineMilliseconds 2000
                $actualSucceeded = $true
            }
            catch {
                if ($ShouldSucceed) { throw }
            }
            Assert-AdapterTest ($actualSucceeded -eq $ShouldSucceed) (
                "concurrent formal owner scenario '$Scenario' acceptance differed"
            )
            Assert-AdapterTest (
                $transferHandle.IsClosed -and $statusHandle.IsClosed
            ) "concurrent formal owner scenario '$Scenario' retained a Grant handle"
            Assert-AdapterTest (
                @($windowsBytes | Where-Object { $_ -ne 0 }).Count -eq 0 -and
                @($linuxBytes | Where-Object { $_ -ne 0 }).Count -eq 0
            ) "concurrent formal owner scenario '$Scenario' retained provenance bytes"
            $private = & $contractModule {
                param($Ledger)
                $state = Resolve-LedgerState $Ledger
                [pscustomobject]@{
                    config_cleared = $null -eq $state.protected_formal_config
                    components_cleared = $null -eq $state.exact_release_components
                    has_observation = $state.observations.Contains('push_21')
                }
            } $ledger
            Assert-AdapterTest (
                $private.config_cleared -and $private.components_cleared -and
                $private.has_observation -eq $ShouldSucceed
            ) "concurrent formal owner scenario '$Scenario' did not clean private state"
            if ($ShouldSucceed) {
                Assert-AdapterTest (
                    $result.completed -eq 1 -and $result.blocked -eq 19 -and -not $result.sealed
                ) 'concurrent captured status evidence changed formal sealability'
            }
        }
        finally {
            $transferGrant.Dispose()
            $statusGrant.Dispose()
        }
    }

    Invoke-ConcurrentOwnerFixture -Scenario 'normal' -ShouldSucceed $true
    Invoke-ConcurrentOwnerFixture -Scenario 'context-mismatch' -ShouldSucceed $false
    Invoke-ConcurrentOwnerFixture -Scenario 'revision-ahead' -ShouldSucceed $false
    Invoke-ConcurrentOwnerFixture -Scenario 'late-status' -ShouldSucceed $false

    $childLaunchMarker = Join-Path $fixtureRoot 'formal-child-launched.marker'
    function ConvertTo-InvalidLinuxProvenanceBytes {
        param(
            [Parameter(Mandatory = $true)]
            [AllowEmptyCollection()]
            [object[]]$BinaryComponents
        )
        return [Text.UTF8Encoding]::new($false, $true).GetBytes((
            [pscustomobject][ordered]@{
                schema_version = 2; platform = 'linux-x86_64'
                binary_components = $BinaryComponents
            } | ConvertTo-Json -Compress -Depth 8
        ))
    }
    function Assert-NativeHelperProvenanceRejectedBeforeChild {
        param(
            [Parameter(Mandatory = $true)][string]$Description,
            [Parameter(Mandatory = $true)][byte[]]$InvalidLinuxBytes
        )
        Remove-Item -LiteralPath $childLaunchMarker -Force -ErrorAction SilentlyContinue
        $transferGrant = [IO.File]::Open(
            $ownerGrantPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read
        )
        $statusGrant = [IO.File]::Open(
            $ownerGrantPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read
        )
        $transferHandle = $transferGrant.SafeFileHandle
        $statusHandle = $statusGrant.SafeFileHandle
        [Serctl.AdapterRuntimeSelfTest.Native]::MakeInheritable(
            $transferHandle.DangerousGetHandle()
        )
        [Serctl.AdapterRuntimeSelfTest.Native]::MakeInheritable(
            $statusHandle.DangerousGetHandle()
        )
        $windowsBytes = [byte[]]$windowsProvenanceBytes.Clone()
        $rejected = $false
        try {
            try {
                Invoke-ExternalTransferFormalOwnerConcurrentTransferCase `
                    -Ledger (New-ExternalTransferRuntimeLedger -Category 'native_transfer_real_host') `
                    -CaseId 'push_21' `
                    -VerifiedWindowsProvenanceBytes $windowsBytes `
                    -VerifiedLinuxProvenanceBytes $InvalidLinuxBytes `
                    -VerifiedComponentPaths $componentPaths `
                    -ExpectedContext $context `
                    -LocalPath 'C:\synthetic\source-21.bin' `
                    -RemotePath '/tmp/identity-rejected.bin' `
                    -TransferGrantInputHandle $transferHandle `
                    -StatusGrantInputHandle $statusHandle `
                    -TransferDeadlineMilliseconds 2000 `
                    -StatusDeadlineMilliseconds 1000 | Out-Null
            }
            catch { $rejected = $true }
            Assert-AdapterTest $rejected "$Description was accepted"
            Assert-AdapterTest (-not (Test-Path -LiteralPath $childLaunchMarker)) (
                "$Description launched a child before provenance rejection"
            )
            Assert-AdapterTest ($transferHandle.IsClosed -and $statusHandle.IsClosed) (
                "$Description retained a Grant handle"
            )
            Assert-AdapterTest (
                @($windowsBytes | Where-Object { $_ -ne 0 }).Count -eq 0 -and
                @($InvalidLinuxBytes | Where-Object { $_ -ne 0 }).Count -eq 0
            ) "$Description retained provenance bytes"
        }
        finally {
            $transferGrant.Dispose()
            $statusGrant.Dispose()
            Remove-Item -LiteralPath $childLaunchMarker -Force -ErrorAction SilentlyContinue
        }
    }

    $helperSizeDrift = [pscustomobject][ordered]@{
        name = 'serctl-xfer'; binary_size = [long]($componentSize + 1)
        sha256 = $componentHash
        version = [string]$components.helper.version
    }
    $helperHashDrift = [pscustomobject][ordered]@{
        name = 'serctl-xfer'; binary_size = [long]$componentSize
        sha256 = ('d' * 64)
        version = [string]$components.helper.version
    }
    $helperVersionDrift = [pscustomobject][ordered]@{
        name = 'serctl-xfer'; binary_size = [long]$componentSize
        sha256 = $componentHash
        version = 'serctl-xfer 1.0.0-beta (git 0123456789ab; transfer protocol v2)'
    }
    $helperUnknownField = [pscustomobject][ordered]@{
        name = 'serctl-xfer'; binary_size = [long]$componentSize
        sha256 = $componentHash
        version = [string]$components.helper.version
        future = $true
    }
    foreach ($invalid in @(
        [pscustomobject]@{ description = 'missing Linux helper record'; components = [object[]]@() }
        [pscustomobject]@{ description = 'Linux helper size drift'; components = [object[]]@($helperSizeDrift) }
        [pscustomobject]@{ description = 'Linux helper hash drift'; components = [object[]]@($helperHashDrift) }
        [pscustomobject]@{ description = 'Linux helper version drift'; components = [object[]]@($helperVersionDrift) }
        [pscustomobject]@{ description = 'Linux helper unknown field'; components = [object[]]@($helperUnknownField) }
    )) {
        Assert-NativeHelperProvenanceRejectedBeforeChild `
            -Description ([string]$invalid.description) `
            -InvalidLinuxBytes (ConvertTo-InvalidLinuxProvenanceBytes $invalid.components)
    }

    $ownerGrant = [IO.File]::Open(
        $ownerGrantPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read
    )
    $ownerGrantHandle = $ownerGrant.SafeFileHandle
    [Serctl.AdapterRuntimeSelfTest.Native]::MakeInheritable(
        $ownerGrantHandle.DangerousGetHandle()
    )
    $ownerWindowsBytes = [byte[]]$windowsProvenanceBytes.Clone()
    $ownerLinuxBytes = [byte[]]$linuxProvenanceBytes.Clone()
    $ownerLedger = New-ExternalTransferRuntimeLedger -Category 'openssh_dropbear_interop'
    $ownerStatus = Invoke-ExternalTransferFormalOwnerCase `
        -Ledger $ownerLedger `
        -CaseId 'OpenSSH_exec' `
        -VerifiedWindowsProvenanceBytes $ownerWindowsBytes `
        -VerifiedLinuxProvenanceBytes $ownerLinuxBytes `
        -VerifiedComponentPaths $componentPaths `
        -ExpectedContext $context `
        -GrantInputHandle $ownerGrantHandle `
        -DeadlineMilliseconds 2000
    Assert-AdapterTest (
        $ownerStatus.completed -eq 1 -and $ownerStatus.blocked -eq 9 -and
        -not $ownerStatus.sealed -and $ownerGrantHandle.IsClosed
    ) 'exact-tag formal owner did not remain unsealed after one derived child receipt'
    Assert-AdapterTest (
        @($ownerWindowsBytes | Where-Object { $_ -ne 0 }).Count -eq 0 -and
        @($ownerLinuxBytes | Where-Object { $_ -ne 0 }).Count -eq 0
    ) 'formal owner retained verified provenance bytes'
    $ownerPrivateState = & $contractModule {
        param($Ledger)
        $state = Resolve-LedgerState $Ledger
        [pscustomobject]@{
            config_cleared = $null -eq $state.protected_formal_config
            components_cleared = $null -eq $state.exact_release_components
            stored_receipt = [string]$state.observations['OpenSSH_exec'].receipt_base64
        }
    } $ownerLedger
    Assert-AdapterTest (
        $ownerPrivateState.config_cleared -and $ownerPrivateState.components_cleared -and
        -not [string]::IsNullOrWhiteSpace($ownerPrivateState.stored_receipt)
    ) 'formal owner left protected inputs live or failed to retain its derived receipt'

    $reuseWindowsBytes = [byte[]]$windowsProvenanceBytes.Clone()
    $reuseLinuxBytes = [byte[]]$linuxProvenanceBytes.Clone()
    Assert-AdapterRejected -Description 'formal owner Grant handle reuse' -Action {
        Invoke-ExternalTransferFormalOwnerCase `
            -Ledger (New-ExternalTransferRuntimeLedger -Category 'openssh_dropbear_interop') `
            -CaseId 'OpenSSH_exec' `
            -VerifiedWindowsProvenanceBytes $reuseWindowsBytes `
            -VerifiedLinuxProvenanceBytes $reuseLinuxBytes `
            -VerifiedComponentPaths $componentPaths `
            -ExpectedContext $context `
            -GrantInputHandle $ownerGrantHandle `
            -DeadlineMilliseconds 2000
    }
    Assert-AdapterTest (
        @($reuseWindowsBytes | Where-Object { $_ -ne 0 }).Count -eq 0 -and
        @($reuseLinuxBytes | Where-Object { $_ -ne 0 }).Count -eq 0
    ) 'Grant handle reuse rejection retained provenance bytes'
    $ownerGrant.Dispose()

    $substitutedWindows = [Text.UTF8Encoding]::new($false, $true).GetBytes(
        [Text.UTF8Encoding]::new($false, $true).GetString($windowsProvenanceBytes).Replace(
            $componentHash, ('D' * 64)
        )
    )
    $substitutionGrant = [IO.File]::Open(
        $ownerGrantPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read
    )
    $substitutionGrantHandle = $substitutionGrant.SafeFileHandle
    [Serctl.AdapterRuntimeSelfTest.Native]::MakeInheritable(
        $substitutionGrantHandle.DangerousGetHandle()
    )
    $substitutionLinux = [byte[]]$linuxProvenanceBytes.Clone()
    Assert-AdapterRejected -Description 'verified exact component byte substitution' -Action {
        Invoke-ExternalTransferFormalOwnerCase `
            -Ledger (New-ExternalTransferRuntimeLedger -Category 'openssh_dropbear_interop') `
            -CaseId 'OpenSSH_exec' `
            -VerifiedWindowsProvenanceBytes $substitutedWindows `
            -VerifiedLinuxProvenanceBytes $substitutionLinux `
            -VerifiedComponentPaths $componentPaths `
            -ExpectedContext $context `
            -GrantInputHandle $substitutionGrantHandle `
            -DeadlineMilliseconds 2000
    }
    Assert-AdapterTest ($substitutionGrantHandle.IsClosed) (
        'component substitution failure did not consume the Grant handle'
    )
    $substitutionGrant.Dispose()

    $directoryHandle = [Serctl.AdapterRuntimeSelfTest.Native]::OpenDirectory($fixtureRoot)
    $directoryWindows = [byte[]]$windowsProvenanceBytes.Clone()
    $directoryLinux = [byte[]]$linuxProvenanceBytes.Clone()
    Assert-AdapterRejected -Description 'formal owner directory Grant handle type' -Action {
        Invoke-ExternalTransferFormalOwnerCase `
            -Ledger (New-ExternalTransferRuntimeLedger -Category 'openssh_dropbear_interop') `
            -CaseId 'OpenSSH_exec' `
            -VerifiedWindowsProvenanceBytes $directoryWindows `
            -VerifiedLinuxProvenanceBytes $directoryLinux `
            -VerifiedComponentPaths $componentPaths `
            -ExpectedContext $context `
            -GrantInputHandle $directoryHandle `
            -DeadlineMilliseconds 2000
    }
    Assert-AdapterTest $directoryHandle.IsClosed (
        'rejected directory Grant handle was not consumed'
    )

    $lateGrant = [IO.File]::Open(
        $ownerGrantPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read
    )
    [Serctl.AdapterRuntimeSelfTest.Native]::MakeInheritable(
        $lateGrant.SafeFileHandle.DangerousGetHandle()
    )
    $lateWindows = [byte[]]$windowsProvenanceBytes.Clone()
    $lateLinux = [byte[]]$linuxProvenanceBytes.Clone()
    Assert-AdapterRejected -Description 'formal owner component late mutation' -Action {
        Invoke-ExternalTransferFormalOwnerCase `
            -Ledger (New-ExternalTransferRuntimeLedger -Category 'openssh_dropbear_interop') `
            -CaseId 'OpenSSH_directory' `
            -VerifiedWindowsProvenanceBytes $lateWindows `
            -VerifiedLinuxProvenanceBytes $lateLinux `
            -VerifiedComponentPaths $componentPaths `
            -ExpectedContext $context `
            -GrantInputHandle $lateGrant.SafeFileHandle `
            -DeadlineMilliseconds 2000
    }
    $lateGrant.Dispose()
    [IO.File]::Copy($helperPath, $daemonFixturePath, $true)

    $summary = & $contractModule {
        param($ApplicationPath, $InputBytes, $Context)
        Invoke-SerctlSyntheticRuntimeAdapterProbe `
            -ApplicationPath $ApplicationPath `
            -Category 'openssh_dropbear_interop' `
            -CaseId 'OpenSSH_tunnel_local' `
            -Scenario 'success' `
            -StandardInputBytes $InputBytes `
            -ExpectedContext $Context
    } $helperPath ([byte[]]$tunnelRequestBytes.Clone()) $context
    Assert-AdapterTest (-not $summary.sealable) 'synthetic parser probe became sealable'

    Assert-AdapterRejected -Description 'synthetic parser summary as formal observation' -Action {
        $ledger = New-ExternalTransferRuntimeLedger -Category 'openssh_dropbear_interop'
        & $contractModule {
            param($Ledger, $Summary)
            Accept-ExternalTransferRuntimeAdapterObservation `
                -State (Resolve-LedgerState -Ledger $Ledger) `
                -Observation $Summary
        } $ledger $summary
    }
    Assert-AdapterRejected -Description 'controlled transcript hash mismatch' -Action {
        & $contractModule {
            param($ApplicationPath, $InputBytes, $Context)
            Invoke-SerctlSyntheticRuntimeAdapterProbe $ApplicationPath `
                'openssh_dropbear_interop' 'OpenSSH_tunnel_local' 'wrong-hash' $InputBytes $Context
        } $helperPath ([byte[]]$tunnelRequestBytes.Clone()) $context
    }
    Assert-AdapterRejected -Description 'controlled process deadline' -Action {
        & $contractModule {
            param($ApplicationPath, $InputBytes, $Context)
            Invoke-SerctlSyntheticRuntimeAdapterProbe $ApplicationPath `
                'openssh_dropbear_interop' 'OpenSSH_tunnel_local' 'deadline' $InputBytes $Context
        } $helperPath ([byte[]]$tunnelRequestBytes.Clone()) $context
    }
    Assert-AdapterRejected -Description 'controlled process-tree deadline' -Action {
        & $contractModule {
            param($ApplicationPath, $InputBytes, $Context)
            Invoke-SerctlSyntheticRuntimeAdapterProbe $ApplicationPath `
                'openssh_dropbear_interop' 'OpenSSH_tunnel_local' `
                'process-tree-deadline' $InputBytes $Context
        } $helperPath ([byte[]]$tunnelRequestBytes.Clone()) $context
    }
    Assert-AdapterRejected -Description 'controlled stdout flood' -Action {
        & $contractModule {
            param($ApplicationPath, $InputBytes, $Context)
            Invoke-SerctlSyntheticRuntimeAdapterProbe $ApplicationPath `
                'openssh_dropbear_interop' 'OpenSSH_tunnel_local' 'stdout-flood' $InputBytes $Context
        } $helperPath ([byte[]]$tunnelRequestBytes.Clone()) $context
    }
    $wrongExpectedContext = [pscustomobject][ordered]@{
        profile_id = $profileId; profile_generation = [uint64]7
        observed_host_key_sha256 = $hostKey
        server_identification = 'SSH-2.0-OpenSSH_other'
        transport_attempt_id = $attemptId; context_sha256 = 'D' * 64
    }
    Assert-AdapterRejected -Description 'controlled process context substitution' -Action {
        & $contractModule {
            param($ApplicationPath, $InputBytes, $Context)
            Invoke-SerctlSyntheticRuntimeAdapterProbe $ApplicationPath `
                'openssh_dropbear_interop' 'OpenSSH_tunnel_local' 'success' $InputBytes $Context
        } $helperPath ([byte[]]$tunnelRequestBytes.Clone()) $wrongExpectedContext
    }

    $duplicateId = [Text.UTF8Encoding]::new($false).GetString($execBytes).Replace(
        '"request_id":2', '"request_id":1'
    )
    Assert-AdapterRejected -Description 'duplicate request id' -Action {
        & $contractModule { param($Text, $Context)
            ConvertFrom-SerctlAgentTranscript ([Text.Encoding]::UTF8.GetBytes($Text)) `
                'openssh_dropbear_interop' 'OpenSSH_exec' $Context
        } $duplicateId $context
    }
    $execLines = [Text.UTF8Encoding]::new($false).GetString($execBytes).TrimEnd("`n") -split "`n"
    $outOfOrder = [Text.Encoding]::UTF8.GetBytes(($execLines[1], $execLines[0] -join "`n") + "`n")
    Assert-AdapterRejected -Description 'out-of-order terminal' -Action {
        & $contractModule { param($Bytes, $Context)
            ConvertFrom-SerctlAgentTranscript $Bytes 'openssh_dropbear_interop' 'OpenSSH_exec' $Context
        } $outOfOrder $context
    }
    $multipleTerminal = [byte[]]($execBytes + [Text.Encoding]::UTF8.GetBytes($execLines[1] + "`n"))
    Assert-AdapterRejected -Description 'multiple terminal for one request' -Action {
        & $contractModule { param($Bytes, $Context)
            ConvertFrom-SerctlAgentTranscript $Bytes 'openssh_dropbear_interop' 'OpenSSH_exec' $Context
        } $multipleTerminal $context
    }
    $unknown = [Text.UTF8Encoding]::new($false).GetString($execBytes).Replace(
        '"code":0,', '"code":0,"unknown":true,'
    )
    Assert-AdapterRejected -Description 'unknown terminal field' -Action {
        & $contractModule { param($Text, $Context)
            ConvertFrom-SerctlAgentTranscript ([Text.Encoding]::UTF8.GetBytes($Text)) `
                'openssh_dropbear_interop' 'OpenSSH_exec' $Context
        } $unknown $context
    }
    $tunnelMismatch = [Text.UTF8Encoding]::new($false).GetString($tunnelBytes).Replace(
        $tunnelId, 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
    ).Replace('"tunnel_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","mode":"local","stage":"ready"',
        '"tunnel_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","mode":"local","stage":"ready"')
    Assert-AdapterRejected -Description 'tunnel id mismatch' -Action {
        & $contractModule { param($Text, $Context)
            ConvertFrom-SerctlAgentTranscript ([Text.Encoding]::UTF8.GetBytes($Text)) `
                'openssh_dropbear_interop' 'OpenSSH_tunnel_local' $Context
        } $tunnelMismatch $context
    }
    $tunnelLines = [Text.UTF8Encoding]::new($false).GetString($tunnelBytes).TrimEnd("`n") -split "`n"
    $tunnelContextFragment = ',"operation_context_id":"' + $tunnelOperationContextId + '"'
    $missingTunnelContext = [string]::Join("`n", @(
        $tunnelLines[0],
        $tunnelLines[1].Replace($tunnelContextFragment, ''),
        $tunnelLines[2],
        $tunnelLines[3]
    )) + "`n"
    Assert-AdapterRejected -Description 'missing tunnel operation context' -Action {
        & $contractModule { param($Text, $Context)
            ConvertFrom-SerctlAgentTranscript ([Text.Encoding]::UTF8.GetBytes($Text)) `
                'openssh_dropbear_interop' 'OpenSSH_tunnel_local' $Context
        } $missingTunnelContext $context
    }
    $substitutedTunnelContext = [string]::Join("`n", @(
        $tunnelLines[0],
        $tunnelLines[1],
        $tunnelLines[2].Replace($tunnelOperationContextId, ('55' * 32)),
        $tunnelLines[3]
    )) + "`n"
    Assert-AdapterRejected -Description 'tunnel operation context substitution' -Action {
        & $contractModule { param($Text, $Context)
            ConvertFrom-SerctlAgentTranscript ([Text.Encoding]::UTF8.GetBytes($Text)) `
                'openssh_dropbear_interop' 'OpenSSH_tunnel_local' $Context
        } $substitutedTunnelContext $context
    }
    $tunnelRevisionRollback = [string]::Join("`n", @(
        $tunnelLines[0],
        $tunnelLines[1],
        $tunnelLines[2],
        $tunnelLines[3].Replace('"revision":3', '"revision":0')
    )) + "`n"
    Assert-AdapterRejected -Description 'tunnel revision rollback' -Action {
        & $contractModule { param($Text, $Context)
            ConvertFrom-SerctlAgentTranscript ([Text.Encoding]::UTF8.GetBytes($Text)) `
                'openssh_dropbear_interop' 'OpenSSH_tunnel_local' $Context
        } $tunnelRevisionRollback $context
    }
    & $contractModule {
        Assert-SerctlDaemonStatusData ([pscustomobject][ordered]@{
            profile='prod'; host='example.invalid'; user='runner'; started_unix=[int64]1
            operation_context_id=('55' * 32); revision=[uint64]1
        }) ('11' * 32)
        Assert-SerctlCreateDirData ([pscustomobject][ordered]@{
            created='/tmp/owned'; operation_context_id=('66' * 32); revision=[uint64]1
        }) ('11' * 32)
    }
    Assert-AdapterRejected -Description 'missing daemon-status operation context' -Action {
        & $contractModule {
            Assert-SerctlDaemonStatusData ([pscustomobject][ordered]@{
                profile='prod'; host='example.invalid'; user='runner'; started_unix=[int64]1
                revision=[uint64]1
            }) $null
        }
    }
    Assert-AdapterRejected -Description 'create-dir operation context substitution' -Action {
        & $contractModule {
            Assert-SerctlCreateDirData ([pscustomobject][ordered]@{
                created='/tmp/owned'; operation_context_id=('11' * 32); revision=[uint64]1
            }) ('11' * 32)
        }
    }
    Assert-AdapterRejected -Description 'nonmonotonic transfer confirmation' -Action {
        & $contractModule {
            $prior = [pscustomobject]@{
                total_bytes = [uint64]21; confirmed_bytes = [uint64]20
                durable_bytes = [uint64]20; updated_unix_ms = [uint64]10
                revision = [uint64]2; stage = 'transferring'; terminal = $false
            }
            $progress = [pscustomobject][ordered]@{
                schema_version=1; event='progress'; transfer_id='00112233445566778899aabbccddeeff'
                operation_context_id=('ab' * 32); revision=[uint64]3
                direction='push'; stage='transferring'; total_bytes=[uint64]21
                confirmed_bytes=[uint64]19; durable_bytes=[uint64]19; window_bps=1.0
                average_bps=1.0; eta_ms=$null; backend='native'; chunk_bytes=[uint32]1
                window_bytes=[uint32]1; updated_unix_ms=[uint64]11
            }
            Assert-SerctlTransferProgress $progress $progress.transfer_id 'push' `
                $progress.operation_context_id 1 $prior
        }
    }
    Assert-AdapterRejected -Description 'transfer stage regression' -Action {
        & $contractModule {
            $prior = [pscustomobject]@{
                total_bytes=[uint64]21; confirmed_bytes=[uint64]10; durable_bytes=[uint64]10
                updated_unix_ms=[uint64]10; revision=[uint64]2
                stage='verifying'; terminal=$false
            }
            $progress = [pscustomobject][ordered]@{
                schema_version=1; event='progress'; transfer_id='00112233445566778899aabbccddeeff'
                operation_context_id=('ab' * 32); revision=[uint64]3
                direction='push'; stage='transferring'; total_bytes=[uint64]21
                confirmed_bytes=[uint64]10; durable_bytes=[uint64]10; window_bps=1.0
                average_bps=1.0; eta_ms=$null; backend='native'; chunk_bytes=[uint32]1
                window_bytes=[uint32]1; updated_unix_ms=[uint64]11
            }
            Assert-SerctlTransferProgress $progress $progress.transfer_id 'push' `
                $progress.operation_context_id 1 $prior
        }
    }
    $nonterminalTransfer = [Text.UTF8Encoding]::new($false).GetString($transferBytes).Replace(
        '"stage":"completed"', '"stage":"transferring"'
    )
    Assert-AdapterRejected -Description 'transfer transcript without terminal status' -Action {
        & $contractModule { param($Text, $Context)
            ConvertFrom-SerctlAgentTranscript ([Text.Encoding]::UTF8.GetBytes($Text)) `
                'native_transfer_real_host' 'push_21' $Context
        } $nonterminalTransfer $context
    }
    Assert-AdapterRejected -Description 'terminal transfer replay' -Action {
        & $contractModule {
            $prior = [pscustomobject]@{
                total_bytes=[uint64]21; confirmed_bytes=[uint64]21; durable_bytes=[uint64]21
                updated_unix_ms=[uint64]10; revision=[uint64]3
                stage='completed'; terminal=$true
            }
            $progress = [pscustomobject][ordered]@{
                schema_version=1; event='completed'; transfer_id='00112233445566778899aabbccddeeff'
                operation_context_id=('ab' * 32); revision=[uint64]4
                direction='push'; stage='completed'; total_bytes=[uint64]21
                confirmed_bytes=[uint64]21; durable_bytes=[uint64]21; window_bps=1.0
                average_bps=1.0; eta_ms=$null; backend='native'; chunk_bytes=[uint32]1
                window_bytes=[uint32]1; updated_unix_ms=[uint64]11
            }
            Assert-SerctlTransferProgress $progress $progress.transfer_id 'push' `
                $progress.operation_context_id 1 $prior
        }
    }
    $forgedContext = [Text.UTF8Encoding]::new($false).GetString($transferBytes).Replace(
        ('"operation_context_id":"' + $operationContextId + '","revision":4,"direction"'),
        ('"operation_context_id":"' + ('cd' * 32) + '","revision":4,"direction"')
    )
    Assert-AdapterRejected -Description 'transfer operation context substitution' -Action {
        & $contractModule { param($Text, $Context)
            ConvertFrom-SerctlAgentTranscript ([Text.Encoding]::UTF8.GetBytes($Text)) `
                'native_transfer_real_host' 'push_21' $Context
        } $forgedContext $context
    }
    $revisionRollback = [Text.UTF8Encoding]::new($false).GetString($transferBytes).Replace(
        '"revision":4,"direction":"push"', '"revision":3,"direction":"push"'
    )
    Assert-AdapterRejected -Description 'transfer revision rollback' -Action {
        & $contractModule { param($Text, $Context)
            ConvertFrom-SerctlAgentTranscript ([Text.Encoding]::UTF8.GetBytes($Text)) `
                'native_transfer_real_host' 'push_21' $Context
        } $revisionRollback $context
    }
    $zeroRevision = [Text.UTF8Encoding]::new($false).GetString($transferBytes).Replace(
        '"revision":4,"bytes":21', '"revision":0,"bytes":21'
    )
    Assert-AdapterRejected -Description 'nonpositive transfer terminal revision' -Action {
        & $contractModule { param($Text, $Context)
            ConvertFrom-SerctlAgentTranscript ([Text.Encoding]::UTF8.GetBytes($Text)) `
                'native_transfer_real_host' 'push_21' $Context
        } $zeroRevision $context
    }
    $pathCanary = [Text.UTF8Encoding]::new($false).GetString($directoryBytes).Replace(
        '/tmp/artifact.bin', '/tmp/path_canary'
    )
    Assert-AdapterRejected -Description 'path canary' -Action {
        & $contractModule { param($Text, $Context)
            ConvertFrom-SerctlAgentTranscript ([Text.Encoding]::UTF8.GetBytes($Text)) `
                'openssh_dropbear_interop' 'OpenSSH_directory' $Context
        } $pathCanary $context
    }
    $credential = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes('password_canary'))
    $credentialCanary = [Text.UTF8Encoding]::new($false).GetString($execBytes).Replace('b2sK', $credential)
    Assert-AdapterRejected -Description 'credential canary in Base64 output' -Action {
        & $contractModule { param($Text, $Context)
            ConvertFrom-SerctlAgentTranscript ([Text.Encoding]::UTF8.GetBytes($Text)) `
                'openssh_dropbear_interop' 'OpenSSH_exec' $Context
        } $credentialCanary $context
    }
    $identityContextFragment = ',"operation_context_id":"' + ('11' * 32) + '","revision":1'
    Assert-AdapterRejected -Description 'missing connection-identity operation context' -Action {
        & $contractModule { param($Text, $Context)
            ConvertFrom-SerctlAgentTranscript ([Text.Encoding]::UTF8.GetBytes($Text)) `
                'openssh_dropbear_interop' 'OpenSSH_exec' $Context
        } ([Text.UTF8Encoding]::new($false).GetString($execBytes).Replace(
            $identityContextFragment, ''
        )) $context
    }
    $execText = [Text.UTF8Encoding]::new($false).GetString($execBytes)
    $execContextFragment = ',"operation_context_id":"' + ('22' * 32) + '","revision":1'
    Assert-AdapterRejected -Description 'missing exec operation context' -Action {
        & $contractModule { param($Text, $Context)
            ConvertFrom-SerctlAgentTranscript ([Text.Encoding]::UTF8.GetBytes($Text)) `
                'openssh_dropbear_interop' 'OpenSSH_exec' $Context
        } ($execText.Replace($execContextFragment, '')) $context
    }
    Assert-AdapterRejected -Description 'exec operation context substitution' -Action {
        & $contractModule { param($Text, $Context)
            ConvertFrom-SerctlAgentTranscript ([Text.Encoding]::UTF8.GetBytes($Text)) `
                'openssh_dropbear_interop' 'OpenSSH_exec' $Context
        } ($execText.Replace(('22' * 32), ('11' * 32))) $context
    }
    $directoryText = [Text.UTF8Encoding]::new($false).GetString($directoryBytes)
    $directoryContextFragment = ',"operation_context_id":"' + ('33' * 32) + '","revision":1'
    Assert-AdapterRejected -Description 'missing list-dir operation context' -Action {
        & $contractModule { param($Text, $Context)
            ConvertFrom-SerctlAgentTranscript ([Text.Encoding]::UTF8.GetBytes($Text)) `
                'openssh_dropbear_interop' 'OpenSSH_directory' $Context
        } ($directoryText.Replace($directoryContextFragment, '')) $context
    }
    Assert-AdapterRejected -Description 'list-dir operation context substitution' -Action {
        & $contractModule { param($Text, $Context)
            ConvertFrom-SerctlAgentTranscript ([Text.Encoding]::UTF8.GetBytes($Text)) `
                'openssh_dropbear_interop' 'OpenSSH_directory' $Context
        } ($directoryText.Replace(('33' * 32), ('11' * 32))) $context
    }
    Assert-AdapterRejected -Description 'transfer-pull direction substitution' -Action {
        & $contractModule { param($Bytes, $Context)
            ConvertFrom-SerctlAgentTranscript $Bytes 'native_transfer_real_host' 'pull_21' $Context
        } $transferBytes $context
    }
    Assert-AdapterRejected -Description 'formal real-host case while supervisor prerequisites are open' -Action {
        Invoke-ExternalTransferRuntimeCase -Ledger (
            New-ExternalTransferRuntimeLedger -Category 'openssh_dropbear_interop'
        ) -CaseId 'OpenSSH_exec'
    }
}
finally {
    foreach ($bytes in @(
        $tunnelBytes, $tunnelRequestBytes, $execBytes, $execRequestBytes,
        $directoryBytes, $directoryRequestBytes, $transferBytes, $pullBytes
    )) {
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
    if (Test-Path -LiteralPath $fixtureRoot -PathType Container) {
        Assert-AdapterTest ([IO.File]::ReadAllText($ownerPath).Trim() -ceq $ownerToken) (
            'synthetic fixture ownership changed before cleanup'
        )
        Remove-Item -LiteralPath $fixtureRoot -Recurse -Force
    }
}

Write-Host (
    'External transfer runtime adapter self-test passed ' +
    '(closed synthetic parsers only; every formal real-host case remains BLOCKED).'
)
