[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-OwnerTest {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "isolated formal owner self-test failed: $Message" }
}

function ConvertTo-OwnerJsonBytes {
    param($Value)
    return ,([Text.UTF8Encoding]::new($false, $true).GetBytes(
        (($Value | ConvertTo-Json -Compress -Depth 12) + "`n")
    ))
}

function ConvertTo-OwnerNdjsonBytes {
    param([object[]]$Values)
    return ,([Text.UTF8Encoding]::new($false, $true).GetBytes(
        ((@($Values) | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 12 }) -join "`n") + "`n"
    ))
}

$runnerPath = Join-Path $PSScriptRoot 'Invoke-IsolatedExternalTransferFormalOwner.ps1'
$launcherPath = Join-Path $PSScriptRoot 'ExternalTransferIsolatedOwnerLauncher.ps1'
foreach ($path in @($runnerPath, $launcherPath)) {
    $tokens = $null
    $errors = $null
    [void][Management.Automation.Language.Parser]::ParseFile(
        $path, [ref]$tokens, [ref]$errors
    )
    Assert-OwnerTest (@($errors).Count -eq 0) "$path does not parse"
}
$runnerSource = Get-Content -LiteralPath $runnerPath -Raw -Encoding utf8
foreach ($required in @(
    'serctl-isolated-formal-owner-input-v1',
    'serctl-isolated-formal-owner-receipt-v2',
    '$fixedCaseIds = @(',
    '''OpenSSH_exec'', ''Dropbear_exec'', ''OpenSSH_directory''',
    '''OpenSSH_tunnel_local'', ''OpenSSH_tunnel_remote'', ''OpenSSH_tunnel_dynamic''',
    '''OpenSSH_sftp'', ''OpenSSH_native'', ''Dropbear_sftp'', ''Dropbear_native''',
    'evidence_context_sha256 = [string]$config.evidence_context_sha256',
    'component_set_base64 = [Convert]::ToBase64String($componentSetBytes)',
    'Write-ExternalTransferOfficialReceiptHandleInternal',
    'Invoke-SerctlFormalRuntimeProcessSkeletonInternal',
    'Invoke-SerctlFormalManagedTunnelInternal',
    'Invoke-IsolatedOwnerInteropTransfer',
    'Invoke-SerctlFormalConcurrentTransferInternal'
)) {
    Assert-OwnerTest $runnerSource.Contains($required) "runner omits '$required'"
}
foreach ($forbidden in @(
    '[bool]$Passed', '$Result', '$StructuredResult', '$ExpectedStdout',
    '$ExpectedTranscript', '$ReceiptBytes', 'ConvertFrom-Json', 'Invoke-Expression',
    '[string]$ReceiptPath', 'windows_provenance_base64', 'linux_provenance_base64'
)) {
    Assert-OwnerTest (-not $runnerSource.Contains($forbidden)) (
        "runner accepts or uses forbidden evidence input '$forbidden'"
    )
}

. $launcherPath

$fixtureRoot = Join-Path (
    Join-Path ([IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))) 'target'
) ('isolated-formal-owner-selftest-' + [Guid]::NewGuid().ToString('N'))
[IO.Directory]::CreateDirectory($fixtureRoot) | Out-Null
$ownerPath = Join-Path $fixtureRoot '.owner'
$ownerToken = [Guid]::NewGuid().ToString('N')
[IO.File]::WriteAllText($ownerPath, $ownerToken, [Text.UTF8Encoding]::new($false))

$openSshContext = [pscustomobject][ordered]@{
    profile_id = '0123456789abcdef0123456789abcdef'; profile_generation = [uint64]7
    observed_host_key_sha256 = 'SHA256:' + ('A' * 43)
    server_identification = 'SSH-2.0-OpenSSH_isolated_fixture'
    transport_attempt_id = 'B' * 32; context_sha256 = 'C' * 64
}
$dropbearContext = [pscustomobject][ordered]@{
    profile_id = 'fedcba9876543210fedcba9876543210'; profile_generation = [uint64]8
    observed_host_key_sha256 = 'SHA256:' + ('D' * 43)
    server_identification = 'SSH-2.0-dropbear_isolated_fixture'
    transport_attempt_id = 'D' * 32; context_sha256 = 'E' * 64
}
$directoryContext = [pscustomobject][ordered]@{
    profile_id = '11223344556677889900aabbccddeeff'; profile_generation = [uint64]9
    observed_host_key_sha256 = 'SHA256:' + ('F' * 43)
    server_identification = 'SSH-2.0-OpenSSH_directory_fixture'
    transport_attempt_id = 'F' * 32; context_sha256 = 'A' * 64
}
$localTunnelContext = [pscustomobject][ordered]@{
    profile_id = '223344556677889900aabbccddeeff11'; profile_generation = [uint64]10
    observed_host_key_sha256 = 'SHA256:' + ('G' * 43)
    server_identification = 'SSH-2.0-OpenSSH_tunnel_local_fixture'
    transport_attempt_id = '1' * 32; context_sha256 = '1' * 64
}
$remoteTunnelContext = [pscustomobject][ordered]@{
    profile_id = '3344556677889900aabbccddeeff1122'; profile_generation = [uint64]11
    observed_host_key_sha256 = 'SHA256:' + ('H' * 43)
    server_identification = 'SSH-2.0-OpenSSH_tunnel_remote_fixture'
    transport_attempt_id = '2' * 32; context_sha256 = '2' * 64
}
$dynamicTunnelContext = [pscustomobject][ordered]@{
    profile_id = '44556677889900aabbccddeeff112233'; profile_generation = [uint64]12
    observed_host_key_sha256 = 'SHA256:' + ('I' * 43)
    server_identification = 'SSH-2.0-OpenSSH_tunnel_dynamic_fixture'
    transport_attempt_id = '3' * 32; context_sha256 = '3' * 64
}
$openSshSftpContext = [pscustomobject][ordered]@{
    profile_id = '556677889900aabbccddeeff11223344'; profile_generation = [uint64]13
    observed_host_key_sha256 = 'SHA256:' + ('J' * 43)
    server_identification = 'SSH-2.0-OpenSSH_sftp_fixture'
    transport_attempt_id = '4' * 32; context_sha256 = '4' * 64
}
$openSshNativeContext = [pscustomobject][ordered]@{
    profile_id = '6677889900aabbccddeeff1122334455'; profile_generation = [uint64]14
    observed_host_key_sha256 = 'SHA256:' + ('K' * 43)
    server_identification = 'SSH-2.0-OpenSSH_native_fixture'
    transport_attempt_id = '5' * 32; context_sha256 = '5' * 64
}
$dropbearSftpContext = [pscustomobject][ordered]@{
    profile_id = '77889900aabbccddeeff112233445566'; profile_generation = [uint64]15
    observed_host_key_sha256 = 'SHA256:' + ('L' * 43)
    server_identification = 'SSH-2.0-dropbear_sftp_fixture'
    transport_attempt_id = '6' * 32; context_sha256 = '6' * 64
}
$dropbearNativeContext = [pscustomobject][ordered]@{
    profile_id = '889900aabbccddeeff11223344556677'; profile_generation = [uint64]16
    observed_host_key_sha256 = 'SHA256:' + ('M' * 43)
    server_identification = 'SSH-2.0-dropbear_native_fixture'
    transport_attempt_id = '7' * 32; context_sha256 = '7' * 64
}
$fixedPayloadBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes(
    "serctl-fixed-payload`n"
)
$fixedPayloadSha = [Security.Cryptography.SHA256]::Create()
try {
    $fixedPayloadHash = ([BitConverter]::ToString(
        $fixedPayloadSha.ComputeHash($fixedPayloadBytes)
    )).Replace('-', '')
}
finally { $fixedPayloadSha.Dispose() }
$execRequestBytes = ConvertTo-OwnerNdjsonBytes @(
    [pscustomobject][ordered]@{
        schema_version = 1; request_id = [uint64]1; op = 'ssh-connection-identity'
    },
    [pscustomobject][ordered]@{
        schema_version = 1; request_id = [uint64]2; op = 'exec'
        cmd = '/usr/bin/true'; timeout_ms = [uint64]30000
    }
)
$directoryRequestBytes = ConvertTo-OwnerNdjsonBytes @(
    [pscustomobject][ordered]@{
        schema_version = 1; request_id = [uint64]1; op = 'ssh-connection-identity'
    },
    [pscustomobject][ordered]@{
        schema_version = 1; request_id = [uint64]2; op = 'list-dir'
        path = '/tmp'; timeout_ms = [uint64]30000
    }
)
$openSshOutputBytes = ConvertTo-OwnerNdjsonBytes @(
    [pscustomobject][ordered]@{
        schema_version = 1; request_id = [uint64]1; ok = $true
        data = [pscustomobject][ordered]@{
            profile_id = $openSshContext.profile_id
            profile_generation = $openSshContext.profile_generation
            observed_host_key_sha256 = $openSshContext.observed_host_key_sha256
            pin_match = $true; server_identification = $openSshContext.server_identification
            transport_attempt_id = $openSshContext.transport_attempt_id
            operation_context_id = ('11' * 32); revision = [uint64]1
        }
    },
    [pscustomobject][ordered]@{
        schema_version = 1; request_id = [uint64]2; ok = $true
        data = [pscustomobject][ordered]@{
            stdout = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("ok`n"))
            stderr = ''; code = 0
            operation_context_id = ('22' * 32); revision = [uint64]1
        }
    }
)
$dropbearOutputBytes = ConvertTo-OwnerNdjsonBytes @(
    [pscustomobject][ordered]@{
        schema_version = 1; request_id = [uint64]1; ok = $true
        data = [pscustomobject][ordered]@{
            profile_id = $dropbearContext.profile_id
            profile_generation = $dropbearContext.profile_generation
            observed_host_key_sha256 = $dropbearContext.observed_host_key_sha256
            pin_match = $true; server_identification = $dropbearContext.server_identification
            transport_attempt_id = $dropbearContext.transport_attempt_id
            operation_context_id = ('33' * 32); revision = [uint64]1
        }
    },
    [pscustomobject][ordered]@{
        schema_version = 1; request_id = [uint64]2; ok = $true
        data = [pscustomobject][ordered]@{
            stdout = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes("ok`n"))
            stderr = ''; code = 0
            operation_context_id = ('44' * 32); revision = [uint64]1
        }
    }
)
$directoryOutputBytes = ConvertTo-OwnerNdjsonBytes @(
    [pscustomobject][ordered]@{
        schema_version = 1; request_id = [uint64]1; ok = $true
        data = [pscustomobject][ordered]@{
            profile_id = $directoryContext.profile_id
            profile_generation = $directoryContext.profile_generation
            observed_host_key_sha256 = $directoryContext.observed_host_key_sha256
            pin_match = $true; server_identification = $directoryContext.server_identification
            transport_attempt_id = $directoryContext.transport_attempt_id
            operation_context_id = ('55' * 32); revision = [uint64]1
        }
    },
    [pscustomobject][ordered]@{
        schema_version = 1; request_id = [uint64]2; ok = $true
        data = [pscustomobject][ordered]@{
            path = '/tmp'; entries = @([pscustomobject][ordered]@{
                name = 'artifact.bin'; path = '/tmp/artifact.bin'; is_dir = $false
                is_symlink = $false; size = [uint64]21; modified_unix = [uint32]123
            })
            operation_context_id = ('66' * 32); revision = [uint64]1
        }
    }
)

try {
    $helperPath = Join-Path $fixtureRoot 'serctl_cli.exe'
    $daemonPath = Join-Path $fixtureRoot 'serctl_daemon.exe'
    $xferPath = Join-Path $fixtureRoot 'serctl-xfer'
    $sourcePath = Join-Path $fixtureRoot 'isolated-owner-fixture.cs'
    $expectedExecInput = [Convert]::ToBase64String($execRequestBytes)
    $expectedDirectoryInput = [Convert]::ToBase64String($directoryRequestBytes)
    $openSshOutput = [Convert]::ToBase64String($openSshOutputBytes)
    $dropbearOutput = [Convert]::ToBase64String($dropbearOutputBytes)
    $directoryOutput = [Convert]::ToBase64String($directoryOutputBytes)
    $openSshGrantValue = [Convert]::ToBase64String(
        [Text.UTF8Encoding]::new($false).GetBytes('non-secret-openssh-exec-grant')
    )
    $dropbearGrantValue = [Convert]::ToBase64String(
        [Text.UTF8Encoding]::new($false).GetBytes('non-secret-dropbear-exec-grant')
    )
    $directoryGrantValue = [Convert]::ToBase64String(
        [Text.UTF8Encoding]::new($false).GetBytes('non-secret-openssh-directory-grant')
    )
    $localOpenGrantValue = [Convert]::ToBase64String(
        [Text.UTF8Encoding]::new($false).GetBytes('non-secret-local-open-grant')
    )
    $localStatusGrantValue = [Convert]::ToBase64String(
        [Text.UTF8Encoding]::new($false).GetBytes('non-secret-local-status-grant')
    )
    $localCancelGrantValue = [Convert]::ToBase64String(
        [Text.UTF8Encoding]::new($false).GetBytes('non-secret-local-cancel-grant')
    )
    $remoteOpenGrantValue = [Convert]::ToBase64String(
        [Text.UTF8Encoding]::new($false).GetBytes('non-secret-remote-open-grant')
    )
    $remoteStatusGrantValue = [Convert]::ToBase64String(
        [Text.UTF8Encoding]::new($false).GetBytes('non-secret-remote-status-grant')
    )
    $remoteCancelGrantValue = [Convert]::ToBase64String(
        [Text.UTF8Encoding]::new($false).GetBytes('non-secret-remote-cancel-grant')
    )
    $dynamicOpenGrantValue = [Convert]::ToBase64String(
        [Text.UTF8Encoding]::new($false).GetBytes('non-secret-dynamic-open-grant')
    )
    $dynamicStatusGrantValue = [Convert]::ToBase64String(
        [Text.UTF8Encoding]::new($false).GetBytes('non-secret-dynamic-status-grant')
    )
    $dynamicCancelGrantValue = [Convert]::ToBase64String(
        [Text.UTF8Encoding]::new($false).GetBytes('non-secret-dynamic-cancel-grant')
    )
    $openSshSftpTransferGrantValue = [Convert]::ToBase64String(
        [Text.UTF8Encoding]::new($false).GetBytes('non-secret-openssh-sftp-transfer-grant')
    )
    $openSshSftpStatusGrantValue = [Convert]::ToBase64String(
        [Text.UTF8Encoding]::new($false).GetBytes('non-secret-openssh-sftp-status-grant')
    )
    $openSshNativeTransferGrantValue = [Convert]::ToBase64String(
        [Text.UTF8Encoding]::new($false).GetBytes('non-secret-openssh-native-transfer-grant')
    )
    $openSshNativeStatusGrantValue = [Convert]::ToBase64String(
        [Text.UTF8Encoding]::new($false).GetBytes('non-secret-openssh-native-status-grant')
    )
    $dropbearSftpTransferGrantValue = [Convert]::ToBase64String(
        [Text.UTF8Encoding]::new($false).GetBytes('non-secret-dropbear-sftp-transfer-grant')
    )
    $dropbearSftpStatusGrantValue = [Convert]::ToBase64String(
        [Text.UTF8Encoding]::new($false).GetBytes('non-secret-dropbear-sftp-status-grant')
    )
    $dropbearNativeTransferGrantValue = [Convert]::ToBase64String(
        [Text.UTF8Encoding]::new($false).GetBytes('non-secret-dropbear-native-transfer-grant')
    )
    $dropbearNativeStatusGrantValue = [Convert]::ToBase64String(
        [Text.UTF8Encoding]::new($false).GetBytes('non-secret-dropbear-native-status-grant')
    )
    $source = @"
using System;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Win32.SafeHandles;
public static class IsolatedOwnerFixture {
  static readonly byte[] ExpectedExecInput=Convert.FromBase64String("$expectedExecInput");
  static readonly byte[] ExpectedDirectoryInput=Convert.FromBase64String("$expectedDirectoryInput");
  static readonly byte[] OpenSshOutput=Convert.FromBase64String("$openSshOutput");
  static readonly byte[] DropbearOutput=Convert.FromBase64String("$dropbearOutput");
  static readonly byte[] DirectoryOutput=Convert.FromBase64String("$directoryOutput");
  static readonly byte[] OpenSshGrant=Convert.FromBase64String("$openSshGrantValue");
  static readonly byte[] DropbearGrant=Convert.FromBase64String("$dropbearGrantValue");
  static readonly byte[] DirectoryGrant=Convert.FromBase64String("$directoryGrantValue");
  static readonly byte[] LocalOpenGrant=Convert.FromBase64String("$localOpenGrantValue");
  static readonly byte[] LocalStatusGrant=Convert.FromBase64String("$localStatusGrantValue");
  static readonly byte[] LocalCancelGrant=Convert.FromBase64String("$localCancelGrantValue");
  static readonly byte[] RemoteOpenGrant=Convert.FromBase64String("$remoteOpenGrantValue");
  static readonly byte[] RemoteStatusGrant=Convert.FromBase64String("$remoteStatusGrantValue");
  static readonly byte[] RemoteCancelGrant=Convert.FromBase64String("$remoteCancelGrantValue");
  static readonly byte[] DynamicOpenGrant=Convert.FromBase64String("$dynamicOpenGrantValue");
  static readonly byte[] DynamicStatusGrant=Convert.FromBase64String("$dynamicStatusGrantValue");
  static readonly byte[] DynamicCancelGrant=Convert.FromBase64String("$dynamicCancelGrantValue");
  static readonly byte[] OpenSshSftpTransferGrant=Convert.FromBase64String("$openSshSftpTransferGrantValue");
  static readonly byte[] OpenSshSftpStatusGrant=Convert.FromBase64String("$openSshSftpStatusGrantValue");
  static readonly byte[] OpenSshNativeTransferGrant=Convert.FromBase64String("$openSshNativeTransferGrantValue");
  static readonly byte[] OpenSshNativeStatusGrant=Convert.FromBase64String("$openSshNativeStatusGrantValue");
  static readonly byte[] DropbearSftpTransferGrant=Convert.FromBase64String("$dropbearSftpTransferGrantValue");
  static readonly byte[] DropbearSftpStatusGrant=Convert.FromBase64String("$dropbearSftpStatusGrantValue");
  static readonly byte[] DropbearNativeTransferGrant=Convert.FromBase64String("$dropbearNativeTransferGrantValue");
  static readonly byte[] DropbearNativeStatusGrant=Convert.FromBase64String("$dropbearNativeStatusGrantValue");
  static byte[] ReadAll(Stream s) { using(var m=new MemoryStream()) { s.CopyTo(m); return m.ToArray(); } }
  static bool Same(byte[] a,byte[] b) { if(a.Length!=b.Length)return false; for(int i=0;i<a.Length;i++)if(a[i]!=b[i])return false; return true; }
  static string Deadline(string input) {
    Match m=Regex.Match(input,"\"deadline_unix_ms\":([0-9]+)");
    return m.Success ? m.Groups[1].Value : null;
  }
  static byte[] TunnelOutput(string input,string phase,string op,string mode,string tunnelId,
      string operationContextId,string profileId,string generation,string hostKey,
      string serverId,string attemptId,int bindPort) {
    string deadline=Deadline(input); if(deadline==null) return null;
    string expectedOp=phase=="open"?"\"op\":\""+op+"\"":
      (phase=="status"?"\"op\":\"forward-status\"":"\"op\":\"forward-cancel\"");
    if(!input.Contains(expectedOp)) return null;
    string contextField="\"operation_context_id\":\""+operationContextId+"\"";
    if(phase!="open"&&(!input.Contains("\"tunnel_id\":\""+tunnelId+"\"")||!input.Contains(contextField))) return null;
    string identity="{\"schema_version\":1,\"request_id\":1,\"ok\":true,\"data\":{"+
      "\"profile_id\":\""+profileId+"\",\"profile_generation\":"+generation+
      ",\"observed_host_key_sha256\":\""+hostKey+"\",\"pin_match\":true,"+
      "\"server_identification\":\""+serverId+"\",\"transport_attempt_id\":\""+attemptId+"\","+
      "\"operation_context_id\":\""+new string('a',64)+"\",\"revision\":1}}";
    string snapshot="{\"tunnel_id\":\""+tunnelId+"\",\"mode\":\""+mode+"\",\"stage\":\""+
      (phase=="cancel"?"closed":"ready")+"\",\"bind_host\":\"127.0.0.1\",\"bind_port\":"+
      bindPort.ToString(CultureInfo.InvariantCulture)+",\"deadline_unix_ms\":"+deadline+","+contextField+
      ",\"revision\":"+(phase=="cancel"?"2":"1")+"}";
    string result=phase=="open" ? identity+"\n{\"schema_version\":1,\"request_id\":2,\"ok\":true,\"data\":"+snapshot+"}\n" :
      (phase=="status" ? "{\"schema_version\":1,\"request_id\":3,\"ok\":true,\"data\":{\"tunnels\":["+snapshot+"]}}\n" :
      "{\"schema_version\":1,\"request_id\":4,\"ok\":true,\"data\":"+snapshot+"}\n");
    return new UTF8Encoding(false,true).GetBytes(result);
  }
  static byte[] TransferOutput(string input,string phase,string caseId,string backend,
      string operationContextId,string profileId,string generation,string hostKey,
      string serverId,string attemptId) {
    Match idMatch=Regex.Match(input,"\"transfer_id\":\"([0-9a-f]{32})\"");
    if(!idMatch.Success) return null;
    string transferId=idMatch.Groups[1].Value;
    if(phase=="primary") {
      Match localMatch=Regex.Match(input,"\"local\":\"([^\"]+)\"");
      if(!localMatch.Success) return null;
      string localPath=Regex.Unescape(localMatch.Groups[1].Value);
      byte[] actualPayload; try { actualPayload=File.ReadAllBytes(localPath); } catch { return null; }
      byte[] expectedPayload=new UTF8Encoding(false,true).GetBytes("serctl-fixed-payload\n");
      if(!Same(actualPayload,expectedPayload)) return null;
      try {
        using(var mutation=new FileStream(localPath,FileMode.Open,FileAccess.Write,FileShare.None)) {
          mutation.WriteByte(0); return null;
        }
      } catch(IOException) { } catch(UnauthorizedAccessException) { }
      if(!input.Contains("\"op\":\"transfer-push\"") ||
         !Regex.IsMatch(input,"\"remote\":\"/tmp/serctl-v1-beta-"+caseId.ToLowerInvariant()+"-[0-9a-f]{32}-target-21.bin\"") ||
         !input.Contains("\"backend\":\""+backend+"\"") ||
         !input.Contains("\"resume\":\"never\"")) return null;
      bool hasHelper=input.Contains("\"expected_helper_identity\":{");
      if((backend=="native")!=hasHelper) return null;
      if(hasHelper && (!input.Contains("\"name\":\"serctl-xfer\"") ||
         !input.Contains("transfer protocol v1"))) return null;
      // The primary remains blocked until the independently authorized status
      // process has actually reached its terminal. The extra bounded margin
      // makes the timestamp ordering deterministic across PS7 and PS5.
      string marker=Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"status-"+transferId);
      var wait=System.Diagnostics.Stopwatch.StartNew();
      while(!File.Exists(marker) && wait.ElapsedMilliseconds<6000)
        System.Threading.Thread.Sleep(20);
      if(!File.Exists(marker)) return null;
      System.Threading.Thread.Sleep(1000);
      File.WriteAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"source-stable-"+transferId),"21");
      string identity="{\"schema_version\":1,\"request_id\":1,\"ok\":true,\"data\":{"+
        "\"profile_id\":\""+profileId+"\",\"profile_generation\":"+generation+
        ",\"observed_host_key_sha256\":\""+hostKey+"\",\"pin_match\":true,"+
        "\"server_identification\":\""+serverId+"\",\"transport_attempt_id\":\""+attemptId+"\","+
        "\"operation_context_id\":\""+new string('b',64)+"\",\"revision\":1}}";
      string terminal="{\"schema_version\":1,\"request_id\":2,\"ok\":true,\"data\":{"+
        "\"transfer_id\":\""+transferId+"\",\"operation_context_id\":\""+operationContextId+
        "\",\"revision\":4,\"bytes\":21,\"backend_requested\":\""+backend+
        "\",\"backend\":\""+backend+"\",\"chunk_bytes\":2048,\"window_bytes\":2048}}";
      return new UTF8Encoding(false,true).GetBytes(identity+"\n"+terminal+"\n");
    }
    if(!input.Contains("\"op\":\"transfer-status\"")) return null;
    string progress="{\"schema_version\":1,\"event\":\"progress\",\"transfer_id\":\""+
      transferId+"\",\"operation_context_id\":\""+operationContextId+
      "\",\"revision\":3,\"direction\":\"push\",\"stage\":\"transferring\","+
      "\"total_bytes\":21,\"confirmed_bytes\":10,\"durable_bytes\":8,"+
      "\"window_bps\":1.0,\"average_bps\":1.0,\"eta_ms\":11000,"+
      "\"backend\":\""+backend+"\",\"chunk_bytes\":2048,\"window_bytes\":2048,"+
      "\"updated_unix_ms\":1800000000000}";
    string result="{\"schema_version\":1,\"request_id\":3,\"ok\":true,\"data\":{\"transfers\":["+
      progress+"]}}\n";
    return new UTF8Encoding(false,true).GetBytes(result);
  }
  static int Done(int code) { File.WriteAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"helper.result"),code.ToString(CultureInfo.InvariantCulture)); return code; }
  public static int Main(string[] a) {
    if(a.Length!=3||a[0]!="agent"||a[1]!="--grant-handle") return Done(90);
    if(Environment.GetEnvironmentVariable("SERCTL_PROFILE_PASSPHRASE")!=null) return Done(91);
    byte[] input=ReadAll(Console.OpenStandardInput());
    long raw; if(!long.TryParse(a[2],NumberStyles.None,CultureInfo.InvariantCulture,out raw)) return Done(93);
    byte[] grant;
    using(var h=new SafeFileHandle(new IntPtr(raw),true)) using(var f=new FileStream(h,FileAccess.Read)) {
      grant=ReadAll(f);
    }
    byte[] output;
    if(Same(grant,OpenSshGrant)) { if(!Same(input,ExpectedExecInput)) return Done(92); output=OpenSshOutput; }
    else if(Same(grant,DropbearGrant)) { if(!Same(input,ExpectedExecInput)) return Done(92); output=DropbearOutput; }
    else if(Same(grant,DirectoryGrant)) { if(!Same(input,ExpectedDirectoryInput)) return Done(92); output=DirectoryOutput; }
    else {
      string text; try { text=new UTF8Encoding(false,true).GetString(input); } catch { return Done(95); }
      if(Same(grant,LocalOpenGrant)) output=TunnelOutput(text,"open","forward-local-open","local","11111111111111111111111111111111","11"+new string('1',62),"223344556677889900aabbccddeeff11","10","SHA256:"+new string('G',43),"SSH-2.0-OpenSSH_tunnel_local_fixture",new string('1',32),15432);
      else if(Same(grant,LocalStatusGrant)) output=TunnelOutput(text,"status","forward-local-open","local","11111111111111111111111111111111","11"+new string('1',62),"223344556677889900aabbccddeeff11","10","SHA256:"+new string('G',43),"SSH-2.0-OpenSSH_tunnel_local_fixture",new string('1',32),15432);
      else if(Same(grant,LocalCancelGrant)) output=TunnelOutput(text,"cancel","forward-local-open","local","11111111111111111111111111111111","11"+new string('1',62),"223344556677889900aabbccddeeff11","10","SHA256:"+new string('G',43),"SSH-2.0-OpenSSH_tunnel_local_fixture",new string('1',32),15432);
      else if(Same(grant,RemoteOpenGrant)) output=TunnelOutput(text,"open","forward-remote-open","remote","22222222222222222222222222222222","22"+new string('2',62),"3344556677889900aabbccddeeff1122","11","SHA256:"+new string('H',43),"SSH-2.0-OpenSSH_tunnel_remote_fixture",new string('2',32),18080);
      else if(Same(grant,RemoteStatusGrant)) output=TunnelOutput(text,"status","forward-remote-open","remote","22222222222222222222222222222222","22"+new string('2',62),"3344556677889900aabbccddeeff1122","11","SHA256:"+new string('H',43),"SSH-2.0-OpenSSH_tunnel_remote_fixture",new string('2',32),18080);
      else if(Same(grant,RemoteCancelGrant)) output=TunnelOutput(text,"cancel","forward-remote-open","remote","22222222222222222222222222222222","22"+new string('2',62),"3344556677889900aabbccddeeff1122","11","SHA256:"+new string('H',43),"SSH-2.0-OpenSSH_tunnel_remote_fixture",new string('2',32),18080);
      else if(Same(grant,DynamicOpenGrant)) output=TunnelOutput(text,"open","forward-dynamic-open","dynamic","33333333333333333333333333333333","33"+new string('3',62),"44556677889900aabbccddeeff112233","12","SHA256:"+new string('I',43),"SSH-2.0-OpenSSH_tunnel_dynamic_fixture",new string('3',32),11080);
      else if(Same(grant,DynamicStatusGrant)) output=TunnelOutput(text,"status","forward-dynamic-open","dynamic","33333333333333333333333333333333","33"+new string('3',62),"44556677889900aabbccddeeff112233","12","SHA256:"+new string('I',43),"SSH-2.0-OpenSSH_tunnel_dynamic_fixture",new string('3',32),11080);
      else if(Same(grant,DynamicCancelGrant)) output=TunnelOutput(text,"cancel","forward-dynamic-open","dynamic","33333333333333333333333333333333","33"+new string('3',62),"44556677889900aabbccddeeff112233","12","SHA256:"+new string('I',43),"SSH-2.0-OpenSSH_tunnel_dynamic_fixture",new string('3',32),11080);
      else if(Same(grant,OpenSshSftpTransferGrant)) output=TransferOutput(text,"primary","OpenSSH_sftp","sftp","44"+new string('4',62),"556677889900aabbccddeeff11223344","13","SHA256:"+new string('J',43),"SSH-2.0-OpenSSH_sftp_fixture",new string('4',32));
      else if(Same(grant,OpenSshSftpStatusGrant)) output=TransferOutput(text,"status","OpenSSH_sftp","sftp","44"+new string('4',62),"556677889900aabbccddeeff11223344","13","SHA256:"+new string('J',43),"SSH-2.0-OpenSSH_sftp_fixture",new string('4',32));
      else if(Same(grant,OpenSshNativeTransferGrant)) output=TransferOutput(text,"primary","OpenSSH_native","native","55"+new string('5',62),"6677889900aabbccddeeff1122334455","14","SHA256:"+new string('K',43),"SSH-2.0-OpenSSH_native_fixture",new string('5',32));
      else if(Same(grant,OpenSshNativeStatusGrant)) output=TransferOutput(text,"status","OpenSSH_native","native","55"+new string('5',62),"6677889900aabbccddeeff1122334455","14","SHA256:"+new string('K',43),"SSH-2.0-OpenSSH_native_fixture",new string('5',32));
      else if(Same(grant,DropbearSftpTransferGrant)) output=TransferOutput(text,"primary","Dropbear_sftp","sftp","66"+new string('6',62),"77889900aabbccddeeff112233445566","15","SHA256:"+new string('L',43),"SSH-2.0-dropbear_sftp_fixture",new string('6',32));
      else if(Same(grant,DropbearSftpStatusGrant)) output=TransferOutput(text,"status","Dropbear_sftp","sftp","66"+new string('6',62),"77889900aabbccddeeff112233445566","15","SHA256:"+new string('L',43),"SSH-2.0-dropbear_sftp_fixture",new string('6',32));
      else if(Same(grant,DropbearNativeTransferGrant)) output=TransferOutput(text,"primary","Dropbear_native","native","77"+new string('7',62),"889900aabbccddeeff11223344556677","16","SHA256:"+new string('M',43),"SSH-2.0-dropbear_native_fixture",new string('7',32));
      else if(Same(grant,DropbearNativeStatusGrant)) output=TransferOutput(text,"status","Dropbear_native","native","77"+new string('7',62),"889900aabbccddeeff11223344556677","16","SHA256:"+new string('M',43),"SSH-2.0-dropbear_native_fixture",new string('7',32));
      else return Done(94);
      if(output==null) return Done(92);
    }
    Console.OpenStandardOutput().Write(output,0,output.Length);
    if(Same(grant,OpenSshSftpStatusGrant)||Same(grant,OpenSshNativeStatusGrant)||
       Same(grant,DropbearSftpStatusGrant)||Same(grant,DropbearNativeStatusGrant)) {
      Match completedId=Regex.Match(new UTF8Encoding(false,true).GetString(input),"\"transfer_id\":\"([0-9a-f]{32})\"");
      if(!completedId.Success) return Done(96);
      File.WriteAllText(Path.Combine(AppDomain.CurrentDomain.BaseDirectory,"status-"+completedId.Groups[1].Value),"ready");
    }
    return Done(0);
  }
}
"@
    [IO.File]::WriteAllText($sourcePath, $source, [Text.UTF8Encoding]::new($false))
    $compiler = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    Assert-OwnerTest (Test-Path -LiteralPath $compiler -PathType Leaf) (
        'fixed C# compiler is unavailable'
    )
    & $compiler '/nologo' '/target:exe' ('/out:' + $helperPath) $sourcePath
    Assert-OwnerTest ($LASTEXITCODE -eq 0) 'fixture helper compilation failed'
    [IO.File]::Copy($helperPath, $daemonPath, $false)
    [IO.File]::Copy($helperPath, $xferPath, $false)
    $size = (Get-Item -LiteralPath $helperPath).Length
    $hash = (Get-FileHash -LiteralPath $helperPath -Algorithm SHA256).Hash
    $components = [pscustomobject][ordered]@{
        cli = [pscustomobject][ordered]@{
            name = 'serctl_cli.exe'; binary_size = [long]$size; sha256 = $hash
            version = 'serctl_cli 1.0.0-beta (git 0123456789ab; vault-storage read=v4..=v5 write=v5)'
        }
        daemon = [pscustomobject][ordered]@{
            name = 'serctl_daemon.exe'; binary_size = [long]$size; sha256 = $hash
            version = 'serctl_daemon 1.0.0-beta (git 0123456789ab; IPC v9..=v9; vault-storage read=v4..=v5 write=v5)'
        }
        helper = [pscustomobject][ordered]@{
            name = 'serctl-xfer'; binary_size = [long]$size; sha256 = $hash
            version = 'serctl-xfer 1.0.0-beta (git 0123456789ab; transfer protocol v1)'
        }
    }
    $windowsProvenance = ConvertTo-OwnerJsonBytes ([pscustomobject][ordered]@{
        schema_version = 2; platform = 'windows-x86_64'
        binary_components = @($components.cli, $components.daemon)
    })
    $linuxProvenance = ConvertTo-OwnerJsonBytes ([pscustomobject][ordered]@{
        schema_version = 2; platform = 'linux-x86_64'
        binary_components = @($components.helper)
    })
    $baseConfig = [pscustomobject][ordered]@{
        schema_version = 1
        owner_contract = 'serctl-isolated-formal-owner-input-v1'
        expected_contexts = [pscustomobject][ordered]@{
            OpenSSH_exec = $openSshContext
            Dropbear_exec = $dropbearContext
            OpenSSH_directory = $directoryContext
            OpenSSH_tunnel_local = $localTunnelContext
            OpenSSH_tunnel_remote = $remoteTunnelContext
            OpenSSH_tunnel_dynamic = $dynamicTunnelContext
            OpenSSH_sftp = $openSshSftpContext
            OpenSSH_native = $openSshNativeContext
            Dropbear_sftp = $dropbearSftpContext
            Dropbear_native = $dropbearNativeContext
        }
        evidence_context_sha256 = 'A' * 64
        deadline_ms = [uint64]15000
    }
    $downloadedRecord=[pscustomobject][ordered]@{schema_version=1;record_contract='serctl-verified-downloaded-set-record-v1';release_tag='v1.0.0-beta';commit='0'*40;tag_object='1'*40;repository='fixture/serctl';synthetic_fixture=$true;components=@(
        [pscustomobject][ordered]@{platform='windows-x86_64';name='serctl_cli.exe';binary_size=[long]$size;sha256=$hash;version=$components.cli.version},
        [pscustomobject][ordered]@{platform='windows-x86_64';name='serctl_daemon.exe';binary_size=[long]$size;sha256=$hash;version=$components.daemon.version},
        [pscustomobject][ordered]@{platform='linux-x86_64';name='serctl-xfer';binary_size=[long]$size;sha256=$hash;version=$components.helper.version}
    )}
    $downloadedRecordPath=Join-Path $fixtureRoot 'downloaded-set-record.json'
    [IO.File]::WriteAllText($downloadedRecordPath,(($downloadedRecord|ConvertTo-Json -Compress -Depth 8)+"`n"),[Text.UTF8Encoding]::new($false))
    $grantPaths = @(
        (Join-Path $fixtureRoot 'openssh-exec.grant.bin'),
        (Join-Path $fixtureRoot 'dropbear-exec.grant.bin'),
        (Join-Path $fixtureRoot 'openssh-directory.grant.bin'),
        (Join-Path $fixtureRoot 'openssh-tunnel-local-open.grant.bin'),
        (Join-Path $fixtureRoot 'openssh-tunnel-local-status.grant.bin'),
        (Join-Path $fixtureRoot 'openssh-tunnel-local-cancel.grant.bin'),
        (Join-Path $fixtureRoot 'openssh-tunnel-remote-open.grant.bin'),
        (Join-Path $fixtureRoot 'openssh-tunnel-remote-status.grant.bin'),
        (Join-Path $fixtureRoot 'openssh-tunnel-remote-cancel.grant.bin'),
        (Join-Path $fixtureRoot 'openssh-tunnel-dynamic-open.grant.bin'),
        (Join-Path $fixtureRoot 'openssh-tunnel-dynamic-status.grant.bin'),
        (Join-Path $fixtureRoot 'openssh-tunnel-dynamic-cancel.grant.bin'),
        (Join-Path $fixtureRoot 'openssh-sftp-transfer.grant.bin'),
        (Join-Path $fixtureRoot 'openssh-sftp-status.grant.bin'),
        (Join-Path $fixtureRoot 'openssh-native-transfer.grant.bin'),
        (Join-Path $fixtureRoot 'openssh-native-status.grant.bin'),
        (Join-Path $fixtureRoot 'dropbear-sftp-transfer.grant.bin'),
        (Join-Path $fixtureRoot 'dropbear-sftp-status.grant.bin'),
        (Join-Path $fixtureRoot 'dropbear-native-transfer.grant.bin'),
        (Join-Path $fixtureRoot 'dropbear-native-status.grant.bin')
    )
    [IO.File]::WriteAllBytes($grantPaths[0], [Convert]::FromBase64String($openSshGrantValue))
    [IO.File]::WriteAllBytes($grantPaths[1], [Convert]::FromBase64String($dropbearGrantValue))
    [IO.File]::WriteAllBytes($grantPaths[2], [Convert]::FromBase64String($directoryGrantValue))
    $tunnelGrantValues = @(
        $localOpenGrantValue, $localStatusGrantValue, $localCancelGrantValue,
        $remoteOpenGrantValue, $remoteStatusGrantValue, $remoteCancelGrantValue,
        $dynamicOpenGrantValue, $dynamicStatusGrantValue, $dynamicCancelGrantValue
    )
    for ($grantIndex = 0; $grantIndex -lt $tunnelGrantValues.Count; $grantIndex++) {
        [IO.File]::WriteAllBytes(
            $grantPaths[$grantIndex + 3],
            [Convert]::FromBase64String($tunnelGrantValues[$grantIndex])
        )
    }
    $transferGrantValues = @(
        $openSshSftpTransferGrantValue, $openSshSftpStatusGrantValue,
        $openSshNativeTransferGrantValue, $openSshNativeStatusGrantValue,
        $dropbearSftpTransferGrantValue, $dropbearSftpStatusGrantValue,
        $dropbearNativeTransferGrantValue, $dropbearNativeStatusGrantValue
    )
    for ($grantIndex = 0; $grantIndex -lt $transferGrantValues.Count; $grantIndex++) {
        [IO.File]::WriteAllBytes(
            $grantPaths[$grantIndex + 12],
            [Convert]::FromBase64String($transferGrantValues[$grantIndex])
        )
    }
    if ($null -eq ('Serctl.IsolatedOwnerSelfTest.Native' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
namespace Serctl.IsolatedOwnerSelfTest {
  public static class Native {
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool SetHandleInformation(IntPtr h,uint m,uint f);
    public static void MakeInheritable(IntPtr h) { if(!SetHandleInformation(h,1,1)) throw new Win32Exception(); }
  }
}
'@
    }

    function Invoke-IsolatedOwnerFixture {
        param($Config, [string]$OutputPath, [switch]$DuplicateGrant)
        $configBytes = ConvertTo-OwnerJsonBytes $Config
        $officialStreams=@(
            [IO.File]::Open($downloadedRecordPath,'Open','Read','Read'),
            [IO.File]::Open($helperPath,'Open','Read','Read'),
            [IO.File]::Open($daemonPath,'Open','Read','Read'),
            [IO.File]::Open($xferPath,'Open','Read','Read'),
            [IO.File]::Open($OutputPath,$(if(Test-Path $OutputPath){'Open'}else{'CreateNew'}),'ReadWrite','Read')
        )
        $grantStreams = @($grantPaths | ForEach-Object {
            [IO.File]::Open($_, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
        })
        try {
            if ([Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
                [Runtime.InteropServices.OSPlatform]::Windows
            )) {
                foreach ($grantStream in @($officialStreams)+$grantStreams) {
                    [Serctl.IsolatedOwnerSelfTest.Native]::MakeInheritable(
                        $grantStream.SafeFileHandle.DangerousGetHandle()
                    )
                }
            }
            return Invoke-ExternalTransferIsolatedOwnerProcessInternal `
                -ProtectedConfigBytes $configBytes `
                -DownloadedSetRecordHandle $officialStreams[0].SafeFileHandle `
                -WindowsCliHandle $officialStreams[1].SafeFileHandle `
                -WindowsDaemonHandle $officialStreams[2].SafeFileHandle `
                -LinuxHelperHandle $officialStreams[3].SafeFileHandle `
                -ReceiptOutputHandle $officialStreams[4].SafeFileHandle `
                -OpenSshExecGrantHandle $grantStreams[0].SafeFileHandle `
                -DropbearExecGrantHandle $(if($DuplicateGrant){$grantStreams[0].SafeFileHandle}else{$grantStreams[1].SafeFileHandle}) `
                -OpenSshDirectoryGrantHandle $grantStreams[2].SafeFileHandle `
                -OpenSshTunnelLocalOpenGrantHandle $grantStreams[3].SafeFileHandle `
                -OpenSshTunnelLocalStatusGrantHandle $grantStreams[4].SafeFileHandle `
                -OpenSshTunnelLocalCancelGrantHandle $grantStreams[5].SafeFileHandle `
                -OpenSshTunnelRemoteOpenGrantHandle $grantStreams[6].SafeFileHandle `
                -OpenSshTunnelRemoteStatusGrantHandle $grantStreams[7].SafeFileHandle `
                -OpenSshTunnelRemoteCancelGrantHandle $grantStreams[8].SafeFileHandle `
                -OpenSshTunnelDynamicOpenGrantHandle $grantStreams[9].SafeFileHandle `
                -OpenSshTunnelDynamicStatusGrantHandle $grantStreams[10].SafeFileHandle `
                -OpenSshTunnelDynamicCancelGrantHandle $grantStreams[11].SafeFileHandle `
                -OpenSshSftpTransferGrantHandle $grantStreams[12].SafeFileHandle `
                -OpenSshSftpStatusGrantHandle $grantStreams[13].SafeFileHandle `
                -OpenSshNativeTransferGrantHandle $grantStreams[14].SafeFileHandle `
                -OpenSshNativeStatusGrantHandle $grantStreams[15].SafeFileHandle `
                -DropbearSftpTransferGrantHandle $grantStreams[16].SafeFileHandle `
                -DropbearSftpStatusGrantHandle $grantStreams[17].SafeFileHandle `
                -DropbearNativeTransferGrantHandle $grantStreams[18].SafeFileHandle `
                -DropbearNativeStatusGrantHandle $grantStreams[19].SafeFileHandle `
                -DeadlineMilliseconds 60000 `
                -ErrorAction Stop
        }
        finally { foreach ($grantStream in $grantStreams) { $grantStream.Dispose() };foreach($stream in $officialStreams){$stream.Dispose()} }
    }

    $oldCanary = [Environment]::GetEnvironmentVariable('SERCTL_PROFILE_PASSPHRASE')
    [Environment]::SetEnvironmentVariable('SERCTL_PROFILE_PASSPHRASE', 'PASSWORD_CANARY')
    try {
        $receiptPath = Join-Path $fixtureRoot 'isolated-owner.receipt.json'
        $capture = Invoke-IsolatedOwnerFixture $baseConfig $receiptPath
        try {
            if ($capture.exit_category -cne 'completed_success' -or $capture.exit_code -ne 0 -or
                $capture.stdout.Length -ne 0 -or $capture.stderr.Length -ne 0) {
                Write-Host ("owner_capture=$($capture.exit_category)/$($capture.exit_code) stdout=$($capture.stdout.Length) stderr=$($capture.stderr.Length)")
                Write-Host ([Text.Encoding]::Default.GetString($capture.stdout))
                Write-Host ([Text.Encoding]::Default.GetString($capture.stderr))
                $helperResultPath = Join-Path $fixtureRoot 'helper.result'
                if (Test-Path -LiteralPath $helperResultPath) {
                    Write-Host ('helper_result=' + [IO.File]::ReadAllText($helperResultPath))
                }
            }
            Assert-OwnerTest (
                $capture.exit_category -ceq 'completed_success' -and
                $capture.exit_code -eq 0 -and $capture.stdout.Length -eq 0 -and
                $capture.stderr.Length -eq 0 -and $capture.process_tree_exited
            ) 'isolated owner did not complete through its actual child process'
        }
        finally {
            [Array]::Clear($capture.stdout, 0, $capture.stdout.Length)
            [Array]::Clear($capture.stderr, 0, $capture.stderr.Length)
        }
    }
    finally {
        [Environment]::SetEnvironmentVariable('SERCTL_PROFILE_PASSPHRASE', $oldCanary)
    }
    Assert-OwnerTest (Test-Path -LiteralPath $receiptPath -PathType Leaf) (
        'isolated owner did not create its receipt'
    )
    $firstHash = (Get-FileHash -LiteralPath $receiptPath -Algorithm SHA256).Hash
    $receiptText = [IO.File]::ReadAllText($receiptPath, [Text.UTF8Encoding]::new($false, $true))
    $receipt = $receiptText.TrimEnd("`n") | ConvertFrom-Json
    Assert-OwnerTest (
        $receipt.schema_version -eq 2 -and
        $receipt.owner_contract -ceq 'serctl-isolated-formal-owner-receipt-v2' -and
        $receipt.evidence_context_sha256 -ceq ('A' * 64) -and
        (@($receipt.case_receipts.case_id) -join ',') -ceq
            'OpenSSH_exec,OpenSSH_directory,OpenSSH_tunnel_local,OpenSSH_tunnel_remote,OpenSSH_tunnel_dynamic,OpenSSH_sftp,OpenSSH_native,Dropbear_exec,Dropbear_sftp,Dropbear_native' -and
        @($receipt.case_receipts).Count -eq 10 -and
        @($receipt.case_receipts.receipt_sha256 | Select-Object -Unique).Count -eq 10
    ) 'isolated owner receipt v2 does not contain its exact ten-case slice'
    Assert-OwnerTest (-not $receiptText.Contains('PASSWORD_CANARY')) (
        'environment canary entered the owner receipt'
    )
    . (Join-Path $PSScriptRoot 'ExternalTransferRuntimeReceiptContract.ps1')
    $importLedger = New-ExternalTransferRuntimeLedger -Category 'openssh_dropbear_interop'
    & $contractModule {
        param($Ledger, $Components, $EvidenceContext)
        Set-IsolatedOwnerExpectedBindingInternal `
            (Resolve-LedgerState $Ledger) $Components $EvidenceContext
    } $importLedger $components ('A' * 64)
    $importBytes = [IO.File]::ReadAllBytes($receiptPath)
    $importStatus = Import-ExternalTransferIsolatedOwnerReceiptV2 `
        -Ledger $importLedger -OwnerReceiptBytes $importBytes
    Assert-OwnerTest (
        $importStatus.completed -eq 10 -and $importStatus.blocked -eq 0 -and
        -not $importStatus.sealed
    ) 'owner v2 bytes did not import ten distinct contexts as unsealable state'
    $completeBlocked = $false
    try { Complete-ExternalTransferRuntimeLedger -Ledger $importLedger | Out-Null }
    catch { $completeBlocked = $true }
    Assert-OwnerTest $completeBlocked 'imported provisioning-only evidence became Complete'
    function Assert-IsolatedOwnerImportMutationRejected {
        param([string]$Label, [scriptblock]$Mutate)
        $document = $receiptText.TrimEnd("`n") | ConvertFrom-Json
        & $Mutate $document
        $bytes = ConvertTo-OwnerJsonBytes $document
        $ledger = New-ExternalTransferRuntimeLedger -Category 'openssh_dropbear_interop'
        & $contractModule {
            param($Ledger, $Components)
            Set-IsolatedOwnerExpectedBindingInternal `
                (Resolve-LedgerState $Ledger) $Components ('A' * 64)
        } $ledger $components
        $rejected = $false
        try { Import-ExternalTransferIsolatedOwnerReceiptV2 $ledger $bytes | Out-Null }
        catch { $rejected = $true }
        Assert-OwnerTest $rejected "tampered $Label owner receipt imported"
    }
    Assert-IsolatedOwnerImportMutationRejected 'aggregate context' {
        param($Document) $Document.evidence_context_sha256 = 'B' * 64
    }
    Assert-IsolatedOwnerImportMutationRejected 'component bytes' {
        param($Document)
        $bytes = [Convert]::FromBase64String([string]$Document.component_set_base64)
        $bytes[0] = $bytes[0] -bxor 1
        $Document.component_set_base64 = [Convert]::ToBase64String($bytes)
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
    Assert-IsolatedOwnerImportMutationRejected 'child receipt bytes' {
        param($Document)
        $bytes = [Convert]::FromBase64String([string]$Document.case_receipts[0].receipt_base64)
        $bytes[0] = $bytes[0] -bxor 1
        $Document.case_receipts[0].receipt_base64 = [Convert]::ToBase64String($bytes)
        [Array]::Clear($bytes, 0, $bytes.Length)
    }
    foreach ($childReceipt in @($receipt.case_receipts)) {
        $capturedBytes = [Convert]::FromBase64String([string]$childReceipt.receipt_base64)
        try {
            Assert-OwnerTest (
                [Convert]::ToBase64String($capturedBytes) -ceq
                    [string]$childReceipt.receipt_base64
            ) 'captured child receipt is not canonical Base64'
            $sha = [Security.Cryptography.SHA256]::Create()
            try {
                $capturedHash = ([BitConverter]::ToString(
                    $sha.ComputeHash($capturedBytes)
                )).Replace('-', '')
            }
            finally { $sha.Dispose() }
            $capturedText = [Text.UTF8Encoding]::new($false, $true).GetString($capturedBytes)
            Assert-OwnerTest (
                $capturedHash -ceq [string]$childReceipt.receipt_sha256 -and
                $capturedText.EndsWith("`n") -and -not $capturedText.Contains("`r") -and
                $capturedText.Contains('"case_id":"' + [string]$childReceipt.case_id + '"')
            ) 'captured child receipt bytes do not match their case/hash binding'
        }
        finally { [Array]::Clear($capturedBytes, 0, $capturedBytes.Length) }
    }
    Assert-OwnerTest (
        @(Get-ChildItem -LiteralPath $fixtureRoot -File -Filter 'source-stable-*').Count -eq 4
    ) 'a transfer child observed a missing or mutable fixed payload path'
    foreach ($grantCanary in @(
        'non-secret-openssh-exec-grant', 'non-secret-dropbear-exec-grant',
        'non-secret-openssh-directory-grant', 'non-secret-local-open-grant',
        'non-secret-remote-open-grant', 'non-secret-dynamic-open-grant',
        'non-secret-openssh-sftp-transfer-grant',
        'non-secret-openssh-native-transfer-grant',
        'non-secret-dropbear-sftp-transfer-grant',
        'non-secret-dropbear-native-transfer-grant'
    )) {
        Assert-OwnerTest (-not $receiptText.Contains($grantCanary)) (
            'Grant input bytes entered the owner receipt'
        )
    }

    $reusePath = Join-Path $fixtureRoot 'reused-grant.receipt.json'
    $reuseRejected = $false
    try {
        $reused=Invoke-IsolatedOwnerFixture $baseConfig $reusePath -DuplicateGrant
        try{$reuseRejected=$reused.exit_category -ne 'completed_success'}finally{[Array]::Clear($reused.stdout,0,$reused.stdout.Length);[Array]::Clear($reused.stderr,0,$reused.stderr.Length)}
    } catch { $reuseRejected = $true }
    Assert-OwnerTest ($reuseRejected -and (Get-Item $reusePath).Length -eq 0) 'reused purpose handle was accepted or wrote output'

    $incompleteConfig = $baseConfig.PSObject.Copy()
    $incompleteConfig.expected_contexts = $baseConfig.expected_contexts.PSObject.Copy()
    $wrongFinalTransferContext = $dropbearNativeContext.PSObject.Copy()
    $wrongFinalTransferContext.server_identification = 'SSH-2.0-dropbear_wrong_fixture'
    $incompleteConfig.expected_contexts.Dropbear_native = $wrongFinalTransferContext
    $incompletePath = Join-Path $fixtureRoot 'incomplete-case-set.receipt.json'
    $incomplete = Invoke-IsolatedOwnerFixture $incompleteConfig $incompletePath
    try {
        Assert-OwnerTest (
            $incomplete.exit_category -ne 'completed_success' -and
            (Get-Item -LiteralPath $incompletePath).Length -eq 0
        ) 'incomplete fixed case set produced a sealed receipt'
    }
    finally {
        [Array]::Clear($incomplete.stdout, 0, $incomplete.stdout.Length)
        [Array]::Clear($incomplete.stderr, 0, $incomplete.stderr.Length)
    }

    $second = Invoke-IsolatedOwnerFixture $baseConfig $receiptPath
    try {
        Assert-OwnerTest (
            $second.exit_category -ne 'completed_success' -and
            $second.process_tree_exited
        ) 'create-new receipt overwrite attempt succeeded'
    }
    finally {
        [Array]::Clear($second.stdout, 0, $second.stdout.Length)
        [Array]::Clear($second.stderr, 0, $second.stderr.Length)
    }
    Assert-OwnerTest (
        (Get-FileHash -LiteralPath $receiptPath -Algorithm SHA256).Hash -ceq $firstHash
    ) 'create-new rejection changed the sealed receipt'

    $syntheticConfig = $baseConfig.PSObject.Copy()
    $syntheticConfig | Add-Member -NotePropertyName synthetic_summary -NotePropertyValue ([pscustomobject]@{
        sealable = $true; passed = $true
    })
    $syntheticPath = Join-Path $fixtureRoot 'synthetic.receipt.json'
    $synthetic = Invoke-IsolatedOwnerFixture $syntheticConfig $syntheticPath
    try {
        Assert-OwnerTest (
            $synthetic.exit_category -ne 'completed_success' -and
            (Get-Item -LiteralPath $syntheticPath).Length -eq 0
        ) 'caller-supplied synthetic summary reached the sealed path'
    }
    finally {
        [Array]::Clear($synthetic.stdout, 0, $synthetic.stdout.Length)
        [Array]::Clear($synthetic.stderr, 0, $synthetic.stderr.Length)
    }

    $substituted = $baseConfig.PSObject.Copy()
    $substituted|Add-Member windows_provenance_base64 'QQ=='
    $substitutedPath = Join-Path $fixtureRoot 'substituted.receipt.json'
    $substitution = Invoke-IsolatedOwnerFixture $substituted $substitutedPath
    try {
        Assert-OwnerTest (
            $substitution.exit_category -ne 'completed_success' -and
            (Get-Item -LiteralPath $substitutedPath).Length -eq 0
        ) 'component provenance substitution reached the sealed path'
    }
    finally {
        [Array]::Clear($substitution.stdout, 0, $substitution.stdout.Length)
        [Array]::Clear($substitution.stderr, 0, $substitution.stderr.Length)
    }

    $helperSubstituted = $baseConfig.PSObject.Copy()
    $helperSubstituted|Add-Member component_paths ([pscustomobject]@{cli='x';daemon='y';helper='z'})
    $helperSubstitutedPath = Join-Path $fixtureRoot 'helper-substituted.receipt.json'
    $helperSubstitution = Invoke-IsolatedOwnerFixture `
        $helperSubstituted $helperSubstitutedPath
    try {
        Assert-OwnerTest (
            $helperSubstitution.exit_category -ne 'completed_success' -and
            (Get-Item -LiteralPath $helperSubstitutedPath).Length -eq 0
        ) 'helper provenance substitution reached the sealed native path'
    }
    finally {
        [Array]::Clear($helperSubstitution.stdout, 0, $helperSubstitution.stdout.Length)
        [Array]::Clear($helperSubstitution.stderr, 0, $helperSubstitution.stderr.Length)
    }
}
finally {
    foreach ($bytes in @(
        $execRequestBytes, $directoryRequestBytes, $openSshOutputBytes,
        $dropbearOutputBytes, $directoryOutputBytes,
        $windowsProvenance, $linuxProvenance, $fixedPayloadBytes
    )) {
        if ($null -ne $bytes) { [Array]::Clear($bytes, 0, $bytes.Length) }
    }
    if (Test-Path -LiteralPath $fixtureRoot -PathType Container) {
        Assert-OwnerTest ([IO.File]::ReadAllText($ownerPath).Trim() -ceq $ownerToken) (
            'fixture ownership changed before cleanup'
        )
        Remove-Item -LiteralPath $fixtureRoot -Recurse -Force
    }
}

Write-Host (
    'Isolated external transfer formal owner self-test passed ' +
    '(sealed provisioning vertical slice only; full release categories remain BLOCKED).'
)
