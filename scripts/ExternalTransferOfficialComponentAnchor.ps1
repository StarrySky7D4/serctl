Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'StrictJson.ps1')

if ($null -eq ('Serctl.OfficialAnchor.Native' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace Serctl.OfficialAnchor {
  public static class Native {
    const uint DUPLICATE_SAME_ACCESS=2;
    [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool DuplicateHandle(
      IntPtr sourceProcess,IntPtr source,IntPtr targetProcess,out IntPtr target,
      uint access,bool inherit,uint options);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)]
    static extern uint GetFinalPathNameByHandle(IntPtr h,System.Text.StringBuilder p,uint n,uint flags);
    [StructLayout(LayoutKind.Sequential)] struct BY_HANDLE_FILE_INFORMATION {
      public uint attr; public System.Runtime.InteropServices.ComTypes.FILETIME c,a,w;
      public uint volume,sizeHigh,sizeLow,links,indexHigh,indexLow;
    }
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetFileInformationByHandle(
      IntPtr h,out BY_HANDLE_FILE_INFORMATION info);
    public static SafeFileHandle Duplicate(SafeHandle source) {
      IntPtr current=GetCurrentProcess(), copy;
      if(source==null||source.IsInvalid||source.IsClosed||
         !DuplicateHandle(current,source.DangerousGetHandle(),current,out copy,0,false,DUPLICATE_SAME_ACCESS))
        throw new Win32Exception(Marshal.GetLastWin32Error(),"official anchor handle duplication failed");
      return new SafeFileHandle(copy,true);
    }
    public static string FinalPath(SafeHandle h) {
      var b=new System.Text.StringBuilder(32768); uint n=GetFinalPathNameByHandle(h.DangerousGetHandle(),b,(uint)b.Capacity,0);
      if(n==0||n>=b.Capacity) throw new Win32Exception(Marshal.GetLastWin32Error(),"component final path failed");
      string p=b.ToString(); return p.StartsWith(@"\\?\")?p.Substring(4):p;
    }
    public static string Identity(SafeHandle h) {
      BY_HANDLE_FILE_INFORMATION i; if(!GetFileInformationByHandle(h.DangerousGetHandle(),out i))
        throw new Win32Exception(Marshal.GetLastWin32Error(),"component identity failed");
      return i.volume.ToString("X8")+":"+i.indexHigh.ToString("X8")+i.indexLow.ToString("X8");
    }
  }
}
'@
}

function Assert-OfficialAnchorInternal {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "official component anchor failed: $Message" }
}
function Assert-OfficialClosedObjectInternal {
    param($Value,[string[]]$Fields,[string]$Label)
    Assert-OfficialAnchorInternal (Test-StrictJsonObject $Value) "$Label is not an object"
    $actual=@($Value.PSObject.Properties.Name)
    Assert-OfficialAnchorInternal (
        $actual.Count -eq $Fields.Count -and (($actual|Sort-Object)-join "`n") -ceq (($Fields|Sort-Object)-join "`n")
    ) "$Label has unknown or missing fields"
}

function Read-OfficialAnchorHandleBytesInternal {
    param([Runtime.InteropServices.SafeHandle]$Handle, [int]$MaximumBytes)
    $copy = [Serctl.OfficialAnchor.Native]::Duplicate($Handle)
    $stream = [IO.FileStream]::new($copy, [IO.FileAccess]::Read)
    $memory = [IO.MemoryStream]::new()
    $buffer = [byte[]]::new(8192)
    try {
        Assert-OfficialAnchorInternal ($stream.CanRead -and $stream.CanSeek) 'input is not a regular seekable file'
        Assert-OfficialAnchorInternal ($stream.Length -le $MaximumBytes) 'input exceeds its byte bound'
        $stream.Position = 0
        while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
            $memory.Write($buffer, 0, $read)
        }
        return ,$memory.ToArray()
    }
    finally {
        [Array]::Clear($buffer, 0, $buffer.Length)
        $memory.Dispose(); $stream.Dispose()
    }
}

function Get-OfficialAnchorSha256Internal {
    param([byte[]]$Bytes)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '') }
    finally { $sha.Dispose() }
}

function Get-ExternalTransferOfficialComponentBindingInternal {
    param(
        [Runtime.InteropServices.SafeHandle]$DownloadedSetRecordHandle,
        [Runtime.InteropServices.SafeHandle]$WindowsCliHandle,
        [Runtime.InteropServices.SafeHandle]$WindowsDaemonHandle,
        [Runtime.InteropServices.SafeHandle]$LinuxHelperHandle
    )
    $tempPath=Join-Path ([IO.Path]::GetTempPath()) ('serctl-anchor-'+[Guid]::NewGuid().ToString('N'))
    $temp=[IO.File]::Open($tempPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    try {
        New-ExternalTransferOfficialComponentAnchorInternal $DownloadedSetRecordHandle `
            $WindowsCliHandle $WindowsDaemonHandle $LinuxHelperHandle $temp.SafeFileHandle
        $temp.Position=0;$reader=[IO.StreamReader]::new($temp,[Text.UTF8Encoding]::new($false,$true),$false,4096,$true)
        try{$anchor=ConvertFrom-StrictJson ($reader.ReadToEnd().TrimEnd("`n")) 'official component anchor'}finally{$reader.Dispose()}
        $bytes=[Convert]::FromBase64String([string]$anchor.component_set_base64)
        try{$components=ConvertFrom-StrictJson ([Text.UTF8Encoding]::new($false,$true).GetString($bytes).TrimEnd("`n")) 'official components'}finally{[Array]::Clear($bytes,0,$bytes.Length)}
        $handles=@($WindowsCliHandle,$WindowsDaemonHandle,$LinuxHelperHandle)
        $paths=[ordered]@{};$identities=[ordered]@{};$keys=@('cli','daemon','helper')
        for($i=0;$i -lt 3;$i++){$paths[$keys[$i]]=[Serctl.OfficialAnchor.Native]::FinalPath($handles[$i]);$identities[$keys[$i]]=[Serctl.OfficialAnchor.Native]::Identity($handles[$i])}
        return [pscustomobject][ordered]@{anchor=$anchor;components=$components;component_paths=[pscustomobject]$paths;component_identities=[pscustomobject]$identities}
    } finally {$temp.Dispose();if(Test-Path -LiteralPath $tempPath){[IO.File]::Delete($tempPath)}}
}

function Write-ExternalTransferOfficialReceiptHandleInternal {
    param([Runtime.InteropServices.SafeHandle]$Handle,[byte[]]$Bytes)
    $copy=[Serctl.OfficialAnchor.Native]::Duplicate($Handle);$stream=[IO.FileStream]::new($copy,[IO.FileAccess]::ReadWrite)
    try{Assert-OfficialAnchorInternal ($stream.CanSeek -and $stream.Length -eq 0) 'receipt output handle is not empty';$stream.Write($Bytes,0,$Bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
}

# INTERNAL provisioning boundary. It accepts only already-open handles: one
# verifier-owned downloaded-set record, the exact three component files, and
# one caller-created empty output file. No path, version, digest, pass bit or
# receipt summary is accepted as a loose parameter.
function New-ExternalTransferOfficialComponentAnchorInternal {
    param(
        [Parameter(Mandatory=$true)][Runtime.InteropServices.SafeHandle]$DownloadedSetRecordHandle,
        [Parameter(Mandatory=$true)][Runtime.InteropServices.SafeHandle]$WindowsCliHandle,
        [Parameter(Mandatory=$true)][Runtime.InteropServices.SafeHandle]$WindowsDaemonHandle,
        [Parameter(Mandatory=$true)][Runtime.InteropServices.SafeHandle]$LinuxHelperHandle,
        [Parameter(Mandatory=$true)][Runtime.InteropServices.SafeHandle]$ReceiptOutputHandle
    )
    Assert-OfficialAnchorInternal (
        [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
            [Runtime.InteropServices.OSPlatform]::Windows
        )
    ) 'official component anchoring is not proven on this platform'
    $handles = @($DownloadedSetRecordHandle,$WindowsCliHandle,$WindowsDaemonHandle,
        $LinuxHelperHandle,$ReceiptOutputHandle)
    foreach ($handle in $handles) {
        Assert-OfficialAnchorInternal (
            $null -ne $handle -and -not $handle.IsInvalid -and -not $handle.IsClosed
        ) 'an official component handle is unavailable'
    }
    $raw = @($handles | ForEach-Object { $_.DangerousGetHandle().ToInt64() })
    Assert-OfficialAnchorInternal (@($raw | Select-Object -Unique).Count -eq 5) (
        'official component purposes require five distinct handles'
    )
    $recordBytes = $null; $componentBuffers = @(); $componentBytes = $null
    $outputBytes = $null
    try {
        $recordBytes = Read-OfficialAnchorHandleBytesInternal $DownloadedSetRecordHandle 262144
        try { $recordText = [Text.UTF8Encoding]::new($false,$true).GetString($recordBytes) }
        catch { throw 'official component anchor failed: downloaded-set record is not strict UTF-8' }
        Assert-OfficialAnchorInternal (
            $recordText.EndsWith("`n") -and -not $recordText.Contains("`r")
        ) 'downloaded-set record is not canonical JSON'
        $record = ConvertFrom-StrictJson $recordText.Substring(0,$recordText.Length-1) 'downloaded-set record'
        Assert-OfficialClosedObjectInternal $record @('schema_version','record_contract','release_tag',
            'commit','tag_object','repository','synthetic_fixture','components') 'downloaded-set record'
        Assert-OfficialAnchorInternal (
            (Test-StrictJsonInteger $record.schema_version) -and [int]$record.schema_version -eq 1 -and
            [string]$record.record_contract -ceq 'serctl-verified-downloaded-set-record-v1' -and
            [string]$record.release_tag -cmatch '^v[0-9]+\.[0-9]+\.[0-9]+-(?:alpha|beta|rc)(?:\.[0-9]+)?$' -and
            [string]$record.commit -cmatch '^[0-9a-f]{40}$' -and
            [string]$record.tag_object -cmatch '^[0-9a-f]{40}$' -and
            [string]$record.repository -cmatch '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$' -and
            $record.synthetic_fixture -is [bool] -and
            (Test-StrictJsonArray $record.components) -and @($record.components).Count -eq 3
        ) 'downloaded-set release identity is invalid'
        $bindings = @(
            @('windows-x86_64','serctl_cli.exe',$WindowsCliHandle),
            @('windows-x86_64','serctl_daemon.exe',$WindowsDaemonHandle),
            @('linux-x86_64','serctl-xfer',$LinuxHelperHandle)
        )
        $canonical = [ordered]@{}
        for ($index=0;$index -lt 3;$index++) {
            $entry = @($record.components)[$index]
            Assert-OfficialClosedObjectInternal $entry @('platform','name','binary_size','sha256','version') 'downloaded component'
            $bytes = Read-OfficialAnchorHandleBytesInternal $bindings[$index][2] 536870912
            $componentBuffers += ,$bytes
            Assert-OfficialAnchorInternal (
                [string]$entry.platform -ceq $bindings[$index][0] -and
                [string]$entry.name -ceq $bindings[$index][1] -and
                (Test-StrictJsonInteger $entry.binary_size) -and
                [uint64]$entry.binary_size -eq [uint64]$bytes.Length -and
                [string]$entry.sha256 -cmatch '^[0-9A-F]{64}$' -and
                [string]$entry.sha256 -ceq (Get-OfficialAnchorSha256Internal $bytes) -and
                (Test-StrictJsonString $entry.version) -and [string]$entry.version -notmatch '[\r\n]'
            ) "downloaded component '$($bindings[$index][1])' differs from its verified record"
            $key = @('cli','daemon','helper')[$index]
            $canonical[$key] = [pscustomobject][ordered]@{
                name=[string]$entry.name; binary_size=[long]$entry.binary_size
                sha256=[string]$entry.sha256; version=[string]$entry.version
            }
        }
        $componentBytes = [Text.UTF8Encoding]::new($false,$true).GetBytes(
            (([pscustomobject]$canonical | ConvertTo-Json -Compress -Depth 6) + "`n")
        )
        $anchor = [pscustomobject][ordered]@{
            schema_version=1; anchor_contract='serctl-official-component-anchor-v1'
            release_tag=[string]$record.release_tag; commit=[string]$record.commit
            tag_object=[string]$record.tag_object; repository=[string]$record.repository
            synthetic_fixture=[bool]$record.synthetic_fixture
            sealable=(-not [bool]$record.synthetic_fixture)
            component_set_sha256=Get-OfficialAnchorSha256Internal $componentBytes
            component_set_base64=[Convert]::ToBase64String($componentBytes)
        }
        $outputBytes = [Text.UTF8Encoding]::new($false,$true).GetBytes(
            (($anchor | ConvertTo-Json -Compress -Depth 6) + "`n")
        )
        $copy = [Serctl.OfficialAnchor.Native]::Duplicate($ReceiptOutputHandle)
        $output = [IO.FileStream]::new($copy,[IO.FileAccess]::ReadWrite)
        try {
            Assert-OfficialAnchorInternal ($output.CanSeek -and $output.Length -eq 0) (
                'receipt output handle is not a pre-created empty regular file'
            )
            $output.Write($outputBytes,0,$outputBytes.Length); $output.Flush($true)
        }
        finally { $output.Dispose() }
    }
    finally {
        foreach($bytes in @($recordBytes,$componentBytes,$outputBytes)+$componentBuffers) {
            if($null -ne $bytes -and $bytes -is [byte[]]) {[Array]::Clear($bytes,0,$bytes.Length)}
        }
    }
}
