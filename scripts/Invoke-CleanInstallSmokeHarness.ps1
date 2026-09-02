[CmdletBinding(DefaultParameterSetName = 'Runtime')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Runtime')]
    [ValidateNotNullOrEmpty()]
    [string]$CandidateDirectory,

    [Parameter(Mandatory = $true, ParameterSetName = 'Runtime')]
    [ValidateNotNullOrEmpty()]
    [string]$PredecessorDirectory,

    [Parameter(Mandatory = $true, ParameterSetName = 'Runtime')]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$PredecessorCommit,

    [Parameter(Mandatory = $true, ParameterSetName = 'Runtime')]
    [ValidateNotNullOrEmpty()]
    [string]$ScratchParent,

    [Parameter(Mandatory = $true, ParameterSetName = 'Runtime')]
    [ValidateNotNullOrEmpty()]
    [string]$ReceiptPath,

    [Parameter(Mandatory = $true, ParameterSetName = 'Runtime')]
    [ValidatePattern('^v1\.0\.0-beta(?:\.(?:0|[1-9][0-9]*))?$')]
    [string]$Tag,

    [Parameter(Mandatory = $true, ParameterSetName = 'Runtime')]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$TagObject,

    [Parameter(Mandatory = $true, ParameterSetName = 'Runtime')]
    [ValidatePattern('^[0-9a-f]{40}$')]
    [string]$Commit,

    [Parameter(Mandatory = $true, ParameterSetName = 'Runtime')]
    [ValidatePattern('^[0-9A-F]{64}$')]
    [string]$ReleaseManifestSha256,

    [Parameter(Mandatory = $true, ParameterSetName = 'Runtime')]
    [ValidateNotNullOrEmpty()]
    [string]$EvidenceOwner,

    [Parameter(Mandatory = $true, ParameterSetName = 'SelfTest')]
    [switch]$SelfTest
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
try {
    . (Join-Path $PSScriptRoot 'StrictJson.ps1')
    . (Join-Path $PSScriptRoot 'ReleaseLogSanitization.ps1')
}
catch {
    [Console]::Error.WriteLine(
        "category=clean_install_dependency_failed; file='clean-install.evidence'; bytes=0"
    )
    exit 1
}

if ($env:OS -ceq 'Windows_NT' -and $null -eq ('SerctlCleanInstallNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class SerctlCleanInstallNative {
    public const uint GENERIC_READ = 0x80000000;
    public const uint READ_CONTROL = 0x00020000;
    public const uint FILE_SHARE_READ = 0x00000001;
    public const uint OPEN_EXISTING = 3;
    public const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
    public const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;

    [StructLayout(LayoutKind.Sequential)]
    public struct BY_HANDLE_FILE_INFORMATION {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern SafeFileHandle CreateFileW(
        string path, uint access, uint share, IntPtr securityAttributes,
        uint creationDisposition, uint flagsAndAttributes, IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool GetFileInformationByHandle(
        SafeFileHandle handle, out BY_HANDLE_FILE_INFORMATION information);
}
'@
}

$candidateStorageContract = 'vault-storage read=v4..=v5 write=v5'
$candidateIpcMin = 9
$candidateIpcMax = 9
$predecessorVersion = '0.3.0-beta.2'
$profileName = 'clean-install-local'
$dummyHost = '192.0.2.1'

function Assert-CleanInstallCondition {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if (-not $Condition) {
        throw "clean-install smoke failed: $Message"
    }
}

function Assert-SafeCleanInstallIdentity {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Label
    )
    Assert-CleanInstallCondition (
        -not [string]::IsNullOrWhiteSpace($Value) -and $Value.Length -le 128
    ) "$Label is empty or too long"
    Assert-CleanInstallCondition ($Value -notmatch '[\x00-\x1F\x7F]') (
        "$Label contains a control character"
    )
    Assert-CleanInstallCondition (
        $Value -notmatch '^[A-Za-z]:[\\/]' -and
        $Value -notmatch '^\\\\' -and
        $Value -notmatch '^/'
    ) "$Label contains an absolute local path"
}

function Get-RegularFileRecord {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedName
    )
    $full = [System.IO.Path]::GetFullPath($Path)
    $item = Get-Item -LiteralPath $full -Force -ErrorAction Stop
    Assert-CleanInstallCondition (-not $item.PSIsContainer) (
        "required component '$ExpectedName' is not a file"
    )
    Assert-CleanInstallCondition (
        $item.Name -ceq $ExpectedName -and
        ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0 -and
        $item.Length -gt 0
    ) "required component '$ExpectedName' has an unsafe file identity"
    return [ordered]@{
        path = $full
        length = [long]$item.Length
        sha256 = (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash.ToUpperInvariant()
    }
}

function Assert-FileRecordUnchanged {
    param(
        [Parameter(Mandatory = $true)]$Record,
        [Parameter(Mandatory = $true)][string]$ExpectedName
    )
    $current = Get-RegularFileRecord -Path $Record.path -ExpectedName $ExpectedName
    Assert-CleanInstallCondition (
        [long]$current.length -eq [long]$Record.length -and
        [string]$current.sha256 -ceq [string]$Record.sha256
    ) "component '$ExpectedName' changed after it was pinned"
}

function Open-PinnedCleanInstallFile {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedName,
        [Parameter(Mandatory = $true)][long]$MaximumBytes,
        $ExpectedRecord
    )
    Assert-CleanInstallCondition ($env:OS -ceq 'Windows_NT') (
        'no-follow file identity checks require Windows'
    )
    $full = [System.IO.Path]::GetFullPath($Path)
    Assert-CleanInstallCondition (
        [System.IO.Path]::GetFileName($full) -ceq $ExpectedName
    ) "protected file has an unexpected leaf name"
    $handle = [SerctlCleanInstallNative]::CreateFileW(
        $full,
        [SerctlCleanInstallNative]::GENERIC_READ -bor [SerctlCleanInstallNative]::READ_CONTROL,
        [SerctlCleanInstallNative]::FILE_SHARE_READ,
        [IntPtr]::Zero,
        [SerctlCleanInstallNative]::OPEN_EXISTING,
        [SerctlCleanInstallNative]::FILE_FLAG_OPEN_REPARSE_POINT,
        [IntPtr]::Zero
    )
    if ($handle.IsInvalid) {
        $handle.Dispose()
        throw 'clean-install smoke failed: protected file open failed; details withheld'
    }
    try {
        $information = New-Object SerctlCleanInstallNative+BY_HANDLE_FILE_INFORMATION
        Assert-CleanInstallCondition (
            [SerctlCleanInstallNative]::GetFileInformationByHandle($handle, [ref]$information)
        ) 'protected file identity query failed'
        Assert-CleanInstallCondition (
            ($information.FileAttributes -band [SerctlCleanInstallNative]::FILE_ATTRIBUTE_REPARSE_POINT) -eq 0
        ) 'protected file is a reparse point'
        $length = ([uint64]$information.FileSizeHigh -shl 32) -bor [uint64]$information.FileSizeLow
        Assert-CleanInstallCondition (
            $length -gt 0 -and $length -le [uint64]$MaximumBytes
        ) 'protected file violates its size bound'
        $stream = [System.IO.FileStream]::new($handle, [System.IO.FileAccess]::Read, 4096, $false)
        $handle = $null
        try {
            $sha = [System.Security.Cryptography.SHA256]::Create()
            try { $digest = $sha.ComputeHash($stream) }
            finally { $sha.Dispose() }
            $hash = ($digest | ForEach-Object { $_.ToString('X2') }) -join ''
            if ($null -ne $ExpectedRecord) {
                Assert-CleanInstallCondition (
                    [long]$ExpectedRecord.length -eq [long]$length -and
                    [string]$ExpectedRecord.sha256 -ceq $hash
                ) "component '$ExpectedName' changed after it was pinned"
            }
            $stream.Position = 0
            return [pscustomobject]@{
                stream = $stream
                length = [long]$length
                sha256 = $hash
                volume_serial = [uint32]$information.VolumeSerialNumber
                file_index = ('{0:X8}{1:X8}' -f $information.FileIndexHigh, $information.FileIndexLow)
            }
        }
        catch {
            if ($null -ne $stream) { $stream.Dispose() }
            throw
        }
    }
    catch {
        if ($null -ne $handle) { $handle.Dispose() }
        throw
    }
}

function Read-BoundedPinnedUtf8Text {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedName,
        [Parameter(Mandatory = $true)][long]$MaximumBytes,
        [switch]$RequireProtectedAcl
    )
    $opened = Open-PinnedCleanInstallFile -Path $Path -ExpectedName $ExpectedName -MaximumBytes $MaximumBytes
    try {
        if ($RequireProtectedAcl) {
            $acl = Get-Acl -LiteralPath ([System.IO.Path]::GetFullPath($Path)) -ErrorAction Stop
            Assert-CleanInstallCondition $acl.AreAccessRulesProtected (
                'protected runtime file still inherits access rules'
            )
            $identity = [System.Security.Principal.WindowsIdentity]::GetCurrent()
            $ownerSid = ([System.Security.Principal.NTAccount]$acl.Owner).Translate(
                [System.Security.Principal.SecurityIdentifier]
            )
            Assert-CleanInstallCondition (
                $ownerSid.Value -ceq $identity.User.Value -or
                ($null -ne $identity.Owner -and $ownerSid.Value -ceq $identity.Owner.Value)
            ) 'protected runtime file owner is not the current token owner'
            $allowed = @(
                $identity.User.Value,
                'S-1-5-18', 'S-1-5-32-544'
            )
            $rules = @($acl.GetAccessRules($true, $false, [System.Security.Principal.SecurityIdentifier]))
            Assert-CleanInstallCondition ($rules.Count -eq 3) 'protected runtime file ACL is not exact'
            foreach ($rule in $rules) {
                Assert-CleanInstallCondition (
                    $allowed -ccontains $rule.IdentityReference.Value -and
                    $rule.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow -and
                    -not $rule.IsInherited -and
                    (($rule.FileSystemRights -band [System.Security.AccessControl.FileSystemRights]::FullControl) -eq
                        [System.Security.AccessControl.FileSystemRights]::FullControl)
                ) 'protected runtime file ACL contains an unauthorized rule'
            }
        }
        $bytes = New-Object byte[] ([int]$opened.length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $opened.stream.Read($bytes, $offset, $bytes.Length - $offset)
            Assert-CleanInstallCondition ($read -gt 0) 'protected file was truncated while held'
            $offset += $read
        }
        $encoding = [System.Text.UTF8Encoding]::new($false, $true)
        $text = $encoding.GetString($bytes)
        return [pscustomobject]@{
            text = $text
            length = $opened.length
            sha256 = $opened.sha256
            volume_serial = $opened.volume_serial
            file_index = $opened.file_index
        }
    }
    finally {
        $opened.stream.Dispose()
        $bytes = $null
    }
}

function Quote-NativeArgument {
    param([Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value)
    if ($Value -notmatch '[\s"]') { return $Value }
    return '"' + (($Value -replace '(\\*)"', '$1$1\"') -replace '(\\+)$', '$1$1') + '"'
}

function Invoke-IsolatedCleanInstallProcess {
    param(
        [Parameter(Mandatory = $true)][string]$Binary,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Home,
        [Parameter(Mandatory = $true)][string]$LocalAppData,
        [Parameter(Mandatory = $true)][string]$RoamingAppData,
        [Parameter(Mandatory = $true)][string]$Temp,
        [hashtable]$SecretEnvironment = @{},
        [AllowEmptyString()][string]$StandardInputText = '',
        $ExpectedBinaryRecord,
        [hashtable]$DaemonObserver,
        [ValidateRange(1, 120)][int]$TimeoutSeconds = 45
    )

    $start = [System.Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $Binary
    $start.Arguments = (@($Arguments | ForEach-Object { Quote-NativeArgument $_ }) -join ' ')
    $start.WorkingDirectory = $Home
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($name in @(
        'SERCTL_SSH_PASS', 'SERCTL_PROFILE_PASS', 'SERCTL_ADMIN_PASS',
        'SERCTL_LEGACY_MASTER', 'SERCTL_MASTER'
    )) {
        [void]$start.EnvironmentVariables.Remove($name)
    }
    $environment = [ordered]@{
        HOME = $Home
        USERPROFILE = $Home
        LOCALAPPDATA = $LocalAppData
        APPDATA = $RoamingAppData
        TEMP = $Temp
        TMP = $Temp
        XDG_CONFIG_HOME = (Join-Path $Home 'config')
        XDG_STATE_HOME = (Join-Path $Home 'state')
    }
    foreach ($name in $environment.Keys) {
        $start.EnvironmentVariables[$name] = [string]$environment[$name]
    }
    foreach ($name in $SecretEnvironment.Keys) {
        Assert-CleanInstallCondition (
            @(
                'SERCTL_SSH_PASS', 'SERCTL_PROFILE_PASS', 'SERCTL_ADMIN_PASS',
                'SERCTL_MASTER'
            ) -ccontains $name
        ) 'runtime process requested an unsupported secret environment variable'
        $start.EnvironmentVariables[$name] = [string]$SecretEnvironment[$name]
    }

    $binaryHold = $null
    if ($null -ne $ExpectedBinaryRecord) {
        $binaryHold = Open-PinnedCleanInstallFile `
            -Path $Binary `
            -ExpectedName ([System.IO.Path]::GetFileName($Binary)) `
            -MaximumBytes ([long]$ExpectedBinaryRecord.length) `
            -ExpectedRecord $ExpectedBinaryRecord
    }
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $start
    $stdoutBuffer = [System.IO.MemoryStream]::new()
    $stderrBuffer = [System.IO.MemoryStream]::new()
    try {
        Assert-CleanInstallCondition $process.Start() 'isolated child process did not start'
        if (-not [string]::IsNullOrEmpty($StandardInputText)) {
            $process.StandardInput.Write($StandardInputText)
        }
        $process.StandardInput.Close()
        $stdoutChunk = New-Object byte[] 16384
        $stderrChunk = New-Object byte[] 16384
        $stdoutTask = $process.StandardOutput.BaseStream.ReadAsync($stdoutChunk, 0, $stdoutChunk.Length)
        $stderrTask = $process.StandardError.BaseStream.ReadAsync($stderrChunk, 0, $stderrChunk.Length)
        $stdoutDone = $false
        $stderrDone = $false
        $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
        while (-not ($process.HasExited -and $stdoutDone -and $stderrDone)) {
            if ($null -ne $DaemonObserver) {
                Update-CleanInstallDaemonOwner -Observer $DaemonObserver
            }
            if (-not $stdoutDone -and $stdoutTask.IsCompleted) {
                $count = $stdoutTask.GetAwaiter().GetResult()
                if ($count -eq 0) { $stdoutDone = $true }
                else {
                    $stdoutBuffer.Write($stdoutChunk, 0, $count)
                    Assert-CleanInstallCondition ($stdoutBuffer.Length -le 1048576) (
                        'isolated child output exceeded its retained bound; output withheld'
                    )
                    $stdoutTask = $process.StandardOutput.BaseStream.ReadAsync(
                        $stdoutChunk, 0, $stdoutChunk.Length
                    )
                }
            }
            if (-not $stderrDone -and $stderrTask.IsCompleted) {
                $count = $stderrTask.GetAwaiter().GetResult()
                if ($count -eq 0) { $stderrDone = $true }
                else {
                    $stderrBuffer.Write($stderrChunk, 0, $count)
                    Assert-CleanInstallCondition ($stderrBuffer.Length -le 1048576) (
                        'isolated child output exceeded its retained bound; output withheld'
                    )
                    $stderrTask = $process.StandardError.BaseStream.ReadAsync(
                        $stderrChunk, 0, $stderrChunk.Length
                    )
                }
            }
            if ([DateTimeOffset]::UtcNow -ge $deadline) {
                throw 'clean-install smoke failed: isolated child exceeded its deadline; output withheld'
            }
            Start-Sleep -Milliseconds 10
        }
        $process.WaitForExit()
        if ($null -ne $DaemonObserver) {
            Update-CleanInstallDaemonOwner -Observer $DaemonObserver
        }
        $encoding = [System.Text.UTF8Encoding]::new($false, $true)
        $stdout = $encoding.GetString($stdoutBuffer.ToArray())
        $stderr = $encoding.GetString($stderrBuffer.ToArray())
        if ($null -ne $ExpectedBinaryRecord) {
            Assert-FileRecordUnchanged `
                -Record $ExpectedBinaryRecord `
                -ExpectedName ([System.IO.Path]::GetFileName($Binary))
        }
        return [pscustomobject]@{
            exit_code = [int]$process.ExitCode
            stdout = $stdout
            stderr = $stderr
        }
    }
    catch {
        if (-not $process.HasExited) {
            try { $process.Kill() } catch {}
            try { [void]$process.WaitForExit(5000) } catch {}
        }
        throw
    }
    finally {
        $stdoutBuffer.Dispose()
        $stderrBuffer.Dispose()
        $process.Dispose()
        if ($null -ne $binaryHold) { $binaryHold.stream.Dispose() }
    }
}

function Get-ExactCandidateIdentity {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('cli', 'daemon')][string]$Kind,
        [Parameter(Mandatory = $true)][string]$Line,
        [Parameter(Mandatory = $true)][string]$Version,
        [Parameter(Mandatory = $true)][string]$FullCommit
    )
    $short = $FullCommit.Substring(0, 12)
    $prefix = if ($Kind -ceq 'cli') { 'serctl_cli' } else { 'serctl_daemon' }
    $contract = if ($Kind -ceq 'cli') {
        [regex]::Escape($candidateStorageContract)
    }
    else {
        'IPC v9\.\.=v9; ' + [regex]::Escape($candidateStorageContract)
    }
    $pattern = '^' + $prefix + ' ' + [regex]::Escape($Version) +
        ' \(git ' + [regex]::Escape($short) + '; ' + $contract + '\)$'
    Assert-CleanInstallCondition (
        [regex]::IsMatch(
            $Line,
            $pattern,
            [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
        )
    ) "$Kind identity does not match the exact candidate grammar"
}

function Get-ExactPredecessorIdentity {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('cli', 'daemon')][string]$Kind,
        [Parameter(Mandatory = $true)][string]$Line,
        [Parameter(Mandatory = $true)][string]$FullCommit
    )
    $short = $FullCommit.Substring(0, 12)
    $pattern = if ($Kind -ceq 'cli') {
        '^serctl_cli 0\.3\.0-beta\.2 \(git ' + [regex]::Escape($short) + '\)$'
    }
    else {
        '^serctl_daemon 0\.3\.0-beta\.2 \(git ' + [regex]::Escape($short) +
            '; IPC v8\.\.=v8\)$'
    }
    Assert-CleanInstallCondition (
        [regex]::IsMatch(
            $Line,
            $pattern,
            [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
        )
    ) "$Kind identity does not match the exact predecessor grammar"
}

function Get-VersionLine {
    param(
        [Parameter(Mandatory = $true)][string]$Binary,
        [Parameter(Mandatory = $true)]$Isolation,
        [Parameter(Mandatory = $true)]$ExpectedBinaryRecord
    )
    $result = Invoke-IsolatedCleanInstallProcess `
        -Binary $Binary `
        -Arguments @('--version') `
        -Home $Isolation.home `
        -LocalAppData $Isolation.local `
        -RoamingAppData $Isolation.roaming `
        -Temp $Isolation.temp `
        -ExpectedBinaryRecord $ExpectedBinaryRecord
    Assert-CleanInstallCondition ($result.exit_code -eq 0) (
        'component version probe failed; output withheld'
    )
    $line = $result.stdout.Trim()
    Assert-CleanInstallCondition (
        -not [string]::IsNullOrWhiteSpace($line) -and
        $line.Length -le 256 -and
        $line -notmatch '[\r\n]'
    ) 'component version probe did not return one bounded line'
    return $line
}

function Add-CleanInstallFullControlRule {
    param(
        [Parameter(Mandatory = $true)]$Acl,
        [Parameter(Mandatory = $true)]$Sid,
        [Parameter(Mandatory = $true)][bool]$Directory
    )
    if ($Directory) {
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $Sid,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit',
            [System.Security.AccessControl.PropagationFlags]::None,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
    }
    else {
        $rule = [System.Security.AccessControl.FileSystemAccessRule]::new(
            $Sid,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.AccessControlType]::Allow
        )
    }
    $Acl.AddAccessRule($rule)
}

function Set-ProtectedCleanInstallAcl {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][bool]$Directory
    )
    $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = if ($Directory) {
        [System.Security.AccessControl.DirectorySecurity]::new()
    }
    else {
        [System.Security.AccessControl.FileSecurity]::new()
    }
    $acl.SetOwner($currentSid)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @(
        $currentSid,
        [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18'),
        [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    )) {
        Add-CleanInstallFullControlRule -Acl $acl -Sid $sid -Directory $Directory
    }
    Set-Acl -LiteralPath $Path -AclObject $acl -ErrorAction Stop
    $written = Get-Acl -LiteralPath $Path -ErrorAction Stop
    Assert-CleanInstallCondition $written.AreAccessRulesProtected (
        'protected object still inherits access rules'
    )
}

function Write-ProtectedCleanInstallReceipt {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][byte[]]$Bytes
    )
    $full = [System.IO.Path]::GetFullPath($Path)
    $parentPath = [System.IO.Path]::GetDirectoryName($full)
    Assert-CleanInstallCondition (-not [string]::IsNullOrWhiteSpace($parentPath)) (
        'receipt destination has no parent directory'
    )
    $parent = Get-Item -LiteralPath $parentPath -Force -ErrorAction Stop
    Assert-CleanInstallCondition (
        $parent.PSIsContainer -and
        ($parent.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0
    ) 'receipt parent is not a regular directory'
    Assert-CleanInstallCondition (-not (Test-Path -LiteralPath $full)) (
        'receipt destination already exists; refusing replacement'
    )
    $digest = [System.Security.Cryptography.SHA256]::Create()
    try {
        $expected = ($digest.ComputeHash($Bytes) | ForEach-Object { $_.ToString('x2') }) -join ''
    }
    finally { $digest.Dispose() }
    $stream = [System.IO.FileStream]::new(
        $full,
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None,
        4096,
        [System.IO.FileOptions]::WriteThrough
    )
    try {
        $stream.Write($Bytes, 0, $Bytes.Length)
        $stream.Flush($true)
        Set-ProtectedCleanInstallAcl -Path $full -Directory $false
    }
    catch {
        $stream.Dispose()
        try { Remove-Item -LiteralPath $full -Force -ErrorAction Stop } catch {}
        throw 'clean-install smoke failed: protected receipt write failed; details withheld'
    }
    finally { $stream.Dispose() }
    $item = Get-Item -LiteralPath $full -Force -ErrorAction Stop
    Assert-CleanInstallCondition (
        -not $item.PSIsContainer -and
        ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0 -and
        $item.Length -eq $Bytes.Length
    ) 'protected receipt post-write identity check failed'
    Assert-CleanInstallCondition (
        (Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash.ToLowerInvariant() -ceq $expected
    ) 'protected receipt bytes do not match the same-process digest'
}

function Write-CleanInstallAcceptanceReceipt {
    param(
        [Parameter(Mandatory = $true)]$RuntimeResult,
        [Parameter(Mandatory = $true)][DateTimeOffset]$StartedUtc,
        [Parameter(Mandatory = $true)][DateTimeOffset]$CompletedUtc,
        [Parameter(Mandatory = $true)][string]$OutputPath,
        [Parameter(Mandatory = $true)][string]$ReceiptTag,
        [Parameter(Mandatory = $true)][string]$ReceiptTagObject,
        [Parameter(Mandatory = $true)][string]$ReceiptCommit,
        [Parameter(Mandatory = $true)][string]$ManifestSha256,
        [Parameter(Mandatory = $true)][string]$Owner
    )
    Assert-SafeCleanInstallIdentity -Value $Owner -Label 'evidence owner'
    foreach ($field in @(
        'fresh_home', 'install_passed', 'status_passed', 'grant_issue_passed',
        'cleanup_passed', 'rollback_passed'
    )) {
        Assert-CleanInstallCondition (
            $RuntimeResult.details[$field] -is [bool] -and
            [bool]$RuntimeResult.details[$field]
        ) "same-process runtime result did not pass '$field'"
    }
    $receipt = [ordered]@{
        schema_version = 1
        category = 'clean_install_smoke'
        status = 'passed'
        tag = $ReceiptTag
        tag_object = $ReceiptTagObject
        commit = $ReceiptCommit
        release_manifest_sha256 = $ManifestSha256
        evidence_owner = $Owner
        timestamps = [ordered]@{
            started_utc = $StartedUtc.ToString('o')
            completed_utc = $CompletedUtc.ToString('o')
        }
        test_counts = [ordered]@{
            total = 6
            passed = 6
            failed = 0
            skipped = 0
            ignored = 0
            unknown = 0
        }
        limitations = @(
            'Windows x86_64 clean-install smoke; no SSH transport or remote operation was attempted.'
        )
        details = $RuntimeResult.details
    }
    $json = ($receipt | ConvertTo-Json -Depth 12) + "`n"
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($json)
    Assert-CleanInstallCondition ($bytes.Length -le 65536) 'receipt exceeds 64 KiB'
    Write-ProtectedCleanInstallReceipt -Path $OutputPath -Bytes $bytes
}

function Copy-PinnedComponent {
    param(
        [Parameter(Mandatory = $true)]$SourceRecord,
        [Parameter(Mandatory = $true)][string]$Destination
    )
    Assert-FileRecordUnchanged -Record $SourceRecord -ExpectedName (
        [System.IO.Path]::GetFileName($SourceRecord.path)
    )
    $input = [System.IO.FileStream]::new(
        $SourceRecord.path,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read
    )
    $output = [System.IO.FileStream]::new(
        $Destination,
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None,
        1048576,
        [System.IO.FileOptions]::WriteThrough
    )
    try {
        $input.CopyTo($output)
        $output.Flush($true)
    }
    finally {
        $output.Dispose()
        $input.Dispose()
    }
    $copied = Get-RegularFileRecord `
        -Path $Destination `
        -ExpectedName ([System.IO.Path]::GetFileName($Destination))
    Assert-CleanInstallCondition (
        [long]$copied.length -eq [long]$SourceRecord.length -and
        [string]$copied.sha256 -ceq [string]$SourceRecord.sha256
    ) 'installed component differs from its pinned downloaded bytes'
}

function Get-IsolationPaths {
    param([Parameter(Mandatory = $true)][string]$Root)
    $result = [ordered]@{
        home = (Join-Path $Root 'home')
        local = (Join-Path $Root 'local-app-data')
        roaming = (Join-Path $Root 'roaming-app-data')
        temp = (Join-Path $Root 'temp')
    }
    foreach ($path in $result.Values) {
        [System.IO.Directory]::CreateDirectory($path) | Out-Null
    }
    return $result
}

function Wait-CleanInstallProcessExit {
    param(
        [Parameter(Mandatory = $true)][int64]$Pid,
        [ValidateRange(1, 30)][int]$TimeoutSeconds = 15
    )
    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    while ([DateTimeOffset]::UtcNow -lt $deadline) {
        if ($null -eq (Get-Process -Id $Pid -ErrorAction SilentlyContinue)) { return $true }
        Start-Sleep -Milliseconds 100
    }
    return $false
}

function Update-CleanInstallDaemonOwner {
    param([Parameter(Mandatory = $true)][hashtable]$Observer)
    if ($null -ne $Observer.owner -or -not (Test-Path -LiteralPath $Observer.descriptor_path -PathType Leaf)) {
        return
    }
    $descriptorFile = Read-BoundedPinnedUtf8Text `
        -Path $Observer.descriptor_path -ExpectedName 'daemon.json' `
        -MaximumBytes 4096 -RequireProtectedAcl
    $secretFile = Read-BoundedPinnedUtf8Text `
        -Path $Observer.secret_path -ExpectedName 'daemon.secret' `
        -MaximumBytes 128 -RequireProtectedAcl
    try {
        Assert-CleanInstallCondition (
            $secretFile.text.Trim() -cmatch '^[A-Za-z0-9+/]{43}=$'
        ) 'activation secret does not have the exact bounded encoding'
        $descriptor = ConvertFrom-StrictJson -Json $descriptorFile.text -Label 'daemon descriptor'
        $fields = @($descriptor.PSObject.Properties.Name | Sort-Object)
        $expected = @(
            'build_commit', 'endpoint', 'instance_id', 'pid', 'protocol_max',
            'protocol_min', 'started_unix', 'version'
        ) | Sort-Object
        Assert-CleanInstallCondition (
            ($fields -join "`n") -ceq ($expected -join "`n") -and
            [int]$descriptor.version -eq 1 -and
            [int]$descriptor.protocol_min -eq [int]$Observer.ipc_min -and
            [int]$descriptor.protocol_max -eq [int]$Observer.ipc_max -and
            [string]$descriptor.build_commit -ceq [string]$Observer.build_commit -and
            [string]$descriptor.instance_id -cmatch '^[0-9a-f]{32}$' -and
            [string]$descriptor.endpoint -ceq ('\\.\pipe\serctl-v6-' + [string]$descriptor.instance_id) -and
            [int64]$descriptor.pid -gt 0
        ) 'runtime descriptor is not the exact candidate identity'
        $owned = Get-Process -Id ([int64]$descriptor.pid) -ErrorAction Stop
        [void]$owned.Handle
        $start = $owned.StartTime.ToUniversalTime()
        Assert-CleanInstallCondition (
            [System.IO.Path]::GetFullPath($owned.Path) -ceq
                [System.IO.Path]::GetFullPath($Observer.daemon_path) -and
            $start -ge $Observer.launch_utc.UtcDateTime.AddSeconds(-2) -and
            [Math]::Abs(([DateTimeOffset]$start).ToUnixTimeSeconds() - [int64]$descriptor.started_unix) -le 5
        ) 'runtime descriptor process is not the observed child daemon'
        $heldDaemon = Open-PinnedCleanInstallFile `
            -Path $Observer.daemon_path -ExpectedName 'serctl_daemon.exe' `
            -MaximumBytes ([long]$Observer.daemon_record.length) `
            -ExpectedRecord $Observer.daemon_record
        $heldDaemon.stream.Dispose()
        $Observer.owner = [pscustomobject]@{
            process = $owned
            pid = [int64]$owned.Id
            start_ticks = [int64]$owned.StartTime.ToUniversalTime().Ticks
            instance_id = [string]$descriptor.instance_id
            descriptor_version = [int]$descriptor.version
            protocol_min = [int]$descriptor.protocol_min
            protocol_max = [int]$descriptor.protocol_max
            build_commit = [string]$descriptor.build_commit
            descriptor_identity = "$($descriptorFile.volume_serial):$($descriptorFile.file_index)"
            secret_identity = "$($secretFile.volume_serial):$($secretFile.file_index)"
        }
    }
    finally {
        $secretFile.text = $null
    }
}

function Find-CleanInstallOwnedDaemon {
    param([Parameter(Mandatory = $true)][hashtable]$Observer)
    if ($null -ne $Observer.owner) { return }
    $matches = @()
    foreach ($process in @(Get-Process -Name 'serctl_daemon' -ErrorAction SilentlyContinue)) {
        try {
            [void]$process.Handle
            if ([System.IO.Path]::GetFullPath($process.Path) -ceq
                    [System.IO.Path]::GetFullPath($Observer.daemon_path) -and
                $process.StartTime.ToUniversalTime() -ge $Observer.launch_utc.UtcDateTime.AddSeconds(-2)) {
                $matches += $process
            }
        }
        catch { $process.Dispose() }
    }
    Assert-CleanInstallCondition ($matches.Count -le 1) (
        'isolated daemon ownership is ambiguous; refusing PID-based cleanup'
    )
    if ($matches.Count -eq 1) {
        $held = Open-PinnedCleanInstallFile `
            -Path $Observer.daemon_path -ExpectedName 'serctl_daemon.exe' `
            -MaximumBytes ([long]$Observer.daemon_record.length) `
            -ExpectedRecord $Observer.daemon_record
        $held.stream.Dispose()
        $Observer.owner = [pscustomobject]@{
            process = $matches[0]
            pid = [int64]$matches[0].Id
            start_ticks = [int64]$matches[0].StartTime.ToUniversalTime().Ticks
            instance_id = 'unpublished'
            descriptor_identity = 'unpublished'
            secret_identity = 'unpublished'
        }
    }
}

function Stop-CleanInstallOwnedDaemon {
    param([Parameter(Mandatory = $true)][hashtable]$Observer)
    Find-CleanInstallOwnedDaemon -Observer $Observer
    if ($null -eq $Observer.owner) { return }
    $owned = $Observer.owner
    try {
        if (-not $owned.process.HasExited) {
            Assert-CleanInstallCondition (
                [int64]$owned.process.Id -eq [int64]$owned.pid -and
                [int64]$owned.process.StartTime.ToUniversalTime().Ticks -eq [int64]$owned.start_ticks -and
                [System.IO.Path]::GetFullPath($owned.process.Path) -ceq
                    [System.IO.Path]::GetFullPath($Observer.daemon_path)
            ) 'daemon process handle identity changed; refusing cleanup'
            $owned.process.Kill()
            Assert-CleanInstallCondition ($owned.process.WaitForExit(15000)) (
                'isolated daemon did not terminate during failure cleanup'
            )
        }
    }
    finally {
        $owned.process.Dispose()
        $Observer.owner = $null
    }
}

function Assert-CleanInstallJsonFields {
    param(
        [Parameter(Mandatory = $true)]$Object,
        [Parameter(Mandatory = $true)][string[]]$Expected,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $actual = @($Object.PSObject.Properties.Name | Sort-Object)
    $wanted = @($Expected | Sort-Object)
    Assert-CleanInstallCondition (($actual -join "`n") -ceq ($wanted -join "`n")) (
        "$Label has unknown or missing fields"
    )
}

function Assert-CleanInstallByteArray {
    param(
        [Parameter(Mandatory = $true)]$Value,
        [Parameter(Mandatory = $true)][int]$Length,
        [Parameter(Mandatory = $true)][string]$Label
    )
    $items = @($Value)
    Assert-CleanInstallCondition ($items.Count -eq $Length) "$Label has an invalid length"
    foreach ($item in $items) {
        Assert-CleanInstallCondition (
            $item -is [long] -or $item -is [int] -or $item -is [byte]
        ) "$Label contains a non-integer byte"
        Assert-CleanInstallCondition ([int64]$item -ge 0 -and [int64]$item -le 255) (
            "$Label contains an out-of-range byte"
        )
    }
    Assert-CleanInstallCondition (@($items | Where-Object { [int64]$_ -ne 0 }).Count -gt 0) (
        "$Label is all zero"
    )
}

function Read-CleanInstallGrantMetadata {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedProfile,
        [Parameter(Mandatory = $true)][DateTimeOffset]$IssuedNotBefore,
        [Parameter(Mandatory = $true)][DateTimeOffset]$IssuedNotAfter
    )
    $file = Read-BoundedPinnedUtf8Text `
        -Path $Path -ExpectedName ([System.IO.Path]::GetFileName($Path)) `
        -MaximumBytes 65536 -RequireProtectedAcl
    $document = $null
    try {
        $document = ConvertFrom-StrictJson -Json $file.text -Label 'OperationGrant file'
        Assert-CleanInstallJsonFields -Object $document `
            -Expected @('agent_key', 'grant') -Label 'OperationGrant file'
        Assert-CleanInstallCondition (
            [string]$document.agent_key -cmatch '^[A-Za-z0-9+/]{43}=$'
        ) 'OperationGrant private key encoding is invalid'
        $grant = $document.grant
        Assert-CleanInstallJsonFields -Object $grant -Expected @(
            'budget', 'expires_unix_ms', 'grant_id', 'holder_key', 'issued_unix_ms',
            'operations', 'profile_generation', 'profile_id', 'profile_name'
        ) -Label 'OperationGrant public metadata'
        Assert-CleanInstallByteArray -Value $grant.grant_id -Length 16 -Label 'grant id'
        Assert-CleanInstallByteArray -Value $grant.profile_id -Length 16 -Label 'profile id'
        Assert-CleanInstallByteArray -Value $grant.holder_key -Length 32 -Label 'holder key'
        Assert-CleanInstallCondition (
            [string]$grant.profile_name -ceq $ExpectedProfile -and
            [uint64]$grant.profile_generation -eq 1 -and
            [uint64]$grant.budget -eq 1 -and
            @($grant.operations).Count -eq 1 -and
            [string]@($grant.operations)[0] -ceq 'daemon.status'
        ) 'OperationGrant profile identity, scope, or budget is not exact'
        $issued = [uint64]$grant.issued_unix_ms
        $expires = [uint64]$grant.expires_unix_ms
        Assert-CleanInstallCondition (
            $expires -gt $issued -and ($expires - $issued) -eq 60000 -and
            $issued -ge [uint64]$IssuedNotBefore.AddSeconds(-5).ToUnixTimeMilliseconds() -and
            $issued -le [uint64]$IssuedNotAfter.AddSeconds(5).ToUnixTimeMilliseconds()
        ) 'OperationGrant TTL or issuance time is outside the one-minute policy'
        return [pscustomobject]@{
            profile_name = [string]$grant.profile_name
            profile_generation = [uint64]$grant.profile_generation
            budget = [uint64]$grant.budget
            operation = [string]@($grant.operations)[0]
            ttl_ms = [uint64]($expires - $issued)
            file_identity = "$($file.volume_serial):$($file.file_index)"
        }
    }
    finally {
        if ($null -ne $document) {
            $document.agent_key = $null
            $document = $null
        }
        $file.text = $null
    }
}

function Assert-CleanInstallAgentConsumption {
    param(
        [Parameter(Mandatory = $true)]$Result,
        [Parameter(Mandatory = $true)][string]$ExpectedProfile
    )
    Assert-CleanInstallCondition (
        $Result.exit_code -eq 0 -and [string]::IsNullOrWhiteSpace($Result.stderr)
    ) 'Agent status consumption process failed; output withheld'
    $lines = @($Result.stdout -split '\r?\n' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
    Assert-CleanInstallCondition ($lines.Count -eq 2) 'Agent did not return exactly two result lines'
    $first = ConvertFrom-StrictJson -Json $lines[0] -Label 'first Agent result'
    $second = ConvertFrom-StrictJson -Json $lines[1] -Label 'second Agent result'
    Assert-CleanInstallJsonFields -Object $first `
        -Expected @('data', 'ok', 'request_id', 'schema_version') -Label 'first Agent result'
    Assert-CleanInstallJsonFields -Object $first.data `
        -Expected @('host', 'profile', 'started_unix', 'user') -Label 'Agent status data'
    Assert-CleanInstallCondition (
        [uint64]$first.schema_version -eq 1 -and [uint64]$first.request_id -eq 1 -and
        [bool]$first.ok -and [string]$first.data.profile -ceq $ExpectedProfile -and
        [string]$first.data.host -ceq $dummyHost -and
        [string]$first.data.user -ceq 'serctl-smoke'
    ) 'first Agent daemon.status result is not the exact local fixture'
    Assert-CleanInstallJsonFields -Object $second `
        -Expected @('error', 'error_code', 'ok', 'request_id', 'schema_version') `
        -Label 'second Agent result'
    Assert-CleanInstallCondition (
        [uint64]$second.schema_version -eq 1 -and [uint64]$second.request_id -eq 2 -and
        -not [bool]$second.ok -and
        [string]$second.error_code -ceq 'agent.operation_failed' -and
        -not [string]::IsNullOrWhiteSpace([string]$second.error) -and
        [string]$second.error -notmatch '[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]'
    ) 'second Agent daemon.status request was not rejected after budget exhaustion'
}

function Get-CleanInstallFailureLogRecord {
    return Format-ReleaseLogRecord `
        -Category 'clean_install_runtime_failed' `
        -LeafName 'clean-install.evidence' `
        -Bytes 0
}

function Remove-OwnedCleanInstallRoot {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Parent,
        [Parameter(Mandatory = $true)][string]$OwnerToken
    )
    $full = [System.IO.Path]::GetFullPath($Root)
    $prefix = [System.IO.Path]::GetFullPath($Parent).TrimEnd('\', '/') +
        [System.IO.Path]::DirectorySeparatorChar
    Assert-CleanInstallCondition (
        $full.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)
    ) 'cleanup root escaped the caller-provided scratch parent'
    $marker = Join-Path $full '.serctl-clean-install-owner'
    Assert-CleanInstallCondition (Test-Path -LiteralPath $marker -PathType Leaf) (
        'cleanup owner marker is absent'
    )
    Assert-CleanInstallCondition (
        (Get-Content -LiteralPath $marker -Encoding utf8 -Raw).Trim() -ceq $OwnerToken
    ) 'cleanup owner marker does not match this harness process'
    $item = Get-Item -LiteralPath $full -Force -ErrorAction Stop
    Assert-CleanInstallCondition (
        $item.PSIsContainer -and
        ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0
    ) 'cleanup root is not a regular directory'
    Remove-Item -LiteralPath $full -Recurse -Force -ErrorAction Stop
    Assert-CleanInstallCondition (-not (Test-Path -LiteralPath $full)) (
        'isolated clean-install root remained after cleanup'
    )
}

function Invoke-CleanInstallRuntime {
    param(
        [Parameter(Mandatory = $true)][string]$CandidateRoot,
        [Parameter(Mandatory = $true)][string]$PredecessorRoot,
        [Parameter(Mandatory = $true)][string]$PreviousCommit,
        [Parameter(Mandatory = $true)][string]$Scratch,
        [Parameter(Mandatory = $true)][string]$CandidateVersion,
        [Parameter(Mandatory = $true)][string]$CandidateCommit
    )
    Assert-CleanInstallCondition (
        $env:OS -ceq 'Windows_NT' -and
        [Environment]::Is64BitOperatingSystem -and
        [Environment]::Is64BitProcess
    ) 'formal clean-install runtime requires native Windows X64'
    Assert-CleanInstallCondition (
        $env:GITHUB_ACTIONS -ceq 'true' -and
        $env:RUNNER_ENVIRONMENT -ceq 'github-hosted' -and
        -not [string]::IsNullOrWhiteSpace($env:RUNNER_TEMP) -and
        [System.IO.Path]::GetFullPath($Scratch).StartsWith(
            [System.IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd('\', '/') +
                [System.IO.Path]::DirectorySeparatorChar,
            [StringComparison]::OrdinalIgnoreCase
        )
    ) 'formal clean-install runtime requires a disposable GitHub-hosted runner scratch root'

    $candidateRootItem = Get-Item -LiteralPath ([System.IO.Path]::GetFullPath($CandidateRoot)) -Force
    $predecessorRootItem = Get-Item -LiteralPath ([System.IO.Path]::GetFullPath($PredecessorRoot)) -Force
    foreach ($item in @($candidateRootItem, $predecessorRootItem)) {
        Assert-CleanInstallCondition (
            $item.PSIsContainer -and
            ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0
        ) 'bundle source is not a regular directory'
    }
    $candidateCliSource = Get-RegularFileRecord `
        -Path (Join-Path $candidateRootItem.FullName 'serctl_cli.exe') `
        -ExpectedName 'serctl_cli.exe'
    $candidateDaemonSource = Get-RegularFileRecord `
        -Path (Join-Path $candidateRootItem.FullName 'serctl_daemon.exe') `
        -ExpectedName 'serctl_daemon.exe'
    $previousCliSource = Get-RegularFileRecord `
        -Path (Join-Path $predecessorRootItem.FullName 'serctl_cli.exe') `
        -ExpectedName 'serctl_cli.exe'
    $previousDaemonSource = Get-RegularFileRecord `
        -Path (Join-Path $predecessorRootItem.FullName 'serctl_daemon.exe') `
        -ExpectedName 'serctl_daemon.exe'

    $scratchParentItem = Get-Item -LiteralPath ([System.IO.Path]::GetFullPath($Scratch)) -Force
    Assert-CleanInstallCondition (
        $scratchParentItem.PSIsContainer -and
        ($scratchParentItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0
    ) 'scratch parent is not a regular directory'
    $ownerToken = [System.Guid]::NewGuid().ToString('N')
    $root = $null
    $candidateObserver = $null
    $rollbackObserver = $null
    $profilePass = $null
    $adminPass = $null
    $sshPass = $null
    try {
    $root = Join-Path $scratchParentItem.FullName ('clean-install-' + $ownerToken)
    [System.IO.Directory]::CreateDirectory($root) | Out-Null
    Set-ProtectedCleanInstallAcl -Path $root -Directory $true
    [System.IO.File]::WriteAllText(
        (Join-Path $root '.serctl-clean-install-owner'),
        $ownerToken + "`n",
        [System.Text.UTF8Encoding]::new($false)
    )
    $install = Join-Path $root 'install'
    [System.IO.Directory]::CreateDirectory($install) | Out-Null
    $candidateIsolation = Get-IsolationPaths -Root (Join-Path $root 'candidate-runtime')
    $rollbackIsolation = Get-IsolationPaths -Root (Join-Path $root 'rollback-runtime')
    $candidateCli = Join-Path $install 'serctl_cli.exe'
    $candidateDaemon = Join-Path $install 'serctl_daemon.exe'
    $profilePass = 'profile-' + [System.Guid]::NewGuid().ToString('N')
    $adminPass = 'admin-' + [System.Guid]::NewGuid().ToString('N')
    $sshPass = 'ssh-' + [System.Guid]::NewGuid().ToString('N')
    $profileSecret = @{ SERCTL_PROFILE_PASS = $profilePass }
        Assert-CleanInstallCondition (
            @(Get-ChildItem -LiteralPath $candidateIsolation.home -Force).Count -eq 0 -and
            @(Get-ChildItem -LiteralPath $candidateIsolation.local -Force).Count -eq 0
        ) 'candidate HOME or LOCALAPPDATA was not fresh before installation'
        Copy-PinnedComponent -SourceRecord $candidateCliSource -Destination $candidateCli
        Copy-PinnedComponent -SourceRecord $candidateDaemonSource -Destination $candidateDaemon
        $installedCandidateCli = Get-RegularFileRecord -Path $candidateCli -ExpectedName 'serctl_cli.exe'
        $installedCandidateDaemon = Get-RegularFileRecord -Path $candidateDaemon -ExpectedName 'serctl_daemon.exe'

        $cliLine = Get-VersionLine -Binary $candidateCli -Isolation $candidateIsolation `
            -ExpectedBinaryRecord $installedCandidateCli
        $daemonLine = Get-VersionLine -Binary $candidateDaemon -Isolation $candidateIsolation `
            -ExpectedBinaryRecord $installedCandidateDaemon
        Get-ExactCandidateIdentity `
            -Kind cli -Line $cliLine -Version $CandidateVersion -FullCommit $CandidateCommit
        Get-ExactCandidateIdentity `
            -Kind daemon -Line $daemonLine -Version $CandidateVersion -FullCommit $CandidateCommit

        $recoveryMedia = Join-Path $candidateIsolation.home 'clean-install-recovery.srrec'
        $adminInit = Invoke-IsolatedCleanInstallProcess `
            -Binary $candidateCli `
            -Arguments @('admin', 'init', '--recovery-media', $recoveryMedia) `
            -Home $candidateIsolation.home `
            -LocalAppData $candidateIsolation.local `
            -RoamingAppData $candidateIsolation.roaming `
            -Temp $candidateIsolation.temp `
            -SecretEnvironment @{ SERCTL_ADMIN_PASS = $adminPass } `
            -ExpectedBinaryRecord $installedCandidateCli
        Assert-CleanInstallCondition ($adminInit.exit_code -eq 0) (
            'fresh administrator initialization failed; output withheld'
        )
        $add = Invoke-IsolatedCleanInstallProcess `
            -Binary $candidateCli `
            -Arguments @(
                'add', $profileName, '--host', $dummyHost, '--user', 'serctl-smoke',
                '--port', '22'
            ) `
            -Home $candidateIsolation.home `
            -LocalAppData $candidateIsolation.local `
            -RoamingAppData $candidateIsolation.roaming `
            -Temp $candidateIsolation.temp `
            -SecretEnvironment @{
                SERCTL_ADMIN_PASS = $adminPass
                SERCTL_PROFILE_PASS = $profilePass
                SERCTL_SSH_PASS = $sshPass
            } `
            -ExpectedBinaryRecord $installedCandidateCli
        Assert-CleanInstallCondition ($add.exit_code -eq 0) (
            'local-only fixture profile creation failed; output withheld'
        )
        $list = Invoke-IsolatedCleanInstallProcess `
            -Binary $candidateCli `
            -Arguments @('list') `
            -Home $candidateIsolation.home `
            -LocalAppData $candidateIsolation.local `
            -RoamingAppData $candidateIsolation.roaming `
            -Temp $candidateIsolation.temp `
            -ExpectedBinaryRecord $installedCandidateCli
        Assert-CleanInstallCondition (
            $list.exit_code -eq 0 -and
            $list.stdout -cmatch '(?m)^clean-install-local\t192\.0\.2\.1:22\tgeneration=1\r?$'
        ) 'fresh local profile was not listed exactly once; output withheld'

        $runRoot = Join-Path $candidateIsolation.home '.serctl/run'
        $descriptorPath = Join-Path $runRoot 'daemon.json'
        $secretPath = Join-Path $runRoot 'daemon.secret'
        $candidateObserver = @{
            owner = $null
            descriptor_path = $descriptorPath
            secret_path = $secretPath
            daemon_path = $candidateDaemon
            daemon_record = $installedCandidateDaemon
            build_commit = $CandidateCommit.Substring(0, 12)
            ipc_min = $candidateIpcMin
            ipc_max = $candidateIpcMax
            launch_utc = [DateTimeOffset]::UtcNow
        }
        $status = Invoke-IsolatedCleanInstallProcess `
            -Binary $candidateCli `
            -Arguments @('status', $profileName) `
            -Home $candidateIsolation.home `
            -LocalAppData $candidateIsolation.local `
            -RoamingAppData $candidateIsolation.roaming `
            -Temp $candidateIsolation.temp `
            -SecretEnvironment $profileSecret `
            -ExpectedBinaryRecord $installedCandidateCli `
            -DaemonObserver $candidateObserver
        Assert-CleanInstallCondition ($status.exit_code -eq 0) (
            'matched local daemon status smoke failed; output withheld'
        )
        Update-CleanInstallDaemonOwner -Observer $candidateObserver
        Assert-CleanInstallCondition ($null -ne $candidateObserver.owner) (
            'candidate daemon child ownership was not captured'
        )
        $descriptorOwner = $candidateObserver.owner
        Assert-CleanInstallCondition (
            $descriptorOwner.descriptor_version -eq 1 -and
            $descriptorOwner.protocol_min -eq $candidateIpcMin -and
            $descriptorOwner.protocol_max -eq $candidateIpcMax -and
            $descriptorOwner.build_commit -ceq $CandidateCommit.Substring(0, 12) -and
            $descriptorOwner.instance_id -cmatch '^[0-9a-f]{32}$' -and
            $descriptorOwner.descriptor_identity -cne $descriptorOwner.secret_identity
        ) 'runtime descriptor is not the exact candidate IPC/storage generation'
        $daemonProcess = $candidateObserver.owner.process
        Assert-CleanInstallCondition (
            [System.IO.Path]::GetFullPath($daemonProcess.Path) -ceq
                [System.IO.Path]::GetFullPath($candidateDaemon)
        ) 'runtime descriptor PID is not the installed candidate daemon'
        Assert-FileRecordUnchanged -Record $candidateDaemonSource -ExpectedName 'serctl_daemon.exe'
        $installedDaemon = Get-RegularFileRecord -Path $candidateDaemon -ExpectedName 'serctl_daemon.exe'
        Assert-CleanInstallCondition (
            [string]$installedDaemon.sha256 -ceq [string]$candidateDaemonSource.sha256
        ) 'running daemon bytes differ from the downloaded candidate daemon'

        $grantPath = Join-Path $candidateIsolation.home 'clean-install.grant'
        $grantIssuedBefore = [DateTimeOffset]::UtcNow
        $grant = Invoke-IsolatedCleanInstallProcess `
            -Binary $candidateCli `
            -Arguments @(
                'grant-issue', $profileName, '--operations', 'daemon.status',
                '--budget', '1', '--ttl-minutes', '1', '--output', $grantPath
            ) `
            -Home $candidateIsolation.home `
            -LocalAppData $candidateIsolation.local `
            -RoamingAppData $candidateIsolation.roaming `
            -Temp $candidateIsolation.temp `
            -SecretEnvironment $profileSecret `
            -ExpectedBinaryRecord $installedCandidateCli
        $grantIssuedAfter = [DateTimeOffset]::UtcNow
        Assert-CleanInstallCondition ($grant.exit_code -eq 0) (
            'local OperationGrant issuance failed; output withheld'
        )
        $grantItem = Get-Item -LiteralPath $grantPath -Force -ErrorAction Stop
        Assert-CleanInstallCondition (
            -not $grantItem.PSIsContainer -and
            ($grantItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0 -and
            $grantItem.Length -gt 0 -and $grantItem.Length -le 1048576
        ) 'local OperationGrant output has an unsafe file identity'
        $grantMetadata = Read-CleanInstallGrantMetadata `
            -Path $grantPath `
            -ExpectedProfile $profileName `
            -IssuedNotBefore $grantIssuedBefore `
            -IssuedNotAfter $grantIssuedAfter
        Assert-CleanInstallCondition (
            $grantMetadata.profile_generation -eq 1 -and
            $grantMetadata.budget -eq 1 -and
            $grantMetadata.operation -ceq 'daemon.status' -and
            $grantMetadata.ttl_ms -eq 60000
        ) 'OperationGrant public metadata was not retained exactly'
        $agentInput = `
            "{`"op`":`"status`",`"schema_version`":1,`"request_id`":1}`n" +
            "{`"op`":`"status`",`"schema_version`":1,`"request_id`":2}`n"
        $agent = Invoke-IsolatedCleanInstallProcess `
            -Binary $candidateCli `
            -Arguments @('agent', '--grant', $grantPath) `
            -Home $candidateIsolation.home `
            -LocalAppData $candidateIsolation.local `
            -RoamingAppData $candidateIsolation.roaming `
            -Temp $candidateIsolation.temp `
            -StandardInputText $agentInput `
            -ExpectedBinaryRecord $installedCandidateCli
        Assert-CleanInstallAgentConsumption -Result $agent -ExpectedProfile $profileName
        $agentInput = $null
        Remove-Item -LiteralPath $grantPath -Force -ErrorAction Stop
        Assert-CleanInstallCondition (-not (Test-Path -LiteralPath $grantPath)) (
            'consumed OperationGrant file remained after bounded cleanup'
        )

        $down = Invoke-IsolatedCleanInstallProcess `
            -Binary $candidateCli `
            -Arguments @('down', $profileName) `
            -Home $candidateIsolation.home `
            -LocalAppData $candidateIsolation.local `
            -RoamingAppData $candidateIsolation.roaming `
            -Temp $candidateIsolation.temp `
            -SecretEnvironment $profileSecret `
            -ExpectedBinaryRecord $installedCandidateCli
        Assert-CleanInstallCondition ($down.exit_code -eq 0) (
            'matched candidate daemon shutdown failed; output withheld'
        )
        Assert-CleanInstallCondition ($candidateObserver.owner.process.WaitForExit(15000)) (
            'matched candidate daemon remained alive after shutdown'
        )
        $candidateObserver.owner.process.Dispose()
        $candidateObserver.owner = $null
        Assert-CleanInstallCondition (
            -not (Test-Path -LiteralPath $descriptorPath) -and
            -not (Test-Path -LiteralPath $secretPath)
        ) 'isolated runtime descriptor or activation secret remained after shutdown'

        Remove-Item -LiteralPath $install -Recurse -Force -ErrorAction Stop
        [System.IO.Directory]::CreateDirectory($install) | Out-Null
        Copy-PinnedComponent -SourceRecord $previousCliSource -Destination $candidateCli
        Copy-PinnedComponent -SourceRecord $previousDaemonSource -Destination $candidateDaemon
        $installedPreviousCli = Get-RegularFileRecord -Path $candidateCli -ExpectedName 'serctl_cli.exe'
        $installedPreviousDaemon = Get-RegularFileRecord -Path $candidateDaemon -ExpectedName 'serctl_daemon.exe'
        $previousCliLine = Get-VersionLine -Binary $candidateCli -Isolation $rollbackIsolation `
            -ExpectedBinaryRecord $installedPreviousCli
        $previousDaemonLine = Get-VersionLine -Binary $candidateDaemon -Isolation $rollbackIsolation `
            -ExpectedBinaryRecord $installedPreviousDaemon
        Get-ExactPredecessorIdentity -Kind cli -Line $previousCliLine -FullCommit $PreviousCommit
        Get-ExactPredecessorIdentity -Kind daemon -Line $previousDaemonLine -FullCommit $PreviousCommit
        $rollbackList = Invoke-IsolatedCleanInstallProcess `
            -Binary $candidateCli `
            -Arguments @('list') `
            -Home $rollbackIsolation.home `
            -LocalAppData $rollbackIsolation.local `
            -RoamingAppData $rollbackIsolation.roaming `
            -Temp $rollbackIsolation.temp `
            -ExpectedBinaryRecord $installedPreviousCli
        Assert-CleanInstallCondition (
            $rollbackList.exit_code -eq 0 -and $rollbackList.stdout.Trim() -ceq '(no profiles)'
        ) 'restored predecessor did not open a fresh rollback home; output withheld'

        $rollbackProfile = 'clean-install-rollback'
        $rollbackRecovery = Join-Path $rollbackIsolation.home 'rollback-recovery.srrec'
        $rollbackAdmin = Invoke-IsolatedCleanInstallProcess `
            -Binary $candidateCli `
            -Arguments @('admin', 'init', '--recovery-media', $rollbackRecovery) `
            -Home $rollbackIsolation.home `
            -LocalAppData $rollbackIsolation.local `
            -RoamingAppData $rollbackIsolation.roaming `
            -Temp $rollbackIsolation.temp `
            -SecretEnvironment @{ SERCTL_ADMIN_PASS = $adminPass } `
            -ExpectedBinaryRecord $installedPreviousCli
        Assert-CleanInstallCondition ($rollbackAdmin.exit_code -eq 0) (
            'predecessor administrator initialization failed; output withheld'
        )
        $rollbackAdd = Invoke-IsolatedCleanInstallProcess `
            -Binary $candidateCli `
            -Arguments @(
                'add', $rollbackProfile, '--host', $dummyHost, '--user', 'serctl-smoke',
                '--port', '22'
            ) `
            -Home $rollbackIsolation.home `
            -LocalAppData $rollbackIsolation.local `
            -RoamingAppData $rollbackIsolation.roaming `
            -Temp $rollbackIsolation.temp `
            -SecretEnvironment @{
                SERCTL_ADMIN_PASS = $adminPass
                SERCTL_PROFILE_PASS = $profilePass
                SERCTL_SSH_PASS = $sshPass
            } `
            -ExpectedBinaryRecord $installedPreviousCli
        Assert-CleanInstallCondition ($rollbackAdd.exit_code -eq 0) (
            'predecessor local-only fixture profile creation failed; output withheld'
        )
        $rollbackRunRoot = Join-Path $rollbackIsolation.home '.serctl/run'
        $rollbackDescriptorPath = Join-Path $rollbackRunRoot 'daemon.json'
        $rollbackSecretPath = Join-Path $rollbackRunRoot 'daemon.secret'
        $rollbackObserver = @{
            owner = $null
            descriptor_path = $rollbackDescriptorPath
            secret_path = $rollbackSecretPath
            daemon_path = $candidateDaemon
            daemon_record = $installedPreviousDaemon
            build_commit = $PreviousCommit.Substring(0, 12)
            ipc_min = 8
            ipc_max = 8
            launch_utc = [DateTimeOffset]::UtcNow
        }
        $rollbackStatus = Invoke-IsolatedCleanInstallProcess `
            -Binary $candidateCli `
            -Arguments @('status', $rollbackProfile) `
            -Home $rollbackIsolation.home `
            -LocalAppData $rollbackIsolation.local `
            -RoamingAppData $rollbackIsolation.roaming `
            -Temp $rollbackIsolation.temp `
            -SecretEnvironment $profileSecret `
            -ExpectedBinaryRecord $installedPreviousCli `
            -DaemonObserver $rollbackObserver
        Assert-CleanInstallCondition ($rollbackStatus.exit_code -eq 0) (
            'matched predecessor IPC v8 status failed; output withheld'
        )
        Update-CleanInstallDaemonOwner -Observer $rollbackObserver
        Assert-CleanInstallCondition (
            $null -ne $rollbackObserver.owner -and
            $rollbackObserver.owner.instance_id -cmatch '^[0-9a-f]{32}$'
        ) 'predecessor daemon ownership or descriptor identity was not captured'
        $rollbackDown = Invoke-IsolatedCleanInstallProcess `
            -Binary $candidateCli `
            -Arguments @('down', $rollbackProfile) `
            -Home $rollbackIsolation.home `
            -LocalAppData $rollbackIsolation.local `
            -RoamingAppData $rollbackIsolation.roaming `
            -Temp $rollbackIsolation.temp `
            -SecretEnvironment $profileSecret `
            -ExpectedBinaryRecord $installedPreviousCli
        Assert-CleanInstallCondition ($rollbackDown.exit_code -eq 0) (
            'matched predecessor daemon shutdown failed; output withheld'
        )
        Assert-CleanInstallCondition ($rollbackObserver.owner.process.WaitForExit(15000)) (
            'matched predecessor daemon remained alive after shutdown'
        )
        $rollbackObserver.owner.process.Dispose()
        $rollbackObserver.owner = $null
        Assert-CleanInstallCondition (
            -not (Test-Path -LiteralPath $rollbackDescriptorPath) -and
            -not (Test-Path -LiteralPath $rollbackSecretPath)
        ) 'predecessor runtime descriptor or activation secret remained after shutdown'

        Assert-FileRecordUnchanged -Record $candidateCliSource -ExpectedName 'serctl_cli.exe'
        Assert-FileRecordUnchanged -Record $candidateDaemonSource -ExpectedName 'serctl_daemon.exe'
        Assert-FileRecordUnchanged -Record $previousCliSource -ExpectedName 'serctl_cli.exe'
        Assert-FileRecordUnchanged -Record $previousDaemonSource -ExpectedName 'serctl_daemon.exe'

        $details = [ordered]@{
            runner = [ordered]@{
                os = 'Windows'
                arch = 'X64'
                rust_host = 'x86_64-pc-windows-msvc'
            }
            bundle_version = $CandidateVersion
            cli_identity = [ordered]@{
                component = 'serctl_cli'
                version = $CandidateVersion
                commit = $CandidateCommit
                sha256 = [string]$candidateCliSource.sha256
                ipc_min = $candidateIpcMin
                ipc_max = $candidateIpcMax
                storage_contract = $candidateStorageContract
            }
            daemon_identity = [ordered]@{
                component = 'serctl_daemon'
                version = $CandidateVersion
                commit = $CandidateCommit
                sha256 = [string]$candidateDaemonSource.sha256
                ipc_min = $candidateIpcMin
                ipc_max = $candidateIpcMax
                storage_contract = $candidateStorageContract
            }
            fresh_home = $true
            install_passed = $true
            status_passed = $true
            grant_issue_passed = $true
            cleanup_passed = $true
            rollback_passed = $true
        }
    }
    finally {
        $cleanupFailure = $null
        if ($null -ne $rollbackObserver) {
            try { Stop-CleanInstallOwnedDaemon -Observer $rollbackObserver }
            catch { $cleanupFailure = $_ }
        }
        if ($null -ne $candidateObserver) {
            try { Stop-CleanInstallOwnedDaemon -Observer $candidateObserver }
            catch { $cleanupFailure = $_ }
        }
        $profilePass = $null
        $adminPass = $null
        $sshPass = $null
        if ($null -ne $root -and (Test-Path -LiteralPath $root)) {
            try {
                Remove-OwnedCleanInstallRoot `
                    -Root $root `
                    -Parent $scratchParentItem.FullName `
                    -OwnerToken $ownerToken
            }
            catch { if ($null -eq $cleanupFailure) { $cleanupFailure = $_ } }
        }
        if ($null -ne $cleanupFailure) {
            throw 'clean-install smoke failed: isolated cleanup failed; details withheld'
        }
    }
    return [ordered]@{ details = $details }
}

function Invoke-CleanInstallSyntheticSelfTest {
    Assert-CleanInstallCondition ($env:OS -ceq 'Windows_NT') (
        'clean-install synthetic receipt self-test requires Windows'
    )
    $root = Join-Path ([System.IO.Path]::GetTempPath()) (
        'serctl-clean-install-selftest-' + [System.Guid]::NewGuid().ToString('N')
    )
    [System.IO.Directory]::CreateDirectory($root) | Out-Null
    try {
        $tag = 'v1.0.0-beta'
        $commit = 'a' * 40
        $tagObject = 'b' * 40
        $manifest = 'C' * 64
        $result = [ordered]@{
            details = [ordered]@{
                runner = [ordered]@{
                    os = 'Windows'; arch = 'X64'; rust_host = 'x86_64-pc-windows-msvc'
                }
                bundle_version = '1.0.0-beta'
                cli_identity = [ordered]@{
                    component = 'serctl_cli'; version = '1.0.0-beta'; commit = $commit
                    sha256 = ('D' * 64); ipc_min = 9; ipc_max = 9
                    storage_contract = $candidateStorageContract
                }
                daemon_identity = [ordered]@{
                    component = 'serctl_daemon'; version = '1.0.0-beta'; commit = $commit
                    sha256 = ('E' * 64); ipc_min = 9; ipc_max = 9
                    storage_contract = $candidateStorageContract
                }
                fresh_home = $true; install_passed = $true; status_passed = $true
                grant_issue_passed = $true; cleanup_passed = $true; rollback_passed = $true
            }
        }
        Get-ExactCandidateIdentity `
            -Kind cli `
            -Line 'serctl_cli 1.0.0-beta (git aaaaaaaaaaaa; vault-storage read=v4..=v5 write=v5)' `
            -Version '1.0.0-beta' `
            -FullCommit $commit
        Get-ExactCandidateIdentity `
            -Kind daemon `
            -Line 'serctl_daemon 1.0.0-beta (git aaaaaaaaaaaa; IPC v9..=v9; vault-storage read=v4..=v5 write=v5)' `
            -Version '1.0.0-beta' `
            -FullCommit $commit
        $issuedAt = [DateTimeOffset]::UtcNow
        $issuedMs = [uint64]$issuedAt.ToUnixTimeMilliseconds()
        $grantFixture = [ordered]@{
            grant = [ordered]@{
                grant_id = @(1..16)
                profile_name = $profileName
                profile_id = @(17..32)
                profile_generation = 1
                operations = @('daemon.status')
                budget = 1
                issued_unix_ms = $issuedMs
                expires_unix_ms = $issuedMs + 60000
                holder_key = @(33..64)
            }
            agent_key = ('A' * 43) + '='
        }
        $grantFixturePath = Join-Path $root 'synthetic.grant'
        $grantFixtureBytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
            ($grantFixture | ConvertTo-Json -Depth 8 -Compress)
        )
        Write-ProtectedCleanInstallReceipt -Path $grantFixturePath -Bytes $grantFixtureBytes
        $metadata = Read-CleanInstallGrantMetadata `
            -Path $grantFixturePath -ExpectedProfile $profileName `
            -IssuedNotBefore $issuedAt.AddSeconds(-1) -IssuedNotAfter $issuedAt.AddSeconds(1)
        Assert-CleanInstallCondition (
            $metadata.operation -ceq 'daemon.status' -and $metadata.ttl_ms -eq 60000
        ) 'synthetic exact OperationGrant metadata was rejected'
        $grantFixture.grant.operations = @('transfer.status')
        $badGrantPath = Join-Path $root 'synthetic-bad.grant'
        $badGrantBytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
            ($grantFixture | ConvertTo-Json -Depth 8 -Compress)
        )
        Write-ProtectedCleanInstallReceipt -Path $badGrantPath -Bytes $badGrantBytes
        $badGrantRejected = $false
        try {
            [void](Read-CleanInstallGrantMetadata `
                -Path $badGrantPath -ExpectedProfile $profileName `
                -IssuedNotBefore $issuedAt.AddSeconds(-1) -IssuedNotAfter $issuedAt.AddSeconds(1))
        }
        catch { $badGrantRejected = $true }
        Assert-CleanInstallCondition $badGrantRejected (
            'synthetic over-scoped OperationGrant was not rejected'
        )
        $agentFixture = [pscustomobject]@{
            exit_code = 0
            stderr = ''
            stdout = (
                '{"schema_version":1,"request_id":1,"ok":true,"data":' +
                '{"profile":"clean-install-local","host":"192.0.2.1",' +
                '"user":"serctl-smoke","started_unix":1}}' + "`n" +
                '{"schema_version":1,"request_id":2,"ok":false,' +
                '"error_code":"agent.operation_failed","error":"budget unavailable"}' + "`n"
            )
        }
        Assert-CleanInstallAgentConsumption -Result $agentFixture -ExpectedProfile $profileName
        $agentFixture.stdout = $agentFixture.stdout.Replace(
            'agent.operation_failed', 'agent.scope_denied'
        )
        $wrongRejectionRejected = $false
        try {
            Assert-CleanInstallAgentConsumption -Result $agentFixture -ExpectedProfile $profileName
        }
        catch { $wrongRejectionRejected = $true }
        Assert-CleanInstallCondition $wrongRejectionRejected (
            'synthetic wrong Agent rejection code was accepted'
        )
        $grantFixture.agent_key = $null
        $grantFixtureBytes = $null
        $badGrantBytes = $null
        $receipt = Join-Path $root 'clean-install.evidence'
        $started = [DateTimeOffset]::UtcNow.AddSeconds(-1)
        Write-CleanInstallAcceptanceReceipt `
            -RuntimeResult $result `
            -StartedUtc $started `
            -CompletedUtc ([DateTimeOffset]::UtcNow) `
            -OutputPath $receipt `
            -ReceiptTag $tag `
            -ReceiptTagObject $tagObject `
            -ReceiptCommit $commit `
            -ManifestSha256 $manifest `
            -Owner 'clean-install-selftest-owner'
        $document = ConvertFrom-StrictJson `
            -Json (Read-StrictUtf8Text -Path $receipt) `
            -Label 'clean-install synthetic receipt'
        Assert-CleanInstallCondition (
            [string]$document.category -ceq 'clean_install_smoke' -and
            [bool]$document.details.cleanup_passed -and
            [string]$document.details.cli_identity.storage_contract -ceq $candidateStorageContract
        ) 'synthetic receipt lost its closed runtime claims'
        $duplicateRejected = $false
        try {
            Write-CleanInstallAcceptanceReceipt `
                -RuntimeResult $result `
                -StartedUtc $started `
                -CompletedUtc ([DateTimeOffset]::UtcNow) `
                -OutputPath $receipt `
                -ReceiptTag $tag `
                -ReceiptTagObject $tagObject `
                -ReceiptCommit $commit `
                -ManifestSha256 $manifest `
                -Owner 'clean-install-selftest-owner'
        }
        catch { $duplicateRejected = $true }
        Assert-CleanInstallCondition $duplicateRejected 'pre-existing receipt was not rejected'
        $unsafeOwnerRejected = $false
        try {
            Write-CleanInstallAcceptanceReceipt `
                -RuntimeResult $result `
                -StartedUtc $started `
                -CompletedUtc ([DateTimeOffset]::UtcNow) `
                -OutputPath (Join-Path $root 'unsafe.evidence') `
                -ReceiptTag $tag `
                -ReceiptTagObject $tagObject `
                -ReceiptCommit $commit `
                -ManifestSha256 $manifest `
                -Owner 'C:\unsafe-owner'
        }
        catch { $unsafeOwnerRejected = $true }
        Assert-CleanInstallCondition $unsafeOwnerRejected 'absolute-path owner was not rejected'
        $failureRecord = Get-CleanInstallFailureLogRecord
        Assert-CleanInstallCondition (
            $failureRecord -ceq "category=clean_install_runtime_failed; file='clean-install.evidence'; bytes=0" -and
            $failureRecord -notmatch 'C:\\secret-canary|SECRET-CANARY|[\x00-\x1F\x7F]'
        ) 'formal failure record is not fixed and sanitized'
    }
    finally {
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
    }
    Write-Output 'Clean-install smoke harness synthetic self-test passed.'
}

if ($PSCmdlet.ParameterSetName -ceq 'SelfTest') {
    Invoke-CleanInstallSyntheticSelfTest
    return
}

try {
    $startedUtc = [DateTimeOffset]::UtcNow
    $version = $Tag.Substring(1)
    $runtimeResult = Invoke-CleanInstallRuntime `
        -CandidateRoot $CandidateDirectory `
        -PredecessorRoot $PredecessorDirectory `
        -PreviousCommit $PredecessorCommit `
        -Scratch $ScratchParent `
        -CandidateVersion $version `
        -CandidateCommit $Commit
    $completedUtc = [DateTimeOffset]::UtcNow
    Write-CleanInstallAcceptanceReceipt `
        -RuntimeResult $runtimeResult `
        -StartedUtc $startedUtc `
        -CompletedUtc $completedUtc `
        -OutputPath $ReceiptPath `
        -ReceiptTag $Tag `
        -ReceiptTagObject $TagObject `
        -ReceiptCommit $Commit `
        -ManifestSha256 $ReleaseManifestSha256 `
        -Owner $EvidenceOwner
    Write-Output 'Clean-install smoke passed and protected receipt was created.'
}
catch {
    [Console]::Error.WriteLine((Get-CleanInstallFailureLogRecord))
    exit 1
}
