[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Version,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$RepositoryRoot = (Join-Path $PSScriptRoot '..'),

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$CargoExecutable = 'cargo',

    [Parameter(Mandatory = $false)]
    [string]$RustcExecutable,

    [Parameter(Mandatory = $false)]
    [string]$RustdocExecutable,

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$GitExecutable = 'git',

    [Parameter(Mandatory = $false)]
    [ValidateNotNullOrEmpty()]
    [string]$ChmodExecutable = 'chmod',

    [Parameter(Mandatory = $false, DontShow = $true)]
    [ValidateSet('none', 'replace-stage-artifact')]
    [string]$SelfTestMutation = 'none'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ipcContract = 'IPC v9..=v9'
$transferContract = 'transfer protocol v1'
$vaultContract = 'vault-storage read=v4..=v5 write=v5'
$versionPattern = '^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)-(?:alpha|beta|rc)(?:\.(?:0|[1-9][0-9]*))?$'
$gitOverrideVariables = @(
    'GIT_DIR',
    'GIT_COMMON_DIR',
    'GIT_WORK_TREE',
    'GIT_INDEX_FILE',
    'GIT_OBJECT_DIRECTORY',
    'GIT_ALTERNATE_OBJECT_DIRECTORIES',
    'GIT_NAMESPACE',
    'GIT_SHALLOW_FILE',
    'GIT_REPLACE_REF_BASE',
    'GIT_CEILING_DIRECTORIES',
    'GIT_DISCOVERY_ACROSS_FILESYSTEM',
    'GIT_CONFIG_GLOBAL',
    'GIT_CONFIG_SYSTEM',
    'GIT_CONFIG_NOSYSTEM',
    'GIT_NO_REPLACE_OBJECTS',
    'GIT_CONFIG_PARAMETERS'
)
$compilerOverrideVariables = @(
    'RUSTC',
    'RUSTC_WRAPPER',
    'RUSTC_WORKSPACE_WRAPPER',
    'RUSTC_BOOTSTRAP',
    'RUSTDOC',
    'RUSTDOCFLAGS',
    'RUSTUP_TOOLCHAIN',
    'RUSTFLAGS',
    'CARGO_ENCODED_RUSTFLAGS',
    'CARGO_BUILD_RUSTC',
    'CARGO_BUILD_RUSTC_WRAPPER',
    'CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER',
    'CARGO_BUILD_RUSTFLAGS',
    'CARGO_BUILD_RUSTDOC',
    'CARGO_BUILD_RUSTDOCFLAGS'
)
$hostIsWindows = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
    [System.Runtime.InteropServices.OSPlatform]::Windows
)
$pathComparison = if ($hostIsWindows) {
    [System.StringComparison]::OrdinalIgnoreCase
}
else {
    [System.StringComparison]::Ordinal
}

$candidateNativeSource = @'
using System;
using System.ComponentModel;
using System.IO;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public sealed class SerctlCandidateObjectInfo
{
    public string Identity { get; private set; }
    public long Size { get; private set; }
    public bool IsDirectory { get; private set; }
    public bool IsReparsePoint { get; private set; }

    public SerctlCandidateObjectInfo(
        string identity,
        long size,
        bool isDirectory,
        bool isReparsePoint)
    {
        Identity = identity;
        Size = size;
        IsDirectory = isDirectory;
        IsReparsePoint = isReparsePoint;
    }
}

public static class SerctlCandidateNative
{
    private const uint FILE_READ_DATA = 0x0001;
    private const uint FILE_READ_ATTRIBUTES = 0x0080;
    private const uint FILE_SHARE_READ = 0x00000001;
    private const uint FILE_SHARE_WRITE = 0x00000002;
    private const uint OPEN_EXISTING = 3;
    private const uint FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
    private const uint FILE_ATTRIBUTE_REPARSE_POINT = 0x00000400;
    private const uint FILE_FLAG_OPEN_REPARSE_POINT = 0x00200000;
    private const uint FILE_FLAG_BACKUP_SEMANTICS = 0x02000000;
    private const uint FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000;

    [StructLayout(LayoutKind.Sequential)]
    private struct BY_HANDLE_FILE_INFORMATION
    {
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
    private static extern SafeFileHandle CreateFileW(
        string fileName,
        uint desiredAccess,
        uint shareMode,
        IntPtr securityAttributes,
        uint creationDisposition,
        uint flagsAndAttributes,
        IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandle(
        SafeFileHandle file,
        out BY_HANDLE_FILE_INFORMATION information);

    private static SafeFileHandle Open(
        string path,
        uint access,
        uint shareMode,
        uint flags)
    {
        SafeFileHandle handle = CreateFileW(
            path,
            access,
            shareMode,
            IntPtr.Zero,
            OPEN_EXISTING,
            flags | FILE_FLAG_OPEN_REPARSE_POINT,
            IntPtr.Zero);
        if (handle.IsInvalid)
        {
            int error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(error, "open pinned candidate object");
        }
        return handle;
    }

    public static SafeFileHandle OpenDirectory(string path)
    {
        return Open(
            path,
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            FILE_FLAG_BACKUP_SEMANTICS);
    }

    public static SafeFileHandle OpenFileRead(string path)
    {
        return Open(
            path,
            FILE_READ_DATA | FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ,
            FILE_FLAG_SEQUENTIAL_SCAN);
    }

    public static SerctlCandidateObjectInfo Inspect(SafeFileHandle handle)
    {
        BY_HANDLE_FILE_INFORMATION information;
        if (!GetFileInformationByHandle(handle, out information))
        {
            throw new Win32Exception(
                Marshal.GetLastWin32Error(),
                "inspect pinned candidate object");
        }
        string identity = String.Format(
            System.Globalization.CultureInfo.InvariantCulture,
            "win:{0:x8}:{1:x8}{2:x8}",
            information.VolumeSerialNumber,
            information.FileIndexHigh,
            information.FileIndexLow);
        long size = ((long)information.FileSizeHigh << 32) |
            information.FileSizeLow;
        return new SerctlCandidateObjectInfo(
            identity,
            size,
            (information.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0,
            (information.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0);
    }
}

public sealed class SerctlCandidateChangeMonitor : IDisposable
{
    private readonly FileSystemWatcher watcher;
    private readonly object gate = new object();
    private readonly System.Collections.Generic.List<string> changes =
        new System.Collections.Generic.List<string>();
    private bool overflowed;

    public SerctlCandidateChangeMonitor(string root, bool includeSubdirectories)
    {
        watcher = new FileSystemWatcher(root);
        watcher.IncludeSubdirectories = includeSubdirectories;
        watcher.NotifyFilter = NotifyFilters.FileName |
            NotifyFilters.DirectoryName |
            NotifyFilters.LastWrite |
            NotifyFilters.Size |
            NotifyFilters.CreationTime |
            NotifyFilters.Security;
        watcher.InternalBufferSize = 65536;
        watcher.Changed += OnChange;
        watcher.Created += OnChange;
        watcher.Deleted += OnChange;
        watcher.Renamed += OnRename;
        watcher.Error += OnError;
        watcher.EnableRaisingEvents = true;
    }

    private void OnChange(object sender, FileSystemEventArgs args)
    {
        lock (gate)
        {
            changes.Add(args.FullPath);
        }
    }

    private void OnRename(object sender, RenamedEventArgs args)
    {
        lock (gate)
        {
            changes.Add(args.OldFullPath);
            changes.Add(args.FullPath);
        }
    }

    private void OnError(object sender, ErrorEventArgs args)
    {
        lock (gate)
        {
            overflowed = true;
        }
    }

    public string[] StopAndGetChanges(out bool hadOverflow)
    {
        watcher.EnableRaisingEvents = false;
        lock (gate)
        {
            hadOverflow = overflowed;
            return changes.ToArray();
        }
    }

    public void Dispose()
    {
        watcher.Dispose();
    }
}
'@

if ($null -eq ('SerctlCandidateNative' -as [type])) {
    Add-Type -TypeDefinition $candidateNativeSource -Language CSharp
}

function Assert-CandidateCondition {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if (-not $Condition) {
        throw "isolated candidate check failed: $Message"
    }
}

Assert-CandidateCondition $hostIsWindows (
    'P1 isolated candidate construction requires Windows persistent object ' +
    'handles; other platforms fail closed until equivalent handle-relative ' +
    'publication and cleanup are implemented'
)

function Invoke-CandidateGit {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = @(
            & $script:GitPath `
                -c core.autocrlf=false `
                -c core.safecrlf=false `
                -c core.hooksPath= `
                -C $Root `
                @Arguments 2>&1
        )
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    Assert-CandidateCondition ($exitCode -eq 0) (
        "git command failed: git $($Arguments -join ' ')"
    )
    return (($output | ForEach-Object { $_.ToString() }) -join "`n").Trim()
}

function Get-CleanGitSnapshot {
    param([Parameter(Mandatory = $true)][string]$Root)

    $headBefore = Invoke-CandidateGit -Root $Root -Arguments @('rev-parse', 'HEAD')
    $treeBefore = Invoke-CandidateGit `
        -Root $Root `
        -Arguments @('rev-parse', 'HEAD^{tree}')
    Assert-CandidateCondition ($headBefore -cmatch '^[0-9a-f]{40}$') (
        "HEAD is not one canonical full commit id: '$headBefore'"
    )
    Assert-CandidateCondition ($treeBefore -cmatch '^[0-9a-f]{40}$') (
        "HEAD tree is not one canonical full object id: '$treeBefore'"
    )
    $status = Invoke-CandidateGit -Root $Root -Arguments @(
        'status',
        '--porcelain=v1',
        '--untracked-files=all',
        '--ignore-submodules=none'
    )
    Assert-CandidateCondition ([string]::IsNullOrEmpty($status)) (
        'source checkout is not clean; refusing to build an unbound candidate'
    )
    $treeAfter = Invoke-CandidateGit `
        -Root $Root `
        -Arguments @('rev-parse', 'HEAD^{tree}')
    $headAfter = Invoke-CandidateGit -Root $Root -Arguments @('rev-parse', 'HEAD')
    Assert-CandidateCondition (
        $headAfter -ceq $headBefore -and
        $treeAfter -ceq $treeBefore
    ) 'HEAD or its tree changed while checking source cleanliness'
    return [pscustomobject]@{
        Head = $headBefore
        Tree = $treeBefore
    }
}

function Get-TrackedPathSet {
    param([Parameter(Mandatory = $true)][string]$Root)

    $raw = Invoke-CandidateGit -Root $Root -Arguments @('ls-files', '-z')
    $comparer = if ($hostIsWindows) {
        [System.StringComparer]::OrdinalIgnoreCase
    }
    else {
        [System.StringComparer]::Ordinal
    }
    $set = [System.Collections.Generic.HashSet[string]]::new($comparer)
    foreach ($entry in $raw.Split([char]0)) {
        if (-not [string]::IsNullOrEmpty($entry)) {
            [void]$set.Add($entry.Replace('\', '/'))
        }
    }
    Assert-CandidateCondition ($set.Count -gt 0) 'source repository has no tracked paths'
    return $set
}

function Assert-NoTrackedSourceChanges {
    param(
        [Parameter(Mandatory = $true)][object[]]$Monitors,
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][object]$TrackedPaths,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $changes = @()
    foreach ($monitor in $Monitors) {
        $overflowed = $false
        $changes += @($monitor.StopAndGetChanges([ref]$overflowed))
        Assert-CandidateCondition (-not $overflowed) (
            "$Label source-change monitor overflowed"
        )
    }
    $prefix = [System.IO.Path]::GetFullPath($Root).TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    ) + [System.IO.Path]::DirectorySeparatorChar
    foreach ($changedPath in $changes) {
        $full = [System.IO.Path]::GetFullPath($changedPath)
        if (-not $full.StartsWith($prefix, $pathComparison)) {
            continue
        }
        $relative = $full.Substring($prefix.Length).Replace('\', '/')
        if ($TrackedPaths.Contains($relative)) {
            throw "isolated candidate check failed: $Label tracked source changed " +
                'during the build, even if its bytes were later restored'
        }
        $relativePrefix = $relative.TrimEnd('/') + '/'
        foreach ($tracked in $TrackedPaths) {
            if ($tracked.StartsWith($relativePrefix, $pathComparison)) {
                throw "isolated candidate check failed: $Label tracked source tree " +
                    'was renamed or replaced during the build'
            }
        }
    }
}

function New-TrackedSourceMonitors {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][object]$TrackedPaths
    )

    $monitors = @([SerctlCandidateChangeMonitor]::new($Root, $false))
    $comparer = if ($hostIsWindows) {
        [System.StringComparer]::OrdinalIgnoreCase
    }
    else {
        [System.StringComparer]::Ordinal
    }
    $topDirectories = [System.Collections.Generic.HashSet[string]]::new($comparer)
    foreach ($tracked in $TrackedPaths) {
        $separator = $tracked.IndexOf('/')
        if ($separator -gt 0) {
            [void]$topDirectories.Add($tracked.Substring(0, $separator))
        }
    }
    foreach ($topDirectory in $topDirectories) {
        $path = Join-Path $Root $topDirectory
        Assert-PlainDirectory `
            -Path $path `
            -Label "tracked source directory '$topDirectory'"
        $monitors += [SerctlCandidateChangeMonitor]::new($path, $true)
    }
    return $monitors
}

function Stop-CandidateChangeMonitors {
    param([Parameter(Mandatory = $false)][AllowNull()][object[]]$Monitors)

    if ($null -eq $Monitors) {
        return
    }
    foreach ($monitor in $Monitors) {
        if ($null -ne $monitor) {
            $monitor.Dispose()
        }
    }
}

function Assert-PlainDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $false)][bool]$Create = $false
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        Assert-CandidateCondition $Create "$Label does not exist: '$Path'"
        [System.IO.Directory]::CreateDirectory($Path) | Out-Null
    }
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    Assert-CandidateCondition $item.PSIsContainer "$Label is not a directory: '$Path'"
    Assert-CandidateCondition (
        ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0
    ) "$Label is a symbolic link or reparse point: '$Path'"
}

function Assert-PathBelow {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Parent,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $prefix = [System.IO.Path]::GetFullPath($Parent).TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    ) + [System.IO.Path]::DirectorySeparatorChar
    Assert-CandidateCondition ($fullPath.StartsWith($prefix, $pathComparison)) (
        "$Label escaped its dedicated parent: '$fullPath'"
    )
}

function Get-RepositoryRelativePath {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Root
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $rootPrefix = [System.IO.Path]::GetFullPath($Root).TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    ) + [System.IO.Path]::DirectorySeparatorChar
    Assert-CandidateCondition ($fullPath.StartsWith($rootPrefix, $pathComparison)) (
        "path is not repository-relative: '$fullPath'"
    )
    return $fullPath.Substring($rootPrefix.Length).Replace('\', '/')
}

function Resolve-StrictApplication {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][string]$Repository
    )

    Assert-CandidateCondition (
        -not [System.Management.Automation.WildcardPattern]::ContainsWildcardCharacters(
            $Name
        )
    ) "$Label command contains wildcard characters"
    $commands = @(Get-Command `
        -Name $Name `
        -CommandType Application `
        -All `
        -ErrorAction Stop)
    $paths = @($commands | ForEach-Object {
        [System.IO.Path]::GetFullPath($_.Source)
    } | Select-Object -Unique)
    Assert-CandidateCondition ($paths.Count -ge 1) "$Label Application was not found"
    $path = $paths[0]
    Assert-CandidateCondition ([System.IO.Path]::IsPathRooted($path)) (
        "$Label command did not resolve to an absolute path"
    )
    $repositoryPrefix = [System.IO.Path]::GetFullPath($Repository).TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    ) + [System.IO.Path]::DirectorySeparatorChar
    Assert-CandidateCondition (-not $path.StartsWith(
        $repositoryPrefix,
        $pathComparison
    )) "$Label command is shadowed from inside the source repository"
    $information = Get-PinnedRegularFileDigest -Path $path
    return [pscustomobject]@{
        Path = $path
        Identity = $information.Identity
        FileIdentity = $information.Identity
        Size = $information.Size
        Sha256 = $information.Sha256
    }
}

function Invoke-CapturedCommand {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Description
    )

    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = @(& $FilePath @Arguments 2>&1)
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    Assert-CandidateCondition ($exitCode -eq 0) "$Description failed"
    return @($output | ForEach-Object { $_.ToString() })
}

function Get-VerboseToolIdentity {
    param(
        [Parameter(Mandatory = $true)][string[]]$Lines,
        [Parameter(Mandatory = $true)][string]$Tool
    )

    Assert-CandidateCondition ($Lines.Count -ge 1) "$Tool verbose version is empty"
    $headline = [regex]::Match(
        [string]$Lines[0],
        ('^' + [regex]::Escape($Tool) + ' (?<version>[^ ]+) ')
    )
    Assert-CandidateCondition $headline.Success "$Tool verbose version headline is invalid"
    $fields = @{}
    foreach ($line in $Lines) {
        $field = [regex]::Match([string]$line, '^(?<name>[a-z0-9-]+): (?<value>.+)$')
        if ($field.Success) {
            Assert-CandidateCondition (-not $fields.ContainsKey($field.Groups['name'].Value)) (
                "$Tool verbose version repeats '$($field.Groups['name'].Value)'"
            )
            $fields[$field.Groups['name'].Value] = $field.Groups['value'].Value
        }
    }
    foreach ($required in @('release', 'host')) {
        Assert-CandidateCondition ($fields.ContainsKey($required)) (
            "$Tool verbose version lacks '$required'"
        )
    }
    return [pscustomobject]@{
        Version = $headline.Groups['version'].Value
        Release = [string]$fields['release']
        Host = [string]$fields['host']
        CommitHash = if ($fields.ContainsKey('commit-hash')) {
            [string]$fields['commit-hash']
        }
        else {
            $null
        }
        Text = $Lines -join "`n"
    }
}

function Invoke-CargoBuild {
    param(
        [Parameter(Mandatory = $true)][string]$CargoPath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory
    )

    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    Push-Location -LiteralPath $WorkingDirectory
    try {
        & $CargoPath @Arguments
        $exitCode = $LASTEXITCODE
    }
    finally {
        Pop-Location
        $ErrorActionPreference = $previousErrorActionPreference
    }
    Assert-CandidateCondition ($exitCode -eq 0) 'isolated Cargo release build failed'
}

function Invoke-BinaryVersion {
    param(
        [Parameter(Mandatory = $true)][string]$BinaryPath,
        [Parameter(Mandatory = $true)][string]$Component
    )

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $BinaryPath
    $startInfo.Arguments = '--version'
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        Assert-CandidateCondition $process.Start() "$Component --version failed to start"
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(10000)) {
            $process.Kill()
            $process.WaitForExit()
            throw "isolated candidate check failed: $Component --version exceeded 10 seconds"
        }
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        Assert-CandidateCondition ($process.ExitCode -eq 0) (
            "$Component --version failed with exit code $($process.ExitCode)"
        )
        Assert-CandidateCondition ([string]::IsNullOrEmpty($stderr)) (
            "$Component --version wrote to standard error"
        )
        return $stdout.TrimEnd("`r", "`n")
    }
    finally {
        $process.Dispose()
    }
}

function Assert-ExactVersionLine {
    param(
        [Parameter(Mandatory = $true)][string]$Line,
        [Parameter(Mandatory = $true)][string]$Component,
        [Parameter(Mandatory = $true)][string]$ExpectedVersion,
        [Parameter(Mandatory = $true)][string]$ExpectedCommit
    )

    Assert-CandidateCondition (
        -not [string]::IsNullOrWhiteSpace($Line) -and
        -not $Line.Contains("`r") -and
        -not $Line.Contains("`n")
    ) "$Component --version returned an invalid identity"

    $versionToken = [regex]::Escape($ExpectedVersion)
    $commitToken = [regex]::Escape($ExpectedCommit.Substring(0, 12))
    $pattern = switch ($Component) {
        'serctl_cli' {
            '^serctl_cli ' + $versionToken + ' \(git ' + $commitToken + '; ' +
                [regex]::Escape($vaultContract) + '\)$'
        }
        'serctl_daemon' {
            '^serctl_daemon ' + $versionToken + ' \(git ' + $commitToken + '; ' +
                [regex]::Escape($ipcContract) + '; ' +
                [regex]::Escape($vaultContract) + '\)$'
        }
        'serctl-xfer' {
            '^serctl-xfer ' + $versionToken + ' \(git ' + $commitToken + '; ' +
                [regex]::Escape($transferContract) + '\)$'
        }
        default { $null }
    }
    Assert-CandidateCondition ($null -ne $pattern) "unknown component '$Component'"
    Assert-CandidateCondition ([regex]::IsMatch(
        $Line,
        $pattern,
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    )) "$Component does not report the exact clean candidate identity: $Line"
    Assert-CandidateCondition (-not $Line.Contains('-dirty')) (
        "$Component reports dirty build provenance"
    )
}

function ConvertTo-LowerHex {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)

    return ([System.BitConverter]::ToString($Bytes)).Replace('-', '').ToLowerInvariant()
}

function Get-PinnedFileEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Component,
        [Parameter(Mandatory = $true)][string]$ExpectedVersion,
        [Parameter(Mandatory = $true)][string]$ExpectedCommit
    )

    $handle = [SerctlCandidateNative]::OpenFileRead($Path)
    $stream = $null
    try {
        $before = [SerctlCandidateNative]::Inspect($handle)
        Assert-CandidateCondition (-not $before.IsDirectory) (
            "component '$Component' is not a regular file"
        )
        Assert-CandidateCondition (-not $before.IsReparsePoint) (
            "component '$Component' is a symbolic link or reparse point"
        )
        Assert-CandidateCondition ($before.Size -gt 0) "component '$Component' is empty"

        $stream = [System.IO.FileStream]::new(
            $handle,
            [System.IO.FileAccess]::Read
        )
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            $hashBefore = ConvertTo-LowerHex -Bytes $sha.ComputeHash($stream)
        }
        finally {
            $sha.Dispose()
        }

        $line = Invoke-BinaryVersion -BinaryPath $Path -Component $Component
        Assert-ExactVersionLine `
            -Line $line `
            -Component $Component `
            -ExpectedVersion $ExpectedVersion `
            -ExpectedCommit $ExpectedCommit

        $stream.Position = 0
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            $hashAfter = ConvertTo-LowerHex -Bytes $sha.ComputeHash($stream)
        }
        finally {
            $sha.Dispose()
        }
        $after = [SerctlCandidateNative]::Inspect($handle)
        Assert-CandidateCondition ($before.Identity -ceq $after.Identity) (
            "component '$Component' changed file identity during validation"
        )
        Assert-CandidateCondition ($before.Size -eq $after.Size) (
            "component '$Component' changed size during validation"
        )
        Assert-CandidateCondition ($hashBefore -ceq $hashAfter) (
            "component '$Component' changed content during validation"
        )

        return [pscustomobject]@{
            Identity = $before.Identity
            Size = [long]$before.Size
            Sha256 = $hashBefore
            VersionLine = $line
        }
    }
    finally {
        if ($null -ne $stream) {
            $stream.Dispose()
        }
        else {
            $handle.Dispose()
        }
    }
}

function Assert-ArtifactEvidenceUnchanged {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Component,
        [Parameter(Mandatory = $true)][object]$Expected
    )

    $actual = Get-PinnedRegularFileDigest -Path $Path
    Assert-CandidateCondition ($actual.Identity -ceq $Expected.Identity) (
        "component '$Component' was replaced after validation"
    )
    Assert-CandidateCondition ($actual.Size -eq $Expected.Size) (
        "component '$Component' size changed after validation"
    )
    Assert-CandidateCondition ($actual.Sha256 -ceq $Expected.Sha256) (
        "component '$Component' hash changed after validation"
    )
}

function Copy-NewFile {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    $input = [System.IO.FileStream]::new(
        $Source,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read
    )
    try {
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
        }
    }
    finally {
        $input.Dispose()
    }
}

function Set-CandidateExecutableMode {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $false)][AllowNull()][string]$ChmodPath
    )

    if ($hostIsWindows) {
        return 'windows-executable'
    }
    Assert-CandidateCondition (-not [string]::IsNullOrWhiteSpace($ChmodPath)) (
        'Unix executable mode requires one resolved chmod Application path'
    )
    $getMode = [System.IO.File].GetMethod(
        'GetUnixFileMode',
        [type[]]@([string])
    )
    Assert-CandidateCondition ($null -ne $getMode) (
        'this PowerShell runtime cannot read Unix file mode; refusing to claim 0755'
    )
    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $ChmodPath 0755 -- $Path
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    Assert-CandidateCondition ($exitCode -eq 0) (
        "failed to set candidate executable mode 0755 on '$Path'"
    )
    $mode = [int]$getMode.Invoke($null, [object[]]@($Path))
    Assert-CandidateCondition (($mode -band 4095) -eq 493) (
        "candidate executable mode is not exactly 0755 on '$Path'"
    )
    return '0755'
}

function Write-NewUtf8File {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Text
    )

    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($Text)
    $stream = [System.IO.FileStream]::new(
        $Path,
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None,
        4096,
        [System.IO.FileOptions]::WriteThrough
    )
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
}

function Restore-CandidateEnvironmentVariable {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $false)][AllowNull()][string]$Value
    )

    if ([string]::IsNullOrEmpty($Value)) {
        Remove-Item -LiteralPath "Env:$Name" -ErrorAction SilentlyContinue
    }
    else {
        [System.Environment]::SetEnvironmentVariable($Name, $Value, 'Process')
    }
}

function New-PinnedDirectoryState {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $handle = [SerctlCandidateNative]::OpenDirectory($Path)
    try {
        $information = [SerctlCandidateNative]::Inspect($handle)
        Assert-CandidateCondition $information.IsDirectory (
            "$Label is not a directory: '$Path'"
        )
        Assert-CandidateCondition (-not $information.IsReparsePoint) (
            "$Label is a symbolic link or reparse point: '$Path'"
        )
        return [pscustomobject]@{
            Path = [System.IO.Path]::GetFullPath($Path)
            Label = $Label
            Identity = $information.Identity
            Handle = $handle
        }
    }
    catch {
        $handle.Dispose()
        throw
    }
}

function Assert-PinnedDirectoryState {
    param([Parameter(Mandatory = $true)][object]$State)

    Assert-CandidateCondition (-not $State.Handle.IsClosed) (
        "$($State.Label) identity handle is closed"
    )
    $held = [SerctlCandidateNative]::Inspect($State.Handle)
    Assert-CandidateCondition (
        $held.IsDirectory -and
        -not $held.IsReparsePoint -and
        $held.Identity -ceq $State.Identity
    ) "$($State.Label) held identity changed"

    $probe = [SerctlCandidateNative]::OpenDirectory($State.Path)
    try {
        $current = [SerctlCandidateNative]::Inspect($probe)
        Assert-CandidateCondition (
            $current.IsDirectory -and
            -not $current.IsReparsePoint -and
            $current.Identity -ceq $State.Identity
        ) "$($State.Label) path was replaced or became a reparse point"
    }
    finally {
        $probe.Dispose()
    }
}

function Read-PinnedOwnerToken {
    param([Parameter(Mandatory = $true)][string]$Path)

    $handle = [SerctlCandidateNative]::OpenFileRead($Path)
    $stream = $null
    try {
        $information = [SerctlCandidateNative]::Inspect($handle)
        Assert-CandidateCondition (
            -not $information.IsDirectory -and
            -not $information.IsReparsePoint -and
            $information.Size -ge 1 -and
            $information.Size -le 128
        ) 'private directory owner marker is not one bounded regular file'
        $stream = [System.IO.FileStream]::new($handle, [System.IO.FileAccess]::Read)
        $bytes = [byte[]]::new([int]$information.Size)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            Assert-CandidateCondition ($read -gt 0) (
                'private directory owner marker ended early'
            )
            $offset += $read
        }
        return [System.Text.UTF8Encoding]::new($false, $true).GetString($bytes)
    }
    finally {
        if ($null -ne $stream) {
            $stream.Dispose()
        }
        else {
            $handle.Dispose()
        }
    }
}

function Get-PinnedRegularFileDigest {
    param([Parameter(Mandatory = $true)][string]$Path)

    $handle = [SerctlCandidateNative]::OpenFileRead($Path)
    $stream = $null
    try {
        $information = [SerctlCandidateNative]::Inspect($handle)
        Assert-CandidateCondition (
            -not $information.IsDirectory -and
            -not $information.IsReparsePoint
        ) "expected one regular non-reparse file: '$Path'"
        $stream = [System.IO.FileStream]::new($handle, [System.IO.FileAccess]::Read)
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            $hash = ConvertTo-LowerHex -Bytes $sha.ComputeHash($stream)
        }
        finally {
            $sha.Dispose()
        }
        return [pscustomobject]@{
            Identity = $information.Identity
            Size = [long]$information.Size
            Sha256 = $hash
        }
    }
    finally {
        if ($null -ne $stream) {
            $stream.Dispose()
        }
        else {
            $handle.Dispose()
        }
    }
}

function Assert-RegularFileDigestUnchanged {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][object]$Expected,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $actual = Get-PinnedRegularFileDigest -Path $Path
    Assert-CandidateCondition (
        $actual.Identity -ceq $Expected.Identity -and
        $actual.Size -eq $Expected.Size -and
        $actual.Sha256 -ceq $Expected.Sha256
    ) "$Label was replaced or changed after validation"
}

function Get-PinnedUtf8FileEvidence {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][long]$MaximumBytes
    )

    $handle = [SerctlCandidateNative]::OpenFileRead($Path)
    $stream = $null
    try {
        $information = [SerctlCandidateNative]::Inspect($handle)
        Assert-CandidateCondition (
            -not $information.IsDirectory -and
            -not $information.IsReparsePoint -and
            $information.Size -ge 1 -and
            $information.Size -le $MaximumBytes
        ) "expected one bounded regular UTF-8 file: '$Path'"
        $stream = [System.IO.FileStream]::new($handle, [System.IO.FileAccess]::Read)
        $bytes = [byte[]]::new([int]$information.Size)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $read = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            Assert-CandidateCondition ($read -gt 0) "UTF-8 file ended early: '$Path'"
            $offset += $read
        }
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            $hash = ConvertTo-LowerHex -Bytes $sha.ComputeHash($bytes)
        }
        finally {
            $sha.Dispose()
        }
        return [pscustomobject]@{
            Identity = $information.Identity
            Size = [long]$information.Size
            Sha256 = $hash
            Text = [System.Text.UTF8Encoding]::new($false, $true).GetString($bytes)
        }
    }
    finally {
        if ($null -ne $stream) {
            $stream.Dispose()
        }
        else {
            $handle.Dispose()
        }
    }
}

function New-OwnedPrivateDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][object]$ParentState,
        [Parameter(Mandatory = $true)][string]$OwnerToken
    )

    Assert-PinnedDirectoryState -State $ParentState
    Assert-CandidateCondition (-not (Test-Path -LiteralPath $Path)) (
        "$Label already exists: '$Path'"
    )
    [System.IO.Directory]::CreateDirectory($Path) | Out-Null
    $state = New-PinnedDirectoryState -Path $Path -Label $Label
    $state | Add-Member -NotePropertyName OwnerToken -NotePropertyValue $OwnerToken
    $state | Add-Member `
        -NotePropertyName OwnerMarker `
        -NotePropertyValue (Join-Path $Path '.serctl-candidate-owner')
    $state | Add-Member -NotePropertyName OwnerManifestPath -NotePropertyValue $null
    $state | Add-Member -NotePropertyName OwnerManifestEvidence -NotePropertyValue $null
    Write-NewUtf8File -Path $state.OwnerMarker -Text $OwnerToken
    return $state
}

function Assert-OwnedDirectoryState {
    param(
        [Parameter(Mandatory = $true)][object]$State,
        [Parameter(Mandatory = $true)][object]$ParentState
    )

    Assert-PinnedDirectoryState -State $ParentState
    Assert-PinnedDirectoryState -State $State
    if ($null -ne $State.OwnerMarker) {
        $token = Read-PinnedOwnerToken -Path $State.OwnerMarker
        Assert-CandidateCondition ($token -ceq $State.OwnerToken) (
            "$($State.Label) owner token changed; refusing cleanup or publication"
        )
    }
    else {
        Assert-CandidateCondition (
            $null -ne $State.OwnerManifestPath -and
            $null -ne $State.OwnerManifestEvidence
        ) "$($State.Label) has no owner proof; refusing cleanup or publication"
        $actualManifest = Get-PinnedUtf8FileEvidence `
            -Path $State.OwnerManifestPath `
            -MaximumBytes 1048576
        Assert-CandidateCondition (
            $actualManifest.Identity -ceq $State.OwnerManifestEvidence.Identity -and
            $actualManifest.Size -eq $State.OwnerManifestEvidence.Size -and
            $actualManifest.Sha256 -ceq $State.OwnerManifestEvidence.Sha256
        ) "$($State.Label) owner manifest was replaced or changed"
        $manifestOwner = (
            $actualManifest.Text | ConvertFrom-Json
        ).candidate_set.owner_token
        Assert-CandidateCondition ([string]$manifestOwner -ceq $State.OwnerToken) (
            "$($State.Label) manifest owner token changed; refusing cleanup"
        )
    }
}

function Assert-TreeContainsNoReparsePoints {
    param([Parameter(Mandatory = $true)][string]$Root)

    $pending = [System.Collections.Generic.Stack[string]]::new()
    $pending.Push($Root)
    while ($pending.Count -gt 0) {
        $directory = $pending.Pop()
        foreach ($entry in [System.IO.Directory]::EnumerateFileSystemEntries($directory)) {
            $attributes = [System.IO.File]::GetAttributes($entry)
            Assert-CandidateCondition (
                ($attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0
            ) "cleanup tree contains a symbolic link or reparse point: '$entry'"
            if (($attributes -band [System.IO.FileAttributes]::Directory) -ne 0) {
                $pending.Push($entry)
            }
        }
    }
}

function Remove-OwnedPrivateDirectory {
    param(
        [Parameter(Mandatory = $true)][AllowNull()][object]$State,
        [Parameter(Mandatory = $true)][object]$ParentState,
        [Parameter(Mandatory = $true)][string]$LeafPrefix
    )

    if ($null -eq $State) {
        return
    }
    Assert-PathBelow -Path $State.Path -Parent $ParentState.Path -Label 'cleanup path'
    Assert-CandidateCondition (
        [System.IO.Path]::GetFileName($State.Path).StartsWith(
            $LeafPrefix,
            [System.StringComparison]::Ordinal
        )
    ) "refusing to clean an unexpected private directory '$($State.Path)'"
    Assert-OwnedDirectoryState -State $State -ParentState $ParentState
    Assert-TreeContainsNoReparsePoints -Root $State.Path
    $expectedIdentity = $State.Identity
    $State.Handle.Dispose()
    $probe = New-PinnedDirectoryState -Path $State.Path -Label $State.Label
    try {
        Assert-CandidateCondition ($probe.Identity -ceq $expectedIdentity) (
            "$($State.Label) was replaced immediately before cleanup"
        )
        Assert-PinnedDirectoryState -State $ParentState
    }
    finally {
        $probe.Handle.Dispose()
    }
    try {
        [System.IO.Directory]::Delete($State.Path, $true)
        Assert-CandidateCondition (-not [System.IO.Directory]::Exists($State.Path)) (
            "$($State.Label) cleanup did not complete"
        )
    }
    catch {
        if ([System.IO.Directory]::Exists($State.Path)) {
            $replacement = New-PinnedDirectoryState `
                -Path $State.Path `
                -Label $State.Label
            if ($replacement.Identity -ceq $expectedIdentity) {
                $State.Handle = $replacement.Handle
            }
            else {
                $replacement.Handle.Dispose()
            }
        }
        throw
    }
}

function Remove-OwnedDetachedWorktree {
    param(
        [Parameter(Mandatory = $true)][AllowNull()][object]$State,
        [Parameter(Mandatory = $true)][object]$ParentState,
        [Parameter(Mandatory = $true)][string]$Repository
    )

    if ($null -eq $State) {
        return
    }
    Assert-PathBelow -Path $State.Path -Parent $ParentState.Path -Label 'worktree path'
    Assert-CandidateCondition (
        [System.IO.Path]::GetFileName($State.Path).StartsWith(
            'candidate-source-',
            [System.StringComparison]::Ordinal
        )
    ) "refusing to clean an unexpected detached worktree '$($State.Path)'"
    Assert-OwnedDirectoryState -State $State -ParentState $ParentState
    Assert-TreeContainsNoReparsePoints -Root $State.Path
    $expectedIdentity = $State.Identity
    $State.Handle.Dispose()
    try {
        [void](Invoke-CandidateGit `
            -Root $Repository `
            -Arguments @('worktree', 'remove', '--force', $State.Path))
        Assert-CandidateCondition (-not [System.IO.Directory]::Exists($State.Path)) (
            'detached source worktree cleanup did not complete'
        )
    }
    catch {
        if ([System.IO.Directory]::Exists($State.Path)) {
            $replacement = New-PinnedDirectoryState `
                -Path $State.Path `
                -Label $State.Label
            if ($replacement.Identity -ceq $expectedIdentity) {
                $State.Handle = $replacement.Handle
            }
            else {
                $replacement.Handle.Dispose()
            }
        }
        throw
    }
}

Assert-CandidateCondition ([regex]::IsMatch(
    $Version,
    $versionPattern,
    [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
)) "version '$Version' is not one canonical prerelease version"
foreach ($name in $gitOverrideVariables) {
    Assert-CandidateCondition ([string]::IsNullOrEmpty(
        [System.Environment]::GetEnvironmentVariable($name, 'Process')
    )) "Git repository override '$name' must be unset"
}
foreach ($name in $compilerOverrideVariables) {
    Assert-CandidateCondition ([string]::IsNullOrEmpty(
        [System.Environment]::GetEnvironmentVariable($name, 'Process')
    )) "compiler override '$name' must be unset"
}
$gitConfigCountRaw = [System.Environment]::GetEnvironmentVariable(
    'GIT_CONFIG_COUNT',
    'Process'
)
if (-not [string]::IsNullOrEmpty($gitConfigCountRaw)) {
    Assert-CandidateCondition ($gitConfigCountRaw -cmatch '^(?:0|[1-9][0-9]?)$') (
        'GIT_CONFIG_COUNT is not a bounded canonical integer'
    )
    $gitConfigCount = [int]$gitConfigCountRaw
    Assert-CandidateCondition ($gitConfigCount -le 64) (
        'GIT_CONFIG_COUNT exceeds the bounded safe-directory allowance'
    )
    for ($index = 0; $index -lt $gitConfigCount; $index++) {
        $key = [System.Environment]::GetEnvironmentVariable(
            "GIT_CONFIG_KEY_$index",
            'Process'
        )
        $value = [System.Environment]::GetEnvironmentVariable(
            "GIT_CONFIG_VALUE_$index",
            'Process'
        )
        Assert-CandidateCondition ($key -ceq 'safe.directory') (
            "Git injected config entry $index is not safe.directory"
        )
        Assert-CandidateCondition (-not [string]::IsNullOrWhiteSpace($value)) (
            "Git safe.directory entry $index has no value"
        )
    }
}

$repository = [System.IO.Path]::GetFullPath($RepositoryRoot)
Assert-PlainDirectory -Path $repository -Label 'repository root'
$gitTool = Resolve-StrictApplication `
    -Name $GitExecutable `
    -Label 'git' `
    -Repository $repository
$script:GitPath = $gitTool.Path
$gitVersionOutput = @(
    Invoke-CapturedCommand `
        -FilePath $script:GitPath `
        -Arguments @('--version') `
        -Description 'git --version'
)
Assert-CandidateCondition ($gitVersionOutput.Count -eq 1) (
    'git --version did not return exactly one line'
)
$gitVersion = [string]$gitVersionOutput[0]
$resolvedTop = Invoke-CandidateGit -Root $repository -Arguments @(
    'rev-parse', '--show-toplevel'
)
$resolvedTop = [System.IO.Path]::GetFullPath($resolvedTop)
Assert-CandidateCondition ($resolvedTop.Equals($repository, $pathComparison)) (
    "repository root '$repository' is not the Git top level '$resolvedTop'"
)
$initialSnapshot = Get-CleanGitSnapshot -Root $repository
$initialHead = $initialSnapshot.Head
$initialTree = $initialSnapshot.Tree
$trackedPaths = Get-TrackedPathSet -Root $repository

$workspaceManifest = [System.IO.File]::ReadAllText(
    (Join-Path $repository 'Cargo.toml'),
    [System.Text.Encoding]::UTF8
)
$workspaceVersion = [regex]::Match(
    $workspaceManifest,
    '(?ms)^\[workspace\.package\]\s*.*?^version\s*=\s*"(?<version>[^"]+)"\s*$',
    [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
)
Assert-CandidateCondition $workspaceVersion.Success 'cannot read workspace package version'
Assert-CandidateCondition (
    $workspaceVersion.Groups['version'].Value -ceq $Version
) (
    "requested version '$Version' does not equal workspace version " +
    "'$($workspaceVersion.Groups['version'].Value)'"
)

$identity = "v$Version-$($initialHead.Substring(0, 12))"
$targetRoot = Join-Path $repository 'target'
$candidatesRoot = Join-Path $targetRoot 'candidates'
$buildParent = Join-Path $targetRoot 'candidate-builds'
$stagingParent = Join-Path $targetRoot 'candidate-staging'
$sourceParent = Join-Path $targetRoot 'candidate-sources'
$candidatePath = Join-Path $candidatesRoot $identity
$forbiddenRelease = [System.IO.Path]::GetFullPath((Join-Path $targetRoot 'release'))
$forbiddenPredecessor = [System.IO.Path]::GetFullPath((Join-Path $targetRoot 'staging-v0.3'))
foreach ($path in @($candidatePath, $buildParent, $stagingParent, $sourceParent)) {
    Assert-PathBelow -Path $path -Parent $targetRoot -Label 'candidate path'
    $full = [System.IO.Path]::GetFullPath($path)
    Assert-CandidateCondition (-not $full.Equals($forbiddenRelease, $pathComparison)) (
        'candidate path resolves to target/release'
    )
    Assert-CandidateCondition (-not $full.StartsWith(
        $forbiddenPredecessor + [System.IO.Path]::DirectorySeparatorChar,
        $pathComparison
    ) -and -not $full.Equals($forbiddenPredecessor, $pathComparison)) (
        'candidate path resolves into target/staging-v0.3'
    )
}

Assert-PlainDirectory -Path $targetRoot -Label 'target root' -Create $true
$targetState = New-PinnedDirectoryState -Path $targetRoot -Label 'target root'
Assert-PlainDirectory -Path $candidatesRoot -Label 'candidate-set parent' -Create $true
$candidatesState = New-PinnedDirectoryState `
    -Path $candidatesRoot `
    -Label 'candidate-set parent'
Assert-PlainDirectory -Path $buildParent -Label 'candidate build parent' -Create $true
$buildParentState = New-PinnedDirectoryState `
    -Path $buildParent `
    -Label 'candidate build parent'
Assert-PlainDirectory -Path $stagingParent -Label 'candidate staging parent' -Create $true
$stagingParentState = New-PinnedDirectoryState `
    -Path $stagingParent `
    -Label 'candidate staging parent'
Assert-PlainDirectory -Path $sourceParent -Label 'candidate source parent' -Create $true
$sourceParentState = New-PinnedDirectoryState `
    -Path $sourceParent `
    -Label 'candidate source parent'
foreach ($state in @(
    $targetState,
    $candidatesState,
    $buildParentState,
    $stagingParentState,
    $sourceParentState
)) {
    Assert-PinnedDirectoryState -State $state
}
Assert-CandidateCondition (-not (Test-Path -LiteralPath $candidatePath)) (
    "refusing to overwrite existing candidate set '$candidatePath'"
)

$cargoTool = Resolve-StrictApplication `
    -Name $CargoExecutable `
    -Label 'cargo' `
    -Repository $repository
$cargoPath = $cargoTool.Path
$cargoVersionOutput = @(
    Invoke-CapturedCommand `
        -FilePath $cargoPath `
        -Arguments @('--version', '--verbose') `
        -Description 'cargo --version --verbose'
)
$cargoIdentity = Get-VerboseToolIdentity -Lines $cargoVersionOutput -Tool 'cargo'
$cargoVersion = $cargoIdentity.Text
$rustcCommand = if ([string]::IsNullOrWhiteSpace($RustcExecutable)) {
    Join-Path `
        ([System.IO.Path]::GetDirectoryName($cargoPath)) `
        $(if ($hostIsWindows) { 'rustc.exe' } else { 'rustc' })
}
else {
    $RustcExecutable
}
$rustcTool = Resolve-StrictApplication `
    -Name $rustcCommand `
    -Label 'rustc' `
    -Repository $repository
$rustcPath = $rustcTool.Path
$rustcVersionOutput = @(
    Invoke-CapturedCommand `
        -FilePath $rustcPath `
        -Arguments @('--version', '--verbose') `
        -Description 'rustc --version --verbose'
)
$rustcIdentity = Get-VerboseToolIdentity -Lines $rustcVersionOutput -Tool 'rustc'
$rustcVersion = $rustcIdentity.Text
$rustdocCommand = if ([string]::IsNullOrWhiteSpace($RustdocExecutable)) {
    Join-Path `
        ([System.IO.Path]::GetDirectoryName($cargoPath)) `
        $(if ($hostIsWindows) { 'rustdoc.exe' } else { 'rustdoc' })
}
else {
    $RustdocExecutable
}
$rustdocTool = Resolve-StrictApplication `
    -Name $rustdocCommand `
    -Label 'rustdoc' `
    -Repository $repository
$rustdocPath = $rustdocTool.Path
$rustdocVersionOutput = @(
    Invoke-CapturedCommand `
        -FilePath $rustdocPath `
        -Arguments @('--version', '--verbose') `
        -Description 'rustdoc --version --verbose'
)
$rustdocIdentity = Get-VerboseToolIdentity -Lines $rustdocVersionOutput -Tool 'rustdoc'
$rustdocVersion = $rustdocIdentity.Text
$toolDirectory = [System.IO.Path]::GetDirectoryName($cargoPath)
Assert-CandidateCondition (
    [System.IO.Path]::GetDirectoryName($rustcPath).Equals(
        $toolDirectory,
        $pathComparison
    ) -and
    [System.IO.Path]::GetDirectoryName($rustdocPath).Equals(
        $toolDirectory,
        $pathComparison
    )
) 'cargo, rustc, and rustdoc must be regular files in one toolchain directory'
Assert-CandidateCondition (
    $cargoTool.FileIdentity -cne $rustcTool.FileIdentity -and
    $cargoTool.FileIdentity -cne $rustdocTool.FileIdentity -and
    $rustcTool.FileIdentity -cne $rustdocTool.FileIdentity
) 'cargo, rustc, and rustdoc must have distinct file identities'
$toolchainManifestPath = Join-Path $repository 'rust-toolchain.toml'
$toolchainManifest = Get-PinnedRegularFileDigest -Path $toolchainManifestPath
$toolchainManifestText = [System.IO.File]::ReadAllText(
    $toolchainManifestPath,
    [System.Text.UTF8Encoding]::new($false, $true)
)
$toolchainChannelMatch = [regex]::Match(
    $toolchainManifestText,
    '(?ms)^\[toolchain\]\s*.*?^channel\s*=\s*"(?<channel>[^"]+)"\s*$'
)
Assert-CandidateCondition $toolchainChannelMatch.Success (
    'rust-toolchain.toml has no canonical toolchain channel'
)
$toolchainChannel = $toolchainChannelMatch.Groups['channel'].Value
Assert-CandidateCondition (
    $cargoIdentity.Version -ceq $toolchainChannel -and
    $cargoIdentity.Release -ceq $toolchainChannel -and
    $rustcIdentity.Version -ceq $toolchainChannel -and
    $rustcIdentity.Release -ceq $toolchainChannel -and
    $rustdocIdentity.Version -ceq $toolchainChannel -and
    $rustdocIdentity.Release -ceq $toolchainChannel
) 'cargo, rustc, and rustdoc do not match the pinned rust-toolchain channel'
Assert-CandidateCondition (
    $cargoIdentity.Host -ceq $rustcIdentity.Host -and
    $rustcIdentity.Host -ceq $rustdocIdentity.Host
) 'cargo, rustc, and rustdoc do not report one host triple'
Assert-CandidateCondition (
    $rustcIdentity.CommitHash -cmatch '^[0-9a-f]{40}$' -and
    $rustcIdentity.CommitHash -ceq $rustdocIdentity.CommitHash
) 'rustc and rustdoc do not report one compiler commit'
$chmodTool = $null
$chmodVersion = $null
if (-not $hostIsWindows) {
    $chmodTool = Resolve-StrictApplication `
        -Name $ChmodExecutable `
        -Label 'chmod' `
        -Repository $repository
    $chmodVersionOutput = @(
        Invoke-CapturedCommand `
            -FilePath $chmodTool.Path `
            -Arguments @('--version') `
            -Description 'chmod --version'
    )
    Assert-CandidateCondition ($chmodVersionOutput.Count -ge 1) (
        'chmod --version did not return a version line'
    )
    $chmodVersion = [string]$chmodVersionOutput[0]
}

$nonce = [System.Guid]::NewGuid().ToString('N')
$buildOwnerToken = [System.Guid]::NewGuid().ToString('N') +
    [System.Guid]::NewGuid().ToString('N')
$stageOwnerToken = [System.Guid]::NewGuid().ToString('N') +
    [System.Guid]::NewGuid().ToString('N')
$sourceOwnerToken = [System.Guid]::NewGuid().ToString('N') +
    [System.Guid]::NewGuid().ToString('N')
$buildRoot = Join-Path $buildParent "candidate-build-$identity-$nonce"
$stageRoot = Join-Path $stagingParent "candidate-stage-$identity-$nonce"
$sourceRoot = Join-Path $sourceParent "candidate-source-$identity-$nonce"
Assert-PathBelow -Path $buildRoot -Parent $buildParent -Label 'Cargo target directory'
Assert-PathBelow -Path $stageRoot -Parent $stagingParent -Label 'candidate staging directory'
Assert-PathBelow -Path $sourceRoot -Parent $sourceParent -Label 'candidate source directory'
Assert-CandidateCondition (-not (Test-Path -LiteralPath $buildRoot)) (
    "private Cargo target already exists: '$buildRoot'"
)
Assert-CandidateCondition (-not (Test-Path -LiteralPath $stageRoot)) (
    "private candidate staging already exists: '$stageRoot'"
)
Assert-CandidateCondition (-not (Test-Path -LiteralPath $sourceRoot)) (
    "private candidate source already exists: '$sourceRoot'"
)
$previousCargoTarget = [System.Environment]::GetEnvironmentVariable(
    'CARGO_TARGET_DIR',
    'Process'
)
$previousRustc = [System.Environment]::GetEnvironmentVariable('RUSTC', 'Process')
$previousRustdoc = [System.Environment]::GetEnvironmentVariable('RUSTDOC', 'Process')
$published = $false
$buildCleaned = $false
$sourceCleaned = $false
$cargoEnvironmentRestored = $false
$rustcEnvironmentRestored = $false
$rustdocEnvironmentRestored = $false
$buildState = $null
$stageState = $null
$sourceState = $null
$originalMonitors = $null
$worktreeMonitors = $null
try {
    $buildState = New-OwnedPrivateDirectory `
        -Path $buildRoot `
        -Label 'private Cargo target directory' `
        -ParentState $buildParentState `
        -OwnerToken $buildOwnerToken
    $stageState = New-OwnedPrivateDirectory `
        -Path $stageRoot `
        -Label 'private candidate staging directory' `
        -ParentState $stagingParentState `
        -OwnerToken $stageOwnerToken

    Assert-PinnedDirectoryState -State $sourceParentState
    [void](Invoke-CandidateGit `
        -Root $repository `
        -Arguments @('worktree', 'add', '--detach', $sourceRoot, $initialHead))
    $sourceState = New-PinnedDirectoryState `
        -Path $sourceRoot `
        -Label 'private detached source worktree'
    $sourceState | Add-Member `
        -NotePropertyName OwnerToken `
        -NotePropertyValue $sourceOwnerToken
    [System.IO.Directory]::CreateDirectory((Join-Path $sourceRoot 'target')) | Out-Null
    $sourceState | Add-Member `
        -NotePropertyName OwnerMarker `
        -NotePropertyValue (Join-Path $sourceRoot 'target/.serctl-candidate-owner')
    $sourceState | Add-Member -NotePropertyName OwnerManifestPath -NotePropertyValue $null
    $sourceState | Add-Member `
        -NotePropertyName OwnerManifestEvidence `
        -NotePropertyValue $null
    Write-NewUtf8File -Path $sourceState.OwnerMarker -Text $sourceOwnerToken
    [void](Invoke-CandidateGit `
        -Root $sourceRoot `
        -Arguments @('check-ignore', '-q', '--', 'target/.serctl-candidate-owner'))
    $worktreeSnapshot = Get-CleanGitSnapshot -Root $sourceRoot
    Assert-CandidateCondition (
        $worktreeSnapshot.Head -ceq $initialHead -and
        $worktreeSnapshot.Tree -ceq $initialTree
    ) 'detached build worktree does not match the approved HEAD and tree'
    Assert-OwnedDirectoryState -State $sourceState -ParentState $sourceParentState

    [System.Environment]::SetEnvironmentVariable(
        'CARGO_TARGET_DIR',
        $buildRoot,
        'Process'
    )
    [System.Environment]::SetEnvironmentVariable('RUSTC', $rustcPath, 'Process')
    [System.Environment]::SetEnvironmentVariable('RUSTDOC', $rustdocPath, 'Process')
    $buildArguments = @(
        'build',
        '--locked',
        '--release',
        '--manifest-path', (Join-Path $sourceRoot 'Cargo.toml'),
        '-p', 'serctl-cli',
        '-p', 'serctl-daemon',
        '-p', 'serctl-xfer'
    )
    $originalMonitors = @(
        New-TrackedSourceMonitors -Root $repository -TrackedPaths $trackedPaths
    )
    $worktreeMonitors = @(
        New-TrackedSourceMonitors -Root $sourceRoot -TrackedPaths $trackedPaths
    )
    Invoke-CargoBuild `
        -CargoPath $cargoPath `
        -Arguments $buildArguments `
        -WorkingDirectory $repository
    Start-Sleep -Milliseconds 100
    Assert-NoTrackedSourceChanges `
        -Monitors $originalMonitors `
        -Root $repository `
        -TrackedPaths $trackedPaths `
        -Label 'repository'
    Stop-CandidateChangeMonitors -Monitors $originalMonitors
    $originalMonitors = $null
    Assert-NoTrackedSourceChanges `
        -Monitors $worktreeMonitors `
        -Root $sourceRoot `
        -TrackedPaths $trackedPaths `
        -Label 'detached worktree'
    Stop-CandidateChangeMonitors -Monitors $worktreeMonitors
    $worktreeMonitors = $null
    Restore-CandidateEnvironmentVariable `
        -Name 'CARGO_TARGET_DIR' `
        -Value $previousCargoTarget
    $cargoEnvironmentRestored = $true
    Restore-CandidateEnvironmentVariable -Name 'RUSTC' -Value $previousRustc
    $rustcEnvironmentRestored = $true
    Restore-CandidateEnvironmentVariable -Name 'RUSTDOC' -Value $previousRustdoc
    $rustdocEnvironmentRestored = $true

    Assert-OwnedDirectoryState -State $buildState -ParentState $buildParentState
    Assert-OwnedDirectoryState -State $stageState -ParentState $stagingParentState
    $releaseDirectory = Join-Path $buildRoot 'release'
    Assert-PlainDirectory -Path $releaseDirectory -Label 'private Cargo release output'
    $extension = if ($hostIsWindows) { '.exe' } else { '' }
    $definitions = @(
        [pscustomobject]@{
            Component = 'serctl_cli'
            FileName = "serctl_cli$extension"
        },
        [pscustomobject]@{
            Component = 'serctl_daemon'
            FileName = "serctl_daemon$extension"
        },
        [pscustomobject]@{
            Component = 'serctl-xfer'
            FileName = "serctl-xfer$extension"
        }
    )

    $evidenceByComponent = [ordered]@{}
    foreach ($definition in $definitions) {
        $source = Join-Path $releaseDirectory $definition.FileName
        $stageDestination = Join-Path $stageRoot $definition.FileName
        Copy-NewFile -Source $source -Destination $stageDestination
        $chmodPath = if ($null -ne $chmodTool) { $chmodTool.Path } else { $null }
        $runtimeMode = Set-CandidateExecutableMode `
            -Path $stageDestination `
            -ChmodPath $chmodPath
        $evidence = Get-PinnedFileEvidence `
            -Path $stageDestination `
            -Component $definition.Component `
            -ExpectedVersion $Version `
            -ExpectedCommit $initialHead
        $evidence | Add-Member `
            -NotePropertyName RuntimeMode `
            -NotePropertyValue $runtimeMode
        $evidenceByComponent[$definition.Component] = $evidence
    }

    $postBuildSnapshot = Get-CleanGitSnapshot -Root $repository
    Assert-CandidateCondition (
        $postBuildSnapshot.Head -ceq $initialHead -and
        $postBuildSnapshot.Tree -ceq $initialTree
    ) (
        'repository HEAD or tree changed while building the candidate'
    )
    $postBuildWorktreeSnapshot = Get-CleanGitSnapshot -Root $sourceRoot
    Assert-CandidateCondition (
        $postBuildWorktreeSnapshot.Head -ceq $initialHead -and
        $postBuildWorktreeSnapshot.Tree -ceq $initialTree
    ) (
        'detached worktree HEAD or tree changed while building the candidate'
    )
    Assert-PlainDirectory -Path $candidatesRoot -Label 'candidate-set parent'
    Assert-CandidateCondition (-not (Test-Path -LiteralPath $candidatePath)) (
        "refusing to overwrite candidate set created during the build '$candidatePath'"
    )

    $artifacts = @()
    foreach ($definition in $definitions) {
        $stageDestination = Join-Path $stageRoot $definition.FileName
        $evidence = $evidenceByComponent[$definition.Component]
        $finalAbsolute = Join-Path $candidatePath $definition.FileName
        $relative = Get-RepositoryRelativePath `
            -Path $finalAbsolute `
            -Root $repository
        $artifacts += [ordered]@{
            component = $definition.Component
            file_name = $definition.FileName
            absolute_path = $finalAbsolute
            repository_relative_path = $relative
            file_identity = $evidence.Identity
            size_bytes = [long]$evidence.Size
            runtime_mode = $evidence.RuntimeMode
            sha256 = $evidence.Sha256
            version_line = $evidence.VersionLine
        }
    }

    $candidateRelative = Get-RepositoryRelativePath `
        -Path $candidatePath `
        -Root $repository
    $manifest = [ordered]@{
        schema_version = 1
        identity = $identity
        version = $Version
        head = $initialHead
        head_short = $initialHead.Substring(0, 12)
        tree = $initialTree
        source = [ordered]@{
            repository_absolute_path = $repository
            repository_relative_identity = '.'
            detached_worktree_absolute_path = $sourceRoot
            detached_worktree_root_identity = $sourceState.Identity
            detached_worktree_owner_token = $sourceOwnerToken
            clean_before_build = $true
            clean_after_build = $true
            tracked_change_monitor = 'original-and-detached-worktree'
        }
        candidate_set = [ordered]@{
            absolute_path = $candidatePath
            repository_relative_path = $candidateRelative
            root_identity = $stageState.Identity
            owner_token = $stageOwnerToken
        }
        build = [ordered]@{
            working_directory_absolute_path = $repository
            manifest_absolute_path = (Join-Path $sourceRoot 'Cargo.toml')
            cargo_executable_absolute_path = $cargoPath
            cargo_executable_file_identity = $cargoTool.FileIdentity
            cargo_executable_size_bytes = [long]$cargoTool.Size
            cargo_executable_sha256 = $cargoTool.Sha256
            cargo_version_line = $cargoVersion
            rustc_executable_absolute_path = $rustcPath
            rustc_executable_file_identity = $rustcTool.FileIdentity
            rustc_executable_size_bytes = [long]$rustcTool.Size
            rustc_executable_sha256 = $rustcTool.Sha256
            rustc_version_verbose = $rustcVersion
            rustdoc_executable_absolute_path = $rustdocPath
            rustdoc_executable_file_identity = $rustdocTool.FileIdentity
            rustdoc_executable_size_bytes = [long]$rustdocTool.Size
            rustdoc_executable_sha256 = $rustdocTool.Sha256
            rustdoc_version_verbose = $rustdocVersion
            toolchain_channel = $toolchainChannel
            toolchain_host = $rustcIdentity.Host
            toolchain_manifest_absolute_path = $toolchainManifestPath
            toolchain_manifest_file_identity = $toolchainManifest.Identity
            toolchain_manifest_size_bytes = [long]$toolchainManifest.Size
            toolchain_manifest_sha256 = $toolchainManifest.Sha256
            linker_binding = 'ambient-unbound'
            cargo_arguments = $buildArguments
            cargo_target_separate_from_candidate_set = $true
        }
        tools = [ordered]@{
            git = [ordered]@{
                absolute_path = $gitTool.Path
                file_identity = $gitTool.FileIdentity
                size_bytes = [long]$gitTool.Size
                sha256 = $gitTool.Sha256
                version_line = $gitVersion
            }
            cargo = [ordered]@{
                absolute_path = $cargoTool.Path
                file_identity = $cargoTool.FileIdentity
                size_bytes = [long]$cargoTool.Size
                sha256 = $cargoTool.Sha256
                version_line = $cargoVersion
            }
            rustc = [ordered]@{
                absolute_path = $rustcTool.Path
                file_identity = $rustcTool.FileIdentity
                size_bytes = [long]$rustcTool.Size
                sha256 = $rustcTool.Sha256
                version_line = $rustcVersion
            }
            rustdoc = [ordered]@{
                absolute_path = $rustdocTool.Path
                file_identity = $rustdocTool.FileIdentity
                size_bytes = [long]$rustdocTool.Size
                sha256 = $rustdocTool.Sha256
                version_line = $rustdocVersion
            }
            chmod = if ($null -eq $chmodTool) {
                $null
            }
            else {
                [ordered]@{
                    absolute_path = $chmodTool.Path
                    file_identity = $chmodTool.FileIdentity
                    size_bytes = [long]$chmodTool.Size
                    sha256 = $chmodTool.Sha256
                    version_line = $chmodVersion
                }
            }
        }
        contracts = [ordered]@{
            ipc = $ipcContract
            transfer = $transferContract
            vault_storage = $vaultContract
        }
        artifacts = $artifacts
    }
    $manifestPath = Join-Path $stageRoot 'candidate-manifest.json'
    $manifestText = ($manifest | ConvertTo-Json -Depth 8) + "`n"
    Write-NewUtf8File `
        -Path $manifestPath `
        -Text $manifestText
    $manifestEvidence = Get-PinnedRegularFileDigest -Path $manifestPath

    if ($SelfTestMutation -cne 'none') {
        $selfTestRoot = [System.IO.Path]::GetFullPath((
            Join-Path $PSScriptRoot '../target/ic-selftests'
        )).TrimEnd(
            [System.IO.Path]::DirectorySeparatorChar,
            [System.IO.Path]::AltDirectorySeparatorChar
        ) + [System.IO.Path]::DirectorySeparatorChar
        Assert-CandidateCondition (
            [System.Environment]::GetEnvironmentVariable(
                'SERCTL_ISOLATED_CANDIDATE_SELFTEST',
                'Process'
            ) -ceq '1' -and
            $repository.StartsWith($selfTestRoot, $pathComparison)
        ) 'self-test mutation is forbidden outside a dedicated fixture repository'
        if ($SelfTestMutation -ceq 'replace-stage-artifact') {
            $mutationPath = Join-Path $stageRoot $definitions[0].FileName
            [System.IO.File]::Delete($mutationPath)
            Write-NewUtf8File -Path $mutationPath -Text 'replacement'
        }
    }

    $prePublishSnapshot = Get-CleanGitSnapshot -Root $repository
    Assert-CandidateCondition (
        $prePublishSnapshot.Head -ceq $initialHead -and
        $prePublishSnapshot.Tree -ceq $initialTree
    ) (
        'repository HEAD or tree changed before atomic candidate publication'
    )
    $prePublishWorktreeSnapshot = Get-CleanGitSnapshot -Root $sourceRoot
    Assert-CandidateCondition (
        $prePublishWorktreeSnapshot.Head -ceq $initialHead -and
        $prePublishWorktreeSnapshot.Tree -ceq $initialTree
    ) (
        'detached worktree HEAD or tree changed before candidate publication'
    )
    Assert-PlainDirectory -Path $candidatesRoot -Label 'candidate-set parent'
    Assert-CandidateCondition (-not (Test-Path -LiteralPath $candidatePath)) (
        "refusing to overwrite candidate set created before publication '$candidatePath'"
    )
    foreach ($state in @(
        $targetState,
        $candidatesState,
        $buildParentState,
        $stagingParentState,
        $sourceParentState
    )) {
        Assert-PinnedDirectoryState -State $state
    }
    Assert-OwnedDirectoryState -State $stageState -ParentState $stagingParentState
    foreach ($definition in $definitions) {
        Assert-ArtifactEvidenceUnchanged `
            -Path (Join-Path $stageRoot $definition.FileName) `
            -Component $definition.Component `
            -Expected $evidenceByComponent[$definition.Component]
    }
    Assert-RegularFileDigestUnchanged `
        -Path $manifestPath `
        -Expected $manifestEvidence `
        -Label 'candidate manifest'
    Assert-RegularFileDigestUnchanged `
        -Path $gitTool.Path `
        -Expected $gitTool `
        -Label 'git Application'
    Assert-RegularFileDigestUnchanged `
        -Path $cargoTool.Path `
        -Expected $cargoTool `
        -Label 'cargo Application'
    Assert-RegularFileDigestUnchanged `
        -Path $rustcTool.Path `
        -Expected $rustcTool `
        -Label 'rustc Application'
    Assert-RegularFileDigestUnchanged `
        -Path $rustdocTool.Path `
        -Expected $rustdocTool `
        -Label 'rustdoc Application'
    Assert-RegularFileDigestUnchanged `
        -Path $toolchainManifestPath `
        -Expected $toolchainManifest `
        -Label 'rust-toolchain.toml'
    if ($null -ne $chmodTool) {
        Assert-RegularFileDigestUnchanged `
            -Path $chmodTool.Path `
            -Expected $chmodTool `
            -Label 'chmod Application'
    }

    Remove-OwnedDetachedWorktree `
        -State $sourceState `
        -ParentState $sourceParentState `
        -Repository $repository
    $sourceCleaned = $true
    $sourceState = $null

    Remove-OwnedPrivateDirectory `
        -State $buildState `
        -ParentState $buildParentState `
        -LeafPrefix 'candidate-build-'
    $buildCleaned = $true
    $buildState = $null

    $postCleanupSnapshot = Get-CleanGitSnapshot -Root $repository
    Assert-CandidateCondition (
        $postCleanupSnapshot.Head -ceq $initialHead -and
        $postCleanupSnapshot.Tree -ceq $initialTree
    ) 'repository HEAD or tree changed during private cleanup'

    Assert-OwnedDirectoryState -State $stageState -ParentState $stagingParentState
    foreach ($definition in $definitions) {
        Assert-ArtifactEvidenceUnchanged `
            -Path (Join-Path $stageRoot $definition.FileName) `
            -Component $definition.Component `
            -Expected $evidenceByComponent[$definition.Component]
    }
    Assert-RegularFileDigestUnchanged `
        -Path $manifestPath `
        -Expected $manifestEvidence `
        -Label 'candidate manifest'
    Assert-TreeContainsNoReparsePoints -Root $stageRoot
    $stageEntries = @([System.IO.Directory]::EnumerateFileSystemEntries($stageRoot))
    Assert-CandidateCondition ($stageEntries.Count -eq 5) (
        'candidate staging set contains unexpected entries before publication'
    )
    [System.IO.File]::Delete($stageState.OwnerMarker)
    Assert-CandidateCondition (-not (Test-Path -LiteralPath $stageState.OwnerMarker)) (
        'candidate staging owner marker removal did not complete'
    )
    $stageState.OwnerMarker = $null
    $stageState.OwnerManifestPath = $manifestPath
    $stageState.OwnerManifestEvidence = $manifestEvidence
    Assert-OwnedDirectoryState -State $stageState -ParentState $stagingParentState
    Assert-PinnedDirectoryState -State $stageState
    Assert-PinnedDirectoryState -State $stagingParentState
    Assert-PinnedDirectoryState -State $candidatesState
    Assert-CandidateCondition (-not (Test-Path -LiteralPath $candidatePath)) (
        "refusing to overwrite candidate set created at final move '$candidatePath'"
    )
    $stageState.Handle.Dispose()
    try {
        [System.IO.Directory]::Move($stageRoot, $candidatePath)
    }
    catch {
        if ([System.IO.Directory]::Exists($stageRoot)) {
            $replacement = New-PinnedDirectoryState `
                -Path $stageRoot `
                -Label $stageState.Label
            if ($replacement.Identity -ceq $stageState.Identity) {
                $stageState.Handle = $replacement.Handle
            }
            else {
                $replacement.Handle.Dispose()
            }
        }
        else {
            $stageState = $null
        }
        throw
    }
    $published = $true
    $stageState = $null

    Write-Host "Created isolated candidate '$candidatePath'."
    Write-Host "Manifest: '$(Join-Path $candidatePath 'candidate-manifest.json')'."
}
finally {
    Stop-CandidateChangeMonitors -Monitors $originalMonitors
    Stop-CandidateChangeMonitors -Monitors $worktreeMonitors
    if (-not $cargoEnvironmentRestored) {
        Restore-CandidateEnvironmentVariable `
            -Name 'CARGO_TARGET_DIR' `
            -Value $previousCargoTarget
    }
    if (-not $rustcEnvironmentRestored) {
        Restore-CandidateEnvironmentVariable -Name 'RUSTC' -Value $previousRustc
    }
    if (-not $rustdocEnvironmentRestored) {
        Restore-CandidateEnvironmentVariable -Name 'RUSTDOC' -Value $previousRustdoc
    }
    if (-not $sourceCleaned) {
        Remove-OwnedDetachedWorktree `
            -State $sourceState `
            -ParentState $sourceParentState `
            -Repository $repository
    }
    if (-not $published) {
        Remove-OwnedPrivateDirectory `
            -State $stageState `
            -ParentState $stagingParentState `
            -LeafPrefix 'candidate-stage-'
    }
    if (-not $buildCleaned) {
        Remove-OwnedPrivateDirectory `
            -State $buildState `
            -ParentState $buildParentState `
            -LeafPrefix 'candidate-build-'
    }
    foreach ($state in @(
        $stageState,
        $buildState,
        $sourceState,
        $sourceParentState,
        $stagingParentState,
        $buildParentState,
        $candidatesState,
        $targetState
    )) {
        if ($null -ne $state -and -not $state.Handle.IsClosed) {
            $state.Handle.Dispose()
        }
    }
}
