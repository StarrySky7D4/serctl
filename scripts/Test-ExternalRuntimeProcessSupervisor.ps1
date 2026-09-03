[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-SupervisorTest {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if (-not $Condition) {
        throw "external runtime process supervisor self-test failed: $Message"
    }
}

function Invoke-SupervisorExpectedFailure {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Action,
        [Parameter(Mandatory = $true)][string]$Message
    )
    $failed = $false
    try {
        & $Action *> $null
    }
    catch {
        $failed = $true
    }
    Assert-SupervisorTest $failed $Message
}

function Get-TestSha256 {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

$supervisorScript = Join-Path $PSScriptRoot 'ExternalRuntimeProcessSupervisor.ps1'
Assert-SupervisorTest (
    Test-Path -LiteralPath $supervisorScript -PathType Leaf
) 'supervisor script is missing'
. $supervisorScript

function Assert-SupervisorStaticContract {
    $supervisorSource = [System.IO.File]::ReadAllText($supervisorScript)
    $formalReceiptContractPath = Join-Path `
        $PSScriptRoot `
        'ExternalTransferRuntimeReceiptContract.ps1'
    Assert-SupervisorTest (
        Test-Path -LiteralPath $formalReceiptContractPath -PathType Leaf
    ) 'formal receipt contract fixture is missing'
    $formalReceiptContractSource = [System.IO.File]::ReadAllText(
        $formalReceiptContractPath
    )
    Assert-SupervisorTest (
        -not $formalReceiptContractSource.Contains(
            'Invoke-ExternalRuntimeProcessCaptureInternal'
        )
    ) 'internal capture function was exported through the formal receipt contract'
    Assert-SupervisorTest ($supervisorSource.Contains('posix_spawn(')) (
        'Unix launcher does not use posix_spawn'
    )
    Assert-SupervisorTest ($supervisorSource.Contains('POSIX_SPAWN_SETPGROUP')) (
        'Unix launcher does not atomically request a process group'
    )
    Assert-SupervisorTest (
        $supervisorSource.Contains('posix_spawn_file_actions_addclosefrom_np')
    ) 'Linux launcher does not close all unlisted inherited descriptors'
    foreach ($mapping in @(
        @('grant_input', 4),
        @('profile_passphrase_input', 5),
        @('grant_output', 6),
        @('receipt_output', 7)
    )) {
        Assert-SupervisorTest (
            (Get-ExternalRuntimeInheritedChildFdInternal -Purpose $mapping[0]) -eq
                [int]$mapping[1]
        ) "internal purpose mapping drifted for '$($mapping[0])'"
    }
    Invoke-SupervisorExpectedFailure `
        -Message 'caller selected an unknown inherited child-fd purpose' `
        -Action {
            Get-ExternalRuntimeInheritedChildFdInternal -Purpose 'caller_selected_fd_9'
        }
    foreach ($linuxHandleBoundary in @(
        'statx(fd, "", AT_EMPTY_PATH_LINUX | AT_STATX_DONT_SYNC_LINUX',
        'mode != S_IFREG_LINUX && mode != S_IFIFO_LINUX',
        'F_DUPFD_CLOEXEC_LINUX',
        'inheritedCopies[i], childFd',
        'for (int childFd = 4; childFd <= 7; childFd++)',
        'posix_spawn_file_actions_addclosefrom_np(actions, 8)',
        'inheritedHandlePurposes.Length != allowedInheritedHandles.Length'
    )) {
        Assert-SupervisorTest ($supervisorSource.Contains($linuxHandleBoundary)) (
            "Linux inherited-handle boundary is missing '$linuxHandleBoundary'"
        )
    }
    Assert-SupervisorTest (
        -not $supervisorSource.Contains(
            'explicit Unix handle inheritance is not implemented'
        )
    ) 'Linux inherited-handle implementation remains hard-disabled'
    Assert-SupervisorTest ($supervisorSource.Contains('"/proc/self/fd/3"')) (
        'Linux launcher does not execute the already-pinned file descriptor'
    )
    Assert-SupervisorTest (
        $supervisorSource.Contains('posix_spawn_file_actions_addchdir_np')
    ) 'Linux launcher does not atomically set its bounded working directory'
    Assert-SupervisorTest (
        $supervisorSource.Contains(
            'posix_spawn_file_actions_adddup2(actions, stdinPipe[0], 0)'
        )
    ) 'Linux launcher does not replace inherited stdin with a bounded EOF pipe'
    Assert-SupervisorTest (-not $supervisorSource.Contains('setpgid(')) (
        'Unix launcher retained the post-start setpgid race'
    )
    Assert-SupervisorTest (-not $supervisorSource.Contains('Process.Start(psi)')) (
        'Unix launcher retained the Process.Start race'
    )
    Assert-SupervisorTest (
        $supervisorSource.Contains('atomic Unix launcher unavailable on this platform')
    ) 'non-Linux Unix platforms do not explicitly fail closed'
}

Assert-SupervisorStaticContract
$hostIsWindows = [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
    [Runtime.InteropServices.OSPlatform]::Windows
)
if (-not $hostIsWindows) {
    Write-Host (
        'External runtime process supervisor static contract self-test passed; ' +
        'Windows runtime fixture skipped on non-Windows host.'
    )
    return
}

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$fixtureRoot = Join-Path `
    (Join-Path $repositoryRoot 'target') `
    ('external-runtime-supervisor-selftest-' + [Guid]::NewGuid().ToString('N'))
[System.IO.Directory]::CreateDirectory($fixtureRoot) | Out-Null
$ownerToken = [Guid]::NewGuid().ToString('N')
$ownerPath = Join-Path $fixtureRoot '.owner'
[System.IO.File]::WriteAllText($ownerPath, $ownerToken, [System.Text.UTF8Encoding]::new($false))

try {
    $helperPath = Join-Path $fixtureRoot 'supervisor-fixture.exe'
    $helperSource = @'
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

public static class SupervisorFixture {
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadFile(IntPtr handle, byte[] buffer, uint count,
        out uint read, IntPtr overlapped);

    public static int Main(string[] args) {
        if (args.Length == 0) return 90;
        switch (args[0]) {
            case "success":
                Console.OpenStandardOutput().Write(new byte[] { 111, 107 }, 0, 2);
                return 0;
            case "nonzero":
                Console.OpenStandardOutput().Write(new byte[] { 112, 97, 114, 116, 105, 97, 108 }, 0, 7);
                Console.OpenStandardError().Write(new byte[] { 102, 97, 105, 108, 101, 100 }, 0, 6);
                return 7;
            case "hang":
                Thread.Sleep(Int32.Parse(args[1]));
                return 0;
            case "flood-stdout":
                return Flood(Console.OpenStandardOutput());
            case "flood-stderr":
                return Flood(Console.OpenStandardError());
            case "environment":
                string safe = Environment.GetEnvironmentVariable("LC_ALL") ?? "missing";
                string canary = Environment.GetEnvironmentVariable("SERCTL_ENV_CANARY") == null
                    ? "missing" : "leaked";
                Console.Write("safe=" + safe + ";canary=" + canary);
                return 0;
            case "stdin-eof":
                Console.Write(Console.OpenStandardInput().ReadByte() == -1 ? "eof" : "leaked");
                return 0;
            case "stdin-json":
                byte[] json = ReadStdin();
                string jsonText = new UTF8Encoding(false, true).GetString(json);
                bool validJsonLine = jsonText.EndsWith("\n") &&
                    jsonText.IndexOf("\r", StringComparison.Ordinal) < 0 &&
                    jsonText.IndexOf("\"op\":\"status\"", StringComparison.Ordinal) >= 0;
                Array.Clear(json, 0, json.Length);
                Console.Write(validJsonLine ? "{\"ok\":true}\n" : "{\"ok\":false}\n");
                return validJsonLine ? 0 : 92;
            case "stdin-ignore":
                return 0;
            case "probe-handle":
                byte[] probe = new byte[1];
                uint read;
                bool opened = ReadFile(new IntPtr(Int64.Parse(args[1])), probe, 1,
                    out read, IntPtr.Zero) && read == 1 && probe[0] == 42;
                Console.Write(opened ? "open" : "closed");
                return 0;
            case "tree":
                ProcessStartInfo child = new ProcessStartInfo();
                child.FileName = Process.GetCurrentProcess().MainModule.FileName;
                child.Arguments = "child";
                child.UseShellExecute = false;
                Process process = Process.Start(child);
                File.WriteAllText(args[1], process.Id.ToString());
                Thread.Sleep(10000);
                return 0;
            case "child":
                Thread.Sleep(10000);
                return 0;
            case "replace":
                Thread.Sleep(80);
                try {
                    File.Copy(args[2], args[1], true);
                    File.WriteAllText(args[3], "replaced");
                } catch {
                    File.WriteAllText(args[3], "blocked");
                }
                return 0;
            default:
                return 91;
        }
    }

    private static int Flood(Stream stream) {
        byte[] bytes = new byte[8192];
        for (int i = 0; i < bytes.Length; i++) bytes[i] = 120;
        for (int i = 0; i < 1024; i++) stream.Write(bytes, 0, bytes.Length);
        stream.Flush();
        return 0;
    }

    private static byte[] ReadStdin() {
        using (MemoryStream output = new MemoryStream()) {
            Stream input = Console.OpenStandardInput();
            byte[] chunk = new byte[4096];
            while (true) {
                int count = input.Read(chunk, 0, chunk.Length);
                if (count == 0) break;
                output.Write(chunk, 0, count);
            }
            Array.Clear(chunk, 0, chunk.Length);
            return output.ToArray();
        }
    }
}
'@
    $helperSourcePath = Join-Path $fixtureRoot 'supervisor-fixture.cs'
    [System.IO.File]::WriteAllText(
        $helperSourcePath,
        $helperSource,
        [System.Text.UTF8Encoding]::new($false)
    )
    $compilerPath = 'C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    Assert-SupervisorTest (Test-Path -LiteralPath $compilerPath -PathType Leaf) (
        'fixed synthetic helper compiler is unavailable'
    )
    & $compilerPath `
        '/nologo' `
        '/target:exe' `
        ('/out:' + $helperPath) `
        $helperSourcePath
    Assert-SupervisorTest ($LASTEXITCODE -eq 0) 'synthetic helper compilation failed'
    Assert-SupervisorTest (Test-Path -LiteralPath $helperPath -PathType Leaf) (
        'synthetic helper did not compile'
    )

    $receipt = Invoke-ExternalRuntimeProcess `
        -ApplicationPath $helperPath `
        -ArgumentList @('success') `
        -DeadlineMilliseconds 2000 `
        -StdoutLimitBytes 64 `
        -StderrLimitBytes 64
    Assert-SupervisorTest ($receipt.exit_category -eq 'completed_success') (
        'success was not classified as completed_success'
    )
    Assert-SupervisorTest ($receipt.stdout_bytes -eq 2) 'success stdout length drifted'
    $okHash = Get-TestSha256 -Bytes ([byte[]](111, 107))
    Assert-SupervisorTest ($receipt.stdout_sha256 -eq $okHash) 'success stdout hash drifted'
    Assert-SupervisorTest $receipt.process_tree_exited 'success tree exit was not proven'
    $stdinReceipt = Invoke-ExternalRuntimeProcess `
        -ApplicationPath $helperPath `
        -ArgumentList @('stdin-eof') `
        -DeadlineMilliseconds 2000 `
        -StdoutLimitBytes 64 `
        -StderrLimitBytes 64
    Assert-SupervisorTest (
        $stdinReceipt.stdout_sha256 -eq (
            Get-TestSha256 -Bytes ([System.Text.Encoding]::UTF8.GetBytes('eof'))
        )
    ) 'child standard input was not an explicit EOF stream'

    $jsonInput = [System.Text.UTF8Encoding]::new($false).GetBytes(
        '{"op":"status","value":1}' + "`n"
    )
    $jsonCapture = Invoke-ExternalRuntimeProcessCaptureInternal `
        -ApplicationPath $helperPath `
        -ArgumentList @('stdin-json') `
        -StandardInputBytes $jsonInput `
        -StdinLimitBytes 4096 `
        -DeadlineMilliseconds 2000 `
        -StdoutLimitBytes 4096 `
        -StderrLimitBytes 4096
    try {
        Assert-SupervisorTest ($jsonCapture.exit_category -eq 'completed_success') (
            'internal capture did not accept bounded JSONL stdin'
        )
        Assert-SupervisorTest (
            [System.Text.UTF8Encoding]::new($false, $true).GetString($jsonCapture.stdout) -ceq
                "{`"ok`":true}`n"
        ) 'internal capture did not return the exact bounded JSONL terminal'
        Assert-SupervisorTest (
            @($jsonCapture.PSObject.Properties.Name | Sort-Object) -join ',' -ceq
                'deadline_ms,elapsed_ms,exit_category,exit_code,process_tree_exited,schema_version,stderr,stdout'
        ) 'internal capture surface contains an unexpected formal-contract field'
    }
    finally {
        [Array]::Clear($jsonCapture.stdout, 0, $jsonCapture.stdout.Length)
        [Array]::Clear($jsonCapture.stderr, 0, $jsonCapture.stderr.Length)
    }
    Assert-SupervisorTest (
        @($jsonInput | Where-Object { $_ -ne 0 }).Count -eq 0
    ) 'accepted standard-input bytes were not zeroized after the writer closed'

    $oversizedInput = [byte[]]::new(65)
    for ($index = 0; $index -lt $oversizedInput.Length; $index++) {
        $oversizedInput[$index] = 65
    }
    Invoke-SupervisorExpectedFailure `
        -Message 'standard input beyond its strict bound was accepted' `
        -Action {
            Invoke-ExternalRuntimeProcessCaptureInternal `
                -ApplicationPath $helperPath `
                -ArgumentList @('stdin-json') `
                -StandardInputBytes $oversizedInput `
                -StdinLimitBytes 64
        }
    Assert-SupervisorTest (
        @($oversizedInput | Where-Object { $_ -ne 0 }).Count -eq 0
    ) 'rejected oversized standard input was not zeroized'

    $ignoredInput = [byte[]]::new(1048576)
    for ($index = 0; $index -lt $ignoredInput.Length; $index++) {
        $ignoredInput[$index] = 73
    }
    $ignoredCapture = Invoke-ExternalRuntimeProcessCaptureInternal `
        -ApplicationPath $helperPath `
        -ArgumentList @('stdin-ignore') `
        -StandardInputBytes $ignoredInput `
        -DeadlineMilliseconds 2000 `
        -StdoutLimitBytes 64 `
        -StderrLimitBytes 64
    try {
        Assert-SupervisorTest (
            @('completed_success', 'stdin_write') -contains $ignoredCapture.exit_category
        ) 'child that ignored stdin produced a noncanonical terminal category'
        Assert-SupervisorTest ($ignoredCapture.elapsed_ms -lt 3000) (
            'child that ignored stdin blocked the supervisor'
        )
        Assert-SupervisorTest $ignoredCapture.process_tree_exited (
            'child that ignored stdin left a process tree'
        )
    }
    finally {
        [Array]::Clear($ignoredCapture.stdout, 0, $ignoredCapture.stdout.Length)
        [Array]::Clear($ignoredCapture.stderr, 0, $ignoredCapture.stderr.Length)
    }
    Assert-SupervisorTest (
        @($ignoredInput | Where-Object { $_ -ne 0 }).Count -eq 0
    ) 'ignored standard input was not zeroized'
    $expectedReceiptFields = @(
        'deadline_ms', 'elapsed_ms', 'exit_category', 'exit_code',
        'process_tree_exited', 'schema_version', 'stderr_bytes', 'stderr_sha256',
        'stdout_bytes', 'stdout_sha256', 'terminal_sha256'
    )
    $actualReceiptFields = @($receipt.PSObject.Properties.Name | Sort-Object)
    Assert-SupervisorTest (
        (@(Compare-Object $expectedReceiptFields $actualReceiptFields).Count -eq 0)
    ) 'receipt leaked argv, path, output, or another unapproved field'

    $previousEnvironmentCanary = [Environment]::GetEnvironmentVariable('SERCTL_ENV_CANARY')
    [Environment]::SetEnvironmentVariable('SERCTL_ENV_CANARY', 'parent-environment-canary')
    try {
        $emptyEnvironment = Invoke-ExternalRuntimeProcess `
            -ApplicationPath $helperPath `
            -ArgumentList @('environment') `
            -DeadlineMilliseconds 2000 `
            -StdoutLimitBytes 64 `
            -StderrLimitBytes 64
        $emptyEnvironmentText = [System.Text.Encoding]::UTF8.GetBytes(
            'safe=missing;canary=missing'
        )
        Assert-SupervisorTest (
            $emptyEnvironment.stdout_sha256 -eq (Get-TestSha256 -Bytes $emptyEnvironmentText)
        ) 'parent environment canary leaked into the child'

        $restrictedEnvironment = Invoke-ExternalRuntimeProcess `
            -ApplicationPath $helperPath `
            -ArgumentList @('environment') `
            -EnvironmentVariables @{ LC_ALL = 'C' } `
            -DeadlineMilliseconds 2000 `
            -StdoutLimitBytes 64 `
            -StderrLimitBytes 64
        $restrictedEnvironmentText = [System.Text.Encoding]::UTF8.GetBytes(
            'safe=C;canary=missing'
        )
        Assert-SupervisorTest (
            $restrictedEnvironment.stdout_sha256 -eq (
                Get-TestSha256 -Bytes $restrictedEnvironmentText
            )
        ) 'restricted non-secret environment did not pass exactly'
    }
    finally {
        [Environment]::SetEnvironmentVariable(
            'SERCTL_ENV_CANARY',
            $previousEnvironmentCanary
        )
    }
    Invoke-SupervisorExpectedFailure `
        -Message 'caller-created environment variable name was accepted' `
        -Action {
            Invoke-ExternalRuntimeProcess `
                -ApplicationPath $helperPath `
                -ArgumentList @('success') `
                -EnvironmentVariables @{ SAFE_FIXTURE = 'value' }
        }
    Invoke-SupervisorExpectedFailure `
        -Message 'secret environment variable name was accepted' `
        -Action {
            Invoke-ExternalRuntimeProcess `
                -ApplicationPath $helperPath `
                -ArgumentList @('success') `
                -EnvironmentVariables @{ TOKEN = 'not-a-real-token' }
        }

    if ($env:OS -eq 'Windows_NT') {
        if (-not ('Serctl.SupervisorSelfTest.Native' -as [type])) {
            Add-Type -TypeDefinition @'
using System;
using Microsoft.Win32.SafeHandles;
using System.Runtime.InteropServices;
namespace Serctl.SupervisorSelfTest {
    public static class Native {
        [StructLayout(LayoutKind.Sequential)]
        private struct SECURITY_ATTRIBUTES {
            public int Length;
            public IntPtr SecurityDescriptor;
            public bool InheritHandle;
        }
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetHandleInformation(IntPtr handle, uint mask, uint flags);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateEvent(IntPtr attributes, bool manualReset,
            bool initialState, string name);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern IntPtr CreateFile(string path, uint access, uint share,
            ref SECURITY_ATTRIBUTES attributes, uint creation, uint flags, IntPtr template);
        public static void MakeInheritable(IntPtr handle) {
            if (!SetHandleInformation(handle, 1, 1))
                throw new InvalidOperationException("test handle inheritance setup failed");
        }
        public static SafeWaitHandle CreateInheritableEvent() {
            IntPtr handle = CreateEvent(IntPtr.Zero, true, false, null);
            if (handle == IntPtr.Zero) throw new InvalidOperationException("event creation failed");
            MakeInheritable(handle);
            return new SafeWaitHandle(handle, true);
        }
        public static SafeFileHandle OpenInheritableDirectory(string path) {
            SECURITY_ATTRIBUTES attributes = new SECURITY_ATTRIBUTES();
            attributes.Length = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
            attributes.InheritHandle = true;
            IntPtr handle = CreateFile(path, 0x80000000, 7, ref attributes, 3,
                0x02000000, IntPtr.Zero);
            if (handle == new IntPtr(-1))
                throw new InvalidOperationException("directory handle creation failed");
            return new SafeFileHandle(handle, true);
        }
    }
}
'@
        }
        $handleProbePath = Join-Path $fixtureRoot 'handle-probe.bin'
        [System.IO.File]::WriteAllBytes($handleProbePath, [byte[]](42))
        $handleProbe = [System.IO.File]::Open(
            $handleProbePath,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::Read
        )
        try {
            [Serctl.SupervisorSelfTest.Native]::MakeInheritable(
                $handleProbe.SafeFileHandle.DangerousGetHandle()
            )
            $handleValue = $handleProbe.SafeFileHandle.DangerousGetHandle().ToInt64().ToString()
            $notAllowed = Invoke-ExternalRuntimeProcess `
                -ApplicationPath $helperPath `
                -ArgumentList @('probe-handle', $handleValue) `
                -DeadlineMilliseconds 2000 `
                -StdoutLimitBytes 64 `
                -StderrLimitBytes 64
            $closedHash = Get-TestSha256 -Bytes (
                [System.Text.Encoding]::UTF8.GetBytes('closed')
            )
            Assert-SupervisorTest ($notAllowed.stdout_sha256 -eq $closedHash) (
                'extra inheritable handle leaked outside the exact handle list'
            )

            $handleAndStdinInput = [byte[]](104, 105)
            $allowed = Invoke-ExternalRuntimeProcess `
                -ApplicationPath $helperPath `
                -ArgumentList @('probe-handle', $handleValue) `
                -InheritedHandleByPurpose @{ grant_input = $handleProbe.SafeFileHandle } `
                -StandardInputBytes $handleAndStdinInput `
                -DeadlineMilliseconds 2000 `
                -StdoutLimitBytes 64 `
                -StderrLimitBytes 64
            $openHash = Get-TestSha256 -Bytes (
                [System.Text.Encoding]::UTF8.GetBytes('open')
            )
            Assert-SupervisorTest ($allowed.stdout_sha256 -eq $openHash) (
                'explicit purpose-bound inherited handle was unavailable'
            )
            Assert-SupervisorTest (
                @($handleAndStdinInput | Where-Object { $_ -ne 0 }).Count -eq 0
            ) 'purpose-bound handle mapping conflicted with or retained stdin bytes'

            Invoke-SupervisorExpectedFailure `
                -Message 'duplicate inherited source handle was accepted' `
                -Action {
                    Invoke-ExternalRuntimeProcess `
                        -ApplicationPath $helperPath `
                        -ArgumentList @('success') `
                        -InheritedHandleByPurpose @{
                            grant_input = $handleProbe.SafeFileHandle
                            profile_passphrase_input = $handleProbe.SafeFileHandle
                        }
                }
        }
        finally {
            $handleProbe.Dispose()
        }

        $eventHandle = [Serctl.SupervisorSelfTest.Native]::CreateInheritableEvent()
        try {
            Invoke-SupervisorExpectedFailure `
                -Message 'process-like wait handle was accepted for inheritance' `
                -Action {
                    Invoke-ExternalRuntimeProcess `
                        -ApplicationPath $helperPath `
                        -ArgumentList @('success') `
                        -InheritedHandleByPurpose @{ grant_input = $eventHandle }
                }
        }
        finally {
            $eventHandle.Dispose()
        }

        $directoryHandle = [Serctl.SupervisorSelfTest.Native]::OpenInheritableDirectory(
            $fixtureRoot
        )
        try {
            Invoke-SupervisorExpectedFailure `
                -Message 'directory handle was accepted for inheritance' `
                -Action {
                    Invoke-ExternalRuntimeProcess `
                        -ApplicationPath $helperPath `
                        -ArgumentList @('success') `
                        -InheritedHandleByPurpose @{ grant_input = $directoryHandle }
                }
        }
        finally {
            $directoryHandle.Dispose()
        }
    }

    $nonzero = Invoke-ExternalRuntimeProcess `
        -ApplicationPath $helperPath `
        -ArgumentList @('nonzero') `
        -DeadlineMilliseconds 2000 `
        -StdoutLimitBytes 64 `
        -StderrLimitBytes 64
    Assert-SupervisorTest ($nonzero.exit_category -eq 'completed_nonzero') (
        'nonzero exit was not classified as completed_nonzero'
    )
    Assert-SupervisorTest ($nonzero.exit_code -eq 7) 'nonzero exit code was not retained'
    Assert-SupervisorTest ($nonzero.stdout_bytes -eq 7 -and $nonzero.stderr_bytes -eq 6) (
        'nonzero stream accounting drifted'
    )

    $deadlineInput = [byte[]]::new(1048576)
    for ($index = 0; $index -lt $deadlineInput.Length; $index++) {
        $deadlineInput[$index] = 68
    }
    $deadline = Invoke-ExternalRuntimeProcess `
        -ApplicationPath $helperPath `
        -ArgumentList @('hang', '10000') `
        -StandardInputBytes $deadlineInput `
        -DeadlineMilliseconds 120 `
        -StdoutLimitBytes 64 `
        -StderrLimitBytes 64
    Assert-SupervisorTest ($deadline.exit_category -eq 'deadline') (
        'hung process was not classified as deadline'
    )
    Assert-SupervisorTest ($deadline.elapsed_ms -lt 3000) 'deadline termination was not bounded'
    Assert-SupervisorTest $deadline.process_tree_exited 'deadline tree exit was not proven'
    Assert-SupervisorTest (
        @($deadlineInput | Where-Object { $_ -ne 0 }).Count -eq 0
    ) 'deadline did not zeroize pending stdin bytes'

    $floodInput = [byte[]](106, 115, 111, 110, 108, 10)
    $stdoutFlood = Invoke-ExternalRuntimeProcess `
        -ApplicationPath $helperPath `
        -ArgumentList @('flood-stdout') `
        -StandardInputBytes $floodInput `
        -DeadlineMilliseconds 3000 `
        -StdoutLimitBytes 4096 `
        -StderrLimitBytes 4096
    Assert-SupervisorTest ($stdoutFlood.exit_category -eq 'stdout_limit') (
        'stdout flood did not terminate at its hard limit'
    )
    Assert-SupervisorTest ($stdoutFlood.stdout_bytes -eq 4096) (
        'stdout flood retained bytes beyond or below its hard limit'
    )
    Assert-SupervisorTest (
        @($floodInput | Where-Object { $_ -ne 0 }).Count -eq 0
    ) 'stdout flood did not zeroize stdin bytes'

    $stderrFlood = Invoke-ExternalRuntimeProcess `
        -ApplicationPath $helperPath `
        -ArgumentList @('flood-stderr') `
        -DeadlineMilliseconds 3000 `
        -StdoutLimitBytes 4096 `
        -StderrLimitBytes 4096
    Assert-SupervisorTest ($stderrFlood.exit_category -eq 'stderr_limit') (
        'stderr flood did not terminate at its hard limit'
    )
    Assert-SupervisorTest ($stderrFlood.stderr_bytes -eq 4096) (
        'stderr flood retained bytes beyond or below its hard limit'
    )

    $childPidPath = Join-Path $fixtureRoot 'child.pid'
    $tree = Invoke-ExternalRuntimeProcess `
        -ApplicationPath $helperPath `
        -ArgumentList @('tree', $childPidPath) `
        -DeadlineMilliseconds 250 `
        -StdoutLimitBytes 64 `
        -StderrLimitBytes 64
    Assert-SupervisorTest ($tree.exit_category -eq 'deadline') 'child tree did not hit deadline'
    Assert-SupervisorTest (Test-Path -LiteralPath $childPidPath -PathType Leaf) (
        'child tree did not publish its synthetic PID'
    )
    $childPid = [int]([System.IO.File]::ReadAllText($childPidPath).Trim())
    Start-Sleep -Milliseconds 100
    Assert-SupervisorTest ($null -eq (Get-Process -Id $childPid -ErrorAction SilentlyContinue)) (
        'descendant survived process-tree termination proof'
    )

    foreach ($iteration in 1..8) {
        $race = Invoke-ExternalRuntimeProcess `
            -ApplicationPath $helperPath `
            -ArgumentList @('hang', '25') `
            -DeadlineMilliseconds 25 `
            -StdoutLimitBytes 64 `
            -StderrLimitBytes 64
        Assert-SupervisorTest (
            @('completed_success', 'deadline') -contains $race.exit_category
        ) 'deadline race produced a noncanonical category'
        Assert-SupervisorTest $race.process_tree_exited 'deadline race left a process tree'
    }

    Invoke-SupervisorExpectedFailure `
        -Message 'relative application path was accepted' `
        -Action {
            Invoke-ExternalRuntimeProcess `
                -ApplicationPath '.\supervisor-fixture.exe' `
                -ArgumentList @('success')
        }
    Invoke-SupervisorExpectedFailure `
        -Message 'wildcard application path was accepted' `
        -Action {
            Invoke-ExternalRuntimeProcess `
                -ApplicationPath (Join-Path $fixtureRoot '*.exe') `
                -ArgumentList @('success')
        }
    $scriptPath = Join-Path $fixtureRoot 'forbidden.ps1'
    [System.IO.File]::WriteAllText($scriptPath, 'exit 0', [System.Text.UTF8Encoding]::new($false))
    Invoke-SupervisorExpectedFailure `
        -Message 'script application was accepted' `
        -Action {
            Invoke-ExternalRuntimeProcess -ApplicationPath $scriptPath -ArgumentList @()
        }
    foreach ($canaryCase in @(
        @('SERCTL_SECRET_CANARY-value', @()),
        @('SERCTL_PATH_CANARY-value', @()),
        @('fixture-private-canary', @('fixture-private-canary'))
    )) {
        Invoke-SupervisorExpectedFailure `
            -Message 'secret or path canary was accepted in argv' `
            -Action {
                Invoke-ExternalRuntimeProcess `
                    -ApplicationPath $helperPath `
                    -ArgumentList @([string]$canaryCase[0]) `
                    -ForbiddenCanary ([string[]]$canaryCase[1])
            }
    }

    $secretInput = [System.Text.UTF8Encoding]::new($false).GetBytes(
        '{"op":"status","secret":"SERCTL_SECRET_CANARY-private"}' + "`n"
    )
    $secretReceipt = Invoke-ExternalRuntimeProcess `
        -ApplicationPath $helperPath `
        -ArgumentList @('stdin-json') `
        -StandardInputBytes $secretInput `
        -StdinLimitBytes 4096 `
        -DeadlineMilliseconds 2000 `
        -StdoutLimitBytes 4096 `
        -StderrLimitBytes 4096
    $secretReceiptText = $secretReceipt | ConvertTo-Json -Compress
    Assert-SupervisorTest (
        $secretReceiptText.IndexOf('SERCTL_SECRET_CANARY-private',
            [System.StringComparison]::Ordinal) -lt 0
    ) 'stdin secret canary leaked into the public receipt'
    Assert-SupervisorTest (
        @($secretInput | Where-Object { $_ -ne 0 }).Count -eq 0
    ) 'stdin secret canary was not zeroized'

    $shadowPath = Join-Path $fixtureRoot 'cmd.exe'
    [System.IO.File]::Copy($helperPath, $shadowPath, $false)
    Invoke-SupervisorExpectedFailure `
        -Message 'renamed shell/shadow leaf was accepted' `
        -Action {
            Invoke-ExternalRuntimeProcess -ApplicationPath $shadowPath -ArgumentList @('success')
        }

    $replacementPath = Join-Path $fixtureRoot 'replacement.bin'
    [System.IO.File]::WriteAllBytes($replacementPath, [byte[]](1, 2, 3, 4))
    $replacementResult = Join-Path $fixtureRoot 'replacement.result'
    $replaceStart = [System.Diagnostics.ProcessStartInfo]::new()
    $replaceStart.FileName = $helperPath
    $replaceStart.Arguments = 'replace ' +
        (ConvertTo-ExternalRuntimeCommandLine -Values @($helperPath, $replacementPath, $replacementResult))
    $replaceStart.UseShellExecute = $false
    $replaceStart.CreateNoWindow = $true
    $replaceProcess = [System.Diagnostics.Process]::Start($replaceStart)
    try {
        $replaceProbe = Invoke-ExternalRuntimeProcess `
            -ApplicationPath $helperPath `
            -ArgumentList @('hang', '350') `
            -DeadlineMilliseconds 1000 `
            -StdoutLimitBytes 64 `
            -StderrLimitBytes 64
        Assert-SupervisorTest ($replaceProbe.exit_category -eq 'completed_success') (
            'path replacement probe did not complete normally'
        )
        Assert-SupervisorTest ($replaceProcess.WaitForExit(2000)) (
            'path replacement attacker did not finish'
        )
        Assert-SupervisorTest (
            [System.IO.File]::ReadAllText($replacementResult).Trim() -eq 'blocked'
        ) 'executable replacement was not blocked while its identity was pinned'
    }
    finally {
        if (-not $replaceProcess.HasExited) { $replaceProcess.Kill() }
        $replaceProcess.Dispose()
    }
}
finally {
    if (Test-Path -LiteralPath $fixtureRoot -PathType Container) {
        Assert-SupervisorTest (
            [System.IO.File]::ReadAllText($ownerPath).Trim() -eq $ownerToken
        ) 'fixture ownership changed before cleanup'
        Remove-Item -LiteralPath $fixtureRoot -Recurse -Force
    }
}

Write-Host 'External runtime process supervisor self-test passed.'
