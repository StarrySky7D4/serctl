Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# This file is dot-sourced by local acceptance adapters. It deliberately does
# not know about serctl, profiles, grants, vaults, or external evidence ledgers.

if (-not ('Serctl.ExternalRuntimeProcessSupervisor.NativeRunner' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;

namespace Serctl.ExternalRuntimeProcessSupervisor {
    public sealed class NativeRunResult {
        public string Category;
        public int ExitCode;
        public byte[] Stdout;
        public byte[] Stderr;
        public long ElapsedMilliseconds;
        public bool ProcessTreeExited;
    }

    public static class NativeRunner {
        private const uint CREATE_SUSPENDED = 0x00000004;
        private const uint CREATE_NO_WINDOW = 0x08000000;
        private const uint CREATE_UNICODE_ENVIRONMENT = 0x00000400;
        private const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
        private const uint STARTF_USESTDHANDLES = 0x00000100;
        private const uint HANDLE_FLAG_INHERIT = 0x00000001;
        private const uint FILE_TYPE_DISK = 0x00000001;
        private const uint FILE_TYPE_PIPE = 0x00000003;
        private const uint FILE_ATTRIBUTE_DIRECTORY = 0x00000010;
        private const int PROC_THREAD_ATTRIBUTE_HANDLE_LIST = 0x00020002;
        private const uint JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000;
        private const int JobObjectExtendedLimitInformation = 9;
        private const int JobObjectBasicAccountingInformation = 1;
        private const uint WAIT_OBJECT_0 = 0;
        private const uint WAIT_TIMEOUT = 258;
        private const uint INFINITE = 0xffffffff;
        private const uint SIGTERM = 15;
        private const uint SIGKILL = 9;
        private const int ESRCH = 3;
        private const int WNOHANG = 1;
        private const int O_CLOEXEC_LINUX = 0x00080000;
        private const int F_GETFL_LINUX = 3;
        private const int F_DUPFD_CLOEXEC_LINUX = 1030;
        private const int O_ACCMODE_LINUX = 3;
        private const int O_RDONLY_LINUX = 0;
        private const int O_WRONLY_LINUX = 1;
        private const int AT_EMPTY_PATH_LINUX = 0x1000;
        private const int AT_STATX_DONT_SYNC_LINUX = 0x4000;
        private const uint STATX_TYPE_LINUX = 0x00000001;
        private const int S_IFMT_LINUX = 0xF000;
        private const int S_IFREG_LINUX = 0x8000;
        private const int S_IFIFO_LINUX = 0x1000;
        private const short POSIX_SPAWN_SETPGROUP = 0x0002;

        [StructLayout(LayoutKind.Sequential)]
        private struct SECURITY_ATTRIBUTES {
            public int nLength;
            public IntPtr lpSecurityDescriptor;
            [MarshalAs(UnmanagedType.Bool)] public bool bInheritHandle;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct STARTUPINFO {
            public int cb;
            public string lpReserved;
            public string lpDesktop;
            public string lpTitle;
            public int dwX;
            public int dwY;
            public int dwXSize;
            public int dwYSize;
            public int dwXCountChars;
            public int dwYCountChars;
            public int dwFillAttribute;
            public uint dwFlags;
            public short wShowWindow;
            public short cbReserved2;
            public IntPtr lpReserved2;
            public IntPtr hStdInput;
            public IntPtr hStdOutput;
            public IntPtr hStdError;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct STARTUPINFOEX {
            public STARTUPINFO StartupInfo;
            public IntPtr lpAttributeList;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct PROCESS_INFORMATION {
            public IntPtr hProcess;
            public IntPtr hThread;
            public uint dwProcessId;
            public uint dwThreadId;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_BASIC_LIMIT_INFORMATION {
            public long PerProcessUserTimeLimit;
            public long PerJobUserTimeLimit;
            public uint LimitFlags;
            public UIntPtr MinimumWorkingSetSize;
            public UIntPtr MaximumWorkingSetSize;
            public uint ActiveProcessLimit;
            public UIntPtr Affinity;
            public uint PriorityClass;
            public uint SchedulingClass;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct IO_COUNTERS {
            public ulong ReadOperationCount;
            public ulong WriteOperationCount;
            public ulong OtherOperationCount;
            public ulong ReadTransferCount;
            public ulong WriteTransferCount;
            public ulong OtherTransferCount;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
            public JOBOBJECT_BASIC_LIMIT_INFORMATION BasicLimitInformation;
            public IO_COUNTERS IoInfo;
            public UIntPtr ProcessMemoryLimit;
            public UIntPtr JobMemoryLimit;
            public UIntPtr PeakProcessMemoryUsed;
            public UIntPtr PeakJobMemoryUsed;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct JOBOBJECT_BASIC_ACCOUNTING_INFORMATION {
            public long TotalUserTime;
            public long TotalKernelTime;
            public long ThisPeriodTotalUserTime;
            public long ThisPeriodTotalKernelTime;
            public uint TotalPageFaultCount;
            public uint TotalProcesses;
            public uint ActiveProcesses;
            public uint TotalTerminatedProcesses;
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CreatePipe(out IntPtr readPipe, out IntPtr writePipe,
            ref SECURITY_ATTRIBUTES attributes, uint size);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetHandleInformation(IntPtr handle, uint mask, uint flags);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetHandleInformation(IntPtr handle, out uint flags);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint GetFileType(IntPtr handle);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool InitializeProcThreadAttributeList(IntPtr attributeList,
            int attributeCount, int flags, ref UIntPtr size);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool UpdateProcThreadAttribute(IntPtr attributeList, uint flags,
            IntPtr attribute, IntPtr value, UIntPtr size, IntPtr previousValue, IntPtr returnSize);
        [DllImport("kernel32.dll")]
        private static extern void DeleteProcThreadAttributeList(IntPtr attributeList);
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        private static extern bool CreateProcessW(string applicationName, StringBuilder commandLine,
            IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles,
            uint creationFlags, IntPtr environment, string currentDirectory,
            ref STARTUPINFOEX startupInfo, out PROCESS_INFORMATION processInformation);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateJobObject(IntPtr attributes, string name);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool SetInformationJobObject(IntPtr job, int infoClass,
            IntPtr info, uint length);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool QueryInformationJobObject(IntPtr job, int infoClass,
            out JOBOBJECT_BASIC_ACCOUNTING_INFORMATION info, uint length, IntPtr returnLength);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool TerminateJobObject(IntPtr job, uint exitCode);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint ResumeThread(IntPtr thread);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetExitCodeProcess(IntPtr process, out uint exitCode);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileInformationByHandle(IntPtr handle,
            out BY_HANDLE_FILE_INFORMATION information);

        [StructLayout(LayoutKind.Sequential)]
        private struct FILETIME {
            public uint Low;
            public uint High;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct BY_HANDLE_FILE_INFORMATION {
            public uint FileAttributes;
            public FILETIME CreationTime;
            public FILETIME LastAccessTime;
            public FILETIME LastWriteTime;
            public uint VolumeSerialNumber;
            public uint FileSizeHigh;
            public uint FileSizeLow;
            public uint NumberOfLinks;
            public uint FileIndexHigh;
            public uint FileIndexLow;
        }

        [DllImport("libc", SetLastError = true)]
        private static extern int kill(int pid, int signal);
        [DllImport("libc", SetLastError = true)]
        private static extern int fstat(int fd, IntPtr statBuffer);
        [DllImport("libc", SetLastError = true)]
        private static extern int statx(int dirfd, string pathname, int flags,
            uint mask, IntPtr statxBuffer);
        [DllImport("libc", SetLastError = true)]
        private static extern int fcntl(int fd, int command, int argument);
        [DllImport("libc", SetLastError = true)]
        private static extern int pipe2([Out] int[] pipefd, int flags);
        [DllImport("libc", SetLastError = true)]
        private static extern int close(int fd);
        [DllImport("libc", SetLastError = true)]
        private static extern int waitpid(int pid, out int status, int options);
        [DllImport("libc", SetLastError = true)]
        private static extern int getpgid(int pid);
        [DllImport("libc", SetLastError = true)]
        private static extern int posix_spawn_file_actions_init(IntPtr actions);
        [DllImport("libc", SetLastError = true)]
        private static extern int posix_spawn_file_actions_destroy(IntPtr actions);
        [DllImport("libc", SetLastError = true)]
        private static extern int posix_spawn_file_actions_adddup2(IntPtr actions, int fd, int newfd);
        [DllImport("libc", SetLastError = true)]
        private static extern int posix_spawn_file_actions_addclose(IntPtr actions, int fd);
        [DllImport("libc", SetLastError = true)]
        private static extern int posix_spawn_file_actions_addclosefrom_np(IntPtr actions,
            int lowfd);
        [DllImport("libc", SetLastError = true)]
        private static extern int posix_spawn_file_actions_addchdir_np(IntPtr actions,
            string path);
        [DllImport("libc", SetLastError = true)]
        private static extern int posix_spawnattr_init(IntPtr attributes);
        [DllImport("libc", SetLastError = true)]
        private static extern int posix_spawnattr_destroy(IntPtr attributes);
        [DllImport("libc", SetLastError = true)]
        private static extern int posix_spawnattr_setflags(IntPtr attributes, short flags);
        [DllImport("libc", SetLastError = true)]
        private static extern int posix_spawnattr_setpgroup(IntPtr attributes, int processGroup);
        [DllImport("libc", SetLastError = true)]
        private static extern int posix_spawn(out int pid, string path, IntPtr fileActions,
            IntPtr attributes, IntPtr argv, IntPtr envp);

        public static string GetOpenFileIdentity(Microsoft.Win32.SafeHandles.SafeFileHandle handle) {
            if (handle == null || handle.IsInvalid || handle.IsClosed)
                throw new InvalidOperationException("file identity unavailable");
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows)) {
                BY_HANDLE_FILE_INFORMATION info;
                if (!GetFileInformationByHandle(handle.DangerousGetHandle(), out info))
                    throw new InvalidOperationException("file identity unavailable");
                return info.VolumeSerialNumber.ToString("x8") + ":" +
                    info.FileIndexHigh.ToString("x8") + info.FileIndexLow.ToString("x8");
            }
            // Linux and Darwin expose device/inode identity in the leading 16
            // bytes of struct stat on the supported 64-bit release runners.
            if (IntPtr.Size != 8 ||
                !(RuntimeInformation.IsOSPlatform(OSPlatform.Linux) ||
                  RuntimeInformation.IsOSPlatform(OSPlatform.OSX)))
                throw new InvalidOperationException("file identity unavailable");
            IntPtr memory = Marshal.AllocHGlobal(256);
            try {
                for (int i = 0; i < 256; i++) Marshal.WriteByte(memory, i, 0);
                int fd = handle.DangerousGetHandle().ToInt32();
                if (fstat(fd, memory) != 0)
                    throw new InvalidOperationException("file identity unavailable");
                byte[] prefix = new byte[16];
                Marshal.Copy(memory, prefix, 0, prefix.Length);
                return BitConverter.ToString(prefix).Replace("-", "").ToLowerInvariant();
            } finally {
                Marshal.FreeHGlobal(memory);
            }
        }

        private sealed class CaptureState {
            public readonly MemoryStream Buffer = new MemoryStream();
            public readonly object Sync = new object();
            public readonly int Limit;
            public readonly string LimitCategory;
            private bool Cleared;
            public CaptureState(int limit, string category) { Limit = limit; LimitCategory = category; }
            public byte[] TakeAndClear() {
                lock (Sync) {
                    if (Cleared) throw new InvalidOperationException("capture already cleared");
                    byte[] result = Buffer.ToArray();
                    ClearLocked();
                    return result;
                }
            }
            public void Clear() {
                lock (Sync) { ClearLocked(); }
            }
            private void ClearLocked() {
                if (Cleared) return;
                byte[] storage = Buffer.GetBuffer();
                Array.Clear(storage, 0, storage.Length);
                Buffer.Dispose();
                Cleared = true;
            }
        }

        private sealed class StopState {
            public int Requested;
            public string Category;
            public Action Terminate;
            public void Request(string category) {
                if (Interlocked.CompareExchange(ref Requested, 1, 0) == 0) {
                    Category = category;
                    Terminate();
                }
            }
        }

        private static async Task PumpAsync(Stream stream, CaptureState state, StopState stop) {
            byte[] chunk = new byte[8192];
            try {
                while (true) {
                    int count = await stream.ReadAsync(chunk, 0, chunk.Length).ConfigureAwait(false);
                    if (count == 0) return;
                    lock (state.Sync) {
                        if (state.Buffer.Length + count > state.Limit) {
                            int remaining = state.Limit - (int)state.Buffer.Length;
                            if (remaining > 0) state.Buffer.Write(chunk, 0, remaining);
                            stop.Request(state.LimitCategory);
                            return;
                        }
                        state.Buffer.Write(chunk, 0, count);
                    }
                }
            } finally {
                Array.Clear(chunk, 0, chunk.Length);
            }
        }

        private static async Task PumpInputAsync(Stream stream, byte[] input, StopState stop) {
            try {
                if (input.Length != 0) {
                    await stream.WriteAsync(input, 0, input.Length).ConfigureAwait(false);
                    await stream.FlushAsync().ConfigureAwait(false);
                }
            } catch (IOException) {
                stop.Request("stdin_write");
            } catch (ObjectDisposedException) {
                stop.Request("stdin_write");
            } finally {
                Array.Clear(input, 0, input.Length);
                stream.Dispose();
            }
        }

        private static IntPtr BuildWindowsEnvironmentBlock(string[] environmentEntries) {
            SortedDictionary<string, string> entries = new SortedDictionary<string, string>(
                StringComparer.OrdinalIgnoreCase);
            foreach (string entry in environmentEntries) {
                int separator = entry.IndexOf('=');
                if (separator <= 0) throw new InvalidOperationException("environment entry invalid");
                entries[entry.Substring(0, separator)] = entry.Substring(separator + 1);
            }
            StringBuilder block = new StringBuilder();
            foreach (KeyValuePair<string, string> item in entries) {
                block.Append(item.Key).Append('=').Append(item.Value).Append('\0');
            }
            block.Append('\0');
            return Marshal.StringToHGlobalUni(block.ToString());
        }

        private static void RequireInheritableHandle(IntPtr handle) {
            uint flags;
            if (handle == IntPtr.Zero || handle == new IntPtr(-1) ||
                !GetHandleInformation(handle, out flags) ||
                (flags & HANDLE_FLAG_INHERIT) == 0)
                throw new InvalidOperationException("explicit inherited handle invalid");
            uint type = GetFileType(handle);
            if (type != FILE_TYPE_PIPE && type != FILE_TYPE_DISK)
                throw new InvalidOperationException("explicit inherited handle type invalid");
            if (type == FILE_TYPE_DISK) {
                BY_HANDLE_FILE_INFORMATION info;
                if (!GetFileInformationByHandle(handle, out info) ||
                    (info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0)
                    throw new InvalidOperationException("explicit inherited file handle invalid");
            }
        }

        private static IntPtr CreateHandleAttributeList(IntPtr[] handles,
            out IntPtr handleArray) {
            UIntPtr bytes = UIntPtr.Zero;
            InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref bytes);
            if (bytes == UIntPtr.Zero)
                throw new InvalidOperationException("attribute list sizing failed");
            IntPtr list = Marshal.AllocHGlobal(checked((int)bytes.ToUInt64()));
            handleArray = IntPtr.Zero;
            bool initialized = false;
            try {
                if (!InitializeProcThreadAttributeList(list, 1, 0, ref bytes))
                    throw new InvalidOperationException("attribute list initialization failed");
                initialized = true;
                handleArray = Marshal.AllocHGlobal(checked(handles.Length * IntPtr.Size));
                for (int i = 0; i < handles.Length; i++)
                    Marshal.WriteIntPtr(handleArray, i * IntPtr.Size, handles[i]);
                if (!UpdateProcThreadAttribute(list, 0,
                    new IntPtr(PROC_THREAD_ATTRIBUTE_HANDLE_LIST), handleArray,
                    new UIntPtr(checked((uint)(handles.Length * IntPtr.Size))),
                    IntPtr.Zero, IntPtr.Zero))
                    throw new InvalidOperationException("handle allowlist installation failed");
                return list;
            } catch {
                if (handleArray != IntPtr.Zero) Marshal.FreeHGlobal(handleArray);
                if (initialized) DeleteProcThreadAttributeList(list);
                Marshal.FreeHGlobal(list);
                throw;
            }
        }

        private static IntPtr CreateKillOnCloseJob() {
            IntPtr job = CreateJobObject(IntPtr.Zero, null);
            if (job == IntPtr.Zero) throw new InvalidOperationException("job creation failed");
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
            limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            int size = Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION));
            IntPtr memory = Marshal.AllocHGlobal(size);
            try {
                Marshal.StructureToPtr(limits, memory, false);
                if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation, memory, (uint)size))
                    throw new InvalidOperationException("job configuration failed");
                return job;
            } catch {
                CloseHandle(job);
                throw;
            } finally {
                Marshal.FreeHGlobal(memory);
            }
        }

        private static bool JobIsEmpty(IntPtr job) {
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION info;
            if (!QueryInformationJobObject(job, JobObjectBasicAccountingInformation, out info,
                (uint)Marshal.SizeOf(typeof(JOBOBJECT_BASIC_ACCOUNTING_INFORMATION)), IntPtr.Zero))
                throw new InvalidOperationException("job accounting failed");
            return info.ActiveProcesses == 0;
        }

        private static bool WaitForJobEmpty(IntPtr job, int milliseconds) {
            Stopwatch timer = Stopwatch.StartNew();
            while (timer.ElapsedMilliseconds < milliseconds) {
                if (JobIsEmpty(job)) return true;
                Thread.Sleep(10);
            }
            return JobIsEmpty(job);
        }

        private static NativeRunResult RunWindows(string application, string commandLine,
            string[] environmentEntries, long[] allowedInheritedHandles, byte[] stdinBytes,
            int deadlineMs, int stdoutLimit, int stderrLimit) {
            IntPtr stdinRead = IntPtr.Zero, stdinWrite = IntPtr.Zero;
            IntPtr stdoutRead = IntPtr.Zero, stdoutWrite = IntPtr.Zero;
            IntPtr stderrRead = IntPtr.Zero, stderrWrite = IntPtr.Zero;
            IntPtr job = IntPtr.Zero, environment = IntPtr.Zero;
            IntPtr attributeList = IntPtr.Zero, attributeHandles = IntPtr.Zero;
            PROCESS_INFORMATION pi = new PROCESS_INFORMATION();
            FileStream stdinStream = null, stdoutStream = null, stderrStream = null;
            CaptureState stdout = null, stderr = null;
            Stopwatch timer = Stopwatch.StartNew();
            try {
                SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
                sa.nLength = Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES));
                sa.bInheritHandle = true;
                if (!CreatePipe(out stdinRead, out stdinWrite, ref sa, 0) ||
                    !CreatePipe(out stdoutRead, out stdoutWrite, ref sa, 0) ||
                    !CreatePipe(out stderrRead, out stderrWrite, ref sa, 0))
                    throw new InvalidOperationException("pipe creation failed");
                if (!SetHandleInformation(stdinWrite, HANDLE_FLAG_INHERIT, 0) ||
                    !SetHandleInformation(stdoutRead, HANDLE_FLAG_INHERIT, 0) ||
                    !SetHandleInformation(stderrRead, HANDLE_FLAG_INHERIT, 0))
                    throw new InvalidOperationException("pipe protection failed");

                List<IntPtr> inherited = new List<IntPtr>();
                inherited.Add(stdinRead);
                inherited.Add(stdoutWrite);
                inherited.Add(stderrWrite);
                foreach (long raw in allowedInheritedHandles) {
                    IntPtr handle = new IntPtr(raw);
                    RequireInheritableHandle(handle);
                    if (!inherited.Contains(handle)) inherited.Add(handle);
                }
                attributeList = CreateHandleAttributeList(inherited.ToArray(), out attributeHandles);

                job = CreateKillOnCloseJob();
                environment = BuildWindowsEnvironmentBlock(environmentEntries);
                STARTUPINFOEX si = new STARTUPINFOEX();
                si.StartupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFOEX));
                si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
                si.StartupInfo.hStdInput = stdinRead;
                si.StartupInfo.hStdOutput = stdoutWrite;
                si.StartupInfo.hStdError = stderrWrite;
                si.lpAttributeList = attributeList;
                StringBuilder mutableCommandLine = new StringBuilder(commandLine);
                if (!CreateProcessW(application, mutableCommandLine, IntPtr.Zero, IntPtr.Zero, true,
                    CREATE_SUSPENDED | CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT |
                    EXTENDED_STARTUPINFO_PRESENT,
                    environment, Path.GetDirectoryName(application), ref si, out pi))
                    throw new InvalidOperationException("process creation failed");
                if (!AssignProcessToJobObject(job, pi.hProcess)) {
                    TerminateJobObject(job, 1);
                    throw new InvalidOperationException("job assignment failed");
                }
                CloseHandle(stdinRead); stdinRead = IntPtr.Zero;
                CloseHandle(stdoutWrite); stdoutWrite = IntPtr.Zero;
                CloseHandle(stderrWrite); stderrWrite = IntPtr.Zero;
                stdinStream = new FileStream(new Microsoft.Win32.SafeHandles.SafeFileHandle(stdinWrite, true), FileAccess.Write, 8192, false);
                stdinWrite = IntPtr.Zero;
                stdoutStream = new FileStream(new Microsoft.Win32.SafeHandles.SafeFileHandle(stdoutRead, true), FileAccess.Read, 8192, false);
                stdoutRead = IntPtr.Zero;
                stderrStream = new FileStream(new Microsoft.Win32.SafeHandles.SafeFileHandle(stderrRead, true), FileAccess.Read, 8192, false);
                stderrRead = IntPtr.Zero;

                StopState stop = new StopState();
                stop.Terminate = delegate { TerminateJobObject(job, 1); };
                stdout = new CaptureState(stdoutLimit, "stdout_limit");
                stderr = new CaptureState(stderrLimit, "stderr_limit");
                Task stdinTask = PumpInputAsync(stdinStream, stdinBytes, stop);
                stdinStream = null;
                Task stdoutTask = PumpAsync(stdoutStream, stdout, stop);
                Task stderrTask = PumpAsync(stderrStream, stderr, stop);
                if (ResumeThread(pi.hThread) == 0xffffffff)
                    stop.Request("launcher_failure");

                bool rootExited = false;
                while (!rootExited && Volatile.Read(ref stop.Requested) == 0) {
                    uint wait = WaitForSingleObject(pi.hProcess, 10);
                    if (wait == WAIT_OBJECT_0) rootExited = true;
                    else if (wait != WAIT_TIMEOUT) stop.Request("launcher_failure");
                    else if (timer.ElapsedMilliseconds >= deadlineMs) stop.Request("deadline");
                }
                if (rootExited && !JobIsEmpty(job)) TerminateJobObject(job, 1);
                if (!WaitForJobEmpty(job, 3000)) {
                    TerminateJobObject(job, 1);
                    if (!WaitForJobEmpty(job, 3000))
                        throw new InvalidOperationException("process tree termination could not be proven");
                }
                if (!Task.WaitAll(new Task[] { stdinTask, stdoutTask, stderrTask }, 3000))
                    throw new InvalidOperationException("stream completion could not be proven");

                uint rawExit = 1;
                GetExitCodeProcess(pi.hProcess, out rawExit);
                int exitCode = unchecked((int)rawExit);
                string category = stop.Category;
                if (category == null) category = exitCode == 0 ? "completed_success" : "completed_nonzero";
                return new NativeRunResult {
                    Category = category,
                    ExitCode = exitCode,
                    Stdout = stdout.TakeAndClear(),
                    Stderr = stderr.TakeAndClear(),
                    ElapsedMilliseconds = timer.ElapsedMilliseconds,
                    ProcessTreeExited = true
                };
            } finally {
                if (environment != IntPtr.Zero) Marshal.ZeroFreeGlobalAllocUnicode(environment);
                if (stdout != null) stdout.Clear();
                if (stderr != null) stderr.Clear();
                if (attributeList != IntPtr.Zero) {
                    DeleteProcThreadAttributeList(attributeList);
                    Marshal.FreeHGlobal(attributeList);
                }
                if (attributeHandles != IntPtr.Zero) Marshal.FreeHGlobal(attributeHandles);
                if (stdinStream != null) stdinStream.Dispose();
                if (stdoutStream != null) stdoutStream.Dispose();
                if (stderrStream != null) stderrStream.Dispose();
                if (stdinRead != IntPtr.Zero) CloseHandle(stdinRead);
                if (stdinWrite != IntPtr.Zero) CloseHandle(stdinWrite);
                if (stdoutRead != IntPtr.Zero) CloseHandle(stdoutRead);
                if (stdoutWrite != IntPtr.Zero) CloseHandle(stdoutWrite);
                if (stderrRead != IntPtr.Zero) CloseHandle(stderrRead);
                if (stderrWrite != IntPtr.Zero) CloseHandle(stderrWrite);
                if (pi.hThread != IntPtr.Zero) CloseHandle(pi.hThread);
                if (pi.hProcess != IntPtr.Zero) CloseHandle(pi.hProcess);
                if (job != IntPtr.Zero) CloseHandle(job);
            }
        }

        private static IntPtr Utf8String(string value) {
            byte[] bytes = Encoding.UTF8.GetBytes(value + "\0");
            IntPtr pointer = Marshal.AllocHGlobal(bytes.Length);
            Marshal.Copy(bytes, 0, pointer, bytes.Length);
            Array.Clear(bytes, 0, bytes.Length);
            return pointer;
        }

        private static IntPtr BuildPointerVector(string[] values, List<IntPtr> strings) {
            IntPtr vector = Marshal.AllocHGlobal((values.Length + 1) * IntPtr.Size);
            for (int i = 0; i < values.Length; i++) {
                IntPtr item = Utf8String(values[i]);
                strings.Add(item);
                Marshal.WriteIntPtr(vector, i * IntPtr.Size, item);
            }
            Marshal.WriteIntPtr(vector, values.Length * IntPtr.Size, IntPtr.Zero);
            return vector;
        }

        private static int DecodeWaitStatus(int status) {
            int signal = status & 0x7f;
            if (signal == 0) return (status >> 8) & 0xff;
            return 128 + signal;
        }

        private static bool UnixGroupAbsent(int pgid) {
            if (kill(-pgid, 0) == 0) return false;
            return Marshal.GetLastWin32Error() == ESRCH;
        }

        private static int GetInheritedChildFd(string purpose) {
            switch (purpose) {
                case "grant_input": return 4;
                case "profile_passphrase_input": return 5;
                case "grant_output": return 6;
                case "receipt_output": return 7;
                default: throw new InvalidOperationException("inherited handle purpose rejected");
            }
        }

        private static void RequireUnixInheritedHandle(int fd, string purpose) {
            if (fd < 0) throw new InvalidOperationException("inherited descriptor invalid");
            IntPtr statxBuffer = Marshal.AllocHGlobal(256);
            try {
                for (int i = 0; i < 256; i++) Marshal.WriteByte(statxBuffer, i, 0);
                if (statx(fd, "", AT_EMPTY_PATH_LINUX | AT_STATX_DONT_SYNC_LINUX,
                    STATX_TYPE_LINUX, statxBuffer) != 0)
                    throw new InvalidOperationException("inherited descriptor identity unavailable");
                int mode = ((int)(ushort)Marshal.ReadInt16(statxBuffer, 28)) & S_IFMT_LINUX;
                if (mode != S_IFREG_LINUX && mode != S_IFIFO_LINUX)
                    throw new InvalidOperationException("inherited descriptor type rejected");
            } finally {
                Marshal.FreeHGlobal(statxBuffer);
            }
            int flags = fcntl(fd, F_GETFL_LINUX, 0);
            if (flags < 0) throw new InvalidOperationException("inherited descriptor access unavailable");
            int access = flags & O_ACCMODE_LINUX;
            bool inputPurpose = purpose == "grant_input" ||
                purpose == "profile_passphrase_input";
            if ((inputPurpose && access == O_WRONLY_LINUX) ||
                (!inputPurpose && access == O_RDONLY_LINUX))
                throw new InvalidOperationException("inherited descriptor access rejected");
        }

        private static NativeRunResult RunUnix(string application, long pinnedApplicationHandle,
            string[] arguments, string[] environmentEntries, long[] allowedInheritedHandles,
            string[] inheritedHandlePurposes, byte[] stdinBytes, int deadlineMs,
            int stdoutLimit, int stderrLimit) {
            if (!RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                throw new InvalidOperationException("atomic Unix launcher unavailable on this platform");
            if (allowedInheritedHandles.Length != inheritedHandlePurposes.Length ||
                allowedInheritedHandles.Length > 4)
                throw new InvalidOperationException("inherited descriptor mapping rejected");
            if (pinnedApplicationHandle < 0 || pinnedApplicationHandle > Int32.MaxValue)
                throw new InvalidOperationException("pinned executable descriptor unavailable");
            int executableFd = checked((int)pinnedApplicationHandle);
            if (executableFd == 0 || executableFd == 1 || executableFd == 2)
                throw new InvalidOperationException("pinned executable descriptor invalid");

            int[] stdinPipe = new int[] { -1, -1 };
            int[] stdoutPipe = new int[] { -1, -1 };
            int[] stderrPipe = new int[] { -1, -1 };
            int[] inheritedCopies = new int[allowedInheritedHandles.Length];
            for (int i = 0; i < inheritedCopies.Length; i++) inheritedCopies[i] = -1;
            IntPtr actions = Marshal.AllocHGlobal(1024);
            IntPtr attributes = Marshal.AllocHGlobal(1024);
            bool actionsReady = false, attributesReady = false;
            IntPtr argv = IntPtr.Zero, envp = IntPtr.Zero;
            List<IntPtr> strings = new List<IntPtr>();
            FileStream stdinStream = null, stdoutStream = null, stderrStream = null;
            CaptureState stdout = null, stderr = null;
            int pid = 0, waitStatus = 0;
            bool rootReaped = false;
            Stopwatch timer = Stopwatch.StartNew();
            try {
                if (pipe2(stdinPipe, O_CLOEXEC_LINUX) != 0 ||
                    pipe2(stdoutPipe, O_CLOEXEC_LINUX) != 0 ||
                    pipe2(stderrPipe, O_CLOEXEC_LINUX) != 0)
                    throw new InvalidOperationException("atomic pipe creation failed");
                if (stdinPipe[0] < 3 || stdinPipe[1] < 3 ||
                    stdoutPipe[0] < 3 || stdoutPipe[1] < 3 ||
                    stderrPipe[0] < 3 || stderrPipe[1] < 3)
                    throw new InvalidOperationException("unexpected standard descriptor state");
                HashSet<int> sourceDescriptors = new HashSet<int>();
                HashSet<int> childDescriptors = new HashSet<int>();
                for (int i = 0; i < allowedInheritedHandles.Length; i++) {
                    if (allowedInheritedHandles[i] < 0 ||
                        allowedInheritedHandles[i] > Int32.MaxValue)
                        throw new InvalidOperationException("inherited descriptor invalid");
                    int sourceFd = checked((int)allowedInheritedHandles[i]);
                    int childFd = GetInheritedChildFd(inheritedHandlePurposes[i]);
                    if (!sourceDescriptors.Add(sourceFd) || !childDescriptors.Add(childFd))
                        throw new InvalidOperationException("inherited descriptor mapping rejected");
                    RequireUnixInheritedHandle(sourceFd, inheritedHandlePurposes[i]);
                    inheritedCopies[i] = fcntl(sourceFd, F_DUPFD_CLOEXEC_LINUX, 64);
                    if (inheritedCopies[i] < 64)
                        throw new InvalidOperationException("inherited descriptor pin failed");
                }
                if (posix_spawn_file_actions_init(actions) != 0)
                    throw new InvalidOperationException("spawn file actions initialization failed");
                actionsReady = true;
                if (posix_spawn_file_actions_adddup2(actions, stdinPipe[0], 0) != 0 ||
                    posix_spawn_file_actions_adddup2(actions, stdoutPipe[1], 1) != 0 ||
                    posix_spawn_file_actions_adddup2(actions, stderrPipe[1], 2) != 0 ||
                    posix_spawn_file_actions_adddup2(actions, executableFd, 3) != 0)
                    throw new InvalidOperationException("spawn file actions configuration failed");
                for (int i = 0; i < inheritedCopies.Length; i++) {
                    int childFd = GetInheritedChildFd(inheritedHandlePurposes[i]);
                    if (posix_spawn_file_actions_adddup2(actions,
                        inheritedCopies[i], childFd) != 0)
                        throw new InvalidOperationException("spawn inherited descriptor mapping failed");
                }
                for (int childFd = 4; childFd <= 7; childFd++) {
                    if (!childDescriptors.Contains(childFd) &&
                        posix_spawn_file_actions_addclose(actions, childFd) != 0)
                        throw new InvalidOperationException("spawn descriptor closure failed");
                }
                if (posix_spawn_file_actions_addclosefrom_np(actions, 8) != 0 ||
                    posix_spawn_file_actions_addchdir_np(actions,
                        Path.GetDirectoryName(application)) != 0)
                    throw new InvalidOperationException("spawn file actions configuration failed");
                if (posix_spawnattr_init(attributes) != 0)
                    throw new InvalidOperationException("spawn attributes initialization failed");
                attributesReady = true;
                if (posix_spawnattr_setflags(attributes, POSIX_SPAWN_SETPGROUP) != 0 ||
                    posix_spawnattr_setpgroup(attributes, 0) != 0)
                    throw new InvalidOperationException("atomic process group configuration failed");

                string[] argvValues = new string[arguments.Length + 1];
                argvValues[0] = application;
                Array.Copy(arguments, 0, argvValues, 1, arguments.Length);
                argv = BuildPointerVector(argvValues, strings);
                envp = BuildPointerVector(environmentEntries, strings);
                int spawnResult = posix_spawn(out pid, "/proc/self/fd/3", actions,
                    attributes, argv, envp);
                if (spawnResult != 0 || pid <= 0)
                    throw new InvalidOperationException("atomic process creation failed");
                close(stdinPipe[0]); stdinPipe[0] = -1;
                close(stdoutPipe[1]); stdoutPipe[1] = -1;
                close(stderrPipe[1]); stderrPipe[1] = -1;
                stdinStream = new FileStream(
                    new Microsoft.Win32.SafeHandles.SafeFileHandle(new IntPtr(stdinPipe[1]), true),
                    FileAccess.Write, 8192, false);
                stdinPipe[1] = -1;
                stdoutStream = new FileStream(
                    new Microsoft.Win32.SafeHandles.SafeFileHandle(new IntPtr(stdoutPipe[0]), true),
                    FileAccess.Read, 8192, false);
                stdoutPipe[0] = -1;
                stderrStream = new FileStream(
                    new Microsoft.Win32.SafeHandles.SafeFileHandle(new IntPtr(stderrPipe[0]), true),
                    FileAccess.Read, 8192, false);
                stderrPipe[0] = -1;

                StopState stop = new StopState();
                stop.Terminate = delegate { kill(-pid, (int)SIGTERM); };
                stdout = new CaptureState(stdoutLimit, "stdout_limit");
                stderr = new CaptureState(stderrLimit, "stderr_limit");
                Task stdinTask = PumpInputAsync(stdinStream, stdinBytes, stop);
                stdinStream = null;
                Task stdoutTask = PumpAsync(stdoutStream, stdout, stop);
                Task stderrTask = PumpAsync(stderrStream, stderr, stop);
                while (!rootReaped && Volatile.Read(ref stop.Requested) == 0) {
                    int waited = waitpid(pid, out waitStatus, WNOHANG);
                    if (waited == pid) rootReaped = true;
                    else if (waited < 0) stop.Request("launcher_failure");
                    else if (timer.ElapsedMilliseconds >= deadlineMs) stop.Request("deadline");
                    else Thread.Sleep(10);
                }

                kill(-pid, (int)SIGTERM);
                Thread.Sleep(100);
                if (!UnixGroupAbsent(pid)) kill(-pid, (int)SIGKILL);
                Stopwatch proof = Stopwatch.StartNew();
                while (proof.ElapsedMilliseconds < 3000 && !UnixGroupAbsent(pid)) Thread.Sleep(10);
                if (!UnixGroupAbsent(pid))
                    throw new InvalidOperationException("process tree termination could not be proven");
                if (!rootReaped) {
                    Stopwatch reap = Stopwatch.StartNew();
                    while (reap.ElapsedMilliseconds < 3000) {
                        int waited = waitpid(pid, out waitStatus, WNOHANG);
                        if (waited == pid) { rootReaped = true; break; }
                        if (waited < 0) break;
                        Thread.Sleep(10);
                    }
                }
                if (!rootReaped)
                    throw new InvalidOperationException("root process reaping could not be proven");
                if (!Task.WaitAll(new Task[] { stdinTask, stdoutTask, stderrTask }, 3000))
                    throw new InvalidOperationException("stream completion could not be proven");
                int exitCode = DecodeWaitStatus(waitStatus);
                string category = stop.Category;
                if (category == null) category = exitCode == 0 ? "completed_success" : "completed_nonzero";
                return new NativeRunResult {
                    Category = category,
                    ExitCode = exitCode,
                    Stdout = stdout.TakeAndClear(),
                    Stderr = stderr.TakeAndClear(),
                    ElapsedMilliseconds = timer.ElapsedMilliseconds,
                    ProcessTreeExited = true
                };
            } finally {
                if (pid > 0 && !rootReaped) { kill(-pid, (int)SIGKILL); waitpid(pid, out waitStatus, 0); }
                if (stdout != null) stdout.Clear();
                if (stderr != null) stderr.Clear();
                if (stdinStream != null) stdinStream.Dispose();
                if (stdoutStream != null) stdoutStream.Dispose();
                if (stderrStream != null) stderrStream.Dispose();
                for (int i = 0; i < stdinPipe.Length; i++) if (stdinPipe[i] >= 0) close(stdinPipe[i]);
                for (int i = 0; i < stdoutPipe.Length; i++) if (stdoutPipe[i] >= 0) close(stdoutPipe[i]);
                for (int i = 0; i < stderrPipe.Length; i++) if (stderrPipe[i] >= 0) close(stderrPipe[i]);
                for (int i = 0; i < inheritedCopies.Length; i++)
                    if (inheritedCopies[i] >= 0) close(inheritedCopies[i]);
                if (actionsReady) posix_spawn_file_actions_destroy(actions);
                if (attributesReady) posix_spawnattr_destroy(attributes);
                Marshal.FreeHGlobal(actions);
                Marshal.FreeHGlobal(attributes);
                if (argv != IntPtr.Zero) Marshal.FreeHGlobal(argv);
                if (envp != IntPtr.Zero) Marshal.FreeHGlobal(envp);
                foreach (IntPtr item in strings) Marshal.FreeHGlobal(item);
            }
        }

        public static NativeRunResult Run(string application, long pinnedApplicationHandle,
            string commandLine, string[] arguments, string[] environmentEntries,
            long[] allowedInheritedHandles, string[] inheritedHandlePurposes,
            byte[] stdinBytes, int deadlineMs, int stdoutLimit, int stderrLimit) {
            if (stdinBytes == null || stdinBytes.Length > 1048576)
                throw new InvalidOperationException("standard input rejected");
            if (inheritedHandlePurposes == null ||
                inheritedHandlePurposes.Length != allowedInheritedHandles.Length)
                throw new InvalidOperationException("inherited handle mapping rejected");
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                return RunWindows(application, commandLine, environmentEntries,
                    allowedInheritedHandles, stdinBytes, deadlineMs, stdoutLimit, stderrLimit);
            return RunUnix(application, pinnedApplicationHandle, arguments, environmentEntries,
                allowedInheritedHandles, inheritedHandlePurposes, stdinBytes, deadlineMs,
                stdoutLimit, stderrLimit);
        }
    }
}
'@
}

function Test-ExternalRuntimeForbiddenText {
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$ForbiddenCanary
    )

    foreach ($builtIn in @('SERCTL_SECRET_CANARY', 'SERCTL_PATH_CANARY')) {
        if ($Value.IndexOf($builtIn, [System.StringComparison]::Ordinal) -ge 0) {
            return $true
        }
    }
    foreach ($canary in $ForbiddenCanary) {
        if ([string]::IsNullOrEmpty($canary) -or $canary.Length -lt 8) {
            throw 'external runtime canary policy is invalid'
        }
        if ($Value.IndexOf($canary, [System.StringComparison]::Ordinal) -ge 0) {
            return $true
        }
    }
    return $false
}

function Assert-ExternalRuntimeApplication {
    param(
        [Parameter(Mandatory = $true)][string]$ApplicationPath,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$ForbiddenCanary
    )

    if (-not [System.IO.Path]::IsPathRooted($ApplicationPath) -or
        [System.Management.Automation.WildcardPattern]::ContainsWildcardCharacters($ApplicationPath) -or
        (Test-ExternalRuntimeForbiddenText -Value $ApplicationPath -ForbiddenCanary $ForbiddenCanary)) {
        throw 'external runtime application identity was rejected'
    }
    $absolute = [System.IO.Path]::GetFullPath($ApplicationPath)
    if (-not [string]::Equals($absolute, $ApplicationPath, [System.StringComparison]::OrdinalIgnoreCase) -or
        -not (Test-Path -LiteralPath $absolute -PathType Leaf)) {
        throw 'external runtime application identity was rejected'
    }
    $forbiddenLeaves = @(
        'cmd', 'cmd.exe', 'powershell', 'powershell.exe', 'pwsh', 'pwsh.exe',
        'sh', 'bash', 'dash', 'zsh', 'fish', 'wscript.exe', 'cscript.exe'
    )
    $leaf = [System.IO.Path]::GetFileName($absolute).ToLowerInvariant()
    $extension = [System.IO.Path]::GetExtension($leaf).ToLowerInvariant()
    if ($forbiddenLeaves -contains $leaf -or
        @('.ps1', '.cmd', '.bat', '.com', '.sh') -contains $extension) {
        throw 'external runtime application type was rejected'
    }
    $cursor = [System.IO.FileSystemInfo][System.IO.FileInfo]::new($absolute)
    while ($null -ne $cursor) {
        if (($cursor.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'external runtime application identity was rejected'
        }
        if ($cursor -is [System.IO.FileInfo]) {
            $cursor = $cursor.Directory
        }
        else {
            $cursor = ([System.IO.DirectoryInfo]$cursor).Parent
        }
    }
    return $absolute
}

function ConvertTo-ExternalRuntimeCommandLine {
    param([Parameter(Mandatory = $true)][string[]]$Values)

    $encoded = foreach ($value in $Values) {
        if ($value.Length -eq 0) {
            '""'
            continue
        }
        if ($value -notmatch '[\s"]') {
            $value
            continue
        }
        $builder = [System.Text.StringBuilder]::new()
        [void]$builder.Append('"')
        $slashes = 0
        foreach ($character in $value.ToCharArray()) {
            if ($character -eq '\') {
                $slashes++
                continue
            }
            if ($character -eq '"') {
                [void]$builder.Append(('\' * (($slashes * 2) + 1)))
                [void]$builder.Append('"')
                $slashes = 0
                continue
            }
            if ($slashes -gt 0) {
                [void]$builder.Append(('\' * $slashes))
                $slashes = 0
            }
            [void]$builder.Append($character)
        }
        if ($slashes -gt 0) {
            [void]$builder.Append(('\' * ($slashes * 2)))
        }
        [void]$builder.Append('"')
        $builder.ToString()
    }
    return ($encoded -join ' ')
}

function Get-ExternalRuntimeSha256 {
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

# INTERNAL-ONLY read-only mapping for adapter argv construction. Callers select
# a purpose, never a child descriptor number; NativeRunner enforces the same
# mapping inside the atomic Linux posix_spawn file-actions transaction.
function Get-ExternalRuntimeInheritedChildFdInternal {
    param([Parameter(Mandatory = $true)][string]$Purpose)

    switch -CaseSensitive ($Purpose) {
        'grant_input' { return [int]4 }
        'profile_passphrase_input' { return [int]5 }
        'grant_output' { return [int]6 }
        'receipt_output' { return [int]7 }
        default { throw 'external runtime inherited handle purpose was rejected' }
    }
}

function ConvertTo-ExternalRuntimeEnvironmentEntries {
    param(
        [Parameter(Mandatory = $true)][System.Collections.IDictionary]$Variables,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$ForbiddenCanary
    )

    if ($Variables.Count -gt 6) {
        throw 'external runtime environment was rejected'
    }
    $allowedNames = @('LANG', 'LC_ALL', 'NO_COLOR', 'TERM', 'TMPDIR', 'TZ')
    $entries = [System.Collections.Generic.List[string]]::new()
    $totalLength = 0
    foreach ($keyObject in @($Variables.Keys | Sort-Object)) {
        if ($null -eq $keyObject -or $null -eq $Variables[$keyObject]) {
            throw 'external runtime environment was rejected'
        }
        $key = [string]$keyObject
        $value = [string]$Variables[$keyObject]
        $upper = $key.ToUpperInvariant()
        if ($allowedNames -cnotcontains $key -or
            $value.Length -gt 4096 -or $value -match '[\x00\r\n]' -or
            (Test-ExternalRuntimeForbiddenText -Value $value -ForbiddenCanary $ForbiddenCanary)) {
            throw 'external runtime environment was rejected'
        }
        $entry = $key + '=' + $value
        $totalLength += $entry.Length
        [void]$entries.Add($entry)
    }
    if ($totalLength -gt 16384) {
        throw 'external runtime environment was rejected'
    }
    return [string[]]$entries.ToArray()
}

# INTERNAL-ONLY ADAPTER API. This function deliberately returns bounded raw
# stdout/stderr byte arrays so the in-repository adapter can parse one strict
# terminal. It is not a formal evidence contract and must never be exported as
# a receipt-producing or caller-injectable result API. Its in-module caller owns
# both returned arrays and must clear them in a finally block after parsing.
function Invoke-ExternalRuntimeProcessCaptureInternal {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ApplicationPath,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$ArgumentList,
        [ValidateRange(1, 3600000)][int]$DeadlineMilliseconds = 30000,
        [ValidateRange(1, 16777216)][int]$StdoutLimitBytes = 1048576,
        [ValidateRange(1, 16777216)][int]$StderrLimitBytes = 1048576,
        [AllowEmptyCollection()][byte[]]$StandardInputBytes = [byte[]]::new(0),
        [ValidateRange(0, 1048576)][int]$StdinLimitBytes = 1048576,
        [string[]]$ForbiddenCanary = @(),
        [System.Collections.IDictionary]$EnvironmentVariables = @{},
        [System.Collections.IDictionary]$InheritedHandleByPurpose = @{}
    )

    $standardInputOwned = $StandardInputBytes
    $native = $null
    $rawCaptureReleased = $false
    try {
    if ($null -eq $standardInputOwned -or
        $standardInputOwned.Length -gt $StdinLimitBytes -or
        $standardInputOwned.Length -gt 1048576) {
        throw 'external runtime standard input was rejected'
    }
    $application = Assert-ExternalRuntimeApplication `
        -ApplicationPath $ApplicationPath `
        -ForbiddenCanary $ForbiddenCanary
    if ($ArgumentList.Count -gt 128) {
        throw 'external runtime argument vector was rejected'
    }
    $totalCharacters = 0
    foreach ($argument in $ArgumentList) {
        if ($null -eq $argument -or $argument.Length -gt 8192 -or $argument -match '[\x00\r\n]' -or
            (Test-ExternalRuntimeForbiddenText -Value $argument -ForbiddenCanary $ForbiddenCanary)) {
            throw 'external runtime argument vector was rejected'
        }
        $totalCharacters += $argument.Length
    }
    if ($totalCharacters -gt 32768) {
        throw 'external runtime argument vector was rejected'
    }
    $environmentEntries = [string[]]@(
        ConvertTo-ExternalRuntimeEnvironmentEntries `
            -Variables $EnvironmentVariables `
            -ForbiddenCanary $ForbiddenCanary
    )
    if ($InheritedHandleByPurpose.Count -gt 4) {
        throw 'external runtime inherited handle allowlist was rejected'
    }
    $inheritedHandleValues = [System.Collections.Generic.List[long]]::new()
    $inheritedHandlePurposes = [System.Collections.Generic.List[string]]::new()
    $inheritedHandleReferences = [System.Collections.Generic.List[System.Runtime.InteropServices.SafeHandle]]::new()
    try {
        foreach ($purposeObject in @($InheritedHandleByPurpose.Keys | Sort-Object)) {
            $purpose = [string]$purposeObject
            [void](Get-ExternalRuntimeInheritedChildFdInternal -Purpose $purpose)
            $handle = $InheritedHandleByPurpose[$purposeObject]
            if ($handle -isnot [System.Runtime.InteropServices.SafeHandle]) {
                throw 'external runtime inherited handle allowlist was rejected'
            }
            if ($null -eq $handle -or $handle.IsInvalid -or $handle.IsClosed) {
                throw 'external runtime inherited handle allowlist was rejected'
            }
            $referenceAdded = $false
            $handle.DangerousAddRef([ref]$referenceAdded)
            if (-not $referenceAdded) {
                throw 'external runtime inherited handle allowlist was rejected'
            }
            [void]$inheritedHandleReferences.Add($handle)
            $raw = $handle.DangerousGetHandle().ToInt64()
            if ($inheritedHandleValues.Contains($raw)) {
                throw 'external runtime inherited handle allowlist was rejected'
            }
            [void]$inheritedHandleValues.Add($raw)
            [void]$inheritedHandlePurposes.Add($purpose)
        }

        # FileShare.Read pins the executable against write/delete replacement on
        # Windows. Unix permits rename of an open inode, so the path evidence is
        # re-opened and compared before the receipt is released.
        $pinned = [System.IO.File]::Open(
            $application,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::Read
        )
        try {
        $initialLength = $pinned.Length
        try {
            $initialIdentity = [Serctl.ExternalRuntimeProcessSupervisor.NativeRunner]::GetOpenFileIdentity(
                $pinned.SafeFileHandle
            )
        }
        catch {
            throw 'external runtime application identity could not be pinned'
        }
        $initialBytes = [byte[]]::new($initialLength)
        $offset = 0
        while ($offset -lt $initialBytes.Length) {
            $count = $pinned.Read($initialBytes, $offset, $initialBytes.Length - $offset)
            if ($count -le 0) { throw 'external runtime application integrity check failed' }
            $offset += $count
        }
        $initialHash = Get-ExternalRuntimeSha256 -Bytes $initialBytes
        [Array]::Clear($initialBytes, 0, $initialBytes.Length)

        $values = @($application) + @($ArgumentList)
        $commandLine = ConvertTo-ExternalRuntimeCommandLine -Values $values
        try {
            $native = [Serctl.ExternalRuntimeProcessSupervisor.NativeRunner]::Run(
                $application,
                $pinned.SafeFileHandle.DangerousGetHandle().ToInt64(),
                $commandLine,
                [string[]]$ArgumentList,
                [string[]]$environmentEntries,
                [long[]]$inheritedHandleValues.ToArray(),
                [string[]]$inheritedHandlePurposes.ToArray(),
                [byte[]]$standardInputOwned,
                $DeadlineMilliseconds,
                $StdoutLimitBytes,
                $StderrLimitBytes
            )
        }
        catch {
            throw 'external runtime supervision failed closed'
        }

        $reopened = [System.IO.File]::Open(
            $application,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::Read
        )
        try {
            try {
                $currentIdentity = [Serctl.ExternalRuntimeProcessSupervisor.NativeRunner]::GetOpenFileIdentity(
                    $reopened.SafeFileHandle
                )
            }
            catch {
                throw 'external runtime application integrity check failed'
            }
            if ($reopened.Length -ne $initialLength -or
                -not [string]::Equals(
                    $initialIdentity,
                    $currentIdentity,
                    [System.StringComparison]::Ordinal
                )) {
                throw 'external runtime application integrity check failed'
            }
            $currentBytes = [byte[]]::new($reopened.Length)
            $offset = 0
            while ($offset -lt $currentBytes.Length) {
                $count = $reopened.Read($currentBytes, $offset, $currentBytes.Length - $offset)
                if ($count -le 0) { throw 'external runtime application integrity check failed' }
                $offset += $count
            }
            $currentHash = Get-ExternalRuntimeSha256 -Bytes $currentBytes
            [Array]::Clear($currentBytes, 0, $currentBytes.Length)
            if (-not [string]::Equals($initialHash, $currentHash, [System.StringComparison]::Ordinal)) {
                throw 'external runtime application integrity check failed'
            }
        }
        finally {
            $reopened.Dispose()
        }

        if (-not $native.ProcessTreeExited) {
            throw 'external runtime process tree termination could not be proven'
        }
        $capture = [pscustomobject][ordered]@{
            schema_version = 'serctl-external-runtime-supervisor-capture-internal-v1'
            exit_category = $native.Category
            exit_code = [int]$native.ExitCode
            stdout = [byte[]]$native.Stdout
            stderr = [byte[]]$native.Stderr
            elapsed_ms = [long]$native.ElapsedMilliseconds
            deadline_ms = [long]$DeadlineMilliseconds
            process_tree_exited = $true
        }
        $rawCaptureReleased = $true
        return $capture
        }
        finally {
            $pinned.Dispose()
        }
    }
    finally {
        foreach ($handle in $inheritedHandleReferences) {
            $handle.DangerousRelease()
        }
    }
    }
    finally {
        if ($null -ne $standardInputOwned) {
            [Array]::Clear($standardInputOwned, 0, $standardInputOwned.Length)
        }
        if ($null -ne $native -and -not $rawCaptureReleased) {
            [Array]::Clear($native.Stdout, 0, $native.Stdout.Length)
            [Array]::Clear($native.Stderr, 0, $native.Stderr.Length)
        }
    }
}

function Invoke-ExternalRuntimeProcess {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$ApplicationPath,
        [Parameter(Mandatory = $true)][AllowEmptyCollection()][string[]]$ArgumentList,
        [ValidateRange(1, 3600000)][int]$DeadlineMilliseconds = 30000,
        [ValidateRange(1, 16777216)][int]$StdoutLimitBytes = 1048576,
        [ValidateRange(1, 16777216)][int]$StderrLimitBytes = 1048576,
        [AllowEmptyCollection()][byte[]]$StandardInputBytes = [byte[]]::new(0),
        [ValidateRange(0, 1048576)][int]$StdinLimitBytes = 1048576,
        [string[]]$ForbiddenCanary = @(),
        [System.Collections.IDictionary]$EnvironmentVariables = @{},
        [System.Collections.IDictionary]$InheritedHandleByPurpose = @{}
    )

    $capture = $null
    try {
        $capture = Invoke-ExternalRuntimeProcessCaptureInternal `
            -ApplicationPath $ApplicationPath `
            -ArgumentList $ArgumentList `
            -DeadlineMilliseconds $DeadlineMilliseconds `
            -StdoutLimitBytes $StdoutLimitBytes `
            -StderrLimitBytes $StderrLimitBytes `
            -StandardInputBytes $StandardInputBytes `
            -StdinLimitBytes $StdinLimitBytes `
            -ForbiddenCanary $ForbiddenCanary `
            -EnvironmentVariables $EnvironmentVariables `
            -InheritedHandleByPurpose $InheritedHandleByPurpose
        $stdoutHash = Get-ExternalRuntimeSha256 -Bytes $capture.stdout
        $stderrHash = Get-ExternalRuntimeSha256 -Bytes $capture.stderr
        $terminalText = 'external-runtime-receipt-v1|' + $capture.exit_category + '|' +
            $capture.exit_code + '|' + $capture.stdout.Length + '|' + $stdoutHash + '|' +
            $capture.stderr.Length + '|' + $stderrHash + '|' + $capture.elapsed_ms +
            '|' + $DeadlineMilliseconds + '|true'
        $terminalBytes = [System.Text.Encoding]::UTF8.GetBytes($terminalText)
        try {
            $terminalHash = Get-ExternalRuntimeSha256 -Bytes $terminalBytes
        }
        finally {
            [Array]::Clear($terminalBytes, 0, $terminalBytes.Length)
        }

        return [pscustomobject][ordered]@{
            schema_version = 'serctl-external-runtime-supervisor-v1'
            exit_category = $capture.exit_category
            exit_code = [int]$capture.exit_code
            stdout_bytes = [long]$capture.stdout.Length
            stdout_sha256 = $stdoutHash
            stderr_bytes = [long]$capture.stderr.Length
            stderr_sha256 = $stderrHash
            elapsed_ms = [long]$capture.elapsed_ms
            deadline_ms = [long]$DeadlineMilliseconds
            process_tree_exited = $true
            terminal_sha256 = $terminalHash
        }
    }
    finally {
        if ($null -ne $capture) {
            [Array]::Clear($capture.stdout, 0, $capture.stdout.Length)
            [Array]::Clear($capture.stderr, 0, $capture.stderr.Length)
        }
    }
}
