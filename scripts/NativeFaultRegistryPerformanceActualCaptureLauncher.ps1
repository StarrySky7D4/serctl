Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'ExternalRuntimeProcessSupervisor.ps1')

function Invoke-NativeFixtureFixedPowerShellInternal {
    param(
        [Parameter(Mandatory = $true)][ValidateSet('fixture', 'owner')][string]$Role,
        [string]$ReceiptPath,
        [ValidateRange(1, 3600000)][int]$DeadlineMilliseconds = 300000
    )

    if (-not [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [Runtime.InteropServices.OSPlatform]::Windows
    )) {
        throw 'native fixture actual-capture launcher is not proven on this platform'
    }
    $scriptName = if ($Role -ceq 'fixture') {
        'NativeFaultRegistryPerformanceFixture.ps1'
    } else {
        'Invoke-NativeFaultRegistryPerformanceActualCaptureOwner.ps1'
    }
    if ($Role -ceq 'owner' -and [string]::IsNullOrWhiteSpace($ReceiptPath)) {
        throw 'native fixture owner receipt path was rejected'
    }
    $scriptPath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot $scriptName))
    $hostPath = [IO.Path]::GetFullPath((Join-Path (
        [Environment]::GetEnvironmentVariable('SystemRoot')
    ) 'System32\WindowsPowerShell\v1.0\powershell.exe'))
    $scriptItem = Get-Item -LiteralPath $scriptPath -Force -ErrorAction Stop
    $hostItem = Get-Item -LiteralPath $hostPath -Force -ErrorAction Stop
    foreach ($item in @($scriptItem, $hostItem)) {
        if ($item.PSIsContainer -or
            ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'native fixture actual-capture TCB identity was rejected'
        }
    }

    $hostStream = $null
    $scriptStream = $null
    $native = $null
    try {
        $hostStream = [IO.File]::Open(
            $hostPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read
        )
        $scriptStream = [IO.File]::Open(
            $scriptPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read
        )
        $hostLength = $hostStream.Length
        $scriptLength = $scriptStream.Length
        $hostHash = (Get-FileHash -LiteralPath $hostPath -Algorithm SHA256).Hash
        $scriptHash = (Get-FileHash -LiteralPath $scriptPath -Algorithm SHA256).Hash
        $scriptLiteral = "'" + $scriptPath.Replace("'", "''") + "'"
        $command = '& ' + $scriptLiteral
        if ($Role -ceq 'owner') {
            $receiptFullPath = [IO.Path]::GetFullPath($ReceiptPath)
            if ($receiptFullPath -match '[\x00\r\n]') {
                throw 'native fixture owner receipt path was rejected'
            }
            $receiptLiteral = "'" + $receiptFullPath.Replace("'", "''") + "'"
            $command += ' -ReceiptPath ' + $receiptLiteral
        }
        $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
        $arguments = [string[]]@(
            '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
            '-EncodedCommand', $encoded
        )
        $systemRoot = [Environment]::GetEnvironmentVariable('SystemRoot')
        $processTemp = [Environment]::GetEnvironmentVariable('TEMP')
        if ([string]::IsNullOrWhiteSpace($systemRoot) -or
            [string]::IsNullOrWhiteSpace($processTemp) -or
            $systemRoot -match '[\x00\r\n=]' -or $processTemp -match '[\x00\r\n=]') {
            throw 'native fixture actual-capture system environment was rejected'
        }
        $environment = [Collections.Generic.List[string]]::new()
        foreach ($entry in @(
            'LANG=C', 'LC_ALL=C', 'NO_COLOR=1', 'TERM=dumb', 'TZ=UTC',
            ('SystemRoot=' + $systemRoot), ('TEMP=' + $processTemp), ('TMP=' + $processTemp)
        )) { [void]$environment.Add($entry) }
        foreach ($name in @('CODEX_PERMISSION_PROFILE', 'CODEX_SANDBOX_NETWORK_DISABLED', 'CODEX_CI')) {
            $value = [Environment]::GetEnvironmentVariable($name)
            if (($name -ceq 'CODEX_PERMISSION_PROFILE' -and $value -ceq ':workspace') -or
                ($name -cne 'CODEX_PERMISSION_PROFILE' -and $value -ceq '1')) {
                [void]$environment.Add($name + '=' + $value)
            }
        }
        $commandLine = ConvertTo-ExternalRuntimeCommandLine (@($hostPath) + @($arguments))
        $native = [Serctl.ExternalRuntimeProcessSupervisor.NativeRunner]::Run(
            $hostPath,
            $hostStream.SafeFileHandle.DangerousGetHandle().ToInt64(),
            $commandLine,
            $arguments,
            [string[]]$environment.ToArray(),
            [long[]]@(),
            [string[]]@(),
            [byte[]]::new(0),
            $DeadlineMilliseconds,
            4194304,
            65536
        )
        if (-not $native.ProcessTreeExited) {
            throw 'native fixture actual-capture process tree termination was not proven'
        }
        if ($hostStream.Length -ne $hostLength -or $scriptStream.Length -ne $scriptLength -or
            (Get-FileHash -LiteralPath $hostPath -Algorithm SHA256).Hash -cne $hostHash -or
            (Get-FileHash -LiteralPath $scriptPath -Algorithm SHA256).Hash -cne $scriptHash) {
            throw 'native fixture actual-capture TCB bytes changed during execution'
        }
        $stdout = [byte[]]$native.Stdout.Clone()
        $stderr = [byte[]]$native.Stderr.Clone()
        return [pscustomobject][ordered]@{
            schema_version = 'serctl-native-fixture-process-capture-v1'
            role = $Role
            script_sha256 = $scriptHash.ToLowerInvariant()
            exit_category = [string]$native.Category
            exit_code = [int]$native.ExitCode
            elapsed_ms = [long]$native.ElapsedMilliseconds
            deadline_ms = [long]$DeadlineMilliseconds
            process_tree_exited = [bool]$native.ProcessTreeExited
            stdout = $stdout
            stderr = $stderr
        }
    }
    finally {
        if ($null -ne $native) {
            if ($null -ne $native.Stdout) { [Array]::Clear($native.Stdout, 0, $native.Stdout.Length) }
            if ($null -ne $native.Stderr) { [Array]::Clear($native.Stderr, 0, $native.Stderr.Length) }
        }
        if ($null -ne $scriptStream) { $scriptStream.Dispose() }
        if ($null -ne $hostStream) { $hostStream.Dispose() }
    }
}

function Invoke-NativeFaultRegistryPerformanceActualCaptureOwnerInternal {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$ReceiptPath,
        [ValidateRange(1, 3600000)][int]$DeadlineMilliseconds = 300000
    )
    Invoke-NativeFixtureFixedPowerShellInternal `
        -Role owner -ReceiptPath $ReceiptPath -DeadlineMilliseconds $DeadlineMilliseconds
}
