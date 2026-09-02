Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'ExternalRuntimeProcessSupervisor.ps1')

# INTERNAL-ONLY launcher for the fixed formal-owner script. General shells are
# correctly forbidden by the external runtime supervisor. This narrower TCB
# permits only the current PowerShell host plus the repository-fixed owner
# entry point, pins both byte streams for the whole child lifetime, and passes
# exactly the fixed formal case set's purpose-checked Grant handles.
function Invoke-ExternalTransferIsolatedOwnerProcessCoreInternal {
    param(
        [Parameter(Mandatory = $true)][byte[]]$ProtectedConfigBytes,
        [Parameter(Mandatory = $true)][Runtime.InteropServices.SafeHandle]$DownloadedSetRecordHandle,
        [Parameter(Mandatory = $true)][Runtime.InteropServices.SafeHandle]$WindowsCliHandle,
        [Parameter(Mandatory = $true)][Runtime.InteropServices.SafeHandle]$WindowsDaemonHandle,
        [Parameter(Mandatory = $true)][Runtime.InteropServices.SafeHandle]$LinuxHelperHandle,
        [Parameter(Mandatory = $true)][Runtime.InteropServices.SafeHandle]$ReceiptOutputHandle,
        [Parameter(Mandatory = $true)][Runtime.InteropServices.SafeHandle]$OpenSshExecGrantHandle,
        [Parameter(Mandatory = $true)][Runtime.InteropServices.SafeHandle]$DropbearExecGrantHandle,
        [Parameter(Mandatory = $true)][Runtime.InteropServices.SafeHandle]$OpenSshDirectoryGrantHandle,
        [Parameter(Mandatory = $true)][Runtime.InteropServices.SafeHandle]$OpenSshTunnelLocalOpenGrantHandle,
        [Parameter(Mandatory = $true)][Runtime.InteropServices.SafeHandle]$OpenSshTunnelLocalStatusGrantHandle,
        [Parameter(Mandatory = $true)][Runtime.InteropServices.SafeHandle]$OpenSshTunnelLocalCancelGrantHandle,
        [Parameter(Mandatory = $true)][Runtime.InteropServices.SafeHandle]$OpenSshTunnelRemoteOpenGrantHandle,
        [Parameter(Mandatory = $true)][Runtime.InteropServices.SafeHandle]$OpenSshTunnelRemoteStatusGrantHandle,
        [Parameter(Mandatory = $true)][Runtime.InteropServices.SafeHandle]$OpenSshTunnelRemoteCancelGrantHandle,
        [Parameter(Mandatory = $true)][Runtime.InteropServices.SafeHandle]$OpenSshTunnelDynamicOpenGrantHandle,
        [Parameter(Mandatory = $true)][Runtime.InteropServices.SafeHandle]$OpenSshTunnelDynamicStatusGrantHandle,
        [Parameter(Mandatory = $true)][Runtime.InteropServices.SafeHandle]$OpenSshTunnelDynamicCancelGrantHandle,
        [Parameter(Mandatory = $true)][Runtime.InteropServices.SafeHandle]$OpenSshSftpTransferGrantHandle,
        [Parameter(Mandatory = $true)][Runtime.InteropServices.SafeHandle]$OpenSshSftpStatusGrantHandle,
        [Parameter(Mandatory = $true)][Runtime.InteropServices.SafeHandle]$OpenSshNativeTransferGrantHandle,
        [Parameter(Mandatory = $true)][Runtime.InteropServices.SafeHandle]$OpenSshNativeStatusGrantHandle,
        [Parameter(Mandatory = $true)][Runtime.InteropServices.SafeHandle]$DropbearSftpTransferGrantHandle,
        [Parameter(Mandatory = $true)][Runtime.InteropServices.SafeHandle]$DropbearSftpStatusGrantHandle,
        [Parameter(Mandatory = $true)][Runtime.InteropServices.SafeHandle]$DropbearNativeTransferGrantHandle,
        [Parameter(Mandatory = $true)][Runtime.InteropServices.SafeHandle]$DropbearNativeStatusGrantHandle,
        [ValidateRange(1, 3600000)][int]$DeadlineMilliseconds = 300000
    )

    $onWindows = [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [Runtime.InteropServices.OSPlatform]::Windows
    )
    if (-not $onWindows) {
        throw 'isolated formal owner launcher is not proven on this platform'
    }
    if ($null -eq $ProtectedConfigBytes -or $ProtectedConfigBytes.Length -eq 0 -or
        $ProtectedConfigBytes.Length -gt 1048576) {
        throw 'isolated formal owner configuration was rejected'
    }
    $officialHandles=@($DownloadedSetRecordHandle,$WindowsCliHandle,$WindowsDaemonHandle,$LinuxHelperHandle,$ReceiptOutputHandle)
    $grantHandles = @(
        $OpenSshExecGrantHandle, $DropbearExecGrantHandle, $OpenSshDirectoryGrantHandle,
        $OpenSshTunnelLocalOpenGrantHandle, $OpenSshTunnelLocalStatusGrantHandle,
        $OpenSshTunnelLocalCancelGrantHandle, $OpenSshTunnelRemoteOpenGrantHandle,
        $OpenSshTunnelRemoteStatusGrantHandle, $OpenSshTunnelRemoteCancelGrantHandle,
        $OpenSshTunnelDynamicOpenGrantHandle, $OpenSshTunnelDynamicStatusGrantHandle,
        $OpenSshTunnelDynamicCancelGrantHandle,
        $OpenSshSftpTransferGrantHandle, $OpenSshSftpStatusGrantHandle,
        $OpenSshNativeTransferGrantHandle, $OpenSshNativeStatusGrantHandle,
        $DropbearSftpTransferGrantHandle, $DropbearSftpStatusGrantHandle,
        $DropbearNativeTransferGrantHandle, $DropbearNativeStatusGrantHandle
    )
    foreach ($grantHandle in @($officialHandles)+$grantHandles) {
        if ($null -eq $grantHandle -or $grantHandle.IsInvalid -or $grantHandle.IsClosed) {
            throw 'isolated formal owner Grant handle was rejected'
        }
    }
    [void](Get-ExternalRuntimeInheritedChildFdInternal 'grant_input')
    $rawOfficial=@($officialHandles|ForEach-Object{$_.DangerousGetHandle().ToInt64()})
    $rawGrants = @($grantHandles | ForEach-Object {
        $_.DangerousGetHandle().ToInt64()
    })
    if (@($rawOfficial+$rawGrants|Select-Object -Unique).Count -ne 25) {
        throw 'isolated formal owner requires twenty-five distinct purpose handles'
    }
    $runnerPath = [IO.Path]::GetFullPath(
        (Join-Path $PSScriptRoot 'Invoke-IsolatedExternalTransferFormalOwner.ps1')
    )
    # Use the fixed in-box Windows PowerShell host for the owner boundary. It
    # is stable across PS7/PS5 callers and avoids caller-selected shell bytes.
    $hostPath = [IO.Path]::GetFullPath((Join-Path (
        [Environment]::GetEnvironmentVariable('SystemRoot')
    ) 'System32\WindowsPowerShell\v1.0\powershell.exe'))
    foreach ($value in @($hostPath, $runnerPath)) {
        if ($value -match '[\x00\r\n]' -or
            (Test-ExternalRuntimeForbiddenText -Value $value -ForbiddenCanary @(
                'SERCTL_SECRET_CANARY', 'SERCTL_PATH_CANARY'
            ))) {
            throw 'isolated formal owner path was rejected'
        }
    }
    $hostItem = Get-Item -LiteralPath $hostPath -Force -ErrorAction Stop
    $runnerItem = Get-Item -LiteralPath $runnerPath -Force -ErrorAction Stop
    foreach ($item in @($hostItem, $runnerItem)) {
        if ($item.PSIsContainer -or
            ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'isolated formal owner executable identity was rejected'
        }
    }

    $configOwned = $ProtectedConfigBytes
    $native = $null
    $captureReleased = $false
    $referencedHandles = [Collections.Generic.List[Runtime.InteropServices.SafeHandle]]::new()
    $hostStream = $null
    $runnerStream = $null
    try {
        foreach ($grantHandle in @($officialHandles)+$grantHandles) {
            $referenceAdded = $false
            $grantHandle.DangerousAddRef([ref]$referenceAdded)
            if (-not $referenceAdded) { throw 'isolated formal owner Grant handle pin failed' }
            [void]$referencedHandles.Add($grantHandle)
        }
        # FileShare.Read prevents same-path write/delete replacement on Windows.
        $hostStream = [IO.File]::Open(
            $hostPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read
        )
        $runnerStream = [IO.File]::Open(
            $runnerPath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read
        )
        $hostLength = $hostStream.Length
        $runnerLength = $runnerStream.Length
        $hostHash = (Get-FileHash -LiteralPath $hostPath -Algorithm SHA256).Hash
        $runnerHash = (Get-FileHash -LiteralPath $runnerPath -Algorithm SHA256).Hash
        $runnerLiteral = "'" + $runnerPath.Replace("'", "''") + "'"
        $ownerCommand = (
            '& ' + $runnerLiteral + ' -DownloadedSetRecordHandleRaw '+$rawOfficial[0]+' -WindowsCliHandleRaw '+$rawOfficial[1]+' -WindowsDaemonHandleRaw '+$rawOfficial[2]+' -LinuxHelperHandleRaw '+$rawOfficial[3]+' -ReceiptOutputHandleRaw '+$rawOfficial[4]+' -OpenSshExecGrantHandleRaw ' +
            $rawGrants[0].ToString([Globalization.CultureInfo]::InvariantCulture) +
            ' -DropbearExecGrantHandleRaw ' +
            $rawGrants[1].ToString([Globalization.CultureInfo]::InvariantCulture) +
            ' -OpenSshDirectoryGrantHandleRaw ' +
            $rawGrants[2].ToString([Globalization.CultureInfo]::InvariantCulture) +
            ' -OpenSshTunnelLocalOpenGrantHandleRaw ' +
            $rawGrants[3].ToString([Globalization.CultureInfo]::InvariantCulture) +
            ' -OpenSshTunnelLocalStatusGrantHandleRaw ' +
            $rawGrants[4].ToString([Globalization.CultureInfo]::InvariantCulture) +
            ' -OpenSshTunnelLocalCancelGrantHandleRaw ' +
            $rawGrants[5].ToString([Globalization.CultureInfo]::InvariantCulture) +
            ' -OpenSshTunnelRemoteOpenGrantHandleRaw ' +
            $rawGrants[6].ToString([Globalization.CultureInfo]::InvariantCulture) +
            ' -OpenSshTunnelRemoteStatusGrantHandleRaw ' +
            $rawGrants[7].ToString([Globalization.CultureInfo]::InvariantCulture) +
            ' -OpenSshTunnelRemoteCancelGrantHandleRaw ' +
            $rawGrants[8].ToString([Globalization.CultureInfo]::InvariantCulture) +
            ' -OpenSshTunnelDynamicOpenGrantHandleRaw ' +
            $rawGrants[9].ToString([Globalization.CultureInfo]::InvariantCulture) +
            ' -OpenSshTunnelDynamicStatusGrantHandleRaw ' +
            $rawGrants[10].ToString([Globalization.CultureInfo]::InvariantCulture) +
            ' -OpenSshTunnelDynamicCancelGrantHandleRaw ' +
            $rawGrants[11].ToString([Globalization.CultureInfo]::InvariantCulture) +
            ' -OpenSshSftpTransferGrantHandleRaw ' +
            $rawGrants[12].ToString([Globalization.CultureInfo]::InvariantCulture) +
            ' -OpenSshSftpStatusGrantHandleRaw ' +
            $rawGrants[13].ToString([Globalization.CultureInfo]::InvariantCulture) +
            ' -OpenSshNativeTransferGrantHandleRaw ' +
            $rawGrants[14].ToString([Globalization.CultureInfo]::InvariantCulture) +
            ' -OpenSshNativeStatusGrantHandleRaw ' +
            $rawGrants[15].ToString([Globalization.CultureInfo]::InvariantCulture) +
            ' -DropbearSftpTransferGrantHandleRaw ' +
            $rawGrants[16].ToString([Globalization.CultureInfo]::InvariantCulture) +
            ' -DropbearSftpStatusGrantHandleRaw ' +
            $rawGrants[17].ToString([Globalization.CultureInfo]::InvariantCulture) +
            ' -DropbearNativeTransferGrantHandleRaw ' +
            $rawGrants[18].ToString([Globalization.CultureInfo]::InvariantCulture) +
            ' -DropbearNativeStatusGrantHandleRaw ' +
            $rawGrants[19].ToString([Globalization.CultureInfo]::InvariantCulture)
        )
        $encodedOwnerCommand = [Convert]::ToBase64String(
            [Text.Encoding]::Unicode.GetBytes($ownerCommand)
        )
        $arguments = [string[]]@(
            '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
            '-EncodedCommand', $encodedOwnerCommand
        )
        # PowerShell requires SystemRoot to initialize its trusted language
        # mode consistently. This specialized launcher supplies that single
        # fixed OS value in addition to the supervisor's public allowlist; it
        # never inherits the caller environment.
        $systemRoot = [Environment]::GetEnvironmentVariable('SystemRoot')
        $processTemp = [Environment]::GetEnvironmentVariable('TEMP')
        if ([string]::IsNullOrWhiteSpace($systemRoot) -or
            $systemRoot -match '[\x00\r\n=]' -or
            [string]::IsNullOrWhiteSpace($processTemp) -or
            $processTemp -match '[\x00\r\n=]') {
            throw 'isolated formal owner system environment was rejected'
        }
        $environmentList = [Collections.Generic.List[string]]::new()
        foreach ($entry in @(
            'LANG=C', 'LC_ALL=C', 'NO_COLOR=1', 'TERM=dumb', 'TZ=UTC',
            ('SystemRoot=' + $systemRoot), ('TEMP=' + $processTemp), ('TMP=' + $processTemp)
        )) { [void]$environmentList.Add($entry) }
        # Preserve only the sandbox-enforcement markers when this launcher is
        # itself running under Codex. Omitting the workspace marker causes the
        # child PowerShell host to enter a different language mode before the
        # owner entry point can run; no tool pipe, session id, path, or secret
        # environment value is inherited.
        $codexPermission = [Environment]::GetEnvironmentVariable('CODEX_PERMISSION_PROFILE')
        if ($codexPermission -ceq ':workspace') {
            [void]$environmentList.Add('CODEX_PERMISSION_PROFILE=:workspace')
        }
        $codexNetwork = [Environment]::GetEnvironmentVariable('CODEX_SANDBOX_NETWORK_DISABLED')
        if ($codexNetwork -ceq '1') {
            [void]$environmentList.Add('CODEX_SANDBOX_NETWORK_DISABLED=1')
        }
        $codexCi = [Environment]::GetEnvironmentVariable('CODEX_CI')
        if ($codexCi -ceq '1') { [void]$environmentList.Add('CODEX_CI=1') }
        $environmentEntries = [string[]]$environmentList.ToArray()
        $commandLine = ConvertTo-ExternalRuntimeCommandLine (@($hostPath) + @($arguments))
        $native = [Serctl.ExternalRuntimeProcessSupervisor.NativeRunner]::Run(
            $hostPath,
            $hostStream.SafeFileHandle.DangerousGetHandle().ToInt64(),
            $commandLine,
            $arguments,
            $environmentEntries,
            [long[]]@($rawOfficial+$rawGrants),
            [string[]]@(
                'downloaded_set_record','component_cli','component_daemon','component_helper','receipt_output',
                'grant_input', 'grant_input', 'grant_input',
                'grant_input', 'grant_input', 'grant_input',
                'grant_input', 'grant_input', 'grant_input',
                'grant_input', 'grant_input', 'grant_input',
                'grant_input', 'grant_input', 'grant_input', 'grant_input',
                'grant_input', 'grant_input', 'grant_input', 'grant_input'
            ),
            $configOwned,
            $DeadlineMilliseconds,
            65536,
            65536
        )
        if (-not $native.ProcessTreeExited) {
            throw 'isolated formal owner process tree termination was not proven'
        }
        if ($hostStream.Length -ne $hostLength -or $runnerStream.Length -ne $runnerLength -or
            (Get-FileHash -LiteralPath $hostPath -Algorithm SHA256).Hash -cne $hostHash -or
            (Get-FileHash -LiteralPath $runnerPath -Algorithm SHA256).Hash -cne $runnerHash) {
            throw 'isolated formal owner TCB bytes changed during execution'
        }
        $capturedStderr = [byte[]]$native.Stderr
        if ($native.Category -ceq 'completed_success' -and $native.ExitCode -eq 0 -and
            $capturedStderr.Length -gt 0 -and $capturedStderr.Length -le 4096) {
            # Windows PowerShell 5.1 may emit one engine-owned module-analysis
            # progress record as CLIXML before the script preference applies.
            # Normalize only the exact progress-only envelope; an Error stream
            # record, non-CLIXML byte, or any other stderr remains fatal to the
            # formal caller.
            $stderrAscii = [Text.Encoding]::ASCII.GetString($capturedStderr)
            if ($stderrAscii.StartsWith("#< CLIXML`r`n<Objs ") -and
                $stderrAscii.Contains('<Obj S="progress"') -and
                -not $stderrAscii.Contains(' S="Error"') -and
                $stderrAscii.TrimEnd().EndsWith('</Objs>')) {
                [Array]::Clear($capturedStderr, 0, $capturedStderr.Length)
                $capturedStderr = [byte[]]::new(0)
            }
        }
        $capture = [pscustomobject][ordered]@{
            schema_version = 'serctl-isolated-formal-owner-capture-internal-v1'
            exit_category = [string]$native.Category
            exit_code = [int]$native.ExitCode
            stdout = [byte[]]$native.Stdout
            stderr = $capturedStderr
            elapsed_ms = [long]$native.ElapsedMilliseconds
            deadline_ms = [long]$DeadlineMilliseconds
            process_tree_exited = $true
        }
        $captureReleased = $true
        return $capture
    }
    finally {
        if ($null -ne $runnerStream) { $runnerStream.Dispose() }
        if ($null -ne $hostStream) { $hostStream.Dispose() }
        foreach ($grantHandle in $referencedHandles) { $grantHandle.DangerousRelease() }
        if ($null -ne $configOwned) {
            [Array]::Clear($configOwned, 0, $configOwned.Length)
        }
        if ($null -ne $native -and -not $captureReleased) {
            [Array]::Clear($native.Stdout, 0, $native.Stdout.Length)
            [Array]::Clear($native.Stderr, 0, $native.Stderr.Length)
        }
    }
}

function Invoke-ExternalTransferIsolatedOwnerProcessInternal {
    param(
        [Parameter(Mandatory = $true)][byte[]]$ProtectedConfigBytes,
        [Parameter(Mandatory = $true)][Runtime.InteropServices.SafeHandle]$DownloadedSetRecordHandle,
        [Parameter(Mandatory = $true)][Runtime.InteropServices.SafeHandle]$WindowsCliHandle,
        [Parameter(Mandatory = $true)][Runtime.InteropServices.SafeHandle]$WindowsDaemonHandle,
        [Parameter(Mandatory = $true)][Runtime.InteropServices.SafeHandle]$LinuxHelperHandle,
        [Parameter(Mandatory = $true)][Runtime.InteropServices.SafeHandle]$ReceiptOutputHandle,
        [Parameter(Mandatory = $true)][Runtime.InteropServices.SafeHandle]$OpenSshExecGrantHandle,
        [Parameter(Mandatory = $true)][Runtime.InteropServices.SafeHandle]$DropbearExecGrantHandle,
        [Parameter(Mandatory = $true)][Runtime.InteropServices.SafeHandle]$OpenSshDirectoryGrantHandle,
        [Parameter(Mandatory = $true)][Runtime.InteropServices.SafeHandle]$OpenSshTunnelLocalOpenGrantHandle,
        [Parameter(Mandatory = $true)][Runtime.InteropServices.SafeHandle]$OpenSshTunnelLocalStatusGrantHandle,
        [Parameter(Mandatory = $true)][Runtime.InteropServices.SafeHandle]$OpenSshTunnelLocalCancelGrantHandle,
        [Parameter(Mandatory = $true)][Runtime.InteropServices.SafeHandle]$OpenSshTunnelRemoteOpenGrantHandle,
        [Parameter(Mandatory = $true)][Runtime.InteropServices.SafeHandle]$OpenSshTunnelRemoteStatusGrantHandle,
        [Parameter(Mandatory = $true)][Runtime.InteropServices.SafeHandle]$OpenSshTunnelRemoteCancelGrantHandle,
        [Parameter(Mandatory = $true)][Runtime.InteropServices.SafeHandle]$OpenSshTunnelDynamicOpenGrantHandle,
        [Parameter(Mandatory = $true)][Runtime.InteropServices.SafeHandle]$OpenSshTunnelDynamicStatusGrantHandle,
        [Parameter(Mandatory = $true)][Runtime.InteropServices.SafeHandle]$OpenSshTunnelDynamicCancelGrantHandle,
        [Parameter(Mandatory = $true)][Runtime.InteropServices.SafeHandle]$OpenSshSftpTransferGrantHandle,
        [Parameter(Mandatory = $true)][Runtime.InteropServices.SafeHandle]$OpenSshSftpStatusGrantHandle,
        [Parameter(Mandatory = $true)][Runtime.InteropServices.SafeHandle]$OpenSshNativeTransferGrantHandle,
        [Parameter(Mandatory = $true)][Runtime.InteropServices.SafeHandle]$OpenSshNativeStatusGrantHandle,
        [Parameter(Mandatory = $true)][Runtime.InteropServices.SafeHandle]$DropbearSftpTransferGrantHandle,
        [Parameter(Mandatory = $true)][Runtime.InteropServices.SafeHandle]$DropbearSftpStatusGrantHandle,
        [Parameter(Mandatory = $true)][Runtime.InteropServices.SafeHandle]$DropbearNativeTransferGrantHandle,
        [Parameter(Mandatory = $true)][Runtime.InteropServices.SafeHandle]$DropbearNativeStatusGrantHandle,
        [ValidateRange(1, 3600000)][int]$DeadlineMilliseconds = 300000
    )
    try {
        Invoke-ExternalTransferIsolatedOwnerProcessCoreInternal @PSBoundParameters
    }
    finally {
        if ($null -ne $ProtectedConfigBytes) {
            [Array]::Clear($ProtectedConfigBytes, 0, $ProtectedConfigBytes.Length)
        }
    }
}
