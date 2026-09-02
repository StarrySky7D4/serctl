Set-StrictMode -Version Latest

# Windows PowerShell 5.1 does not define the cross-platform `$IsWindows`
# automatic variable. RuntimeInformation is available on every supported
# release host and keeps this shared gate core parseable under both engines.
$script:V1BetaHostIsWindows =
    [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [System.Runtime.InteropServices.OSPlatform]::Windows
    )

function Test-V1BetaPathWithin {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Root
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path).TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    )
    $fullRoot = [System.IO.Path]::GetFullPath($Root).TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar,
        [System.IO.Path]::AltDirectorySeparatorChar
    )
    $comparison = if ($script:V1BetaHostIsWindows) {
        [System.StringComparison]::OrdinalIgnoreCase
    }
    else {
        [System.StringComparison]::Ordinal
    }
    if ($fullPath.Equals($fullRoot, $comparison)) {
        return $true
    }
    $rootPrefix = $fullRoot + [System.IO.Path]::DirectorySeparatorChar
    return $fullPath.StartsWith($rootPrefix, $comparison)
}

function New-V1BetaEvidenceDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][string]$RequestedPath
    )

    if ([string]::IsNullOrWhiteSpace($RequestedPath)) {
        throw 'evidence directory path is empty'
    }
    $requestedFullPath = [System.IO.Path]::GetFullPath($RequestedPath)
    $parentPath = Split-Path -Parent $requestedFullPath
    $leaf = Split-Path -Leaf $requestedFullPath
    if ([string]::IsNullOrWhiteSpace($parentPath) -or [string]::IsNullOrWhiteSpace($leaf)) {
        throw "evidence directory '$RequestedPath' must name a new child of an existing directory"
    }
    if (-not (Test-Path -LiteralPath $parentPath -PathType Container)) {
        throw "evidence directory parent '$parentPath' does not exist"
    }
    $resolvedParent = [System.IO.Path]::GetFullPath(
        (Resolve-Path -LiteralPath $parentPath).ProviderPath
    )
    $candidate = [System.IO.Path]::GetFullPath((Join-Path $resolvedParent $leaf))
    if (Test-V1BetaPathWithin -Path $candidate -Root $RepositoryRoot) {
        throw "evidence directory '$candidate' must be outside the repository"
    }
    if (Test-Path -LiteralPath $candidate) {
        throw "evidence directory '$candidate' already exists; refusing to overwrite it"
    }

    $created = New-Item -ItemType Directory -Path $candidate -ErrorAction Stop
    $createdPath = [System.IO.Path]::GetFullPath($created.FullName)
    if (Test-V1BetaPathWithin -Path $createdPath -Root $RepositoryRoot) {
        throw "created evidence directory '$createdPath' resolved inside the repository"
    }
    if (($created.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "created evidence directory '$createdPath' is a reparse point"
    }
    return $createdPath
}

function Format-V1BetaGateToken {
    param([Parameter(Mandatory = $true)][string]$Token)

    if ($Token -match '[\s"]') {
        return '"' + $Token.Replace('"', '\"') + '"'
    }
    return $Token
}

function New-V1BetaCommandStep {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$File,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [bool]$SkipInQuick = $false,
        [bool]$SuppressStdout = $false,
        [string]$ThenFile,
        [string[]]$ThenArguments = @()
    )

    $first = @($File) + $Arguments | ForEach-Object { Format-V1BetaGateToken $_ }
    $display = $first -join ' '
    if (-not [string]::IsNullOrWhiteSpace($ThenFile)) {
        $second = @($ThenFile) + $ThenArguments | ForEach-Object { Format-V1BetaGateToken $_ }
        $display += ' ; then ' + ($second -join ' ')
    }
    return [pscustomobject]@{
        Name = $Name
        File = $File
        Arguments = [string[]]$Arguments
        SkipInQuick = $SkipInQuick
        SuppressStdout = $SuppressStdout
        ThenFile = $ThenFile
        ThenArguments = [string[]]$ThenArguments
        DisplayCommand = $display
    }
}

function Get-V1BetaLocalGatePlan {
    param(
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][string]$TemporaryDirectory
    )

    $extension = if ($script:V1BetaHostIsWindows) { '.exe' } else { '' }
    $steps = [System.Collections.Generic.List[object]]::new()
    $steps.Add((New-V1BetaCommandStep -Name 'git-diff-check' -File 'git' -Arguments @(
        'diff', '--check'
    )))
    $steps.Add((New-V1BetaCommandStep -Name 'rustfmt' -File 'cargo' -Arguments @(
        'fmt', '--all', '--', '--check'
    )))
    $steps.Add((New-V1BetaCommandStep -Name 'locked-metadata' -File 'cargo' -Arguments @(
        'metadata', '--locked', '--format-version', '1'
    ) -SuppressStdout $true))
    $steps.Add((New-V1BetaCommandStep -Name 'fuzz-locked-metadata' -File 'cargo' -Arguments @(
        'metadata', '--manifest-path', 'fuzz/Cargo.toml', '--locked', '--format-version', '1'
    ) -SuppressStdout $true))
    $steps.Add((New-V1BetaCommandStep -Name 'protocol-corpus-transfer' -File 'cargo' -Arguments @(
        'test', '--locked', '-p', 'serctl-transfer-protocol', '--lib'
    )))
    $steps.Add((New-V1BetaCommandStep -Name 'protocol-corpus-remote' -File 'cargo' -Arguments @(
        'test', '--locked', '-p', 'serctl-remote-protocol', '--lib'
    )))
    $steps.Add((New-V1BetaCommandStep -Name 'protocol-corpus-policy' -File 'cargo' -Arguments @(
        'test', '--locked', '-p', 'serctl-policy', '--lib'
    )))
    $steps.Add((New-V1BetaCommandStep -Name 'runtime-dependency-boundary' -File 'pwsh' -Arguments @(
        '-NoProfile',
        '-File',
        (Join-Path $RepositoryRoot 'scripts/Test-RuntimeDependencyBoundary.ps1'),
        '-Offline'
    )))
    $steps.Add((New-V1BetaCommandStep -Name 'documentation-governance' -File 'pwsh' -Arguments @(
        '-NoProfile', '-File', (Join-Path $RepositoryRoot 'scripts/Test-ReleaseGovernance.ps1')
    )))
    $steps.Add((New-V1BetaCommandStep -Name 'cargo-deny' -File 'cargo' -Arguments @(
        'deny', '--locked', 'check', 'bans', 'licenses', 'sources'
    )))
    $steps.Add((New-V1BetaCommandStep -Name 'workspace-check' -File 'cargo' -Arguments @(
        'check', '--locked', '--workspace', '--all-targets', '--all-features'
    ) -SkipInQuick $true))
    $steps.Add((New-V1BetaCommandStep -Name 'strict-clippy' -File 'cargo' -Arguments @(
        'clippy', '--locked', '--workspace', '--all-targets', '--all-features', '--', '-D', 'warnings'
    ) -SkipInQuick $true))
    $steps.Add((New-V1BetaCommandStep -Name 'serial-tests' -File 'cargo' -Arguments @(
        'test', '--locked', '--workspace', '--all-targets', '--all-features', '--', '--test-threads=1'
    ) -SkipInQuick $true))

    foreach ($fixture in @(
        @{ Name = 'cli'; Source = 'crates/serctl_cli/build.rs' },
        @{ Name = 'daemon'; Source = 'crates/serctl_daemon/build.rs' },
        @{ Name = 'xfer'; Source = 'crates/serctl_xfer/build.rs' },
        @{ Name = 'remote'; Source = 'crates/serctl_remote/build.rs' }
    )) {
        $output = Join-Path $TemporaryDirectory (
            "$($fixture.Name)-build-script-tests$extension"
        )
        $steps.Add((New-V1BetaCommandStep `
            -Name "build-script-$($fixture.Name)" `
            -File 'rustc' `
            -Arguments @(
                '--edition=2021',
                '--test',
                $fixture.Source,
                '-o',
                $output
            ) `
            -ThenFile $output `
            -ThenArguments @('--test-threads=1')
        ))
    }
    return $steps.ToArray()
}

function Invoke-V1BetaLocalGatePlan {
    param(
        [Parameter(Mandatory = $true)][object[]]$Steps,
        [Parameter(Mandatory = $true)][scriptblock]$Runner,
        [Parameter(Mandatory = $true)][scriptblock]$OnRecord,
        [switch]$Quick
    )

    $records = [System.Collections.Generic.List[object]]::new()
    foreach ($step in $Steps) {
        if ($Quick -and $step.SkipInQuick) {
            $record = [pscustomobject]@{
                step = $step.Name
                command = $step.DisplayCommand
                status = 'skipped'
                exit_code = $null
                duration_ms = 0
                reason = 'quick-mode-long-step'
            }
            $records.Add($record)
            & $OnRecord $record
            continue
        }

        $stopwatch = [System.Diagnostics.Stopwatch]::StartNew()
        $exitCode = -1
        $failure = $null
        try {
            # Native command stdout is part of the operator-visible evidence
            # stream. A runner may therefore emit output before returning its
            # final structured result; consume only the final object as the
            # authoritative exit status instead of treating an Object[] as one
            # result and failing under StrictMode member access.
            $runOutput = @(& $Runner $step)
            if ($runOutput.Count -eq 0) {
                throw "runner returned no result for '$($step.Name)'"
            }
            $runResult = $runOutput[$runOutput.Count - 1]
            if ($null -eq $runResult -or $null -eq $runResult.exit_code) {
                throw "runner returned no exit_code for '$($step.Name)'"
            }
            $exitCode = [int]$runResult.exit_code
        }
        catch {
            $failure = $_.Exception.Message
        }
        finally {
            $stopwatch.Stop()
        }
        $record = [pscustomobject]@{
            step = $step.Name
            command = $step.DisplayCommand
            status = if ($exitCode -eq 0 -and $null -eq $failure) { 'passed' } else { 'failed' }
            exit_code = $exitCode
            duration_ms = [long]$stopwatch.ElapsedMilliseconds
            reason = $failure
        }
        $records.Add($record)
        & $OnRecord $record
        if ($record.status -eq 'failed') {
            return [pscustomobject]@{
                success = $false
                failed_step = $step.Name
                records = $records.ToArray()
            }
        }
    }
    return [pscustomobject]@{
        success = $true
        failed_step = $null
        records = $records.ToArray()
    }
}

function Get-V1BetaFinalSourceState {
    param(
        [Parameter(Mandatory = $true)][string]$InitialHead,
        [Parameter(Mandatory = $true)][bool]$InitialDirty,
        [Parameter(Mandatory = $true)][string]$FinalHeadBeforeStatus,
        [Parameter(Mandatory = $true)][string]$FinalHeadAfterStatus,
        [Parameter(Mandatory = $true)][bool]$FinalDirty
    )

    foreach ($commit in @($InitialHead, $FinalHeadBeforeStatus, $FinalHeadAfterStatus)) {
        if ($commit -notmatch '^[0-9a-fA-F]{40}$') {
            throw "source snapshot commit '$commit' is not a full object id"
        }
    }
    $initial = $InitialHead.ToLowerInvariant()
    $before = $FinalHeadBeforeStatus.ToLowerInvariant()
    $after = $FinalHeadAfterStatus.ToLowerInvariant()
    $headUnchanged = $before -ceq $initial -and $after -ceq $initial
    $initialClean = -not $InitialDirty
    $finalClean = -not $FinalDirty
    return [pscustomobject]@{
        initial_head = $initial
        initial_clean = $initialClean
        final_head_before_status = $before
        final_head = $after
        head_unchanged = $headUnchanged
        final_clean = $finalClean
        source_snapshot_stable = $initialClean -and $headUnchanged -and $finalClean
    }
}

function Get-V1BetaLocalGateExitCode {
    param(
        [Parameter(Mandatory = $true)][bool]$Success,
        [Parameter(Mandatory = $true)][bool]$Quick,
        [Parameter(Mandatory = $true)][bool]$SourceSnapshotStable
    )

    if (-not $Success) {
        return 1
    }
    if ($Quick -or -not $SourceSnapshotStable) {
        return 2
    }
    return 0
}
