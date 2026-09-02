[CmdletBinding()]
param(
    [switch]$Quick,

    [string]$EvidenceDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'V1BetaLocalGate.Core.ps1')

function Invoke-ContextCommand {
    param(
        [Parameter(Mandatory = $true)][string]$File,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )

    $output = @(& $File @Arguments 2>&1)
    $exitCode = $LASTEXITCODE
    if ($exitCode -ne 0) {
        throw "context command '$File $($Arguments -join ' ')' failed with exit $exitCode"
    }
    return ($output | Out-String).Trim()
}

function Write-NdjsonEvent {
    param(
        [System.IO.StreamWriter]$Writer,
        [Parameter(Mandatory = $true)][object]$Event
    )

    if ($null -ne $Writer) {
        $Writer.WriteLine(($Event | ConvertTo-Json -Compress -Depth 30))
        $Writer.Flush()
    }
}

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$temporaryRoot = $null
$evidenceWriter = $null
$evidencePath = $null
$exitCode = 1
$head = $null
$worktreeDirty = $null
$finalHead = $null
$finalWorktreeDirty = $null
$sourceSnapshotStable = $false
$cargoVersion = $null
$rustcVersion = $null
$startedAt = [DateTimeOffset]::UtcNow

try {
    if (-not [string]::IsNullOrWhiteSpace($EvidenceDirectory)) {
        $createdEvidenceDirectory = New-V1BetaEvidenceDirectory `
            -RepositoryRoot $repositoryRoot `
            -RequestedPath $EvidenceDirectory
        $evidencePath = Join-Path $createdEvidenceDirectory 'v1-beta-local-gate.ndjson'
        $stream = [System.IO.FileStream]::new(
            $evidencePath,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::Read,
            4096,
            [System.IO.FileOptions]::WriteThrough
        )
        $evidenceWriter = [System.IO.StreamWriter]::new(
            $stream,
            [System.Text.UTF8Encoding]::new($false)
        )
        $evidenceWriter.AutoFlush = $true
        Write-Host "Evidence (create-new): $evidencePath"
    }
    else {
        Write-Host 'Evidence: stdout only (no repository or filesystem evidence file will be created).'
    }

    Push-Location -LiteralPath $repositoryRoot
    try {
        $head = Invoke-ContextCommand -File 'git' -Arguments @('rev-parse', 'HEAD')
        if ($head -notmatch '^[0-9a-fA-F]{40}$') {
            throw "HEAD '$head' is not a full commit id"
        }
        $statusLines = @(& git status --porcelain=v1 --untracked-files=all 2>&1)
        if ($LASTEXITCODE -ne 0) {
            throw 'git status failed while collecting worktree state'
        }
        $worktreeDirty = $statusLines.Count -gt 0
        $cargoVersion = Invoke-ContextCommand -File 'cargo' -Arguments @('--version')
        $rustcVersion = Invoke-ContextCommand -File 'rustc' -Arguments @('--version', '--verbose')

        $context = [ordered]@{
            schema_version = 1
            event = 'run_started'
            started_utc = $startedAt.ToString('o')
            head = $head.ToLowerInvariant()
            worktree_dirty = $worktreeDirty
            quick = [bool]$Quick
            cargo = $cargoVersion
            rustc = $rustcVersion
            powershell = $PSVersionTable.PSVersion.ToString()
            platform = [System.Runtime.InteropServices.RuntimeInformation]::OSDescription
        }
        Write-Host "HEAD: $($context.head)"
        Write-Host "Worktree dirty: $worktreeDirty"
        Write-Host "Cargo: $cargoVersion"
        Write-Host "Rustc:`n$rustcVersion"
        if ($Quick) {
            Write-Warning (
                'Quick mode skips workspace check, strict Clippy, and serial tests. ' +
                'Its result is never acceptance-eligible and exits with code 2 when all executed steps pass.'
            )
        }
        if ($worktreeDirty) {
            Write-Warning (
                'The worktree is dirty. Commands will still run, but the result is not tied to HEAD ' +
                'and is never acceptance-eligible.'
            )
        }
        Write-NdjsonEvent -Writer $evidenceWriter -Event $context

        $temporaryBase = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
        $temporaryRoot = Join-Path $temporaryBase (
            'serctl-v1-beta-local-gate-' + [System.Guid]::NewGuid().ToString('N')
        )
        if (Test-Path -LiteralPath $temporaryRoot) {
            throw "generated temporary path '$temporaryRoot' already exists"
        }
        New-Item -ItemType Directory -Path $temporaryRoot -ErrorAction Stop | Out-Null

        $plan = @(Get-V1BetaLocalGatePlan `
            -RepositoryRoot $repositoryRoot `
            -TemporaryDirectory $temporaryRoot)

        $runner = {
            param($step)

            Write-Host "RUN [$($step.Name)] $($step.DisplayCommand)"
            $nativeArguments = [string[]]$step.Arguments
            if ($step.SuppressStdout) {
                & $step.File @nativeArguments | Out-Null
            }
            else {
                # Preserve native stdout/stderr for the operator without
                # returning those lines from this runner scriptblock; the last
                # success-stream object must remain the structured exit result.
                & $step.File @nativeArguments 2>&1 | ForEach-Object {
                    Write-Host $_
                }
            }
            $nativeExit = $LASTEXITCODE
            if ($nativeExit -eq 0 -and -not [string]::IsNullOrWhiteSpace($step.ThenFile)) {
                $thenArguments = [string[]]$step.ThenArguments
                & $step.ThenFile @thenArguments 2>&1 | ForEach-Object {
                    Write-Host $_
                }
                $nativeExit = $LASTEXITCODE
            }
            return [pscustomobject]@{ exit_code = [int]$nativeExit }
        }.GetNewClosure()

        $onRecord = {
            param($record)

            if ($record.status -eq 'skipped') {
                Write-Warning "SKIP [$($record.step)] $($record.command) ($($record.reason))"
            }
            else {
                Write-Host (
                    "RESULT [$($record.step)] $($record.status) exit=$($record.exit_code) " +
                    "duration_ms=$($record.duration_ms)"
                )
            }
            $event = [ordered]@{
                schema_version = 1
                event = 'step_completed'
                recorded_utc = [DateTimeOffset]::UtcNow.ToString('o')
                head = $head.ToLowerInvariant()
                worktree_dirty = $worktreeDirty
                quick = [bool]$Quick
                cargo = $cargoVersion
                rustc = $rustcVersion
                step = $record.step
                command = $record.command
                status = $record.status
                exit_code = $record.exit_code
                duration_ms = $record.duration_ms
                reason = $record.reason
            }
            Write-NdjsonEvent -Writer $evidenceWriter -Event $event
        }.GetNewClosure()

        $result = Invoke-V1BetaLocalGatePlan `
            -Steps $plan `
            -Runner $runner `
            -OnRecord $onRecord `
            -Quick:$Quick

        # Bracket the final porcelain snapshot with two HEAD reads. This closes
        # the obvious checkout race during `git status`: both HEAD values must
        # still equal the identity captured before the first gate command.
        $finalHeadBeforeStatus = Invoke-ContextCommand `
            -File 'git' `
            -Arguments @('rev-parse', 'HEAD')
        $finalStatusLines = @(& git status --porcelain=v1 --untracked-files=all 2>&1)
        if ($LASTEXITCODE -ne 0) {
            throw 'git status failed while collecting final worktree state'
        }
        $finalWorktreeDirty = $finalStatusLines.Count -gt 0
        $finalHead = Invoke-ContextCommand -File 'git' -Arguments @('rev-parse', 'HEAD')
        $sourceState = Get-V1BetaFinalSourceState `
            -InitialHead $head `
            -InitialDirty ([bool]$worktreeDirty) `
            -FinalHeadBeforeStatus $finalHeadBeforeStatus `
            -FinalHeadAfterStatus $finalHead `
            -FinalDirty ([bool]$finalWorktreeDirty)
        $sourceSnapshotStable = [bool]$sourceState.source_snapshot_stable
        Write-NdjsonEvent -Writer $evidenceWriter -Event ([ordered]@{
            schema_version = 1
            event = 'source_rechecked'
            recorded_utc = [DateTimeOffset]::UtcNow.ToString('o')
            initial_head = $sourceState.initial_head
            initial_clean = $sourceState.initial_clean
            final_head_before_status = $sourceState.final_head_before_status
            final_head = $sourceState.final_head
            head_unchanged = $sourceState.head_unchanged
            final_clean = $sourceState.final_clean
            final_worktree_dirty = $finalWorktreeDirty
            source_snapshot_stable = $sourceSnapshotStable
        })
        Write-Host "Final HEAD: $($sourceState.final_head)"
        Write-Host "Final worktree dirty: $finalWorktreeDirty"
        Write-Host "Source snapshot stable: $sourceSnapshotStable"
        if (-not $sourceSnapshotStable) {
            Write-Warning (
                'HEAD/worktree identity was not clean and unchanged across the gate. ' +
                'The result cannot be acceptance evidence.'
            )
        }

        $temporaryFullPath = [System.IO.Path]::GetFullPath($temporaryRoot)
        if (-not (Test-V1BetaPathWithin -Path $temporaryFullPath -Root $temporaryBase) -or
            -not ([System.IO.Path]::GetFileName($temporaryFullPath).StartsWith(
                'serctl-v1-beta-local-gate-',
                [System.StringComparison]::Ordinal
            ))) {
            throw "refusing to remove unverified temporary directory '$temporaryFullPath'"
        }
        [System.IO.Directory]::Delete($temporaryFullPath, $true)
        $temporaryRoot = $null

        $acceptanceEligible = (
            $result.success -and -not $Quick -and $sourceSnapshotStable
        )
        $completed = [ordered]@{
            schema_version = 1
            event = 'run_completed'
            completed_utc = [DateTimeOffset]::UtcNow.ToString('o')
            head = $head.ToLowerInvariant()
            worktree_dirty = $worktreeDirty
            final_head_before_status = $sourceState.final_head_before_status
            final_head = $sourceState.final_head
            final_worktree_dirty = $finalWorktreeDirty
            head_unchanged = $sourceState.head_unchanged
            final_clean = $sourceState.final_clean
            source_snapshot_stable = $sourceSnapshotStable
            quick = [bool]$Quick
            success = [bool]$result.success
            failed_step = $result.failed_step
            local_gate_eligible = $acceptanceEligible
            release_accepted = $false
            note = if ($acceptanceEligible) {
                'Full clean local gate passed; exact-tag CI, external E2E, artifacts and attestations remain separate.'
            }
            elseif (-not $result.success) {
                'A gate step failed.'
            }
            elseif (-not $sourceState.head_unchanged) {
                'HEAD changed during the gate or final source recheck, so results are not bound to one commit.'
            }
            elseif (-not $sourceState.final_clean) {
                'The final worktree is dirty, so results are not acceptance evidence.'
            }
            elseif (-not $sourceState.initial_clean) {
                'The initial worktree was dirty, so tested content was not bound to HEAD.'
            }
            elseif ($Quick) {
                'Quick mode is incomplete and cannot be acceptance evidence.'
            }
            else {
                'Source evidence is not acceptance-eligible.'
            }
        }
        Write-NdjsonEvent -Writer $evidenceWriter -Event $completed
        Write-Host "Local gate success: $($result.success)"
        Write-Host "Local gate acceptance-eligible: $acceptanceEligible"
        Write-Host 'Release accepted: false (requires the remaining exact-tag acceptance matrix).'

        $exitCode = Get-V1BetaLocalGateExitCode `
            -Success ([bool]$result.success) `
            -Quick ([bool]$Quick) `
            -SourceSnapshotStable $sourceSnapshotStable
    }
    finally {
        Pop-Location
    }
}
catch {
    $message = $_.Exception.Message
    [Console]::Error.WriteLine("V1 beta local gate failed: $message")
    Write-NdjsonEvent -Writer $evidenceWriter -Event ([ordered]@{
        schema_version = 1
        event = 'run_failed'
        failed_utc = [DateTimeOffset]::UtcNow.ToString('o')
        head = $head
        worktree_dirty = $worktreeDirty
        final_head = $finalHead
        final_worktree_dirty = $finalWorktreeDirty
        source_snapshot_stable = $sourceSnapshotStable
        quick = [bool]$Quick
        error = $message
        release_accepted = $false
    })
    $exitCode = 1
}
finally {
    if ($null -ne $evidenceWriter) {
        $evidenceWriter.Dispose()
    }
    if ($null -ne $temporaryRoot -and (Test-Path -LiteralPath $temporaryRoot -PathType Container)) {
        try {
            $temporaryBase = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
            $temporaryFullPath = [System.IO.Path]::GetFullPath($temporaryRoot)
            if ((Test-V1BetaPathWithin -Path $temporaryFullPath -Root $temporaryBase) -and
                [System.IO.Path]::GetFileName($temporaryFullPath).StartsWith(
                    'serctl-v1-beta-local-gate-',
                    [System.StringComparison]::Ordinal
                )) {
                [System.IO.Directory]::Delete($temporaryFullPath, $true)
            }
            else {
                [Console]::Error.WriteLine("refusing fallback cleanup of '$temporaryFullPath'")
                $exitCode = 1
            }
        }
        catch {
            [Console]::Error.WriteLine(
                "temporary gate cleanup failed: $($_.Exception.Message)"
            )
            $exitCode = 1
        }
    }
}

exit $exitCode
