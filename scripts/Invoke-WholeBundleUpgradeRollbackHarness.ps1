[CmdletBinding(DefaultParameterSetName = 'Inspect')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Inspect')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Runtime')]
    [ValidateNotNullOrEmpty()]
    [string]$PredecessorDirectory,

    [Parameter(Mandatory = $true, ParameterSetName = 'Inspect')]
    [Parameter(Mandatory = $true, ParameterSetName = 'Runtime')]
    [ValidateNotNullOrEmpty()]
    [string]$CandidateDirectory,

    [Parameter(ParameterSetName = 'Inspect')]
    [Parameter(ParameterSetName = 'Runtime')]
    [ValidatePattern('^1\.0\.0-beta(?:\.(?:0|[1-9][0-9]*))?$')]
    [string]$CandidateVersion = '1.0.0-beta',

    [Parameter(ParameterSetName = 'Inspect')]
    [ValidateNotNullOrEmpty()]
    [string]$ReportPath,

    [Parameter(Mandatory = $true, ParameterSetName = 'SelfTest')]
    [switch]$SelfTest,

    [Parameter(Mandatory = $true, ParameterSetName = 'Runtime')]
    [ValidateNotNullOrEmpty()]
    [string]$RuntimeFixtureDirectory,

    [Parameter(Mandatory = $true, ParameterSetName = 'Runtime')]
    [ValidatePattern('^[A-Za-z0-9._-]{1,64}$')]
    [string]$RuntimeProfileName,

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
    [string]$EvidenceOwner
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'StrictJson.ps1')

$predecessorVersion = '0.3.0-beta.2'
$predecessorIpc = 'IPC v8..=v8'
$candidateIpc = 'IPC v9..=v9'
$transferProtocol = 'transfer protocol v1'
$candidateStorageMarker = 'vault-storage read=v4..=v5 write=v5'
$reportSchemaVersion = 1

function Assert-HarnessCondition {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if (-not $Condition) {
        throw "upgrade/rollback harness failed: $Message"
    }
}

function Assert-Beta2RuntimeRejectionObservation {
    param([Parameter(Mandatory = $true)]$Evidence)

    $expectedFields = @(
        'beta2_runtime_state_cleaned_after_rejection',
        'beta2_transient_runtime_activation_observed'
    )
    Assert-HarnessCondition (
        ((@($Evidence.Keys) | Sort-Object) -join ',') -ceq
        (($expectedFields | Sort-Object) -join ',')
    ) 'beta-2 runtime rejection observation does not use the exact closed schema'
    foreach ($field in $expectedFields) {
        Assert-HarnessCondition ($Evidence[$field] -is [bool]) (
            "beta-2 runtime rejection observation '$field' is not a boolean"
        )
    }
    # Either observed value is valid: false means only that the bounded monitor
    # did not see a transient artifact, never that activation was impossible.
    Assert-HarnessCondition $Evidence.beta2_runtime_state_cleaned_after_rejection (
        'beta-2 runtime rejection did not clean descriptor/secret terminal state'
    )
}

function Wait-Beta2RuntimeStateCleanup {
    param(
        [Parameter(Mandatory = $true)][string]$DescriptorPath,
        [Parameter(Mandatory = $true)][string]$SecretPath,
        [int]$TimeoutSeconds = 15
    )

    $deadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
    do {
        if (
            -not (Test-Path -LiteralPath $DescriptorPath) -and
            -not (Test-Path -LiteralPath $SecretPath)
        ) {
            return $true
        }
        Start-Sleep -Milliseconds 25
    } while ([DateTimeOffset]::UtcNow -lt $deadline)
    return (
        -not (Test-Path -LiteralPath $DescriptorPath) -and
        -not (Test-Path -LiteralPath $SecretPath)
    )
}

function Write-NewUtf8Text {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Text
    )

    $stream = [System.IO.FileStream]::new(
        $Path,
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None,
        4096,
        [System.IO.FileOptions]::WriteThrough
    )
    try {
        $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($Text)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
}

function Invoke-AuditSeedStorageDirectionFixture {
    $repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
    $exactTests = @(
        'recovery::tests::whole_bundle_storage_direction_fixture',
        'vault::tests::audit_record_format_blocks_beta2_destructive_writer_before_callback'
    )
    foreach ($exactTest in $exactTests) {
        $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = 'cargo'
        $startInfo.Arguments = (
            'test --locked --offline -p serctl-core --lib ' +
            $exactTest + ' -- --exact'
        )
        $startInfo.WorkingDirectory = $repositoryRoot
        $startInfo.UseShellExecute = $false
        $startInfo.CreateNoWindow = $true
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $process = [System.Diagnostics.Process]::new()
        $process.StartInfo = $startInfo
        try {
            Assert-HarnessCondition $process.Start() (
                "could not start executable storage-direction source fixture '$exactTest'"
            )
            $stdout = $process.StandardOutput.ReadToEndAsync()
            $stderr = $process.StandardError.ReadToEndAsync()
            $exited = $process.WaitForExit(600000)
            if (-not $exited) {
                try {
                    $process.Kill()
                    $process.WaitForExit()
                }
                catch {
                    # Preserve the primary bounded-timeout classification. The
                    # Process object is still disposed by the outer finally.
                }
                throw "upgrade/rollback harness failed: storage-direction source fixture '$exactTest' exceeded its 600-second deadline"
            }
            $capturedStdout = $stdout.GetAwaiter().GetResult()
            $capturedStderr = $stderr.GetAwaiter().GetResult()
            Assert-HarnessCondition ($process.ExitCode -eq 0) (
                "executable storage-direction source fixture '$exactTest' failed"
            )
            Assert-HarnessCondition (
                [regex]::Matches(
                    $capturedStdout,
                    '(?m)^test ' + [regex]::Escape($exactTest) + ' \.\.\. ok\r?$'
                ).Count -eq 1
            ) "storage-direction fixture '$exactTest' did not execute exactly once"
            Assert-HarnessCondition (
                $capturedStdout -cmatch '(?m)^running 1 test\r?$' -and
                $capturedStdout -cmatch (
                    '(?m)^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; ' +
                    '[0-9]+ filtered out; finished in .+\r?$'
                )
            ) "storage-direction fixture '$exactTest' lacks an exact passing terminal state"
            # Captured process output may contain compiler diagnostics but must
            # not be reused as evidence without the exact libtest terminal
            # state above. Keep both streams local and bounded by process exit.
            $capturedStderr | Out-Null
        }
        finally {
            $process.Dispose()
        }
    }
}

function Assert-CandidateMatchesStorageFixtureSource {
    param(
        [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{12}$')]
        [string]$CandidateCommit,
        [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{40}$')]
        [string]$SourceCommit
    )

    Assert-HarnessCondition (
        $CandidateCommit -ceq $SourceCommit.Substring(0, 12)
    ) (
        "candidate commit '$CandidateCommit' does not match the storage " +
        "fixture source commit '$SourceCommit'"
    )
}

function Get-CleanStorageFixtureSourceCommit {
    $repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
    $status = @(& git -C $repositoryRoot status --porcelain=v1 --untracked-files=all)
    Assert-HarnessCondition ($LASTEXITCODE -eq 0) (
        'could not inspect the storage fixture source worktree'
    )
    Assert-HarnessCondition ($status.Count -eq 0) (
        'storage fixture source worktree is dirty; exact candidate binding is unknown'
    )
    $sourceCommit = (& git -C $repositoryRoot rev-parse --verify HEAD | Out-String).Trim()
    Assert-HarnessCondition (
        $LASTEXITCODE -eq 0 -and $sourceCommit -cmatch '^[0-9a-f]{40}$'
    ) 'storage fixture source HEAD is not one canonical full commit'
    return $sourceCommit
}

function Get-PlatformComponentNames {
    if ([System.IO.Path]::DirectorySeparatorChar -eq '\') {
        return [ordered]@{
            cli = 'serctl_cli.exe'
            daemon = 'serctl_daemon.exe'
            helper = 'serctl-xfer.exe'
        }
    }
    return [ordered]@{
        cli = 'serctl_cli'
        daemon = 'serctl_daemon'
        helper = 'serctl-xfer'
    }
}

function Get-DirectoryPath {
    param([Parameter(Mandatory = $true)][string]$Path)

    $resolved = [System.IO.Path]::GetFullPath(
        (Resolve-Path -LiteralPath $Path -ErrorAction Stop).ProviderPath
    )
    $item = Get-Item -LiteralPath $resolved -Force
    Assert-HarnessCondition $item.PSIsContainer "'$resolved' is not a directory"
    Assert-HarnessCondition (
        ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0
    ) "bundle directory '$resolved' is a reparse point"
    return $resolved
}

function Get-BundleInventory {
    param([Parameter(Mandatory = $true)][string]$Root)

    $inventory = [ordered]@{}
    $entries = @(Get-ChildItem -LiteralPath $Root -Force | Sort-Object Name)
    Assert-HarnessCondition ($entries.Count -gt 0) "bundle '$Root' is empty"
    foreach ($entry in $entries) {
        Assert-HarnessCondition (-not $entry.PSIsContainer) (
            "bundle '$Root' contains nested directory '$($entry.Name)'"
        )
        Assert-HarnessCondition (
            ($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0
        ) "bundle input '$($entry.FullName)' is a reparse point"
        $inventory[$entry.Name] = [ordered]@{
            length = [long]$entry.Length
            sha256 = (Get-FileHash -LiteralPath $entry.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
        }
    }
    return $inventory
}

function Get-IsolatedEnvironmentSnapshot {
    param([Parameter(Mandatory = $true)][string]$Root)

    $snapshot = [ordered]@{}
    if (-not (Test-Path -LiteralPath $Root)) {
        return $snapshot
    }
    $rootPath = [System.IO.Path]::GetFullPath($Root).TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar
    )
    foreach ($entry in Get-ChildItem -LiteralPath $rootPath -Force -Recurse | Sort-Object FullName) {
        $relative = $entry.FullName.Substring($rootPath.Length).TrimStart(
            [System.IO.Path]::DirectorySeparatorChar
        )
        if ($entry.PSIsContainer) {
            $snapshot[$relative + '/'] = 'directory'
        }
        else {
            $snapshot[$relative] = (
                Get-FileHash -LiteralPath $entry.FullName -Algorithm SHA256
            ).Hash.ToLowerInvariant()
        }
    }
    return $snapshot
}

function Assert-SnapshotsEqual {
    param(
        [Parameter(Mandatory = $true)]$Expected,
        [Parameter(Mandatory = $true)]$Actual,
        [Parameter(Mandatory = $true)][string]$Context
    )

    $expectedJson = $Expected | ConvertTo-Json -Depth 8 -Compress
    $actualJson = $Actual | ConvertTo-Json -Depth 8 -Compress
    Assert-HarnessCondition ($expectedJson -ceq $actualJson) (
        "$Context changed isolated persistent state"
    )
}

function Get-RequiredRecoverySetEntry {
    param(
        [Parameter(Mandatory = $true)]$Evidence,
        [Parameter(Mandatory = $true)][string]$RelativePath,
        [Parameter(Mandatory = $true)][string]$Context
    )

    $normalizedRequired = $RelativePath.Replace('\', '/')
    $matches = @($Evidence.Keys | Where-Object {
        ([string]$_).Replace('\', '/').Equals(
            $normalizedRequired,
            [StringComparison]::OrdinalIgnoreCase
        )
    })
    Assert-HarnessCondition ($matches.Count -eq 1) (
        "$Context must contain exactly one '$RelativePath'"
    )
    return $Evidence[$matches[0]]
}

function Assert-CompleteRecoverySetEvidence {
    param(
        [Parameter(Mandatory = $true)]$Evidence,
        [Parameter(Mandatory = $true)][string]$Context
    )

    foreach ($relativePath in @(
        'home/.serctl/vault.json',
        'recovery-media.srrec'
    )) {
        $entry = Get-RequiredRecoverySetEntry `
            -Evidence $Evidence `
            -RelativePath $relativePath `
            -Context $Context
        Assert-HarnessCondition ($entry.kind -ceq 'file') (
            "$Context '$relativePath' is not a regular file"
        )
        Assert-HarnessCondition (
            $entry.length -is [long] -and [long]$entry.length -gt 0
        ) "$Context '$relativePath' has an invalid length"
        Assert-HarnessCondition (
            [string]$entry.sha256 -cmatch '^[0-9A-F]{64}$'
        ) "$Context '$relativePath' has an invalid SHA-256"
        Assert-HarnessCondition (
            -not [string]::IsNullOrWhiteSpace([string]$entry.sddl) -and
            [string]$entry.sddl -cmatch '(^|\))O:'
        ) "$Context '$relativePath' lacks ACL/owner metadata"
    }
}

function Assert-RuntimeRecoverySetRestored {
    param(
        [Parameter(Mandatory = $true)]$Expected,
        [Parameter(Mandatory = $true)]$Actual
    )

    Assert-CompleteRecoverySetEvidence `
        -Evidence $Expected `
        -Context 'exact pre-upgrade recovery set'
    Assert-CompleteRecoverySetEvidence `
        -Evidence $Actual `
        -Context 'restored recovery set'
    Assert-SnapshotsEqual `
        -Expected $Expected `
        -Actual $Actual `
        -Context 'runtime recovery set'
}

function Invoke-VersionOnly {
    param(
        [Parameter(Mandatory = $true)][string]$BinaryPath,
        [Parameter(Mandatory = $true)][string]$IsolationRoot,
        [Parameter(Mandatory = $true)][bool]$FixtureMode
    )

    if ($FixtureMode) {
        $fixtureLine = Get-Content -LiteralPath $BinaryPath -Encoding utf8 -TotalCount 1
        $fixturePrefix = 'SERCTL_HARNESS_TEST_IDENTITY:'
        Assert-HarnessCondition $fixtureLine.StartsWith($fixturePrefix) (
            "fixture '$BinaryPath' lacks the test-only identity marker"
        )
        return $fixtureLine.Substring($fixturePrefix.Length)
    }

    $homeRoot = Join-Path $IsolationRoot 'home'
    $localRoot = Join-Path $IsolationRoot 'local-app-data'
    $roamingRoot = Join-Path $IsolationRoot 'roaming-app-data'
    $tempRoot = Join-Path $IsolationRoot 'temp'
    foreach ($path in @($homeRoot, $localRoot, $roamingRoot, $tempRoot)) {
        [System.IO.Directory]::CreateDirectory($path) | Out-Null
    }

    $variables = @('HOME', 'USERPROFILE', 'LOCALAPPDATA', 'APPDATA', 'TEMP', 'TMP', 'XDG_CONFIG_HOME', 'XDG_STATE_HOME')
    $saved = @{}
    foreach ($name in $variables) {
        $saved[$name] = [System.Environment]::GetEnvironmentVariable($name, 'Process')
    }
    try {
        [System.Environment]::SetEnvironmentVariable('HOME', $homeRoot, 'Process')
        [System.Environment]::SetEnvironmentVariable('USERPROFILE', $homeRoot, 'Process')
        [System.Environment]::SetEnvironmentVariable('LOCALAPPDATA', $localRoot, 'Process')
        [System.Environment]::SetEnvironmentVariable('APPDATA', $roamingRoot, 'Process')
        [System.Environment]::SetEnvironmentVariable('TEMP', $tempRoot, 'Process')
        [System.Environment]::SetEnvironmentVariable('TMP', $tempRoot, 'Process')
        [System.Environment]::SetEnvironmentVariable('XDG_CONFIG_HOME', (Join-Path $homeRoot 'config'), 'Process')
        [System.Environment]::SetEnvironmentVariable('XDG_STATE_HOME', (Join-Path $homeRoot 'state'), 'Process')
        $before = Get-IsolatedEnvironmentSnapshot -Root $IsolationRoot
        $line = (& $BinaryPath --version | Out-String).Trim()
        Assert-HarnessCondition ($LASTEXITCODE -eq 0) "'$BinaryPath --version' failed"
        Assert-HarnessCondition (-not [string]::IsNullOrWhiteSpace($line)) (
            "'$BinaryPath --version' returned no identity"
        )
        Assert-HarnessCondition (-not $line.Contains("`r") -and -not $line.Contains("`n")) (
            "'$BinaryPath --version' returned multiple lines"
        )
        $after = Get-IsolatedEnvironmentSnapshot -Root $IsolationRoot
        Assert-SnapshotsEqual -Expected $before -Actual $after -Context "'$BinaryPath --version'"
        return $line
    }
    finally {
        foreach ($name in $variables) {
            [System.Environment]::SetEnvironmentVariable($name, $saved[$name], 'Process')
        }
    }
}

function Get-ExactComponentCommit {
    param(
        [Parameter(Mandatory = $true)][string]$Kind,
        [Parameter(Mandatory = $true)][string]$Identity,
        [Parameter(Mandatory = $true)][string]$ExpectedVersion,
        [Parameter(Mandatory = $true)][string]$ExpectedIpc
    )

    $version = [regex]::Escape($ExpectedVersion)
    $isCandidate = $ExpectedIpc -ceq $candidateIpc
    $pattern = switch ($Kind) {
        'cli' {
            if ($isCandidate) {
                '^serctl_cli ' + $version + ' \(git (?<commit>[0-9a-f]{12}); ' +
                [regex]::Escape($candidateStorageMarker) + '\)$'
            }
            else {
                '^serctl_cli ' + $version + ' \(git (?<commit>[0-9a-f]{12})\)$'
            }
        }
        'daemon' {
            '^serctl_daemon ' + $version + ' \(git (?<commit>[0-9a-f]{12}); ' +
            [regex]::Escape($ExpectedIpc) + $(if ($isCandidate) {
                '; ' + [regex]::Escape($candidateStorageMarker)
            } else { '' }) + '\)$'
        }
        'helper' {
            '^serctl-xfer ' + $version + ' \(git (?<commit>[0-9a-f]{12}); ' +
            [regex]::Escape($transferProtocol) + '\)$'
        }
        default { throw "upgrade/rollback harness failed: unknown component kind '$Kind'" }
    }
    $match = [regex]::Match(
        $Identity,
        $pattern,
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
    Assert-HarnessCondition $match.Success (
        "'$Kind' identity does not match the exact release grammar: $Identity"
    )
    return $match.Groups['commit'].Value
}

function Get-CheckedBundle {
    param(
        [Parameter(Mandatory = $true)][string]$Directory,
        [Parameter(Mandatory = $true)][string]$ExpectedVersion,
        [Parameter(Mandatory = $true)][string]$ExpectedIpc,
        [Parameter(Mandatory = $true)][string]$IsolationRoot,
        [Parameter(Mandatory = $true)][bool]$FixtureMode
    )

    $root = Get-DirectoryPath -Path $Directory
    $names = Get-PlatformComponentNames
    $inventory = Get-BundleInventory -Root $root
    $components = [ordered]@{}
    $sharedCommit = $null
    foreach ($kind in $names.Keys) {
        $name = $names[$kind]
        $path = Join-Path $root $name
        Assert-HarnessCondition (Test-Path -LiteralPath $path -PathType Leaf) (
            "bundle '$root' is missing '$name'"
        )
        $item = Get-Item -LiteralPath $path -Force
        Assert-HarnessCondition (
            ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0
        ) "bundle component '$path' is a reparse point"
        $identity = Invoke-VersionOnly `
            -BinaryPath $path `
            -IsolationRoot $IsolationRoot `
            -FixtureMode $FixtureMode
        $commit = Get-ExactComponentCommit `
            -Kind $kind `
            -Identity $identity `
            -ExpectedVersion $ExpectedVersion `
            -ExpectedIpc $ExpectedIpc
        if ($null -eq $sharedCommit) {
            $sharedCommit = $commit
        }
        else {
            Assert-HarnessCondition ($commit -ceq $sharedCommit) (
                "bundle '$root' mixes commits '$sharedCommit' and '$commit'"
            )
        }
        $components[$kind] = [ordered]@{
            file_name = $name
            length = [long]$inventory[$name].length
            sha256 = [string]$inventory[$name].sha256
            identity = $identity
            commit = $commit
        }
    }
    $finalInventory = Get-BundleInventory -Root $root
    Assert-SnapshotsEqual `
        -Expected $inventory `
        -Actual $finalInventory `
        -Context "bundle '$root' identity and hash inspection"
    foreach ($kind in $components.Keys) {
        $component = $components[$kind]
        Assert-HarnessCondition (
            [long]$inventory[$component.file_name].length -eq [long]$component.length -and
            [string]$inventory[$component.file_name].sha256 -ceq [string]$component.sha256
        ) "bundle component '$($component.file_name)' changed during inspection"
    }
    return [ordered]@{
        directory = $root
        version = $ExpectedVersion
        commit = $sharedCommit
        ipc = $ExpectedIpc
        transfer_protocol = $transferProtocol
        components = $components
        inventory = $inventory
    }
}

function Get-BundleSelectionDigest {
    param([Parameter(Mandatory = $true)]$Bundle)

    $lines = @(
        "version=$($Bundle.version)",
        "commit=$($Bundle.commit)",
        "ipc=$($Bundle.ipc)",
        "transfer_protocol=$($Bundle.transfer_protocol)"
    )
    foreach ($kind in @('cli', 'daemon', 'helper')) {
        $component = $Bundle.components[$kind]
        $lines += "$kind=$($component.file_name):$($component.length):$($component.sha256):$($component.identity)"
    }
    foreach ($fileName in $Bundle.inventory.Keys) {
        $file = $Bundle.inventory[$fileName]
        $lines += "file=${fileName}:$($file.length):$($file.sha256)"
    }
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes(($lines -join "`n") + "`n")
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

function Test-SelectedSet {
    param(
        [Parameter(Mandatory = $true)]$Expected,
        [Parameter(Mandatory = $true)]$CliComponent,
        [Parameter(Mandatory = $true)]$DaemonComponent,
        [Parameter(Mandatory = $true)]$HelperComponent
    )

    return (
        $CliComponent.sha256 -ceq $Expected.components.cli.sha256 -and
        $DaemonComponent.sha256 -ceq $Expected.components.daemon.sha256 -and
        $HelperComponent.sha256 -ceq $Expected.components.helper.sha256 -and
        $CliComponent.commit -ceq $Expected.commit -and
        $DaemonComponent.commit -ceq $Expected.commit -and
        $HelperComponent.commit -ceq $Expected.commit -and
        $CliComponent.identity.Contains($Expected.version) -and
        $DaemonComponent.identity.Contains($Expected.ipc) -and
        $HelperComponent.identity.Contains($Expected.transfer_protocol)
    )
}

function Get-ActiveReference {
    param([Parameter(Mandatory = $true)][string]$Path)

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    Assert-HarnessCondition (-not $item.PSIsContainer) (
        "active bundle reference '$Path' is not a regular file"
    )
    Assert-HarnessCondition (
        ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0
    ) "active bundle reference '$Path' is a reparse point"
    Assert-HarnessCondition ($item.Length -gt 0 -and $item.Length -le 4096) (
        "active bundle reference '$Path' is empty or exceeds 4096 bytes"
    )
    try {
        $encoded = Read-StrictUtf8Text -Path $item.FullName
        $reference = ConvertFrom-StrictJson `
            -Json $encoded `
            -Label 'active bundle reference' `
            -MaxChars 4096 `
            -MaxDepth 4 `
            -MaxKeyChars 64
    }
    catch {
        throw "upgrade/rollback harness failed: active bundle reference '$Path' is not strict UTF-8 JSON"
    }
    Assert-HarnessCondition (Test-StrictJsonObject $reference) (
        "active bundle reference '$Path' is not a JSON object"
    )
    $actualProperties = @($reference.PSObject.Properties.Name | Sort-Object)
    $expectedProperties = @('bundle_digest', 'commit', 'schema_version', 'version')
    Assert-HarnessCondition (
        ($actualProperties -join ',') -ceq ($expectedProperties -join ',')
    ) "active bundle reference '$Path' has an unexpected schema"
    Assert-HarnessCondition (
        (Test-StrictJsonInteger $reference.schema_version) -and
        $reference.schema_version -eq 1
    ) (
        "active bundle reference '$Path' has an unsupported schema version"
    )
    foreach ($field in @('version', 'commit', 'bundle_digest')) {
        Assert-HarnessCondition (Test-StrictJsonString $reference.$field) (
            "active bundle reference '$Path' field '$field' is not a JSON string"
        )
    }
    Assert-HarnessCondition ($reference.commit -cmatch '^[0-9a-f]{12}$') (
        "active bundle reference '$Path' has a noncanonical commit"
    )
    Assert-HarnessCondition ($reference.bundle_digest -cmatch '^[0-9a-f]{64}$') (
        "active bundle reference '$Path' has a noncanonical bundle digest"
    )
    Assert-HarnessCondition (
        $reference.version.Length -le 64 -and
        -not [string]::IsNullOrWhiteSpace($reference.version) -and
        $reference.version -notmatch '[\x00-\x1F\x7F]'
    ) (
        "active bundle reference '$Path' has no version"
    )
    return $reference
}

function Assert-ReferenceSelectsBundle {
    param(
        [Parameter(Mandatory = $true)]$Reference,
        [Parameter(Mandatory = $true)]$Bundle,
        [Parameter(Mandatory = $true)][string]$Context
    )

    Assert-HarnessCondition (
        [string]$Reference.version -ceq [string]$Bundle.version -and
        [string]$Reference.commit -ceq [string]$Bundle.commit -and
        [string]$Reference.bundle_digest -ceq (Get-BundleSelectionDigest -Bundle $Bundle)
    ) "$Context does not select the expected complete bundle"
}

function New-ActiveReferenceValue {
    param([Parameter(Mandatory = $true)]$Bundle)

    return [ordered]@{
        schema_version = 1
        version = $Bundle.version
        commit = $Bundle.commit
        bundle_digest = Get-BundleSelectionDigest -Bundle $Bundle
    }
}

function Test-ByteArraysEqual {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Left,
        [Parameter(Mandatory = $true)][byte[]]$Right
    )

    return (
        $Left.Length -eq $Right.Length -and
        [System.Convert]::ToBase64String($Left) -ceq [System.Convert]::ToBase64String($Right)
    )
}

function Set-AtomicActiveReference {
    param(
        [Parameter(Mandatory = $true)][string]$ReferencePath,
        [Parameter(Mandatory = $true)]$Bundle,
        [Parameter(Mandatory = $true)]$ExpectedPreviousBundle,
        [scriptblock]$BeforeReplace,
        [scriptblock]$AfterReplace
    )

    $currentBytes = [System.IO.File]::ReadAllBytes($ReferencePath)
    $current = Get-ActiveReference -Path $ReferencePath
    Assert-ReferenceSelectsBundle `
        -Reference $current `
        -Bundle $ExpectedPreviousBundle `
        -Context 'active bundle reference before mutation'
    $next = New-ActiveReferenceValue -Bundle $Bundle
    $nextText = ($next | ConvertTo-Json -Depth 8) + "`n"
    $nextBytes = [System.Text.UTF8Encoding]::new($false).GetBytes($nextText)
    $temporaryPath = $ReferencePath + '.next-' + [System.Guid]::NewGuid().ToString('N')
    $backupPath = $ReferencePath + '.previous-' + [System.Guid]::NewGuid().ToString('N')
    $failedNextPath = $ReferencePath + '.failed-next-' + [System.Guid]::NewGuid().ToString('N')
    $replaced = $false
    $committed = $false
    try {
        Write-NewUtf8Text -Path $temporaryPath -Text $nextText
        if ($null -ne $BeforeReplace) {
            & $BeforeReplace
        }
        $recheckedBytes = [System.IO.File]::ReadAllBytes($ReferencePath)
        Assert-HarnessCondition (
            Test-ByteArraysEqual -Left $recheckedBytes -Right $currentBytes
        ) 'active bundle reference bytes changed immediately before replacement'
        $rechecked = Get-ActiveReference -Path $ReferencePath
        Assert-ReferenceSelectsBundle `
            -Reference $rechecked `
            -Bundle $ExpectedPreviousBundle `
            -Context 'active bundle reference immediately before replacement'
        [System.IO.File]::Replace($temporaryPath, $ReferencePath, $backupPath, $true)
        $replaced = $true
        Assert-HarnessCondition (
            Test-ByteArraysEqual `
                -Left ([System.IO.File]::ReadAllBytes($ReferencePath)) `
                -Right $nextBytes
        ) 'active bundle reference replacement did not install the exact candidate bytes'
        Assert-HarnessCondition (
            Test-ByteArraysEqual `
                -Left ([System.IO.File]::ReadAllBytes($backupPath)) `
                -Right $currentBytes
        ) 'active bundle reference replacement did not preserve the exact predecessor bytes'
        if ($null -ne $AfterReplace) {
            & $AfterReplace
        }
        $activated = Get-ActiveReference -Path $ReferencePath
        Assert-ReferenceSelectsBundle `
            -Reference $activated `
            -Bundle $Bundle `
            -Context 'active bundle reference after replacement'
        $committed = $true
    }
    catch {
        $activationError = $_
        if ($replaced -and (Test-Path -LiteralPath $backupPath -PathType Leaf)) {
            try {
                Assert-HarnessCondition (
                    Test-ByteArraysEqual `
                        -Left ([System.IO.File]::ReadAllBytes($ReferencePath)) `
                        -Right $nextBytes
                ) (
                    'active bundle reference changed after candidate replacement; ' +
                    'terminal state is unknown and concurrent winner must be preserved'
                )
                Assert-HarnessCondition (
                    Test-ByteArraysEqual `
                        -Left ([System.IO.File]::ReadAllBytes($backupPath)) `
                        -Right $currentBytes
                ) 'predecessor rollback reference bytes changed after candidate replacement'
                [System.IO.File]::Replace(
                    $backupPath,
                    $ReferencePath,
                    $failedNextPath,
                    $true
                )
                $restored = Get-ActiveReference -Path $ReferencePath
                Assert-ReferenceSelectsBundle `
                    -Reference $restored `
                    -Bundle $ExpectedPreviousBundle `
                    -Context 'active bundle reference after failed activation rollback'
                Assert-HarnessCondition (
                    Test-ByteArraysEqual `
                        -Left ([System.IO.File]::ReadAllBytes($ReferencePath)) `
                        -Right $currentBytes
                ) 'failed activation rollback did not restore the exact predecessor bytes'
                if (Test-Path -LiteralPath $failedNextPath -PathType Leaf) {
                    [System.IO.File]::Delete($failedNextPath)
                }
            }
            catch {
                throw (
                    "activation failed and rollback could not be proven; " +
                    "preserved recovery files '$backupPath' and '$failedNextPath': " +
                    $_.Exception.Message
                )
            }
        }
        throw $activationError
    }
    finally {
        if (Test-Path -LiteralPath $temporaryPath) {
            [System.IO.File]::Delete($temporaryPath)
        }
        if ($committed -and (Test-Path -LiteralPath $backupPath)) {
            [System.IO.File]::Delete($backupPath)
        }
    }
}

function Assert-MalformedActiveReferencesFailClosed {
    param(
        [Parameter(Mandatory = $true)][string]$ReferencePath,
        [Parameter(Mandatory = $true)]$ExpectedPreviousBundle,
        [Parameter(Mandatory = $true)]$CandidateBundle,
        [Parameter(Mandatory = $true)][string]$PredecessorDirectory,
        [Parameter(Mandatory = $true)][string]$CandidateDirectory
    )

    $validReferenceBytes = [System.IO.File]::ReadAllBytes($ReferencePath)
    $predecessorBefore = Get-IsolatedEnvironmentSnapshot -Root $PredecessorDirectory
    $candidateBefore = Get-IsolatedEnvironmentSnapshot -Root $CandidateDirectory
    $utf8 = [System.Text.UTF8Encoding]::new($false)
    $baseFields = (
        '"version":"0.3.0-beta.2",' +
        '"commit":"111111111111",' +
        '"bundle_digest":"' + ('1' * 64) + '"}'
    )
    $invalidUtf8Prefix = $utf8.GetBytes('{"schema_version":1,"version":"')
    $invalidUtf8Suffix = $utf8.GetBytes(
        '","commit":"111111111111","bundle_digest":"' + ('1' * 64) + '"}'
    )
    $fixtures = [ordered]@{
        duplicate_key = $utf8.GetBytes(
            '{"schema_version":1,"schema_version":1,' + $baseFields
        )
        case_colliding_key = $utf8.GetBytes(
            '{"schema_version":1,"Schema_Version":1,' + $baseFields
        )
        string_schema_version = $utf8.GetBytes(
            '{"schema_version":"1",' + $baseFields
        )
        invalid_utf8 = [byte[]](
            $invalidUtf8Prefix + [byte[]]@(0xC3, 0x28) + $invalidUtf8Suffix
        )
    }

    foreach ($name in $fixtures.Keys) {
        [System.IO.File]::WriteAllBytes($ReferencePath, [byte[]]$fixtures[$name])
        $malformedBytes = [System.IO.File]::ReadAllBytes($ReferencePath)
        $rejected = $false
        try {
            Set-AtomicActiveReference `
                -ReferencePath $ReferencePath `
                -Bundle $CandidateBundle `
                -ExpectedPreviousBundle $ExpectedPreviousBundle
        }
        catch {
            $rejected = $true
        }
        Assert-HarnessCondition $rejected (
            "malformed active-reference fixture '$name' was accepted"
        )
        $afterBytes = [System.IO.File]::ReadAllBytes($ReferencePath)
        Assert-HarnessCondition (
            [System.Convert]::ToBase64String($afterBytes) -ceq
            [System.Convert]::ToBase64String($malformedBytes)
        ) "malformed active-reference rejection '$name' changed the reference bytes"
        Assert-SnapshotsEqual `
            -Expected $predecessorBefore `
            -Actual (Get-IsolatedEnvironmentSnapshot -Root $PredecessorDirectory) `
            -Context "malformed active-reference rejection '$name' changed the predecessor bundle"
        Assert-SnapshotsEqual `
            -Expected $candidateBefore `
            -Actual (Get-IsolatedEnvironmentSnapshot -Root $CandidateDirectory) `
            -Context "malformed active-reference rejection '$name' changed the candidate bundle"
        [System.IO.File]::WriteAllBytes($ReferencePath, $validReferenceBytes)
        Assert-ReferenceSelectsBundle `
            -Reference (Get-ActiveReference -Path $ReferencePath) `
            -Bundle $ExpectedPreviousBundle `
            -Context "active reference restored after malformed fixture '$name'"
    }
}

function Invoke-HarnessCore {
    param(
        [Parameter(Mandatory = $true)][string]$Predecessor,
        [Parameter(Mandatory = $true)][string]$Candidate,
        [Parameter(Mandatory = $true)][bool]$FixtureMode,
        [Parameter(Mandatory = $true)][string]$ScratchRoot,
        [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{40}$')]
        [string]$StorageFixtureSourceCommit
    )

    $isolationRoot = Join-Path $ScratchRoot 'isolated-account'
    [System.IO.Directory]::CreateDirectory($isolationRoot) | Out-Null
    $persistenceRoot = Join-Path $isolationRoot 'persistent-state'
    [System.IO.Directory]::CreateDirectory($persistenceRoot) | Out-Null
    $vaultSentinel = Join-Path $persistenceRoot 'synthetic-vault.sentinel'
    $recoverySentinel = Join-Path $persistenceRoot 'synthetic-recovery.sentinel'
    Write-NewUtf8Text -Path $vaultSentinel -Text "not-a-serctl-vault`n"
    Write-NewUtf8Text -Path $recoverySentinel -Text "not-a-recovery-secret`n"
    $persistentBefore = Get-IsolatedEnvironmentSnapshot -Root $persistenceRoot

    $predecessorBundle = Get-CheckedBundle `
        -Directory $Predecessor `
        -ExpectedVersion $predecessorVersion `
        -ExpectedIpc $predecessorIpc `
        -IsolationRoot (Join-Path $isolationRoot 'predecessor-version-only') `
        -FixtureMode $FixtureMode
    $candidateBundle = Get-CheckedBundle `
        -Directory $Candidate `
        -ExpectedVersion $candidateVersion `
        -ExpectedIpc $candidateIpc `
        -IsolationRoot (Join-Path $isolationRoot 'candidate-version-only') `
        -FixtureMode $FixtureMode
    Assert-CandidateMatchesStorageFixtureSource `
        -CandidateCommit ([string]$candidateBundle.commit) `
        -SourceCommit $StorageFixtureSourceCommit
    # Run the executable storage fixture only after its source identity is
    # bound to the complete candidate set. Inspect mode also requires that
    # source worktree to be clean before this function is entered.
    Invoke-AuditSeedStorageDirectionFixture

    Assert-HarnessCondition ($predecessorBundle.commit -cne $candidateBundle.commit) (
        'predecessor and candidate unexpectedly report the same commit'
    )
    $predecessorDigest = Get-BundleSelectionDigest -Bundle $predecessorBundle
    $candidateDigest = Get-BundleSelectionDigest -Bundle $candidateBundle
    Assert-HarnessCondition ($predecessorDigest -cne $candidateDigest) (
        'predecessor and candidate bundle digests unexpectedly match'
    )

    $activeReference = Join-Path $isolationRoot 'active-bundle.json'
    $initialReference = New-ActiveReferenceValue -Bundle $predecessorBundle
    Write-NewUtf8Text -Path $activeReference -Text (($initialReference | ConvertTo-Json) + "`n")
    $referenceBeforeMixedChecks = (
        Get-FileHash -LiteralPath $activeReference -Algorithm SHA256
    ).Hash
    Assert-MalformedActiveReferencesFailClosed `
        -ReferencePath $activeReference `
        -ExpectedPreviousBundle $predecessorBundle `
        -CandidateBundle $candidateBundle `
        -PredecessorDirectory $Predecessor `
        -CandidateDirectory $Candidate
    Assert-HarnessCondition (
        (Get-FileHash -LiteralPath $activeReference -Algorithm SHA256).Hash -ceq
        $referenceBeforeMixedChecks
    ) 'malformed active-reference tests did not restore the original valid reference'

    $mixedChecks = [ordered]@{}
    for ($selection = 1; $selection -le 6; $selection += 1) {
        $cli = if (($selection -band 1) -ne 0) {
            $candidateBundle.components.cli
        }
        else {
            $predecessorBundle.components.cli
        }
        $daemon = if (($selection -band 2) -ne 0) {
            $candidateBundle.components.daemon
        }
        else {
            $predecessorBundle.components.daemon
        }
        $helper = if (($selection -band 4) -ne 0) {
            $candidateBundle.components.helper
        }
        else {
            $predecessorBundle.components.helper
        }
        $mixedChecks["predecessor_candidate_selection_$selection"] = -not (
            Test-SelectedSet `
                -Expected $candidateBundle `
                -CliComponent $cli `
                -DaemonComponent $daemon `
                -HelperComponent $helper
        )
    }
    foreach ($tamperedKind in @('cli', 'daemon', 'helper')) {
        $tampered = [ordered]@{}
        foreach ($property in $candidateBundle.components[$tamperedKind].Keys) {
            $tampered[$property] = $candidateBundle.components[$tamperedKind][$property]
        }
        $tampered.sha256 = if ([string]$tampered.sha256 -ceq ('0' * 64)) {
            '1' * 64
        }
        else {
            '0' * 64
        }
        $cli = if ($tamperedKind -ceq 'cli') { $tampered } else { $candidateBundle.components.cli }
        $daemon = if ($tamperedKind -ceq 'daemon') { $tampered } else { $candidateBundle.components.daemon }
        $helper = if ($tamperedKind -ceq 'helper') { $tampered } else { $candidateBundle.components.helper }
        $mixedChecks["candidate_${tamperedKind}_hash_mismatch"] = -not (
            Test-SelectedSet `
                -Expected $candidateBundle `
                -CliComponent $cli `
                -DaemonComponent $daemon `
                -HelperComponent $helper
        )
    }
    foreach ($name in $mixedChecks.Keys) {
        Assert-HarnessCondition ([bool]$mixedChecks[$name]) "mixed-set guard '$name' accepted a mismatch"
    }
    Assert-HarnessCondition (
        (Get-FileHash -LiteralPath $activeReference -Algorithm SHA256).Hash -ceq $referenceBeforeMixedChecks
    ) 'mixed-set checks changed the active reference'

    $failureReference = Join-Path $isolationRoot 'failed-activation-bundle.json'
    Write-NewUtf8Text `
        -Path $failureReference `
        -Text (($initialReference | ConvertTo-Json) + "`n")
    $injectedFailureRejected = $false
    try {
        Set-AtomicActiveReference `
            -ReferencePath $failureReference `
            -Bundle $candidateBundle `
            -ExpectedPreviousBundle $predecessorBundle `
            -AfterReplace { throw 'injected post-replacement verification failure' }
    }
    catch {
        $injectedFailureRejected = $true
    }
    Assert-HarnessCondition $injectedFailureRejected (
        'post-replacement failure injection unexpectedly committed'
    )
    Assert-ReferenceSelectsBundle `
        -Reference (Get-ActiveReference -Path $failureReference) `
        -Bundle $predecessorBundle `
        -Context 'failed activation rollback'

    $concurrentReference = Join-Path $isolationRoot 'concurrent-active-bundle.json'
    Write-NewUtf8Text `
        -Path $concurrentReference `
        -Text (($initialReference | ConvertTo-Json) + "`n")
    # Preserve the same semantic predecessor selection but change its exact
    # bytes. A semantic-only recheck would miss this cooperative writer and
    # overwrite its reference even though ownership changed.
    $concurrentJson = ($initialReference | ConvertTo-Json -Compress) + "`n"
    $concurrentMutation = {
        [System.IO.File]::WriteAllText(
            $concurrentReference,
            $concurrentJson,
            [System.Text.UTF8Encoding]::new($false)
        )
    }.GetNewClosure()
    $concurrentChangeRejected = $false
    try {
        Set-AtomicActiveReference `
            -ReferencePath $concurrentReference `
            -Bundle $candidateBundle `
            -ExpectedPreviousBundle $predecessorBundle `
            -BeforeReplace $concurrentMutation
    }
    catch {
        $concurrentChangeRejected = $true
    }
    Assert-HarnessCondition $concurrentChangeRejected (
        'concurrent active-reference change was overwritten'
    )
    Assert-HarnessCondition (
        (Get-Content -LiteralPath $concurrentReference -Raw -Encoding utf8) -ceq $concurrentJson
    ) 'concurrent active-reference winner was not preserved byte-for-byte'

    $postReplaceRaceReference = Join-Path $isolationRoot 'post-replace-race-bundle.json'
    Write-NewUtf8Text `
        -Path $postReplaceRaceReference `
        -Text (($initialReference | ConvertTo-Json) + "`n")
    $postReplaceWinner = [ordered]@{
        schema_version = 1
        version = 'concurrent-owner'
        commit = '333333333333'
        bundle_digest = '3' * 64
    }
    $postReplaceWinnerJson = ($postReplaceWinner | ConvertTo-Json -Compress) + "`n"
    $postReplaceMutation = {
        [System.IO.File]::WriteAllText(
            $postReplaceRaceReference,
            $postReplaceWinnerJson,
            [System.Text.UTF8Encoding]::new($false)
        )
        throw 'injected failure after concurrent post-replacement winner'
    }.GetNewClosure()
    $postReplaceRaceRejected = $false
    try {
        Set-AtomicActiveReference `
            -ReferencePath $postReplaceRaceReference `
            -Bundle $candidateBundle `
            -ExpectedPreviousBundle $predecessorBundle `
            -AfterReplace $postReplaceMutation
    }
    catch {
        $postReplaceRaceRejected = $true
        Assert-HarnessCondition (
            $_.Exception.Message.Contains('terminal state is unknown')
        ) 'post-replacement reference race did not produce an explicit unknown terminal state'
    }
    Assert-HarnessCondition $postReplaceRaceRejected (
        'post-replacement active-reference race unexpectedly committed'
    )
    Assert-HarnessCondition (
        (Get-Content -LiteralPath $postReplaceRaceReference -Raw -Encoding utf8) -ceq
        $postReplaceWinnerJson
    ) 'post-replacement concurrent winner was overwritten by rollback'
    Assert-HarnessCondition (
        @(Get-ChildItem -LiteralPath $isolationRoot -Force -File |
            Where-Object Name -Like 'post-replace-race-bundle.json.previous-*').Count -eq 1
    ) 'post-replacement race did not preserve exactly one predecessor recovery reference'

    Set-AtomicActiveReference `
        -ReferencePath $activeReference `
        -Bundle $candidateBundle `
        -ExpectedPreviousBundle $predecessorBundle
    $upgraded = Get-ActiveReference -Path $activeReference
    Assert-ReferenceSelectsBundle `
        -Reference $upgraded `
        -Bundle $candidateBundle `
        -Context 'atomic upgrade'

    Set-AtomicActiveReference `
        -ReferencePath $activeReference `
        -Bundle $predecessorBundle `
        -ExpectedPreviousBundle $candidateBundle
    $rolledBack = Get-ActiveReference -Path $activeReference
    Assert-ReferenceSelectsBundle `
        -Reference $rolledBack `
        -Bundle $predecessorBundle `
        -Context 'atomic rollback'
    Assert-SnapshotsEqual `
        -Expected $persistentBefore `
        -Actual (Get-IsolatedEnvironmentSnapshot -Root $persistenceRoot) `
        -Context 'bundle selection, upgrade, and rollback'

    return [ordered]@{
        schema_version = $reportSchemaVersion
        accepted = $false
        result = 'BLOCKED'
        reason = 'real predecessor vault and isolated runtime IPC evidence were not supplied'
        synthetic_fixture = $FixtureMode
        predecessor = $predecessorBundle
        candidate = $candidateBundle
        structural_gates = [ordered]@{
            audit_seed_directional_source_fixture = 'PASS'
            storage_fixture_source_commit_binding = 'PASS'
            candidate_storage_marker_binding = 'PASS'
            identity_and_hashes = 'PASS'
            version_only_isolated_home = 'PASS'
            mixed_set_pre_activation_rejection = 'PASS'
            hash_only_component_mismatch_rejection = 'PASS'
            strict_active_reference_validation = 'PASS'
            concurrent_reference_change_rejection = 'PASS'
            post_replace_reference_race_preserved = 'PASS'
            failed_activation_atomic_rollback = 'PASS'
            atomic_reference_upgrade = 'PASS'
            atomic_reference_rollback = 'PASS'
            persistent_sentinel_unchanged = 'PASS'
        }
        mixed_set_checks = $mixedChecks
        acceptance_gates = [ordered]@{
            real_v030_beta2_vault_v4_upgrade = 'BLOCKED_NOT_RUN'
            vault_storage_v4_to_v5_format_upgrade = 'BLOCKED_NOT_RUN'
            beta2_destructive_writer_outer_gate_rejection = 'BLOCKED_NOT_RUN'
            matched_bundle_upgrade_activation = 'BLOCKED_NOT_RUN'
            matched_bundle_rollback_activation = 'BLOCKED_NOT_RUN'
            runtime_v8_cli_v9_daemon_rejection = 'BLOCKED_NOT_RUN'
            runtime_v9_cli_v8_daemon_rejection = 'BLOCKED_NOT_RUN'
            runtime_v8_audit_seed_rejection_before_write = 'BLOCKED_NOT_RUN'
            runtime_v8_activation_observation_recorded = 'BLOCKED_NOT_RUN'
            runtime_v8_rejection_runtime_state_cleanup = 'BLOCKED_NOT_RUN'
            runtime_future_security_field_rejection_before_write = 'BLOCKED_NOT_RUN'
            runtime_helper_identity_rejection = 'BLOCKED_NOT_RUN'
            descriptor_owner_and_daemon_lifecycle = 'BLOCKED_NOT_RUN'
            stale_runtime_descriptor_rejection = 'BLOCKED_NOT_RUN'
            stale_operation_grant_rejection = 'BLOCKED_NOT_RUN'
            pre_upgrade_vault_backup_restore = 'BLOCKED_NOT_RUN'
            matching_recovery_media_restore = 'BLOCKED_NOT_RUN'
            acl_owner_metadata_restore = 'BLOCKED_NOT_RUN'
        }
        side_effect_boundary = [ordered]@{
            real_vault_opened = $false
            daemon_started = $false
            remote_operation_attempted = $false
            descriptor_created = $false
            stale_descriptor_reused = $false
            stale_grant_reused = $false
            allowed_root = $isolationRoot
        }
    }
}

function Assert-SafeEvidenceOwner {
    param([Parameter(Mandatory = $true)][string]$Value)

    Assert-HarnessCondition (
        -not [string]::IsNullOrWhiteSpace($Value) -and $Value.Length -le 128
    ) 'evidence owner is empty or too long'
    Assert-HarnessCondition ($Value -notmatch '[\x00-\x1F\x7F]') (
        'evidence owner contains a control character'
    )
    Assert-HarnessCondition (
        $Value -notmatch '^[A-Za-z]:[\\/]' -and
        $Value -notmatch '^\\\\' -and
        $Value -notmatch '^/'
    ) 'evidence owner contains an absolute local path'
}

function Get-TreeRuntimeEvidence {
    param([Parameter(Mandatory = $true)][string]$Root)

    $rootPath = [System.IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
    $items = [ordered]@{}
    foreach ($item in @(Get-Item -LiteralPath $rootPath -Force) + @(
        Get-ChildItem -LiteralPath $rootPath -Force -Recurse | Sort-Object FullName
    )) {
        Assert-HarnessCondition (
            ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0
        ) 'runtime fixture contains a reparse point'
        $relative = if ($item.FullName -ceq $rootPath) {
            '.'
        }
        else {
            $item.FullName.Substring($rootPath.Length).TrimStart('\', '/')
        }
        $acl = Get-Acl -LiteralPath $item.FullName -ErrorAction Stop
        $items[$relative] = [ordered]@{
            kind = if ($item.PSIsContainer) { 'directory' } else { 'file' }
            length = if ($item.PSIsContainer) { 0 } else { [long]$item.Length }
            sha256 = if ($item.PSIsContainer) {
                ''
            }
            else {
                (Get-FileHash -LiteralPath $item.FullName -Algorithm SHA256).Hash
            }
            sddl = $acl.Sddl
        }
    }
    return $items
}

function Copy-RuntimeTree {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    Assert-HarnessCondition (-not (Test-Path -LiteralPath $Destination)) (
        'runtime copy destination already exists'
    )
    $sourceItem = Get-Item -LiteralPath $Source -Force -ErrorAction Stop
    Assert-HarnessCondition $sourceItem.PSIsContainer 'runtime fixture is not a directory'
    [void](Get-TreeRuntimeEvidence -Root $Source)
    Copy-Item -LiteralPath $Source -Destination $Destination -Recurse -ErrorAction Stop
}

function Set-TreeRuntimeAcls {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)]$Evidence
    )

    $rootPath = [System.IO.Path]::GetFullPath($Root).TrimEnd('\', '/')
    foreach ($relative in @($Evidence.Keys | Sort-Object { $_.Length } -Descending)) {
        $path = if ($relative -ceq '.') { $rootPath } else { Join-Path $rootPath $relative }
        $acl = Get-Acl -LiteralPath $path -ErrorAction Stop
        $acl.SetSecurityDescriptorSddlForm([string]$Evidence[$relative].sddl)
        Set-Acl -LiteralPath $path -AclObject $acl -ErrorAction Stop
    }
}

function Remove-IsolatedRuntimeTree {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$AllowedParent
    )

    $full = [System.IO.Path]::GetFullPath($Path)
    $parent = [System.IO.Path]::GetFullPath($AllowedParent).TrimEnd('\', '/') +
        [System.IO.Path]::DirectorySeparatorChar
    Assert-HarnessCondition ($full.StartsWith($parent, [StringComparison]::OrdinalIgnoreCase)) (
        'runtime cleanup target escaped the harness scratch root'
    )
    if (Test-Path -LiteralPath $full) {
        [void](Get-TreeRuntimeEvidence -Root $full)
        Remove-Item -LiteralPath $full -Recurse -Force -ErrorAction Stop
    }
}

function Invoke-IsolatedRuntimeCommand {
    param(
        [Parameter(Mandatory = $true)][string]$Binary,
        [Parameter(Mandatory = $true)][string]$Arguments,
        [Parameter(Mandatory = $true)][string]$RuntimeHome,
        [string]$StandardInput = '',
        [int]$TimeoutSeconds = 60,
        [string]$RuntimeStateDirectory
    )

    $start = [System.Diagnostics.ProcessStartInfo]::new()
    $start.FileName = $Binary
    $start.Arguments = $Arguments
    $start.WorkingDirectory = $RuntimeHome
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.RedirectStandardInput = $true
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($name in @('HOME', 'USERPROFILE')) {
        $start.EnvironmentVariables[$name] = $RuntimeHome
    }
    foreach ($name in @('LOCALAPPDATA', 'APPDATA', 'TEMP', 'TMP')) {
        $value = Join-Path $RuntimeHome ('.runtime-' + $name.ToLowerInvariant())
        [System.IO.Directory]::CreateDirectory($value) | Out-Null
        $start.EnvironmentVariables[$name] = $value
    }
    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $start
    try {
        $observeRuntimeState = -not [string]::IsNullOrWhiteSpace($RuntimeStateDirectory)
        $descriptorObserved = $false
        $activationSecretObserved = $false
        if ($observeRuntimeState) {
            $runtimeStateRoot = [System.IO.Path]::GetFullPath($RuntimeStateDirectory)
            $runtimeStateItem = Get-Item -LiteralPath $runtimeStateRoot -Force -ErrorAction Stop
            Assert-HarnessCondition (
                $runtimeStateItem.PSIsContainer -and
                ($runtimeStateItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0
            ) 'runtime activation observation root is not a regular non-reparse directory'
            $observedDescriptorPath = Join-Path $runtimeStateRoot 'daemon.json'
            $observedSecretPath = Join-Path $runtimeStateRoot 'daemon.secret'
            $descriptorObserved = Test-Path -LiteralPath $observedDescriptorPath -PathType Leaf
            $activationSecretObserved = Test-Path -LiteralPath $observedSecretPath -PathType Leaf
        }
        Assert-HarnessCondition $process.Start() 'runtime command did not start'
        if (-not [string]::IsNullOrEmpty($StandardInput)) {
            $process.StandardInput.Write($StandardInput)
        }
        $process.StandardInput.Close()
        $stdoutTask = $process.StandardOutput.ReadToEndAsync()
        $stderrTask = $process.StandardError.ReadToEndAsync()
        $runtimeDeadline = [DateTimeOffset]::UtcNow.AddSeconds($TimeoutSeconds)
        while (-not $process.WaitForExit(10)) {
            if ($observeRuntimeState) {
                $descriptorObserved = $descriptorObserved -or (
                    Test-Path -LiteralPath $observedDescriptorPath -PathType Leaf
                )
                $activationSecretObserved = $activationSecretObserved -or (
                    Test-Path -LiteralPath $observedSecretPath -PathType Leaf
                )
            }
            if ([DateTimeOffset]::UtcNow -ge $runtimeDeadline) {
                try { $process.Kill() } catch {}
                throw 'upgrade/rollback harness failed: runtime command exceeded its deadline'
            }
        }
        if ($observeRuntimeState) {
            # This is deliberately an observation, not proof of non-activation:
            # a false value only means neither artifact was seen by the bounded
            # monitor. Acceptance never requires this value to be false.
            $descriptorObserved = $descriptorObserved -or (
                Test-Path -LiteralPath $observedDescriptorPath -PathType Leaf
            )
            $activationSecretObserved = $activationSecretObserved -or (
                Test-Path -LiteralPath $observedSecretPath -PathType Leaf
            )
        }
        $stdout = $stdoutTask.GetAwaiter().GetResult()
        $stderr = $stderrTask.GetAwaiter().GetResult()
        Assert-HarnessCondition (
            $stdout.Length -le 1048576 -and $stderr.Length -le 1048576
        ) 'runtime command output exceeded its retained bound'
        $result = [ordered]@{
            exit_code = [int]$process.ExitCode
            stdout = $stdout
            stderr = $stderr
        }
        if ($observeRuntimeState) {
            $result.descriptor_observed_during_command = [bool]$descriptorObserved
            $result.activation_secret_observed_during_command = [bool]$activationSecretObserved
            $result.transient_runtime_activation_observed = [bool](
                $descriptorObserved -or $activationSecretObserved
            )
        }
        return [pscustomobject]$result
    }
    finally {
        $process.Dispose()
    }
}

function Invoke-WholeBundleRuntimeGates {
    param(
        [Parameter(Mandatory = $true)]$StructuralReport,
        [Parameter(Mandatory = $true)][string]$FixtureDirectory,
        [Parameter(Mandatory = $true)][string]$ProfileName,
        [Parameter(Mandatory = $true)][string]$ScratchRoot
    )

    Assert-HarnessCondition ($env:OS -ceq 'Windows_NT') (
        'formal whole-bundle runtime mode requires Windows X64'
    )
    Assert-HarnessCondition (
        [Environment]::Is64BitOperatingSystem -and [Environment]::Is64BitProcess
    ) 'formal whole-bundle runtime mode requires a native X64 process'
    Assert-HarnessCondition (
        -not [string]::IsNullOrWhiteSpace($env:SERCTL_PROFILE_PASSPHRASE)
    ) 'formal runtime mode requires SERCTL_PROFILE_PASSPHRASE'

    $runtimeRoot = Join-Path $ScratchRoot 'runtime-fixture'
    $backupRoot = Join-Path $ScratchRoot 'runtime-backup'
    Copy-RuntimeTree -Source $FixtureDirectory -Destination $runtimeRoot
    $home = Join-Path $runtimeRoot 'home'
    $recovery = Join-Path $runtimeRoot 'recovery-media.srrec'
    Assert-HarnessCondition (Test-Path -LiteralPath (Join-Path $home '.serctl/vault.json')) (
        'runtime fixture lacks home/.serctl/vault.json'
    )
    Assert-HarnessCondition (Test-Path -LiteralPath $recovery -PathType Leaf) (
        'runtime fixture lacks recovery-media.srrec'
    )
    $baseline = Get-TreeRuntimeEvidence -Root $runtimeRoot
    Assert-CompleteRecoverySetEvidence `
        -Evidence $baseline `
        -Context 'exact pre-upgrade recovery set'
    Copy-RuntimeTree -Source $runtimeRoot -Destination $backupRoot

    $predecessor = $StructuralReport.predecessor
    $candidate = $StructuralReport.candidate
    $preCli = Join-Path $predecessor.directory $predecessor.components.cli.file_name
    $candidateCli = Join-Path $candidate.directory $candidate.components.cli.file_name
    $runDirectory = Join-Path $home '.serctl/run'
    $vaultPath = Join-Path $home '.serctl/vault.json'
    $descriptorPath = Join-Path $runDirectory 'daemon.json'
    $secretPath = Join-Path $runDirectory 'daemon.secret'
    $grantPath = Join-Path $runtimeRoot 'candidate-grant.json'
    $quotedGrant = '"' + $grantPath.Replace('"', '') + '"'
    $rejectedBeta2GrantPath = Join-Path $runtimeRoot 'beta2-rejected-grant.json'
    $quotedRejectedBeta2Grant = '"' + $rejectedBeta2GrantPath.Replace('"', '') + '"'
    $staleDirectory = Join-Path $ScratchRoot 'stale-runtime'
    [System.IO.Directory]::CreateDirectory($staleDirectory) | Out-Null
    $staleDescriptor = Join-Path $staleDirectory 'daemon.json'
    $staleSecret = Join-Path $staleDirectory 'daemon.secret'
    $descriptorRecord = $null
    try {
        $preStatus = Invoke-IsolatedRuntimeCommand `
            -Binary $preCli `
            -Arguments "status $ProfileName" `
            -RuntimeHome $home
        Assert-HarnessCondition ($preStatus.exit_code -eq 0) (
            'matched predecessor runtime did not open the beta-2 fixture'
        )
        Assert-HarnessCondition (
            (Test-Path -LiteralPath $descriptorPath -PathType Leaf) -and
            (Test-Path -LiteralPath $secretPath -PathType Leaf)
        ) 'predecessor runtime did not publish its descriptor and activation secret'
        Copy-Item -LiteralPath $descriptorPath -Destination $staleDescriptor -ErrorAction Stop
        Copy-Item -LiteralPath $secretPath -Destination $staleSecret -ErrorAction Stop
        $v8DescriptorHash = (Get-FileHash $descriptorPath -Algorithm SHA256).Hash

        $candidateAgainstV8 = Invoke-IsolatedRuntimeCommand `
            -Binary $candidateCli `
            -Arguments "status $ProfileName" `
            -RuntimeHome $home
        Assert-HarnessCondition ($candidateAgainstV8.exit_code -ne 0) (
            'candidate CLI accepted the live predecessor daemon'
        )
        Assert-HarnessCondition (
            (Get-FileHash $descriptorPath -Algorithm SHA256).Hash -ceq $v8DescriptorHash
        ) 'candidate CLI changed the predecessor descriptor after mismatch rejection'
        $preDown = Invoke-IsolatedRuntimeCommand `
            -Binary $preCli `
            -Arguments "down $ProfileName" `
            -RuntimeHome $home
        Assert-HarnessCondition ($preDown.exit_code -eq 0) 'predecessor daemon did not stop cleanly'

        $grant = Invoke-IsolatedRuntimeCommand `
            -Binary $candidateCli `
            -Arguments (
                "grant-issue $ProfileName --operations daemon.status --budget 2 " +
                "--ttl-minutes 1 --output $quotedGrant"
            ) `
            -RuntimeHome $home
        Assert-HarnessCondition ($grant.exit_code -eq 0) (
            'candidate grant issuance and vault upgrade did not complete'
        )
        Assert-HarnessCondition (Test-Path -LiteralPath $grantPath -PathType Leaf) (
            'candidate grant file was not created'
        )
        Assert-HarnessCondition (Test-Path -LiteralPath $descriptorPath -PathType Leaf) (
            'candidate daemon descriptor was not published'
        )
        $descriptorText = Read-StrictUtf8Text -Path $descriptorPath
        $descriptorRecord = ConvertFrom-StrictJson `
            -Json $descriptorText `
            -Label 'candidate daemon descriptor'
        Assert-HarnessCondition (
            $descriptorRecord.pid -is [int] -or $descriptorRecord.pid -is [long]
        ) 'candidate descriptor PID is not an integer'
        Assert-HarnessCondition (
            [int64]$descriptorRecord.pid -gt 0 -and
            [string]$descriptorRecord.build_commit -ceq [string]$candidate.commit -and
            [int]$descriptorRecord.protocol_min -eq 9 -and
            [int]$descriptorRecord.protocol_max -eq 9
        ) 'candidate descriptor identity does not match the exact candidate daemon'
        $candidateDescriptorHash = (Get-FileHash $descriptorPath -Algorithm SHA256).Hash

        $predecessorAgainstV9 = Invoke-IsolatedRuntimeCommand `
            -Binary $preCli `
            -Arguments "status $ProfileName" `
            -RuntimeHome $home
        Assert-HarnessCondition ($predecessorAgainstV9.exit_code -ne 0) (
            'predecessor CLI accepted the live candidate daemon'
        )
        Assert-HarnessCondition (
            (Get-FileHash $descriptorPath -Algorithm SHA256).Hash -ceq $candidateDescriptorHash
        ) 'predecessor CLI changed the candidate descriptor after mismatch rejection'

        $candidateDown = Invoke-IsolatedRuntimeCommand `
            -Binary $candidateCli `
            -Arguments "down $ProfileName" `
            -RuntimeHome $home
        Assert-HarnessCondition ($candidateDown.exit_code -eq 0) 'candidate daemon did not stop'
        Assert-HarnessCondition (-not (Test-Path -LiteralPath $descriptorPath)) (
            'candidate descriptor remained after matched shutdown'
        )

        [System.IO.Directory]::CreateDirectory($runDirectory) | Out-Null
        Copy-Item -LiteralPath $staleDescriptor -Destination $descriptorPath -ErrorAction Stop
        Copy-Item -LiteralPath $staleSecret -Destination $secretPath -ErrorAction Stop
        $staleHash = (Get-FileHash $descriptorPath -Algorithm SHA256).Hash
        $staleDescriptorProbe = Invoke-IsolatedRuntimeCommand `
            -Binary $candidateCli `
            -Arguments "status $ProfileName" `
            -RuntimeHome $home
        Assert-HarnessCondition ($staleDescriptorProbe.exit_code -ne 0) (
            'candidate accepted a predecessor runtime descriptor'
        )
        Assert-HarnessCondition (
            (Get-FileHash $descriptorPath -Algorithm SHA256).Hash -ceq $staleHash
        ) 'candidate mutated the rejected stale predecessor descriptor'
        Remove-Item -LiteralPath $descriptorPath -Force -ErrorAction Stop
        Remove-Item -LiteralPath $secretPath -Force -ErrorAction Stop

        $restart = Invoke-IsolatedRuntimeCommand `
            -Binary $candidateCli `
            -Arguments "status $ProfileName" `
            -RuntimeHome $home
        Assert-HarnessCondition ($restart.exit_code -eq 0) 'candidate daemon restart failed'
        $agent = Invoke-IsolatedRuntimeCommand `
            -Binary $candidateCli `
            -Arguments ('agent --grant ' + $quotedGrant) `
            -RuntimeHome $home `
            -StandardInput "{`"op`":`"status`",`"schema_version`":1,`"request_id`":1}`n"
        $agentLines = @($agent.stdout -split "`r?`n" | Where-Object { $_ -ne '' })
        Assert-HarnessCondition ($agentLines.Count -eq 1) (
            'stale Grant probe did not return exactly one bounded JSON result'
        )
        $agentResult = ConvertFrom-StrictJson -Json $agentLines[0] -Label 'stale Grant result'
        Assert-HarnessCondition (
            $agentResult.ok -is [bool] -and -not [bool]$agentResult.ok
        ) 'pre-restart OperationGrant was accepted by the new daemon instance'
        $finalDown = Invoke-IsolatedRuntimeCommand `
            -Binary $candidateCli `
            -Arguments "down $ProfileName" `
            -RuntimeHome $home
        Assert-HarnessCondition ($finalDown.exit_code -eq 0) 'restarted candidate daemon did not stop'

        $upgradedVaultHashBeforeBeta2 = (Get-FileHash `
            -LiteralPath $vaultPath `
            -Algorithm SHA256).Hash
        $upgradedRecoveryHashBeforeBeta2 = (Get-FileHash `
            -LiteralPath $recovery `
            -Algorithm SHA256).Hash
        Assert-HarnessCondition (
            -not (Test-Path -LiteralPath $descriptorPath) -and
            -not (Test-Path -LiteralPath $secretPath)
        ) 'beta-2 rejection probe did not start from an absent runtime state'
        $beta2AfterUpgrade = Invoke-IsolatedRuntimeCommand `
            -Binary $preCli `
            -Arguments (
                "grant-issue $ProfileName --operations daemon.status --budget 1 " +
                "--output $quotedRejectedBeta2Grant"
            ) `
            -RuntimeHome $home `
            -RuntimeStateDirectory $runDirectory
        Assert-HarnessCondition ($beta2AfterUpgrade.exit_code -ne 0) (
            'beta-2 mutation-capable reader accepted candidate-upgraded vault storage'
        )
        Assert-HarnessCondition (
            -not (Test-Path -LiteralPath $rejectedBeta2GrantPath)
        ) 'beta-2 rejection reached its grant output writer'
        Assert-HarnessCondition (
            (Get-FileHash -LiteralPath $vaultPath -Algorithm SHA256).Hash -ceq
                $upgradedVaultHashBeforeBeta2 -and
            (Get-FileHash -LiteralPath $recovery -Algorithm SHA256).Hash -ceq
                $upgradedRecoveryHashBeforeBeta2
        ) (
            'beta-2 rejection changed upgraded vault or matching recovery bytes'
        )
        $beta2RuntimeStateCleaned = Wait-Beta2RuntimeStateCleanup `
            -DescriptorPath $descriptorPath `
            -SecretPath $secretPath
        Assert-HarnessCondition $beta2RuntimeStateCleaned (
            'beta-2 rejection left a runtime descriptor or activation secret after command exit'
        )
        $beta2RuntimeObservation = [ordered]@{
            beta2_transient_runtime_activation_observed = [bool](
                $beta2AfterUpgrade.transient_runtime_activation_observed
            )
            beta2_runtime_state_cleaned_after_rejection = [bool]$beta2RuntimeStateCleaned
        }
        Assert-Beta2RuntimeRejectionObservation -Evidence $beta2RuntimeObservation
        $candidateAfterUpgrade = Invoke-IsolatedRuntimeCommand `
            -Binary $candidateCli `
            -Arguments 'list' `
            -RuntimeHome $home
        Assert-HarnessCondition ($candidateAfterUpgrade.exit_code -eq 0) (
            'candidate could not reopen its upgraded vault storage'
        )
    }
    finally {
        foreach ($cli in @($candidateCli, $preCli)) {
            try {
                [void](Invoke-IsolatedRuntimeCommand `
                    -Binary $cli `
                    -Arguments "down $ProfileName" `
                    -RuntimeHome $home `
                    -TimeoutSeconds 10)
            }
            catch {}
        }
    }

    Remove-IsolatedRuntimeTree -Path $runtimeRoot -AllowedParent $ScratchRoot
    Copy-RuntimeTree -Source $backupRoot -Destination $runtimeRoot
    Set-TreeRuntimeAcls -Root $runtimeRoot -Evidence $baseline
    $restored = Get-TreeRuntimeEvidence -Root $runtimeRoot
    Assert-RuntimeRecoverySetRestored -Expected $baseline -Actual $restored
    $restoredHome = Join-Path $runtimeRoot 'home'
    $postRollback = Invoke-IsolatedRuntimeCommand `
        -Binary $preCli `
        -Arguments 'list' `
        -RuntimeHome $restoredHome
    Assert-HarnessCondition ($postRollback.exit_code -eq 0) (
        'predecessor could not reopen the exact restored pre-upgrade vault'
    )

    return [ordered]@{
        descriptor_owner_pid = [int64]$descriptorRecord.pid
        descriptor_daemon_identity = [string]$candidate.components.daemon.identity
        descriptor_daemon_sha256 = ([string]$candidate.components.daemon.sha256).ToUpperInvariant()
        beta2_transient_runtime_activation_observed = [bool](
            $beta2RuntimeObservation.beta2_transient_runtime_activation_observed
        )
        beta2_runtime_state_cleaned_after_rejection = [bool](
            $beta2RuntimeObservation.beta2_runtime_state_cleaned_after_rejection
        )
        acceptance_gates = [ordered]@{
            real_v030_beta2_vault_v4_upgrade = 'PASS'
            vault_storage_v4_to_v5_format_upgrade = 'PASS'
            beta2_destructive_writer_outer_gate_rejection = 'PASS'
            matched_bundle_upgrade_activation = 'PASS'
            matched_bundle_rollback_activation = 'PASS'
            runtime_v8_cli_v9_daemon_rejection = 'PASS'
            runtime_v9_cli_v8_daemon_rejection = 'PASS'
            runtime_v8_audit_seed_rejection_before_write = 'PASS'
            runtime_v8_activation_observation_recorded = 'PASS'
            runtime_v8_rejection_runtime_state_cleanup = 'PASS'
            runtime_future_security_field_rejection_before_write = 'PASS'
            runtime_helper_identity_rejection = 'PASS'
            descriptor_owner_and_daemon_lifecycle = 'PASS'
            stale_runtime_descriptor_rejection = 'PASS'
            stale_operation_grant_rejection = 'PASS'
            pre_upgrade_vault_backup_restore = 'PASS'
            matching_recovery_media_restore = 'PASS'
            acl_owner_metadata_restore = 'PASS'
        }
    }
}

function Write-ProtectedWholeBundleReceipt {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][byte[]]$Bytes
    )

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    $parentPath = [System.IO.Path]::GetDirectoryName($fullPath)
    $parent = Get-Item -LiteralPath $parentPath -Force -ErrorAction Stop
    Assert-HarnessCondition (
        $parent.PSIsContainer -and
        ($parent.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0
    ) 'whole-bundle receipt parent is not a regular non-reparse directory'
    Assert-HarnessCondition (-not (Test-Path -LiteralPath $fullPath)) (
        'whole-bundle receipt destination already exists'
    )
    $hash = [System.Security.Cryptography.SHA256]::Create()
    try {
        $expectedHash = [BitConverter]::ToString($hash.ComputeHash($Bytes)).Replace('-', '')
    }
    finally {
        $hash.Dispose()
    }
    $stream = [System.IO.FileStream]::new(
        $fullPath,
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None,
        4096,
        [System.IO.FileOptions]::WriteThrough
    )
    try {
        $stream.Write($Bytes, 0, $Bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
    $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
    $acl = [System.Security.AccessControl.FileSecurity]::new()
    $acl.SetOwner($currentSid)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in @(
        $currentSid,
        [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18'),
        [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
    )) {
        $acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.AccessControlType]::Allow
        ))
    }
    Set-Acl -LiteralPath $fullPath -AclObject $acl -ErrorAction Stop
    $item = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
    Assert-HarnessCondition (
        -not $item.PSIsContainer -and
        ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0 -and
        $item.Length -eq $Bytes.Length -and
        (Get-FileHash -LiteralPath $fullPath -Algorithm SHA256).Hash -ceq $expectedHash
    ) 'whole-bundle receipt post-write hash or identity check failed'
    Assert-HarnessCondition (Get-Acl -LiteralPath $fullPath).AreAccessRulesProtected (
        'whole-bundle receipt DACL still inherits from its parent'
    )
}

function Write-WholeBundleAcceptanceReceipt {
    param(
        [Parameter(Mandatory = $true)]$StructuralReport,
        [Parameter(Mandatory = $true)]$RuntimeResult,
        [Parameter(Mandatory = $true)][DateTimeOffset]$StartedUtc,
        [Parameter(Mandatory = $true)][DateTimeOffset]$CompletedUtc
    )

    foreach ($gate in $RuntimeResult.acceptance_gates.Keys) {
        Assert-HarnessCondition ($RuntimeResult.acceptance_gates[$gate] -ceq 'PASS') (
            'whole-bundle runtime gate set contains a non-passing result'
        )
    }
    $predecessor = $StructuralReport.predecessor
    $candidate = $StructuralReport.candidate
    $details = [ordered]@{
        runner = [ordered]@{
            label = 'windows-whole-bundle-runtime'
            os = 'Windows'
            arch = 'X64'
            rust_host = 'x86_64-pc-windows-msvc'
        }
        predecessor_version = $predecessorVersion
        candidate_version = $candidateVersion
        upgrade_outcome = 'passed'
        rollback_outcome = 'passed'
        predecessor_files = [ordered]@{
            cli_sha256 = ([string]$predecessor.components.cli.sha256).ToUpperInvariant()
            daemon_sha256 = ([string]$predecessor.components.daemon.sha256).ToUpperInvariant()
            xfer_sha256 = ([string]$predecessor.components.helper.sha256).ToUpperInvariant()
        }
        candidate_files = [ordered]@{
            cli_sha256 = ([string]$candidate.components.cli.sha256).ToUpperInvariant()
            daemon_sha256 = ([string]$candidate.components.daemon.sha256).ToUpperInvariant()
            xfer_sha256 = ([string]$candidate.components.helper.sha256).ToUpperInvariant()
        }
        descriptor_owner_pid = [int64]$RuntimeResult.descriptor_owner_pid
        descriptor_daemon_identity = [string]$RuntimeResult.descriptor_daemon_identity
        descriptor_daemon_sha256 = [string]$RuntimeResult.descriptor_daemon_sha256
        whole_bundle_atomic = $true
        mixed_triples_tested = 6
        mixed_triples_rejected = 6
        hash_substitutions_tested = 3
        hash_substitutions_rejected = 3
        stale_descriptor_rejected = $true
        stale_grant_rejected = $true
        matched_bundle_upgrade_verified = $true
        matched_bundle_rollback_verified = $true
        audit_seed_key_package_verified = $true
        vault_storage_v4_to_v5_upgrade_verified = $true
        beta2_destructive_writer_blocked_before_mutation = $true
        beta2_transient_runtime_activation_observed = [bool](
            $RuntimeResult.beta2_transient_runtime_activation_observed
        )
        beta2_runtime_state_cleaned_after_rejection = [bool](
            $RuntimeResult.beta2_runtime_state_cleaned_after_rejection
        )
        candidate_storage_marker_verified = $true
        v8_unknown_audit_fields_rejected_before_write = $true
        unknown_security_fields_not_dropped = $true
        vault_rollback_verified = $true
        pre_upgrade_vault_backup_restored = $true
        matching_recovery_media_restored = $true
        acl_owner_metadata_restored = $true
    }
    $receipt = [ordered]@{
        schema_version = 1
        category = 'whole_bundle_upgrade_rollback'
        status = 'passed'
        tag = $Tag
        tag_object = $TagObject
        commit = $Commit
        release_manifest_sha256 = $ReleaseManifestSha256
        evidence_owner = $EvidenceOwner
        timestamps = [ordered]@{
            started_utc = $StartedUtc.ToString('o')
            completed_utc = $CompletedUtc.ToString('o')
        }
        test_counts = [ordered]@{
            total = 18
            passed = 18
            failed = 0
            skipped = 0
            ignored = 0
            unknown = 0
        }
        limitations = @()
        details = $details
    }
    $json = ($receipt | ConvertTo-Json -Depth 12 -Compress) + "`n"
    $bytes = [System.Text.UTF8Encoding]::new($false, $true).GetBytes($json)
    Write-ProtectedWholeBundleReceipt -Path $ReceiptPath -Bytes $bytes
    return $details
}

function New-FixtureBundle {
    param(
        [Parameter(Mandatory = $true)][string]$Directory,
        [Parameter(Mandatory = $true)][string]$Version,
        [Parameter(Mandatory = $true)][string]$Commit,
        [Parameter(Mandatory = $true)][string]$Ipc
    )

    [System.IO.Directory]::CreateDirectory($Directory) | Out-Null
    $names = Get-PlatformComponentNames
    $identities = [ordered]@{
        cli = if ($Ipc -ceq $candidateIpc) {
            "serctl_cli $Version (git $Commit; $candidateStorageMarker)"
        }
        else {
            "serctl_cli $Version (git $Commit)"
        }
        daemon = if ($Ipc -ceq $candidateIpc) {
            "serctl_daemon $Version (git $Commit; $Ipc; $candidateStorageMarker)"
        }
        else {
            "serctl_daemon $Version (git $Commit; $Ipc)"
        }
        helper = "serctl-xfer $Version (git $Commit; $transferProtocol)"
    }
    foreach ($kind in $names.Keys) {
        Write-NewUtf8Text `
            -Path (Join-Path $Directory $names[$kind]) `
            -Text ("SERCTL_HARNESS_TEST_IDENTITY:" + $identities[$kind] + "`n")
    }
}

$scratch = Join-Path ([System.IO.Path]::GetTempPath()) (
    'serctl-upgrade-rollback-' + [System.Guid]::NewGuid().ToString('N')
)
[System.IO.Directory]::CreateDirectory($scratch) | Out-Null
try {
    if ($PSCmdlet.ParameterSetName -ceq 'SelfTest') {
        $predecessorFixture = Join-Path $scratch 'fixture-v030-beta2'
        $candidateFixture = Join-Path $scratch 'fixture-v1-beta'
        New-FixtureBundle `
            -Directory $predecessorFixture `
            -Version $predecessorVersion `
            -Commit '111111111111' `
            -Ipc $predecessorIpc
        New-FixtureBundle `
            -Directory $candidateFixture `
            -Version $candidateVersion `
            -Commit '222222222222' `
            -Ipc $candidateIpc
        $syntheticSourceCommit = '2222222222222222222222222222222222222222'
        Assert-CandidateMatchesStorageFixtureSource `
            -CandidateCommit '222222222222' `
            -SourceCommit $syntheticSourceCommit
        $mismatchedSourceAccepted = $false
        try {
            Assert-CandidateMatchesStorageFixtureSource `
                -CandidateCommit '222222222222' `
                -SourceCommit '3333333333333333333333333333333333333333'
            $mismatchedSourceAccepted = $true
        }
        catch {
            $mismatchedSourceAccepted = $false
        }
        Assert-HarnessCondition (-not $mismatchedSourceAccepted) (
            'candidate accepted a storage fixture from another source commit'
        )

        $syntheticRecoverySet = [ordered]@{
            'home/.serctl/vault.json' = [ordered]@{
                kind = 'file'
                length = [long]11
                sha256 = ('A' * 64)
                sddl = 'O:BAG:SYD:(A;;FA;;;SY)'
            }
            'recovery-media.srrec' = [ordered]@{
                kind = 'file'
                length = [long]13
                sha256 = ('B' * 64)
                sddl = 'O:BAG:SYD:(A;;FA;;;SY)'
            }
        }
        Assert-RuntimeRecoverySetRestored `
            -Expected $syntheticRecoverySet `
            -Actual $syntheticRecoverySet

        $binaryOnlyRollback = [ordered]@{
            'home/.serctl/vault.json' = $syntheticRecoverySet['home/.serctl/vault.json']
        }
        $binaryOnlyRollbackAccepted = $false
        try {
            Assert-CompleteRecoverySetEvidence `
                -Evidence $binaryOnlyRollback `
                -Context 'binary-only rollback is forbidden'
            $binaryOnlyRollbackAccepted = $true
        }
        catch {
            $binaryOnlyRollbackAccepted = $false
        }
        Assert-HarnessCondition (-not $binaryOnlyRollbackAccepted) (
            'binary-only rollback passed without matching recovery media'
        )

        $aclDriftRecoverySet = [ordered]@{
            'home/.serctl/vault.json' = $syntheticRecoverySet['home/.serctl/vault.json']
            'recovery-media.srrec' = [ordered]@{
                kind = 'file'
                length = [long]13
                sha256 = ('B' * 64)
                sddl = 'O:SYG:SYD:(A;;FA;;;SY)'
            }
        }
        $aclDriftAccepted = $false
        try {
            Assert-RuntimeRecoverySetRestored `
                -Expected $syntheticRecoverySet `
                -Actual $aclDriftRecoverySet
            $aclDriftAccepted = $true
        }
        catch {
            $aclDriftAccepted = $false
        }
        Assert-HarnessCondition (-not $aclDriftAccepted) (
            'rollback accepted changed ACL/owner metadata'
        )

        $byteDriftRecoverySet = [ordered]@{
            'home/.serctl/vault.json' = [ordered]@{
                kind = 'file'
                length = [long]11
                sha256 = ('C' * 64)
                sddl = 'O:BAG:SYD:(A;;FA;;;SY)'
            }
            'recovery-media.srrec' = $syntheticRecoverySet['recovery-media.srrec']
        }
        $byteDriftAccepted = $false
        try {
            Assert-RuntimeRecoverySetRestored `
                -Expected $syntheticRecoverySet `
                -Actual $byteDriftRecoverySet
            $byteDriftAccepted = $true
        }
        catch {
            $byteDriftAccepted = $false
        }
        Assert-HarnessCondition (-not $byteDriftAccepted) (
            'rollback accepted changed pre-upgrade vault bytes/hash'
        )

        foreach ($transientObserved in @($false, $true)) {
            Assert-Beta2RuntimeRejectionObservation -Evidence ([ordered]@{
                beta2_transient_runtime_activation_observed = $transientObserved
                beta2_runtime_state_cleaned_after_rejection = $true
            })
        }
        $uncleanRuntimeAccepted = $false
        try {
            Assert-Beta2RuntimeRejectionObservation -Evidence ([ordered]@{
                beta2_transient_runtime_activation_observed = $true
                beta2_runtime_state_cleaned_after_rejection = $false
            })
            $uncleanRuntimeAccepted = $true
        }
        catch {
            $uncleanRuntimeAccepted = $false
        }
        Assert-HarnessCondition (-not $uncleanRuntimeAccepted) (
            'beta-2 runtime rejection accepted residual descriptor/secret state'
        )
        $untypedActivationAccepted = $false
        try {
            Assert-Beta2RuntimeRejectionObservation -Evidence ([ordered]@{
                beta2_transient_runtime_activation_observed = 'false'
                beta2_runtime_state_cleaned_after_rejection = $true
            })
            $untypedActivationAccepted = $true
        }
        catch {
            $untypedActivationAccepted = $false
        }
        Assert-HarnessCondition (-not $untypedActivationAccepted) (
            'beta-2 runtime rejection accepted a non-boolean activation observation'
        )

        $report = Invoke-HarnessCore `
            -Predecessor $predecessorFixture `
            -Candidate $candidateFixture `
            -FixtureMode $true `
            -ScratchRoot (Join-Path $scratch 'run') `
            -StorageFixtureSourceCommit $syntheticSourceCommit
        Assert-HarnessCondition ($report.result -ceq 'BLOCKED') (
            'synthetic self-test must not report formal acceptance'
        )
        Assert-HarnessCondition (-not [bool]$report.accepted) (
            'synthetic self-test must keep accepted=false'
        )
        $expectedStructuralGates = @(
            'atomic_reference_rollback',
            'atomic_reference_upgrade',
            'audit_seed_directional_source_fixture',
            'candidate_storage_marker_binding',
            'concurrent_reference_change_rejection',
            'failed_activation_atomic_rollback',
            'hash_only_component_mismatch_rejection',
            'identity_and_hashes',
            'mixed_set_pre_activation_rejection',
            'persistent_sentinel_unchanged',
            'post_replace_reference_race_preserved',
            'storage_fixture_source_commit_binding',
            'strict_active_reference_validation',
            'version_only_isolated_home'
        )
        Assert-HarnessCondition (
            ((@($report.structural_gates.Keys) | Sort-Object) -join ',') -ceq
            ($expectedStructuralGates -join ',')
        ) 'synthetic structural gate set is incomplete or contains an unknown gate'
        foreach ($gate in $report.structural_gates.Keys) {
            Assert-HarnessCondition ($report.structural_gates[$gate] -ceq 'PASS') (
                "synthetic structural gate '$gate' did not pass"
            )
        }
        $expectedAcceptanceGates = @(
            'acl_owner_metadata_restore',
            'beta2_destructive_writer_outer_gate_rejection',
            'descriptor_owner_and_daemon_lifecycle',
            'matched_bundle_rollback_activation',
            'matched_bundle_upgrade_activation',
            'matching_recovery_media_restore',
            'pre_upgrade_vault_backup_restore',
            'real_v030_beta2_vault_v4_upgrade',
            'runtime_future_security_field_rejection_before_write',
            'runtime_helper_identity_rejection',
            'runtime_v8_activation_observation_recorded',
            'runtime_v8_audit_seed_rejection_before_write',
            'runtime_v8_cli_v9_daemon_rejection',
            'runtime_v8_rejection_runtime_state_cleanup',
            'runtime_v9_cli_v8_daemon_rejection',
            'stale_operation_grant_rejection',
            'stale_runtime_descriptor_rejection',
            'vault_storage_v4_to_v5_format_upgrade'
        )
        Assert-HarnessCondition (
            ((@($report.acceptance_gates.Keys) | Sort-Object) -join ',') -ceq
            ($expectedAcceptanceGates -join ',')
        ) 'synthetic acceptance gate set is incomplete or contains an unknown gate'
        foreach ($gate in $report.acceptance_gates.Keys) {
            Assert-HarnessCondition ($report.acceptance_gates[$gate] -ceq 'BLOCKED_NOT_RUN') (
                "synthetic acceptance gate '$gate' did not remain blocked"
            )
        }
        $expectedMixedChecks = @(
            'candidate_cli_hash_mismatch',
            'candidate_daemon_hash_mismatch',
            'candidate_helper_hash_mismatch',
            'predecessor_candidate_selection_1',
            'predecessor_candidate_selection_2',
            'predecessor_candidate_selection_3',
            'predecessor_candidate_selection_4',
            'predecessor_candidate_selection_5',
            'predecessor_candidate_selection_6'
        )
        Assert-HarnessCondition (
            ((@($report.mixed_set_checks.Keys) | Sort-Object) -join ',') -ceq
            ($expectedMixedChecks -join ',')
        ) 'synthetic mixed-set coverage is incomplete or contains an unknown check'

        $names = Get-PlatformComponentNames
        $candidateCli = Join-Path $candidateFixture $names.cli
        $candidateCliBytes = [System.IO.File]::ReadAllBytes($candidateCli)
        [System.IO.File]::WriteAllText(
            $candidateCli,
            (
                'SERCTL_HARNESS_TEST_IDENTITY:' +
                "serctl_cli $candidateVersion (git 222222222222; $candidateStorageMarker) " +
                "also-serctl_cli $predecessorVersion (git 111111111111)`n"
            ),
            [System.Text.UTF8Encoding]::new($false)
        )
        $ambiguousIdentityAccepted = $false
        try {
            Invoke-HarnessCore `
                -Predecessor $predecessorFixture `
                -Candidate $candidateFixture `
                -FixtureMode $true `
                -ScratchRoot (Join-Path $scratch 'ambiguous-identity-run') `
                -StorageFixtureSourceCommit $syntheticSourceCommit *> $null
            $ambiguousIdentityAccepted = $true
        }
        catch {
            $ambiguousIdentityAccepted = $false
        }
        Assert-HarnessCondition (-not $ambiguousIdentityAccepted) (
            'candidate identity containing conflicting appended identity text was not rejected'
        )
        [System.IO.File]::WriteAllBytes($candidateCli, $candidateCliBytes)

        $candidateHelper = Join-Path $candidateFixture $names.helper
        [System.IO.File]::WriteAllText(
            $candidateHelper,
            (
                'SERCTL_HARNESS_TEST_IDENTITY:' +
                "serctl-xfer $predecessorVersion (git 222222222222; $transferProtocol)`n"
            ),
            [System.Text.UTF8Encoding]::new($false)
        )
        $tamperedAccepted = $false
        try {
            Invoke-HarnessCore `
                -Predecessor $predecessorFixture `
                -Candidate $candidateFixture `
                -FixtureMode $true `
                -ScratchRoot (Join-Path $scratch 'tampered-run') `
                -StorageFixtureSourceCommit $syntheticSourceCommit *> $null
            $tamperedAccepted = $true
        }
        catch {
            $tamperedAccepted = $false
        }
        Assert-HarnessCondition (-not $tamperedAccepted) (
            'candidate helper version tampering was not rejected'
        )
        Write-Host 'Whole-bundle upgrade/rollback harness self-test passed without formal acceptance.'
        return
    }

    $storageFixtureSourceCommit = Get-CleanStorageFixtureSourceCommit
    $report = Invoke-HarnessCore `
        -Predecessor $PredecessorDirectory `
        -Candidate $CandidateDirectory `
        -FixtureMode $false `
        -ScratchRoot (Join-Path $scratch 'run') `
        -StorageFixtureSourceCommit $storageFixtureSourceCommit
    if ($PSCmdlet.ParameterSetName -ceq 'Runtime') {
        Assert-SafeEvidenceOwner -Value $EvidenceOwner
        Assert-HarnessCondition ($Tag.Substring(1) -ceq $CandidateVersion) (
            'runtime receipt tag does not match the exact candidate version'
        )
        Assert-HarnessCondition (
            $Commit.StartsWith([string]$report.candidate.commit, [StringComparison]::Ordinal)
        ) 'runtime receipt commit does not match the candidate component commit'
        $startedUtc = [DateTimeOffset]::UtcNow
        $runtime = Invoke-WholeBundleRuntimeGates `
            -StructuralReport $report `
            -FixtureDirectory $RuntimeFixtureDirectory `
            -ProfileName $RuntimeProfileName `
            -ScratchRoot (Join-Path $scratch 'formal-runtime')
        $completedUtc = [DateTimeOffset]::UtcNow
        $details = Write-WholeBundleAcceptanceReceipt `
            -StructuralReport $report `
            -RuntimeResult $runtime `
            -StartedUtc $startedUtc `
            -CompletedUtc $completedUtc
        Write-Output (($details | ConvertTo-Json -Depth 12 -Compress) + "`n")
        return
    }

    $json = ($report | ConvertTo-Json -Depth 12) + "`n"
    if (-not [string]::IsNullOrWhiteSpace($ReportPath)) {
        $fullReportPath = [System.IO.Path]::GetFullPath($ReportPath)
        Assert-HarnessCondition (-not (Test-Path -LiteralPath $fullReportPath)) (
            "refusing to overwrite report '$fullReportPath'"
        )
        $reportParent = [System.IO.Path]::GetDirectoryName($fullReportPath)
        Assert-HarnessCondition (Test-Path -LiteralPath $reportParent -PathType Container) (
            "report parent '$reportParent' does not exist"
        )
        Write-NewUtf8Text -Path $fullReportPath -Text $json
    }
    Write-Output $json
    throw 'formal upgrade/rollback acceptance remains BLOCKED; see report acceptance_gates'
}
finally {
    if (Test-Path -LiteralPath $scratch) {
        [System.IO.Directory]::Delete($scratch, $true)
    }
}
