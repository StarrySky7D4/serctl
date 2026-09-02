[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('windows-x86_64', 'linux-x86_64')]
    [string]$Platform,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Version,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{40}$')]
    [string]$Commit,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[0-9a-fA-F]{40}$')]
    [string]$TagObject,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$OutputDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ReleaseLogSanitization.ps1')
$hostIsWindows = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
    [System.Runtime.InteropServices.OSPlatform]::Windows
)
$hostIsLinux = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
    [System.Runtime.InteropServices.OSPlatform]::Linux
)
$ipcContract = 'IPC v9..=v9'
$transferProtocolContract = 'transfer protocol v1'
$vaultStorageContract = 'vault-storage read=v4..=v5 write=v5'

function Assert-BundleCondition {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if (-not $Condition) {
        throw "release bundle check failed: $Message"
    }
}

function Assert-NewOutputPath {
    param([Parameter(Mandatory = $true)][string]$Path)
    Assert-BundleCondition (-not (Test-Path -LiteralPath $Path)) (
        'refusing to overwrite an existing output'
    )
}

function Get-CheckedVersionLine {
    param([Parameter(Mandatory = $true)][string]$BinaryPath)

    $binaryName = Get-ReleaseLogLeafName -Path $BinaryPath -Fallback 'release-binary'
    Assert-BundleCondition (Test-Path -LiteralPath $BinaryPath -PathType Leaf) (
        "required binary '$binaryName' is missing"
    )
    $line = (& $BinaryPath --version 2>$null | Out-String).Trim()
    Assert-BundleCondition ($LASTEXITCODE -eq 0) "'$binaryName --version' failed"
    Assert-BundleCondition (-not [string]::IsNullOrWhiteSpace($line)) (
        "'$binaryName --version' returned no identity"
    )
    Assert-BundleCondition (-not $line.Contains("`n") -and -not $line.Contains("`r")) (
        "'$binaryName --version' returned multiple lines"
    )
    $expectedCommit = $Commit.Substring(0, 12).ToLowerInvariant()
    $versionPattern = [regex]::Escape($Version)
    $commitPattern = [regex]::Escape($expectedCommit)
    $identityPattern = switch -Regex ($binaryName) {
        '^serctl_cli(?:\.exe)?$' {
            '^serctl_cli ' + $versionPattern + ' \(git ' + $commitPattern + '; ' +
                [regex]::Escape($vaultStorageContract) + '\)$'
        }
        '^serctl_daemon(?:\.exe)?$' {
            '^serctl_daemon ' + $versionPattern + ' \(git ' + $commitPattern +
                '; ' + [regex]::Escape($ipcContract) + '; ' +
                [regex]::Escape($vaultStorageContract) + '\)$'
        }
        '^serctl-xfer(?:\.exe)?$' {
            '^serctl-xfer ' + $versionPattern + ' \(git ' + $commitPattern +
                '; ' + [regex]::Escape($transferProtocolContract) + '\)$'
        }
        default { $null }
    }
    Assert-BundleCondition ($null -ne $identityPattern) (
        "release bundler does not recognize binary '$binaryName'"
    )
    Assert-BundleCondition ([regex]::IsMatch(
        $line,
        $identityPattern,
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    )) "binary '$binaryName' does not report the exact release identity"
    return $line
}

function Get-LinuxGlibcEvidence {
    param([Parameter(Mandatory = $true)][string]$BinaryPath)

    $checkScript = Join-Path $PSScriptRoot 'Test-LinuxGlibcBaseline.ps1'
    return & $checkScript -BinaryPath $BinaryPath -MaximumSupported '2.35'
}

function Copy-GovernanceFiles {
    param(
        [Parameter(Mandatory = $true)][string]$RepositoryRoot,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    Copy-Item -LiteralPath (Join-Path $RepositoryRoot 'LICENSE') -Destination $Destination
    Copy-Item -LiteralPath (Join-Path $RepositoryRoot 'SECURITY.md') -Destination $Destination
    Copy-Item -LiteralPath (
        Join-Path $RepositoryRoot 'docs/v1-beta-agent-jsonl.md'
    ) -Destination $Destination
    Copy-Item -LiteralPath (
        Join-Path $RepositoryRoot 'docs/v1-beta-release-contract.md'
    ) -Destination $Destination
    Copy-Item -LiteralPath (
        Join-Path $RepositoryRoot 'docs/v1-beta-acceptance-matrix.md'
    ) -Destination $Destination
}

function Compress-DirectoryAsZip {
    param(
        [Parameter(Mandatory = $true)][string]$SourceDirectory,
        [Parameter(Mandatory = $true)][string]$DestinationPath
    )

    $files = @(
        Get-ChildItem -LiteralPath $SourceDirectory -Force |
            Sort-Object Name |
            ForEach-Object { $_.FullName }
    )
    Assert-BundleCondition ($files.Count -gt 0) 'bundle staging directory is empty'
    Compress-Archive -LiteralPath $files -DestinationPath $DestinationPath -CompressionLevel Optimal
}

function Compress-DirectoryAsTarGz {
    param(
        [Parameter(Mandatory = $true)][string]$SourceDirectory,
        [Parameter(Mandatory = $true)][string]$DestinationPath
    )

    $names = @(
        Get-ChildItem -LiteralPath $SourceDirectory -Force -File |
            Sort-Object Name |
            ForEach-Object { $_.Name }
    )
    Assert-BundleCondition ($names.Count -gt 0) (
        'bundle staging directory is empty'
    )
    $tarArguments = @(
        '--format=ustar',
        '--create',
        '--gzip',
        '--file',
        $DestinationPath,
        '--directory',
        $SourceDirectory,
        '--'
    ) + $names
    & tar @tarArguments *> $null
    Assert-BundleCondition ($LASTEXITCODE -eq 0) 'tar archive creation failed'
}

function Set-LinuxReleaseModes {
    param(
        [Parameter(Mandatory = $true)][string]$RuntimeDirectory,
        [Parameter(Mandatory = $true)][string]$SymbolsDirectory
    )
    $helper = Join-Path $RuntimeDirectory 'serctl-xfer'
    & chmod 0755 -- $helper
    Assert-BundleCondition ($LASTEXITCODE -eq 0) 'failed to set serctl-xfer mode 0755'
    foreach ($file in @(
        Get-ChildItem -LiteralPath $RuntimeDirectory -Force -File |
            Where-Object { $_.Name -cne 'serctl-xfer' }
    ) + @(Get-ChildItem -LiteralPath $SymbolsDirectory -Force -File)) {
        & chmod 0644 -- $file.FullName
        Assert-BundleCondition ($LASTEXITCODE -eq 0) (
            "failed to set non-runtime release member '$($file.Name)' mode 0644"
        )
    }
}

$logLeaf = 'release-bundle'
$logBytes = [long]0
try {
$versionPattern = '^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)-(?:alpha|beta|rc)(?:\.(?:0|[1-9][0-9]*))?$'
Assert-BundleCondition ([regex]::IsMatch(
    $Version,
    $versionPattern,
    [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
)) "version '$Version' is not a canonical prerelease version"

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$outputRoot = [System.IO.Path]::GetFullPath($OutputDirectory)
[string[]]$requiredEnvironment = @(
    'GITHUB_REPOSITORY',
    'GITHUB_WORKFLOW',
    'GITHUB_WORKFLOW_REF',
    'GITHUB_RUN_ID',
    'GITHUB_RUN_ATTEMPT',
    'GITHUB_REF',
    'SOURCE_DATE_EPOCH',
    'RUNNER_OS',
    'RUNNER_ARCH',
    'ImageOS',
    'ImageVersion',
    'CARGO_PROFILE_RELEASE_DEBUG',
    'CARGO_PROFILE_RELEASE_STRIP',
    'CARGO_TARGET_DIR'
)
foreach ($name in $requiredEnvironment) {
    Assert-BundleCondition (-not [string]::IsNullOrWhiteSpace(
        [System.Environment]::GetEnvironmentVariable($name, 'Process')
    )) "required build environment '$name' is missing"
}
Assert-BundleCondition ($env:SOURCE_DATE_EPOCH -match '^[0-9]+$') (
    'SOURCE_DATE_EPOCH must be an unsigned Unix timestamp'
)
Assert-BundleCondition ($env:RUNNER_ARCH -ceq 'X64') (
    "release platform '$Platform' requires an X64 runner, found '$env:RUNNER_ARCH'"
)
Assert-BundleCondition (
    ($Platform -ceq 'windows-x86_64' -and $hostIsWindows) -or
    ($Platform -ceq 'linux-x86_64' -and $hostIsLinux)
) "release platform '$Platform' does not match the current operating system"

$headCommit = (& git -C $repositoryRoot rev-parse HEAD 2>$null | Out-String).Trim().ToLowerInvariant()
Assert-BundleCondition ($LASTEXITCODE -eq 0) 'cannot resolve release checkout HEAD'
Assert-BundleCondition ($headCommit -ceq $Commit.ToLowerInvariant()) (
    "release checkout HEAD '$headCommit' does not equal requested commit '$Commit'"
)
$commitEpoch = (& git -C $repositoryRoot show -s --format=%ct HEAD 2>$null | Out-String).Trim()
Assert-BundleCondition ($LASTEXITCODE -eq 0) 'cannot read release commit timestamp'
Assert-BundleCondition ($commitEpoch -ceq $env:SOURCE_DATE_EPOCH) (
    "SOURCE_DATE_EPOCH '$env:SOURCE_DATE_EPOCH' does not equal commit timestamp '$commitEpoch'"
)
$releaseRoot = [System.IO.Path]::GetFullPath(
    (Join-Path $repositoryRoot (Join-Path $env:CARGO_TARGET_DIR 'release'))
)
$repositoryPrefix = $repositoryRoot.TrimEnd(
    [System.IO.Path]::DirectorySeparatorChar
) + [System.IO.Path]::DirectorySeparatorChar
$pathComparison = if ($hostIsWindows) {
    [System.StringComparison]::OrdinalIgnoreCase
}
else {
    [System.StringComparison]::Ordinal
}
Assert-BundleCondition ($releaseRoot.StartsWith($repositoryPrefix, $pathComparison)) (
    'CARGO_TARGET_DIR resolves outside the repository'
)
[System.IO.Directory]::CreateDirectory($outputRoot) | Out-Null

$stageRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'serctl-release-' + [System.Guid]::NewGuid().ToString('N')
)
$mainStage = Join-Path $stageRoot 'main'
$symbolsStage = Join-Path $stageRoot 'symbols'
[System.IO.Directory]::CreateDirectory($mainStage) | Out-Null
[System.IO.Directory]::CreateDirectory($symbolsStage) | Out-Null

try {
    $binaryEvidence = [ordered]@{}
    $runtimeAbiEvidence = $null
    if ($Platform -ceq 'windows-x86_64') {
        $cli = Join-Path $releaseRoot 'serctl_cli.exe'
        $daemon = Join-Path $releaseRoot 'serctl_daemon.exe'
        $cliPdb = Join-Path $releaseRoot 'serctl_cli.pdb'
        $daemonPdb = Join-Path $releaseRoot 'serctl_daemon.pdb'
        $binaryEvidence['serctl_cli.exe'] = Get-CheckedVersionLine $cli
        $binaryEvidence['serctl_daemon.exe'] = Get-CheckedVersionLine $daemon
        Assert-BundleCondition (
            (Test-Path -LiteralPath $cliPdb -PathType Leaf) -and
            (Get-Item -LiteralPath $cliPdb).Length -gt 0
        ) 'CLI PDB is missing or empty'
        Assert-BundleCondition (
            (Test-Path -LiteralPath $daemonPdb -PathType Leaf) -and
            (Get-Item -LiteralPath $daemonPdb).Length -gt 0
        ) 'daemon PDB is missing or empty'

        Copy-Item -LiteralPath $cli, $daemon -Destination $mainStage
        Copy-Item -LiteralPath $cliPdb, $daemonPdb -Destination $symbolsStage
        $mainArchive = Join-Path $outputRoot "serctl-$Version-windows-x86_64.zip"
        $symbolsArchive = Join-Path $outputRoot "serctl-$Version-windows-x86_64-symbols.zip"
        $archiveKind = 'zip'
        $runtimeAbiEvidence = [ordered]@{
            family = 'windows-msvc'
            architecture = 'x86_64'
        }
    }
    else {
        $helpers = @('serctl-xfer')
        $forbiddenRuntimeArtifacts = @('serctl-remote', 'serctl-remote.debug')
        foreach ($forbiddenName in $forbiddenRuntimeArtifacts) {
            Assert-BundleCondition (-not (Test-Path -LiteralPath (
                Join-Path $releaseRoot $forbiddenName
            ))) (
                "source-only experimental artifact '$forbiddenName' is present in release staging"
            )
        }
        foreach ($helperName in $helpers) {
            $helper = Join-Path $releaseRoot $helperName
            $helperDebug = Join-Path $releaseRoot "$helperName.debug"
            $binaryEvidence[$helperName] = Get-CheckedVersionLine $helper
            $runtimeAbiEvidence = Get-LinuxGlibcEvidence $helper
            Assert-BundleCondition (
                (Test-Path -LiteralPath $helperDebug -PathType Leaf) -and
                (Get-Item -LiteralPath $helperDebug).Length -gt 0
            ) (
                "Linux $helperName debug symbols are missing or empty; create them before packaging"
            )
            Copy-Item -LiteralPath $helper -Destination $mainStage
            Copy-Item -LiteralPath $helperDebug -Destination $symbolsStage
        }
        $mainArchive = Join-Path $outputRoot "serctl-$Version-linux-x86_64-xfer.tar.gz"
        $symbolsArchive = Join-Path $outputRoot "serctl-$Version-linux-x86_64-xfer-symbols.tar.gz"
        $archiveKind = 'tar.gz'
    }

    Copy-GovernanceFiles $repositoryRoot $mainStage
    $binaryComponents = @()
    foreach ($binaryName in $binaryEvidence.Keys) {
        $binaryPath = Join-Path $mainStage $binaryName
        $binaryItem = Get-Item -LiteralPath $binaryPath -Force -ErrorAction Stop
        Assert-BundleCondition (
            -not $binaryItem.PSIsContainer -and
            ($binaryItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0 -and
            [long]$binaryItem.Length -gt 0
        ) "release binary '$binaryName' is not one nonempty regular file"
        $binaryComponents += [pscustomobject][ordered]@{
            name = $binaryName
            binary_size = [long]$binaryItem.Length
            sha256 = (
                Get-FileHash -LiteralPath $binaryItem.FullName -Algorithm SHA256
            ).Hash.ToLowerInvariant()
            version = [string]$binaryEvidence[$binaryName]
        }
    }
    $symbolHashes = [ordered]@{}
    foreach ($symbol in Get-ChildItem -LiteralPath $symbolsStage -File | Sort-Object Name) {
        $symbolHashes[$symbol.Name] = (
            Get-FileHash -LiteralPath $symbol.FullName -Algorithm SHA256
        ).Hash.ToLowerInvariant()
    }

    $provenance = [ordered]@{
        schema_version = 2
        version = $Version
        tag = "v$Version"
        tag_object = $TagObject.ToLowerInvariant()
        commit = $Commit.ToLowerInvariant()
        platform = $Platform
        repository = $env:GITHUB_REPOSITORY
        workflow = $env:GITHUB_WORKFLOW
        workflow_ref = $env:GITHUB_WORKFLOW_REF
        run_id = $env:GITHUB_RUN_ID
        run_attempt = $env:GITHUB_RUN_ATTEMPT
        ref = $env:GITHUB_REF
        source_date_epoch = $env:SOURCE_DATE_EPOCH
        runner_os = $env:RUNNER_OS
        runner_arch = $env:RUNNER_ARCH
        runner_image = "$env:ImageOS-$env:ImageVersion"
        runtime_abi = $runtimeAbiEvidence
        rustc = (& rustc --version --verbose 2>$null | Out-String).Trim()
        cargo = (& cargo --version --verbose 2>$null | Out-String).Trim()
        cargo_lock_sha256 = (
            Get-FileHash -LiteralPath (Join-Path $repositoryRoot 'Cargo.lock') -Algorithm SHA256
        ).Hash.ToLowerInvariant()
        rust_toolchain_sha256 = (
            Get-FileHash -LiteralPath (
                Join-Path $repositoryRoot 'rust-toolchain.toml'
            ) -Algorithm SHA256
        ).Hash.ToLowerInvariant()
        release_debug = $env:CARGO_PROFILE_RELEASE_DEBUG
        release_strip = $env:CARGO_PROFILE_RELEASE_STRIP
        cargo_target_dir = $env:CARGO_TARGET_DIR
        binary_components = @($binaryComponents)
        symbol_sha256 = $symbolHashes
    }
    $provenanceName = "serctl-$Version-$Platform.provenance.json"
    $provenancePath = Join-Path $outputRoot $provenanceName
    Assert-NewOutputPath $provenancePath
    [System.IO.File]::WriteAllText(
        $provenancePath,
        ($provenance | ConvertTo-Json -Depth 8) + "`n",
        [System.Text.UTF8Encoding]::new($false)
    )
    Copy-Item -LiteralPath $provenancePath -Destination $mainStage

    Assert-NewOutputPath $mainArchive
    Assert-NewOutputPath $symbolsArchive
    $logLeaf = Get-ReleaseLogLeafName -Path $mainArchive -Fallback 'release-bundle'
    if ($archiveKind -ceq 'zip') {
        Compress-DirectoryAsZip $mainStage $mainArchive
        Compress-DirectoryAsZip $symbolsStage $symbolsArchive
    }
    else {
        Set-LinuxReleaseModes `
            -RuntimeDirectory $mainStage `
            -SymbolsDirectory $symbolsStage
        Compress-DirectoryAsTarGz $mainStage $mainArchive
        Compress-DirectoryAsTarGz $symbolsStage $symbolsArchive
    }

    Write-Host (
        "Created release bundle '" +
        [System.IO.Path]::GetFileName($mainArchive) +
        "'."
    )
    Write-Host (
        "Created separate symbols bundle '" +
        [System.IO.Path]::GetFileName($symbolsArchive) +
        "'."
    )
}
finally {
    if (Test-Path -LiteralPath $stageRoot) {
        [System.IO.Directory]::Delete($stageRoot, $true)
    }
}
}
catch {
    try {
        if ($null -ne $mainArchive -and (Test-Path -LiteralPath $mainArchive -PathType Leaf)) {
            $logBytes = [long](Get-Item -LiteralPath $mainArchive -Force).Length
        }
    }
    catch { $logBytes = 0 }
    [Console]::Error.WriteLine(
        'release bundle failed: ' +
        (Format-ReleaseLogRecord `
            -Category release_bundle_failed `
            -LeafName $logLeaf `
            -Bytes $logBytes)
    )
    exit 1
}
