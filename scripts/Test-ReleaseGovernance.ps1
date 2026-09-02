[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-TestCondition {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if (-not $Condition) {
        throw "release governance self-test failed: $Message"
    }
}

function Invoke-ExpectedFailure {
    param([Parameter(Mandatory = $true)][string]$Tag)

    $failed = $false
    try {
        & $verifyScript -Tag $Tag *> $null
    }
    catch {
        $failed = $true
    }
    Assert-TestCondition $failed "tag '$Tag' unexpectedly passed verification"
}

function Invoke-ExpectedScriptFailure {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Action,
        [Parameter(Mandatory = $true)][string]$Description
    )

    $failed = $false
    try {
        & $Action *> $null
    }
    catch {
        $failed = $true
    }
    Assert-TestCondition $failed "$Description unexpectedly succeeded"
}

function Invoke-CheckedChildScript {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Description
    )

    $global:LASTEXITCODE = 0
    & $Path
    $childExitCode = $global:LASTEXITCODE
    Assert-TestCondition ($childExitCode -eq 0) (
        "$Description exited with code $childExitCode"
    )
}

function Assert-NativeMatrixJob {
    param(
        [Parameter(Mandatory = $true)][string]$Source,
        [Parameter(Mandatory = $true)][string]$Description
    )

    $testJob = [regex]::Match(
        $Source,
        '(?ms)^  test:\r?\n(?<body>.*?)(?=^  rustsec:\r?\n)'
    )
    Assert-TestCondition $testJob.Success "$Description has no bounded test job"
    $body = $testJob.Groups['body'].Value
    $normalized = [regex]::Replace($body, '\s+', ' ').Trim()

    $nativeRows = @(
        @('Ubuntu x86_64', 'ubuntu-latest', 'Linux', 'X64', 'x86_64-unknown-linux-gnu'),
        @('Windows x86_64', 'windows-latest', 'Windows', 'X64', 'x86_64-pc-windows-msvc'),
        @('macOS arm64', 'macos-15', 'macOS', 'ARM64', 'aarch64-apple-darwin'),
        @('macOS x86_64', 'macos-15-intel', 'macOS', 'X64', 'x86_64-apple-darwin')
    )
    foreach ($row in $nativeRows) {
        $tuplePattern = (
            '(?ms)^\s*- name:\s*' + [regex]::Escape($row[0]) + '\s*\r?\n' +
            '\s*runner:\s*' + [regex]::Escape($row[1]) + '\s*\r?\n' +
            '\s*expected_os:\s*' + [regex]::Escape($row[2]) + '\s*\r?\n' +
            '\s*expected_arch:\s*' + [regex]::Escape($row[3]) + '\s*\r?\n' +
            '\s*expected_rust_host:\s*' + [regex]::Escape($row[4]) + '\s*$'
        )
        Assert-TestCondition (
            ([regex]::Matches($body, $tuplePattern)).Count -eq 1
        ) (
            "$Description must contain exactly one native tuple " +
            "'$($row -join '/')'"
        )
    }

    foreach ($command in @(
        'cargo check --locked --workspace --all-targets --all-features --target ${{ matrix.expected_rust_host }}',
        'cargo clippy --locked --workspace --all-targets --all-features --target ${{ matrix.expected_rust_host }} -- -D warnings',
        'cargo test --locked --workspace --all-targets --all-features --target ${{ matrix.expected_rust_host }} -- --test-threads=1',
        'cargo build --locked -p serctl-cli --bin serctl_cli --target ${{ matrix.expected_rust_host }}',
        '-CliPath target/${{ matrix.expected_rust_host }}/debug/serctl_cli.exe'
    )) {
        Assert-TestCondition (
            ([regex]::Matches($normalized, [regex]::Escape($command))).Count -eq 1
        ) "$Description must bind exactly one matrix command to the declared native Cargo target: '$command'"
    }

    foreach ($cargoPrefix in @(
        'cargo check --locked --workspace --all-targets --all-features',
        'cargo clippy --locked --workspace --all-targets --all-features',
        'cargo test --locked --workspace --all-targets --all-features',
        'cargo build --locked -p serctl-cli --bin serctl_cli'
    )) {
        Assert-TestCondition (
            ([regex]::Matches($normalized, [regex]::Escape($cargoPrefix))).Count -eq 1
        ) "$Description contains a duplicate or unbound native matrix command: '$cargoPrefix'"
    }

    $architectureCheck = $normalized.IndexOf(
        'Require the declared native runner architecture',
        [System.StringComparison]::Ordinal
    )
    $firstCargoCheck = $normalized.IndexOf(
        'cargo check --locked --workspace',
        [System.StringComparison]::Ordinal
    )
    $buildScriptFixtures = $normalized.IndexOf(
        'Run build-script fixtures on the native runner shell: pwsh run: ./scripts/Test-BuildScriptFixtures.ps1',
        [System.StringComparison]::Ordinal
    )
    Assert-TestCondition (
        $architectureCheck -ge 0 -and $firstCargoCheck -gt $architectureCheck
    ) "$Description does not fail on native runner identity before compiling"
    Assert-TestCondition (
        $buildScriptFixtures -gt $architectureCheck -and
        $firstCargoCheck -gt $buildScriptFixtures -and
        ([regex]::Matches(
            $body,
            [regex]::Escape('./scripts/Test-BuildScriptFixtures.ps1')
        )).Count -eq 1
    ) "$Description does not run build-script fixtures exactly once on every native row before Cargo"

    $portableContractGate = $normalized.IndexOf(
        'Verify portable release archives and the isolated fuzz lock shell: pwsh run: |',
        [System.StringComparison]::Ordinal
    )
    Assert-TestCondition (
        $portableContractGate -gt $buildScriptFixtures -and
        $firstCargoCheck -gt $portableContractGate
    ) "$Description does not run the portable release/fuzz contract gate before workspace Cargo"
    foreach ($portableCommand in @(
        'cargo metadata --manifest-path fuzz/Cargo.toml --locked --format-version 1 | Out-Null',
        "if (`$LASTEXITCODE -ne 0) { throw 'isolated fuzz lock metadata resolution failed' }",
        './scripts/Test-ParserFuzzBoundary.ps1 -RepositoryRoot .',
        './scripts/Test-DownloadedReleaseSetSelfTest.ps1',
        './scripts/Test-ReleaseAssetSnapshot.ps1'
    )) {
        Assert-TestCondition (
            ([regex]::Matches($normalized, [regex]::Escape($portableCommand))).Count -eq 1
        ) (
            "$Description must run exactly one portable matrix contract command: " +
            "'$portableCommand'"
        )
    }

    $windowsCliBuild = [regex]::Match(
        $body,
        "(?ms)^      - name: Build the CLI for mandatory Windows multi-account ACL testing\r?\n" +
        "        if: runner\.os == 'Windows'\r?\n" +
        "        run: >-\r?\n" +
        "          cargo build --locked -p serctl-cli --bin serctl_cli\r?\n" +
        "          --target \$\{\{ matrix\.expected_rust_host \}\}\s*$"
    )
    $windowsAclGate = [regex]::Match(
        $body,
        "(?ms)^      - name: Require Windows multi-account DACL and owner isolation\r?\n" +
        "        if: runner\.os == 'Windows'\r?\n" +
        "        shell: pwsh\r?\n" +
        "        run: >-\r?\n" +
        "          \./scripts/Test-WindowsMultiAccountAcl\.ps1\r?\n" +
        "          -CliPath target/\$\{\{ matrix\.expected_rust_host \}\}/debug/serctl_cli\.exe\s*$"
    )
    Assert-TestCondition $windowsCliBuild.Success (
        "$Description does not bind the ACL candidate build exclusively to Windows"
    )
    Assert-TestCondition $windowsAclGate.Success (
        "$Description does not bind the non-skippable ACL gate exclusively to Windows/pwsh"
    )
    Assert-TestCondition ($windowsAclGate.Index -gt $windowsCliBuild.Index) (
        "$Description runs the Windows ACL gate before its candidate CLI build"
    )
    Assert-TestCondition (-not ($body -match '(?m)^\s*continue-on-error:\s*true\s*$')) (
        "$Description permits a native acceptance step to fail without failing the job"
    )
}

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$verifyScript = Join-Path $PSScriptRoot 'Verify-ReleaseConsistency.ps1'
$releaseConsistencySelfTestScript = Join-Path `
    $PSScriptRoot `
    'Test-ReleaseConsistencySelfTest.ps1'
$releaseVersionSwitchSelfTestScript = Join-Path `
    $PSScriptRoot `
    'Test-V1ReleaseVersionSwitch.ps1'
$isolatedCandidateScript = Join-Path `
    $PSScriptRoot `
    'New-IsolatedCandidate.ps1'
$isolatedCandidateSelfTestScript = Join-Path `
    $PSScriptRoot `
    'Test-IsolatedCandidateSelfTest.ps1'
$externalRuntimeSupervisorScript = Join-Path `
    $PSScriptRoot `
    'ExternalRuntimeProcessSupervisor.ps1'
$externalRuntimeSupervisorSelfTestScript = Join-Path `
    $PSScriptRoot `
    'Test-ExternalRuntimeProcessSupervisor.ps1'
$externalTransferRuntimeAdapterScript = Join-Path `
    $PSScriptRoot `
    'ExternalTransferRuntimeAdapter.ps1'
$externalTransferRuntimeAdapterSelfTestScript = Join-Path `
    $PSScriptRoot `
    'Test-ExternalTransferRuntimeAdapter.ps1'
$isolatedExternalTransferOwnerLauncherScript = Join-Path `
    $PSScriptRoot `
    'ExternalTransferIsolatedOwnerLauncher.ps1'
$isolatedExternalTransferOwnerScript = Join-Path `
    $PSScriptRoot `
    'Invoke-IsolatedExternalTransferFormalOwner.ps1'
$isolatedExternalTransferOwnerSelfTestScript = Join-Path `
    $PSScriptRoot `
    'Test-IsolatedExternalTransferFormalOwner.ps1'
$externalTransferOfficialComponentAnchorScript = Join-Path `
    $PSScriptRoot `
    'ExternalTransferOfficialComponentAnchor.ps1'
$externalTransferOfficialComponentAnchorSelfTestScript = Join-Path `
    $PSScriptRoot `
    'Test-ExternalTransferOfficialComponentAnchor.ps1'
$nativeFaultRegistryPerformanceFixtureScript = Join-Path `
    $PSScriptRoot `
    'NativeFaultRegistryPerformanceFixture.ps1'
$nativeFaultRegistryPerformanceLauncherScript = Join-Path `
    $PSScriptRoot `
    'NativeFaultRegistryPerformanceActualCaptureLauncher.ps1'
$nativeFaultRegistryPerformanceOwnerScript = Join-Path `
    $PSScriptRoot `
    'Invoke-NativeFaultRegistryPerformanceActualCaptureOwner.ps1'
$nativeFaultRegistryPerformanceOwnerSelfTestScript = Join-Path `
    $PSScriptRoot `
    'Test-NativeFaultRegistryPerformanceActualCaptureOwner.ps1'
$manifestScript = Join-Path $PSScriptRoot 'New-ReleaseManifest.ps1'
$parserFuzzReceiptGeneratorScript = Join-Path $PSScriptRoot 'New-ParserFuzzReceipt.ps1'
$documentationScript = Join-Path $PSScriptRoot 'Test-V1BetaDocumentation.ps1'
$bundleScript = Join-Path $PSScriptRoot 'New-ReleaseBundle.ps1'
$localGateTestScript = Join-Path $PSScriptRoot 'Test-V1BetaLocalGate.ps1'
$runtimeBoundarySelfTestScript = Join-Path `
    $PSScriptRoot `
    'Test-RuntimeDependencyBoundarySelfTest.ps1'
$runtimeBoundaryScript = Join-Path $PSScriptRoot 'Test-RuntimeDependencyBoundary.ps1'
$buildScriptFixtureScript = Join-Path $PSScriptRoot 'Test-BuildScriptFixtures.ps1'
$downloadedSetSelfTestScript = Join-Path `
    $PSScriptRoot `
    'Test-DownloadedReleaseSetSelfTest.ps1'
$downloadedSetVerifierScript = Join-Path $PSScriptRoot 'Test-DownloadedReleaseSet.ps1'
$releaseAssetSnapshotScript = Join-Path $PSScriptRoot 'ReleaseAssetSnapshot.ps1'
$releaseAssetSnapshotSelfTestScript = Join-Path `
    $PSScriptRoot `
    'Test-ReleaseAssetSnapshot.ps1'
$releaseArchiveContractScript = Join-Path $PSScriptRoot 'ReleaseArchiveContract.ps1'
$strictJsonSelfTestScript = Join-Path $PSScriptRoot 'Test-StrictJson.ps1'
$parserFuzzBoundaryScript = Join-Path $PSScriptRoot 'Test-ParserFuzzBoundary.ps1'
$parserFuzzBoundarySelfTestScript = Join-Path `
    $PSScriptRoot `
    'Test-ParserFuzzBoundarySelfTest.ps1'
$parserFuzzReceiptSelfTestScript = Join-Path `
    $PSScriptRoot `
    'Test-ParserFuzzReceiptSelfTest.ps1'
$sshPreauthEvidenceSelfTestScript = Join-Path `
    $PSScriptRoot `
    'Test-SshPreAuthServerEvidenceSelfTest.ps1'
$externalEvidenceScript = Join-Path `
    $PSScriptRoot `
    'Test-ExternalAcceptanceEvidence.ps1'
$externalEvidencePlanScript = Join-Path `
    $PSScriptRoot `
    'Get-ExternalAcceptanceDownloadPlan.ps1'
$externalEvidenceSelfTestScript = Join-Path `
    $PSScriptRoot `
    'Test-ExternalAcceptanceEvidenceSelfTest.ps1'
$externalTransferRuntimeReceiptContractSelfTestScript = Join-Path `
    $PSScriptRoot `
    'Test-ExternalTransferRuntimeReceiptContract.ps1'
$cleanInstallHarnessScript = Join-Path `
    $PSScriptRoot `
    'Invoke-CleanInstallSmokeHarness.ps1'
$cleanInstallHarnessSelfTestScript = Join-Path `
    $PSScriptRoot `
    'Test-CleanInstallSmokeHarness.ps1'
$boundedHttpsScript = Join-Path $PSScriptRoot 'Save-BoundedHttpsFile.ps1'
$assetContractScript = Join-Path $PSScriptRoot 'ReleaseAssetContract.ps1'
$glibcBaselineSelfTestScript = Join-Path `
    $PSScriptRoot `
    'Test-LinuxGlibcBaselineSelfTest.ps1'
$upgradeRollbackHarnessTestScript = Join-Path `
    $PSScriptRoot `
    'Test-WholeBundleUpgradeRollbackHarness.ps1'
$upgradeRollbackHarnessScript = Join-Path `
    $PSScriptRoot `
    'Invoke-WholeBundleUpgradeRollbackHarness.ps1'
$windowsMultiAccountAclScript = Join-Path `
    $PSScriptRoot `
    'Test-WindowsMultiAccountAcl.ps1'
$windowsAclReceiptContractSelfTestScript = Join-Path `
    $PSScriptRoot `
    'Test-WindowsMultiAccountAclReceiptContract.ps1'
$releaseLogSelfTestScript = Join-Path `
    $PSScriptRoot `
    'Test-ReleaseLogSanitization.ps1'
$workflowPath = Join-Path $repositoryRoot '.github/workflows/release-v1-beta.yml'
$ciWorkflowPath = Join-Path $repositoryRoot '.github/workflows/ci.yml'
$denyPath = Join-Path $repositoryRoot 'deny.toml'
$nativeHelperSourcePath = Join-Path `
    $repositoryRoot `
    'crates/serctl_xfer/src/main.rs'

foreach ($script in Get-ChildItem -LiteralPath $PSScriptRoot -Filter '*.ps1' -File) {
    $nonAscii = @([System.IO.File]::ReadAllBytes($script.FullName) | Where-Object { $_ -gt 127 })
    Assert-TestCondition ($nonAscii.Count -eq 0) (
        "PowerShell governance script '$($script.Name)' is not ASCII-safe for Windows PowerShell 5.1"
    )
}

$manifest = Get-Content -LiteralPath (Join-Path $repositoryRoot 'Cargo.toml') -Raw -Encoding utf8
$versionMatch = [regex]::Match(
    $manifest,
    '(?ms)^\[workspace\.package\]\s*.*?^version\s*=\s*"(?<version>[^"]+)"\s*$',
    [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
)
Assert-TestCondition $versionMatch.Success 'cannot read current workspace version'
$currentVersion = $versionMatch.Groups['version'].Value

# The same governance suite runs in two legitimate source states: the current
# development tree may have a newer leading Unreleased entry, while the exact
# release tag must start with its dated release entry. Require strict
# consistency whenever it already holds; use the explicit development-only
# allowance only when strict verification rejects the leading Unreleased entry.
$strictCurrentVersion = $true
try {
    & $verifyScript -Tag "v$currentVersion" *> $null
}
catch {
    $strictCurrentVersion = $false
}
if (-not $strictCurrentVersion) {
    & $verifyScript `
        -Tag "v$currentVersion" `
        -AllowLeadingUnreleased `
        -ExpectedUnreleasedTag 'v1.0.0-beta'
}
Invoke-ExpectedScriptFailure `
    -Description 'development-only CHANGELOG allowance combined with Git-tag verification' `
    -Action {
        & $verifyScript `
            -Tag "v$currentVersion" `
            -AllowLeadingUnreleased `
            -RequireGitTag
    }
$verifySource = Get-Content -LiteralPath $verifyScript -Raw -Encoding utf8
foreach ($requiredChangelogGuard in @(
    'AllowLeadingUnreleased is a development-tree check and cannot verify a Git tag',
    'AllowLeadingUnreleased requires ExpectedUnreleasedTag as one canonical prerelease tag',
    'leading Unreleased entry does not equal expected candidate $ExpectedUnreleasedTag',
    'CHANGELOG.md must start with the dated release entry unless AllowLeadingUnreleased is explicit',
    'the current release v$releaseVersion is still marked Unreleased',
    'only the first CHANGELOG.md release entry may be Unreleased',
    'the first published CHANGELOG.md release entry is not dated v$releaseVersion'
)) {
    Assert-TestCondition ($verifySource.Contains($requiredChangelogGuard)) (
        "release consistency verifier lacks CHANGELOG state guard '$requiredChangelogGuard'"
    )
}
Assert-TestCondition (
    Test-Path -LiteralPath $releaseConsistencySelfTestScript -PathType Leaf
) 'release consistency synthetic Git self-test is missing'
& $releaseConsistencySelfTestScript
Assert-TestCondition (
    Test-Path -LiteralPath $releaseVersionSwitchSelfTestScript -PathType Leaf
) 'controlled v1 release version switch self-test is missing'
$checkedChildProbe = Join-Path $repositoryRoot (
    'target/release-governance-child-exit-' + [Guid]::NewGuid().ToString('N') + '.ps1'
)
try {
    [System.IO.File]::WriteAllText(
        $checkedChildProbe,
        "`$global:LASTEXITCODE = 37`n",
        [System.Text.UTF8Encoding]::new($false)
    )
    Invoke-ExpectedScriptFailure `
        -Description 'checked governance child with a nonzero native exit code' `
        -Action {
            Invoke-CheckedChildScript `
                -Path $checkedChildProbe `
                -Description 'intentional nonzero child probe'
        }
}
finally {
    if (Test-Path -LiteralPath $checkedChildProbe -PathType Leaf) {
        [System.IO.File]::Delete($checkedChildProbe)
    }
}
Invoke-CheckedChildScript `
    -Path $releaseVersionSwitchSelfTestScript `
    -Description 'controlled v1 release version switch self-test'
Assert-TestCondition (
    Test-Path -LiteralPath $isolatedCandidateScript -PathType Leaf
) 'isolated candidate builder is missing'
Assert-TestCondition (
    Test-Path -LiteralPath $isolatedCandidateSelfTestScript -PathType Leaf
) 'isolated candidate builder self-test is missing'
& $isolatedCandidateSelfTestScript
Assert-TestCondition (
    Test-Path -LiteralPath $externalRuntimeSupervisorScript -PathType Leaf
) 'external runtime process supervisor is missing'
Assert-TestCondition (
    Test-Path -LiteralPath $externalRuntimeSupervisorSelfTestScript -PathType Leaf
) 'external runtime process supervisor self-test is missing'
$externalRuntimeSupervisorSource = Get-Content `
    -LiteralPath $externalRuntimeSupervisorScript `
    -Raw `
    -Encoding utf8
$externalRuntimeSupervisorSelfTestSource = Get-Content `
    -LiteralPath $externalRuntimeSupervisorSelfTestScript `
    -Raw `
    -Encoding utf8
foreach ($supervisorBoundary in @(
    'CREATE_SUSPENDED',
    'JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE',
    'AssignProcessToJobObject',
    'TerminateJobObject',
    'EXTENDED_STARTUPINFO_PRESENT',
    'PROC_THREAD_ATTRIBUTE_HANDLE_LIST',
    'UpdateProcThreadAttribute',
    'posix_spawn',
    'POSIX_SPAWN_SETPGROUP',
    'posix_spawn_file_actions_addclosefrom_np',
    '"/proc/self/fd/3"',
    'posix_spawn_file_actions_adddup2(actions, stdinPipe[0], 0)',
    'PumpInputAsync',
    'Invoke-ExternalRuntimeProcessCaptureInternal',
    'INTERNAL-ONLY ADAPTER API',
    'standardInputOwned.Length -gt 1048576',
    '[Array]::Clear($standardInputOwned, 0, $standardInputOwned.Length)',
    '[Array]::Clear($capture.stdout, 0, $capture.stdout.Length)',
    '[Array]::Clear($capture.stderr, 0, $capture.stderr.Length)',
    'SIGTERM',
    'SIGKILL',
    'ReadAsync',
    'Stopwatch',
    'ForbiddenCanary',
    '[System.IO.FileShare]::Read',
    'process_tree_exited = $true',
    'external runtime process tree termination could not be proven'
)) {
    Assert-TestCondition ($externalRuntimeSupervisorSource.Contains($supervisorBoundary)) (
        "external runtime supervisor lacks boundary '$supervisorBoundary'"
    )
}
foreach ($forbiddenSupervisorBoundary in @(
    'BeginOutputReadLine',
    'BeginErrorReadLine',
    'UseShellExecute = true',
    'Process.Start(psi)',
    'setpgid(',
    'Invoke-Expression'
)) {
    Assert-TestCondition (-not $externalRuntimeSupervisorSource.Contains($forbiddenSupervisorBoundary)) (
        "external runtime supervisor contains forbidden boundary '$forbiddenSupervisorBoundary'"
    )
}
foreach ($supervisorNegative in @(
    'hung process was not classified as deadline',
    'stdout flood did not terminate at its hard limit',
    'stderr flood did not terminate at its hard limit',
    'descendant survived process-tree termination proof',
    'deadline race produced a noncanonical category',
    'relative application path was accepted',
    'wildcard application path was accepted',
    'script application was accepted',
    'secret or path canary was accepted in argv',
    'renamed shell/shadow leaf was accepted',
    'executable replacement was not blocked while its identity was pinned',
    'receipt leaked argv, path, output, or another unapproved field',
    'parent environment canary leaked into the child',
    'caller-created environment variable name was accepted',
    'extra inheritable handle leaked outside the exact handle list',
    'process-like wait handle was accepted for inheritance',
    'directory handle was accepted for inheritance',
    'child standard input was not an explicit EOF stream',
    'internal capture did not accept bounded JSONL stdin',
    'internal capture function was exported through the formal receipt contract',
    'standard input beyond its strict bound was accepted',
    'child that ignored stdin blocked the supervisor',
    'purpose-bound handle mapping conflicted with or retained stdin bytes',
    'stdout flood did not zeroize stdin bytes',
    'deadline did not zeroize pending stdin bytes',
    'stdin secret canary leaked into the public receipt'
)) {
    Assert-TestCondition ($externalRuntimeSupervisorSelfTestSource.Contains($supervisorNegative)) (
        "external runtime supervisor self-test lacks '$supervisorNegative'"
    )
}
Assert-TestCondition (
    Test-Path -LiteralPath $externalTransferRuntimeAdapterScript -PathType Leaf
) 'external transfer runtime adapter is missing'
Assert-TestCondition (
    Test-Path -LiteralPath $externalTransferRuntimeAdapterSelfTestScript -PathType Leaf
) 'external transfer runtime adapter self-test is missing'
foreach ($isolatedOwnerPath in @(
    $isolatedExternalTransferOwnerLauncherScript,
    $isolatedExternalTransferOwnerScript,
    $isolatedExternalTransferOwnerSelfTestScript,
    $externalTransferOfficialComponentAnchorScript,
    $externalTransferOfficialComponentAnchorSelfTestScript,
    $nativeFaultRegistryPerformanceFixtureScript,
    $nativeFaultRegistryPerformanceLauncherScript,
    $nativeFaultRegistryPerformanceOwnerScript,
    $nativeFaultRegistryPerformanceOwnerSelfTestScript
)) {
    Assert-TestCondition (Test-Path -LiteralPath $isolatedOwnerPath -PathType Leaf) (
        "isolated external transfer formal owner component is missing: $isolatedOwnerPath"
    )
}
$externalTransferRuntimeAdapterSource = Get-Content `
    -LiteralPath $externalTransferRuntimeAdapterScript `
    -Raw `
    -Encoding utf8
$externalTransferRuntimeAdapterSelfTestSource = Get-Content `
    -LiteralPath $externalTransferRuntimeAdapterSelfTestScript `
    -Raw `
    -Encoding utf8
foreach ($adapterBoundary in @(
    '$script:SerctlRuntimeAdapterRecipes',
    "'ssh-connection-identity'",
    "'forward-local-open'",
    "'forward-remote-open'",
    "'forward-dynamic-open'",
    "'transfer-push'",
    "'transfer-pull'",
    "'transfer-status'",
    "'exec'",
    "'list-dir'",
    'adapter runtime path is wired to the controlled supervisor and trusted owner',
    'predeclared id',
    'Linux supervisor and Agent runtime behavior',
    'macOS runtime remains unsupported and fail-closed',
    'all formal operation contexts have deterministic local parser coverage',
    'verified Linux provenance binds native helper identity into the local formal root intent',
    'operation_context_id',
    'revision',
    'PowerShell module-private functions and state are not a trust boundary',
    'Invoke-ExternalRuntimeProcess',
    'ConvertFrom-StrictJson',
    'parser_outcome',
    'synthetic_only',
    'sealable = $false'
)) {
    Assert-TestCondition ($externalTransferRuntimeAdapterSource.Contains($adapterBoundary)) (
        "external transfer runtime adapter lacks boundary '$adapterBoundary'"
    )
}
foreach ($adapterNegative in @(
    'synthetic parser summary as formal observation',
    'controlled transcript hash mismatch',
    'controlled process deadline',
    'controlled stdout flood',
    'duplicate request id',
    'out-of-order terminal',
    'multiple terminal for one request',
    'unknown terminal field',
    'tunnel id mismatch',
    'nonmonotonic transfer confirmation',
    'transfer stage regression',
    'transfer transcript without terminal status',
    'terminal transfer replay',
    'transfer operation context substitution',
    'transfer revision rollback',
    'nonpositive transfer terminal revision',
    'path canary',
    'credential canary in Base64 output',
    'transfer-pull direction substitution',
    'formal real-host case while supervisor prerequisites are open'
)) {
    Assert-TestCondition ($externalTransferRuntimeAdapterSelfTestSource.Contains($adapterNegative)) (
        "external transfer runtime adapter self-test lacks '$adapterNegative'"
    )
}
$isolatedCandidateSource = Get-Content `
    -LiteralPath $isolatedCandidateScript `
    -Raw `
    -Encoding utf8
$isolatedCandidateSelfTestSource = Get-Content `
    -LiteralPath $isolatedCandidateSelfTestScript `
    -Raw `
    -Encoding utf8
foreach ($candidateBoundary in @(
    'source checkout is not clean; refusing to build an unbound candidate',
    "Join-Path `$targetRoot 'candidates'",
    'candidate-builds',
    'candidate-staging',
    '[System.IO.FileMode]::CreateNew',
    '[System.IO.Directory]::Move($stageRoot, $candidatePath)',
    'refusing to overwrite existing candidate set',
    'cargo_target_separate_from_candidate_set = $true',
    'repository_absolute_path = $repository',
    'repository_relative_path = $relative',
    'file_identity = $evidence.Identity',
    'size_bytes = [long]$evidence.Size',
    'runtime_mode = $evidence.RuntimeMode',
    'Remove-Item -LiteralPath "Env:$Name" -ErrorAction SilentlyContinue',
    'Get-PinnedFileEvidence',
    'Assert-ArtifactEvidenceUnchanged',
    'New-PinnedDirectoryState',
    'Assert-OwnedDirectoryState',
    'Assert-TreeContainsNoReparsePoints',
    'Remove-OwnedPrivateDirectory',
    'Get-CleanGitSnapshot',
    "@('rev-parse', 'HEAD^{tree}')",
    'SerctlCandidateChangeMonitor',
    'New-TrackedSourceMonitors',
    'watcher.IncludeSubdirectories = includeSubdirectories',
    'Stop-CandidateChangeMonitors',
    'tracked source changed ',
    'even if its bytes were later restored',
    "@('worktree', 'add', '--detach', `$sourceRoot, `$initialHead)",
    'Remove-OwnedDetachedWorktree',
    "'--manifest-path', (Join-Path `$sourceRoot 'Cargo.toml')",
    '-WorkingDirectory $repository',
    'Resolve-StrictApplication',
    'command contains wildcard characters',
    'command is shadowed from inside the source repository',
    'cargo_executable_sha256 = $cargoTool.Sha256',
    "compiler override '`$name' must be unset",
    "[System.Environment]::SetEnvironmentVariable('RUSTC', `$rustcPath, 'Process')",
    'rustc_executable_sha256 = $rustcTool.Sha256',
    "-Label 'rustc Application'",
    'working_directory_absolute_path = $repository',
    'this PowerShell runtime cannot read Unix file mode; refusing to claim 0755',
    '($mode -band 4095) -eq 493',
    '.serctl-candidate-owner',
    'root_identity = $stageState.Identity',
    'owner_token = $stageOwnerToken',
    '$buildCleaned = $true',
    'head = $initialHead',
    'version_line = $evidence.VersionLine',
    'IPC v9..=v9',
    'transfer protocol v1',
    'vault-storage read=v4..=v5 write=v5'
)) {
    Assert-TestCondition ($isolatedCandidateSource.Contains($candidateBoundary)) (
        "isolated candidate builder lacks boundary '$candidateBoundary'"
    )
}
foreach ($forbiddenCandidateCapability in @(
    '--profile',
    '--global-instance',
    'grant-issue',
    'ssh.exec'
)) {
    Assert-TestCondition (
        -not $isolatedCandidateSource.Contains($forbiddenCandidateCapability)
    ) (
        "isolated candidate builder unexpectedly references runtime capability " +
        "'$forbiddenCandidateCapability'"
    )
}
foreach ($candidateCounterexample in @(
    'duplicate candidate identity',
    'Git repository redirection',
    'dirty source checkout',
    'wrong daemon protocol identity',
    'target/release/sentinel.txt',
    'target/staging-v0.3/sentinel.txt',
    'wrong-identity fixture published a candidate set',
    'candidate manifest is empty or has a UTF-8 BOM',
    'builder left an empty CARGO_TARGET_DIR after a null original value',
    'failed builder did not restore the exact nonempty CARGO_TARGET_DIR',
    'builder did not remove an originally empty CARGO_TARGET_DIR',
    'empty CARGO_TARGET_DIR normalization',
    'staged artifact replacement',
    'candidate staging parent junction',
    'private build cleanup ownership mismatch',
    'ownership mismatch did not preserve exactly one untrusted build root',
    'Cargo wildcard command resolution',
    'Cargo command shadow',
    'tracked source changed and restored during build',
    'source-mutation detached worktree parent',
    'manifest does not bind Cargo cwd and detached manifest path',
    'manifest does not bind the exact rustc toolchain executable',
    'manifest tool identity mismatch',
    'SERCTL_FIXTURE_IGNORED_EVENT_STORM',
    'ignored target event storm leaked its private build root'
)) {
    Assert-TestCondition (
        $isolatedCandidateSelfTestSource.Contains($candidateCounterexample)
    ) (
        "isolated candidate self-test lacks counterexample '$candidateCounterexample'"
    )
}
Invoke-ExpectedFailure 'v1.0.0-beta;Write-Host-injected'
Invoke-ExpectedFailure 'v01.0.0-beta'
Invoke-ExpectedFailure 'v1.0.0'
Invoke-ExpectedFailure 'v1.0.0-beta.0'
Invoke-ExpectedFailure 'v1.0.0-beta.01'
Invoke-ExpectedFailure 'v9.9.9-beta'

$workflow = Get-Content -LiteralPath $workflowPath -Raw -Encoding utf8
$nativeHelperSource = Get-Content `
    -LiteralPath $nativeHelperSourcePath `
    -Raw `
    -Encoding utf8
foreach ($testName in @(
    'linux_lock_rejects_unsafe_existing_entry_types_and_metadata',
    'linux_pinned_parent_survives_path_rebind_but_terminal_binding_fails',
    'linux_recreated_lock_invalidates_the_old_holder_and_drop_releases_flock'
)) {
    $definition = (
        '(?ms)#\[cfg\(target_os\s*=\s*"linux"\)\]\s*' +
        '#\[test\]\s*fn\s+' +
        [regex]::Escape($testName) +
        '\s*\('
    )
    Assert-TestCondition (
        ([regex]::Matches($nativeHelperSource, $definition)).Count -eq 1
    ) (
        "serctl-xfer must retain exactly one non-ignored Linux-only native " +
        "lock/parent regression '$testName'"
    )
}
foreach ($required in @(
    'tags:',
    '- "v1.0.0-beta*"',
    'Verify-ReleaseConsistency.ps1',
    'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1',
    'actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a',
    'actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c',
    'actions/attest-build-provenance@e8998f949152b193b063cb0ec769d69d929409be',
    'id-token: write',
    'attestations: write',
    'attestations: read',
    'CARGO_PROFILE_RELEASE_DEBUG: line-tables-only',
    'CARGO_TARGET_DIR: target/v1-beta-release',
    'dedicated release target already exists',
    'RELEASE_TAG_OBJECT:',
    '-TagObject $env:RELEASE_TAG_OBJECT',
    'exact tag commit does not equal the current remote main SHA',
    'remote main no longer equals the exact release commit',
    'remote tag changed after preflight',
    'Test-BuildScriptFixtures.ps1',
    'Exact-tag bounded parser fuzzing',
    'uses: ./.github/workflows/parser-fuzz.yml',
    'tag: ${{ needs.preflight.outputs.tag }}',
    'tag_object: ${{ needs.preflight.outputs.tag_object }}',
    'commit: ${{ needs.preflight.outputs.commit }}',
    'Download exact-tag parser fuzz success receipt',
    'Independently verify retained parser fuzz success receipt',
    'ParserFuzzReceiptPath',
    'ParserFuzzArtifactId',
    'ParserFuzzArtifactDigest',
    'needs: [preflight, quality, parser-fuzz, test, rustsec]',
    'Verify portable release archives and the isolated fuzz lock',
    'cargo metadata --manifest-path fuzz/Cargo.toml --locked --format-version 1',
    'Test-ParserFuzzBoundary.ps1 -RepositoryRoot .',
    'Test-DownloadedReleaseSetSelfTest.ps1',
    'Test-ReleaseAssetSnapshot.ps1',
    'Windows PowerShell 5.1 governance smoke',
    'shell: powershell',
    'runner: macos-15',
    'runner: macos-15-intel',
    'expected_arch: ARM64',
    'expected_rust_host: aarch64-apple-darwin',
    'expected_rust_host: x86_64-apple-darwin',
    'Require the declared native runner architecture',
    'Require Windows multi-account DACL and owner isolation',
    'Test-WindowsMultiAccountAcl.ps1',
    'cargo deny --locked check bans licenses sources',
    'Test-RuntimeDependencyBoundary.ps1',
    'Test-DownloadedReleaseSet.ps1',
    'Reverify the downloaded release set before publication',
    'Verify OIDC provenance for every downloaded release file',
    'GH_TOKEN: ${{ github.token }}',
    'Get-V1BetaFinalReleaseNames -Version $env:RELEASE_VERSION',
    '$expectedSubjects.Count -ne 14',
    'foreach ($subject in $expectedSubjects)',
    'Join-Path release-dist $subject',
    'gh attestation verify $subjectPath',
    '--repo $env:RELEASE_REPOSITORY',
    '--signer-repo $env:RELEASE_REPOSITORY',
    '--signer-workflow "$env:RELEASE_REPOSITORY/.github/workflows/release-v1-beta.yml"',
    '--source-digest $env:RELEASE_COMMIT',
    '--source-ref "refs/tags/$env:RELEASE_TAG"',
    '$LASTEXITCODE -ne 0',
    '-Directory release-dist',
    '-Repository $env:RELEASE_REPOSITORY',
    'git diff --check HEAD^',
    'SERCTL_REQUIRE_WINDOWS_REPARSE_TEST=1',
    'environment: v1-beta-external-acceptance',
    'V1_BETA_ACCEPTANCE_RECORD_URL',
    'V1_BETA_ACCEPTANCE_RECORD_SHA256',
    'Require empty release assembly staging',
    'Require empty publish download staging',
    'Require exact upstream artifact identities',
    'Require exact attested artifact identity',
    'artifact_id: ${{ steps.upload.outputs.artifact-id }}',
    'artifact_digest: ${{ steps.upload.outputs.artifact-digest }}',
    'artifact-ids: ${{ needs.windows-bundle.outputs.artifact_id }}',
    'artifact-ids: ${{ needs.linux-helper-bundle.outputs.artifact_id }}',
    'artifact-ids: ${{ needs.attest.outputs.artifact_id }}',
    'digest-mismatch: error',
    'release-input artifact ID is missing or noncanonical',
    'release-input artifact digest is missing or noncanonical',
    'attested release artifact ID is missing or noncanonical',
    'attested release artifact digest is missing or noncanonical',
    'Test-ExternalAcceptanceEvidence.ps1',
    'Get-ExternalAcceptanceDownloadPlan.ps1',
    'Save-BoundedHttpsFile.ps1',
    'Verify non-release external receipts against release component bytes',
    'rehashes the complete downloaded release set',
    'manifest_url',
    '-MaxBytes 65536',
    '-MaxBytes 262144',
    '-MaxBytes 8388608',
    'external evidence artifact SHA-256 mismatch',
    'remote annotated tag object no longer peels to the preflight commit',
    'cannot prove release absence',
    'publish allowlist contains $($expectedSubjects.Count) files, expected 14',
    '-p serctl-xfer --bin serctl-xfer',
    'runs-on: ubuntu-22.04',
    'test ! -e ./serctl-remote',
    '--manifest-path crates/serctl_cli/Cargo.toml',
    '--manifest-path crates/serctl_daemon/Cargo.toml',
    '--manifest-path crates/serctl_xfer/Cargo.toml',
    '--target x86_64-pc-windows-msvc',
    '--target x86_64-unknown-linux-gnu',
    'cargo metadata --locked --all-features --format-version 1',
    'Test-RuntimeDependencyBoundary.ps1',
    'set -euo pipefail',
    'sbom_lock_sha=',
    'expected_status=',
    'actual_status=',
    '$inputs.Count -ne 6',
    'target/v1-beta-release-input/windows',
    'target/v1-beta-release-input/linux',
    'gh release create',
    'refusing to mutate immutable assets'
)) {
    Assert-TestCondition ($workflow.Contains($required)) "release workflow is missing '$required'"
}
Assert-TestCondition (-not $workflow.Contains('refs/heads/main')) (
    'formal release workflow must not be a main-branch release job'
)
Assert-TestCondition (-not $workflow.Contains('workflow_dispatch:')) (
    'formal release workflow must not permit an unbound manual dispatch'
)
Assert-TestCondition (
    ([regex]::Matches(
        $workflow,
        [regex]::Escape('uses: ./.github/workflows/parser-fuzz.yml')
    )).Count -eq 1
) 'formal release workflow must call the exact-tag parser-fuzz workflow exactly once'
$exactTagFuzzJob = [regex]::Match(
    $workflow,
    '(?ms)^  parser-fuzz:\r?\n' +
    '    name: Exact-tag bounded parser fuzzing\r?\n' +
    '    needs: preflight\r?\n' +
    '    permissions:\r?\n' +
    '      contents: read\r?\n' +
    '    uses: \./\.github/workflows/parser-fuzz\.yml\r?\n' +
    '    with:\r?\n' +
    '      tag: \$\{\{ needs\.preflight\.outputs\.tag \}\}\r?\n' +
    '      tag_object: \$\{\{ needs\.preflight\.outputs\.tag_object \}\}\r?\n' +
    '      commit: \$\{\{ needs\.preflight\.outputs\.commit \}\}\s*' +
    '(?=^  test:\r?\n)'
)
Assert-TestCondition $exactTagFuzzJob.Success (
    'formal release parser-fuzz call is not one read-only job gated by preflight'
)
Assert-TestCondition (
    ([regex]::Matches(
        $workflow,
        [regex]::Escape('needs: [preflight, quality, parser-fuzz, test, rustsec]')
    )).Count -eq 2
) 'both platform bundle jobs must depend on exact-tag parser fuzzing'
Assert-TestCondition (-not $workflow.Contains('runner: macos-latest')) (
    'formal release workflow uses a moving macOS label instead of explicit native architectures'
)
foreach ($macRunner in @('macos-15', 'macos-15-intel')) {
    Assert-TestCondition (
        ([regex]::Matches(
            $workflow,
            "(?m)^\s*runner:\s*$([regex]::Escape($macRunner))\s*$"
        )).Count -eq 1
    ) "formal release workflow must contain exactly one native $macRunner matrix row"
}
Assert-TestCondition (
    ([regex]::Matches(
        $workflow,
        [regex]::Escape('cargo clippy --locked --workspace --all-targets --all-features -- -D warnings')
    )).Count -eq 1
) 'tagged quality must run exactly one separate strict Clippy command'
Assert-NativeMatrixJob `
    -Source $workflow `
    -Description 'formal release workflow'
Assert-TestCondition (-not $workflow.Contains('path: release-input/')) (
    'formal release workflow downloads inputs into an unignored path before its clean-tree SBOM gate'
)
foreach ($forbiddenRemotePackaging in @(
    '-p serctl-remote --bin serctl-remote',
    'objcopy --only-keep-debug ./serctl-remote',
    'strip --strip-debug --strip-unneeded ./serctl-remote',
    'for helper in serctl-xfer serctl-remote'
)) {
    Assert-TestCondition (-not $workflow.Contains($forbiddenRemotePackaging)) (
        "release workflow packages source-only component '$forbiddenRemotePackaging'"
    )
}
foreach ($forbiddenSbomCollection in @(
    '--describe all-cargo-targets',
    '--describe crate',
    'cargo cyclonedx --locked',
    'Copy-Item -LiteralPath bom.xml',
    'Copy-Item -LiteralPath bom.json'
)) {
    Assert-TestCondition (-not $workflow.Contains($forbiddenSbomCollection)) (
        "release workflow uses ambiguous workspace SBOM collection '$forbiddenSbomCollection'"
    )
}
$actionUses = [regex]::Matches($workflow, '(?m)^\s*uses:\s*(?<value>[^#\r\n]+)')
Assert-TestCondition ($actionUses.Count -gt 0) 'release workflow contains no actions'
$expectedReleaseActions = [ordered]@{
    'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1' = 8
    'actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a' = 3
    'actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c' = 5
    'actions/attest-build-provenance@e8998f949152b193b063cb0ec769d69d929409be' = 14
}
$actualReleaseActions = @{}
foreach ($actionUse in $actionUses) {
    $value = $actionUse.Groups['value'].Value.Trim()
    if ($value -ceq './.github/workflows/parser-fuzz.yml') {
        # A repository-local reusable workflow is resolved from the caller's
        # exact tagged commit. Its unique path and count are asserted above;
        # unlike marketplace actions it intentionally has no @commit suffix.
        continue
    }
    Assert-TestCondition ($value -match '^[^@\s]+@[0-9a-f]{40}$') (
        "release workflow action is not pinned to a full commit: '$value'"
    )
    Assert-TestCondition ($expectedReleaseActions.Contains($value)) (
        "release workflow uses an unapproved action identity: '$value'"
    )
    if (-not $actualReleaseActions.ContainsKey($value)) {
        $actualReleaseActions[$value] = 0
    }
    $actualReleaseActions[$value] += 1
}
foreach ($expectedAction in $expectedReleaseActions.Keys) {
    $actualCount = if ($actualReleaseActions.ContainsKey($expectedAction)) {
        [int]$actualReleaseActions[$expectedAction]
    }
    else {
        0
    }
    Assert-TestCondition (
        $actualCount -eq [int]$expectedReleaseActions[$expectedAction]
    ) (
        "release workflow action '$expectedAction' count is $actualCount; " +
        "expected $($expectedReleaseActions[$expectedAction])"
    )
}
foreach ($forbiddenReleaseCache in @(
    'actions/cache@',
    'restore-keys:',
    'save-always:'
)) {
    Assert-TestCondition (-not $workflow.Contains($forbiddenReleaseCache)) (
        "formal release workflow must not consume cross-run mutable cache input: '$forbiddenReleaseCache'"
    )
}
Assert-TestCondition (
    ([regex]::Matches(
        $workflow,
        '(?m)^\s*subject-path:\s*release-dist/[^*?\r\n]+\s*$'
    )).Count -eq 14 -and
    -not $workflow.Contains('subject-path: release-dist/*')
) 'attestation must name all 14 exact release subjects without a wildcard'
Assert-TestCondition (
    ([regex]::Matches($workflow, '(?m)^\s{12}release-dist/[^*?\r\n]+\s*$')).Count -eq 14 -and
    -not $workflow.Contains('path: release-dist/*')
) 'attested artifact upload must list the same 14 literal release paths'
Assert-TestCondition (
    ([regex]::Matches(
        $workflow,
        '(?m)^\s*artifact-ids:\s*\$\{\{\s*needs\.[a-z-]+\.outputs\.artifact_id\s*\}\}\s*$'
    )).Count -eq 5
) 'every formal-release download must bind one exact upstream artifact ID'
Assert-TestCondition (
    ([regex]::Matches(
        $workflow,
        '(?m)^\s*digest-mismatch:\s*error\s*$'
    )).Count -eq 5
) 'every formal-release download must fail on an artifact digest mismatch'
Assert-TestCondition (
    ([regex]::Matches(
        $workflow,
        '(?m)^\s*artifact_id:\s*\$\{\{\s*steps\.upload\.outputs\.artifact-id\s*\}\}\s*$'
    )).Count -eq 3 -and
    ([regex]::Matches(
        $workflow,
        '(?m)^\s*artifact_digest:\s*\$\{\{\s*steps\.upload\.outputs\.artifact-digest\s*\}\}\s*$'
    )).Count -eq 3
) 'all three release uploads must export their immutable artifact ID and digest'
Assert-TestCondition (
    ([regex]::Matches(
        $workflow,
        [regex]::Escape('-cnotmatch ''^[1-9][0-9]*$''')
    )).Count -eq 3 -and
    ([regex]::Matches(
        $workflow,
        [regex]::Escape('-cnotmatch ''^[0-9a-f]{64}$''')
    )).Count -eq 4 -and
    $workflow.Contains('$env:WINDOWS_ARTIFACT_ID -ceq $env:LINUX_ARTIFACT_ID') -and
    $workflow.Contains('$env:FUZZ_ARTIFACT_ID -ceq $env:WINDOWS_ARTIFACT_ID')
) 'artifact identity guards must reject missing, malformed or aliased upstream outputs'
$releaseDownloadBlocks = @([regex]::Matches(
    $workflow,
    '(?ms)^\s{6}- name:\s+Download[^\r\n]*\r?\n' +
    '\s{8}uses:\s+actions/download-artifact@[0-9a-f]{40}[^\r\n]*\r?\n' +
    '\s{8}with:\s*\r?\n(?<inputs>(?:\s{10}[^\r\n]+\r?\n)+)',
    [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
))
Assert-TestCondition ($releaseDownloadBlocks.Count -eq 5) (
    "formal release must contain exactly five bounded artifact downloads; " +
    "found $($releaseDownloadBlocks.Count)"
)
foreach ($downloadBlock in $releaseDownloadBlocks) {
    $inputs = $downloadBlock.Groups['inputs'].Value
    Assert-TestCondition (
        ([regex]::Matches($inputs, '(?m)^\s{10}artifact-ids:\s+[^\r\n]+$')).Count -eq 1 -and
        ([regex]::Matches($inputs, '(?m)^\s{10}path:\s+[^\r\n]+$')).Count -eq 1 -and
        ([regex]::Matches($inputs, '(?m)^\s{10}digest-mismatch:\s+error\s*$')).Count -eq 1
    ) 'each formal-release artifact download must bind one ID, one path and digest errors'
    foreach ($forbiddenInput in @(
        'name',
        'pattern',
        'merge-multiple',
        'github-token',
        'repository',
        'run-id',
        'skip-decompress'
    )) {
        Assert-TestCondition (-not [regex]::IsMatch(
            $inputs,
            "(?m)^\s{10}$([regex]::Escape($forbiddenInput)):\s*"
        )) "formal-release artifact download uses forbidden selector '$forbiddenInput'"
    }
}
$upstreamArtifactIdentityIndex = $workflow.IndexOf(
    'Require exact upstream artifact identities',
    [StringComparison]::Ordinal
)
$windowsDownloadIndex = $workflow.IndexOf('Download Windows inputs', [StringComparison]::Ordinal)
$linuxDownloadIndex = $workflow.IndexOf(
    'Download Linux transfer-helper inputs',
    [StringComparison]::Ordinal
)
$attestedArtifactIdentityIndex = $workflow.IndexOf(
    'Require exact attested artifact identity',
    [StringComparison]::Ordinal
)
$attestedDownloadIndex = $workflow.IndexOf(
    'Download the attested release set',
    [StringComparison]::Ordinal
)
Assert-TestCondition (
    $upstreamArtifactIdentityIndex -ge 0 -and
    $windowsDownloadIndex -gt $upstreamArtifactIdentityIndex -and
    $linuxDownloadIndex -gt $upstreamArtifactIdentityIndex -and
    $attestedArtifactIdentityIndex -gt $linuxDownloadIndex -and
    $attestedDownloadIndex -gt $attestedArtifactIdentityIndex
) 'artifact identities must be validated before their exact-ID downloads'
$publishVerifierIndex = $workflow.IndexOf(
    'Reverify the downloaded release set before publication',
    [StringComparison]::Ordinal
)
$attestationVerifierIndex = $workflow.IndexOf(
    'Verify OIDC provenance for every downloaded release file',
    [StringComparison]::Ordinal
)
$externalEvidenceIndex = $workflow.IndexOf(
    'Verify non-release external receipts against release component bytes',
    [StringComparison]::Ordinal
)
$releaseCreateIndex = $workflow.IndexOf('gh release create', [StringComparison]::Ordinal)
Assert-TestCondition (
    $publishVerifierIndex -ge 0 -and
    $attestationVerifierIndex -gt $publishVerifierIndex -and
    $externalEvidenceIndex -gt $attestationVerifierIndex -and
    $releaseCreateIndex -gt $externalEvidenceIndex
) 'publication gates must reverify artifacts, attestations and external evidence before release creation'
Assert-TestCondition (
    ([regex]::Matches($workflow, '(?m)^\s*contents:\s*write\s*$')).Count -eq 1
) 'release workflow must grant contents:write only to the publish job'
Assert-TestCondition (
    ([regex]::Matches($workflow, '(?m)^\s*id-token:\s*write\s*$')).Count -eq 1
) 'release workflow must grant OIDC only to the attestation job'
Assert-TestCondition (
    ([regex]::Matches($workflow, '(?m)^\s*attestations:\s*read\s*$')).Count -eq 1
) 'release workflow must grant attestation read only to the publish job'
Assert-TestCondition (
    ([regex]::Matches(
        $workflow,
        '(?m)^\s*gh attestation verify \$subjectPath\s*`\s*$'
    )).Count -eq 2
) 'publish must verify each exact allowlisted subject before and after external evidence'
Assert-TestCondition (
    -not $workflow.Contains(
        'Attest every runtime, symbol, SBOM, and evidence file'
    ) -and
    -not $workflow.Contains(
        'GitHub OIDC provenance verification succeeds for every runtime, symbols, SBOM, checksum and evidence file'
    )
) 'release governance must not call external acceptance records OIDC evidence subjects'
$subjectFreezeIndex = $workflow.IndexOf(
    'Freeze the exact 14-file formal OIDC subject set',
    [StringComparison]::Ordinal
)
$attestActionIndex = $workflow.IndexOf(
    'actions/attest-build-provenance@',
    [StringComparison]::Ordinal
)
$attestedUploadIndex = $workflow.IndexOf(
    'Upload the attested release set',
    [StringComparison]::Ordinal
)
Assert-TestCondition (
    $subjectFreezeIndex -ge 0 -and
    $attestActionIndex -gt $subjectFreezeIndex -and
    $attestedUploadIndex -gt $attestActionIndex
) 'exact formal subject freeze must precede attestation and release-set upload'
foreach ($formalSubjectBoundary in @(
    'ReleaseAssetSnapshot.ps1',
    '-Mode Create',
    '-Mode Verify',
    '-Mode CopyCreateNew',
    'target/v1-beta-release-set.snapshot.json',
    'target/v1-beta-publish-staging',
    'subject-path: release-dist/SHA256SUMS',
    'Verify non-release external receipts against release component bytes',
    'never enter release-dist, the release upload, or the OIDC subject set'
)) {
    Assert-TestCondition ($workflow.Contains($formalSubjectBoundary)) (
        "release workflow lacks formal OIDC subject boundary '$formalSubjectBoundary'"
    )
}
Assert-TestCondition (
    ([regex]::Matches(
        $workflow,
        '(?m)^\s*uses:\s+actions/attest-build-provenance@[0-9a-f]{40}[^\r\n]*$'
    )).Count -eq 14 -and
    ([regex]::Matches(
        $workflow,
        '(?m)^\s*subject-path:\s+release-dist/[^*?\r\n]+\s*$'
    )).Count -eq 14
) 'formal release must have one pinned exact-path attestation per frozen subject'

$releaseContractSource = Get-Content `
    -LiteralPath (Join-Path $repositoryRoot 'docs/v1-beta-release-contract.md') `
    -Raw `
    -Encoding utf8
$acceptanceMatrixSource = Get-Content `
    -LiteralPath (Join-Path $repositoryRoot 'docs/v1-beta-acceptance-matrix.md') `
    -Raw `
    -Encoding utf8
foreach ($documentationBoundary in @(
    'The GitHub OIDC subject set is exactly those fourteen formal release files',
    'are not release assets and are never copied into `release-dist`',
    'does not generate or claim GitHub OIDC build-provenance attestations for those external records',
    'The OIDC subject boundary remains exact',
    'are non-release publication-gate inputs'
)) {
    Assert-TestCondition (
        $releaseContractSource.Contains($documentationBoundary) -or
        $acceptanceMatrixSource.Contains($documentationBoundary)
    ) "release documentation lacks OIDC boundary '$documentationBoundary'"
}
Assert-TestCondition (
    -not $acceptanceMatrixSource.Contains(
        'OIDC provenance verification succeeds for every runtime, symbols, SBOM, checksum and evidence file'
    )
) 'acceptance matrix still misclassifies external evidence as OIDC subjects'

$boundedHttpsSource = Get-Content -LiteralPath $boundedHttpsScript -Raw -Encoding utf8
foreach ($downloadBoundary in @(
    '$handler.AllowAutoRedirect = $false',
    '[System.Net.Http.HttpCompletionOption]::ResponseHeadersRead',
    '[System.IO.FileMode]::CreateNew',
    '$total -le $MaxBytes',
    '[int]$response.StatusCode -eq 200'
    'Format-ReleaseLogRecord'
    '[Console]::Error.WriteLine('
    '-Category https_download_completed'
)) {
    Assert-TestCondition ($boundedHttpsSource.Contains($downloadBoundary)) (
        "bounded evidence downloader lacks boundary '$downloadBoundary'"
    )
}
foreach ($forbiddenDownloadLog in @(
    "destination '`$destinationPath'",
    "destination parent '`$parent'",
    'StatusDescription',
    '$_.Exception.Message'
)) {
    Assert-TestCondition (-not $boundedHttpsSource.Contains($forbiddenDownloadLog)) (
        "bounded evidence downloader exposes forbidden log material '$forbiddenDownloadLog'"
    )
}
$planCalls = @([regex]::Matches(
    $workflow,
    [regex]::Escape('./scripts/Get-ExternalAcceptanceDownloadPlan.ps1')
))
$downloadCalls = @([regex]::Matches(
    $workflow,
    [regex]::Escape('./scripts/Save-BoundedHttpsFile.ps1')
))
Assert-TestCondition (
    $planCalls.Count -eq 2 -and $downloadCalls.Count -eq 3 -and
    $planCalls[0].Index -gt $downloadCalls[0].Index -and
    $planCalls[0].Index -lt $downloadCalls[1].Index -and
    $planCalls[1].Index -gt $downloadCalls[1].Index -and
    $planCalls[1].Index -lt $downloadCalls[2].Index
) 'strict record/manifest plans must run before every derived-URL HTTPS GET'
Assert-TestCondition (
    -not $workflow.Contains('$record = Get-Content') -and
    -not $workflow.Contains('$manifest = Get-Content')
) 'release workflow reparses untrusted acceptance JSON inline before a derived GET'
$externalEvidenceSource = Get-Content `
    -LiteralPath $externalEvidenceScript `
    -Raw `
    -Encoding utf8
foreach ($evidenceBoundary in @(
    'Get-ReleaseComponentHashes',
    'Get-V1BetaHashedReleaseNames',
    'release file ''$name'' does not match SHA256SUMS',
    'release platform provenance ''$platform'' binary_components is not an array',
    'evidence_manifest_url',
    'evidence_manifest_sha256',
    'release_manifest_sha256',
    'clean_install_smoke',
    'native_transfer_real_host',
    'openssh_dropbear_interop',
    'whole_bundle_upgrade_rollback',
    'windows_privileged_acl',
    "'binary_size', 'name', 'sha256', 'version'",
    'candidate_cli_sha256',
    '$Label is not bound to the exact release component identity',
    'does not bind the exact downloaded name/size/hash/version',
    'release archive component ''$name'' bytes do not match platform provenance',
    'whole-bundle candidate hashes are not the downloaded release components',
    'Windows ACL candidate CLI SHA-256 is not the downloaded release CLI',
    'evidence category name is not in the exact required allowlist',
    'acceptance owner and evidence owner must be independent identities',
    'windows-x86_64',
    'linux-x86_64',
    'interop implementation is duplicated',
    'native transfer fault matrix is incomplete',
    'native transfer fault case terminal classification mismatch',
    'native registry/window evidence.$field mismatch',
    'native transfer evidence counts do not bind all 20 required cases',
    'disconnect',
    'daemon_restart',
    'target_symlink_or_reparse',
    'OpenSSH_directory',
    'OpenSSH_tunnel_local',
    'OpenSSH_tunnel_remote',
    'OpenSSH_tunnel_dynamic',
    'context_sha256',
    'native transfer performance does not report the effective one-ACK window',
    'native transfer performance summary is not derived from its raw samples',
    'native transfer case.sha256 is not the fixed deterministic payload digest',
    'interop evidence does not bind each OpenSSH/Dropbear case exactly once',
    '$Label receipt SHA-256 is invalid or reused',
    '$Label receipt bytes do not match their declared SHA-256',
    'descriptor_daemon_sha256',
    'whole bundle descriptor daemon identity is not the exact candidate identity',
    'whole bundle descriptor daemon SHA-256 is not the downloaded release daemon',
    '$reportedRatio -eq $computedRatio',
    '0.3.0-beta.2',
    'evidence categories differ from the exact required set',
    'evidence manifest was completed after the acceptance record',
    'evidence artifact for',
    '8388608 bytes',
    'evidence artifact SHA-256 mismatch for',
    'duplicates another evidence URL',
    'Parse the exact byte array whose digest is checked',
    'EmitArtifactDownloadPlan',
    'matched_bundle_upgrade_verified',
    'matched_bundle_rollback_verified',
    'audit_seed_key_package_verified',
    'vault_storage_v4_to_v5_upgrade_verified',
    'beta2_destructive_writer_blocked_before_mutation',
    'candidate_storage_marker_verified',
    'storage_contract',
    'cleanup_passed',
    'v8_unknown_audit_fields_rejected_before_write',
    'unknown_security_fields_not_dropped',
    'pre_upgrade_vault_backup_restored',
    'matching_recovery_media_restored',
    'acl_owner_metadata_restored'
)) {
    Assert-TestCondition ($externalEvidenceSource.Contains($evidenceBoundary)) (
        "external acceptance verifier lacks boundary '$evidenceBoundary'"
    )
}
$cleanInstallHarnessSource = Get-Content `
    -LiteralPath $cleanInstallHarnessScript `
    -Raw `
    -Encoding utf8
foreach ($cleanInstallBoundary in @(
    "ParameterSetName = 'Runtime'",
    'Invoke-CleanInstallRuntime',
    'Write-CleanInstallAcceptanceReceipt',
    '[System.IO.FileMode]::CreateNew',
    '[System.IO.FileShare]::None',
    '[System.IO.FileOptions]::WriteThrough',
    'running daemon bytes differ from the downloaded candidate daemon',
    'isolated runtime descriptor or activation secret remained after shutdown',
    'restored predecessor did not open a fresh rollback home',
    'Remove-OwnedCleanInstallRoot',
    'cleanup_passed = $true',
    'vault-storage read=v4..=v5 write=v5'
)) {
    Assert-TestCondition ($cleanInstallHarnessSource.Contains($cleanInstallBoundary)) (
        "clean-install smoke producer lacks boundary '$cleanInstallBoundary'"
    )
}
foreach ($forbiddenCleanInstallBoundary in @(
    'RuntimeResultPath', 'AcceptanceResultPath', 'Import-Clixml', 'ssh.exec'
)) {
    Assert-TestCondition (-not $cleanInstallHarnessSource.Contains(
        $forbiddenCleanInstallBoundary
    )) "clean-install smoke producer permits '$forbiddenCleanInstallBoundary'"
}
$externalEvidenceSelfTestSource = Get-Content `
    -LiteralPath $externalEvidenceSelfTestScript `
    -Raw `
    -Encoding utf8
foreach ($selfTestBoundary in @(
    'clean-install CLI bytes not present in release provenance',
    'clean-install daemon bytes not present in release provenance',
    'clean-install storage contract mismatch',
    'clean-install cleanup gap',
    'native helper bytes not present in release provenance',
    'native CLI bytes not present in release provenance',
    'native helper size not present in release provenance',
    'native CLI size type confusion',
    'native daemon size missing',
    'native CLI size negative',
    'native helper name drift',
    'release archive component actual byte/hash drift',
    'native daemon identity protocol drift',
    'native fixed payload digest drift',
    'whole-bundle candidate $component not present in release provenance',
    'Windows ACL candidate CLI bytes not present in release provenance',
    'category path traversal before artifact lookup',
    'unsafe acceptance owner absolute path',
    'oversized acceptance owner identity',
    'unsafe evidence owner control character',
    'same acceptance and evidence owner identity',
    'native runner tuple drift',
    'fabricated native performance ratio',
    'non-integer native performance ratio',
    'overflow-shaped native performance input',
    'native raw performance summary mismatch',
    'interop runner tuple drift',
    'duplicate OpenSSH interop implementation',
    'incomplete native fault matrix',
    'native resume percentage drift',
    'lost ACK advanced confirmation',
    'unknown cleanup misclassified',
    'native registry limit drift',
    'missing exact-once interop receipt',
    'reused interop case receipt digest',
    'interop component identity drift',
    'whole-bundle runner tuple drift',
    'whole-bundle predecessor version drift',
    'whole-bundle candidate version drift',
    'whole-bundle descriptor identity drift',
    'whole-bundle descriptor daemon SHA drift',
    'ACL runner tuple drift'
)) {
    Assert-TestCondition ($externalEvidenceSelfTestSource.Contains($selfTestBoundary)) (
        "external acceptance self-test lacks byte-binding rejection '$selfTestBoundary'"
    )
}
$upgradeRollbackHarnessSource = Get-Content `
    -LiteralPath $upgradeRollbackHarnessScript `
    -Raw `
    -Encoding utf8
foreach ($storageBoundary in @(
    'Get-CleanStorageFixtureSourceCommit',
    'storage fixture source worktree is dirty',
    'Assert-CandidateMatchesStorageFixtureSource',
    'storage_fixture_source_commit_binding',
    'vault-storage read=v4..=v5 write=v5',
    'candidate_storage_marker_binding',
    'vault_storage_v4_to_v5_format_upgrade',
    'beta2_destructive_writer_outer_gate_rejection',
    "ParameterSetName = 'Runtime'",
    'Invoke-WholeBundleRuntimeGates',
    'Write-WholeBundleAcceptanceReceipt',
    'candidate CLI accepted the live predecessor daemon',
    'predecessor CLI accepted the live candidate daemon',
    'candidate accepted a predecessor runtime descriptor',
    'pre-restart OperationGrant was accepted by the new daemon instance',
    '[System.IO.FileMode]::CreateNew',
    'whole-bundle receipt post-write hash or identity check failed'
)) {
    Assert-TestCondition ($upgradeRollbackHarnessSource.Contains($storageBoundary)) (
        "upgrade/rollback harness lacks storage boundary '$storageBoundary'"
    )
}
$externalEvidencePlanSource = Get-Content `
    -LiteralPath $externalEvidencePlanScript `
    -Raw `
    -Encoding utf8
foreach ($planBoundary in @(
    'acceptance record parsed bytes do not match the approved SHA-256',
    '-EmitArtifactDownloadPlan'
)) {
    Assert-TestCondition ($externalEvidencePlanSource.Contains($planBoundary)) (
        "external acceptance download plan lacks boundary '$planBoundary'"
    )
}
Assert-TestCondition (
    -not $externalEvidencePlanSource.Contains(
        "Read-StrictUtf8Text -Path `$manifestItem.FullName"
    )
) 'artifact download plan reparses the manifest after strict verification'

$ciWorkflow = Get-Content -LiteralPath $ciWorkflowPath -Raw -Encoding utf8
foreach ($required in @(
    'Windows PowerShell 5.1 governance smoke',
    'shell: powershell',
    './scripts/Test-V1BetaDocumentation.ps1',
    './scripts/Test-V1BetaLocalGate.ps1',
    'runner: macos-15',
    'runner: macos-15-intel',
    'expected_arch: ARM64',
    'expected_rust_host: aarch64-apple-darwin',
    'expected_rust_host: x86_64-apple-darwin',
    'Require the declared native runner architecture',
    'Verify portable release archives and the isolated fuzz lock',
    'cargo metadata --manifest-path fuzz/Cargo.toml --locked --format-version 1',
    'Test-ParserFuzzBoundary.ps1 -RepositoryRoot .',
    'Test-DownloadedReleaseSetSelfTest.ps1',
    'Require Windows multi-account DACL and owner isolation',
    'Test-WindowsMultiAccountAcl.ps1',
    'cargo deny --locked check bans licenses sources',
    'SERCTL_REQUIRE_WINDOWS_REPARSE_TEST=1',
    'cargo clippy --locked --workspace --all-targets --all-features -- -D warnings',
    'target/ci-evidence/cargo-metadata.json',
    'target/ci-evidence/cargo-dependency-tree.txt',
    'cargo metadata --locked --all-features --format-version 1',
    'set -euo pipefail',
    'sbom_lock_sha=',
    'expected_status=',
    'actual_status=',
    '--manifest-path crates/serctl_cli/Cargo.toml',
    '--manifest-path crates/serctl_daemon/Cargo.toml',
    '--manifest-path crates/serctl_xfer/Cargo.toml'
)) {
    Assert-TestCondition ($ciWorkflow.Contains($required)) (
        "ordinary CI omits Windows PowerShell 5.1 smoke marker '$required'"
    )
}
foreach ($forbiddenRootEvidence in @(
    '> cargo-metadata.json',
    '> cargo-dependency-tree.txt'
)) {
    Assert-TestCondition (-not $ciWorkflow.Contains($forbiddenRootEvidence)) (
        "ordinary CI writes tracked-state evidence at repository root: '$forbiddenRootEvidence'"
    )
}
Assert-TestCondition (
    ([regex]::Matches(
        $ciWorkflow,
        [regex]::Escape('cargo clippy --locked --workspace --all-targets --all-features -- -D warnings')
    )).Count -eq 1
) 'ordinary quality must run exactly one separate strict Clippy command'
Assert-NativeMatrixJob `
    -Source $ciWorkflow `
    -Description 'ordinary CI workflow'
Assert-TestCondition (-not $ciWorkflow.Contains('runner: macos-latest')) (
    'ordinary CI uses a moving macOS label instead of explicit native architectures'
)
foreach ($macRunner in @('macos-15', 'macos-15-intel')) {
    Assert-TestCondition (
        ([regex]::Matches(
            $ciWorkflow,
            "(?m)^\s*runner:\s*$([regex]::Escape($macRunner))\s*$"
        )).Count -eq 1
    ) "ordinary CI must contain exactly one native $macRunner matrix row"
}
foreach ($forbiddenCiSbomCollection in @(
    '--describe all-cargo-targets',
    '--describe crate',
    'cargo cyclonedx --locked'
)) {
    Assert-TestCondition (-not $ciWorkflow.Contains($forbiddenCiSbomCollection)) (
        "ordinary CI uses unsupported or ambiguous SBOM option '$forbiddenCiSbomCollection'"
    )
}

Assert-TestCondition (
    Test-Path -LiteralPath $windowsMultiAccountAclScript -PathType Leaf
) 'Windows multi-account ACL harness is missing'
$windowsAclSource = Get-Content `
    -LiteralPath $windowsMultiAccountAclScript `
    -Raw `
    -Encoding utf8
foreach ($aclLogBoundary in @(
    'Format-ReleaseLogRecord',
    '-Category windows_acl_gate_failed',
    '[Console]::Error.WriteLine(',
    'captured output withheld',
    'stdout_bytes=',
    'stderr_bytes='
)) {
    Assert-TestCondition ($windowsAclSource.Contains($aclLogBoundary)) (
        "Windows ACL harness lacks sanitized log boundary '$aclLogBoundary'"
    )
}
Assert-TestCondition (-not $windowsAclSource.Contains('$_.Exception.Message')) (
    'Windows ACL harness exposes a cleanup exception message'
)
foreach ($requiredAclBoundary in @(
    'the runner is not elevated; this gate may not skip account creation',
    'probe root already exists; refusing to reuse it',
    'New-LocalUser',
    'Get-LocalGroupMember',
    'Remove-LocalUser',
    'Assert-SerctlProtectedAcl',
    '$Label is a reparse point',
    'Test-IsAccessDeniedError',
    'observer protected vault lock read failed with a non-access-denied error',
    'observer protected vault write failed with a non-access-denied error',
    'refusing recursive cleanup of reparse-point probe root',
    'observer-parent-control',
    'observer CLI unexpectedly opened owner vault',
    'observer unexpectedly read protected vault lock',
    'observer unexpectedly wrote protected vault directory',
    'owner_reopen_passed',
    'owner and observer SIDs are not distinct',
    'owner probe account is an administrator',
    'observer probe account is an administrator',
    'probe account has an administrator token',
    'probe root still exists after removal',
    'observer account still exists after removal',
    'owner account still exists after removal',
    'Windows multi-account ACL gate cleanup failed closed'
)) {
    Assert-TestCondition ($windowsAclSource.Contains($requiredAclBoundary)) (
        "Windows multi-account ACL harness lacks boundary '$requiredAclBoundary'"
    )
}
foreach ($forbiddenAclFalsePositive in @(
    'catch [System.IO.IOException] { $readDenied = $true }',
    'catch [System.IO.IOException] { $createDenied = $true }',
    'Add-LocalGroupMember'
)) {
    Assert-TestCondition (-not $windowsAclSource.Contains($forbiddenAclFalsePositive)) (
        "Windows multi-account ACL harness accepts a broad I/O error as denial: " +
        "'$forbiddenAclFalsePositive'"
    )
}
$administratorMembershipCheck = $windowsAclSource.IndexOf(
    'Get-LocalGroupMember -SID $administratorsSid -ErrorAction Stop',
    [System.StringComparison]::Ordinal
)
$probeRootCreation = $windowsAclSource.IndexOf(
    '[System.IO.Directory]::CreateDirectory($probeRoot)',
    [System.StringComparison]::Ordinal
)
Assert-TestCondition (
    $administratorMembershipCheck -ge 0 -and
    $administratorMembershipCheck -lt $probeRootCreation
) 'Windows multi-account ACL harness does not reject administrator accounts before probing'
foreach ($cleanupPostcondition in @(
    @(
        'Remove-Item -LiteralPath $probeRoot -Recurse -Force -ErrorAction Stop',
        'probe root still exists after removal'
    ),
    @(
        'Remove-LocalUser -Name $observerName -ErrorAction Stop',
        'observer account still exists after removal'
    ),
    @(
        'Remove-LocalUser -Name $ownerName -ErrorAction Stop',
        'owner account still exists after removal'
    )
)) {
    $removalIndex = $windowsAclSource.LastIndexOf(
        $cleanupPostcondition[0],
        [System.StringComparison]::Ordinal
    )
    $postconditionIndex = $windowsAclSource.LastIndexOf(
        $cleanupPostcondition[1],
        [System.StringComparison]::Ordinal
    )
    Assert-TestCondition (
        $removalIndex -ge 0 -and $postconditionIndex -gt $removalIndex
    ) (
        "Windows multi-account ACL harness does not prove cleanup after " +
        "'$($cleanupPostcondition[0])'"
    )
}
$cleanupFailureIndex = $windowsAclSource.LastIndexOf(
    'Windows multi-account ACL gate cleanup failed closed',
    [System.StringComparison]::Ordinal
)
$passOutputIndex = $windowsAclSource.LastIndexOf(
    '$gateResult | ConvertTo-Json -Compress | Write-Output',
    [System.StringComparison]::Ordinal
)
Assert-TestCondition (
    $cleanupFailureIndex -ge 0 -and $passOutputIndex -gt $cleanupFailureIndex
) 'Windows multi-account ACL harness emits a passing result before cleanup succeeds'
$workerMatch = [regex]::Match(
    $windowsAclSource,
    "(?ms)\`$worker\s*=\s*@'\r?\n(?<source>.*?)\r?\n'@",
    [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
)
Assert-TestCondition $workerMatch.Success (
    'Windows multi-account ACL harness worker source could not be extracted'
)
$workerTokens = $null
$workerParseErrors = $null
[void][System.Management.Automation.Language.Parser]::ParseInput(
    $workerMatch.Groups['source'].Value,
    [ref]$workerTokens,
    [ref]$workerParseErrors
)
Assert-TestCondition ($workerParseErrors.Count -eq 0) (
    'Windows multi-account ACL harness worker is not valid PowerShell: ' +
    (($workerParseErrors | ForEach-Object { $_.Message }) -join '; ')
)

$deny = Get-Content -LiteralPath $denyPath -Raw -Encoding utf8
Assert-TestCondition ($deny -match '(?m)^multiple-versions\s*=\s*"deny"\s*$') (
    'cargo-deny does not fail on unreviewed duplicate versions'
)
Assert-TestCondition (-not ($deny -match '(?m)^skip-tree\s*=')) (
    'cargo-deny uses a subtree exception that can hide future duplicate versions'
)
$skipEntries = @(
    [regex]::Matches(
        $deny,
        'crate\s*=\s*"(?<crate>[^"]+)"\s*,\s*reason\s*=\s*"(?<reason>[^"]+)"',
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
)
Assert-TestCondition ($skipEntries.Count -gt 0) 'cargo-deny has no reviewed exact duplicate exceptions'
$seenSkipEntries = @{}
foreach ($entry in $skipEntries) {
    $crate = $entry.Groups['crate'].Value
    $reason = $entry.Groups['reason'].Value
    Assert-TestCondition ($crate -match '^[A-Za-z0-9_-]+@[0-9][0-9A-Za-z.+-]*$') (
        "cargo-deny duplicate exception is not exact-version scoped: '$crate'"
    )
    Assert-TestCondition (-not [string]::IsNullOrWhiteSpace($reason)) (
        "cargo-deny duplicate exception '$crate' has no review reason"
    )
    Assert-TestCondition (-not $seenSkipEntries.ContainsKey($crate)) (
        "cargo-deny duplicate exception '$crate' is listed more than once"
    )
    $seenSkipEntries[$crate] = $true
}
foreach ($forbidden in @('gh release create', 'Windows release artifact', 'refs/heads/main')) {
    Assert-TestCondition (-not $ciWorkflow.Contains($forbidden)) (
        "ordinary CI still contains formal-release behavior '$forbidden'"
    )
}
$ciActionUses = [regex]::Matches($ciWorkflow, '(?m)^\s*uses:\s*(?<value>[^#\r\n]+)')
Assert-TestCondition ($ciActionUses.Count -gt 0) 'ordinary CI contains no actions'
$expectedCiActions = [ordered]@{
    'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1' = 3
    'actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a' = 1
}
$actualCiActions = @{}
foreach ($actionUse in $ciActionUses) {
    $value = $actionUse.Groups['value'].Value.Trim()
    Assert-TestCondition ($value -match '^[^@\s]+@[0-9a-f]{40}$') (
        "ordinary CI action is not pinned to a full commit: '$value'"
    )
    Assert-TestCondition ($expectedCiActions.Contains($value)) (
        "ordinary CI uses an unapproved action identity: '$value'"
    )
    if (-not $actualCiActions.ContainsKey($value)) {
        $actualCiActions[$value] = 0
    }
    $actualCiActions[$value] += 1
}
foreach ($expectedAction in $expectedCiActions.Keys) {
    $actualCount = if ($actualCiActions.ContainsKey($expectedAction)) {
        [int]$actualCiActions[$expectedAction]
    }
    else {
        0
    }
    Assert-TestCondition (
        $actualCount -eq [int]$expectedCiActions[$expectedAction]
    ) (
        "ordinary CI action '$expectedAction' count is $actualCount; " +
        "expected $($expectedCiActions[$expectedAction])"
    )
}

Assert-TestCondition (
    Test-Path -LiteralPath $buildScriptFixtureScript -PathType Leaf
) 'cross-platform build-script fixture driver is missing'
$buildScriptFixtureSource = Get-Content `
    -LiteralPath $buildScriptFixtureScript `
    -Raw `
    -Encoding utf8
foreach ($requiredFixtureBoundary in @(
    '[System.Environment]::OSVersion.Platform',
    '[System.PlatformID]::Win32NT',
    "'.exe'",
    'target/ci-build-script-fixtures',
    'crates/serctl_cli/build.rs',
    'crates/serctl_daemon/build.rs',
    'crates/serctl_xfer/build.rs',
    'crates/serctl_remote/build.rs',
    '[System.IO.FileAttributes]::ReparsePoint',
    '& $outputPath',
    '$LASTEXITCODE -ne 0'
)) {
    Assert-TestCondition ($buildScriptFixtureSource.Contains($requiredFixtureBoundary)) (
        "cross-platform build-script fixture driver lacks '$requiredFixtureBoundary'"
    )
}
$fixtureTokens = $null
$fixtureParseErrors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile(
    $buildScriptFixtureScript,
    [ref]$fixtureTokens,
    [ref]$fixtureParseErrors
)
Assert-TestCondition ($fixtureParseErrors.Count -eq 0) (
    'cross-platform build-script fixture driver is not valid PowerShell: ' +
    (($fixtureParseErrors | ForEach-Object { $_.Message }) -join '; ')
)

$bundle = Get-Content -LiteralPath $bundleScript -Raw -Encoding utf8
foreach ($governanceFile in @(
    'SECURITY.md',
    'docs/v1-beta-agent-jsonl.md',
    'docs/v1-beta-release-contract.md',
    'docs/v1-beta-acceptance-matrix.md'
)) {
    Assert-TestCondition ($bundle.Contains($governanceFile)) (
        "release bundle omits governance file '$governanceFile'"
    )
}
foreach ($requiredBundleBoundary in @(
    '$helpers = @(''serctl-xfer'')',
    '$forbiddenRuntimeArtifacts = @(''serctl-remote'', ''serctl-remote.debug'')',
    'Test-LinuxGlibcBaseline.ps1',
    "-MaximumSupported '2.35'",
    'tag_object = $TagObject.ToLowerInvariant()',
    'linux-x86_64-xfer.tar.gz',
    'linux-x86_64-xfer-symbols.tar.gz',
    '--format=ustar',
    'Get-ChildItem -LiteralPath $SourceDirectory -Force -File',
    ') + $names',
    'Set-LinuxReleaseModes',
    '& chmod 0755 -- $helper',
    '& chmod 0644 -- $file.FullName'
    'Format-ReleaseLogRecord'
    '-Category release_bundle_failed'
    '[Console]::Error.WriteLine('
    '& tar @tarArguments *> $null'
    '& $BinaryPath --version 2>$null'
    'schema_version = 2'
    'binary_components = @($binaryComponents)'
    'binary_size = [long]$binaryItem.Length'
)) {
    Assert-TestCondition ($bundle.Contains($requiredBundleBoundary)) (
        "release bundle lacks xfer-only boundary '$requiredBundleBoundary'"
    )
}
foreach ($forbiddenBundleLog in @(
    "exact release identity: `$line",
    "tar failed for '`$DestinationPath'",
    "required binary '`$BinaryPath'",
    "CARGO_TARGET_DIR resolves outside the repository: '`$releaseRoot'",
    '$_.Exception.Message'
)) {
    Assert-TestCondition (-not $bundle.Contains($forbiddenBundleLog)) (
        "release bundler exposes forbidden log material '$forbiddenBundleLog'"
    )
}
Assert-TestCondition (-not $bundle.Contains("'^serctl-remote$'")) (
    'release bundler still treats serctl-remote as a versioned runtime binary'
)
foreach ($protocolIdentity in @(
    'IPC v9..=v9',
    'transfer protocol v1',
    'vault-storage read=v4..=v5 write=v5'
)) {
    Assert-TestCondition ($bundle.Contains($protocolIdentity)) (
        "release bundler does not require exact identity '$protocolIdentity'"
    )
}
foreach ($binaryGrammar in @('^serctl_cli ', '^serctl_daemon ', '^serctl-xfer ')) {
    Assert-TestCondition ($bundle.Contains($binaryGrammar)) (
        "release bundler lacks exact anchored identity grammar '$binaryGrammar'"
    )
}

$manifestSource = Get-Content -LiteralPath $manifestScript -Raw -Encoding utf8
$assetContractSource = Get-Content -LiteralPath $assetContractScript -Raw -Encoding utf8
$downloadedSetVerifierSource = Get-Content `
    -LiteralPath $downloadedSetVerifierScript -Raw -Encoding utf8
$releaseArchiveContractSource = Get-Content `
    -LiteralPath $releaseArchiveContractScript -Raw -Encoding utf8
$downloadedSetSelfTestSource = Get-Content `
    -LiteralPath $downloadedSetSelfTestScript -Raw -Encoding utf8
$releaseAssetSnapshotSource = Get-Content `
    -LiteralPath $releaseAssetSnapshotScript -Raw -Encoding utf8
$releaseAssetSnapshotSelfTestSource = Get-Content `
    -LiteralPath $releaseAssetSnapshotSelfTestScript -Raw -Encoding utf8
foreach ($snapshotBoundary in @(
    '[System.IO.FileMode]::CreateNew',
    '[System.IO.FileShare]::None',
    '[System.IO.FileOptions]::WriteThrough',
    'Get-V1BetaFinalReleaseNames -Version $Version',
    'differs from the frozen size/SHA-256 snapshot',
    'publish directory mode is not 0500'
)) {
    Assert-TestCondition ($releaseAssetSnapshotSource.Contains($snapshotBoundary)) (
        "release asset snapshot helper lacks boundary '$snapshotBoundary'"
    )
}
foreach ($snapshotCounterexample in @(
    'same-name byte replacement',
    'extra file injection',
    'allowlisted file deletion',
    'publish staging overwrite'
)) {
    Assert-TestCondition ($releaseAssetSnapshotSelfTestSource.Contains($snapshotCounterexample)) (
        "release asset snapshot self-test lacks counterexample '$snapshotCounterexample'"
    )
}
foreach ($identityBoundary in @(
    'CLI identity missing vault storage contract',
    'daemon identity missing vault storage contract',
    'helper identity falsely claims vault storage contract',
    'platform binary size missing',
    'platform binary size negative',
    'platform binary size type confusion',
    'platform binary size differs from archive bytes',
    'platform binary hash differs from archive bytes'
)) {
    Assert-TestCondition ($downloadedSetSelfTestSource.Contains($identityBoundary)) (
        "downloaded-set self-test lacks identity counterexample '$identityBoundary'"
    )
}
foreach ($marker in @(
    'ReleaseArchiveContract.ps1',
    'Get-VerifiedReleaseArchiveMembers',
    'archive member size/digest does not match platform provenance',
    'runtime archive embeds a platform provenance file different from the released provenance'
)) {
    Assert-TestCondition ($downloadedSetVerifierSource.Contains($marker)) (
        "downloaded release verifier lacks archive guard '$marker'"
    )
}
foreach ($marker in @(
    'duplicate or case-colliding member',
    'symbolic link',
    'hard link',
    'source-only component',
    'two terminal zero blocks',
    'exact allowlist',
    'ZIP EOCD does not end at physical EOF',
    'DOS directory or reparse-point member',
    'gzip archive does not use the canonical single-member header',
    'gzip member trailer does not end at physical EOF',
    'tar archive exceeds the global header-count bound',
    'tar release archive contains a directory entry',
    'does not use the required release mode'
)) {
    Assert-TestCondition ($releaseArchiveContractSource.Contains($marker)) (
        "release archive contract lacks fail-closed guard '$marker'"
    )
}
foreach ($marker in @(
    'ZIP path traversal member',
    'ZIP duplicate member',
    'ZIP case-colliding member',
    'ZIP symbolic link member',
    'ZIP raw trailing bytes after EOCD',
    'ZIP DOS directory attribute',
    'ZIP DOS reparse attribute',
    'tar hard link member',
    'tar symbolic link member',
    'tar root directory header',
    'tar runtime helper without execute mode',
    'tar executable governance document',
    'tar.gz raw trailing bytes',
    'tar.gz second gzip member',
    'oversized ordinary asset before hashing',
    'oversized SBOM before parsing',
    'oversized aggregate release set before hashing',
    'oversized SHA256SUMS before whole-file read',
    'oversized provenance JSON',
    'source-only archive member',
    'archive binary digest differs from provenance',
    'archive symbol digest differs from provenance'
)) {
    Assert-TestCondition ($downloadedSetSelfTestSource.Contains($marker)) (
        "downloaded release self-test lacks archive mutation '$marker'"
    )
}
foreach ($assetMarker in @(
    'linux-x86_64-xfer-symbols.tar.gz',
    'linux-x86_64.provenance.json',
    'linux-x86_64-xfer.tar.gz',
    'serctl-cli.sbom.cdx.json',
    'serctl-cli.sbom.cdx.xml',
    'serctl-daemon.sbom.cdx.json',
    'serctl-daemon.sbom.cdx.xml',
    'serctl-xfer.sbom.cdx.json',
    'serctl-xfer.sbom.cdx.xml',
    'windows-x86_64-symbols.zip',
    'windows-x86_64.provenance.json',
    'windows-x86_64.zip'
)) {
    Assert-TestCondition ($assetContractSource.Contains($assetMarker)) (
        "release asset contract does not require exact asset '$assetMarker'"
    )
}
foreach ($contractFunction in @(
    'Get-V1BetaReleaseInputNames',
    'Get-V1BetaHashedReleaseNames',
    'Get-V1BetaFinalReleaseNames'
)) {
    Assert-TestCondition ($manifestSource.Contains($contractFunction)) (
        "release manifest does not consume shared asset contract '$contractFunction'"
    )
}

$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'serctl-release-governance-test-' + [System.Guid]::NewGuid().ToString('N')
)
$fixtureFuzzReceipt = "$temporaryRoot-parser-fuzz-success.json"
$headCommit = (& git -C $repositoryRoot rev-parse HEAD | Out-String).Trim().ToLowerInvariant()
Assert-TestCondition ($LASTEXITCODE -eq 0) 'cannot resolve HEAD for manifest fixture'
$headEpoch = (& git -C $repositoryRoot show -s --format=%ct HEAD | Out-String).Trim()
Assert-TestCondition ($LASTEXITCODE -eq 0) 'cannot resolve HEAD timestamp for manifest fixture'
$fixtureEnvironment = [ordered]@{
    GITHUB_REPOSITORY = 'example/serctl'
    GITHUB_WORKFLOW = 'release governance fixture'
    GITHUB_WORKFLOW_REF = 'example/serctl/.github/workflows/release-v1-beta.yml@refs/tags/v1.0.0-beta'
    GITHUB_RUN_ID = '123456'
    GITHUB_RUN_ATTEMPT = '1'
    GITHUB_EVENT_NAME = 'push'
    GITHUB_REF = 'refs/tags/v1.0.0-beta'
    SOURCE_DATE_EPOCH = $headEpoch
    RUNNER_OS = 'Linux'
    RUNNER_ARCH = 'X64'
    ImageOS = 'ubuntu24'
    ImageVersion = 'fixture'
}
$savedEnvironment = @{}
foreach ($name in $fixtureEnvironment.Keys) {
    $savedEnvironment[$name] = [System.Environment]::GetEnvironmentVariable($name, 'Process')
    [System.Environment]::SetEnvironmentVariable(
        $name,
        [string]$fixtureEnvironment[$name],
        'Process'
    )
}
[System.IO.Directory]::CreateDirectory($temporaryRoot) | Out-Null
try {
    & $parserFuzzReceiptGeneratorScript `
        -Path $fixtureFuzzReceipt `
        -Tag 'v1.0.0-beta' `
        -TagObject 'fedcba9876543210fedcba9876543210fedcba98' `
        -Commit $headCommit `
        -Repository 'example/serctl' `
        -RunId '123456' `
        -RunAttempt '1' `
        -RepositoryRoot $repositoryRoot
    $fixtureAssets = @(
        'serctl-1.0.0-beta-linux-x86_64-xfer-symbols.tar.gz',
        'serctl-1.0.0-beta-linux-x86_64.provenance.json',
        'serctl-1.0.0-beta-linux-x86_64-xfer.tar.gz',
        'serctl-1.0.0-beta-serctl-cli.sbom.cdx.json',
        'serctl-1.0.0-beta-serctl-cli.sbom.cdx.xml',
        'serctl-1.0.0-beta-serctl-daemon.sbom.cdx.json',
        'serctl-1.0.0-beta-serctl-daemon.sbom.cdx.xml',
        'serctl-1.0.0-beta-serctl-xfer.sbom.cdx.json',
        'serctl-1.0.0-beta-serctl-xfer.sbom.cdx.xml',
        'serctl-1.0.0-beta-windows-x86_64-symbols.zip',
        'serctl-1.0.0-beta-windows-x86_64.provenance.json',
        'serctl-1.0.0-beta-windows-x86_64.zip'
    )
    foreach ($asset in $fixtureAssets) {
        [System.IO.File]::WriteAllText(
            (Join-Path $temporaryRoot $asset),
            "fixture:$asset`n",
            [System.Text.UTF8Encoding]::new($false)
        )
    }
    & $manifestScript `
        -Directory $temporaryRoot `
        -Version '1.0.0-beta' `
        -Commit $headCommit `
        -Tag 'v1.0.0-beta' `
        -TagObject 'fedcba9876543210fedcba9876543210fedcba98' `
        -ParserFuzzReceiptPath $fixtureFuzzReceipt `
        -ParserFuzzArtifactId '987654' `
        -ParserFuzzArtifactDigest ('a' * 64)
    $checksumPath = Join-Path $temporaryRoot 'SHA256SUMS'
    $provenancePath = Join-Path $temporaryRoot 'release-provenance.json'
    Assert-TestCondition (Test-Path -LiteralPath $checksumPath -PathType Leaf) 'SHA256SUMS was not created'
    Assert-TestCondition (Test-Path -LiteralPath $provenancePath -PathType Leaf) (
        'release-provenance.json was not created'
    )
    $checksumLines = @(Get-Content -LiteralPath $checksumPath -Encoding utf8)
    Assert-TestCondition ($checksumLines.Count -eq 13) (
        "expected thirteen hashed files including provenance, found $($checksumLines.Count)"
    )
    Assert-TestCondition (-not ($checksumLines -match 'SHA256SUMS')) 'manifest hashed itself'
    foreach ($line in $checksumLines) {
        Assert-TestCondition ($line -match '^[0-9a-f]{64}  [^\r\n]+$') (
            "invalid checksum line '$line'"
        )
    }
    $createdHashes = @{}
    foreach ($created in Get-ChildItem -LiteralPath $temporaryRoot -File) {
        $createdHashes[$created.Name] = (
            Get-FileHash -LiteralPath $created.FullName -Algorithm SHA256
        ).Hash
    }
    Invoke-ExpectedScriptFailure -Description 'release manifest overwrite attempt' -Action {
        & $manifestScript `
            -Directory $temporaryRoot `
            -Version '1.0.0-beta' `
            -Commit $headCommit `
            -Tag 'v1.0.0-beta' `
            -TagObject 'fedcba9876543210fedcba9876543210fedcba98' `
            -ParserFuzzReceiptPath $fixtureFuzzReceipt `
            -ParserFuzzArtifactId '987654' `
            -ParserFuzzArtifactDigest ('a' * 64)
    }
    foreach ($created in Get-ChildItem -LiteralPath $temporaryRoot -File) {
        Assert-TestCondition (
            $createdHashes[$created.Name] -ceq (
                Get-FileHash -LiteralPath $created.FullName -Algorithm SHA256
            ).Hash
        ) "release manifest overwrite failure changed '$($created.Name)'"
    }
}
finally {
    foreach ($name in $fixtureEnvironment.Keys) {
        $savedValue = $savedEnvironment[$name]
        [System.Environment]::SetEnvironmentVariable(
            $name,
            $savedValue,
            'Process'
        )
    }
    if (Test-Path -LiteralPath $temporaryRoot) {
        [System.IO.Directory]::Delete($temporaryRoot, $true)
    }
    Remove-Item -LiteralPath $fixtureFuzzReceipt -Force -ErrorAction SilentlyContinue
}

$runtimeBoundarySource = Get-Content `
    -LiteralPath $runtimeBoundaryScript `
    -Raw `
    -Encoding utf8
$runtimeBoundarySelfTestSource = Get-Content `
    -LiteralPath $runtimeBoundarySelfTestScript `
    -Raw `
    -Encoding utf8
$strictJsonSelfTestSource = Get-Content `
    -LiteralPath $strictJsonSelfTestScript `
    -Raw `
    -Encoding utf8
$documentationGovernanceSource = Get-Content `
    -LiteralPath $documentationScript `
    -Raw `
    -Encoding utf8
foreach ($auditRecoveryMarker in @(
    'derive_profile_audit_recovery_key_with_lock_timeout',
    'high_level_audit_recovery_contract_uses_only_isolated_state'
)) {
    Assert-TestCondition ($documentationGovernanceSource.Contains($auditRecoveryMarker)) (
        "documentation governance is missing audit recovery guard '$auditRecoveryMarker'"
    )
}
foreach ($requiredBoundary in @(
    "StrictJson.ps1",
    'Read-StrictUtf8Text',
    'ConvertFrom-StrictJson',
    'Get-CycloneDxJsonComponentNames',
    'Get-CargoPackageNameFromPurl',
    'cargo metadata contains an unknown dependency kind',
    'CycloneDX JSON metadata.tools.components',
    'DtdProcessing]::Prohibit',
    'MaxCharactersInDocument = 8388608'
)) {
    Assert-TestCondition ($runtimeBoundarySource.Contains($requiredBoundary)) (
        "runtime dependency boundary is missing strict JSON guard '$requiredBoundary'"
    )
}
foreach ($requiredNegative in @(
    'unknown dependency kind was silently treated as dev-only',
    'unknown dependency kind after a build edge was ignored',
    'numeric cargo dependency target was accepted',
    'string cargo metadata version was accepted',
    'orphan cargo metadata resolve node was accepted',
    'cargo metadata package without a resolve node was accepted',
    'missing source-only workspace member was accepted',
    'invalid UTF-8 metadata did not fail closed',
    'case-colliding metadata key did not fail closed',
    'metadata packages object was accepted as an array',
    'source-only metadata.component did not fail closed',
    'source-only metadata.tools.components entry did not fail closed',
    'source-only Cargo purl hidden behind a different name did not fail closed',
    'dangling source-only CycloneDX dependency reference did not fail closed',
    'CycloneDX components object was accepted as an array',
    'case-colliding CycloneDX key did not fail closed',
    'invalid UTF-8 CycloneDX JSON did not fail closed',
    'wrong CycloneDX XML namespace was accepted',
    'CycloneDX XML DTD was accepted',
    'oversized CycloneDX XML was accepted'
)) {
    Assert-TestCondition ($runtimeBoundarySelfTestSource.Contains($requiredNegative)) (
        "runtime dependency boundary self-test is missing '$requiredNegative'"
    )
}
foreach ($requiredStrictJsonNegative in @(
    'nonstandard primitive',
    'block comment was accepted',
    'line comment was accepted',
    'non-JSON whitespace was accepted',
    'unpaired surrogate',
    'an unpaired raw UTF-16 surrogate was accepted'
)) {
    Assert-TestCondition ($strictJsonSelfTestSource.Contains($requiredStrictJsonNegative)) (
        "strict JSON self-test is missing '$requiredStrictJsonNegative'"
    )
}

& $documentationScript
& $localGateTestScript
& $runtimeBoundarySelfTestScript
& $downloadedSetSelfTestScript
& $releaseAssetSnapshotSelfTestScript
& $strictJsonSelfTestScript
& $parserFuzzBoundaryScript -RepositoryRoot $repositoryRoot
& $parserFuzzBoundarySelfTestScript -RepositoryRoot $repositoryRoot
& $parserFuzzReceiptSelfTestScript -RepositoryRoot $repositoryRoot
& $releaseLogSelfTestScript
& $externalRuntimeSupervisorSelfTestScript
& $externalTransferRuntimeAdapterSelfTestScript
& $isolatedExternalTransferOwnerSelfTestScript
& $externalTransferOfficialComponentAnchorSelfTestScript
& $nativeFaultRegistryPerformanceOwnerSelfTestScript
& $sshPreauthEvidenceSelfTestScript
& $externalEvidenceSelfTestScript
& $externalTransferRuntimeReceiptContractSelfTestScript
& $cleanInstallHarnessSelfTestScript
& $windowsAclReceiptContractSelfTestScript
& $glibcBaselineSelfTestScript
& $upgradeRollbackHarnessTestScript

Write-Host 'Release governance self-tests passed.'
