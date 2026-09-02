[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-SelfTestCondition {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if (-not $Condition) {
        throw "isolated candidate self-test failed: $Message"
    }
}

function Write-Utf8NoBom {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Content
    )
    [System.IO.File]::WriteAllText(
        $Path,
        $Content,
        [System.Text.UTF8Encoding]::new($false)
    )
}

function Restore-ProcessEnvironmentVariable {
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

function Invoke-FixtureGit {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & git -c core.autocrlf=false -C $script:Repository @Arguments *> $null
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    Assert-SelfTestCondition ($exitCode -eq 0) (
        "fixture git command failed: git $($Arguments -join ' ')"
    )
}

function Get-FixtureHead {
    $head = (& git -C $script:Repository rev-parse HEAD | Out-String).Trim()
    Assert-SelfTestCondition ($LASTEXITCODE -eq 0) 'cannot read fixture HEAD'
    Assert-SelfTestCondition ($head -cmatch '^[0-9a-f]{40}$') (
        'fixture HEAD is not canonical'
    )
    return $head
}

function Invoke-ExpectedCandidateFailure {
    param(
        [Parameter(Mandatory = $true)][string]$Description,
        [Parameter(Mandatory = $true)][string]$ExpectedMessage,
        [Parameter(Mandatory = $true)][scriptblock]$Action
    )

    $caught = $null
    try {
        & $Action *> $null
    }
    catch {
        $caught = $_
    }
    Assert-SelfTestCondition ($null -ne $caught) "$Description unexpectedly passed"
    Assert-SelfTestCondition (
        $caught.Exception.Message.Contains($ExpectedMessage)
    ) (
        "$Description failed for the wrong reason: $($caught.Exception.Message)"
    )
}

function Assert-DirectoryEmpty {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Description
    )
    if (-not [System.IO.Directory]::Exists($Path)) {
        return
    }
    Assert-SelfTestCondition (
        @(Get-ChildItem -LiteralPath $Path -Force).Count -eq 0
    ) "$Description contains leaked private build state"
}

function Assert-SentinelUnchanged {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ExpectedHash,
        [Parameter(Mandatory = $true)][datetime]$ExpectedWriteTime,
        [Parameter(Mandatory = $true)][string]$Description
    )
    Assert-SelfTestCondition (Test-Path -LiteralPath $Path -PathType Leaf) (
        "$Description sentinel disappeared"
    )
    Assert-SelfTestCondition (
        (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ceq $ExpectedHash
    ) "$Description sentinel bytes changed"
    Assert-SelfTestCondition (
        (Get-Item -LiteralPath $Path -Force).LastWriteTimeUtc -eq $ExpectedWriteTime
    ) "$Description sentinel write time changed"
}

function Assert-SubsequentCargoWorks {
    param([Parameter(Mandatory = $true)][string]$Description)

    $cargo = Get-Command -Name cargo -CommandType Application -ErrorAction Stop |
        Select-Object -First 1
    $previousErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $cargo.Source `
            metadata `
            --no-deps `
            --format-version 1 `
            --manifest-path (Join-Path $script:Repository 'Cargo.toml') *> $null
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    Assert-SelfTestCondition ($exitCode -eq 0) (
        "$Description left the subsequent Cargo process unusable"
    )
}

$hostIsWindows = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
    [System.Runtime.InteropServices.OSPlatform]::Windows
)
Assert-SelfTestCondition $hostIsWindows (
    'P1 persistent-handle self-test requires Windows; non-Windows candidate ' +
    'construction intentionally fails closed'
)
$pathComparison = if ($hostIsWindows) {
    [System.StringComparison]::OrdinalIgnoreCase
}
else {
    [System.StringComparison]::Ordinal
}
$executableSuffix = if ($hostIsWindows) { '.exe' } else { '' }

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$selfTestParent = Join-Path $repositoryRoot 'target/ic-selftests'
[System.IO.Directory]::CreateDirectory($selfTestParent) | Out-Null
$script:SelfTestRoot = Join-Path $selfTestParent (
    'ic-' + [System.Guid]::NewGuid().ToString('N')
)
$script:Repository = Join-Path $script:SelfTestRoot 'r'
$toolsDirectory = Join-Path $script:SelfTestRoot 't'
$fixtureSource = Join-Path $toolsDirectory 'fixture-binary.rs'
$fixtureBinary = Join-Path $toolsDirectory "fixture-binary$executableSuffix"
$fakeCargo = Join-Path $toolsDirectory "fixture-cargo$executableSuffix"
$fakeRustc = Join-Path $toolsDirectory "rustc$executableSuffix"
$fakeRustdoc = Join-Path $toolsDirectory "rustdoc$executableSuffix"
$buildCount = Join-Path $toolsDirectory 'build-count.txt'
$builder = Join-Path $PSScriptRoot 'New-IsolatedCandidate.ps1'
$version = '1.0.0-beta'
$releaseSentinel = Join-Path $script:Repository 'target/release/sentinel.txt'
$predecessorSentinel = Join-Path (
    $script:Repository
) 'target/staging-v0.3/sentinel.txt'

$selfTestFullPath = [System.IO.Path]::GetFullPath($script:SelfTestRoot)
$selfTestPrefix = [System.IO.Path]::GetFullPath($selfTestParent).TrimEnd(
    [System.IO.Path]::DirectorySeparatorChar
) + [System.IO.Path]::DirectorySeparatorChar
Assert-SelfTestCondition (
    $selfTestFullPath.StartsWith(
        $selfTestPrefix,
        $pathComparison
    ) -and
    [System.IO.Path]::GetFileName($selfTestFullPath).StartsWith(
        'ic-',
        [System.StringComparison]::Ordinal
    )
) 'temporary fixture path escaped its dedicated self-test parent'

$savedFixtureBinary = [System.Environment]::GetEnvironmentVariable(
    'SERCTL_FIXTURE_BINARY',
    'Process'
)
$savedFixtureVersion = [System.Environment]::GetEnvironmentVariable(
    'SERCTL_FIXTURE_VERSION',
    'Process'
)
$savedFixtureCommit = [System.Environment]::GetEnvironmentVariable(
    'SERCTL_FIXTURE_COMMIT',
    'Process'
)
$savedBadDaemon = [System.Environment]::GetEnvironmentVariable(
    'SERCTL_FIXTURE_BAD_DAEMON',
    'Process'
)
$savedBuildCount = [System.Environment]::GetEnvironmentVariable(
    'SERCTL_FIXTURE_BUILD_COUNT',
    'Process'
)
$savedFixtureSuffix = [System.Environment]::GetEnvironmentVariable(
    'SERCTL_FIXTURE_SUFFIX',
    'Process'
)
$savedGitDirectory = [System.Environment]::GetEnvironmentVariable(
    'GIT_DIR',
    'Process'
)
$savedCargoTarget = [System.Environment]::GetEnvironmentVariable(
    'CARGO_TARGET_DIR',
    'Process'
)
$savedSelfTestMode = [System.Environment]::GetEnvironmentVariable(
    'SERCTL_ISOLATED_CANDIDATE_SELFTEST',
    'Process'
)
$savedTamperBuildOwner = [System.Environment]::GetEnvironmentVariable(
    'SERCTL_FIXTURE_TAMPER_BUILD_OWNER',
    'Process'
)
$savedExpectedCwd = [System.Environment]::GetEnvironmentVariable(
    'SERCTL_FIXTURE_EXPECTED_CWD',
    'Process'
)
$savedExpectedRustc = [System.Environment]::GetEnvironmentVariable(
    'SERCTL_FIXTURE_EXPECTED_RUSTC',
    'Process'
)
$savedExpectedRustdoc = [System.Environment]::GetEnvironmentVariable(
    'SERCTL_FIXTURE_EXPECTED_RUSTDOC',
    'Process'
)
$savedMutateSource = [System.Environment]::GetEnvironmentVariable(
    'SERCTL_FIXTURE_MUTATE_SOURCE',
    'Process'
)
$savedIgnoredEventStorm = [System.Environment]::GetEnvironmentVariable(
    'SERCTL_FIXTURE_IGNORED_EVENT_STORM',
    'Process'
)

try {
    [System.IO.Directory]::CreateDirectory($script:Repository) | Out-Null
    [System.IO.Directory]::CreateDirectory($toolsDirectory) | Out-Null
    Write-Utf8NoBom -Path (Join-Path $script:Repository '.gitignore') -Content "target/`n"
    Write-Utf8NoBom -Path (Join-Path $script:Repository 'README.md') -Content "fixture-one`n"
    Write-Utf8NoBom -Path (Join-Path $script:Repository 'Cargo.toml') -Content @"
[workspace]
resolver = "2"
members = []

[workspace.package]
version = "$version"
edition = "2021"
"@
    Write-Utf8NoBom `
        -Path (Join-Path $script:Repository 'rust-toolchain.toml') `
        -Content "[toolchain]`nchannel = `"1.99.0`"`nprofile = `"minimal`"`n"

    Invoke-FixtureGit @('init', '--quiet')
    Invoke-FixtureGit @('config', 'user.name', 'serctl-self-test')
    Invoke-FixtureGit @('config', 'user.email', 'serctl-self-test.invalid')
    Invoke-FixtureGit @('add', '--all')
    Invoke-FixtureGit @('commit', '--quiet', '-m', 'clean fixture source')
    $firstHead = Get-FixtureHead

    Write-Utf8NoBom -Path $fixtureSource -Content @'
use std::env;
use std::path::Path;

fn required(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| {
        eprintln!("missing fixture environment: {name}");
        std::process::exit(3);
    })
}

fn main() {
    let executable = env::current_exe().unwrap();
    let name = Path::new(&executable)
        .file_name()
        .unwrap()
        .to_string_lossy()
        .to_ascii_lowercase()
        .trim_end_matches(".exe")
        .to_owned();
    let arguments = env::args().skip(1).collect::<Vec<_>>();
    if name == "fixture-cargo" {
        if arguments == ["--version", "--verbose"] {
            println!("cargo 1.99.0 (isolated-candidate-fixture)");
            println!("release: 1.99.0");
            println!("commit-hash: 1111111111111111111111111111111111111111");
            println!("host: x86_64-pc-windows-msvc");
            return;
        }
        if arguments.first().map(String::as_str) != Some("build") {
            std::process::exit(11);
        }
        let expected_cwd = required("SERCTL_FIXTURE_EXPECTED_CWD");
        if env::current_dir().unwrap() != Path::new(&expected_cwd) {
            std::process::exit(12);
        }
        if env::var("RUSTC") != Ok(required("SERCTL_FIXTURE_EXPECTED_RUSTC")) {
            std::process::exit(16);
        }
        if env::var("RUSTDOC") != Ok(required("SERCTL_FIXTURE_EXPECTED_RUSTDOC")) {
            std::process::exit(17);
        }
        let manifest_index = arguments.iter().position(|item| item == "--manifest-path")
            .unwrap_or_else(|| std::process::exit(13));
        let manifest = arguments.get(manifest_index + 1)
            .unwrap_or_else(|| std::process::exit(14));
        if !Path::new(manifest).is_file() || !manifest.contains("candidate-sources") {
            std::process::exit(15);
        }
        if env::var("SERCTL_FIXTURE_MUTATE_SOURCE").as_deref() == Ok("1") {
            let readme = Path::new(&expected_cwd).join("README.md");
            let original = std::fs::read(&readme).unwrap();
            std::fs::write(&readme, b"temporary-source-change\n").unwrap();
            std::thread::sleep(std::time::Duration::from_millis(100));
            std::fs::write(&readme, original).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let target = required("CARGO_TARGET_DIR");
        let release = Path::new(&target).join("release");
        std::fs::create_dir_all(&release).unwrap();
        if env::var("SERCTL_FIXTURE_IGNORED_EVENT_STORM").as_deref() == Ok("1") {
            let storm = release.join("ignored-event-storm");
            std::fs::create_dir_all(&storm).unwrap();
            for index in 0..4000u32 {
                std::fs::write(storm.join(format!("event-{index:04}.tmp")), b"x")
                    .unwrap();
            }
        }
        let suffix = required("SERCTL_FIXTURE_SUFFIX");
        let fixture = required("SERCTL_FIXTURE_BINARY");
        for base in ["serctl_cli", "serctl_daemon", "serctl-xfer"] {
            std::fs::copy(&fixture, release.join(format!("{base}{suffix}"))).unwrap();
        }
        let count = required("SERCTL_FIXTURE_BUILD_COUNT");
        use std::io::Write;
        std::fs::OpenOptions::new().create(true).append(true).open(count)
            .unwrap().write_all(b"build\n").unwrap();
        if env::var("SERCTL_FIXTURE_TAMPER_BUILD_OWNER").as_deref() == Ok("1") {
            std::fs::write(
                Path::new(&target).join(".serctl-candidate-owner"),
                b"tampered-owner",
            ).unwrap();
        }
        return;
    }
    if name == "rustc" {
        if arguments == ["--version", "--verbose"] {
            println!("rustc 1.99.0 (isolated-candidate-fixture 2026-01-01)");
            println!("commit-hash: 2222222222222222222222222222222222222222");
            println!("host: x86_64-pc-windows-msvc");
            println!("release: 1.99.0");
            return;
        }
        std::process::exit(5);
    }
    if name == "rustdoc" {
        if arguments == ["--version", "--verbose"] {
            println!("rustdoc 1.99.0 (isolated-candidate-fixture 2026-01-01)");
            println!("commit-hash: 2222222222222222222222222222222222222222");
            println!("host: x86_64-pc-windows-msvc");
            println!("release: 1.99.0");
            return;
        }
        std::process::exit(6);
    }
    if arguments != ["--version"] {
        std::process::exit(2);
    }
    let version = required("SERCTL_FIXTURE_VERSION");
    let commit = required("SERCTL_FIXTURE_COMMIT");
    let short = &commit[..12];
    if name == "serctl_cli" {
        println!("serctl_cli {version} (git {short}; vault-storage read=v4..=v5 write=v5)");
    } else if name == "serctl_daemon" {
        if env::var("SERCTL_FIXTURE_BAD_DAEMON").as_deref() == Ok("1") {
            println!("serctl_daemon {version} (git {short}; IPC v8..=v8; vault-storage read=v4..=v5 write=v5)");
        } else {
            println!("serctl_daemon {version} (git {short}; IPC v9..=v9; vault-storage read=v4..=v5 write=v5)");
        }
    } else if name == "serctl-xfer" {
        println!("serctl-xfer {version} (git {short}; transfer protocol v1)");
    } else {
        std::process::exit(4);
    }
}
'@
    $rustc = Get-Command -Name rustc -CommandType Application -ErrorAction Stop |
        Select-Object -First 1
    & $rustc.Source $fixtureSource '-O' '-o' $fixtureBinary
    Assert-SelfTestCondition ($LASTEXITCODE -eq 0) 'failed to compile fixture binary'
    Assert-SelfTestCondition (Test-Path -LiteralPath $fixtureBinary -PathType Leaf) (
        'fixture binary was not produced'
    )
    [System.IO.File]::Copy($fixtureBinary, $fakeCargo, $false)
    [System.IO.File]::Copy($fixtureBinary, $fakeRustc, $false)
    [System.IO.File]::Copy($fixtureBinary, $fakeRustdoc, $false)

    [System.IO.Directory]::CreateDirectory(
        [System.IO.Path]::GetDirectoryName($releaseSentinel)
    ) | Out-Null
    [System.IO.Directory]::CreateDirectory(
        [System.IO.Path]::GetDirectoryName($predecessorSentinel)
    ) | Out-Null
    Write-Utf8NoBom -Path $releaseSentinel -Content "release-sentinel`n"
    Write-Utf8NoBom -Path $predecessorSentinel -Content "predecessor-sentinel`n"
    $releaseHash = (Get-FileHash -LiteralPath $releaseSentinel -Algorithm SHA256).Hash
    $releaseWriteTime = (Get-Item -LiteralPath $releaseSentinel).LastWriteTimeUtc
    $predecessorHash = (
        Get-FileHash -LiteralPath $predecessorSentinel -Algorithm SHA256
    ).Hash
    $predecessorWriteTime = (
        Get-Item -LiteralPath $predecessorSentinel
    ).LastWriteTimeUtc

    [System.Environment]::SetEnvironmentVariable(
        'SERCTL_FIXTURE_BINARY', $fixtureBinary, 'Process'
    )
    [System.Environment]::SetEnvironmentVariable(
        'SERCTL_FIXTURE_VERSION', $version, 'Process'
    )
    [System.Environment]::SetEnvironmentVariable(
        'SERCTL_FIXTURE_COMMIT', $firstHead, 'Process'
    )
    [System.Environment]::SetEnvironmentVariable(
        'SERCTL_FIXTURE_BAD_DAEMON', '0', 'Process'
    )
    [System.Environment]::SetEnvironmentVariable(
        'SERCTL_FIXTURE_BUILD_COUNT', $buildCount, 'Process'
    )
    [System.Environment]::SetEnvironmentVariable(
        'SERCTL_FIXTURE_SUFFIX', $executableSuffix, 'Process'
    )
    [System.Environment]::SetEnvironmentVariable(
        'SERCTL_ISOLATED_CANDIDATE_SELFTEST', '1', 'Process'
    )
    [System.Environment]::SetEnvironmentVariable(
        'SERCTL_FIXTURE_TAMPER_BUILD_OWNER', '0', 'Process'
    )
    [System.Environment]::SetEnvironmentVariable(
        'SERCTL_FIXTURE_EXPECTED_CWD', $script:Repository, 'Process'
    )
    [System.Environment]::SetEnvironmentVariable(
        'SERCTL_FIXTURE_EXPECTED_RUSTC', $fakeRustc, 'Process'
    )
    [System.Environment]::SetEnvironmentVariable(
        'SERCTL_FIXTURE_EXPECTED_RUSTDOC', $fakeRustdoc, 'Process'
    )
    [System.Environment]::SetEnvironmentVariable(
        'SERCTL_FIXTURE_MUTATE_SOURCE', '0', 'Process'
    )
    [System.Environment]::SetEnvironmentVariable(
        'SERCTL_FIXTURE_IGNORED_EVENT_STORM', '0', 'Process'
    )
    Restore-ProcessEnvironmentVariable `
        -Name 'CARGO_TARGET_DIR' `
        -Value $null
    Assert-SelfTestCondition (-not (Test-Path -LiteralPath Env:CARGO_TARGET_DIR)) (
        'absent CARGO_TARGET_DIR precondition was not established'
    )

    [System.Environment]::SetEnvironmentVariable(
        'SERCTL_FIXTURE_IGNORED_EVENT_STORM', '1', 'Process'
    )
    try {
        & $builder `
            -Version $version `
            -RepositoryRoot $script:Repository `
            -CargoExecutable $fakeCargo *> $null
    }
    finally {
        [System.Environment]::SetEnvironmentVariable(
            'SERCTL_FIXTURE_IGNORED_EVENT_STORM', '0', 'Process'
        )
    }
    Assert-SelfTestCondition (-not (Test-Path -LiteralPath Env:CARGO_TARGET_DIR)) (
        'builder left an empty CARGO_TARGET_DIR after a null original value'
    )
    Assert-SelfTestCondition (-not (Test-Path -LiteralPath Env:RUSTC)) (
        'builder left RUSTC set after the isolated build'
    )
    Assert-SelfTestCondition (-not (Test-Path -LiteralPath Env:RUSTDOC)) (
        'builder left RUSTDOC set after the isolated build'
    )
    Assert-SubsequentCargoWorks -Description 'absent CARGO_TARGET_DIR restoration'

    $identity = "v$version-$($firstHead.Substring(0, 12))"
    $candidate = Join-Path $script:Repository "target/candidates/$identity"
    $manifestPath = Join-Path $candidate 'candidate-manifest.json'
    Assert-SelfTestCondition (Test-Path -LiteralPath $manifestPath -PathType Leaf) (
        'positive fixture did not publish its manifest'
    )
    $manifestBytes = [System.IO.File]::ReadAllBytes($manifestPath)
    Assert-SelfTestCondition (
        $manifestBytes.Length -gt 3 -and
        -not (
            $manifestBytes[0] -eq 0xEF -and
            $manifestBytes[1] -eq 0xBB -and
            $manifestBytes[2] -eq 0xBF
        )
    ) 'candidate manifest is empty or has a UTF-8 BOM'
    $manifest = (
        [System.Text.UTF8Encoding]::new($false, $true).GetString($manifestBytes)
    ) | ConvertFrom-Json
    Assert-SelfTestCondition ([int]$manifest.schema_version -eq 1) (
        'manifest schema version mismatch'
    )
    Assert-SelfTestCondition ([string]$manifest.identity -ceq $identity) (
        'manifest candidate identity mismatch'
    )
    Assert-SelfTestCondition ([string]$manifest.head -ceq $firstHead) (
        'manifest full HEAD mismatch'
    )
    Assert-SelfTestCondition ([string]$manifest.tree -cmatch '^[0-9a-f]{40}$') (
        'manifest full tree identity mismatch'
    )
    Assert-SelfTestCondition (
        [string]$manifest.candidate_set.absolute_path -ceq $candidate
    ) 'manifest absolute candidate-set path mismatch'
    Assert-SelfTestCondition (
        [string]$manifest.candidate_set.repository_relative_path -ceq
            "target/candidates/$identity"
    ) 'manifest relative candidate-set path mismatch'
    Assert-SelfTestCondition (
        [string]$manifest.candidate_set.root_identity -cmatch
            '^win:[0-9a-f]{8}:[0-9a-f]{16}$' -and
        [string]$manifest.candidate_set.owner_token -cmatch '^[0-9a-f]{64}$'
    ) 'manifest does not bind candidate root identity and random owner token'
    Assert-SelfTestCondition (
        [string]$manifest.source.repository_absolute_path -ceq $script:Repository -and
        [string]$manifest.source.repository_relative_identity -ceq '.'
    ) 'manifest absolute/relative source identity mismatch'
    Assert-SelfTestCondition (
        [bool]$manifest.build.cargo_target_separate_from_candidate_set
    ) 'manifest does not assert Cargo target separation'
    Assert-SelfTestCondition (
        [string]$manifest.build.working_directory_absolute_path -ceq
            $script:Repository -and
        [string]$manifest.build.manifest_absolute_path -match
            'target[\\/]candidate-sources[\\/].*[\\/]Cargo.toml$'
    ) 'manifest does not bind Cargo cwd and detached manifest path'
    foreach ($toolName in @('git', 'cargo', 'rustc', 'rustdoc')) {
        $tool = $manifest.tools.$toolName
        Assert-SelfTestCondition (
            [System.IO.Path]::IsPathRooted([string]$tool.absolute_path) -and
            [string]$tool.file_identity -cmatch '^win:[0-9a-f]{8}:[0-9a-f]{16}$' -and
            [long]$tool.size_bytes -gt 0 -and
            [string]$tool.sha256 -cmatch '^[0-9a-f]{64}$' -and
            -not [string]::IsNullOrWhiteSpace([string]$tool.version_line)
        ) "manifest tool identity mismatch for '$toolName'"
    }
    Assert-SelfTestCondition (
        [string]$manifest.build.rustc_executable_absolute_path -ceq $fakeRustc -and
        [string]$manifest.build.rustc_executable_file_identity -cmatch
            '^win:[0-9a-f]{8}:[0-9a-f]{16}$' -and
        [long]$manifest.build.rustc_executable_size_bytes -gt 0 -and
        [string]$manifest.build.rustc_executable_sha256 -cmatch '^[0-9a-f]{64}$' -and
        [string]$manifest.build.rustc_version_verbose -match '^rustc 1\.99\.0 '
    ) 'manifest does not bind the exact rustc toolchain executable'
    Assert-SelfTestCondition (
        [string]$manifest.build.rustdoc_executable_absolute_path -ceq $fakeRustdoc -and
        [string]$manifest.build.rustdoc_executable_file_identity -cmatch
            '^win:[0-9a-f]{8}:[0-9a-f]{16}$' -and
        [long]$manifest.build.rustdoc_executable_size_bytes -gt 0 -and
        [string]$manifest.build.rustdoc_executable_sha256 -cmatch '^[0-9a-f]{64}$' -and
        [string]$manifest.build.rustdoc_version_verbose -match '^rustdoc 1\.99\.0 ' -and
        [string]$manifest.build.toolchain_channel -ceq '1.99.0' -and
        [string]$manifest.build.toolchain_host -ceq 'x86_64-pc-windows-msvc' -and
        [string]$manifest.build.toolchain_manifest_sha256 -cmatch '^[0-9a-f]{64}$' -and
        [string]$manifest.build.linker_binding -ceq 'ambient-unbound'
    ) 'manifest does not bind rustdoc and the pinned toolchain contract'
    Assert-SelfTestCondition (
        [string]$manifest.contracts.ipc -ceq 'IPC v9..=v9' -and
        [string]$manifest.contracts.transfer -ceq 'transfer protocol v1' -and
        [string]$manifest.contracts.vault_storage -ceq
            'vault-storage read=v4..=v5 write=v5'
    ) 'manifest protocol/storage contracts mismatch'
    Assert-SelfTestCondition (@($manifest.artifacts).Count -eq 3) (
        'manifest does not contain exactly three artifacts'
    )
    Assert-SelfTestCondition (
        @(Get-ChildItem -LiteralPath $candidate -Force -File).Count -eq 4 -and
        @(Get-ChildItem -LiteralPath $candidate -Force -Directory).Count -eq 0
    ) 'candidate set does not contain exactly three binaries and one manifest'
    $expectedLines = @{
        'serctl_cli' = "serctl_cli $version (git $($firstHead.Substring(0, 12)); vault-storage read=v4..=v5 write=v5)"
        'serctl_daemon' = "serctl_daemon $version (git $($firstHead.Substring(0, 12)); IPC v9..=v9; vault-storage read=v4..=v5 write=v5)"
        'serctl-xfer' = "serctl-xfer $version (git $($firstHead.Substring(0, 12)); transfer protocol v1)"
    }
    foreach ($artifact in @($manifest.artifacts)) {
        $component = [string]$artifact.component
        Assert-SelfTestCondition $expectedLines.ContainsKey($component) (
            "manifest contains unexpected component '$component'"
        )
        Assert-SelfTestCondition (
            [string]$artifact.version_line -ceq $expectedLines[$component]
        ) "manifest version line mismatch for '$component'"
        $artifactPath = [string]$artifact.absolute_path
        $expectedArtifactPath = Join-Path $candidate ([string]$artifact.file_name)
        Assert-SelfTestCondition ($artifactPath -ceq $expectedArtifactPath) (
            "manifest absolute artifact identity mismatch for '$component'"
        )
        Assert-SelfTestCondition (
            [string]$artifact.repository_relative_path -ceq
                "target/candidates/$identity/$([string]$artifact.file_name)"
        ) "manifest relative artifact identity mismatch for '$component'"
        Assert-SelfTestCondition (
            [string]$artifact.file_identity -cmatch
                '^win:[0-9a-f]{8}:[0-9a-f]{16}$'
        ) "manifest file identity mismatch for '$component'"
        $expectedMode = if ($hostIsWindows) { 'windows-executable' } else { '0755' }
        Assert-SelfTestCondition (
            [string]$artifact.runtime_mode -ceq $expectedMode
        ) "manifest runtime mode mismatch for '$component'"
        Assert-SelfTestCondition (Test-Path -LiteralPath $artifactPath -PathType Leaf) (
            "manifest artifact is missing for '$component'"
        )
        $item = Get-Item -LiteralPath $artifactPath -Force
        Assert-SelfTestCondition ([long]$artifact.size_bytes -eq [long]$item.Length) (
            "manifest size mismatch for '$component'"
        )
        Assert-SelfTestCondition (
            [string]$artifact.sha256 -ceq (
                Get-FileHash -LiteralPath $artifactPath -Algorithm SHA256
            ).Hash.ToLowerInvariant()
        ) "manifest SHA-256 mismatch for '$component'"
        if (-not $hostIsWindows) {
            $actualVersion = @(& $artifactPath '--version')
            Assert-SelfTestCondition (
                $LASTEXITCODE -eq 0 -and
                $actualVersion.Count -eq 1 -and
                [string]$actualVersion[0] -ceq $expectedLines[$component]
            ) "published Unix artifact is not executable for '$component'"
        }
    }
    Assert-SelfTestCondition (
        @([System.IO.File]::ReadAllLines($buildCount)).Count -eq 1
    ) 'positive fixture did not invoke exactly one build'
    Assert-DirectoryEmpty `
        -Path (Join-Path $script:Repository 'target/candidate-builds') `
        -Description 'private Cargo target parent'
    Assert-DirectoryEmpty `
        -Path (Join-Path $script:Repository 'target/candidate-staging') `
        -Description 'candidate staging parent'
    Assert-DirectoryEmpty `
        -Path (Join-Path $script:Repository 'target/candidate-sources') `
        -Description 'detached source worktree parent'

    Invoke-ExpectedCandidateFailure `
        -Description 'duplicate candidate identity' `
        -ExpectedMessage 'refusing to overwrite existing candidate set' `
        -Action {
            & $builder `
                -Version $version `
                -RepositoryRoot $script:Repository `
                -CargoExecutable $fakeCargo
        }
    Assert-SelfTestCondition (
        @([System.IO.File]::ReadAllLines($buildCount)).Count -eq 1
    ) 'duplicate candidate rejection invoked Cargo'

    [System.Environment]::SetEnvironmentVariable(
        'GIT_DIR',
        'redirected-fixture-git-directory',
        'Process'
    )
    try {
        Invoke-ExpectedCandidateFailure `
            -Description 'Git repository redirection' `
            -ExpectedMessage "Git repository override 'GIT_DIR' must be unset" `
            -Action {
                & $builder `
                    -Version $version `
                    -RepositoryRoot $script:Repository `
                    -CargoExecutable $fakeCargo
            }
    }
    finally {
        Restore-ProcessEnvironmentVariable `
            -Name 'GIT_DIR' `
            -Value $savedGitDirectory
    }
    Assert-SelfTestCondition (
        @([System.IO.File]::ReadAllLines($buildCount)).Count -eq 1
    ) 'Git redirection rejection invoked Cargo'

    Write-Utf8NoBom -Path (Join-Path $script:Repository 'README.md') -Content "dirty`n"
    Invoke-ExpectedCandidateFailure `
        -Description 'dirty source checkout' `
        -ExpectedMessage 'source checkout is not clean' `
        -Action {
            & $builder `
                -Version $version `
                -RepositoryRoot $script:Repository `
                -CargoExecutable $fakeCargo
        }
    Assert-SelfTestCondition (
        @([System.IO.File]::ReadAllLines($buildCount)).Count -eq 1
    ) 'dirty source rejection invoked Cargo'

    Write-Utf8NoBom -Path (Join-Path $script:Repository 'README.md') -Content "fixture-two`n"
    Invoke-FixtureGit @('add', '--all')
    Invoke-FixtureGit @('commit', '--quiet', '-m', 'second clean fixture source')
    $secondHead = Get-FixtureHead
    [System.Environment]::SetEnvironmentVariable(
        'SERCTL_FIXTURE_COMMIT', $secondHead, 'Process'
    )
    [System.Environment]::SetEnvironmentVariable(
        'SERCTL_FIXTURE_BAD_DAEMON', '1', 'Process'
    )
    $nonEmptyCargoTarget = Join-Path $script:SelfTestRoot 'preserved-cargo-target'
    [System.Environment]::SetEnvironmentVariable(
        'CARGO_TARGET_DIR',
        $nonEmptyCargoTarget,
        'Process'
    )
    Invoke-ExpectedCandidateFailure `
        -Description 'wrong daemon protocol identity' `
        -ExpectedMessage 'does not report the exact clean candidate identity' `
        -Action {
            & $builder `
                -Version $version `
                -RepositoryRoot $script:Repository `
                -CargoExecutable $fakeCargo
        }
    $failedIdentity = "v$version-$($secondHead.Substring(0, 12))"
    Assert-SelfTestCondition (-not (Test-Path -LiteralPath (
        Join-Path $script:Repository "target/candidates/$failedIdentity"
    ))) 'wrong-identity fixture published a candidate set'
    Assert-SelfTestCondition (
        @([System.IO.File]::ReadAllLines($buildCount)).Count -eq 2
    ) 'wrong-identity fixture build count mismatch'
    Assert-SelfTestCondition (
        (Test-Path -LiteralPath Env:CARGO_TARGET_DIR) -and
        [System.Environment]::GetEnvironmentVariable(
            'CARGO_TARGET_DIR',
            'Process'
        ) -ceq $nonEmptyCargoTarget
    ) 'failed builder did not restore the exact nonempty CARGO_TARGET_DIR'
    Assert-DirectoryEmpty `
        -Path (Join-Path $script:Repository 'target/candidate-builds') `
        -Description 'failed private Cargo target parent'
    Assert-DirectoryEmpty `
        -Path (Join-Path $script:Repository 'target/candidate-staging') `
        -Description 'failed candidate staging parent'

    Write-Utf8NoBom `
        -Path (Join-Path $script:Repository 'README.md') `
        -Content "fixture-three`n"
    Invoke-FixtureGit @('add', '--all')
    Invoke-FixtureGit @('commit', '--quiet', '-m', 'third clean fixture source')
    $thirdHead = Get-FixtureHead
    [System.Environment]::SetEnvironmentVariable(
        'SERCTL_FIXTURE_COMMIT', $thirdHead, 'Process'
    )
    [System.Environment]::SetEnvironmentVariable(
        'SERCTL_FIXTURE_BAD_DAEMON', '0', 'Process'
    )
    Set-Item -LiteralPath Env:CARGO_TARGET_DIR -Value ''
    $emptyEnvironmentRepresentable = Test-Path -LiteralPath Env:CARGO_TARGET_DIR
    if ($emptyEnvironmentRepresentable) {
        Assert-SelfTestCondition ([string]::IsNullOrEmpty(
            [System.Environment]::GetEnvironmentVariable(
                'CARGO_TARGET_DIR',
                'Process'
            )
        )) 'empty CARGO_TARGET_DIR precondition has a nonempty value'
    }
    else {
        Assert-SelfTestCondition (
            $hostIsWindows -and $PSVersionTable.PSEdition -ceq 'Desktop'
        ) (
            'only Windows PowerShell 5.1 may normalize an empty environment ' +
            'entry to absence before invocation'
        )
    }
    & $builder `
        -Version $version `
        -RepositoryRoot $script:Repository `
        -CargoExecutable $fakeCargo *> $null
    Assert-SelfTestCondition (-not (Test-Path -LiteralPath Env:CARGO_TARGET_DIR)) (
        'builder did not remove an originally empty CARGO_TARGET_DIR'
    )
    Assert-SubsequentCargoWorks -Description 'empty CARGO_TARGET_DIR normalization'
    $thirdIdentity = "v$version-$($thirdHead.Substring(0, 12))"
    Assert-SelfTestCondition (Test-Path -LiteralPath (
        Join-Path $script:Repository "target/candidates/$thirdIdentity/candidate-manifest.json"
    ) -PathType Leaf) 'empty-environment fixture did not publish its candidate'
    Assert-SelfTestCondition (
        @([System.IO.File]::ReadAllLines($buildCount)).Count -eq 3
    ) 'three-state environment fixture build count mismatch'
    Assert-SelfTestCondition (
        -not (Get-ChildItem `
            -LiteralPath (Join-Path $script:Repository 'target/candidate-builds') `
            -Force `
            -ErrorAction SilentlyContinue)
    ) 'ignored target event storm leaked its private build root'

    Write-Utf8NoBom `
        -Path (Join-Path $script:Repository 'README.md') `
        -Content "fixture-command-negative`n"
    Invoke-FixtureGit @('add', '--all')
    Invoke-FixtureGit @('commit', '--quiet', '-m', 'command negative fixture')
    $commandNegativeHead = Get-FixtureHead
    [System.Environment]::SetEnvironmentVariable(
        'SERCTL_FIXTURE_COMMIT', $commandNegativeHead, 'Process'
    )
    Invoke-ExpectedCandidateFailure `
        -Description 'Cargo wildcard command resolution' `
        -ExpectedMessage 'cargo command contains wildcard characters' `
        -Action {
            & $builder `
                -Version $version `
                -RepositoryRoot $script:Repository `
                -CargoExecutable '*cargo*'
        }
    $shadowDirectory = Join-Path $script:Repository 'target/command-shadow'
    [System.IO.Directory]::CreateDirectory($shadowDirectory) | Out-Null
    $shadowCargo = Join-Path $shadowDirectory "cargo$executableSuffix"
    [System.IO.File]::Copy($fakeCargo, $shadowCargo, $false)
    $savedPath = [System.Environment]::GetEnvironmentVariable('PATH', 'Process')
    [System.Environment]::SetEnvironmentVariable(
        'PATH',
        $shadowDirectory + [System.IO.Path]::PathSeparator + $savedPath,
        'Process'
    )
    try {
        Invoke-ExpectedCandidateFailure `
            -Description 'Cargo command shadow' `
            -ExpectedMessage 'cargo command is shadowed from inside the source repository' `
            -Action {
                & $builder `
                    -Version $version `
                    -RepositoryRoot $script:Repository `
                    -CargoExecutable 'cargo'
            }
    }
    finally {
        [System.Environment]::SetEnvironmentVariable('PATH', $savedPath, 'Process')
        [System.IO.Directory]::Delete($shadowDirectory, $true)
    }
    Assert-SelfTestCondition (
        @([System.IO.File]::ReadAllLines($buildCount)).Count -eq 3
    ) 'wildcard or command-shadow rejection invoked Cargo'

    Write-Utf8NoBom `
        -Path (Join-Path $script:Repository 'README.md') `
        -Content "fixture-source-mutation`n"
    Invoke-FixtureGit @('add', '--all')
    Invoke-FixtureGit @('commit', '--quiet', '-m', 'source mutation fixture')
    $mutationHead = Get-FixtureHead
    [System.Environment]::SetEnvironmentVariable(
        'SERCTL_FIXTURE_COMMIT', $mutationHead, 'Process'
    )
    [System.Environment]::SetEnvironmentVariable(
        'SERCTL_FIXTURE_MUTATE_SOURCE', '1', 'Process'
    )
    try {
        Invoke-ExpectedCandidateFailure `
            -Description 'tracked source changed and restored during build' `
            -ExpectedMessage 'tracked source changed during the build' `
            -Action {
                & $builder `
                    -Version $version `
                    -RepositoryRoot $script:Repository `
                    -CargoExecutable $fakeCargo
            }
    }
    finally {
        [System.Environment]::SetEnvironmentVariable(
            'SERCTL_FIXTURE_MUTATE_SOURCE', '0', 'Process'
        )
    }
    Assert-SelfTestCondition (
        @([System.IO.File]::ReadAllLines($buildCount)).Count -eq 4
    ) 'source-mutation fixture build count mismatch'
    Assert-DirectoryEmpty `
        -Path (Join-Path $script:Repository 'target/candidate-sources') `
        -Description 'source-mutation detached worktree parent'
    Assert-DirectoryEmpty `
        -Path (Join-Path $script:Repository 'target/candidate-builds') `
        -Description 'source-mutation private Cargo target parent'
    Assert-DirectoryEmpty `
        -Path (Join-Path $script:Repository 'target/candidate-staging') `
        -Description 'source-mutation candidate staging parent'

    Write-Utf8NoBom `
        -Path (Join-Path $script:Repository 'README.md') `
        -Content "fixture-four`n"
    Invoke-FixtureGit @('add', '--all')
    Invoke-FixtureGit @('commit', '--quiet', '-m', 'fourth clean fixture source')
    $fourthHead = Get-FixtureHead
    [System.Environment]::SetEnvironmentVariable(
        'SERCTL_FIXTURE_COMMIT', $fourthHead, 'Process'
    )
    Invoke-ExpectedCandidateFailure `
        -Description 'staged artifact replacement' `
        -ExpectedMessage 'was replaced after validation' `
        -Action {
            & $builder `
                -Version $version `
                -RepositoryRoot $script:Repository `
                -CargoExecutable $fakeCargo `
                -SelfTestMutation 'replace-stage-artifact'
        }
    $fourthIdentity = "v$version-$($fourthHead.Substring(0, 12))"
    Assert-SelfTestCondition (-not (Test-Path -LiteralPath (
        Join-Path $script:Repository "target/candidates/$fourthIdentity"
    ))) 'replacement fixture published a candidate set'
    Assert-SelfTestCondition (
        @([System.IO.File]::ReadAllLines($buildCount)).Count -eq 5
    ) 'replacement fixture build count mismatch'
    Assert-DirectoryEmpty `
        -Path (Join-Path $script:Repository 'target/candidate-builds') `
        -Description 'replacement private Cargo target parent'
    Assert-DirectoryEmpty `
        -Path (Join-Path $script:Repository 'target/candidate-staging') `
        -Description 'replacement candidate staging parent'

    Write-Utf8NoBom `
        -Path (Join-Path $script:Repository 'README.md') `
        -Content "fixture-five`n"
    Invoke-FixtureGit @('add', '--all')
    Invoke-FixtureGit @('commit', '--quiet', '-m', 'fifth clean fixture source')
    $fifthHead = Get-FixtureHead
    [System.Environment]::SetEnvironmentVariable(
        'SERCTL_FIXTURE_COMMIT', $fifthHead, 'Process'
    )
    $stagingParentPath = Join-Path $script:Repository 'target/candidate-staging'
    $junctionTarget = Join-Path $script:SelfTestRoot 'junction-target'
    [System.IO.Directory]::CreateDirectory($junctionTarget) | Out-Null
    $junctionSentinel = Join-Path $junctionTarget 'sentinel.txt'
    Write-Utf8NoBom -Path $junctionSentinel -Content "junction-sentinel`n"
    [System.IO.Directory]::Delete($stagingParentPath, $false)
    New-Item `
        -ItemType Junction `
        -Path $stagingParentPath `
        -Target $junctionTarget `
        -ErrorAction Stop | Out-Null
    try {
        Invoke-ExpectedCandidateFailure `
            -Description 'candidate staging parent junction' `
            -ExpectedMessage 'candidate staging parent is a symbolic link or reparse point' `
            -Action {
                & $builder `
                    -Version $version `
                    -RepositoryRoot $script:Repository `
                    -CargoExecutable $fakeCargo
            }
    }
    finally {
        [System.IO.Directory]::Delete($stagingParentPath, $false)
        [System.IO.Directory]::CreateDirectory($stagingParentPath) | Out-Null
    }
    Assert-SelfTestCondition (
        [System.IO.File]::ReadAllText($junctionSentinel) -ceq "junction-sentinel`n"
    ) 'junction rejection touched the external target'
    Assert-SelfTestCondition (
        @([System.IO.File]::ReadAllLines($buildCount)).Count -eq 5
    ) 'junction rejection invoked Cargo'

    Write-Utf8NoBom `
        -Path (Join-Path $script:Repository 'README.md') `
        -Content "fixture-six`n"
    Invoke-FixtureGit @('add', '--all')
    Invoke-FixtureGit @('commit', '--quiet', '-m', 'sixth clean fixture source')
    $sixthHead = Get-FixtureHead
    [System.Environment]::SetEnvironmentVariable(
        'SERCTL_FIXTURE_COMMIT', $sixthHead, 'Process'
    )
    [System.Environment]::SetEnvironmentVariable(
        'SERCTL_FIXTURE_TAMPER_BUILD_OWNER', '1', 'Process'
    )
    Invoke-ExpectedCandidateFailure `
        -Description 'private build cleanup ownership mismatch' `
        -ExpectedMessage 'owner token changed' `
        -Action {
            & $builder `
                -Version $version `
                -RepositoryRoot $script:Repository `
                -CargoExecutable $fakeCargo
        }
    [System.Environment]::SetEnvironmentVariable(
        'SERCTL_FIXTURE_TAMPER_BUILD_OWNER', '0', 'Process'
    )
    $sixthIdentity = "v$version-$($sixthHead.Substring(0, 12))"
    Assert-SelfTestCondition (-not (Test-Path -LiteralPath (
        Join-Path $script:Repository "target/candidates/$sixthIdentity"
    ))) 'cleanup ownership fixture published a candidate set'
    Assert-SelfTestCondition (
        @([System.IO.File]::ReadAllLines($buildCount)).Count -eq 6
    ) 'cleanup ownership fixture build count mismatch'
    $preservedBuildRoots = @(Get-ChildItem `
        -LiteralPath (Join-Path $script:Repository 'target/candidate-builds') `
        -Force `
        -Directory)
    Assert-SelfTestCondition ($preservedBuildRoots.Count -eq 1) (
        'ownership mismatch did not preserve exactly one untrusted build root'
    )
    Assert-SelfTestCondition (
        [System.IO.File]::ReadAllText((
            Join-Path $preservedBuildRoots[0].FullName '.serctl-candidate-owner'
        )) -ceq 'tampered-owner'
    ) 'ownership mismatch deleted or changed the untrusted build root'
    Assert-DirectoryEmpty `
        -Path (Join-Path $script:Repository 'target/candidate-staging') `
        -Description 'ownership mismatch candidate staging parent'

    Assert-SentinelUnchanged `
        -Path $releaseSentinel `
        -ExpectedHash $releaseHash `
        -ExpectedWriteTime $releaseWriteTime `
        -Description 'target/release'
    Assert-SentinelUnchanged `
        -Path $predecessorSentinel `
        -ExpectedHash $predecessorHash `
        -ExpectedWriteTime $predecessorWriteTime `
        -Description 'target/staging-v0.3'
}
finally {
    [System.Environment]::SetEnvironmentVariable(
        'SERCTL_FIXTURE_BINARY', $savedFixtureBinary, 'Process'
    )
    [System.Environment]::SetEnvironmentVariable(
        'SERCTL_FIXTURE_VERSION', $savedFixtureVersion, 'Process'
    )
    [System.Environment]::SetEnvironmentVariable(
        'SERCTL_FIXTURE_COMMIT', $savedFixtureCommit, 'Process'
    )
    [System.Environment]::SetEnvironmentVariable(
        'SERCTL_FIXTURE_BAD_DAEMON', $savedBadDaemon, 'Process'
    )
    [System.Environment]::SetEnvironmentVariable(
        'SERCTL_FIXTURE_BUILD_COUNT', $savedBuildCount, 'Process'
    )
    [System.Environment]::SetEnvironmentVariable(
        'SERCTL_FIXTURE_SUFFIX', $savedFixtureSuffix, 'Process'
    )
    Restore-ProcessEnvironmentVariable `
        -Name 'SERCTL_ISOLATED_CANDIDATE_SELFTEST' `
        -Value $savedSelfTestMode
    Restore-ProcessEnvironmentVariable `
        -Name 'SERCTL_FIXTURE_TAMPER_BUILD_OWNER' `
        -Value $savedTamperBuildOwner
    Restore-ProcessEnvironmentVariable `
        -Name 'SERCTL_FIXTURE_EXPECTED_CWD' `
        -Value $savedExpectedCwd
    Restore-ProcessEnvironmentVariable `
        -Name 'SERCTL_FIXTURE_EXPECTED_RUSTC' `
        -Value $savedExpectedRustc
    Restore-ProcessEnvironmentVariable `
        -Name 'SERCTL_FIXTURE_EXPECTED_RUSTDOC' `
        -Value $savedExpectedRustdoc
    Restore-ProcessEnvironmentVariable `
        -Name 'SERCTL_FIXTURE_MUTATE_SOURCE' `
        -Value $savedMutateSource
    Restore-ProcessEnvironmentVariable `
        -Name 'SERCTL_FIXTURE_IGNORED_EVENT_STORM' `
        -Value $savedIgnoredEventStorm
    Restore-ProcessEnvironmentVariable `
        -Name 'GIT_DIR' `
        -Value $savedGitDirectory
    Restore-ProcessEnvironmentVariable `
        -Name 'CARGO_TARGET_DIR' `
        -Value $savedCargoTarget
    if ([System.IO.Directory]::Exists($selfTestFullPath)) {
        Assert-SelfTestCondition (
            $selfTestFullPath.StartsWith(
                $selfTestPrefix,
                $pathComparison
            ) -and
            [System.IO.Path]::GetFileName($selfTestFullPath).StartsWith(
                'ic-',
                [System.StringComparison]::Ordinal
            )
        ) 'refusing to clean a fixture outside the dedicated self-test parent'
        foreach ($file in [System.IO.Directory]::EnumerateFiles(
            $selfTestFullPath,
            '*',
            [System.IO.SearchOption]::AllDirectories
        )) {
            [System.IO.File]::SetAttributes($file, [System.IO.FileAttributes]::Normal)
        }
        [System.IO.Directory]::Delete($selfTestFullPath, $true)
    }
}

Write-Host 'Isolated candidate Windows PS7/Windows PowerShell 5.1 self-test passed.'
