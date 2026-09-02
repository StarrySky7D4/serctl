[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Tag,

    [switch]$AllowLeadingUnreleased,

    [string]$ExpectedUnreleasedTag,

    [switch]$RequireGitTag,

    [string]$GithubOutput
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Fail-ReleaseConsistency {
    param([Parameter(Mandatory = $true)][string]$Message)
    throw "release consistency check failed: $Message"
}

function Assert-ReleaseCondition {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if (-not $Condition) {
        Fail-ReleaseConsistency $Message
    }
}

function Read-WorkspaceVersion {
    param([Parameter(Mandatory = $true)][string]$ManifestPath)

    $manifest = Get-Content -LiteralPath $ManifestPath -Raw -Encoding utf8
    $section = [regex]::Match(
        $manifest,
        '(?ms)^\[workspace\.package\]\s*(?<body>.*?)(?=^\[|\z)',
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
    Assert-ReleaseCondition $section.Success 'Cargo.toml has no [workspace.package] section'

    $version = [regex]::Match(
        $section.Groups['body'].Value,
        '(?m)^version\s*=\s*"(?<version>[^"]+)"\s*$',
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
    Assert-ReleaseCondition $version.Success 'Cargo.toml has no workspace package version'
    return $version.Groups['version'].Value
}

function Read-LockPackages {
    param([Parameter(Mandatory = $true)][string]$LockPath)

    $packages = [System.Collections.Generic.List[object]]::new()
    $name = $null
    $version = $null
    foreach ($line in Get-Content -LiteralPath $LockPath -Encoding utf8) {
        if ($line -eq '[[package]]') {
            if ($null -ne $name) {
                $packages.Add([pscustomobject]@{ Name = $name; Version = $version })
            }
            $name = $null
            $version = $null
            continue
        }
        if ($line -match '^name = "([^"]+)"$') {
            $name = $Matches[1]
            continue
        }
        if ($line -match '^version = "([^"]+)"$') {
            $version = $Matches[1]
        }
    }
    if ($null -ne $name) {
        $packages.Add([pscustomobject]@{ Name = $name; Version = $version })
    }
    return $packages
}

$tagMatch = [regex]::Match(
    $Tag,
    '^v(?<version>(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)-(?:alpha|beta|rc)(?:\.[1-9][0-9]*)?)$',
    [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
)
Assert-ReleaseCondition $tagMatch.Success (
    "tag '$Tag' is not a canonical prerelease tag such as v1.0.0-beta or v1.0.0-beta.1"
)
Assert-ReleaseCondition (-not ($AllowLeadingUnreleased -and $RequireGitTag)) (
    'AllowLeadingUnreleased is a development-tree check and cannot verify a Git tag'
)
if ($AllowLeadingUnreleased) {
    $expectedUnreleasedMatch = [regex]::Match(
        $ExpectedUnreleasedTag,
        '^v(?<version>(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)-(?:alpha|beta|rc)(?:\.[1-9][0-9]*)?)$',
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
    Assert-ReleaseCondition $expectedUnreleasedMatch.Success (
        'AllowLeadingUnreleased requires ExpectedUnreleasedTag as one canonical prerelease tag'
    )
    Assert-ReleaseCondition ($ExpectedUnreleasedTag -cne $Tag) (
        'the expected development candidate must differ from the frozen release tag'
    )
}
else {
    Assert-ReleaseCondition ([string]::IsNullOrWhiteSpace($ExpectedUnreleasedTag)) (
        'ExpectedUnreleasedTag is valid only with AllowLeadingUnreleased'
    )
}
$releaseVersion = $tagMatch.Groups['version'].Value
$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$resolvedRepositoryRoot = [System.IO.Path]::GetFullPath(
    (Resolve-Path -LiteralPath $repositoryRoot).ProviderPath
)

Push-Location -LiteralPath $repositoryRoot
try {
    $workspaceVersion = Read-WorkspaceVersion (Join-Path $repositoryRoot 'Cargo.toml')
    Assert-ReleaseCondition ($workspaceVersion -ceq $releaseVersion) (
        "tag version '$releaseVersion' does not equal workspace version '$workspaceVersion'"
    )

    $metadataJson = & cargo metadata --quiet --locked --no-deps --format-version 1
    Assert-ReleaseCondition ($LASTEXITCODE -eq 0) 'cargo metadata --locked failed'
    $metadata = $metadataJson | ConvertFrom-Json
    $workspacePackages = @(
        $metadata.packages | Where-Object { $metadata.workspace_members -contains $_.id }
    )
    Assert-ReleaseCondition ($workspacePackages.Count -gt 0) 'cargo metadata returned no workspace packages'

    $workspaceNames = @{}
    foreach ($package in $workspacePackages) {
        Assert-ReleaseCondition ([string]$package.version -ceq $releaseVersion) (
            "workspace package '$($package.name)' has version '$($package.version)', expected '$releaseVersion'"
        )
        Assert-ReleaseCondition (-not $workspaceNames.ContainsKey([string]$package.name)) (
            "workspace contains duplicate package name '$($package.name)'"
        )
        $workspaceNames[[string]$package.name] = $true
    }

    # Internal crates are release-locked as an exact set. A caret requirement
    # would allow a future compatible version to be selected when a crate is
    # consumed outside this workspace, defeating the matched-component rule.
    $expectedRequirement = "=$releaseVersion"
    $rootPrefix = $resolvedRepositoryRoot.TrimEnd(
        [System.IO.Path]::DirectorySeparatorChar
    ) + [System.IO.Path]::DirectorySeparatorChar
    $isWindowsPlatform = [System.IO.Path]::DirectorySeparatorChar -eq '\'
    $pathComparison = if ($isWindowsPlatform) {
        [System.StringComparison]::OrdinalIgnoreCase
    }
    else {
        [System.StringComparison]::Ordinal
    }
    foreach ($package in $workspacePackages) {
        $duplicateDependencyGroups = @(
            $package.dependencies |
                Group-Object -Property name |
                Where-Object { $_.Count -gt 1 }
        )
        foreach ($group in $duplicateDependencyGroups) {
            $entries = @($group.Group)
            $normalEntries = @($entries | Where-Object { $null -eq $_.kind })
            $devEntries = @($entries | Where-Object { [string]$_.kind -ceq 'dev' })
            $allowedTestSupportSplit = (
                ([string]$package.name -ceq 'serctl-cli' -or
                    [string]$package.name -ceq 'serctl-daemon') -and
                [string]$group.Name -ceq 'serctl-core' -and
                $entries.Count -eq 2 -and
                $normalEntries.Count -eq 1 -and
                $devEntries.Count -eq 1 -and
                @($normalEntries[0].features).Count -eq 0 -and
                @($devEntries[0].features).Count -eq 1 -and
                [string]$devEntries[0].features[0] -ceq 'test-support' -and
                [string]$normalEntries[0].req -ceq [string]$devEntries[0].req -and
                [string]$normalEntries[0].path -ceq [string]$devEntries[0].path
            )
            Assert-ReleaseCondition $allowedTestSupportSplit (
                "package '$($package.name)' declares duplicate direct dependency " +
                "'$($group.Name)' outside the audited normal/dev test-support split"
            )
        }

        foreach ($dependency in $package.dependencies) {
            $pathProperty = $dependency.PSObject.Properties['path']
            if ($null -eq $pathProperty -or $null -eq $pathProperty.Value) {
                continue
            }
            $dependencyPath = [System.IO.Path]::GetFullPath(
                (Resolve-Path -LiteralPath ([string]$pathProperty.Value)).ProviderPath
            )
            Assert-ReleaseCondition (
                $dependencyPath.StartsWith($rootPrefix, $pathComparison)
            ) "package '$($package.name)' has an external path dependency '$dependencyPath'"
            Assert-ReleaseCondition ($workspaceNames.ContainsKey([string]$dependency.name)) (
                "package '$($package.name)' path-depends on non-workspace package '$($dependency.name)'"
            )
            Assert-ReleaseCondition ([string]$dependency.req -ceq $expectedRequirement) (
                "package '$($package.name)' requires internal '$($dependency.name)' as '$($dependency.req)', expected exact '$expectedRequirement'"
            )
        }
    }

    $lockPackages = @(Read-LockPackages (Join-Path $repositoryRoot 'Cargo.lock'))
    foreach ($package in $workspacePackages) {
        $nameMatches = @(
            $lockPackages | Where-Object { $_.Name -ceq [string]$package.name }
        )
        Assert-ReleaseCondition ($nameMatches.Count -eq 1) (
            "Cargo.lock must contain exactly one package named '$($package.name)'; found $($nameMatches.Count)"
        )
        Assert-ReleaseCondition ($nameMatches[0].Version -ceq $releaseVersion) (
            "Cargo.lock package '$($package.name)' has version '$($nameMatches[0].Version)', expected '$releaseVersion'"
        )
    }

    $fuzzManifest = Get-Content -LiteralPath (Join-Path $repositoryRoot 'fuzz/Cargo.toml') -Raw -Encoding utf8
    $fuzzWorkspaceNames = @([regex]::Matches(
        $fuzzManifest,
        '(?m)^(?<name>serctl-[a-z0-9-]+)\s*=\s*\{[^\r\n]*\bpath\s*=',
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    ) | ForEach-Object { $_.Groups['name'].Value } | Sort-Object -Unique)
    Assert-ReleaseCondition ($fuzzWorkspaceNames.Count -gt 0) 'fuzz/Cargo.toml has no internal path dependencies'
    $fuzzLockPackages = @(Read-LockPackages (Join-Path $repositoryRoot 'fuzz/Cargo.lock'))
    foreach ($name in $fuzzWorkspaceNames) {
        Assert-ReleaseCondition ($workspaceNames.ContainsKey($name)) (
            "fuzz/Cargo.toml path-depends on non-workspace package '$name'"
        )
        $nameMatches = @($fuzzLockPackages | Where-Object { $_.Name -ceq $name })
        Assert-ReleaseCondition ($nameMatches.Count -eq 1) (
            "fuzz/Cargo.lock must contain exactly one package named '$name'; found $($nameMatches.Count)"
        )
        Assert-ReleaseCondition ($nameMatches[0].Version -ceq $releaseVersion) (
            "fuzz/Cargo.lock package '$name' has version '$($nameMatches[0].Version)', expected '$releaseVersion'"
        )
    }

    $escapedVersion = [regex]::Escape($releaseVersion)
    $architectureMarker = if ($releaseVersion -match '^1\.0\.0-beta(?:\.|$)') {
        @{
            Pattern = "data-release-candidate=`"v$escapedVersion`""
            MarkerPattern = 'data-release-candidate="[^"]+"'
            Description = 'the v1 architecture candidate marker'
        }
    }
    else {
        @{
            Pattern = "data-release-predecessor=`"v$escapedVersion`""
            MarkerPattern = 'data-release-predecessor="[^"]+"'
            Description = 'the predecessor architecture marker'
        }
    }
    $documentChecks = @(
        @{
            Path = 'CHANGELOG.md'
            Pattern = "(?m)^## v$escapedVersion\s+-\s+\d{4}-\d{2}-\d{2}\s*$"
            Description = 'a dated top-level release heading'
        },
        @{
            Path = 'README.md'
            Pattern = "<!-- release-marker: v$escapedVersion -->"
            MarkerPattern = '(?m)<!--\s*release-marker:\s*[^\s]+\s*-->'
            Description = 'the current prerelease marker'
        },
        @{
            Path = 'docs/serctl-user-guide.md'
            Pattern = "<!-- applicable-version: v$escapedVersion -->"
            MarkerPattern = '(?m)<!--\s*applicable-version:\s*[^\s]+\s*-->'
            Description = 'the user-guide applicable version'
        },
        @{
            Path = 'docs/serctl-architecture-security.html'
            Pattern = $architectureMarker.Pattern
            MarkerPattern = $architectureMarker.MarkerPattern
            Description = $architectureMarker.Description
        }
    )
    foreach ($check in $documentChecks) {
        $path = Join-Path $repositoryRoot $check.Path
        Assert-ReleaseCondition (Test-Path -LiteralPath $path -PathType Leaf) (
            "required release document '$($check.Path)' is missing"
        )
        $content = Get-Content -LiteralPath $path -Raw -Encoding utf8
        Assert-ReleaseCondition ([regex]::IsMatch(
            $content,
            $check.Pattern,
            [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
        )) "'$($check.Path)' does not contain $($check.Description) for v$releaseVersion"
        if ($check.ContainsKey('MarkerPattern')) {
            $markers = [regex]::Matches(
                $content,
                $check.MarkerPattern,
                [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
            )
            Assert-ReleaseCondition ($markers.Count -eq 1) (
                "'$($check.Path)' must contain exactly one release identity marker; found $($markers.Count)"
            )
        }
    }
    $changelogContent = Get-Content -LiteralPath (
        Join-Path $repositoryRoot 'CHANGELOG.md'
    ) -Raw -Encoding utf8
    $changelogEntries = [regex]::Matches(
        $changelogContent,
        '(?m)^##\s+(?<entry>[^\r\n]+)$',
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
    Assert-ReleaseCondition ($changelogEntries.Count -gt 0) 'CHANGELOG.md has no release entry'

    # A development-tree self-test may explicitly allow exactly one future
    # candidate at the top as `Unreleased`, followed by the dated entry for the
    # version still declared by Cargo. The default and tagged-release paths are
    # intentionally stricter, so current main cannot re-validate an old tag.
    $releaseEntryIndex = 0
    $canonicalPrerelease = (
        '(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)-' +
        '(?:alpha|beta|rc)(?:\.[1-9][0-9]*)?'
    )
    $firstEntry = $changelogEntries[0].Groups['entry'].Value
    $unreleasedEntry = [regex]::Match(
        $firstEntry,
        '^v(?<version>' + $canonicalPrerelease + ')\s+-\s+Unreleased$',
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
    if ($unreleasedEntry.Success) {
        Assert-ReleaseCondition $AllowLeadingUnreleased (
            'CHANGELOG.md must start with the dated release entry unless AllowLeadingUnreleased is explicit'
        )
        Assert-ReleaseCondition (
            $unreleasedEntry.Groups['version'].Value -cne $releaseVersion
        ) (
            "the current release v$releaseVersion is still marked Unreleased"
        )
        Assert-ReleaseCondition (
            ('v' + $unreleasedEntry.Groups['version'].Value) -ceq $ExpectedUnreleasedTag
        ) (
            "leading Unreleased entry does not equal expected candidate $ExpectedUnreleasedTag"
        )
        $releaseEntryIndex = 1
    }
    Assert-ReleaseCondition ($changelogEntries.Count -gt $releaseEntryIndex) (
        "CHANGELOG.md has no dated entry for v$releaseVersion"
    )
    for ($index = 1; $index -lt $changelogEntries.Count; $index++) {
        Assert-ReleaseCondition (
            $changelogEntries[$index].Groups['entry'].Value -notmatch '\s+-\s+Unreleased$'
        ) 'only the first CHANGELOG.md release entry may be Unreleased'
    }

    $currentChangelogEntry = $changelogEntries[$releaseEntryIndex]
    Assert-ReleaseCondition (
        $currentChangelogEntry.Groups['entry'].Value -match (
            '^v' + $escapedVersion + '\s+-\s+\d{4}-\d{2}-\d{2}$'
        )
    ) "the first published CHANGELOG.md release entry is not dated v$releaseVersion"

    if ($releaseVersion -match '^1\.0\.0-beta(?:\.|$)') {
        foreach ($path in @(
            'SECURITY.md',
            'docs/v1-beta-agent-jsonl.md',
            'docs/v1-beta-release-contract.md',
            'docs/v1-beta-acceptance-matrix.md'
        )) {
            Assert-ReleaseCondition (Test-Path -LiteralPath (Join-Path $repositoryRoot $path) -PathType Leaf) (
                "v1 beta release governance file '$path' is missing"
            )
        }
        $contract = Get-Content -LiteralPath (
            Join-Path $repositoryRoot 'docs/v1-beta-release-contract.md'
        ) -Raw -Encoding utf8
        $releaseContractMarker = '<!-- release-tag: v{0} -->' -f $releaseVersion
        Assert-ReleaseCondition ($contract.Contains($releaseContractMarker)) (
            "v1 beta release contract is not bound to v$releaseVersion"
        )
        Assert-ReleaseCondition (
            ([regex]::Matches($contract, '<!--\s*release-tag:\s*[^\s]+\s*-->')).Count -eq 1
        ) 'v1 beta release contract must contain exactly one machine release tag marker'
        $agentContract = Get-Content -LiteralPath (
            Join-Path $repositoryRoot 'docs/v1-beta-agent-jsonl.md'
        ) -Raw -Encoding utf8
        $agentContractMarker = '<!-- target-release: v{0} -->' -f $releaseVersion
        Assert-ReleaseCondition ($agentContract.Contains($agentContractMarker)) (
            "v1 beta Agent contract is not bound to v$releaseVersion"
        )
        Assert-ReleaseCondition (
            ([regex]::Matches($agentContract, '<!--\s*target-release:\s*[^\s]+\s*-->')).Count -eq 1
        ) 'v1 beta Agent contract must contain exactly one machine target release marker'
        $securityPolicy = Get-Content -LiteralPath (
            Join-Path $repositoryRoot 'SECURITY.md'
        ) -Raw -Encoding utf8
        $securityReleaseMarker = '| `v{0}` |' -f $releaseVersion
        Assert-ReleaseCondition ($securityPolicy.Contains($securityReleaseMarker)) (
            "SECURITY.md does not list v$releaseVersion as the supported v1 beta line"
        )
        $acceptanceMatrix = Get-Content -LiteralPath (
            Join-Path $repositoryRoot 'docs/v1-beta-acceptance-matrix.md'
        ) -Raw -Encoding utf8
        $acceptanceMarker = '<!-- normative-release: v{0} -->' -f $releaseVersion
        Assert-ReleaseCondition ($acceptanceMatrix.Contains($acceptanceMarker)) (
            "v1 beta acceptance matrix is not bound to v$releaseVersion"
        )
        Assert-ReleaseCondition (
            ([regex]::Matches($acceptanceMatrix, '<!--\s*normative-release:\s*[^\s]+\s*-->')).Count -eq 1
        ) 'v1 beta acceptance matrix must contain exactly one normative release marker'
        & (Join-Path $repositoryRoot 'scripts/Test-V1BetaDocumentation.ps1')
    }

    $verifiedCommit = $null
    $verifiedTagObject = $null
    if ($RequireGitTag) {
        $status = @(& git status --porcelain=v1 --untracked-files=all)
        Assert-ReleaseCondition ($LASTEXITCODE -eq 0) 'git status failed'
        Assert-ReleaseCondition ($status.Count -eq 0) 'tag checkout is not clean'

        $tagReference = "refs/tags/$Tag"
        $tagType = (& git cat-file -t $tagReference).Trim()
        Assert-ReleaseCondition ($LASTEXITCODE -eq 0) "cannot inspect $tagReference"
        Assert-ReleaseCondition ($tagType -ceq 'tag') 'release tag must be an annotated tag object'

        $tagObject = (& git rev-parse $tagReference).Trim().ToLowerInvariant()
        Assert-ReleaseCondition ($LASTEXITCODE -eq 0) "cannot resolve annotated object $tagReference"
        Assert-ReleaseCondition ($tagObject -match '^[0-9a-f]{40}$') (
            "annotated tag object '$tagObject' is not a full SHA-1 object id"
        )

        $tagPayload = @(& git cat-file -p $tagReference)
        Assert-ReleaseCondition ($LASTEXITCODE -eq 0) "cannot read annotated object $tagReference"
        Assert-ReleaseCondition ($tagPayload.Count -ge 3) (
            'annotated release tag has an incomplete object header'
        )
        $tagTargetMatch = [regex]::Match(
            [string]$tagPayload[0],
            '^object (?<object>[0-9a-fA-F]{40})$',
            [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
        )
        Assert-ReleaseCondition $tagTargetMatch.Success (
            'annotated release tag has a noncanonical target object'
        )
        Assert-ReleaseCondition ([string]$tagPayload[1] -ceq 'type commit') (
            'annotated release tag must point directly to a commit, not another tag or object type'
        )
        Assert-ReleaseCondition ([string]$tagPayload[2] -ceq "tag $Tag") (
            'annotated release tag embedded name does not equal its canonical ref name'
        )

        $tagCommit = (& git rev-list -n 1 $tagReference).Trim().ToLowerInvariant()
        Assert-ReleaseCondition ($LASTEXITCODE -eq 0) "cannot resolve $tagReference"
        $headCommit = (& git rev-parse HEAD).Trim().ToLowerInvariant()
        Assert-ReleaseCondition ($LASTEXITCODE -eq 0) 'cannot resolve HEAD'
        Assert-ReleaseCondition ($tagCommit -ceq $headCommit) (
            "tag commit '$tagCommit' does not equal checked-out HEAD '$headCommit'"
        )
        Assert-ReleaseCondition (
            $tagTargetMatch.Groups['object'].Value.ToLowerInvariant() -ceq $headCommit
        ) 'annotated release tag direct target does not equal checked-out HEAD'
        $verifiedCommit = $headCommit
        $verifiedTagObject = $tagObject
    }

    if (-not [string]::IsNullOrWhiteSpace($GithubOutput)) {
        $outputPath = [System.IO.Path]::GetFullPath($GithubOutput)
        $githubOutputText = "version=$releaseVersion`ntag=$Tag`n"
        if ($null -ne $verifiedCommit) {
            $githubOutputText += "commit=$verifiedCommit`n"
            $githubOutputText += "tag_object=$verifiedTagObject`n"
        }
        [System.IO.File]::AppendAllText(
            $outputPath,
            $githubOutputText,
            [System.Text.UTF8Encoding]::new($false)
        )
    }

    Write-Host "Release consistency verified for $Tag across Cargo, lockfile, and release documents."
}
finally {
    Pop-Location
}
