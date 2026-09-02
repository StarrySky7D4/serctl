[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Utf8NoBom = New-Object System.Text.UTF8Encoding($false, $true)
$Git = (Get-Command git -CommandType Application | Select-Object -First 1).Source
$Cargo = (Get-Command cargo -CommandType Application | Select-Object -First 1).Source
$SourceRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$TestRoot = Join-Path $SourceRoot ('target/version-switch-selftest-' + [Guid]::NewGuid().ToString('N'))
$OwnerToken = [Guid]::NewGuid().ToString('N')
$IdentityFiles = @(
    'Cargo.toml',
    'Cargo.lock',
    'fuzz/Cargo.lock',
    'CHANGELOG.md',
    'README.md',
    'docs/serctl-user-guide.md',
    'docs/serctl-architecture-security.html',
    'docs/v1-beta-release-contract.md',
    'docs/v1-beta-agent-jsonl.md',
    'docs/v1-beta-acceptance-matrix.md',
    'SECURITY.md'
)

function Assert-Test {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if (-not $Condition) {
        throw "version switch self-test failed: $Message"
    }
}

function Expand-AsciiUnicode {
    param([Parameter(Mandatory = $true)][string]$Value)
    return [regex]::Unescape($Value)
}

function Write-Utf8 {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Content
    )
    $parent = [System.IO.Path]::GetDirectoryName($Path)
    if (-not [string]::IsNullOrWhiteSpace($parent)) {
        [System.IO.Directory]::CreateDirectory($parent) | Out-Null
    }
    [System.IO.File]::WriteAllText($Path, $Content, $script:Utf8NoBom)
}

function Invoke-GitFixture {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string[]]$Arguments
    )
    Push-Location -LiteralPath $Root
    try {
        $savedPreference = $ErrorActionPreference
        $ErrorActionPreference = 'Continue'
        try {
            $output = @(& $script:Git @Arguments 2>&1)
            $exitCode = $LASTEXITCODE
        }
        finally {
            $ErrorActionPreference = $savedPreference
        }
        if ($exitCode -ne 0) {
            throw (
                "fixture git command failed: git $($Arguments -join ' '); " +
                "output=$($output -join ' | ')"
            )
        }
        return $output
    }
    finally {
        Pop-Location
    }
}

function New-Fixture {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Commit
    )
    $root = Join-Path $script:TestRoot $Name
    Assert-Test (-not (Test-Path -LiteralPath $root)) "fixture root already exists: $Name"
    $savedPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $cloneOutput = @(& $script:Git clone --quiet --local --no-hardlinks --no-tags --no-checkout -- $script:SourceRoot $root 2>&1)
        $cloneExitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $savedPreference
    }
    Assert-Test ($cloneExitCode -eq 0) (
        "local no-hardlink clone failed: $($cloneOutput -join ' ')"
    )
    Assert-Test (
        -not (Test-Path -LiteralPath (Join-Path $root '.git/objects/info/alternates'))
    ) 'local clone unexpectedly depends on source object alternates'
    Invoke-GitFixture $root @('checkout', '--quiet', '--detach', $Commit) | Out-Null
    Assert-Test (
        ([string](Invoke-GitFixture $root @('rev-parse', 'HEAD'))).Trim() -ceq $Commit
    ) 'fixture did not check out the exact requested commit'
    Assert-Test (
        @(Invoke-GitFixture $root @('status', '--porcelain=v1', '--untracked-files=all')).Count -eq 0
    ) 'fresh local clone checkout is not clean'
    $toolPaths = @(
        'scripts/Set-V1ReleaseVersion.ps1',
        'scripts/Verify-ReleaseConsistency.ps1',
        'scripts/Test-V1BetaDocumentation.ps1'
    )
    $installedCurrentTools = $false
    foreach ($relative in $toolPaths) {
        $fixturePath = Join-Path $root $relative
        $sourcePath = Join-Path $script:SourceRoot $relative
        if ((Get-FileHash -LiteralPath $fixturePath -Algorithm SHA256).Hash -cne
            (Get-FileHash -LiteralPath $sourcePath -Algorithm SHA256).Hash) {
            Copy-Item -LiteralPath $sourcePath -Destination $fixturePath
            $installedCurrentTools = $true
        }
    }
    Invoke-GitFixture $root @('config', 'user.name', 'serctl fixture') | Out-Null
    Invoke-GitFixture $root @('config', 'user.email', 'fixture@example.invalid') | Out-Null
    if ($installedCurrentTools) {
        $addArguments = @('add', '--') + $toolPaths
        Invoke-GitFixture $root $addArguments | Out-Null
        Invoke-GitFixture $root @('commit', '-m', 'install current release replay tools') | Out-Null
    }
    foreach ($relative in $toolPaths) {
        Assert-Test (
            (Get-FileHash -LiteralPath (Join-Path $root $relative) -Algorithm SHA256).Hash -ceq
                (Get-FileHash -LiteralPath (Join-Path $script:SourceRoot $relative) -Algorithm SHA256).Hash
        ) "fixture does not contain the current $relative bytes"
    }
    Assert-Test (
        @(Invoke-GitFixture $root @('status', '--porcelain=v1', '--untracked-files=all')).Count -eq 0
    ) 'fixture is not clean after installing current replay tools'
    return $root
}

function Get-WorkspaceVersion {
    param([Parameter(Mandatory = $true)][string]$Root)
    $savedPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $metadataJson = & $script:Cargo metadata --quiet --locked --no-deps --format-version 1 `
            --manifest-path (Join-Path $Root 'Cargo.toml') 2>$null
        $metadataExitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $savedPreference
    }
    Assert-Test ($metadataExitCode -eq 0) 'cargo metadata failed for version-switch fixture'
    $metadata = $metadataJson | ConvertFrom-Json
    $packages = @($metadata.packages | Where-Object { $metadata.workspace_members -contains $_.id })
    $versions = @($packages | ForEach-Object { [string]$_.version } | Sort-Object -Unique)
    Assert-Test ($packages.Count -gt 0 -and $versions.Count -eq 1) (
        'workspace packages do not expose one common version'
    )
    return [string]$versions[0]
}

function Get-WorkspaceVersionAtCommit {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Commit
    )
    Assert-Test ($Commit -match '^[0-9a-f]{40}$') 'manifest commit is not canonical'
    $manifest = @(Invoke-GitFixture $Root @('show', "${Commit}:Cargo.toml")) -join "`n"
    $match = [regex]::Match(
        $manifest,
        '(?ms)^\[workspace\.package\]\s*.*?^version\s*=\s*"(?<version>[^"]+)"\s*$'
    )
    if (-not $match.Success) {
        return $null
    }
    return [string]$match.Groups['version'].Value
}

function Get-NextBetaVersion {
    param([Parameter(Mandatory = $true)][string]$Version)
    $match = [regex]::Match($Version, '^1\.0\.0-beta(?:\.(?<ordinal>[1-9][0-9]*))?$')
    Assert-Test $match.Success "version is not a canonical v1 beta: $Version"
    $ordinal = if ($match.Groups['ordinal'].Success) {
        [System.Numerics.BigInteger]::Parse(
            $match.Groups['ordinal'].Value,
            [Globalization.CultureInfo]::InvariantCulture
        )
    }
    else { [System.Numerics.BigInteger]::Zero }
    $nextOrdinal = $ordinal + [System.Numerics.BigInteger]::One
    return '1.0.0-beta.' + $nextOrdinal.ToString(
        [Globalization.CultureInfo]::InvariantCulture
    )
}

function Test-NextTransition {
    param(
        [Parameter(Mandatory = $true)][string]$Prior,
        [Parameter(Mandatory = $true)][string]$Current
    )
    $priorV03 = [regex]::IsMatch(
        $Prior,
        '^0\.3\.(?:0|[1-9][0-9]*)(?:-(?:alpha|beta|rc)(?:\.(?:0|[1-9][0-9]*))?)?$'
    )
    if ($priorV03) {
        return $Current -ceq '1.0.0-beta'
    }
    if (-not [regex]::IsMatch($Prior, '^1\.0\.0-beta(?:\.[1-9][0-9]*)?$')) {
        return $false
    }
    return (Get-NextBetaVersion $Prior) -ceq $Current
}

function Assert-NextTransition {
    param(
        [Parameter(Mandatory = $true)][string]$Prior,
        [Parameter(Mandatory = $true)][string]$Current
    )
    Assert-Test (Test-NextTransition $Prior $Current) (
        "first parent '$Prior' is not the immediate predecessor of '$Current'"
    )
}

function Get-ReadmeCurrentStateNeutralDocument {
    param([Parameter(Mandatory = $true)][string]$Root)
    $path = Join-Path $Root 'README.md'
    $text = [IO.File]::ReadAllText($path, $script:Utf8NoBom)
    $tag = 'v(?:0\.3\.0-beta\.2|1\.0\.0-beta(?:\.[1-9][0-9]*)?)'
    $visible = '(?<prefix>\u5F53\u524D\u91CD\u5199\u7248\u6807\u8BB0\u4E3A\u9884\u53D1\u5E03\u6D4B\u8BD5\u7248\u672C \*\*)' + $tag + '(?<suffix>\*\*)'
    Assert-Test ([regex]::Matches($text, $visible).Count -eq 1) 'README lacks one visible current version'
    $text = [regex]::Replace($text, $visible, '${prefix}__CURRENT_TAG__${suffix}')
    $marker = '<!-- release-marker: ' + $tag + ' -->'
    Assert-Test ([regex]::Matches($text, $marker).Count -eq 1) 'README lacks one machine current version'
    $text = [regex]::Replace($text, $marker, '<!-- release-marker: __CURRENT_TAG__ -->')
    $candidate = '(?<prefix>^> \u5DE5\u4F5C\u6811\u4E2D\u7684 \*\*)' + $tag + '(?<suffix> \u5019\u9009\u5C1A\u672A\u9A8C\u6536\u6216\u53D1\u5E03\*\*\u3002)'
    Assert-Test ([regex]::Matches($text, $candidate, 'Multiline').Count -eq 1) 'README lacks one candidate identity'
    $text = [regex]::Replace($text, $candidate, '${prefix}__CURRENT_TAG__${suffix}', 'Multiline')
    $status = '(?:\u5F53\u524D\u7248\u672C\u6807\u8BB0\u5728 Cargo\u3001lockfile\u3001CHANGELOG\u3001README\u3001\u7528\u6237\u6307\u5357\u548C\u67B6\u6784\u9875\u7EDF\u4E00\u5207\u6362\u524D\u4ECD\u4FDD\u6301 ' +
        $tag + '|\u5F53\u524D workspace \u4E0E\u9884\u53D1\u5E03\u6807\u8BB0\u5DF2\u540C\u6B65\u4E3A ' + $tag + ')'
    Assert-Test ([regex]::Matches($text, $status).Count -eq 1) 'README lacks one current-state clause'
    $text = [regex]::Replace($text, $status, '__CURRENT_WORKSPACE_STATE__')
    $boundary = '(?:\u5F53\u524D\u6B63\u5F0F\u7248\u672C\u6807\u8BB0\u4ECD\u51BB\u7ED3\u4E3A `' + $tag + '`\uFF1B\u5DE5\u4F5C\u6811\u4E2D\u7684 `' + $tag +
        '` \u53EA\u662F\u672A\u53D1\u5E03\u5019\u9009\u3002|\u5F53\u524D\u9884\u53D1\u5E03\u7248\u672C\u6807\u8BB0\u4E3A `' + $tag + '`\uFF1B\u8BE5\u7248\u672C\u4ECD\u662F\u672A\u53D1\u5E03\u5019\u9009\u3002)'
    Assert-Test ([regex]::Matches($text, $boundary).Count -eq 1) 'README lacks one release-boundary prefix'
    $text = [regex]::Replace($text, $boundary, '__CURRENT_RELEASE_BOUNDARY__')
    $workflow = '(?<prefix>\u6B63\u5F0F\u9884\u53D1\u5E03\u4EC5\u7531 exact annotated tag `)' + $tag + '(?<suffix>` \u89E6\u53D1\u4E13\u7528 workflow)'
    Assert-Test ([regex]::Matches($text, $workflow).Count -eq 1) 'README lacks one workflow tag binding'
    return [regex]::Replace($text, $workflow, '${prefix}__CURRENT_TAG__${suffix}')
}

function Get-GuideCurrentStateNeutralDocument {
    param([Parameter(Mandatory = $true)][string]$Root)
    $path = Join-Path $Root 'docs/serctl-user-guide.md'
    $text = [IO.File]::ReadAllText($path, $script:Utf8NoBom)
    $tag = 'v(?:0\.3\.0-beta\.2|1\.0\.0-beta(?:\.[1-9][0-9]*)?)'
    $visible = '(?<prefix>\u9002\u7528\u7248\u672C\uFF1A`)' + $tag + '(?<suffix>`\uFF08\u9884\u53D1\u5E03\u6D4B\u8BD5\u7248\uFF09)'
    Assert-Test ([regex]::Matches($text, $visible).Count -eq 1) 'user guide lacks one visible current version'
    $text = [regex]::Replace($text, $visible, '${prefix}__CURRENT_TAG__${suffix}')
    $marker = '<!-- applicable-version: ' + $tag + ' -->'
    Assert-Test ([regex]::Matches($text, $marker).Count -eq 1) 'user guide lacks one machine current version'
    $text = [regex]::Replace($text, $marker, '<!-- applicable-version: __CURRENT_TAG__ -->')
    $status = '(?:^> \u5F53\u524D\u53D1\u5E03\u6807\u8BB0\u4ECD\u4E3A ' + $tag + '\uFF1B\u5DE5\u4F5C\u6811\u4E2D\u7684 ' + $tag +
        ' \u5019\u9009\u5C1A\u672A\u9A8C\u6536\u6216\u53D1\u5E03\u3002|^> \u5F53\u524D\u9884\u53D1\u5E03\u6807\u8BB0\u5DF2\u540C\u6B65\u4E3A ' + $tag + '\uFF1B\u8BE5\u5019\u9009\u5C1A\u672A\u9A8C\u6536\u6216\u53D1\u5E03\u3002)'
    Assert-Test ([regex]::Matches($text, $status, 'Multiline').Count -eq 1) 'user guide lacks one current-state prefix'
    $text = [regex]::Replace($text, $status, '> __CURRENT_RELEASE_STATE__', 'Multiline')
    $capability = '(?<prefix>\u4EE5\u4E0A\u65B0\u589E schema/error/transfer/tunnel/connection-identity \u884C\u4E3A\u5C5E\u4E8E )' +
        $tag + '(?<suffix> \u5019\u9009)'
    Assert-Test ([regex]::Matches($text, $capability).Count -eq 1) 'user guide lacks one capability candidate identity'
    $text = [regex]::Replace($text, $capability, '${prefix}__CURRENT_TAG__${suffix}')
    $tail = '(?:\u5F53\u524D ' + $tag + ' \u53D1\u5E03\u6807\u8BB0\u4E0D\u56E0\u6B64\u88AB\u6539\u5199\u3002|\u5F53\u524D\u9884\u53D1\u5E03\u6807\u8BB0\u5DF2\u540C\u6B65\u4E3A ' +
        $tag + '\uFF0C\u4F46\u4E0D\u56E0\u6B64\u89C6\u4E3A\u5DF2\u9A8C\u6536\u3002)'
    Assert-Test ([regex]::Matches($text, $tail).Count -eq 1) 'user guide lacks one capability acceptance boundary'
    return [regex]::Replace($text, $tail, '__CURRENT_ACCEPTANCE_BOUNDARY__')
}

function Get-ArchitectureCurrentStateNeutralDocument {
    param([Parameter(Mandatory = $true)][string]$Root)
    $path = Join-Path $Root 'docs/serctl-architecture-security.html'
    $text = [IO.File]::ReadAllText($path, $script:Utf8NoBom)
    $tag = 'v1\.0\.0-beta(?:\.[1-9][0-9]*)?'
    $pattern = '(?<prefix>data-release-candidate=")' + $tag +
        '(?<middle>">[^<]*<code>)' + $tag +
        '(?<suffix></code>)'
    Assert-Test ([regex]::Matches($text, $pattern).Count -eq 1) 'architecture lacks one bound current version'
    $text = [regex]::Replace(
        $text,
        $pattern,
        '${prefix}__CURRENT_TAG__${middle}__CURRENT_TAG__${suffix}'
    )
    foreach ($binding in @(
        [pscustomobject]@{ Pattern = '(?<prefix><strong>)' + $tag + '(?<suffix> \u5019\u9009\uFF0C\u5C1A\u672A\u9A8C\u6536</strong>)'; Replacement = '${prefix}__CURRENT_TAG__${suffix}'; Description = 'status card' },
        [pscustomobject]@{ Pattern = '(?<prefix>\u53EA\u6709 exact annotated clean tag <code>)' + $tag + '(?<suffix></code> \u4E0A)'; Replacement = '${prefix}__CURRENT_TAG__${suffix}'; Description = 'artifact boundary' },
        [pscustomobject]@{ Pattern = '(?<prefix>v1 beta \u53D1\u5E03\u94FE\u53EA\u54CD\u5E94\u89C4\u8303 annotated tag <code>)' + $tag + '(?<suffix></code>)'; Replacement = '${prefix}__CURRENT_TAG__${suffix}'; Description = 'workflow tag' },
        [pscustomobject]@{ Pattern = '(?<prefix>\u7684 <code>)' + $tag + '(?<suffix></code> \u5019\u9009\u3001vault-storage)'; Replacement = '${prefix}__CURRENT_TAG__${suffix}'; Description = 'footer tag' }
    )) {
        Assert-Test ([regex]::Matches($text, [string]$binding.Pattern).Count -eq 1) (
            "architecture lacks one current $($binding.Description)"
        )
        $text = [regex]::Replace($text, [string]$binding.Pattern, [string]$binding.Replacement)
    }
    return $text
}

function Invoke-RealDocumentationGate {
    param([Parameter(Mandatory = $true)][string]$Root)
    $gate = Join-Path $Root 'scripts/Test-V1BetaDocumentation.ps1'
    Assert-Test (
        (Get-FileHash -LiteralPath $gate -Algorithm SHA256).Hash -ceq
            (Get-FileHash -LiteralPath (Join-Path $script:SourceRoot 'scripts/Test-V1BetaDocumentation.ps1') -Algorithm SHA256).Hash
    ) 'fixture documentation gate differs from the real source gate'
    & $gate | Out-Null
}

function Assert-ExactTextCount {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][string]$Literal,
        [Parameter(Mandatory = $true)][int]$Count,
        [Parameter(Mandatory = $true)][string]$Description
    )
    Assert-Test (
        [regex]::Matches($Text, [regex]::Escape($Literal)).Count -eq $Count
    ) "$Description does not occur exactly $Count time(s)"
}

function Assert-CurrentReleaseBindings {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Tag,
        [Parameter(Mandatory = $true)][string]$Version,
        [Parameter(Mandatory = $true)][string]$ReleaseDate
    )
    $readme = [IO.File]::ReadAllText((Join-Path $Root 'README.md'), $script:Utf8NoBom)
    foreach ($binding in @(
        [pscustomobject]@{ Text = (Expand-AsciiUnicode '\u5F53\u524D\u91CD\u5199\u7248\u6807\u8BB0\u4E3A\u9884\u53D1\u5E03\u6D4B\u8BD5\u7248\u672C **{0}**') -f $Tag; Description = 'README visible tag' },
        [pscustomobject]@{ Text = "<!-- release-marker: $Tag -->"; Description = 'README machine tag' },
        [pscustomobject]@{ Text = (Expand-AsciiUnicode '> \u5DE5\u4F5C\u6811\u4E2D\u7684 **{0} \u5019\u9009\u5C1A\u672A\u9A8C\u6536\u6216\u53D1\u5E03**\u3002') -f $Tag; Description = 'README candidate tag' },
        [pscustomobject]@{ Text = (Expand-AsciiUnicode '\u5F53\u524D workspace \u4E0E\u9884\u53D1\u5E03\u6807\u8BB0\u5DF2\u540C\u6B65\u4E3A {0}') -f $Tag; Description = 'README current-state tag' },
        [pscustomobject]@{ Text = (Expand-AsciiUnicode '\u5F53\u524D\u9884\u53D1\u5E03\u7248\u672C\u6807\u8BB0\u4E3A `{0}`\uFF1B\u8BE5\u7248\u672C\u4ECD\u662F\u672A\u53D1\u5E03\u5019\u9009\u3002') -f $Tag; Description = 'README release boundary tag' },
        [pscustomobject]@{ Text = (Expand-AsciiUnicode '\u6B63\u5F0F\u9884\u53D1\u5E03\u4EC5\u7531 exact annotated tag `{0}` \u89E6\u53D1\u4E13\u7528 workflow') -f $Tag; Description = 'README workflow tag' }
    )) {
        Assert-ExactTextCount $readme $binding.Text 1 $binding.Description
    }

    $guide = [IO.File]::ReadAllText((Join-Path $Root 'docs/serctl-user-guide.md'), $script:Utf8NoBom)
    foreach ($binding in @(
        [pscustomobject]@{ Text = (Expand-AsciiUnicode '\u9002\u7528\u7248\u672C\uFF1A`{0}`\uFF08\u9884\u53D1\u5E03\u6D4B\u8BD5\u7248\uFF09') -f $Tag; Description = 'user-guide visible tag' },
        [pscustomobject]@{ Text = "<!-- applicable-version: $Tag -->"; Description = 'user-guide machine tag' },
        [pscustomobject]@{ Text = (Expand-AsciiUnicode '> \u5F53\u524D\u9884\u53D1\u5E03\u6807\u8BB0\u5DF2\u540C\u6B65\u4E3A {0}\uFF1B\u8BE5\u5019\u9009\u5C1A\u672A\u9A8C\u6536\u6216\u53D1\u5E03\u3002') -f $Tag; Description = 'user-guide state tag' },
        [pscustomobject]@{ Text = (Expand-AsciiUnicode '\u4EE5\u4E0A\u65B0\u589E schema/error/transfer/tunnel/connection-identity \u884C\u4E3A\u5C5E\u4E8E {0} \u5019\u9009') -f $Tag; Description = 'user-guide capability tag' },
        [pscustomobject]@{ Text = (Expand-AsciiUnicode '\u5F53\u524D\u9884\u53D1\u5E03\u6807\u8BB0\u5DF2\u540C\u6B65\u4E3A {0}\uFF0C\u4F46\u4E0D\u56E0\u6B64\u89C6\u4E3A\u5DF2\u9A8C\u6536\u3002') -f $Tag; Description = 'user-guide acceptance tag' }
    )) {
        Assert-ExactTextCount $guide $binding.Text 1 $binding.Description
    }

    $architecture = [IO.File]::ReadAllText((Join-Path $Root 'docs/serctl-architecture-security.html'), $script:Utf8NoBom)
    foreach ($binding in @(
        [pscustomobject]@{ Text = "data-release-candidate=`"$Tag`""; Description = 'architecture machine tag' },
        [pscustomobject]@{ Text = (Expand-AsciiUnicode '<strong>{0} \u5019\u9009\uFF0C\u5C1A\u672A\u9A8C\u6536</strong>') -f $Tag; Description = 'architecture status tag' },
        [pscustomobject]@{ Text = (Expand-AsciiUnicode '\u53EA\u6709 exact annotated clean tag <code>{0}</code> \u4E0A') -f $Tag; Description = 'architecture artifact tag' },
        [pscustomobject]@{ Text = (Expand-AsciiUnicode 'v1 beta \u53D1\u5E03\u94FE\u53EA\u54CD\u5E94\u89C4\u8303 annotated tag <code>{0}</code>') -f $Tag; Description = 'architecture workflow tag' },
        [pscustomobject]@{ Text = (Expand-AsciiUnicode '\u7684 <code>{0}</code> \u5019\u9009\u3001vault-storage') -f $Tag; Description = 'architecture footer tag' }
    )) {
        Assert-ExactTextCount $architecture $binding.Text 1 $binding.Description
    }

    $changelog = [IO.File]::ReadAllText((Join-Path $Root 'CHANGELOG.md'), $script:Utf8NoBom)
    Assert-ExactTextCount $changelog "## $Tag - $ReleaseDate" 1 'CHANGELOG current heading'
    Assert-ExactTextCount $changelog ((Expand-AsciiUnicode (
        '> **\u5019\u9009\u72B6\u6001\uFF08\u5C1A\u672A\u9A8C\u6536/\u53D1\u5E03\uFF09**\uFF1A' +
        '\u5F53\u524D workspace \u4E0E\u9884\u53D1\u5E03\u6807\u8BB0\u5DF2\u540C\u6B65\u4E3A `{0}`\uFF1B' +
        'exact-tag CI\u3001\u53D7\u63A7\u5B9E\u673A\u548C\u4ED3\u5E93\u6CBB\u7406\u95E8\u7981\u4ECD\u987B\u901A\u8FC7\u540E\u65B9\u53EF\u53D1\u5E03\u3002'
    )) -f $Tag) 1 'CHANGELOG current-state tag'

    $contract = [IO.File]::ReadAllText((Join-Path $Root 'docs/v1-beta-release-contract.md'), $script:Utf8NoBom)
    Assert-ExactTextCount $contract "<!-- release-tag: $Tag -->" 1 'release-contract machine tag'
    Assert-ExactTextCount $contract "  `"tag`": `"$Tag`"," 2 'release-contract JSON tags'
    Assert-ExactTextCount $contract "scripts/New-IsolatedCandidate.ps1 -Version $Version" 1 'release-contract candidate command'
    Assert-ExactTextCount $contract "target/candidates/$Tag-<12-character-HEAD>" 1 'release-contract candidate path'

    $agent = [IO.File]::ReadAllText((Join-Path $Root 'docs/v1-beta-agent-jsonl.md'), $script:Utf8NoBom)
    Assert-ExactTextCount $agent "<!-- target-release: $Tag -->" 1 'Agent contract machine tag'
    Assert-ExactTextCount $agent "Target release: ``$Tag`` (candidate, not accepted or published)" 1 'Agent contract visible tag'
    Assert-ExactTextCount $agent "The current workspace/release marker is ``$Tag``; exact-tag acceptance gates still control support and publication." 1 'Agent contract state tag'

    $matrix = [IO.File]::ReadAllText((Join-Path $Root 'docs/v1-beta-acceptance-matrix.md'), $script:Utf8NoBom)
    Assert-ExactTextCount $matrix "<!-- normative-release: $Tag -->" 1 'acceptance-matrix machine tag'
    Assert-ExactTextCount $matrix "This matrix is normative for ``$Tag``." 1 'acceptance-matrix normative tag'
    Assert-ExactTextCount $matrix "scripts/Verify-ReleaseConsistency.ps1 -Tag $Tag -RequireGitTag" 1 'acceptance-matrix verifier tag'
    Assert-ExactTextCount $matrix "all name ``$Version`` consistently" 1 'acceptance-matrix version tuple'
    Assert-ExactTextCount $matrix "target/candidates/$Tag-<12-character-HEAD>" 1 'acceptance-matrix candidate path'
}

function Get-CurrentChangelogEntryNeutralDocument {
    param([Parameter(Mandatory = $true)][string]$Root)
    $text = [IO.File]::ReadAllText((Join-Path $Root 'CHANGELOG.md'), $script:Utf8NoBom)
    $entry = [regex]::Match($text, '(?ms)^## [^\r\n]+\r?\n.*?(?=^## |\z)')
    Assert-Test $entry.Success 'CHANGELOG has no current release entry'
    $current = $entry.Value
    $heading = '(?m)^## v1\.0\.0-beta(?:\.[1-9][0-9]*)? - (?:Unreleased|\d{4}-\d{2}-\d{2})$'
    Assert-Test ([regex]::Matches($current, $heading).Count -eq 1) 'CHANGELOG current heading is not canonical'
    $current = [regex]::Replace($current, $heading, '## __CURRENT_RELEASE__')
    $tag = 'v(?:0\.3\.0-beta\.2|1\.0\.0-beta(?:\.[1-9][0-9]*)?)'
    $status = '(?<prefix>^> \*\*\u5019\u9009\u72B6\u6001\uFF08\u5C1A\u672A\u9A8C\u6536/\u53D1\u5E03\uFF09\*\*\uFF1A)(?:' +
        '\u5F53\u524D workspace \u4E0E\u6B63\u5F0F\u53D1\u5E03\u6807\u8BB0\u4ECD\u4FDD\u6301 `' + $tag +
        '`\uFF0C\u5F85 Rust \u96C6\u6210\u3001exact-tag CI\u3001\u53D7\u63A7\u5B9E\u673A\u548C\u4ED3\u5E93\u6CBB\u7406\u95E8\u7981\u5168\u90E8\u901A\u8FC7\u540E\u518D\u7EDF\u4E00\u5207\u6362\u3002|' +
        '\u5F53\u524D workspace \u4E0E\u9884\u53D1\u5E03\u6807\u8BB0\u5DF2\u540C\u6B65\u4E3A `' + $tag +
        '`\uFF1Bexact-tag CI\u3001\u53D7\u63A7\u5B9E\u673A\u548C\u4ED3\u5E93\u6CBB\u7406\u95E8\u7981\u4ECD\u987B\u901A\u8FC7\u540E\u65B9\u53EF\u53D1\u5E03\u3002)'
    Assert-Test ([regex]::Matches($current, $status, 'Multiline').Count -eq 1) 'CHANGELOG lacks one current-state prefix'
    return [regex]::Replace($current, $status, '${prefix}__CURRENT_STATE__', 'Multiline')
}

function Prepare-NextBetaFixture {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$CurrentTag,
        [Parameter(Mandatory = $true)][string]$TargetTag
    )
    $changelogPath = Join-Path $Root 'CHANGELOG.md'
    $changelog = [IO.File]::ReadAllText($changelogPath, $script:Utf8NoBom)
    $firstRelease = [regex]::Match($changelog, '(?m)^## ')
    Assert-Test $firstRelease.Success 'fixture changelog has no release heading'
    $prefix = $changelog.Substring(0, $firstRelease.Index)
    $newline = if ($changelog.Contains("`r`n")) { "`r`n" } else { "`n" }
    $history = $changelog.Substring($firstRelease.Index)
    $preparedStatus = (Expand-AsciiUnicode (
        '> **\u5019\u9009\u72B6\u6001\uFF08\u5C1A\u672A\u9A8C\u6536/\u53D1\u5E03\uFF09**\uFF1A' +
        '\u5F53\u524D workspace \u4E0E\u6B63\u5F0F\u53D1\u5E03\u6807\u8BB0\u4ECD\u4FDD\u6301 `{0}`\uFF0C' +
        '\u5F85 Rust \u96C6\u6210\u3001exact-tag CI\u3001\u53D7\u63A7\u5B9E\u673A\u548C\u4ED3\u5E93\u6CBB\u7406' +
        '\u95E8\u7981\u5168\u90E8\u901A\u8FC7\u540E\u518D\u7EDF\u4E00\u5207\u6362\u3002' +
        '\u5019\u9009 wire \u4E3A IPC v9\uFF0C\u5E76\u62D2\u7EDD v8 \u6216 direct-connect downgrade\uFF1B' +
        'Agent JSONL \u56FA\u5B9A `schema_version=1` \u548C\u7A33\u5B9A `error_code`\u3002' +
        '\u666E\u901A `main` CI \u4E0D\u4EA7\u751F\u6B63\u5F0F\u53D1\u884C\u7269\u3002'
    )) -f $CurrentTag
    Write-Utf8 $changelogPath (
        $prefix + "## $TargetTag - Unreleased$newline$newline" +
        $preparedStatus + "$newline$newline" +
        $history
    )
}

function Assert-VersionSwitchRejected {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Version,
        [Parameter(Mandatory = $true)][string]$Description
    )
    $rejected = $false
    try {
        & (Join-Path $Root 'scripts/Set-V1ReleaseVersion.ps1') `
            -Version $Version -WhatIf -ReleaseDate 2026-09-02 | Out-Null
    }
    catch { $rejected = $true }
    Assert-Test $rejected "$Description was accepted"
}

function Get-GovernanceCurrentStateNeutralDocument {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$RelativePath,
        [Parameter(Mandatory = $true)][string]$MarkerName
    )
    $text = [IO.File]::ReadAllText((Join-Path $Root $RelativePath), $script:Utf8NoBom)
    $pattern = '<!--\s*' + [regex]::Escape($MarkerName) + ':\s*[^\s]+\s*-->'
    $matches = [regex]::Matches($text, $pattern)
    Assert-Test ($matches.Count -eq 1) "$RelativePath lacks one machine marker"
    $text = [regex]::Replace($text, $pattern, "<!-- ${MarkerName}: __VERSION__ -->")
    $tag = 'v1\.0\.0-beta(?:\.[1-9][0-9]*)?'
    $version = '1\.0\.0-beta(?:\.[1-9][0-9]*)?'
    $releaseStateTag = 'v(?:0\.3\.0-beta\.2|1\.0\.0-beta(?:\.[1-9][0-9]*)?)'
    $bindings = switch ($RelativePath) {
        'docs/v1-beta-release-contract.md' {
            @(
                [pscustomobject]@{ Pattern = '(?m)^(  "tag": ")' + $tag + '(",$)'; Replacement = '${1}__CURRENT_TAG__${2}'; Count = 2; Description = 'JSON tag examples' },
                [pscustomobject]@{ Pattern = '(?<prefix>scripts/New-IsolatedCandidate\.ps1 -Version )' + $version; Replacement = '${prefix}__CURRENT_VERSION__'; Count = 1; Description = 'candidate command' },
                [pscustomobject]@{ Pattern = '(?<prefix>target/candidates/)' + $tag + '(?<suffix>-<12-character-HEAD>)'; Replacement = '${prefix}__CURRENT_TAG__${suffix}'; Count = 1; Description = 'candidate path' }
            )
        }
        'docs/v1-beta-agent-jsonl.md' {
            @(
                [pscustomobject]@{ Pattern = '(?<prefix>Target release: `)' + $tag + '(?<suffix>` \(candidate, not accepted or published\))'; Replacement = '${prefix}__CURRENT_TAG__${suffix}'; Count = 1; Description = 'target release' },
                [pscustomobject]@{ Pattern = '(?:The current workspace/release marker remains `' + $releaseStateTag +
                    '` until the exact-tag acceptance gates pass\.|The current workspace/release marker is `' +
                    $releaseStateTag + '`; exact-tag acceptance gates still control support and publication\.)'; Replacement = '__CURRENT_RELEASE_STATE__'; Count = 1; Description = 'current state' }
            )
        }
        'docs/v1-beta-acceptance-matrix.md' {
            @(
                [pscustomobject]@{ Pattern = '(?<prefix>This matrix is normative for `)' + $tag + '(?<suffix>`\.)'; Replacement = '${prefix}__CURRENT_TAG__${suffix}'; Count = 1; Description = 'normative tag' },
                [pscustomobject]@{ Pattern = '(?<prefix>scripts/Verify-ReleaseConsistency\.ps1 -Tag )' + $tag + '(?<suffix> -RequireGitTag)'; Replacement = '${prefix}__CURRENT_TAG__${suffix}'; Count = 1; Description = 'verifier tag' },
                [pscustomobject]@{ Pattern = '(?<prefix>all name `)' + $version + '(?<suffix>` consistently)'; Replacement = '${prefix}__CURRENT_VERSION__${suffix}'; Count = 1; Description = 'version tuple' },
                [pscustomobject]@{ Pattern = '(?<prefix>target/candidates/)' + $tag + '(?<suffix>-<12-character-HEAD>)'; Replacement = '${prefix}__CURRENT_TAG__${suffix}'; Count = 1; Description = 'candidate path' }
            )
        }
        default { throw "unexpected governance document '$RelativePath'" }
    }
    foreach ($binding in $bindings) {
        Assert-Test ([regex]::Matches($text, [string]$binding.Pattern).Count -eq [int]$binding.Count) (
            "$RelativePath lacks $($binding.Count) current $($binding.Description) binding(s)"
        )
        $text = [regex]::Replace($text, [string]$binding.Pattern, [string]$binding.Replacement)
    }
    return $text
}

function Get-CurrentSecurityLineNeutralDocument {
    param([Parameter(Mandatory = $true)][string]$Root)
    $path = Join-Path $Root 'SECURITY.md'
    $text = [IO.File]::ReadAllText($path, $script:Utf8NoBom)
    $pattern = '(?m)^\| `v1\.0\.0-beta(?:\.[1-9][0-9]*)?` \| Supported after its tagged acceptance workflow publishes the attested prerelease; fixes are delivered as a new immutable prerelease tag\. \|$'
    Assert-Test ([regex]::Matches($text, $pattern).Count -eq 1) (
        'SECURITY does not contain exactly one current supported prerelease line'
    )
    return [regex]::Replace(
        $text,
        $pattern,
        '| `__CURRENT_BETA__` | Supported after its tagged acceptance workflow publishes the attested prerelease; fixes are delivered as a new immutable prerelease tag. |'
    )
}

function Get-TrackedHashes {
    param([Parameter(Mandatory = $true)][string]$Root)
    $result = @{}
    foreach ($relative in @(Invoke-GitFixture $Root @('ls-files'))) {
        $path = Join-Path $Root ([string]$relative)
        $result[[string]$relative] = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    }
    return $result
}

[System.IO.Directory]::CreateDirectory($TestRoot) | Out-Null
Write-Utf8 (Join-Path $TestRoot 'owner-token') $OwnerToken
try {
    $sourceHead = ([string](Invoke-GitFixture $SourceRoot @('rev-parse', 'HEAD'))).Trim().ToLowerInvariant()
    $sourceStatus = @(Invoke-GitFixture $SourceRoot @('status', '--porcelain=v1', '--untracked-files=all'))
    Assert-Test ($sourceHead -match '^[0-9a-f]{40}$') 'source HEAD is not canonical'
    Assert-Test ($sourceStatus.Count -eq 0) 'source checkout must be clean'
    $isShallow = ([string](Invoke-GitFixture $SourceRoot @(
        'rev-parse', '--is-shallow-repository'
    ))).Trim().ToLowerInvariant()
    Assert-Test ($isShallow -ceq 'false') (
        'full first-parent release history required; source checkout is shallow'
    )
    $currentVersion = Get-WorkspaceVersion $SourceRoot
    $currentTag = "v$currentVersion"
    Assert-Test ([regex]::IsMatch(
        $currentVersion,
        '^1\.0\.0-beta(?:\.[1-9][0-9]*)?$'
    )) 'source version is not a canonical v1 beta'
    $sourceChangelog = [IO.File]::ReadAllText(
        (Join-Path $SourceRoot 'CHANGELOG.md'),
        $Utf8NoBom
    )
    $dateMatch = [regex]::Match(
        $sourceChangelog,
        '(?m)^## ' + [regex]::Escape($currentTag) + ' - (?<date>\d{4}-\d{2}-\d{2})$'
    )
    Assert-Test ($dateMatch.Success -and [regex]::Matches(
        $sourceChangelog,
        '(?m)^## ' + [regex]::Escape($currentTag) + ' - \d{4}-\d{2}-\d{2}$'
    ).Count -eq 1) 'source CHANGELOG lacks one dated current release heading'
    $currentReleaseDate = [string]$dateMatch.Groups['date'].Value
    $parsedReleaseDate = [DateTime]::MinValue
    Assert-Test ([DateTime]::TryParseExact(
        $currentReleaseDate,
        'yyyy-MM-dd',
        [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::None,
        [ref]$parsedReleaseDate
    )) 'current CHANGELOG release date is not canonical'

    $releaseTransitions = [System.Collections.Generic.List[object]]::new()
    foreach ($candidateCommit in @(Invoke-GitFixture $SourceRoot @(
        'log', '--first-parent', '--format=%H', '--', 'Cargo.toml'
    ))) {
        $candidateCommit = ([string]$candidateCommit).Trim().ToLowerInvariant()
        Assert-Test ($candidateCommit -match '^[0-9a-f]{40}$') (
            'Cargo.toml history contains a noncanonical commit'
        )
        if ((Get-WorkspaceVersionAtCommit $SourceRoot $candidateCommit) -cne $currentVersion) {
            continue
        }
        $candidateParentLine = ([string](Invoke-GitFixture $SourceRoot @(
            'rev-list', '--parents', '-n', '1', $candidateCommit
        ))).Trim()
        $candidateParentFields = @($candidateParentLine -split ' ')
        if ($candidateParentFields.Count -ne 2 -or
            $candidateParentFields[0] -cne $candidateCommit -or
            $candidateParentFields[1] -notmatch '^[0-9a-f]{40}$') {
            continue
        }
        $candidateParent = [string]$candidateParentFields[1]
        $candidateParentVersion = Get-WorkspaceVersionAtCommit $SourceRoot $candidateParent
        if (Test-NextTransition $candidateParentVersion $currentVersion) {
            $releaseTransitions.Add([pscustomobject]@{
                Commit = $candidateCommit
                Parent = $candidateParent
                ParentVersion = $candidateParentVersion
            })
        }
    }
    Assert-Test ($releaseTransitions.Count -eq 1) (
        "first-parent Cargo.toml history contains $($releaseTransitions.Count) legal transitions into '$currentVersion', expected one"
    )
    $releaseCommit = [string]$releaseTransitions[0].Commit
    $parentCommit = [string]$releaseTransitions[0].Parent
    $identityDrift = @(Invoke-GitFixture $SourceRoot @(
        'diff', '--name-only', $releaseCommit, $sourceHead, '--'
    ) | ForEach-Object { ([string]$_).Replace('\', '/') } | Where-Object {
        $IdentityFiles -ccontains $_
    })
    Assert-Test ($identityDrift.Count -eq 0) (
        'approved release identity outputs drifted after the current release commit'
    )

    $releaseChanged = @(Invoke-GitFixture $SourceRoot @(
        'diff', '--name-only', '--diff-filter=ACMRTUXB', $parentCommit, $releaseCommit, '--'
    ) | ForEach-Object { ([string]$_).Replace('\', '/') } | Sort-Object -Unique)
    Assert-Test ($releaseChanged.Count -gt 0) 'release commit has no identity changes'
    foreach ($relative in $releaseChanged) {
        Assert-Test ($IdentityFiles -ccontains $relative) (
            "release commit changed non-identity path '$relative'"
        )
    }

    $success = New-Fixture 'success' $parentCommit
    $parentVersion = Get-WorkspaceVersion $success
    Assert-NextTransition $parentVersion $currentVersion
    $baselineHead = ([string](Invoke-GitFixture $success @('rev-parse', 'HEAD'))).Trim()
    $baselineTree = ([string](Invoke-GitFixture $success @('rev-parse', 'HEAD^{tree}'))).Trim()
    $neutralReadme = Get-ReadmeCurrentStateNeutralDocument $success
    $neutralGuide = Get-GuideCurrentStateNeutralDocument $success
    $neutralArchitecture = Get-ArchitectureCurrentStateNeutralDocument $success
    $initialChangelogEntry = Get-CurrentChangelogEntryNeutralDocument $success
    $neutralGovernance = [ordered]@{}
    foreach ($binding in @(
        @('docs/v1-beta-release-contract.md', 'release-tag'),
        @('docs/v1-beta-agent-jsonl.md', 'target-release'),
        @('docs/v1-beta-acceptance-matrix.md', 'normative-release')
    )) {
        $neutralGovernance[[string]$binding[0]] = Get-GovernanceCurrentStateNeutralDocument `
            $success ([string]$binding[0]) ([string]$binding[1])
    }
    $neutralSecurity = Get-CurrentSecurityLineNeutralDocument $success
    $rollbackPredecessorLine = '| `v0.3.0-beta.2` | Rollback predecessor during the v1 beta compatibility window; critical fixes only until the v1 beta line is superseded. |'

    & (Join-Path $success 'scripts/Set-V1ReleaseVersion.ps1') `
        -Version $currentVersion -WhatIf -ReleaseDate $currentReleaseDate | Out-Null
    Assert-Test (@(Invoke-GitFixture $success @('status', '--porcelain=v1', '--untracked-files=all')).Count -eq 0) 'WhatIf changed the fixture'

    & (Join-Path $success 'scripts/Set-V1ReleaseVersion.ps1') `
        -Version $currentVersion -Apply -ReleaseDate $currentReleaseDate | Out-Null
    & (Join-Path $success 'scripts/Verify-ReleaseConsistency.ps1') -Tag $currentTag | Out-Null
    Assert-Test ($LASTEXITCODE -eq 0) 'post-Apply Verify-ReleaseConsistency failed'
    Invoke-RealDocumentationGate $success
    Assert-CurrentReleaseBindings $success $currentTag $currentVersion $currentReleaseDate
    Assert-Test (
        (Get-ReadmeCurrentStateNeutralDocument $success) -ceq $neutralReadme
    ) 'initial beta transition changed README outside its explicit current-state regions'
    Assert-Test (
        (Get-GuideCurrentStateNeutralDocument $success) -ceq $neutralGuide
    ) 'initial beta transition changed the user guide outside its explicit current-state regions'
    Assert-Test (
        (Get-ArchitectureCurrentStateNeutralDocument $success) -ceq $neutralArchitecture
    ) 'initial beta transition changed architecture outside its explicit current-state bindings'
    Assert-Test (
        (Get-CurrentChangelogEntryNeutralDocument $success) -ceq $initialChangelogEntry
    ) 'initial beta transition changed CHANGELOG detail outside its heading/current-state prefix'
    foreach ($binding in @(
        @('docs/v1-beta-release-contract.md', 'release-tag'),
        @('docs/v1-beta-agent-jsonl.md', 'target-release'),
        @('docs/v1-beta-acceptance-matrix.md', 'normative-release')
    )) {
        Assert-Test (
            (Get-GovernanceCurrentStateNeutralDocument $success $binding[0] $binding[1]) -ceq
                [string]$neutralGovernance[[string]$binding[0]]
        ) "initial beta transition changed historical prose in $($binding[0])"
    }
    Assert-Test (
        (Get-CurrentSecurityLineNeutralDocument $success) -ceq $neutralSecurity
    ) 'initial beta transition changed SECURITY outside its current support binding'
    Assert-Test (([string](Invoke-GitFixture $success @('rev-parse', 'HEAD'))).Trim() -ceq $baselineHead) 'Apply changed HEAD'
    Assert-Test (([string](Invoke-GitFixture $success @('rev-parse', 'HEAD^{tree}'))).Trim() -ceq $baselineTree) 'Apply changed HEAD tree'
    $successStatus = @(Invoke-GitFixture $success @('status', '--porcelain=v1', '--untracked-files=all'))
    $successPaths = @($successStatus | ForEach-Object {
        ([string]$_).Substring(3).Replace('\', '/')
    } | Sort-Object -Unique)
    Assert-Test (($successPaths -join "`n") -ceq ($releaseChanged -join "`n")) (
        'replayed Apply changed a different path set than the release commit'
    )
    foreach ($relative in $IdentityFiles) {
        $fixtureBytes = [IO.File]::ReadAllBytes((Join-Path $success $relative))
        $sourceBytes = [IO.File]::ReadAllBytes((Join-Path $SourceRoot $relative))
        Assert-Test ([System.Linq.Enumerable]::SequenceEqual(
            [byte[]]$fixtureBytes,
            [byte[]]$sourceBytes
        )) "replayed identity output differs byte-for-byte for $relative"
    }
    Invoke-GitFixture $success @('add', '--all') | Out-Null
    Invoke-GitFixture $success @('commit', '-m', 'replayed current release identity') | Out-Null

    $fixtureVersion = $currentVersion
    $fixtureDate = $parsedReleaseDate
    $completedVersions = [System.Collections.Generic.List[string]]::new()
    $completedVersions.Add($currentVersion)
    for ($step = 1; $step -le 2; $step++) {
        $priorChangelog = [IO.File]::ReadAllText(
            (Join-Path $success 'CHANGELOG.md'),
            $Utf8NoBom
        )
        $priorHistoryStart = [regex]::Match($priorChangelog, '(?m)^## ')
        Assert-Test $priorHistoryStart.Success 'prior CHANGELOG has no dated release history'
        $priorHistory = $priorChangelog.Substring($priorHistoryStart.Index)
        $targetVersion = Get-NextBetaVersion $fixtureVersion
        $targetTag = "v$targetVersion"
        $targetDate = $fixtureDate.AddDays(1).ToString(
            'yyyy-MM-dd',
            [Globalization.CultureInfo]::InvariantCulture
        )
        Prepare-NextBetaFixture $success "v$fixtureVersion" $targetTag
        Invoke-GitFixture $success @('add', '--all') | Out-Null
        Invoke-GitFixture $success @('commit', '-m', "prepare $targetTag") | Out-Null
        $preparedChangelogEntry = Get-CurrentChangelogEntryNeutralDocument $success

        & (Join-Path $success 'scripts/Set-V1ReleaseVersion.ps1') `
            -Version $targetVersion -Apply -ReleaseDate $targetDate | Out-Null
        & (Join-Path $success 'scripts/Verify-ReleaseConsistency.ps1') `
            -Tag $targetTag | Out-Null
        Assert-Test ($LASTEXITCODE -eq 0) "verification failed for $targetTag"
        Invoke-RealDocumentationGate $success
        Assert-CurrentReleaseBindings $success $targetTag $targetVersion $targetDate
        Assert-Test (
            (Get-ReadmeCurrentStateNeutralDocument $success) -ceq $neutralReadme
        ) "$targetTag changed README outside current-state regions"
        Assert-Test (
            (Get-GuideCurrentStateNeutralDocument $success) -ceq $neutralGuide
        ) "$targetTag changed the user guide outside current-state regions"
        Assert-Test (
            (Get-ArchitectureCurrentStateNeutralDocument $success) -ceq $neutralArchitecture
        ) "$targetTag changed architecture outside current-state regions"
        Assert-Test (
            (Get-CurrentChangelogEntryNeutralDocument $success) -ceq $preparedChangelogEntry
        ) "$targetTag changed CHANGELOG outside its heading/current-state prefix"
        $afterChangelog = [IO.File]::ReadAllText(
            (Join-Path $success 'CHANGELOG.md'),
            $Utf8NoBom
        )
        Assert-Test ($afterChangelog.EndsWith($priorHistory)) (
            "$targetTag modified prior dated CHANGELOG history"
        )
        foreach ($binding in @(
            @('docs/v1-beta-release-contract.md', 'release-tag'),
            @('docs/v1-beta-agent-jsonl.md', 'target-release'),
            @('docs/v1-beta-acceptance-matrix.md', 'normative-release')
        )) {
            Assert-Test (
                (Get-GovernanceCurrentStateNeutralDocument $success $binding[0] $binding[1]) -ceq
                    [string]$neutralGovernance[[string]$binding[0]]
            ) "$targetTag modified historical prose in $($binding[0])"
        }
        $security = [IO.File]::ReadAllText(
            (Join-Path $success 'SECURITY.md'),
            $Utf8NoBom
        )
        Assert-Test (
            (Get-CurrentSecurityLineNeutralDocument $success) -ceq $neutralSecurity -and
            $security.Contains($rollbackPredecessorLine)
        ) "$targetTag modified SECURITY history or its rollback predecessor"
        $transitionStatus = @(Invoke-GitFixture $success @(
            'status', '--porcelain=v1', '--untracked-files=all'
        ))
        $transitionPaths = @($transitionStatus | ForEach-Object {
            ([string]$_).Substring(3).Replace('\', '/')
        } | Sort-Object -Unique)
        Assert-Test (($transitionPaths -join "`n") -ceq (($IdentityFiles | Sort-Object) -join "`n")) (
            "$targetTag did not leave the exact approved identity path set"
        )
        Invoke-GitFixture $success @('add', '--all') | Out-Null
        Invoke-GitFixture $success @('commit', '-m', "freeze $targetTag") | Out-Null
        $fixtureVersion = $targetVersion
        $fixtureDate = [DateTime]::ParseExact(
            $targetDate,
            'yyyy-MM-dd',
            [Globalization.CultureInfo]::InvariantCulture
        )
        $completedVersions.Add($targetVersion)
    }

    $previousVersion = [string]$completedVersions[$completedVersions.Count - 2]
    $jumpVersion = Get-NextBetaVersion (Get-NextBetaVersion $fixtureVersion)
    Assert-VersionSwitchRejected $success $fixtureVersion 'same beta version'
    Assert-VersionSwitchRejected $success $previousVersion 'beta downgrade'
    Assert-VersionSwitchRejected $success $jumpVersion 'beta ordinal jump'
    Assert-VersionSwitchRejected $success '1.0.0-beta.0' 'beta zero ordinal'
    Assert-VersionSwitchRejected $success '1.0.0-beta.03' 'beta leading-zero ordinal'
    $verifyBetaZeroRejected = $false
    try {
        & (Join-Path $success 'scripts/Verify-ReleaseConsistency.ps1') `
            -Tag v1.0.0-beta.0 | Out-Null
    }
    catch { $verifyBetaZeroRejected = $true }
    Assert-Test $verifyBetaZeroRejected 'release verifier accepted beta.0'

    $initialSkip = New-Fixture 'initial-skip' $parentCommit
    Assert-VersionSwitchRejected $initialSkip (Get-NextBetaVersion $currentVersion) (
        'first-parent immediate-transition skip'
    )

    $failure = New-Fixture 'failure' $parentCommit
    Write-Utf8 (Join-Path $failure '.serctl-version-switch-test-fixture') (
        "SERCTL_VERSION_SWITCH_TEST_FIXTURE_V1`n"
    )
    Invoke-GitFixture $failure @('add', '--all') | Out-Null
    Invoke-GitFixture $failure @('commit', '-m', 'enable fixture-only failure injection') | Out-Null
    $failureHashes = Get-TrackedHashes $failure
    $failed = $false
    try {
        & (Join-Path $failure 'scripts/Set-V1ReleaseVersion.ps1') `
            -Version $currentVersion -Apply -ReleaseDate $currentReleaseDate `
            -TestFixture -InjectFailureAfterWrites 3 | Out-Null
    }
    catch {
        $failed = $true
    }
    Assert-Test $failed 'failure injection unexpectedly succeeded'
    Assert-Test (@(Invoke-GitFixture $failure @('status', '--porcelain=v1', '--untracked-files=all')).Count -eq 0) 'failure injection did not restore clean status'
    $restoredHashes = Get-TrackedHashes $failure
    Assert-Test ($restoredHashes.Count -eq $failureHashes.Count) 'rollback changed the tracked file set'
    foreach ($relative in $failureHashes.Keys) {
        Assert-Test ([string]$restoredHashes[$relative] -ceq [string]$failureHashes[$relative]) "rollback changed bytes for $relative"
    }

    [IO.File]::AppendAllText(
        (Join-Path $failure 'README.md'),
        "`n<!-- release-marker: v$parentVersion -->`n",
        $Utf8NoBom
    )
    Invoke-GitFixture $failure @('add', 'README.md') | Out-Null
    Invoke-GitFixture $failure @('commit', '-m', 'duplicate marker fixture') | Out-Null
    $duplicateRejected = $false
    try {
        & (Join-Path $failure 'scripts/Set-V1ReleaseVersion.ps1') `
            -Version $currentVersion -WhatIf -ReleaseDate $currentReleaseDate -TestFixture | Out-Null
    }
    catch {
        $duplicateRejected = $true
    }
    Assert-Test $duplicateRejected 'duplicate old current marker was not rejected'

    $sourceHeadAfter = ([string](Invoke-GitFixture $SourceRoot @('rev-parse', 'HEAD'))).Trim().ToLowerInvariant()
    $sourceStatusAfter = @(Invoke-GitFixture $SourceRoot @(
        'status', '--porcelain=v1', '--untracked-files=all'
    ))
    Assert-Test ($sourceHeadAfter -ceq $sourceHead) 'source HEAD changed during local-clone replay'
    Assert-Test ($sourceStatusAfter.Count -eq 0) 'source checkout changed during local-clone replay'

    Write-Output (
        "V1 release version switch local-clone replay self-test: PASS " +
        "($parentVersion -> $currentVersion -> $($completedVersions[1]) -> $($completedVersions[2]))"
    )
}
finally {
    if (Test-Path -LiteralPath $TestRoot -PathType Container) {
        $tokenPath = Join-Path $TestRoot 'owner-token'
        if ((Test-Path -LiteralPath $tokenPath -PathType Leaf) -and
            ([System.IO.File]::ReadAllText($tokenPath, $Utf8NoBom) -ceq $OwnerToken)) {
            Remove-Item -LiteralPath $TestRoot -Recurse -Force
        }
    }
}
