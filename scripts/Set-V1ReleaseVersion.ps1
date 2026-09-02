[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^1\.0\.0-beta(?:\.[1-9][0-9]*)?$')]
    [string]$Version,

    [switch]$WhatIf,

    [switch]$Apply,

    [ValidatePattern('^\d{4}-\d{2}-\d{2}$')]
    [string]$ReleaseDate,

    [switch]$TestFixture,

    [ValidateRange(0, 32)]
    [int]$InjectFailureAfterWrites = 0
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Utf8NoBom = New-Object System.Text.UTF8Encoding($false, $true)
$TargetTag = "v$Version"
$RepositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$FixtureMarker = Join-Path $RepositoryRoot '.serctl-version-switch-test-fixture'

if ($null -eq ('SerctlVersionSwitchNative' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class SerctlVersionSwitchNative {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    public static extern bool MoveFileEx(string existingPath, string newPath, uint flags);

    [DllImport("libc", SetLastError = true)]
    public static extern int rename(string oldPath, string newPath);
}
'@
}

function Fail-VersionSwitch {
    param([Parameter(Mandatory = $true)][string]$Message)
    throw "controlled version switch failed: $Message"
}

function Assert-Condition {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if (-not $Condition) {
        Fail-VersionSwitch $Message
    }
}

function Expand-AsciiUnicode {
    param([Parameter(Mandatory = $true)][string]$Value)
    return [regex]::Unescape($Value)
}

function Resolve-Application {
    param([Parameter(Mandatory = $true)][string]$Name)
    Assert-Condition ($Name -match '^[A-Za-z0-9._-]+$') 'application name contains wildcard or path syntax'
    $command = Get-Command $Name -CommandType Application -ErrorAction Stop | Select-Object -First 1
    Assert-Condition ($null -ne $command) "'$Name' did not resolve to an application"
    return [System.IO.Path]::GetFullPath([string]$command.Source)
}

function Invoke-Git {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)
    $savedPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $output = @(& $script:GitPath @Arguments 2>&1)
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $savedPreference
    }
    if ($exitCode -ne 0) {
        Fail-VersionSwitch "git command failed"
    }
    return $output
}

function Read-Text {
    param([Parameter(Mandatory = $true)][string]$Path)
    return [System.IO.File]::ReadAllText($Path, $script:Utf8NoBom)
}

function Get-BytesHash {
    param([Parameter(Mandatory = $true)][byte[]]$Bytes)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-', '').ToLowerInvariant()
    }
    finally {
        $sha.Dispose()
    }
}

function Get-FileHashExact {
    param([Parameter(Mandatory = $true)][string]$Path)
    return Get-BytesHash ([System.IO.File]::ReadAllBytes($Path))
}

function Replace-ExactLiteral {
    param(
        [Parameter(Mandatory = $true)][string]$Content,
        [Parameter(Mandatory = $true)][string]$Old,
        [Parameter(Mandatory = $true)][string]$New,
        [Parameter(Mandatory = $true)][int]$ExpectedCount,
        [Parameter(Mandatory = $true)][string]$Description
    )
    $count = ([regex]::Matches(
        $Content,
        [regex]::Escape($Old),
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    )).Count
    Assert-Condition ($count -eq $ExpectedCount) "$Description count is $count, expected $ExpectedCount"
    return $Content.Replace($Old, $New)
}

function Replace-ExactLiteralOrAssertTarget {
    param(
        [Parameter(Mandatory = $true)][string]$Content,
        [Parameter(Mandatory = $true)][string]$Old,
        [Parameter(Mandatory = $true)][string]$New,
        [Parameter(Mandatory = $true)][int]$ExpectedCount,
        [Parameter(Mandatory = $true)][string]$Description
    )
    Assert-Condition ($Old -cne $New) "$Description old and target bindings are identical"
    $oldCount = ([regex]::Matches(
        $Content,
        [regex]::Escape($Old),
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    )).Count
    $newCount = ([regex]::Matches(
        $Content,
        [regex]::Escape($New),
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    )).Count
    if ($oldCount -eq $ExpectedCount -and $newCount -eq 0) {
        return $Content.Replace($Old, $New)
    }
    Assert-Condition (
        $oldCount -eq 0 -and $newCount -eq $ExpectedCount
    ) "$Description is not bound exactly $ExpectedCount time(s) to either the prior or target value"
    return $Content
}

function Replace-ExactRegex {
    param(
        [Parameter(Mandatory = $true)][string]$Content,
        [Parameter(Mandatory = $true)][string]$Pattern,
        [Parameter(Mandatory = $true)][string]$Replacement,
        [Parameter(Mandatory = $true)][int]$ExpectedCount,
        [Parameter(Mandatory = $true)][string]$Description
    )
    $regex = New-Object System.Text.RegularExpressions.Regex(
        $Pattern,
        ([System.Text.RegularExpressions.RegexOptions]::Multiline -bor
            [System.Text.RegularExpressions.RegexOptions]::CultureInvariant)
    )
    $matches = $regex.Matches($Content)
    Assert-Condition ($matches.Count -eq $ExpectedCount) "$Description count is $($matches.Count), expected $ExpectedCount"
    return $regex.Replace($Content, $Replacement)
}

function Write-TextReplace {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Content,
        [Parameter(Mandatory = $true)][string]$Token
    )
    $temporary = Join-Path ([System.IO.Path]::GetDirectoryName($Path)) ('.serctl-version-switch-' + $Token + '.tmp')
    $stream = New-Object System.IO.FileStream(
        $temporary,
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None,
        4096,
        [System.IO.FileOptions]::WriteThrough
    )
    try {
        $bytes = $script:Utf8NoBom.GetBytes($Content)
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally {
        $stream.Dispose()
    }
    try {
        if ([System.IO.Path]::DirectorySeparatorChar -eq '\') {
            $moveFileReplaceExisting = [uint32]0x1
            $moveFileWriteThrough = [uint32]0x8
            $replaced = [SerctlVersionSwitchNative]::MoveFileEx(
                $temporary,
                $Path,
                ($moveFileReplaceExisting -bor $moveFileWriteThrough)
            )
            if (-not $replaced) {
                throw (New-Object System.ComponentModel.Win32Exception([Runtime.InteropServices.Marshal]::GetLastWin32Error()))
            }
        }
        else {
            $renamed = [SerctlVersionSwitchNative]::rename($temporary, $Path)
            if ($renamed -ne 0) {
                throw (New-Object System.ComponentModel.Win32Exception([Runtime.InteropServices.Marshal]::GetLastWin32Error()))
            }
        }
    }
    finally {
        if (Test-Path -LiteralPath $temporary) {
            Remove-Item -LiteralPath $temporary -Force
        }
    }
}

function Get-RepositoryIdentity {
    $head = ([string](Invoke-Git @('rev-parse', 'HEAD'))).Trim().ToLowerInvariant()
    $tree = ([string](Invoke-Git @('rev-parse', 'HEAD^{tree}'))).Trim().ToLowerInvariant()
    $status = @((Invoke-Git @('status', '--porcelain=v1', '--untracked-files=all')))
    Assert-Condition ($head -match '^[0-9a-f]{40}$') 'HEAD is not a full commit id'
    Assert-Condition ($tree -match '^[0-9a-f]{40}$') 'HEAD tree is not a full tree id'
    return [pscustomobject]@{ Head = $head; Tree = $tree; Status = $status }
}

function Assert-CleanIdentity {
    param([Parameter(Mandatory = $true)]$Identity)
    Assert-Condition ($Identity.Status.Count -eq 0) 'source snapshot is not clean'
}

function New-TransformationPlan {
    param(
        [Parameter(Mandatory = $true)][string]$OldVersion,
        [Parameter(Mandatory = $true)][string[]]$WorkspaceNames
    )
    $oldTag = "v$OldVersion"
    $plan = [ordered]@{}

    $cargoPath = Join-Path $RepositoryRoot 'Cargo.toml'
    $cargo = Read-Text $cargoPath
    $workspaceVersionPattern = '^(version\s*=\s*")' + [regex]::Escape($OldVersion) + '("\s*)$'
    $cargo = Replace-ExactRegex $cargo $workspaceVersionPattern ('${1}' + $Version + '${2}') 1 'workspace package version'
    $oldRequirement = "version = `"=$OldVersion`""
    $newRequirement = "version = `"=$Version`""
    $requirementLines = @([regex]::Matches(
        $cargo,
        '(?m)^serctl-[a-z0-9-]+\s*=\s*\{[^\r\n]*version\s*=\s*"=' + [regex]::Escape($OldVersion) + '"[^\r\n]*path\s*=',
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    ))
    Assert-Condition ($requirementLines.Count -gt 0) 'Cargo.toml has no old exact internal requirements'
    $allOldRequirements = ([regex]::Matches(
        $cargo,
        [regex]::Escape($oldRequirement),
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    )).Count
    Assert-Condition ($allOldRequirements -eq $requirementLines.Count) 'an old exact requirement is outside an internal path dependency'
    $cargo = $cargo.Replace($oldRequirement, $newRequirement)
    $plan['Cargo.toml'] = $cargo

    $lockPath = Join-Path $RepositoryRoot 'Cargo.lock'
    $lock = Read-Text $lockPath
    foreach ($name in $WorkspaceNames) {
        $pattern = '(?ms)(^\[\[package\]\]\r?\n(?:(?!^\[\[package\]\]).)*?^name = "' +
            [regex]::Escape($name) + '"\r?\n(?:(?!^\[\[package\]\]).)*?^version = ")' +
            [regex]::Escape($OldVersion) + '("\s*$)'
        $lock = Replace-ExactRegex $lock $pattern ('${1}' + $Version + '${2}') 1 "Cargo.lock workspace package $name"
    }
    $plan['Cargo.lock'] = $lock

    $fuzzManifestPath = Join-Path $RepositoryRoot 'fuzz/Cargo.toml'
    $fuzzManifest = Read-Text $fuzzManifestPath
    $fuzzWorkspaceNames = @([regex]::Matches(
        $fuzzManifest,
        '(?m)^(?<name>[A-Za-z0-9_-]+)\s*=\s*\{[^\r\n]*\bpath\s*=',
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    ) | ForEach-Object { $_.Groups['name'].Value } | Sort-Object -Unique)
    Assert-Condition ($fuzzWorkspaceNames.Count -gt 0) 'fuzz/Cargo.toml has no internal path dependencies'
    foreach ($name in $fuzzWorkspaceNames) {
        Assert-Condition ($WorkspaceNames -ccontains $name) "fuzz/Cargo.toml path-depends on non-workspace package $name"
    }

    $fuzzLockPath = Join-Path $RepositoryRoot 'fuzz/Cargo.lock'
    $fuzzLock = Read-Text $fuzzLockPath
    foreach ($name in $fuzzWorkspaceNames) {
        $pattern = '(?ms)(^\[\[package\]\]\r?\n(?:(?!^\[\[package\]\]).)*?^name = "' +
            [regex]::Escape($name) + '"\r?\n(?:(?!^\[\[package\]\]).)*?^version = ")' +
            [regex]::Escape($OldVersion) + '("\s*$)'
        $fuzzLock = Replace-ExactRegex $fuzzLock $pattern ('${1}' + $Version + '${2}') 1 "fuzz/Cargo.lock workspace package $name"
    }
    $plan['fuzz/Cargo.lock'] = $fuzzLock

    $changelogPath = Join-Path $RepositoryRoot 'CHANGELOG.md'
    $changelog = Read-Text $changelogPath
    $changelog = Replace-ExactLiteral $changelog "## $TargetTag - Unreleased" "## $TargetTag - $ReleaseDate" 1 'v1 Unreleased heading'
    $changelogOldStatus = (Expand-AsciiUnicode (
        '> **\u5019\u9009\u72B6\u6001\uFF08\u5C1A\u672A\u9A8C\u6536/\u53D1\u5E03\uFF09**\uFF1A' +
        '\u5F53\u524D workspace \u4E0E\u6B63\u5F0F\u53D1\u5E03\u6807\u8BB0\u4ECD\u4FDD\u6301 `{0}`\uFF0C' +
        '\u5F85 Rust \u96C6\u6210\u3001exact-tag CI\u3001\u53D7\u63A7\u5B9E\u673A\u548C\u4ED3\u5E93' +
        '\u6CBB\u7406\u95E8\u7981\u5168\u90E8\u901A\u8FC7\u540E\u518D\u7EDF\u4E00\u5207\u6362\u3002'
    )) -f $oldTag
    $changelogTargetStatus = (Expand-AsciiUnicode (
        '> **\u5019\u9009\u72B6\u6001\uFF08\u5C1A\u672A\u9A8C\u6536/\u53D1\u5E03\uFF09**\uFF1A' +
        '\u5F53\u524D workspace \u4E0E\u9884\u53D1\u5E03\u6807\u8BB0\u5DF2\u540C\u6B65\u4E3A `{0}`\uFF1B' +
        'exact-tag CI\u3001\u53D7\u63A7\u5B9E\u673A\u548C\u4ED3\u5E93\u6CBB\u7406\u95E8\u7981' +
        '\u4ECD\u987B\u901A\u8FC7\u540E\u65B9\u53EF\u53D1\u5E03\u3002'
    )) -f $TargetTag
    $changelog = Replace-ExactLiteral `
        $changelog $changelogOldStatus $changelogTargetStatus 1 'CHANGELOG current-state prefix'
    $plan['CHANGELOG.md'] = $changelog

    $readmePath = Join-Path $RepositoryRoot 'README.md'
    $readme = Read-Text $readmePath
    $readmeVisiblePattern = '^(?<prefix>[^\r\n]*\*\*)' +
        [regex]::Escape($oldTag) + '(?<suffix>\*\*[^\r\n]*V1[^\r\n]*)$'
    $readme = Replace-ExactRegex $readme $readmeVisiblePattern (
        '${prefix}' + $TargetTag + '${suffix}'
    ) 1 'README visible current version'
    $readme = Replace-ExactLiteral $readme "<!-- release-marker: $oldTag -->" "<!-- release-marker: $TargetTag -->" 1 'README release marker'
    $readmeCandidateOld = (Expand-AsciiUnicode '> \u5DE5\u4F5C\u6811\u4E2D\u7684 **{0} \u5019\u9009\u5C1A\u672A\u9A8C\u6536\u6216\u53D1\u5E03**\u3002') -f $oldTag
    $readmeCandidateTarget = (Expand-AsciiUnicode '> \u5DE5\u4F5C\u6811\u4E2D\u7684 **{0} \u5019\u9009\u5C1A\u672A\u9A8C\u6536\u6216\u53D1\u5E03**\u3002') -f $TargetTag
    $readme = Replace-ExactLiteralOrAssertTarget `
        $readme $readmeCandidateOld $readmeCandidateTarget 1 'README candidate identity'
    $readmeStatusOld = (
        (Expand-AsciiUnicode '\u5F53\u524D\u7248\u672C\u6807\u8BB0\u5728 Cargo\u3001lockfile\u3001CHANGELOG\u3001README\u3001\u7528\u6237\u6307\u5357\u548C\u67B6\u6784\u9875\u7EDF\u4E00\u5207\u6362\u524D\u4ECD\u4FDD\u6301 {0}') -f $oldTag
    )
    if ($oldTag -match '^v1\.0\.0-beta') {
        $readmeStatusOld = (Expand-AsciiUnicode '\u5F53\u524D workspace \u4E0E\u9884\u53D1\u5E03\u6807\u8BB0\u5DF2\u540C\u6B65\u4E3A {0}') -f $oldTag
    }
    $readmeStatusTarget = (Expand-AsciiUnicode '\u5F53\u524D workspace \u4E0E\u9884\u53D1\u5E03\u6807\u8BB0\u5DF2\u540C\u6B65\u4E3A {0}') -f $TargetTag
    $readme = Replace-ExactLiteral `
        $readme $readmeStatusOld $readmeStatusTarget 1 'README current-state clause'
    $readmeBoundaryOld = if ($oldTag -match '^v1\.0\.0-beta') {
        (Expand-AsciiUnicode '\u5F53\u524D\u9884\u53D1\u5E03\u7248\u672C\u6807\u8BB0\u4E3A `{0}`\uFF1B\u8BE5\u7248\u672C\u4ECD\u662F\u672A\u53D1\u5E03\u5019\u9009\u3002') -f $oldTag
    }
    else {
        (Expand-AsciiUnicode '\u5F53\u524D\u6B63\u5F0F\u7248\u672C\u6807\u8BB0\u4ECD\u51BB\u7ED3\u4E3A `{0}`\uFF1B\u5DE5\u4F5C\u6811\u4E2D\u7684 `{1}` \u53EA\u662F\u672A\u53D1\u5E03\u5019\u9009\u3002') -f $oldTag, $TargetTag
    }
    $readmeBoundaryTarget = (Expand-AsciiUnicode '\u5F53\u524D\u9884\u53D1\u5E03\u7248\u672C\u6807\u8BB0\u4E3A `{0}`\uFF1B\u8BE5\u7248\u672C\u4ECD\u662F\u672A\u53D1\u5E03\u5019\u9009\u3002') -f $TargetTag
    $readme = Replace-ExactLiteral `
        $readme $readmeBoundaryOld $readmeBoundaryTarget 1 'README release-boundary prefix'
    $readmeWorkflowOld = (Expand-AsciiUnicode '\u6B63\u5F0F\u9884\u53D1\u5E03\u4EC5\u7531 exact annotated tag `{0}` \u89E6\u53D1\u4E13\u7528 workflow') -f $oldTag
    $readmeWorkflowTarget = (Expand-AsciiUnicode '\u6B63\u5F0F\u9884\u53D1\u5E03\u4EC5\u7531 exact annotated tag `{0}` \u89E6\u53D1\u4E13\u7528 workflow') -f $TargetTag
    $readme = Replace-ExactLiteralOrAssertTarget `
        $readme $readmeWorkflowOld $readmeWorkflowTarget 1 'README workflow tag binding'
    $plan['README.md'] = $readme

    $guidePath = Join-Path $RepositoryRoot 'docs/serctl-user-guide.md'
    $guide = Read-Text $guidePath
    $guideHeaderPattern = '\A(?<heading># [^\r\n]+\r?\n\r?\n)(?<prefix>[^\r\n]*`)' +
        [regex]::Escape($oldTag) + '(?<suffix>`[^\r\n]*)'
    $guide = Replace-ExactRegex $guide $guideHeaderPattern (
        '${heading}${prefix}' + $TargetTag + '${suffix}'
    ) 1 'user-guide visible version'
    $guide = Replace-ExactLiteral $guide "<!-- applicable-version: $oldTag -->" "<!-- applicable-version: $TargetTag -->" 1 'user-guide version marker'
    $guideStatusOld = if ($oldTag -match '^v1\.0\.0-beta') {
        (Expand-AsciiUnicode '> \u5F53\u524D\u9884\u53D1\u5E03\u6807\u8BB0\u5DF2\u540C\u6B65\u4E3A {0}\uFF1B\u8BE5\u5019\u9009\u5C1A\u672A\u9A8C\u6536\u6216\u53D1\u5E03\u3002') -f $oldTag
    }
    else {
        (Expand-AsciiUnicode '> \u5F53\u524D\u53D1\u5E03\u6807\u8BB0\u4ECD\u4E3A {0}\uFF1B\u5DE5\u4F5C\u6811\u4E2D\u7684 {1} \u5019\u9009\u5C1A\u672A\u9A8C\u6536\u6216\u53D1\u5E03\u3002') -f $oldTag, $TargetTag
    }
    $guideStatusTarget = (Expand-AsciiUnicode '> \u5F53\u524D\u9884\u53D1\u5E03\u6807\u8BB0\u5DF2\u540C\u6B65\u4E3A {0}\uFF1B\u8BE5\u5019\u9009\u5C1A\u672A\u9A8C\u6536\u6216\u53D1\u5E03\u3002') -f $TargetTag
    $guide = Replace-ExactLiteral `
        $guide $guideStatusOld $guideStatusTarget 1 'user-guide current-state prefix'
    $guideCapabilityOld = (Expand-AsciiUnicode '\u4EE5\u4E0A\u65B0\u589E schema/error/transfer/tunnel/connection-identity \u884C\u4E3A\u5C5E\u4E8E {0} \u5019\u9009') -f $oldTag
    $guideCapabilityTarget = (Expand-AsciiUnicode '\u4EE5\u4E0A\u65B0\u589E schema/error/transfer/tunnel/connection-identity \u884C\u4E3A\u5C5E\u4E8E {0} \u5019\u9009') -f $TargetTag
    $guide = Replace-ExactLiteralOrAssertTarget `
        $guide $guideCapabilityOld $guideCapabilityTarget 1 'user-guide capability candidate identity'
    $guideTailOld = if ($oldTag -match '^v1\.0\.0-beta') {
        (Expand-AsciiUnicode '\u5F53\u524D\u9884\u53D1\u5E03\u6807\u8BB0\u5DF2\u540C\u6B65\u4E3A {0}\uFF0C\u4F46\u4E0D\u56E0\u6B64\u89C6\u4E3A\u5DF2\u9A8C\u6536\u3002') -f $oldTag
    }
    else {
        (Expand-AsciiUnicode '\u5F53\u524D {0} \u53D1\u5E03\u6807\u8BB0\u4E0D\u56E0\u6B64\u88AB\u6539\u5199\u3002') -f $oldTag
    }
    $guideTailTarget = (Expand-AsciiUnicode '\u5F53\u524D\u9884\u53D1\u5E03\u6807\u8BB0\u5DF2\u540C\u6B65\u4E3A {0}\uFF0C\u4F46\u4E0D\u56E0\u6B64\u89C6\u4E3A\u5DF2\u9A8C\u6536\u3002') -f $TargetTag
    $guide = Replace-ExactLiteral `
        $guide $guideTailOld $guideTailTarget 1 'user-guide capability acceptance boundary'
    $plan['docs/serctl-user-guide.md'] = $guide

    $architecturePath = Join-Path $RepositoryRoot 'docs/serctl-architecture-security.html'
    $architecture = Read-Text $architecturePath
    $architectureOldPattern = '(?<prefix>data-release-candidate=")' +
        [regex]::Escape($oldTag) + '(?<middle>">[^<]*<code>)' +
        [regex]::Escape($oldTag) + '(?<suffix></code>)'
    $architectureTargetPattern = 'data-release-candidate="' +
        [regex]::Escape($TargetTag) + '">[^<]*<code>' +
        [regex]::Escape($TargetTag) + '</code>'
    $architectureOldCount = ([regex]::Matches($architecture, $architectureOldPattern)).Count
    $architectureTargetCount = ([regex]::Matches($architecture, $architectureTargetPattern)).Count
    if ($architectureOldCount -eq 1 -and $architectureTargetCount -eq 0) {
        $architecture = Replace-ExactRegex $architecture $architectureOldPattern (
            '${prefix}' + $TargetTag + '${middle}' + $TargetTag + '${suffix}'
        ) 1 'architecture current candidate marker'
    }
    else {
        Assert-Condition (
            $architectureOldCount -eq 0 -and $architectureTargetCount -eq 1
        ) 'architecture current candidate marker is not bound exactly once to either the prior or target tag'
    }
    foreach ($binding in @(
        @(((Expand-AsciiUnicode '<strong>{0} \u5019\u9009\uFF0C\u5C1A\u672A\u9A8C\u6536</strong>') -f $oldTag), ((Expand-AsciiUnicode '<strong>{0} \u5019\u9009\uFF0C\u5C1A\u672A\u9A8C\u6536</strong>') -f $TargetTag), 'architecture status-card tag'),
        @(((Expand-AsciiUnicode '\u53EA\u6709 exact annotated clean tag <code>{0}</code> \u4E0A') -f $oldTag), ((Expand-AsciiUnicode '\u53EA\u6709 exact annotated clean tag <code>{0}</code> \u4E0A') -f $TargetTag), 'architecture artifact-boundary tag'),
        @(((Expand-AsciiUnicode 'v1 beta \u53D1\u5E03\u94FE\u53EA\u54CD\u5E94\u89C4\u8303 annotated tag <code>{0}</code>') -f $oldTag), ((Expand-AsciiUnicode 'v1 beta \u53D1\u5E03\u94FE\u53EA\u54CD\u5E94\u89C4\u8303 annotated tag <code>{0}</code>') -f $TargetTag), 'architecture workflow tag'),
        @(((Expand-AsciiUnicode '\u7684 <code>{0}</code> \u5019\u9009\u3001vault-storage') -f $oldTag), ((Expand-AsciiUnicode '\u7684 <code>{0}</code> \u5019\u9009\u3001vault-storage') -f $TargetTag), 'architecture footer tag')
    )) {
        $architecture = Replace-ExactLiteralOrAssertTarget `
            $architecture ([string]$binding[0]) ([string]$binding[1]) 1 ([string]$binding[2])
    }
    $plan['docs/serctl-architecture-security.html'] = $architecture

    # On the initial 0.3 -> v1 beta transition these governance documents are
    # already staged for the target tag.  A beta repair starts from the prior
    # immutable beta tag, so advance each exact binding once without touching
    # historical prose or accepting a third identity.
    foreach ($binding in @(
        @('docs/v1-beta-release-contract.md', "<!-- release-tag: $oldTag -->", "<!-- release-tag: $TargetTag -->", 'release contract machine marker'),
        @('docs/v1-beta-agent-jsonl.md', "<!-- target-release: $oldTag -->", "<!-- target-release: $TargetTag -->", 'Agent contract machine marker'),
        @('docs/v1-beta-acceptance-matrix.md', "<!-- normative-release: $oldTag -->", "<!-- normative-release: $TargetTag -->", 'acceptance matrix machine marker')
    )) {
        $relative = [string]$binding[0]
        $path = Join-Path $RepositoryRoot $relative
        $content = Read-Text $path
        $oldLiteral = [string]$binding[1]
        $targetLiteral = [string]$binding[2]
        $oldCount = ([regex]::Matches($content, [regex]::Escape($oldLiteral))).Count
        $targetCount = ([regex]::Matches($content, [regex]::Escape($targetLiteral))).Count
        if ($oldCount -eq 1 -and $targetCount -eq 0) {
            $plan[$relative] = Replace-ExactLiteral `
                $content $oldLiteral $targetLiteral 1 ([string]$binding[3])
        }
        else {
            Assert-Condition ($oldCount -eq 0 -and $targetCount -eq 1) (
                "$($binding[3]) is not bound exactly once to either the prior or target tag"
            )
            $plan[$relative] = $content
        }
    }
    $releaseContract = [string]$plan['docs/v1-beta-release-contract.md']
    $releaseContract = Replace-ExactLiteralOrAssertTarget `
        $releaseContract "  `"tag`": `"$oldTag`"," "  `"tag`": `"$TargetTag`"," 2 'release-contract JSON tag examples'
    $releaseContract = Replace-ExactLiteralOrAssertTarget `
        $releaseContract "scripts/New-IsolatedCandidate.ps1 -Version $OldVersion" "scripts/New-IsolatedCandidate.ps1 -Version $Version" 1 'release-contract candidate command'
    $releaseContract = Replace-ExactLiteralOrAssertTarget `
        $releaseContract "target/candidates/$oldTag-<12-character-HEAD>" "target/candidates/$TargetTag-<12-character-HEAD>" 1 'release-contract candidate path'
    $plan['docs/v1-beta-release-contract.md'] = $releaseContract

    $agentContract = [string]$plan['docs/v1-beta-agent-jsonl.md']
    $agentContract = Replace-ExactLiteralOrAssertTarget `
        $agentContract "Target release: ``$oldTag`` (candidate, not accepted or published)" "Target release: ``$TargetTag`` (candidate, not accepted or published)" 1 'Agent contract target release'
    $agentStatusOld = if ($oldTag -match '^v1\.0\.0-beta') {
        "The current workspace/release marker is ``$oldTag``; exact-tag acceptance gates still control support and publication."
    }
    else {
        "The current workspace/release marker remains ``$oldTag`` until the exact-tag acceptance gates pass."
    }
    $agentStatusTarget = "The current workspace/release marker is ``$TargetTag``; exact-tag acceptance gates still control support and publication."
    $agentContract = Replace-ExactLiteral `
        $agentContract $agentStatusOld $agentStatusTarget 1 'Agent contract current-state sentence'
    $plan['docs/v1-beta-agent-jsonl.md'] = $agentContract

    $acceptanceMatrix = [string]$plan['docs/v1-beta-acceptance-matrix.md']
    foreach ($binding in @(
        @("This matrix is normative for ``$oldTag``.", "This matrix is normative for ``$TargetTag``.", 'acceptance-matrix normative tag'),
        @("- [ ] ``scripts/Verify-ReleaseConsistency.ps1 -Tag $oldTag -RequireGitTag``", "- [ ] ``scripts/Verify-ReleaseConsistency.ps1 -Tag $TargetTag -RequireGitTag``", 'acceptance-matrix verifier tag'),
        @("all name ``$OldVersion`` consistently", "all name ``$Version`` consistently", 'acceptance-matrix version tuple'),
        @("scripts/New-IsolatedCandidate.ps1``, at the new path ``target/candidates/$oldTag-<12-character-HEAD>``", "scripts/New-IsolatedCandidate.ps1``, at the new path ``target/candidates/$TargetTag-<12-character-HEAD>``", 'acceptance-matrix candidate path')
    )) {
        $acceptanceMatrix = Replace-ExactLiteralOrAssertTarget `
            $acceptanceMatrix ([string]$binding[0]) ([string]$binding[1]) 1 ([string]$binding[2])
    }
    $plan['docs/v1-beta-acceptance-matrix.md'] = $acceptanceMatrix
    $securityPath = Join-Path $RepositoryRoot 'SECURITY.md'
    $security = Read-Text $securityPath
    $supportSuffix = ' | Supported after its tagged acceptance workflow publishes the attested prerelease; fixes are delivered as a new immutable prerelease tag. |'
    $oldSupportLine = "| ``$oldTag``$supportSuffix"
    $targetSupportLine = "| ``$TargetTag``$supportSuffix"
    $oldSupportCount = ([regex]::Matches(
        $security, [regex]::Escape($oldSupportLine)
    )).Count
    $targetSupportCount = ([regex]::Matches(
        $security, [regex]::Escape($targetSupportLine)
    )).Count
    if ($oldSupportCount -eq 1 -and $targetSupportCount -eq 0) {
        $plan['SECURITY.md'] = Replace-ExactLiteral `
            $security $oldSupportLine $targetSupportLine 1 'current security support line'
    }
    else {
        Assert-Condition (
            $oldSupportCount -eq 0 -and $targetSupportCount -eq 1
        ) 'current security support line is not bound exactly once to either the prior or target tag'
    }

    return $plan
}

function Assert-PlanPostconditions {
    param(
        [Parameter(Mandatory = $true)]$Plan,
        [Parameter(Mandatory = $true)][string[]]$WorkspaceNames,
        [Parameter(Mandatory = $true)][string]$OldVersion
    )
    $oldTag = "v$OldVersion"
    Assert-Condition (([regex]::Matches($Plan['README.md'], '<!--\s*release-marker:', 'CultureInvariant')).Count -eq 1) 'README must contain exactly one release marker'
    Assert-Condition ($Plan['README.md'].Contains("<!-- release-marker: $TargetTag -->")) 'README target marker is missing'
    Assert-Condition (-not $Plan['README.md'].Contains("<!-- release-marker: $oldTag -->")) 'README retains the old current marker'
    Assert-Condition (([regex]::Matches($Plan['docs/serctl-user-guide.md'], '<!--\s*applicable-version:', 'CultureInvariant')).Count -eq 1) 'user guide must contain exactly one applicable-version marker'
    Assert-Condition ($Plan['docs/serctl-user-guide.md'].Contains("<!-- applicable-version: $TargetTag -->")) 'user-guide target marker is missing'
    Assert-Condition (([regex]::Matches($Plan['docs/serctl-architecture-security.html'], 'data-release-candidate="[^"]+"', 'CultureInvariant')).Count -eq 1) 'architecture must contain exactly one candidate marker'
    Assert-Condition ($Plan['docs/serctl-architecture-security.html'].Contains("data-release-candidate=`"$TargetTag`"")) 'architecture target marker is missing'
    Assert-Condition (-not $Plan['CHANGELOG.md'].Contains("## $TargetTag - Unreleased")) 'CHANGELOG still marks the target Unreleased'
    Assert-Condition (([regex]::Matches($Plan['CHANGELOG.md'], '(?m)^## ' + [regex]::Escape($TargetTag) + ' - \d{4}-\d{2}-\d{2}$', 'CultureInvariant')).Count -eq 1) 'CHANGELOG has no unique dated target heading'
    foreach ($name in $WorkspaceNames) {
        Assert-Condition ($Plan['Cargo.lock'].Contains("name = `"$name`"")) "Cargo.lock lost workspace package $name"
    }
    Assert-Condition ($Plan.Contains('fuzz/Cargo.lock')) 'transformation plan omitted fuzz/Cargo.lock'
}

Assert-Condition (-not ($Apply -and $WhatIf)) '-Apply and -WhatIf are mutually exclusive'
Assert-Condition (-not ($InjectFailureAfterWrites -gt 0 -and -not $TestFixture)) 'failure injection is available only for an explicit test fixture'
if ([string]::IsNullOrWhiteSpace($ReleaseDate)) {
    $ReleaseDate = [DateTimeOffset]::UtcNow.ToString('yyyy-MM-dd')
}
$parsedDate = [DateTime]::MinValue
Assert-Condition ([DateTime]::TryParseExact(
    $ReleaseDate,
    'yyyy-MM-dd',
    [Globalization.CultureInfo]::InvariantCulture,
    [Globalization.DateTimeStyles]::None,
    [ref]$parsedDate
)) 'ReleaseDate is not a real canonical calendar date'

$GitPath = Resolve-Application 'git'
$CargoPath = Resolve-Application 'cargo'
if ($TestFixture) {
    Assert-Condition (Test-Path -LiteralPath $FixtureMarker -PathType Leaf) 'test fixture marker is missing'
    Assert-Condition ((Read-Text $FixtureMarker).Trim() -ceq 'SERCTL_VERSION_SWITCH_TEST_FIXTURE_V1') 'test fixture marker is invalid'
}

Push-Location -LiteralPath $RepositoryRoot
$lockStream = $null
$backupRoot = $null
$token = $null
$before = $null
$snapshots = [ordered]@{}
$written = [System.Collections.Generic.List[string]]::new()
try {
    $before = Get-RepositoryIdentity
    Assert-CleanIdentity $before

    $savedPreference = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $metadataJson = & $CargoPath metadata --quiet --locked --no-deps --format-version 1
        $metadataExitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $savedPreference
    }
    Assert-Condition ($metadataExitCode -eq 0) 'cargo metadata --locked failed before switching'
    $metadata = $metadataJson | ConvertFrom-Json
    $workspacePackages = @($metadata.packages | Where-Object { $metadata.workspace_members -contains $_.id })
    Assert-Condition ($workspacePackages.Count -gt 0) 'cargo metadata returned no workspace packages'
    $oldVersions = @($workspacePackages | ForEach-Object { [string]$_.version } | Sort-Object -Unique)
    Assert-Condition ($oldVersions.Count -eq 1) 'workspace packages do not share one current version'
    $oldVersion = [string]$oldVersions[0]
    Assert-Condition ($oldVersion -cne $Version) 'workspace is already at the requested version'
    $targetMatch = [regex]::Match($Version, '^1\.0\.0-beta(?:\.(?<ordinal>[1-9][0-9]*))?$')
    Assert-Condition $targetMatch.Success 'target is not a canonical v1 beta version'
    $oldBeta = [regex]::Match($oldVersion, '^1\.0\.0-beta(?:\.(?<ordinal>[1-9][0-9]*))?$')
    $oldV03 = [regex]::IsMatch(
        $oldVersion,
        '^0\.3\.(?:0|[1-9][0-9]*)(?:-(?:alpha|beta|rc)(?:\.(?:0|[1-9][0-9]*))?)?$'
    )
    $transitionAllowed = $false
    if ($oldV03) {
        $transitionAllowed = -not $targetMatch.Groups['ordinal'].Success
    }
    elseif ($oldBeta.Success) {
        $oldOrdinal = if ($oldBeta.Groups['ordinal'].Success) {
            [System.Numerics.BigInteger]::Parse(
                $oldBeta.Groups['ordinal'].Value,
                [Globalization.CultureInfo]::InvariantCulture
            )
        } else { [System.Numerics.BigInteger]::Zero }
        $targetOrdinal = if ($targetMatch.Groups['ordinal'].Success) {
            [System.Numerics.BigInteger]::Parse(
                $targetMatch.Groups['ordinal'].Value,
                [Globalization.CultureInfo]::InvariantCulture
            )
        } else { [System.Numerics.BigInteger]::Zero }
        $transitionAllowed = $targetOrdinal -eq (
            $oldOrdinal + [System.Numerics.BigInteger]::One
        )
    }
    Assert-Condition $transitionAllowed (
        "version transition '$oldVersion' -> '$Version' is not the next allowed v1 beta candidate"
    )
    $workspaceNames = @($workspacePackages | ForEach-Object { [string]$_.name } | Sort-Object -Unique)

    $plan = New-TransformationPlan $oldVersion $workspaceNames
    Assert-PlanPostconditions $plan $workspaceNames $oldVersion

    if (-not $Apply) {
        [pscustomobject]@{
            mode = 'what-if'
            version = $Version
            release_date = $ReleaseDate
            head = $before.Head
            tree = $before.Tree
            files = @($plan.Keys)
        }
        return
    }

    $gitDirectory = ([string](Invoke-Git @('rev-parse', '--git-dir'))).Trim()
    if (-not [System.IO.Path]::IsPathRooted($gitDirectory)) {
        $gitDirectory = Join-Path $RepositoryRoot $gitDirectory
    }
    $gitDirectory = [System.IO.Path]::GetFullPath($gitDirectory)
    $lockPath = Join-Path $gitDirectory 'serctl-version-switch.lock'
    $token = [Guid]::NewGuid().ToString('N')
    $lockOptions = if ([System.IO.Path]::DirectorySeparatorChar -eq '\') {
        [System.IO.FileOptions]::DeleteOnClose
    }
    else {
        [System.IO.FileOptions]::None
    }
    $lockStream = New-Object System.IO.FileStream(
        $lockPath,
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::ReadWrite,
        [System.IO.FileShare]::None,
        4096,
        $lockOptions
    )
    $tokenBytes = $Utf8NoBom.GetBytes($token)
    $lockStream.Write($tokenBytes, 0, $tokenBytes.Length)
    $lockStream.Flush($true)

    $backupRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('serctl-version-switch-' + $token)
    [System.IO.Directory]::CreateDirectory($backupRoot) | Out-Null
    [System.IO.File]::WriteAllText((Join-Path $backupRoot 'owner-token'), $token, $Utf8NoBom)
    foreach ($relative in $plan.Keys) {
        $path = Join-Path $RepositoryRoot $relative
        Assert-Condition (Test-Path -LiteralPath $path -PathType Leaf) "required source file '$relative' is missing"
        $bytes = [System.IO.File]::ReadAllBytes($path)
        $snapshots[$relative] = [pscustomobject]@{
            Bytes = $bytes
            OriginalHash = Get-BytesHash $bytes
            WrittenHash = Get-BytesHash ($Utf8NoBom.GetBytes([string]$plan[$relative]))
        }
        $backupPath = Join-Path $backupRoot ($relative.Replace('/', [System.IO.Path]::DirectorySeparatorChar))
        [System.IO.Directory]::CreateDirectory([System.IO.Path]::GetDirectoryName($backupPath)) | Out-Null
        [System.IO.File]::WriteAllBytes($backupPath, $bytes)
    }

    $bracket = Get-RepositoryIdentity
    Assert-CleanIdentity $bracket
    Assert-Condition ($bracket.Head -ceq $before.Head -and $bracket.Tree -ceq $before.Tree) 'HEAD/tree changed before mutation'

    $writeCount = 0
    foreach ($relative in $plan.Keys) {
        foreach ($checkRelative in $plan.Keys) {
            $checkPath = Join-Path $RepositoryRoot $checkRelative
            $expectedHash = if ($written.Contains([string]$checkRelative)) {
                $snapshots[$checkRelative].WrittenHash
            }
            else {
                $snapshots[$checkRelative].OriginalHash
            }
            Assert-Condition ((Get-FileHashExact $checkPath) -ceq $expectedHash) "source changed concurrently during version switch"
        }
        $path = Join-Path $RepositoryRoot $relative
        Write-TextReplace $path ([string]$plan[$relative]) $token
        $written.Add([string]$relative)
        $writeCount++
        Assert-Condition ((Get-FileHashExact $path) -ceq $snapshots[$relative].WrittenHash) "written file '$relative' failed readback"
        if ($InjectFailureAfterWrites -gt 0 -and $writeCount -eq $InjectFailureAfterWrites) {
            Fail-VersionSwitch 'injected test-fixture failure'
        }
    }

    $after = Get-RepositoryIdentity
    Assert-Condition ($after.Head -ceq $before.Head -and $after.Tree -ceq $before.Tree) 'HEAD/tree changed during mutation'
    $actualChanged = @($after.Status | ForEach-Object { ([string]$_).Substring(3).Replace('\', '/') } | Sort-Object -Unique)
    $expectedChanged = @($plan.Keys | Where-Object {
        -not [System.Linq.Enumerable]::SequenceEqual(
            [byte[]]$snapshots[[string]$_].Bytes,
            [byte[]][System.IO.File]::ReadAllBytes((Join-Path $RepositoryRoot ([string]$_)))
        )
    } | Sort-Object -Unique)
    Assert-Condition (($actualChanged -join "`n") -ceq ($expectedChanged -join "`n")) (
        "post-switch Git status differs from the exact approved file set; actual=[$($actualChanged -join ', ')]; expected=[$($expectedChanged -join ', ')]"
    )

    & (Join-Path $RepositoryRoot 'scripts/Verify-ReleaseConsistency.ps1') -Tag $TargetTag
    Assert-Condition ($LASTEXITCODE -eq 0) 'Verify-ReleaseConsistency rejected the switched source'

    [pscustomobject]@{
        mode = 'applied'
        version = $Version
        release_date = $ReleaseDate
        head = $after.Head
        tree = $after.Tree
        files = @($plan.Keys)
    }
}
catch {
    $primary = $_
    $rollbackErrors = [System.Collections.Generic.List[string]]::new()
    for ($rollbackIndex = $written.Count - 1; $rollbackIndex -ge 0; $rollbackIndex--) {
        $relative = [string]$written[$rollbackIndex]
        try {
            $path = Join-Path $RepositoryRoot $relative
            if ((Get-FileHashExact $path) -cne $snapshots[$relative].WrittenHash) {
                throw 'owned written bytes were replaced concurrently'
            }
            $originalText = $Utf8NoBom.GetString([byte[]]$snapshots[$relative].Bytes)
            Write-TextReplace $path $originalText ([Guid]::NewGuid().ToString('N'))
            if ((Get-FileHashExact $path) -cne $snapshots[$relative].OriginalHash) {
                throw 'original bytes did not roundtrip'
            }
        }
        catch {
            $rollbackErrors.Add("$relative rollback failed")
        }
    }
    if ($rollbackErrors.Count -gt 0) {
        throw "controlled version switch failed and rollback is incomplete: $($rollbackErrors -join '; ')"
    }
    if ($null -ne $before -and $written.Count -gt 0) {
        $rolledBack = Get-RepositoryIdentity
        if ($rolledBack.Head -cne $before.Head -or
            $rolledBack.Tree -cne $before.Tree -or
            $rolledBack.Status.Count -ne 0) {
            throw 'controlled version switch failed and rollback did not restore HEAD/tree/status'
        }
    }
    throw $primary
}
finally {
    if ($null -ne $lockStream) {
        $lockPath = [string]$lockStream.Name
        $lockStream.Dispose()
        if ([System.IO.Path]::DirectorySeparatorChar -ne '\' -and
            (Test-Path -LiteralPath $lockPath -PathType Leaf) -and
            ((Read-Text $lockPath) -ceq $token)) {
            Remove-Item -LiteralPath $lockPath -Force
        }
    }
    if ($null -ne $backupRoot -and (Test-Path -LiteralPath $backupRoot -PathType Container)) {
        $expectedPrefix = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath()).TrimEnd(
            [System.IO.Path]::DirectorySeparatorChar
        ) + [System.IO.Path]::DirectorySeparatorChar
        $resolvedBackup = [System.IO.Path]::GetFullPath($backupRoot)
        $ownerPath = Join-Path $resolvedBackup 'owner-token'
        $owned = (
            $null -ne $token -and
            $resolvedBackup.StartsWith($expectedPrefix, [System.StringComparison]::OrdinalIgnoreCase) -and
            (Test-Path -LiteralPath $ownerPath -PathType Leaf) -and
            ((Read-Text $ownerPath) -ceq $token)
        )
        if ($owned) {
            Remove-Item -LiteralPath $resolvedBackup -Recurse -Force
        }
        else {
            throw 'controlled version switch refused to clean an unowned backup directory'
        }
    }
    Pop-Location
}
