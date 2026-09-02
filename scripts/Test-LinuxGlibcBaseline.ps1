[CmdletBinding(DefaultParameterSetName = 'Binary')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Binary')]
    [ValidateNotNullOrEmpty()]
    [string]$BinaryPath,

    [Parameter(Mandatory = $true, ParameterSetName = 'Fixture')]
    [ValidateNotNullOrEmpty()]
    [string]$VersionInfoPath,

    [ValidatePattern('^[0-9]+(?:\.[0-9]+)+$')]
    [string]$MaximumSupported = '2.35'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-GlibcCondition {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if (-not $Condition) {
        throw "Linux GLIBC baseline check failed: $Message"
    }
}

if ($PSCmdlet.ParameterSetName -ceq 'Binary') {
    $resolved = Get-Item -LiteralPath $BinaryPath -Force -ErrorAction Stop
    Assert-GlibcCondition (-not $resolved.PSIsContainer) "binary is a directory"
    Assert-GlibcCondition (
        ($resolved.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0
    ) "binary is a reparse point"
    Assert-GlibcCondition ($resolved.Length -gt 0) "binary is empty"
    $versionInfo = @(& readelf --version-info --wide $resolved.FullName 2>&1)
    Assert-GlibcCondition ($LASTEXITCODE -eq 0) "readelf could not inspect the binary"
    $versionInfoText = $versionInfo | Out-String
}
else {
    $fixture = Get-Item -LiteralPath $VersionInfoPath -Force -ErrorAction Stop
    Assert-GlibcCondition (-not $fixture.PSIsContainer) "fixture is a directory"
    Assert-GlibcCondition (
        ($fixture.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0
    ) "fixture is a reparse point"
    Assert-GlibcCondition ($fixture.Length -gt 0 -and $fixture.Length -le 1MB) (
        "fixture must contain between 1 byte and 1 MiB"
    )
    $versionInfoText = [System.IO.File]::ReadAllText(
        $fixture.FullName,
        [System.Text.Encoding]::UTF8
    )
}

$matches = [regex]::Matches(
    $versionInfoText,
    'GLIBC_(?<version>[0-9]+(?:\.[0-9]+)+)',
    [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
)
Assert-GlibcCondition ($matches.Count -gt 0) "no inspectable GLIBC version needs"
$requiredVersions = @(
    $matches |
        ForEach-Object { [Version]::Parse($_.Groups['version'].Value) } |
        Sort-Object -Unique
)
[Version]$maximumRequiredVersion = $requiredVersions[-1]
[Version]$maximumSupportedVersion = [Version]::Parse($MaximumSupported)
Assert-GlibcCondition ($maximumRequiredVersion -le $maximumSupportedVersion) (
    "binary requires GLIBC_$maximumRequiredVersion, above supported baseline " +
    "GLIBC_$maximumSupportedVersion"
)

[pscustomobject][ordered]@{
    family = 'glibc'
    maximum_supported = $maximumSupportedVersion.ToString()
    maximum_required = $maximumRequiredVersion.ToString()
    verifier = 'readelf --version-info --wide'
}
