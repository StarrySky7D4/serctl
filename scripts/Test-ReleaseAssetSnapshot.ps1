[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'ReleaseAssetContract.ps1')

function Assert-SnapshotSelfTestCondition {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "release asset snapshot self-test failed: $Message" }
}

function Invoke-ExpectedSnapshotFailure {
    param(
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][scriptblock]$Action
    )
    $failed = $false
    try { & $Action }
    catch {
        $failed = $true
        Assert-SnapshotSelfTestCondition (
            $_.Exception.Message.Contains('release asset snapshot failed:')
        ) "$Label did not fail through the bounded snapshot guard"
    }
    Assert-SnapshotSelfTestCondition $failed "$Label unexpectedly passed"
}

$version = '1.0.0-beta'
$probeRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'serctl-release-snapshot-' + [Guid]::NewGuid().ToString('N')
)
$releaseRoot = Join-Path $probeRoot 'release-dist'
$snapshotPath = Join-Path $probeRoot 'release.snapshot.json'
$publishRoot = Join-Path $probeRoot 'publish-staging'

try {
    [System.IO.Directory]::CreateDirectory($releaseRoot) | Out-Null
    foreach ($name in @(Get-V1BetaFinalReleaseNames -Version $version)) {
        [System.IO.File]::WriteAllText(
            (Join-Path $releaseRoot $name),
            "fixture:$name`n",
            [System.Text.UTF8Encoding]::new($false)
        )
    }

    & (Join-Path $PSScriptRoot 'ReleaseAssetSnapshot.ps1') `
        -Mode Create `
        -Directory $releaseRoot `
        -Version $version `
        -SnapshotPath $snapshotPath
    & (Join-Path $PSScriptRoot 'ReleaseAssetSnapshot.ps1') `
        -Mode Verify `
        -Directory $releaseRoot `
        -Version $version `
        -SnapshotPath $snapshotPath

    $mutatedName = @(Get-V1BetaFinalReleaseNames -Version $version)[0]
    $mutatedPath = Join-Path $releaseRoot $mutatedName
    $originalBytes = [System.IO.File]::ReadAllBytes($mutatedPath)
    [System.IO.File]::WriteAllText(
        $mutatedPath,
        "replacement bytes`n",
        [System.Text.UTF8Encoding]::new($false)
    )
    Invoke-ExpectedSnapshotFailure 'same-name byte replacement' {
        & (Join-Path $PSScriptRoot 'ReleaseAssetSnapshot.ps1') `
            -Mode Verify -Directory $releaseRoot -Version $version -SnapshotPath $snapshotPath
    }
    [System.IO.File]::WriteAllBytes($mutatedPath, $originalBytes)

    $extraPath = Join-Path $releaseRoot 'external-acceptance.json'
    [System.IO.File]::WriteAllText($extraPath, "not a release asset`n")
    Invoke-ExpectedSnapshotFailure 'extra file injection' {
        & (Join-Path $PSScriptRoot 'ReleaseAssetSnapshot.ps1') `
            -Mode Verify -Directory $releaseRoot -Version $version -SnapshotPath $snapshotPath
    }
    [System.IO.File]::Delete($extraPath)

    [System.IO.File]::Delete($mutatedPath)
    Invoke-ExpectedSnapshotFailure 'allowlisted file deletion' {
        & (Join-Path $PSScriptRoot 'ReleaseAssetSnapshot.ps1') `
            -Mode Verify -Directory $releaseRoot -Version $version -SnapshotPath $snapshotPath
    }
    [System.IO.File]::WriteAllBytes($mutatedPath, $originalBytes)

    & (Join-Path $PSScriptRoot 'ReleaseAssetSnapshot.ps1') `
        -Mode CopyCreateNew `
        -Directory $releaseRoot `
        -Version $version `
        -SnapshotPath $snapshotPath `
        -DestinationDirectory $publishRoot
    Invoke-ExpectedSnapshotFailure 'publish staging overwrite' {
        & (Join-Path $PSScriptRoot 'ReleaseAssetSnapshot.ps1') `
            -Mode CopyCreateNew `
            -Directory $releaseRoot `
            -Version $version `
            -SnapshotPath $snapshotPath `
            -DestinationDirectory $publishRoot
    }

    Write-Host 'Release asset snapshot self-test passed.'
}
finally {
    if (Test-Path -LiteralPath $probeRoot) {
        Get-ChildItem -LiteralPath $probeRoot -Recurse -Force -ErrorAction SilentlyContinue |
            ForEach-Object {
                try { $_.Attributes = [System.IO.FileAttributes]::Normal }
                catch { }
            }
        try { (Get-Item -LiteralPath $probeRoot -Force).Attributes = [System.IO.FileAttributes]::Normal }
        catch { }
        Remove-Item -LiteralPath $probeRoot -Recurse -Force
    }
}
