[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$outputDirectory = Join-Path $repositoryRoot 'target/ci-build-script-fixtures'
$isWindowsHost = (
    [System.Environment]::OSVersion.Platform -eq
    [System.PlatformID]::Win32NT
)
$executableSuffix = if ($isWindowsHost) { '.exe' } else { '' }

$fixtures = @(
    @{ Name = 'cli'; Source = 'crates/serctl_cli/build.rs' },
    @{ Name = 'daemon'; Source = 'crates/serctl_daemon/build.rs' },
    @{ Name = 'xfer'; Source = 'crates/serctl_xfer/build.rs' },
    @{ Name = 'remote'; Source = 'crates/serctl_remote/build.rs' }
)

[System.IO.Directory]::CreateDirectory($outputDirectory) | Out-Null
$outputDirectoryItem = Get-Item -LiteralPath $outputDirectory -Force
if (($outputDirectoryItem.Attributes -band
        [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw 'build-script fixture output directory is a reparse point'
}

Push-Location -LiteralPath $repositoryRoot
try {
    foreach ($fixture in $fixtures) {
        $sourcePath = Join-Path $repositoryRoot $fixture.Source
        $sourceItem = Get-Item -LiteralPath $sourcePath -Force -ErrorAction Stop
        if ($sourceItem.PSIsContainer -or
            ($sourceItem.Attributes -band
                [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
            $sourceItem.Length -le 0) {
            throw "build-script fixture source is not a nonempty regular file: $($fixture.Source)"
        }

        $outputPath = Join-Path `
            $outputDirectory `
            "$($fixture.Name)-build-script-tests$executableSuffix"
        & rustc `
            --edition=2021 `
            --test `
            $fixture.Source `
            -o `
            $outputPath
        if ($LASTEXITCODE -ne 0) {
            throw "rustc failed for build-script fixture '$($fixture.Name)' with exit $LASTEXITCODE"
        }

        $outputItem = Get-Item -LiteralPath $outputPath -Force -ErrorAction Stop
        if ($outputItem.PSIsContainer -or
            ($outputItem.Attributes -band
                [System.IO.FileAttributes]::ReparsePoint) -ne 0 -or
            $outputItem.Length -le 0) {
            throw "compiled build-script fixture is not a nonempty regular file: $outputPath"
        }

        & $outputPath
        if ($LASTEXITCODE -ne 0) {
            throw "build-script fixture '$($fixture.Name)' failed with exit $LASTEXITCODE"
        }
    }
}
finally {
    Pop-Location
}

Write-Output "Build-script fixtures passed on $([System.Runtime.InteropServices.RuntimeInformation]::OSDescription)."
