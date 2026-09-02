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
        throw "Linux GLIBC baseline self-test failed: $Message"
    }
}

function Invoke-ExpectedFailure {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Description
    )
    $failed = $false
    try {
        & $checkScript -VersionInfoPath $Path *> $null
    }
    catch {
        $failed = $true
    }
    Assert-TestCondition $failed "$Description unexpectedly passed"
}

$checkScript = Join-Path $PSScriptRoot 'Test-LinuxGlibcBaseline.ps1'
$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'serctl-glibc-baseline-test-' + [System.Guid]::NewGuid().ToString('N')
)
[System.IO.Directory]::CreateDirectory($temporaryRoot) | Out-Null
try {
    $passPath = Join-Path $temporaryRoot 'pass.txt'
    $tooNewPath = Join-Path $temporaryRoot 'too-new.txt'
    $missingPath = Join-Path $temporaryRoot 'missing.txt'
    [System.IO.File]::WriteAllText(
        $passPath,
        "Version needs: GLIBC_2.2.5 GLIBC_2.34 GLIBC_2.17`n",
        [System.Text.UTF8Encoding]::new($false)
    )
    [System.IO.File]::WriteAllText(
        $tooNewPath,
        "Version needs: GLIBC_2.34 GLIBC_2.36`n",
        [System.Text.UTF8Encoding]::new($false)
    )
    [System.IO.File]::WriteAllText(
        $missingPath,
        "Version needs: LIBC_2.35`n",
        [System.Text.UTF8Encoding]::new($false)
    )

    $result = & $checkScript -VersionInfoPath $passPath
    Assert-TestCondition ($result.family -ceq 'glibc') 'family was not recorded'
    Assert-TestCondition ($result.maximum_supported -ceq '2.35') (
        'supported ceiling was not recorded'
    )
    Assert-TestCondition ($result.maximum_required -ceq '2.34') (
        'maximum requirement was not selected numerically'
    )
    Invoke-ExpectedFailure -Path $tooNewPath -Description 'too-new requirement'
    Invoke-ExpectedFailure -Path $missingPath -Description 'missing GLIBC evidence'
}
finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        [System.IO.Directory]::Delete($temporaryRoot, $true)
    }
}

Write-Host 'Linux GLIBC baseline self-tests passed.'
