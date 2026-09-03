[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ReleaseLogSanitization.ps1')

function Assert-LogSelfTest {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "release log sanitization self-test failed: $Message" }
}

$secret = 'SECRET-CANARY-7f16'
$absoluteWindows = "C:\private\$secret\receipt.json"
$absolutePosix = "/private/$secret/bundle.tar.gz"
$unc = "\\server\share\$secret\acl.txt"
$control = "bad`r`n$secret.json"
$cases = @(
    @{ Name = 'windows-absolute'; Path = $absoluteWindows; Fallback = 'download'; Expected = 'receipt.json' },
    @{ Name = 'posix-absolute'; Path = $absolutePosix; Fallback = 'bundle'; Expected = 'bundle.tar.gz' },
    @{ Name = 'unc'; Path = $unc; Fallback = 'acl'; Expected = 'acl.txt' },
    @{ Name = 'mixed-separator'; Path = 'mixed\directory/file.txt'; Fallback = 'mixed'; Expected = 'file.txt' },
    @{ Name = 'trailing-separator'; Path = 'trailing\directory\'; Fallback = 'trailing'; Expected = 'trailing' },
    @{ Name = 'bare-leaf'; Path = 'manifest.json'; Fallback = 'manifest'; Expected = 'manifest.json' },
    @{ Name = 'control-character'; Path = $control; Fallback = 'redacted'; Expected = 'redacted' }
)
foreach ($case in $cases) {
    $leaf = Get-ReleaseLogLeafName -Path $case.Path -Fallback $case.Fallback
    Assert-LogSelfTest ($leaf -ceq $case.Expected) (
        "leaf-name policy mismatch for $($case.Name)"
    )
    $success = Format-ReleaseLogRecord -Category release_step_completed -LeafName $leaf -Bytes 17
    $failure = Format-ReleaseLogRecord -Category release_step_failed -LeafName $leaf -Bytes 23
    foreach ($output in @($success, $failure)) {
        Assert-LogSelfTest (-not $output.Contains($secret)) 'secret canary reached log output'
        Assert-LogSelfTest (-not $output.Contains("`r") -and -not $output.Contains("`n")) (
            'control character reached log output'
        )
        Assert-LogSelfTest (-not $output.Contains('C:\private\')) 'Windows absolute path leaked'
        Assert-LogSelfTest (-not $output.Contains('/private/')) 'POSIX absolute path leaked'
        Assert-LogSelfTest (-not $output.Contains('\\server\share\')) 'UNC path leaked'
    }
}

function Invoke-SanitizedFailureProbe {
    param(
        [Parameter(Mandatory = $true)][string]$Script,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$Expected
    )

    $engine = (Get-Process -Id $PID).Path
    $probeRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
        'serctl-release-log-probe-' + [guid]::NewGuid().ToString('N')
    )
    [System.IO.Directory]::CreateDirectory($probeRoot) | Out-Null
    $stdoutPath = Join-Path $probeRoot 'stdout.txt'
    $stderrPath = Join-Path $probeRoot 'stderr.txt'
    try {
        $argumentList = @(
            '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
            '-File', $Script
        ) + $Arguments
        $process = Start-Process `
            -FilePath $engine `
            -ArgumentList $argumentList `
            -RedirectStandardOutput $stdoutPath `
            -RedirectStandardError $stderrPath `
            -Wait `
            -PassThru
        $stdout = if (Test-Path -LiteralPath $stdoutPath) {
            [System.IO.File]::ReadAllText($stdoutPath)
        }
        else { '' }
        $stderr = if (Test-Path -LiteralPath $stderrPath) {
            [System.IO.File]::ReadAllText($stderrPath)
        }
        else { '' }
        $combined = ($stdout + $stderr).Trim()
        Assert-LogSelfTest ($process.ExitCode -eq 1) 'failure probe did not exit 1'
        Assert-LogSelfTest ($combined -ceq $Expected) (
            'failure probe did not emit exactly one sanitized record'
        )
        foreach ($canary in @(
            $secret, 'C:\private\', '/private/', '\\server\share\', "`r", "`n"
        )) {
            if ($canary -ceq "`r" -or $canary -ceq "`n") {
                Assert-LogSelfTest (-not $combined.Contains($canary)) (
                    'failure probe emitted a control character'
                )
            }
            else {
                Assert-LogSelfTest (-not $combined.Contains($canary)) (
                    'failure probe emitted a path or secret canary'
                )
            }
        }
    }
    finally {
        if (Test-Path -LiteralPath $probeRoot) {
            [System.IO.Directory]::Delete($probeRoot, $true)
        }
    }
}

$canaryRoot = "C:\private\$secret"
Invoke-SanitizedFailureProbe `
    -Script (Join-Path $PSScriptRoot 'Save-BoundedHttpsFile.ps1') `
    -Arguments @(
        '-Url', "http://example.invalid/$secret", '-Destination',
        "$canaryRoot\receipt.json", '-MaxBytes', '128'
    ) `
    -Expected "bounded HTTPS download failed: category=https_input_invalid; file='receipt.json'; bytes=0"
Invoke-SanitizedFailureProbe `
    -Script (Join-Path $PSScriptRoot 'New-ReleaseBundle.ps1') `
    -Arguments @(
        '-Platform', 'windows-x86_64', '-Version', $secret,
        '-Commit', ('a' * 40), '-TagObject', ('b' * 40),
        '-OutputDirectory', "$canaryRoot\release-output"
    ) `
    -Expected "release bundle failed: category=release_bundle_failed; file='release-bundle'; bytes=0"
Invoke-SanitizedFailureProbe `
    -Script (Join-Path $PSScriptRoot 'Test-WindowsMultiAccountAcl.ps1') `
    -Arguments @('-CliPath', "$canaryRoot\serctl_cli.exe") `
    -Expected "Windows multi-account ACL gate failed: category=windows_acl_gate_failed; file='serctl_cli.exe'; bytes=0"

Write-Host 'Release log sanitization self-test passed.'
