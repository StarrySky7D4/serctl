[CmdletBinding()]
param([string]$RepositoryRoot)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $RepositoryRoot = Join-Path $PSScriptRoot '..'
}

$generator = Join-Path $PSScriptRoot 'New-ParserFuzzReceipt.ps1'
$verifier = Join-Path $PSScriptRoot 'Test-ParserFuzzReceipt.ps1'
$root = [System.IO.Path]::GetFullPath($RepositoryRoot)
$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'serctl-parser-fuzz-receipt-selftest-' + [guid]::NewGuid().ToString('N')
)
$receiptPath = Join-Path $temporaryRoot 'parser-fuzz-success.json'
$tagObject = 'fedcba9876543210fedcba9876543210fedcba98'
$commit = '0123456789abcdef0123456789abcdef01234567'

function Assert-SelfTestCondition {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) { throw "parser fuzz receipt self-test failed: $Message" }
}

function Invoke-ReceiptVerifier {
    & $verifier `
        -Path $receiptPath `
        -Tag 'v1.0.0-beta' `
        -TagObject $tagObject `
        -Commit $commit `
        -Repository 'example/serctl' `
        -RunId '123456' `
        -RunAttempt '2' *> $null
}

function Reset-Receipt {
    Remove-Item -LiteralPath $receiptPath -Force -ErrorAction SilentlyContinue
    & $generator `
        -Path $receiptPath `
        -Tag 'v1.0.0-beta' `
        -TagObject $tagObject `
        -Commit $commit `
        -Repository 'example/serctl' `
        -RunId '123456' `
        -RunAttempt '2' `
        -RepositoryRoot $root *> $null
}

function Write-ReceiptObject {
    param([Parameter(Mandatory = $true)]$Value)
    $json = ($Value | ConvertTo-Json -Depth 12).Replace("`r`n", "`n") + "`n"
    [System.IO.File]::WriteAllText(
        $receiptPath,
        $json,
        [System.Text.UTF8Encoding]::new($false)
    )
}

function Invoke-ExpectedFailure {
    param([string]$Description, [scriptblock]$Mutation)
    Reset-Receipt
    & $Mutation
    $failed = $false
    try { Invoke-ReceiptVerifier }
    catch { $failed = $true }
    Assert-SelfTestCondition $failed "accepted $Description"
}

[System.IO.Directory]::CreateDirectory($temporaryRoot) | Out-Null
try {
    Reset-Receipt
    Invoke-ReceiptVerifier
    $originalHash = (Get-FileHash -LiteralPath $receiptPath -Algorithm SHA256).Hash
    $overwriteFailed = $false
    try {
        & $generator `
            -Path $receiptPath `
            -Tag 'v1.0.0-beta' `
            -TagObject $tagObject `
            -Commit $commit `
            -Repository 'example/serctl' `
            -RunId '123456' `
            -RunAttempt '2' `
            -RepositoryRoot $root *> $null
    }
    catch { $overwriteFailed = $true }
    Assert-SelfTestCondition $overwriteFailed 'generator overwrote an existing receipt'
    Assert-SelfTestCondition (
        (Get-FileHash -LiteralPath $receiptPath -Algorithm SHA256).Hash -ceq $originalHash
    ) 'failed overwrite changed the existing receipt'

    Invoke-ExpectedFailure 'an unknown top-level field' {
        $value = Get-Content -LiteralPath $receiptPath -Raw -Encoding utf8 | ConvertFrom-Json
        $value | Add-Member -NotePropertyName unexpected -NotePropertyValue 'x'
        Write-ReceiptObject $value
    }
    Invoke-ExpectedFailure 'another tag object' {
        $value = Get-Content -LiteralPath $receiptPath -Raw -Encoding utf8 | ConvertFrom-Json
        $value.tag_object = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
        Write-ReceiptObject $value
    }
    Invoke-ExpectedFailure 'a missing matrix row' {
        $value = Get-Content -LiteralPath $receiptPath -Raw -Encoding utf8 | ConvertFrom-Json
        $value.matrix = @($value.matrix)[0..1]
        Write-ReceiptObject $value
    }
    Invoke-ExpectedFailure 'a changed corpus command' {
        $value = Get-Content -LiteralPath $receiptPath -Raw -Encoding utf8 | ConvertFrom-Json
        $value.corpus_commands[0] = 'cargo fuzz run transfer_protocol'
        Write-ReceiptObject $value
    }
    Invoke-ExpectedFailure 'a noncanonical source digest' {
        $value = Get-Content -LiteralPath $receiptPath -Raw -Encoding utf8 | ConvertFrom-Json
        $value.source_digests.fuzz_lock = 'A' * 64
        Write-ReceiptObject $value
    }
    Invoke-ExpectedFailure 'one failed matrix row' {
        $value = Get-Content -LiteralPath $receiptPath -Raw -Encoding utf8 | ConvertFrom-Json
        $value.test_counts.passed = 2
        $value.test_counts.failed = 1
        Write-ReceiptObject $value
    }
    Invoke-ExpectedFailure 'trailing non-JSON bytes' {
        [System.IO.File]::AppendAllText(
            $receiptPath,
            "x",
            [System.Text.UTF8Encoding]::new($false)
        )
    }
}
finally {
    if (Test-Path -LiteralPath $temporaryRoot) {
        [System.IO.Directory]::Delete($temporaryRoot, $true)
    }
}

Write-Host 'Parser fuzz success receipt self-test passed.'
