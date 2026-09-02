[CmdletBinding()]
param(
    [string]$RepositoryRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $RepositoryRoot = Join-Path $PSScriptRoot '..'
}

function Assert-SelfTestCondition {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )

    if (-not $Condition) {
        throw "parser fuzz boundary self-test failed: $Message"
    }
}

function Write-Utf8Fixture {
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

$sourceRoot = [System.IO.Path]::GetFullPath($RepositoryRoot)
$verifier = Join-Path $PSScriptRoot 'Test-ParserFuzzBoundary.ps1'
$temporaryRoot = Join-Path (
    [System.IO.Path]::GetTempPath()
) ("serctl-parser-fuzz-selftest-" + [guid]::NewGuid().ToString('N'))

function Reset-Fixture {
    if (Test-Path -LiteralPath $temporaryRoot) {
        Remove-Item -LiteralPath $temporaryRoot -Recurse -Force
    }
    New-Item -ItemType Directory -Path (Join-Path $temporaryRoot '.github/workflows') -Force | Out-Null
    New-Item -ItemType Directory -Path (Join-Path $temporaryRoot 'fuzz/fuzz_targets') -Force | Out-Null
    foreach ($relative in @(
        '.github/workflows/parser-fuzz.yml',
        'Cargo.toml',
        'Cargo.lock',
        'fuzz/Cargo.toml',
        'fuzz/Cargo.lock',
        'fuzz/fuzz_targets/transfer_protocol.rs',
        'fuzz/fuzz_targets/remote_protocol.rs',
        'fuzz/fuzz_targets/policy_json.rs'
    )) {
        Copy-Item `
            -LiteralPath (Join-Path $sourceRoot $relative) `
            -Destination (Join-Path $temporaryRoot $relative) `
            -Force
    }
}

function Invoke-ExpectedFailure {
    param(
        [Parameter(Mandatory = $true)][scriptblock]$Mutation,
        [Parameter(Mandatory = $true)][string]$Description
    )

    Reset-Fixture
    & $Mutation
    $failed = $false
    try {
        & $verifier -RepositoryRoot $temporaryRoot *> $null
    }
    catch {
        $failed = $true
    }
    Assert-SelfTestCondition $failed "$Description unexpectedly passed"
}

try {
    Reset-Fixture
    & $verifier -RepositoryRoot $temporaryRoot *> $null

    Invoke-ExpectedFailure -Description 'floating nightly' -Mutation {
        $path = Join-Path $temporaryRoot '.github/workflows/parser-fuzz.yml'
        $value = [System.IO.File]::ReadAllText($path).Replace(
            'nightly-2026-08-03',
            'nightly'
        )
        Write-Utf8Fixture $path $value
    }
    Invoke-ExpectedFailure -Description 'missing reusable exact-tag trigger' -Mutation {
        $path = Join-Path $temporaryRoot '.github/workflows/parser-fuzz.yml'
        $value = [System.IO.File]::ReadAllText($path).Replace(
            "  workflow_call:`r`n",
            ''
        ).Replace(
            "  workflow_call:`n",
            ''
        )
        Write-Utf8Fixture $path $value
    }
    Invoke-ExpectedFailure -Description 'metadata does not enforce the isolated fuzz lock' -Mutation {
        $path = Join-Path $temporaryRoot '.github/workflows/parser-fuzz.yml'
        $value = [regex]::Replace(
            [System.IO.File]::ReadAllText($path),
            '(?m)^(\s*)--locked\r?\n(\s*--format-version 1\s*)$',
            '$1--offline' + "`n" + '$2',
            1
        )
        Write-Utf8Fixture $path $value
    }
    Invoke-ExpectedFailure -Description 'tag-pinned action' -Mutation {
        $path = Join-Path $temporaryRoot '.github/workflows/parser-fuzz.yml'
        $value = [System.IO.File]::ReadAllText($path).Replace(
            'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1',
            'actions/checkout@v7'
        )
        Write-Utf8Fixture $path $value
    }
    Invoke-ExpectedFailure -Description 'unbounded transfer input' -Mutation {
        $path = Join-Path $temporaryRoot '.github/workflows/parser-fuzz.yml'
        $value = [System.IO.File]::ReadAllText($path).Replace(
            'max_len: 1048644',
            'max_len: 16777216'
        )
        Write-Utf8Fixture $path $value
    }
    Invoke-ExpectedFailure -Description 'fuzz workspace merged into release workspace' -Mutation {
        $path = Join-Path $temporaryRoot 'Cargo.toml'
        $value = [System.IO.File]::ReadAllText($path).Replace(
            'members = [',
            'members = ["fuzz",'
        )
        Write-Utf8Fixture $path $value
    }
    Invoke-ExpectedFailure -Description 'missing nested fuzz workspace' -Mutation {
        $path = Join-Path $temporaryRoot 'fuzz/Cargo.toml'
        $value = [System.IO.File]::ReadAllText($path).Replace(
            '[workspace]',
            '[not-a-workspace]'
        )
        Write-Utf8Fixture $path $value
    }
    Invoke-ExpectedFailure -Description 'fuzz lock omits a harness dependency' -Mutation {
        $path = Join-Path $temporaryRoot 'fuzz/Cargo.lock'
        $value = [regex]::Replace(
            [System.IO.File]::ReadAllText($path),
            '(?m)^ "libfuzzer-sys",\r?\n',
            '',
            1
        )
        Write-Utf8Fixture $path $value
    }
    Invoke-ExpectedFailure -Description 'release lock contains a fuzz-only package' -Mutation {
        $path = Join-Path $temporaryRoot 'Cargo.lock'
        $value = [System.IO.File]::ReadAllText($path) + @'

[[package]]
name = "libfuzzer-sys"
version = "0.4.13"
'@
        Write-Utf8Fixture $path $value
    }
    Invoke-ExpectedFailure -Description 'transfer target bypasses production data parser' -Mutation {
        $path = Join-Path $temporaryRoot 'fuzz/fuzz_targets/transfer_protocol.rs'
        $value = [System.IO.File]::ReadAllText($path).Replace(
            'FrameKind::Data as u8',
            'FrameKind::Control as u8'
        )
        Write-Utf8Fixture $path $value
    }
    Invoke-ExpectedFailure -Description 'policy target bypasses production compiler' -Mutation {
        $path = Join-Path $temporaryRoot 'fuzz/fuzz_targets/policy_json.rs'
        $value = [System.IO.File]::ReadAllText($path).Replace(
            'compile_policy_json(data)',
            'Ok::<(), ()>(())'
        )
        Write-Utf8Fixture $path $value
    }
    Invoke-ExpectedFailure -Description 'policy target lacks structured deep path' -Mutation {
        $path = Join-Path $temporaryRoot 'fuzz/fuzz_targets/policy_json.rs'
        $value = [System.IO.File]::ReadAllText($path).Replace(
            'compile_policy_json(structured.as_bytes())',
            'compile_policy_json(data)'
        )
        Write-Utf8Fixture $path $value
    }
}
finally {
    $systemTemporaryRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
    $resolvedTemporaryRoot = [System.IO.Path]::GetFullPath($temporaryRoot)
    if (
        $resolvedTemporaryRoot.StartsWith(
            $systemTemporaryRoot,
            [System.StringComparison]::OrdinalIgnoreCase
        ) -and
        (Test-Path -LiteralPath $resolvedTemporaryRoot)
    ) {
        Remove-Item -LiteralPath $resolvedTemporaryRoot -Recurse -Force
    }
}

Write-Host 'Parser fuzz boundary self-test passed.'
