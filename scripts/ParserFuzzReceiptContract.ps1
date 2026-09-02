Set-StrictMode -Version Latest

. (Join-Path $PSScriptRoot 'StrictJson.ps1')

function Assert-ParserFuzzReceiptCondition {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if (-not $Condition) {
        throw "parser fuzz receipt verification failed: $Message"
    }
}

function Read-ValidatedParserFuzzReceipt {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][string]$Tag,
        [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{40}$')][string]$TagObject,
        [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{40}$')][string]$Commit,
        [Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')]
        [string]$Repository,
        [Parameter(Mandatory = $true)][ValidatePattern('^[0-9]+$')][string]$RunId,
        [Parameter(Mandatory = $true)][ValidatePattern('^[0-9]+$')][string]$RunAttempt
    )

    Assert-ParserFuzzReceiptCondition (
        $Bytes.Length -gt 0 -and $Bytes.Length -le 65536
    ) 'receipt is empty or exceeds 65536 bytes'
    $encoding = [System.Text.UTF8Encoding]::new($false, $true)
    try { $json = $encoding.GetString($Bytes) }
    catch { throw "parser fuzz receipt verification failed: receipt is not strict UTF-8" }
    Assert-ParserFuzzReceiptCondition (
        $json.EndsWith("`n", [System.StringComparison]::Ordinal) -and
        -not $json.Contains("`r")
    ) 'receipt is not canonical LF-terminated text'
    try { $receipt = ConvertFrom-StrictJson -Json $json -Label 'parser fuzz receipt' }
    catch { throw "parser fuzz receipt verification failed: $($_.Exception.Message)" }
    Assert-ParserFuzzReceiptCondition (Test-StrictJsonObject $receipt) 'receipt is not an object'

    $expectedFields = @(
        'commit', 'corpus_commands', 'matrix', 'repository', 'run_attempt', 'run_id',
        'schema_version', 'source_digests', 'tag', 'tag_object', 'test_counts',
        'toolchain', 'workflow_ref'
    ) | Sort-Object
    $actualFields = @($receipt.PSObject.Properties.Name | Sort-Object)
    Assert-ParserFuzzReceiptCondition (
        ($actualFields -join "`n") -ceq ($expectedFields -join "`n")
    ) 'receipt does not use the exact closed schema'
    Assert-ParserFuzzReceiptCondition (
        (Test-StrictJsonInteger $receipt.schema_version) -and $receipt.schema_version -eq 1
    ) 'schema_version is not integer 1'
    foreach ($field in @(
        'tag', 'tag_object', 'commit', 'repository', 'workflow_ref', 'run_id', 'run_attempt'
    )) {
        Assert-ParserFuzzReceiptCondition (Test-StrictJsonString $receipt.$field) (
            "field '$field' is not a JSON string"
        )
    }
    Assert-ParserFuzzReceiptCondition ([string]$receipt.tag -ceq $Tag) 'tag mismatch'
    Assert-ParserFuzzReceiptCondition (
        [string]$receipt.tag_object -ceq $TagObject
    ) 'tag object mismatch'
    Assert-ParserFuzzReceiptCondition ([string]$receipt.commit -ceq $Commit) 'commit mismatch'
    Assert-ParserFuzzReceiptCondition (
        [string]$receipt.repository -ceq $Repository
    ) 'repository mismatch'
    Assert-ParserFuzzReceiptCondition (
        [string]$receipt.workflow_ref -ceq (
            "$Repository/.github/workflows/parser-fuzz.yml@refs/tags/$Tag"
        )
    ) 'workflow_ref is not the exact tagged reusable workflow'
    Assert-ParserFuzzReceiptCondition ([string]$receipt.run_id -ceq $RunId) 'run_id mismatch'
    Assert-ParserFuzzReceiptCondition (
        [string]$receipt.run_attempt -ceq $RunAttempt
    ) 'run_attempt mismatch'

    Assert-ParserFuzzReceiptCondition (Test-StrictJsonObject $receipt.toolchain) (
        'toolchain is not an object'
    )
    Assert-ParserFuzzReceiptCondition (
        (($receipt.toolchain.PSObject.Properties.Name | Sort-Object) -join "`n") -ceq
            "cargo_fuzz`nnightly"
    ) 'toolchain does not use the exact closed schema'
    Assert-ParserFuzzReceiptCondition (
        (Test-StrictJsonString $receipt.toolchain.nightly) -and
        [string]$receipt.toolchain.nightly -ceq 'nightly-2026-08-03' -and
        (Test-StrictJsonString $receipt.toolchain.cargo_fuzz) -and
        [string]$receipt.toolchain.cargo_fuzz -ceq '0.13.2'
    ) 'toolchain identity mismatch'

    $expectedMatrix = @(
        @('transfer_protocol', 1048644),
        @('remote_protocol', 131092),
        @('policy_json', 65537)
    )
    Assert-ParserFuzzReceiptCondition (Test-StrictJsonArray $receipt.matrix) (
        'matrix is not an array'
    )
    Assert-ParserFuzzReceiptCondition (@($receipt.matrix).Count -eq 3) (
        'matrix does not contain exactly three rows'
    )
    for ($index = 0; $index -lt $expectedMatrix.Count; $index++) {
        $row = @($receipt.matrix)[$index]
        Assert-ParserFuzzReceiptCondition (Test-StrictJsonObject $row) (
            "matrix row $index is not an object"
        )
        Assert-ParserFuzzReceiptCondition (
            (($row.PSObject.Properties.Name | Sort-Object) -join "`n") -ceq "max_len`ntarget"
        ) "matrix row $index does not use the exact closed schema"
        Assert-ParserFuzzReceiptCondition (
            (Test-StrictJsonString $row.target) -and
            [string]$row.target -ceq [string]$expectedMatrix[$index][0] -and
            (Test-StrictJsonInteger $row.max_len) -and
            [int64]$row.max_len -eq [int64]$expectedMatrix[$index][1]
        ) "matrix row $index identity mismatch"
    }

    $expectedCommands = @(
        'cargo +nightly-2026-08-03 fuzz run transfer_protocol -- -max_total_time=180 -max_len=1048644 -rss_limit_mb=2048 -timeout=10',
        'cargo +nightly-2026-08-03 fuzz run remote_protocol -- -max_total_time=180 -max_len=131092 -rss_limit_mb=2048 -timeout=10',
        'cargo +nightly-2026-08-03 fuzz run policy_json -- -max_total_time=180 -max_len=65537 -rss_limit_mb=2048 -timeout=10'
    )
    Assert-ParserFuzzReceiptCondition (Test-StrictJsonArray $receipt.corpus_commands) (
        'corpus_commands is not an array'
    )
    $commands = @($receipt.corpus_commands)
    Assert-ParserFuzzReceiptCondition ($commands.Count -eq 3) (
        'corpus_commands does not contain exactly three commands'
    )
    for ($index = 0; $index -lt $expectedCommands.Count; $index++) {
        Assert-ParserFuzzReceiptCondition (
            (Test-StrictJsonString $commands[$index]) -and
            [string]$commands[$index] -ceq $expectedCommands[$index]
        ) "corpus command $index mismatch"
    }

    Assert-ParserFuzzReceiptCondition (Test-StrictJsonObject $receipt.source_digests) (
        'source_digests is not an object'
    )
    $digestNames = @(
        'fuzz_lock', 'parser_fuzz_workflow', 'policy_json_target',
        'remote_protocol_target', 'transfer_protocol_target'
    ) | Sort-Object
    Assert-ParserFuzzReceiptCondition (
        (($receipt.source_digests.PSObject.Properties.Name | Sort-Object) -join "`n") -ceq
            ($digestNames -join "`n")
    ) 'source_digests does not use the exact closed schema'
    foreach ($name in $digestNames) {
        Assert-ParserFuzzReceiptCondition (
            (Test-StrictJsonString $receipt.source_digests.$name) -and
            [string]$receipt.source_digests.$name -cmatch '^[0-9a-f]{64}$'
        ) "source digest '$name' is not lowercase SHA-256"
    }

    Assert-ParserFuzzReceiptCondition (Test-StrictJsonObject $receipt.test_counts) (
        'test_counts is not an object'
    )
    $countNames = @('failed', 'passed', 'skipped', 'unknown')
    Assert-ParserFuzzReceiptCondition (
        (($receipt.test_counts.PSObject.Properties.Name | Sort-Object) -join "`n") -ceq
            (($countNames | Sort-Object) -join "`n")
    ) 'test_counts does not use the exact closed schema'
    foreach ($name in $countNames) {
        Assert-ParserFuzzReceiptCondition (Test-StrictJsonInteger $receipt.test_counts.$name) (
            "test_counts.$name is not an integer"
        )
    }
    Assert-ParserFuzzReceiptCondition (
        [int64]$receipt.test_counts.passed -eq 3 -and
        [int64]$receipt.test_counts.failed -eq 0 -and
        [int64]$receipt.test_counts.skipped -eq 0 -and
        [int64]$receipt.test_counts.unknown -eq 0
    ) 'test counts do not prove all three matrix rows passed'

    return $receipt
}
