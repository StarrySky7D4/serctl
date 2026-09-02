[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'StrictJson.ps1')

function Assert-StrictJsonTest {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) {
        throw "strict JSON self-test failed: $Message"
    }
}

function Get-Rejection {
    param([string]$Json, [hashtable]$Options = @{})
    try {
        ConvertFrom-StrictJson -Json $Json -Label fixture @Options | Out-Null
    }
    catch {
        return $_.Exception.Message
    }
    throw 'strict JSON self-test expected rejection'
}

$valid = ConvertFrom-StrictJson -Json '{"a":1,"nested":{"b":2}}' -Label fixture
Assert-StrictJsonTest ($valid.a -eq 1 -and $valid.nested.b -eq 2) 'valid object failed'

$duplicate = Get-Rejection '{"a":1,"\u0061":2}'
Assert-StrictJsonTest (
    $duplicate -ceq 'fixture contains a duplicate JSON object key'
) 'duplicate rejection disclosed or changed the decoded key'

$deep = ('[' * 65) + '0' + (']' * 65)
Assert-StrictJsonTest (
    (Get-Rejection $deep).Contains('nesting limit')
) 'over-depth JSON was accepted'

$longDocument = '{"a":"' + ('x' * 80) + '"}'
Assert-StrictJsonTest (
    (Get-Rejection -Json $longDocument -Options @{ MaxChars = 64 }).Contains('character limit')
) 'over-size JSON was accepted'

$longKey = '{"' + ('k' * 257) + '":1}'
Assert-StrictJsonTest (
    (Get-Rejection $longKey).Contains('overlong JSON object key')
) 'overlong JSON key was accepted'

$controlKey = Get-Rejection '{"line\u000akey":1}'
Assert-StrictJsonTest (
    $controlKey -ceq 'fixture contains a control character in a JSON object key' -and
    -not $controlKey.Contains("`n") -and
    -not $controlKey.Contains("`r")
) 'control-key rejection contaminated its error line'

$escapedControlValue = ConvertFrom-StrictJson `
    -Json '{"description":"line one\nline two"}' `
    -Label 'fixture'
Assert-StrictJsonTest (
    $escapedControlValue.description -ceq "line one`nline two"
) 'a valid escaped control character in a JSON string value was rejected'

foreach ($invalidPrimitive in @(
    '{"value":NaN}',
    '{"value":Infinity}',
    '{"value":-Infinity}',
    '{"value":01}',
    '{"value":+1}',
    '{"value":1.}',
    '{"value":.1}',
    '{"value":1e}'
)) {
    Assert-StrictJsonTest (
        (Get-Rejection $invalidPrimitive).Contains('invalid JSON primitive')
    ) "nonstandard primitive '$invalidPrimitive' was accepted"
}

$blockComment = Get-Rejection '{"value":1/* comment */}'
Assert-StrictJsonTest (
    $blockComment.Contains('invalid JSON primitive')
) 'block comment was accepted'

$lineComment = Get-Rejection ('{"value":1// comment' + "`n" + '}')
Assert-StrictJsonTest (
    $lineComment.Contains('invalid JSON primitive')
) 'line comment was accepted'

$nonJsonWhitespace = Get-Rejection (([char]0x00A0) + '{"value":1}')
Assert-StrictJsonTest (
    $nonJsonWhitespace.Contains('invalid JSON primitive')
) 'non-JSON whitespace was accepted'

foreach ($validNumber in @(
    '0', '-0', '1', '-1', '0.1', '-0.1', '1e2', '1E+2', '1e-2'
)) {
    $parsedNumber = ConvertFrom-StrictJson `
        -Json ('{"value":' + $validNumber + '}') `
        -Label fixture
    Assert-StrictJsonTest ($null -ne $parsedNumber.value) (
        "valid JSON number '$validNumber' was rejected"
    )
}

$jsonWhitespace = " `t`r`n" + '{"value":true}' + "`r`n`t "
$whitespaceValue = ConvertFrom-StrictJson -Json $jsonWhitespace -Label fixture
Assert-StrictJsonTest ($whitespaceValue.value -eq $true) (
    'one of SP, TAB, CR, or LF was rejected as JSON whitespace'
)

$primitiveValues = ConvertFrom-StrictJson `
    -Json '{"truth":true,"falsity":false,"nothing":null}' `
    -Label fixture
Assert-StrictJsonTest (
    $primitiveValues.truth -eq $true -and
    $primitiveValues.falsity -eq $false -and
    $null -eq $primitiveValues.nothing
) 'one of the standard true, false, or null primitives was rejected'

foreach ($unpairedSurrogate in @(
    '{"value":"\uD800"}',
    '{"value":"\uDBFFx"}',
    '{"value":"\uDC00"}',
    '{"value":"\uD800\uD800"}',
    '{"value":"\uDC00\uD800"}'
)) {
    Assert-StrictJsonTest (
        (Get-Rejection $unpairedSurrogate).Contains('unpaired Unicode surrogate')
    ) "unpaired surrogate '$unpairedSurrogate' was accepted"
}

$surrogatePair = ConvertFrom-StrictJson `
    -Json '{"value":"\uD83D\uDE00"}' `
    -Label fixture
Assert-StrictJsonTest (
    $surrogatePair.value.Length -eq 2 -and
    [char]::ConvertToUtf32($surrogatePair.value, 0) -eq 0x1F600
) 'a correctly paired escaped Unicode surrogate was rejected'

foreach ($rawUnpaired in @([char]0xD800, [char]0xDC00)) {
    $rawSurrogateJson = '{"value":"' + $rawUnpaired + '"}'
    Assert-StrictJsonTest (
        (Get-Rejection $rawSurrogateJson).Contains('unpaired Unicode surrogate')
    ) 'an unpaired raw UTF-16 surrogate was accepted'
}
$rawPairText = [string]::Concat([char]0xD83D, [char]0xDE00)
$rawPair = ConvertFrom-StrictJson `
    -Json ('{"value":"' + $rawPairText + '"}') `
    -Label fixture
Assert-StrictJsonTest (
    $rawPair.value.Length -eq 2 -and
    [char]::ConvertToUtf32($rawPair.value, 0) -eq 0x1F600
) 'a correctly paired raw UTF-16 surrogate was rejected'

Write-Host 'Strict JSON self-tests passed.'
