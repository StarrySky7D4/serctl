Set-StrictMode -Version Latest

function Read-StrictUtf8Text {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][string]$Path)

    $encoding = [System.Text.UTF8Encoding]::new($false, $true)
    return [System.IO.File]::ReadAllText($Path, $encoding)
}

function Test-StrictJsonInteger {
    param([AllowNull()]$Value)
    return (
        $Value -is [sbyte] -or $Value -is [byte] -or
        $Value -is [int16] -or $Value -is [uint16] -or
        $Value -is [int32] -or $Value -is [uint32] -or
        $Value -is [int64] -or $Value -is [uint64]
    )
}

function Test-StrictJsonBoolean {
    param([AllowNull()]$Value)
    return $Value -is [bool]
}

function Test-StrictJsonString {
    param([AllowNull()]$Value)
    return $Value -is [string]
}

function Test-StrictJsonObject {
    param([AllowNull()]$Value)
    return $Value -is [pscustomobject]
}

function Test-StrictJsonArray {
    param([AllowNull()]$Value)
    return $Value -is [System.Array]
}

function ConvertFrom-StrictJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string]$Json,
        [Parameter(Mandatory = $true)][string]$Label,
        [ValidateRange(1, 8388608)][int]$MaxChars = 262144,
        [ValidateRange(1, 256)][int]$MaxDepth = 64,
        [ValidateRange(1, 4096)][int]$MaxKeyChars = 256
    )

    if ($Json.Length -gt $MaxChars) {
        throw "$Label exceeds the strict JSON character limit"
    }
    $state = [pscustomobject]@{ Index = 0 }
    $length = $Json.Length
    $skipWhitespace = {
        while ($state.Index -lt $length) {
            $codePoint = [int]$Json[$state.Index]
            if ($codePoint -ne 0x20 -and $codePoint -ne 0x09 -and
                $codePoint -ne 0x0A -and $codePoint -ne 0x0D) {
                break
            }
            $state.Index++
        }
    }
    $readString = {
        param([bool]$IsObjectKey = $false)
        if ($state.Index -ge $length -or $Json[$state.Index] -cne '"') {
            throw "$Label contains an invalid JSON object key"
        }
        $start = $state.Index
        $state.Index++
        while ($state.Index -lt $length) {
            $character = $Json[$state.Index]
            if ([int]$character -lt 0x20) {
                throw "$Label contains an unescaped control character"
            }
            if ($character -ceq '"') {
                $state.Index++
                $token = $Json.Substring($start, $state.Index - $start)
                # Decode only the already bounded key token. The full document
                # is parsed once, after duplicate/depth/key checks complete.
                $decoded = [string](ConvertFrom-Json -InputObject $token)
                if ($IsObjectKey) {
                    if ($decoded.Length -gt $MaxKeyChars) {
                        throw "$Label contains an overlong JSON object key"
                    }
                    if (@($decoded.ToCharArray() | Where-Object { [char]::IsControl($_) }).Count -gt 0) {
                        throw "$Label contains a control character in a JSON object key"
                    }
                }
                return $decoded
            }
            if ($character -ceq '\') {
                $state.Index++
                if ($state.Index -ge $length) {
                    throw "$Label contains an incomplete JSON escape"
                }
                $escape = $Json[$state.Index]
                if ($escape -ceq 'u') {
                    if ($state.Index + 4 -ge $length) {
                        throw "$Label contains an incomplete JSON Unicode escape"
                    }
                    $digits = $Json.Substring($state.Index + 1, 4)
                    if ($digits -cnotmatch '^[0-9A-Fa-f]{4}$') {
                        throw "$Label contains an invalid JSON Unicode escape"
                    }
                    $codeUnit = [Convert]::ToInt32($digits, 16)
                    if ($codeUnit -ge 0xD800 -and $codeUnit -le 0xDBFF) {
                        $lowSlashIndex = $state.Index + 5
                        $lowMarkerIndex = $state.Index + 6
                        $lowDigitsIndex = $state.Index + 7
                        if ($lowDigitsIndex + 3 -ge $length -or
                            $Json[$lowSlashIndex] -cne '\' -or
                            $Json[$lowMarkerIndex] -cne 'u') {
                            throw "$Label contains an unpaired Unicode surrogate"
                        }
                        $lowDigits = $Json.Substring($lowDigitsIndex, 4)
                        if ($lowDigits -cnotmatch '^[0-9A-Fa-f]{4}$') {
                            throw "$Label contains an invalid JSON Unicode escape"
                        }
                        $lowCodeUnit = [Convert]::ToInt32($lowDigits, 16)
                        if ($lowCodeUnit -lt 0xDC00 -or $lowCodeUnit -gt 0xDFFF) {
                            throw "$Label contains an unpaired Unicode surrogate"
                        }
                        # Consume the high escape and its immediately following
                        # low escape as one Unicode scalar value.
                        $state.Index += 11
                        continue
                    }
                    if ($codeUnit -ge 0xDC00 -and $codeUnit -le 0xDFFF) {
                        throw "$Label contains an unpaired Unicode surrogate"
                    }
                    $state.Index += 5
                    continue
                }
                if ('"\/bfnrt'.IndexOf($escape) -lt 0) {
                    throw "$Label contains an invalid JSON escape"
                }
                $state.Index++
                continue
            }
            if ([char]::IsHighSurrogate($character)) {
                if ($state.Index + 1 -ge $length -or
                    -not [char]::IsLowSurrogate($Json[$state.Index + 1])) {
                    throw "$Label contains an unpaired Unicode surrogate"
                }
                $state.Index += 2
                continue
            }
            if ([char]::IsLowSurrogate($character)) {
                throw "$Label contains an unpaired Unicode surrogate"
            }
            $state.Index++
        }
        throw "$Label contains an unterminated JSON string"
    }
    $readValue = $null
    $readValue = {
        param([int]$Depth)
        if ($Depth -gt $MaxDepth) {
            throw "$Label exceeds the strict JSON nesting limit"
        }
        & $skipWhitespace
        if ($state.Index -ge $length) {
            throw "$Label contains an incomplete JSON value"
        }
        $character = $Json[$state.Index]
        if ($character -ceq '{') {
            $state.Index++
            $keys = [System.Collections.Generic.HashSet[string]]::new(
                [System.StringComparer]::OrdinalIgnoreCase
            )
            & $skipWhitespace
            if ($state.Index -lt $length -and $Json[$state.Index] -ceq '}') {
                $state.Index++
                return
            }
            while ($true) {
                & $skipWhitespace
                $key = & $readString $true
                if (-not $keys.Add([string]$key)) {
                    throw "$Label contains a duplicate JSON object key"
                }
                & $skipWhitespace
                if ($state.Index -ge $length -or $Json[$state.Index] -cne ':') {
                    throw "$Label contains a JSON object key without a value"
                }
                $state.Index++
                & $readValue ($Depth + 1)
                & $skipWhitespace
                if ($state.Index -lt $length -and $Json[$state.Index] -ceq '}') {
                    $state.Index++
                    return
                }
                if ($state.Index -ge $length -or $Json[$state.Index] -cne ',') {
                    throw "$Label contains an unterminated JSON object"
                }
                $state.Index++
            }
        }
        if ($character -ceq '[') {
            $state.Index++
            & $skipWhitespace
            if ($state.Index -lt $length -and $Json[$state.Index] -ceq ']') {
                $state.Index++
                return
            }
            while ($true) {
                & $readValue ($Depth + 1)
                & $skipWhitespace
                if ($state.Index -lt $length -and $Json[$state.Index] -ceq ']') {
                    $state.Index++
                    return
                }
                if ($state.Index -ge $length -or $Json[$state.Index] -cne ',') {
                    throw "$Label contains an unterminated JSON array"
                }
                $state.Index++
            }
        }
        if ($character -ceq '"') {
            $null = & $readString $false
            return
        }
        $start = $state.Index
        while ($state.Index -lt $length) {
            $character = $Json[$state.Index]
            $codePoint = [int]$character
            if (
                $codePoint -eq 0x20 -or
                $codePoint -eq 0x09 -or
                $codePoint -eq 0x0A -or
                $codePoint -eq 0x0D -or
                $character -ceq ',' -or
                $character -ceq ']' -or
                $character -ceq '}'
            ) {
                break
            }
            $state.Index++
        }
        if ($state.Index -eq $start) {
            throw "$Label contains an empty JSON value"
        }
        $token = $Json.Substring($start, $state.Index - $start)
        if ($token -cnotmatch '^(?:true|false|null|-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?)$') {
            throw "$Label contains an invalid JSON primitive"
        }
    }

    & $readValue 0
    & $skipWhitespace
    if ($state.Index -ne $length) {
        throw "$Label contains trailing JSON data"
    }
    $convertParameters = @{}
    if ((Get-Command ConvertFrom-Json).Parameters.ContainsKey('DateKind')) {
        $convertParameters['DateKind'] = 'String'
    }
    return (ConvertFrom-Json -InputObject $Json @convertParameters)
}
