Set-StrictMode -Version Latest

function Get-ReleaseLogLeafName {
    [CmdletBinding()]
    param(
        [AllowEmptyString()][string]$Path,
        [Parameter(Mandatory = $true)][ValidatePattern('^[a-z0-9][a-z0-9._-]{0,63}$')]
        [string]$Fallback
    )

    # Release inputs may originate on a different operating system than the
    # runner validating them. Treat both slash forms as separators so an
    # absolute Windows or UNC path can never become a log-visible leaf on Unix.
    $segments = ([string]$Path) -split '[\\/]'
    $leaf = $segments[-1]
    if ([string]::IsNullOrWhiteSpace($leaf) -or
        $leaf.Length -gt 128 -or
        $leaf -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') {
        return $Fallback
    }
    return $leaf
}

function Format-ReleaseLogRecord {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[a-z][a-z0-9_]{0,63}$')]
        [string]$Category,
        [Parameter(Mandatory = $true)]
        [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$')]
        [string]$LeafName,
        [Parameter(Mandatory = $true)][ValidateRange(0, [long]::MaxValue)]
        [long]$Bytes
    )

    return "category=$Category; file='$LeafName'; bytes=$Bytes"
}
