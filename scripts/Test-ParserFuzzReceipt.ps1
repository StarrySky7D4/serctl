[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Path,
    [Parameter(Mandatory = $true)][string]$Tag,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{40}$')][string]$TagObject,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{40}$')][string]$Commit,
    [Parameter(Mandatory = $true)][ValidatePattern('^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')]
    [string]$Repository,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9]+$')][string]$RunId,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9]+$')][string]$RunAttempt
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ParserFuzzReceiptContract.ps1')

$item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
if ($item.PSIsContainer -or
    ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "parser fuzz receipt verification failed: receipt is not a regular file"
}
$bytes = [System.IO.File]::ReadAllBytes($item.FullName)
$null = Read-ValidatedParserFuzzReceipt `
    -Bytes $bytes -Tag $Tag -TagObject $TagObject -Commit $Commit `
    -Repository $Repository -RunId $RunId -RunAttempt $RunAttempt
Write-Host "Verified exact-tag parser fuzz success receipt: $($item.FullName)"
