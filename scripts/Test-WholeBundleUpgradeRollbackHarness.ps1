[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$harness = Join-Path $PSScriptRoot 'Invoke-WholeBundleUpgradeRollbackHarness.ps1'
if (-not (Test-Path -LiteralPath $harness -PathType Leaf)) {
    throw "whole-bundle harness self-test failed: missing '$harness'"
}

& $harness -SelfTest
& (Join-Path $PSScriptRoot 'Test-WholeBundleRuntimeReceiptContract.ps1')

Write-Host 'Whole-bundle upgrade/rollback harness tests passed.'
