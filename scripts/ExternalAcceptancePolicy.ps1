Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'StrictJson.ps1')

function Assert-ExternalAcceptancePolicyConfiguration {
    param([string]$GovernanceMode, [string]$MaintainerLogin)

    if ($GovernanceMode -cnotin @('independent', 'single-maintainer')) {
        throw 'external acceptance policy: unknown or noncanonical governance mode'
    }
    if ($GovernanceMode -ceq 'single-maintainer') {
        if ($MaintainerLogin -cnotmatch '^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$') {
            throw 'external acceptance policy: single-maintainer requires a pinned GitHub login'
        }
    }
    elseif (-not [string]::IsNullOrEmpty($MaintainerLogin)) {
        throw 'external acceptance policy: independent mode cannot carry a maintainer override'
    }
}

function Get-ExternalAcceptanceRecordFields {
    param([string]$GovernanceMode, [string]$MaintainerLogin)
    Assert-ExternalAcceptancePolicyConfiguration $GovernanceMode $MaintainerLogin
    @(
        'schema_version', 'accepted', 'tag', 'tag_object', 'commit',
        'release_manifest_sha256', 'acceptance_owner', 'completed_utc',
        'evidence_manifest_url', 'evidence_manifest_sha256'
    )
    if ($GovernanceMode -ceq 'single-maintainer') { 'governance_mode' }
}

function Assert-ExternalAcceptanceRecordPolicy {
    param($Record, [string]$GovernanceMode, [string]$MaintainerLogin)
    Assert-ExternalAcceptancePolicyConfiguration $GovernanceMode $MaintainerLogin
    # The trusted caller pins the policy; downloaded JSON cannot choose a weaker mode.
    $expectedSchema = if ($GovernanceMode -ceq 'single-maintainer') { 2 } else { 1 }
    if (-not (Test-StrictJsonInteger $Record.schema_version) -or
        $Record.schema_version -ne $expectedSchema) {
        throw 'external acceptance policy: record schema does not match the pinned governance mode'
    }
    if ($GovernanceMode -ceq 'single-maintainer') {
        if (-not (Test-StrictJsonString $Record.governance_mode) -or
            $Record.governance_mode -cne 'single-maintainer') {
            throw 'external acceptance policy: record must explicitly declare single-maintainer'
        }
        if (-not (Test-StrictJsonString $Record.acceptance_owner) -or
            $Record.acceptance_owner -cne $MaintainerLogin) {
            throw 'external acceptance policy: acceptance owner is not the pinned maintainer'
        }
    }
}
