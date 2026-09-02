[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][ValidateSet('manifest', 'artifacts')]
    [string]$Phase,
    [Parameter(Mandatory = $true)][string]$AcceptanceRecordPath,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9A-F]{64}$')]
    [string]$AcceptanceRecordSha256,
    [Parameter(Mandatory = $true)][string]$AcceptanceRecordUrl,
    [string]$EvidenceManifestPath,
    [Parameter(Mandatory = $true)][string]$ReleaseManifestPath,
    [Parameter(Mandatory = $true)][string]$Tag,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{40}$')][string]$Commit,
    [Parameter(Mandatory = $true)][ValidatePattern('^[0-9a-f]{40}$')][string]$TagObject
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'StrictJson.ps1')

function Assert-PlanCondition {
    param([bool]$Condition, [string]$Message)
    if (-not $Condition) {
        throw "external acceptance download plan failed: $Message"
    }
}

function Get-CheckedHttpsUri {
    param([string]$Value, [string]$Label)
    $uri = $null
    Assert-PlanCondition ([Uri]::TryCreate($Value, [UriKind]::Absolute, [ref]$uri)) (
        "$Label is not absolute"
    )
    Assert-PlanCondition ($uri.Scheme -ceq 'https') "$Label is not HTTPS"
    Assert-PlanCondition (-not [string]::IsNullOrWhiteSpace($uri.DnsSafeHost)) (
        "$Label has no host"
    )
    Assert-PlanCondition ([string]::IsNullOrEmpty($uri.UserInfo)) (
        "$Label contains user information"
    )
    Assert-PlanCondition ([string]::IsNullOrEmpty($uri.Fragment)) (
        "$Label contains a fragment"
    )
    return $uri
}

$recordItem = Get-Item -LiteralPath $AcceptanceRecordPath -Force -ErrorAction Stop
Assert-PlanCondition (
    -not $recordItem.PSIsContainer -and
    ($recordItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0 -and
    $recordItem.Length -gt 0 -and
    $recordItem.Length -le 65536
) 'acceptance record is not one bounded regular file'
Assert-PlanCondition (
    (Get-FileHash -LiteralPath $recordItem.FullName -Algorithm SHA256).Hash -ceq
        $AcceptanceRecordSha256
) 'acceptance record SHA-256 mismatch'
$recordBytes = [System.IO.File]::ReadAllBytes($recordItem.FullName)
Assert-PlanCondition (
    $recordBytes.Length -gt 0 -and $recordBytes.Length -le 65536
) 'acceptance record byte count is outside 1..65536 bytes'
$recordByteHash = $null
$recordHasher = [System.Security.Cryptography.SHA256]::Create()
try {
    $recordByteHash = (
        [System.BitConverter]::ToString($recordHasher.ComputeHash($recordBytes))
    ).Replace('-', '')
}
finally {
    $recordHasher.Dispose()
}
Assert-PlanCondition ($recordByteHash -ceq $AcceptanceRecordSha256) (
    'acceptance record parsed bytes do not match the approved SHA-256'
)
$strictUtf8 = [System.Text.UTF8Encoding]::new($false, $true)
$recordJson = $strictUtf8.GetString($recordBytes)
$record = ConvertFrom-StrictJson -Json $recordJson -Label 'acceptance record'
Assert-PlanCondition (Test-StrictJsonObject $record) 'acceptance record is not a JSON object'
$recordFields = @(
    'schema_version', 'accepted', 'tag', 'tag_object', 'commit',
    'release_manifest_sha256', 'acceptance_owner', 'completed_utc',
    'evidence_manifest_url', 'evidence_manifest_sha256'
) | Sort-Object
$actualRecordFields = @($record.PSObject.Properties.Name | Sort-Object)
Assert-PlanCondition (
    ($actualRecordFields -join "`n") -ceq ($recordFields -join "`n")
) 'acceptance record does not use the exact closed schema'
Assert-PlanCondition (
    (Test-StrictJsonInteger $record.schema_version) -and $record.schema_version -eq 1
) 'acceptance record schema_version is not integer 1'
Assert-PlanCondition (
    (Test-StrictJsonBoolean $record.accepted) -and $record.accepted -eq $true
) (
    'acceptance record does not authorize publication'
)
foreach ($field in @(
    'tag', 'tag_object', 'commit', 'release_manifest_sha256',
    'acceptance_owner', 'completed_utc', 'evidence_manifest_url',
    'evidence_manifest_sha256'
)) {
    Assert-PlanCondition (Test-StrictJsonString $record.$field) (
        "acceptance record field '$field' is not a JSON string"
    )
}
Assert-PlanCondition (
    [string]$record.tag -ceq $Tag -and
    [string]$record.tag_object -ceq $TagObject -and
    [string]$record.commit -ceq $Commit
) 'acceptance record release identity mismatch'
$releaseManifestHash = (
    Get-FileHash -LiteralPath $ReleaseManifestPath -Algorithm SHA256
).Hash
Assert-PlanCondition (
    [string]$record.release_manifest_sha256 -ceq $releaseManifestHash
) 'acceptance record release manifest mismatch'
Assert-PlanCondition (
    -not [string]::IsNullOrWhiteSpace([string]$record.acceptance_owner)
) 'acceptance record owner is empty'
$completed = [DateTimeOffset]::MinValue
Assert-PlanCondition ([DateTimeOffset]::TryParseExact(
    [string]$record.completed_utc,
    'o',
    [Globalization.CultureInfo]::InvariantCulture,
    [Globalization.DateTimeStyles]::RoundtripKind,
    [ref]$completed
)) 'acceptance record completed_utc is not canonical'
$recordUri = Get-CheckedHttpsUri -Value $AcceptanceRecordUrl -Label 'acceptance record URL'
$manifestUri = Get-CheckedHttpsUri `
    -Value ([string]$record.evidence_manifest_url) `
    -Label 'evidence manifest URL'
Assert-PlanCondition (
    [Uri]::Compare(
        $recordUri,
        $manifestUri,
        [UriComponents]::AbsoluteUri,
        [UriFormat]::SafeUnescaped,
        [StringComparison]::OrdinalIgnoreCase
    ) -ne 0
) 'evidence manifest URL equals the acceptance record URL'
Assert-PlanCondition (
    [string]$record.evidence_manifest_sha256 -cmatch '^[0-9A-F]{64}$'
) 'evidence manifest SHA-256 is not canonical uppercase hex'

if ($Phase -ceq 'manifest') {
    [ordered]@{
        schema_version = 1
        manifest_url = [string]$record.evidence_manifest_url
        manifest_sha256 = [string]$record.evidence_manifest_sha256
    } | ConvertTo-Json -Compress
    exit 0
}

Assert-PlanCondition (-not [string]::IsNullOrWhiteSpace($EvidenceManifestPath)) (
    'artifact phase requires an evidence manifest path'
)
$verifier = Join-Path $PSScriptRoot 'Test-ExternalAcceptanceEvidence.ps1'
& $verifier `
    -AcceptanceRecordPath $recordItem.FullName `
    -AcceptanceRecordSha256 $AcceptanceRecordSha256 `
    -AcceptanceRecordUrl $AcceptanceRecordUrl `
    -EvidenceManifestPath $EvidenceManifestPath `
    -ReleaseManifestPath $ReleaseManifestPath `
    -Tag $Tag `
    -Commit $Commit `
    -TagObject $TagObject `
    -EmitArtifactDownloadPlan
