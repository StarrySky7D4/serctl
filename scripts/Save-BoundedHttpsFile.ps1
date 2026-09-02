[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Url,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Destination,

    [Parameter(Mandatory = $true)]
    [ValidateRange(1, 8388608)]
    [int]$MaxBytes
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'ReleaseLogSanitization.ps1')

function Assert-DownloadCondition {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if (-not $Condition) {
        throw "bounded HTTPS download failed: $Message"
    }
}

$destinationName = Get-ReleaseLogLeafName -Path $Destination -Fallback 'downloaded-evidence'
$total = [long]0
$failureCategory = 'https_input_invalid'
try {
$uri = $null
Assert-DownloadCondition ([Uri]::TryCreate($Url, [UriKind]::Absolute, [ref]$uri)) (
    'URL is not absolute'
)
Assert-DownloadCondition ($uri.Scheme -ceq 'https') 'URL scheme is not HTTPS'
Assert-DownloadCondition (-not [string]::IsNullOrWhiteSpace($uri.DnsSafeHost)) (
    'URL host is empty'
)
Assert-DownloadCondition ([string]::IsNullOrEmpty($uri.UserInfo)) (
    'URL must not contain user information'
)
Assert-DownloadCondition ([string]::IsNullOrEmpty($uri.Fragment)) (
    'URL must not contain a fragment'
)

$destinationPath = [System.IO.Path]::GetFullPath($Destination)
Assert-DownloadCondition (-not (Test-Path -LiteralPath $destinationPath)) (
    'destination already exists'
)
$parent = [System.IO.Path]::GetDirectoryName($destinationPath)
Assert-DownloadCondition (Test-Path -LiteralPath $parent -PathType Container) (
    'destination parent does not exist'
)
$parentItem = Get-Item -LiteralPath $parent -Force
Assert-DownloadCondition (
    ($parentItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0
) 'destination parent is a reparse point'

$failureCategory = 'https_transport_failed'
$handler = [System.Net.Http.HttpClientHandler]::new()
$handler.AllowAutoRedirect = $false
$client = [System.Net.Http.HttpClient]::new($handler)
$client.Timeout = [TimeSpan]::FromSeconds(30)
$response = $null
$input = $null
$output = $null
$completed = $false
try {
    $response = $client.GetAsync(
        $uri,
        [System.Net.Http.HttpCompletionOption]::ResponseHeadersRead
    ).GetAwaiter().GetResult()
    Assert-DownloadCondition (
        [int]$response.StatusCode -eq 200
    ) 'HTTP response was not accepted'
    if ($response.Content.Headers.ContentLength.HasValue) {
        Assert-DownloadCondition (
            $response.Content.Headers.ContentLength.Value -le $MaxBytes
        ) 'Content-Length exceeds the configured byte limit'
    }

    $failureCategory = 'https_response_rejected'
    $input = $response.Content.ReadAsStreamAsync().GetAwaiter().GetResult()
    $failureCategory = 'https_destination_write_failed'
    $output = [System.IO.FileStream]::new(
        $destinationPath,
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None,
        8192,
        [System.IO.FileOptions]::WriteThrough
    )
    $buffer = [byte[]]::new(8192)
    $total = 0
    while (($read = $input.Read($buffer, 0, $buffer.Length)) -gt 0) {
        $total += $read
        Assert-DownloadCondition ($total -le $MaxBytes) (
            'response body exceeds the configured byte limit'
        )
        $output.Write($buffer, 0, $read)
    }
    Assert-DownloadCondition ($total -gt 0) 'response body is empty'
    $output.Flush($true)
    $completed = $true
}
finally {
    if ($null -ne $output) {
        $output.Dispose()
    }
    if ($null -ne $input) {
        $input.Dispose()
    }
    if ($null -ne $response) {
        $response.Dispose()
    }
    $client.Dispose()
    $handler.Dispose()
    if (-not $completed -and (Test-Path -LiteralPath $destinationPath -PathType Leaf)) {
        [System.IO.File]::Delete($destinationPath)
    }
}

Write-Host (
    'bounded HTTPS download completed: ' +
    (Format-ReleaseLogRecord `
        -Category https_download_completed `
        -LeafName $destinationName `
        -Bytes $total)
)
}
catch {
    [Console]::Error.WriteLine(
        'bounded HTTPS download failed: ' +
        (Format-ReleaseLogRecord `
            -Category $failureCategory `
            -LeafName $destinationName `
            -Bytes $total)
    )
    exit 1
}
