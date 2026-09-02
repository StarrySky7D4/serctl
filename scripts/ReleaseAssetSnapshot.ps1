[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Create', 'Verify', 'CopyCreateNew')]
    [string]$Mode,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$Directory,

    [Parameter(Mandatory = $true)]
    [ValidatePattern('^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)-(?:alpha|beta|rc)(?:\.(?:0|[1-9][0-9]*))?$')]
    [string]$Version,

    [Parameter(Mandatory = $true)]
    [ValidateNotNullOrEmpty()]
    [string]$SnapshotPath,

    [Parameter()]
    [ValidateNotNullOrEmpty()]
    [string]$DestinationDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'ReleaseAssetContract.ps1')
. (Join-Path $PSScriptRoot 'StrictJson.ps1')

function Assert-ReleaseSnapshotCondition {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )
    if (-not $Condition) {
        throw "release asset snapshot failed: $Message"
    }
}

function Get-ExactReleaseFiles {
    param([Parameter(Mandatory = $true)][string]$Root)

    $rootItem = Get-Item -LiteralPath $Root -Force -ErrorAction Stop
    Assert-ReleaseSnapshotCondition $rootItem.PSIsContainer "'$Root' is not a directory"
    Assert-ReleaseSnapshotCondition (
        ($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0
    ) "release directory '$Root' is a reparse point"

    $expected = @(Get-V1BetaFinalReleaseNames -Version $Version)
    $entries = @(Get-ChildItem -LiteralPath $Root -Force)
    $actual = @($entries | Sort-Object Name | ForEach-Object { $_.Name })
    Assert-ReleaseSnapshotCondition (
        $expected.Count -eq 14 -and
        $entries.Count -eq 14 -and
        ($actual -join "`n") -ceq (($expected | Sort-Object) -join "`n")
    ) "release directory differs from the exact 14-file allowlist"
    foreach ($entry in $entries) {
        Assert-ReleaseSnapshotCondition (-not $entry.PSIsContainer) (
            "release entry '$($entry.Name)' is a directory"
        )
        Assert-ReleaseSnapshotCondition (
            ($entry.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0
        ) "release entry '$($entry.Name)' is a reparse point"
        Assert-ReleaseSnapshotCondition ($entry.Length -gt 0) (
            "release entry '$($entry.Name)' is empty"
        )
    }
    return @($entries | Sort-Object Name)
}

function Get-HandleBoundFileRecord {
    param([Parameter(Mandatory = $true)][System.IO.FileInfo]$File)

    $stream = [System.IO.FileStream]::new(
        $File.FullName,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read,
        131072,
        [System.IO.FileOptions]::SequentialScan
    )
    try {
        $size = [long]$stream.Length
        Assert-ReleaseSnapshotCondition ($size -gt 0) "release file '$($File.Name)' is empty"
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try { $digestBytes = $sha.ComputeHash($stream) }
        finally { $sha.Dispose() }
        Assert-ReleaseSnapshotCondition ($stream.Length -eq $size) (
            "release file '$($File.Name)' changed while it was hashed"
        )
        $digest = [System.BitConverter]::ToString($digestBytes).Replace('-', '').ToLowerInvariant()
        return [pscustomobject][ordered]@{
            name = $File.Name
            size = $size
            sha256 = $digest
        }
    }
    finally {
        $stream.Dispose()
    }
}

function Get-CurrentReleaseRecords {
    param([Parameter(Mandatory = $true)][string]$Root)
    return @(
        Get-ExactReleaseFiles -Root $Root |
            ForEach-Object { Get-HandleBoundFileRecord -File $_ }
    )
}

function Read-ReleaseSnapshot {
    param([Parameter(Mandatory = $true)][string]$Path)

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    Assert-ReleaseSnapshotCondition (
        -not $item.PSIsContainer -and
        ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0 -and
        $item.Length -gt 0 -and
        $item.Length -le 65536
    ) "snapshot is not one bounded regular file"
    $snapshot = ConvertFrom-StrictJson `
        -Json (Read-StrictUtf8Text -Path $item.FullName) `
        -Label 'release asset snapshot' `
        -MaxChars 65536 `
        -MaxDepth 8
    Assert-ReleaseSnapshotCondition (Test-StrictJsonObject $snapshot) "snapshot is not an object"
    Assert-ReleaseSnapshotCondition (
        (($snapshot.PSObject.Properties.Name | Sort-Object) -join "`n") -ceq
        ((@('files', 'schema_version', 'version') | Sort-Object) -join "`n")
    ) "snapshot does not use the exact schema"
    Assert-ReleaseSnapshotCondition (
        (Test-StrictJsonInteger $snapshot.schema_version) -and $snapshot.schema_version -eq 1
    ) "snapshot schema_version is not 1"
    Assert-ReleaseSnapshotCondition (
        (Test-StrictJsonString $snapshot.version) -and [string]$snapshot.version -ceq $Version
    ) "snapshot version does not match '$Version'"
    Assert-ReleaseSnapshotCondition (Test-StrictJsonArray $snapshot.files) "snapshot files is not an array"
    $files = @($snapshot.files)
    $expectedNames = @(Get-V1BetaFinalReleaseNames -Version $Version)
    Assert-ReleaseSnapshotCondition ($files.Count -eq 14) "snapshot does not contain 14 files"
    $records = @{}
    foreach ($file in $files) {
        Assert-ReleaseSnapshotCondition (Test-StrictJsonObject $file) "snapshot file record is not an object"
        Assert-ReleaseSnapshotCondition (
            (($file.PSObject.Properties.Name | Sort-Object) -join "`n") -ceq
            ((@('name', 'sha256', 'size') | Sort-Object) -join "`n")
        ) "snapshot file record does not use the exact schema"
        Assert-ReleaseSnapshotCondition (
            (Test-StrictJsonString $file.name) -and
            [string]$file.name -ceq [System.IO.Path]::GetFileName([string]$file.name)
        ) "snapshot contains a noncanonical filename"
        Assert-ReleaseSnapshotCondition (-not $records.ContainsKey([string]$file.name)) (
            "snapshot contains duplicate file '$($file.name)'"
        )
        Assert-ReleaseSnapshotCondition (
            (Test-StrictJsonInteger $file.size) -and [long]$file.size -gt 0
        ) "snapshot size for '$($file.name)' is invalid"
        Assert-ReleaseSnapshotCondition (
            (Test-StrictJsonString $file.sha256) -and
            [string]$file.sha256 -cmatch '^[0-9a-f]{64}$'
        ) "snapshot SHA-256 for '$($file.name)' is invalid"
        $records[[string]$file.name] = $file
    }
    Assert-ReleaseSnapshotCondition (
        (($records.Keys | Sort-Object) -join "`n") -ceq (($expectedNames | Sort-Object) -join "`n")
    ) "snapshot filenames differ from the exact 14-file allowlist"
    return $records
}

function Assert-DirectoryMatchesSnapshot {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][hashtable]$Snapshot
    )
    $current = @(Get-CurrentReleaseRecords -Root $Root)
    foreach ($record in $current) {
        $expected = $Snapshot[[string]$record.name]
        Assert-ReleaseSnapshotCondition (
            $null -ne $expected -and
            [long]$record.size -eq [long]$expected.size -and
            [string]$record.sha256 -ceq [string]$expected.sha256
        ) "release file '$($record.name)' differs from the frozen size/SHA-256 snapshot"
    }
}

function Write-ReleaseSnapshotCreateNew {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][object[]]$Records
    )
    $document = [pscustomobject][ordered]@{
        schema_version = 1
        version = $Version
        files = @($Records)
    }
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes(
        (($document | ConvertTo-Json -Depth 4 -Compress) + "`n")
    )
    $parent = Split-Path -Parent ([System.IO.Path]::GetFullPath($Path))
    Assert-ReleaseSnapshotCondition (Test-Path -LiteralPath $parent -PathType Container) (
        "snapshot parent '$parent' does not exist"
    )
    $stream = [System.IO.FileStream]::new(
        [System.IO.Path]::GetFullPath($Path),
        [System.IO.FileMode]::CreateNew,
        [System.IO.FileAccess]::Write,
        [System.IO.FileShare]::None,
        4096,
        [System.IO.FileOptions]::WriteThrough
    )
    try {
        $stream.Write($bytes, 0, $bytes.Length)
        $stream.Flush($true)
    }
    finally { $stream.Dispose() }
}

function Set-ProtectedPublishModes {
    param([Parameter(Mandatory = $true)][string]$Root)

    $isWindowsPlatform = [System.Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
    if ($isWindowsPlatform) {
        foreach ($file in Get-ExactReleaseFiles -Root $Root) {
            $file.Attributes = $file.Attributes -bor [System.IO.FileAttributes]::ReadOnly
        }
        return
    }

    $unixModeType = [System.Type]::GetType('System.IO.UnixFileMode, System.Private.CoreLib', $false)
    $fileType = [System.IO.File]
    $setMode = if ($null -ne $unixModeType) {
        $fileType.GetMethod('SetUnixFileMode', [type[]]@([string], $unixModeType))
    }
    else { $null }
    $getMode = if ($null -ne $unixModeType) {
        $fileType.GetMethod('GetUnixFileMode', [type[]]@([string]))
    }
    else { $null }
    Assert-ReleaseSnapshotCondition ($null -ne $setMode -and $null -ne $getMode) (
        'this non-Windows PowerShell runtime cannot enforce Unix publish-staging modes'
    )
    $fileMode = [Enum]::ToObject($unixModeType, 256) # 0400
    $directoryMode = [Enum]::ToObject($unixModeType, 320) # 0500
    foreach ($file in Get-ExactReleaseFiles -Root $Root) {
        $null = $setMode.Invoke($null, @($file.FullName, $fileMode))
        $actual = $getMode.Invoke($null, @($file.FullName))
        Assert-ReleaseSnapshotCondition ([int]$actual -eq 256) (
            "publish file '$($file.Name)' mode is not 0400"
        )
    }
    $null = $setMode.Invoke($null, @([System.IO.Path]::GetFullPath($Root), $directoryMode))
    $actualRootMode = $getMode.Invoke($null, @([System.IO.Path]::GetFullPath($Root)))
    Assert-ReleaseSnapshotCondition ([int]$actualRootMode -eq 320) (
        'publish directory mode is not 0500'
    )
}

$root = [System.IO.Path]::GetFullPath($Directory)
$snapshotFullPath = [System.IO.Path]::GetFullPath($SnapshotPath)
switch ($Mode) {
    'Create' {
        $records = @(Get-CurrentReleaseRecords -Root $root)
        Write-ReleaseSnapshotCreateNew -Path $snapshotFullPath -Records $records
        $snapshot = Read-ReleaseSnapshot -Path $snapshotFullPath
        Assert-DirectoryMatchesSnapshot -Root $root -Snapshot $snapshot
    }
    'Verify' {
        $snapshot = Read-ReleaseSnapshot -Path $snapshotFullPath
        Assert-DirectoryMatchesSnapshot -Root $root -Snapshot $snapshot
    }
    'CopyCreateNew' {
        Assert-ReleaseSnapshotCondition (
            -not [string]::IsNullOrWhiteSpace($DestinationDirectory)
        ) 'CopyCreateNew requires DestinationDirectory'
        $snapshot = Read-ReleaseSnapshot -Path $snapshotFullPath
        Assert-DirectoryMatchesSnapshot -Root $root -Snapshot $snapshot
        $destination = [System.IO.Path]::GetFullPath($DestinationDirectory)
        Assert-ReleaseSnapshotCondition (-not (Test-Path -LiteralPath $destination)) (
            "publish destination '$destination' already exists"
        )
        [System.IO.Directory]::CreateDirectory($destination) | Out-Null
        foreach ($name in @(Get-V1BetaFinalReleaseNames -Version $Version)) {
            $sourcePath = Join-Path $root $name
            $destinationPath = Join-Path $destination $name
            $source = [System.IO.FileStream]::new(
                $sourcePath,
                [System.IO.FileMode]::Open,
                [System.IO.FileAccess]::Read,
                [System.IO.FileShare]::Read,
                131072,
                [System.IO.FileOptions]::SequentialScan
            )
            try {
                $sourceLength = [long]$source.Length
                $target = [System.IO.FileStream]::new(
                    $destinationPath,
                    [System.IO.FileMode]::CreateNew,
                    [System.IO.FileAccess]::ReadWrite,
                    [System.IO.FileShare]::None,
                    131072,
                    [System.IO.FileOptions]::WriteThrough
                )
                try {
                    $source.CopyTo($target, 131072)
                    $target.Flush($true)
                    Assert-ReleaseSnapshotCondition (
                        $source.Length -eq $sourceLength -and
                        $target.Length -eq [long]$snapshot[$name].size
                    ) "release file '$name' changed while copied to publish staging"
                    $target.Position = 0
                    $sha = [System.Security.Cryptography.SHA256]::Create()
                    try { $digestBytes = $sha.ComputeHash($target) }
                    finally { $sha.Dispose() }
                    $digest = [System.BitConverter]::ToString($digestBytes).Replace('-', '').ToLowerInvariant()
                    Assert-ReleaseSnapshotCondition (
                        $digest -ceq [string]$snapshot[$name].sha256
                    ) "publish copy '$name' differs from the frozen SHA-256"
                }
                finally { $target.Dispose() }
            }
            finally { $source.Dispose() }
        }
        Assert-DirectoryMatchesSnapshot -Root $destination -Snapshot $snapshot
        Set-ProtectedPublishModes -Root $destination
        Assert-DirectoryMatchesSnapshot -Root $destination -Snapshot $snapshot
    }
}

Write-Host "Release asset snapshot $Mode passed."
