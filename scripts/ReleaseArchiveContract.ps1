Set-StrictMode -Version Latest

$script:ReleaseArchiveMaximumMembers = 64
$script:ReleaseArchiveMaximumExpandedBytes = 1073807360

if ($null -eq ('Serctl.ReleaseCrc32ReadStream' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.IO;

namespace Serctl {
    public sealed class ReleaseCrc32ReadStream : Stream {
        private readonly Stream inner;
        private readonly long maximum;
        private uint crc = 0xffffffffu;
        private long count;
        private static readonly uint[] Table = BuildTable();

        public ReleaseCrc32ReadStream(Stream inner, long maximum) {
            if (inner == null) throw new ArgumentNullException("inner");
            this.inner = inner;
            this.maximum = maximum;
        }
        private static uint[] BuildTable() {
            var table = new uint[256];
            for (uint i = 0; i < table.Length; i++) {
                uint value = i;
                for (int bit = 0; bit < 8; bit++)
                    value = (value & 1) != 0 ? 0xedb88320u ^ (value >> 1) : value >> 1;
                table[i] = value;
            }
            return table;
        }
        public uint Crc32 { get { return crc ^ 0xffffffffu; } }
        public long BytesRead { get { return count; } }
        public override int Read(byte[] buffer, int offset, int length) {
            int read = inner.Read(buffer, offset, length);
            if (read > 0) {
                checked { count += read; }
                if (count > maximum) throw new InvalidDataException("archive expands beyond the global bound");
                for (int i = 0; i < read; i++) crc = Table[(int)((crc ^ buffer[offset + i]) & 0xff)] ^ (crc >> 8);
            }
            return read;
        }
        public override bool CanRead { get { return true; } }
        public override bool CanSeek { get { return false; } }
        public override bool CanWrite { get { return false; } }
        public override long Length { get { throw new NotSupportedException(); } }
        public override long Position { get { throw new NotSupportedException(); } set { throw new NotSupportedException(); } }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) { throw new NotSupportedException(); }
        public override void SetLength(long value) { throw new NotSupportedException(); }
        public override void Write(byte[] buffer, int offset, int count) { throw new NotSupportedException(); }
    }

    public sealed class ReleaseSingleByteReadStream : Stream {
        private readonly Stream inner;
        public ReleaseSingleByteReadStream(Stream inner) {
            if (inner == null) throw new ArgumentNullException("inner");
            this.inner = inner;
        }
        public override int Read(byte[] buffer, int offset, int count) {
            return inner.Read(buffer, offset, Math.Min(count, 1));
        }
        public override int ReadByte() { return inner.ReadByte(); }
        public override bool CanRead { get { return true; } }
        public override bool CanSeek { get { return false; } }
        public override bool CanWrite { get { return false; } }
        public override long Length { get { throw new NotSupportedException(); } }
        public override long Position { get { throw new NotSupportedException(); } set { throw new NotSupportedException(); } }
        public override void Flush() { }
        public override long Seek(long offset, SeekOrigin origin) { throw new NotSupportedException(); }
        public override void SetLength(long value) { throw new NotSupportedException(); }
        public override void Write(byte[] buffer, int offset, int count) { throw new NotSupportedException(); }
    }
}
'@
}

function Get-ReleaseUInt16LittleEndian {
    param([byte[]]$Bytes, [int]$Offset)
    return [uint16]([uint16]$Bytes[$Offset] -bor ([uint16]$Bytes[$Offset + 1] -shl 8))
}

function Get-ReleaseUInt32LittleEndian {
    param([byte[]]$Bytes, [int]$Offset)
    return [uint32](
        [uint64]$Bytes[$Offset] +
        ([uint64]$Bytes[$Offset + 1] * 256) +
        ([uint64]$Bytes[$Offset + 2] * 65536) +
        ([uint64]$Bytes[$Offset + 3] * 16777216)
    )
}

function Assert-ReleaseZipEnvelope {
    param([Parameter(Mandatory = $true)][string]$Path)
    $file = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        if ($file.Length -lt 22) { throw 'ZIP release archive is too short for EOCD' }
        $file.Position = $file.Length - 22
        $eocd = [byte[]]::new(22)
        Read-ReleaseArchiveExactly $file $eocd 0 22 'ZIP EOCD'
        if ((Get-ReleaseUInt32LittleEndian $eocd 0) -ne [uint32]0x06054b50) {
            throw 'ZIP EOCD does not end at physical EOF'
        }
        $disk = Get-ReleaseUInt16LittleEndian $eocd 4
        $centralDisk = Get-ReleaseUInt16LittleEndian $eocd 6
        $diskEntries = Get-ReleaseUInt16LittleEndian $eocd 8
        $totalEntries = Get-ReleaseUInt16LittleEndian $eocd 10
        $centralSize = Get-ReleaseUInt32LittleEndian $eocd 12
        $centralOffset = Get-ReleaseUInt32LittleEndian $eocd 16
        $commentLength = Get-ReleaseUInt16LittleEndian $eocd 20
        if ($disk -ne 0 -or $centralDisk -ne 0 -or $diskEntries -ne $totalEntries -or
            $totalEntries -eq 0xffff -or $centralSize -eq [uint32]::MaxValue -or
            $centralOffset -eq [uint32]::MaxValue -or $commentLength -ne 0) {
            throw 'ZIP release archive uses multipart, ZIP64, or an archive comment'
        }
        if ([long]$centralOffset + [long]$centralSize -ne $file.Length - 22) {
            throw 'ZIP central directory does not exactly precede EOCD'
        }
        return [int]$totalEntries
    }
    finally { $file.Dispose() }
}

function Assert-ReleaseGzipHeader {
    param(
        [Parameter(Mandatory = $true)][System.IO.FileStream]$File
    )
    if ($File.Length -lt 18) { throw 'gzip archive is too short' }
    $header = [byte[]]::new(10)
    Read-ReleaseArchiveExactly $File $header 0 10 'gzip header'
    if ($header[0] -ne 0x1f -or $header[1] -ne 0x8b -or $header[2] -ne 8 -or
        $header[3] -ne 0) {
        throw 'gzip archive does not use the canonical single-member header'
    }
}

function Assert-ReleaseGzipTrailerAtPhysicalEnd {
    param(
        [Parameter(Mandatory = $true)][System.IO.FileStream]$File,
        [Parameter(Mandatory = $true)][uint32]$Crc32,
        [Parameter(Mandatory = $true)][long]$ExpandedLength
    )
    if ($File.Position + 8 -ne $File.Length) {
        throw 'gzip member trailer does not end at physical EOF'
    }
    $trailer = [byte[]]::new(8)
    Read-ReleaseArchiveExactly $File $trailer 0 8 'gzip trailer'
    $storedCrc = Get-ReleaseUInt32LittleEndian $trailer 0
    $storedSize = Get-ReleaseUInt32LittleEndian $trailer 4
    if ($storedCrc -ne $Crc32 -or $storedSize -ne [uint32]$ExpandedLength) {
        throw 'gzip trailer does not bind the complete expanded stream'
    }
}

function Read-ReleaseArchiveExactly {
    param(
        [Parameter(Mandatory = $true)][System.IO.Stream]$Stream,
        [Parameter(Mandatory = $true)][byte[]]$Buffer,
        [int]$Offset = 0,
        [Parameter(Mandatory = $true)][int]$Count,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $end = $Offset + $Count
    while ($Offset -lt $end) {
        $read = $Stream.Read($Buffer, $Offset, $end - $Offset)
        if ($read -le 0) {
            throw "$Label is truncated"
        }
        $Offset += $read
    }
}

function ConvertFrom-ReleaseTarOctal {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Bytes,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $text = [System.Text.Encoding]::ASCII.GetString($Bytes).Trim([char]0, [char]32)
    if ($text.Length -eq 0) { return [long]0 }
    if ($text -cnotmatch '^[0-7]+$') { throw "$Label is not canonical octal" }
    $value = [long]0
    foreach ($character in $text.ToCharArray()) {
        if ($value -gt ([long]::MaxValue - 7) / 8) { throw "$Label overflows" }
        $value = ($value * 8) + ([int]$character - [int][char]'0')
    }
    return $value
}

function Get-ReleaseTarText {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Header,
        [Parameter(Mandatory = $true)][int]$Offset,
        [Parameter(Mandatory = $true)][int]$Length,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $slice = [byte[]]::new($Length)
    [Array]::Copy($Header, $Offset, $slice, 0, $Length)
    $terminator = [Array]::IndexOf($slice, [byte]0)
    if ($terminator -lt 0) { $terminator = $Length }
    for ($index = 0; $index -lt $terminator; $index++) {
        if ($slice[$index] -lt 0x20 -or $slice[$index] -gt 0x7e) {
            throw "$Label contains a non-ASCII or control byte"
        }
    }
    return [System.Text.Encoding]::ASCII.GetString($slice, 0, $terminator)
}

function Get-CheckedReleaseMemberName {
    param(
        [Parameter(Mandatory = $true)][string]$RawName,
        [Parameter(Mandatory = $true)][string]$Label
    )

    $name = if ($RawName.StartsWith('./', [StringComparison]::Ordinal)) {
        $RawName.Substring(2)
    } else { $RawName }
    if (
        [string]::IsNullOrEmpty($name) -or
        $name -ceq '.' -or $name -ceq '..' -or
        $name.Contains('/') -or $name.Contains('\') -or
        $name.Contains("`r") -or $name.Contains("`n") -or
        $name -cne [System.IO.Path]::GetFileName($name)
    ) {
        throw "$Label is not one top-level plain filename"
    }
    return $name
}

function Add-CheckedReleaseArchiveMember {
    param(
        [Parameter(Mandatory = $true)][hashtable]$Snapshot,
        [Parameter(Mandatory = $true)]$CaseInsensitiveNames,
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$Hash,
        [Parameter(Mandatory = $true)][long]$Length
    )

    if (-not $CaseInsensitiveNames.Add($Name)) {
        throw "release archive contains a duplicate or case-colliding member"
    }
    if ($Snapshot.ContainsKey($Name)) {
        throw "release archive contains a duplicate member"
    }
    if ($Name -cmatch '^(?:serctl-remote(?:\.debug)?|serctl-jobs|serctl-policy|serctl-remote-protocol)$') {
        throw "release archive contains a source-only component"
    }
    $Snapshot[$Name] = [pscustomobject]@{ Hash = $Hash; Length = $Length }
}

function Get-VerifiedZipReleaseMembers {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$AllowedNames
    )

    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $snapshot = @{}
    $caseNames = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    $archiveTotal = [long]0
    $expectedEntryCount = Assert-ReleaseZipEnvelope $Path
    if ($expectedEntryCount -ne $AllowedNames.Count -or
        $expectedEntryCount -gt $script:ReleaseArchiveMaximumMembers) {
        throw 'ZIP EOCD member count differs from the exact allowlist'
    }
    $archive = [System.IO.Compression.ZipFile]::OpenRead($Path)
    try {
        if ($archive.Entries.Count -ne $expectedEntryCount) {
            throw 'ZIP central directory entry count mismatch'
        }
        foreach ($entry in $archive.Entries) {
            if ($entry.FullName.EndsWith('/', [StringComparison]::Ordinal) -or
                [string]::IsNullOrEmpty($entry.Name)) {
                throw 'ZIP release archive contains a directory entry'
            }
            $unixType = (($entry.ExternalAttributes -shr 16) -band 0xF000)
            if ($unixType -eq 0xA000) {
                throw 'ZIP release archive contains a symbolic link'
            }
            if ($unixType -ne 0 -and $unixType -ne 0x8000) {
                throw 'ZIP release archive contains a non-regular member'
            }
            $dosAttributes = $entry.ExternalAttributes -band 0xffff
            if (($dosAttributes -band 0x10) -ne 0 -or
                ($dosAttributes -band 0x400) -ne 0) {
                throw 'ZIP release archive contains a DOS directory or reparse-point member'
            }
            $name = Get-CheckedReleaseMemberName $entry.FullName 'ZIP member name'
            if (-not $AllowedNames.Contains($name)) {
                throw "ZIP release archive contains an unexpected member '$name'"
            }
            if ($entry.Length -le 0 -or $entry.Length -gt 536870912) {
                throw 'ZIP release archive member size is outside the bound'
            }
            $archiveTotal += $entry.Length
            if ($archiveTotal -gt 1073741824) {
                throw 'ZIP release archive expands beyond the total size bound'
            }
            $stream = $entry.Open()
            $sha = [System.Security.Cryptography.SHA256]::Create()
            try {
                $buffer = [byte[]]::new(65536)
                $total = [long]0
                while (($read = $stream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    $total += $read
                    if ($total -gt 536870912) { throw 'ZIP member exceeded its size bound' }
                    [void]$sha.TransformBlock($buffer, 0, $read, $null, 0)
                }
                [void]$sha.TransformFinalBlock([byte[]]::new(0), 0, 0)
                if ($total -ne $entry.Length) { throw 'ZIP member length changed while reading' }
                $hash = ([BitConverter]::ToString($sha.Hash)).Replace('-', '').ToLowerInvariant()
            }
            finally {
                $sha.Dispose()
                $stream.Dispose()
            }
            Add-CheckedReleaseArchiveMember $snapshot $caseNames $name $hash $total
        }
    }
    finally { $archive.Dispose() }
    return $snapshot
}

function Get-VerifiedTarGzReleaseMembers {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)]$AllowedNames
    )

    $snapshot = @{}
    $caseNames = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::OrdinalIgnoreCase
    )
    $archiveTotal = [long]0
    $headerCount = 0
    $file = [System.IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    $singleByte = $null
    $deflate = $null
    $tracked = $null
    try {
        Assert-ReleaseGzipHeader $file
        $singleByte = [Serctl.ReleaseSingleByteReadStream]::new($file)
        $deflate = [IO.Compression.DeflateStream]::new(
            $singleByte,
            [IO.Compression.CompressionMode]::Decompress,
            $true
        )
        $tracked = [Serctl.ReleaseCrc32ReadStream]::new(
            $deflate,
            [long]$script:ReleaseArchiveMaximumExpandedBytes
        )
        $header = [byte[]]::new(512)
        $zeroBlocks = 0
        while ($true) {
            $first = $tracked.Read($header, 0, 512)
            if ($first -eq 0) { break }
            if ($first -lt 512) {
                Read-ReleaseArchiveExactly `
                    -Stream $tracked -Buffer $header -Offset $first `
                    -Count (512 - $first) -Label 'tar header'
            }
            $allZero = $true
            foreach ($byte in $header) { if ($byte -ne 0) { $allZero = $false; break } }
            if ($allZero) {
                $zeroBlocks++
                if ($zeroBlocks -eq 2) { break }
                continue
            }
            if ($zeroBlocks -ne 0) { throw 'tar archive contains data after a zero block' }

            $headerCount++
            if ($headerCount -gt $script:ReleaseArchiveMaximumMembers) {
                throw 'tar archive exceeds the global header-count bound'
            }

            $storedBytes = [byte[]]::new(8)
            [Array]::Copy($header, 148, $storedBytes, 0, 8)
            $storedChecksum = ConvertFrom-ReleaseTarOctal $storedBytes 'tar checksum'
            $computedChecksum = [long]0
            for ($index = 0; $index -lt 512; $index++) {
                $computedChecksum += if ($index -ge 148 -and $index -lt 156) { 32 } else { $header[$index] }
            }
            if ($storedChecksum -ne $computedChecksum) { throw 'tar header checksum mismatch' }
            $prefix = Get-ReleaseTarText $header 345 155 'tar prefix'
            if ($prefix.Length -ne 0) { throw 'tar archive contains a prefixed or nested member' }
            if ((Get-ReleaseTarText $header 257 6 'tar magic') -cne 'ustar' -or
                (Get-ReleaseTarText $header 263 2 'tar version') -cne '00') {
                throw 'tar archive is not canonical ustar'
            }
            $rawName = Get-ReleaseTarText $header 0 100 'tar member name'
            $type = $header[156]
            $sizeBytes = [byte[]]::new(12)
            [Array]::Copy($header, 124, $sizeBytes, 0, 12)
            $size = ConvertFrom-ReleaseTarOctal $sizeBytes 'tar member size'
            if ($type -eq [byte][char]'5') { throw 'tar release archive contains a directory entry' }
            if ($type -eq [byte][char]'1') { throw 'tar release archive contains a hard link' }
            if ($type -eq [byte][char]'2') { throw 'tar release archive contains a symbolic link' }
            if ($type -ne 0 -and $type -ne [byte][char]'0') {
                throw 'tar release archive contains a non-regular or extended member'
            }
            $linkName = Get-ReleaseTarText $header 157 100 'tar link name'
            if ($linkName.Length -ne 0) { throw 'regular tar member has a link target' }
            if ($size -le 0 -or $size -gt 536870912) { throw 'tar member size is outside the bound' }
            $archiveTotal += $size
            if ($archiveTotal -gt 1073741824) {
                throw 'tar release archive expands beyond the total size bound'
            }
            $name = Get-CheckedReleaseMemberName $rawName 'tar member name'
            if (-not $AllowedNames.Contains($name)) {
                throw "tar release archive contains an unexpected member '$name'"
            }
            $modeBytes = [byte[]]::new(8)
            [Array]::Copy($header, 100, $modeBytes, 0, 8)
            $mode = ConvertFrom-ReleaseTarOctal $modeBytes 'tar member mode'
            $expectedMode = if ($name -ceq 'serctl-xfer') { 493 } else { 420 }
            if ($mode -ne $expectedMode) {
                throw "tar member '$name' does not use the required release mode"
            }
            $sha = [System.Security.Cryptography.SHA256]::Create()
            try {
                $remaining = $size
                $buffer = [byte[]]::new(65536)
                while ($remaining -gt 0) {
                    $take = [int][Math]::Min([long]$buffer.Length, $remaining)
                    Read-ReleaseArchiveExactly `
                        -Stream $tracked -Buffer $buffer -Count $take -Label 'tar member payload'
                    [void]$sha.TransformBlock($buffer, 0, $take, $null, 0)
                    $remaining -= $take
                }
                [void]$sha.TransformFinalBlock([byte[]]::new(0), 0, 0)
                $hash = ([BitConverter]::ToString($sha.Hash)).Replace('-', '').ToLowerInvariant()
            }
            finally { $sha.Dispose() }
            $padding = [int]((512 - ($size % 512)) % 512)
            if ($padding -gt 0) {
                $pad = [byte[]]::new($padding)
                Read-ReleaseArchiveExactly `
                    -Stream $tracked -Buffer $pad -Count $padding -Label 'tar member padding'
                foreach ($byte in $pad) { if ($byte -ne 0) { throw 'tar padding is nonzero' } }
            }
            Add-CheckedReleaseArchiveMember $snapshot $caseNames $name $hash $size
        }
        if ($zeroBlocks -ne 2) { throw 'tar archive lacks two terminal zero blocks' }
        $trailing = [byte[]]::new(65536)
        $trailingCount = [long]0
        while (($read = $tracked.Read($trailing, 0, $trailing.Length)) -gt 0) {
            $trailingCount += $read
            if ($trailingCount -gt 16777216) {
                throw 'tar archive has excessive trailing zero padding'
            }
            for ($index = 0; $index -lt $read; $index++) {
                if ($trailing[$index] -ne 0) {
                    throw 'tar archive contains hidden data after its terminal zero blocks'
                }
            }
        }
        $expandedLength = $tracked.BytesRead
        $expandedCrc = $tracked.Crc32
        $tracked.Dispose()
        $tracked = $null
        $deflate.Dispose()
        $deflate = $null
        $singleByte.Dispose()
        $singleByte = $null
        Assert-ReleaseGzipTrailerAtPhysicalEnd $file $expandedCrc $expandedLength
    }
    finally {
        if ($null -ne $tracked) { $tracked.Dispose() }
        if ($null -ne $deflate) { $deflate.Dispose() }
        if ($null -ne $singleByte) { $singleByte.Dispose() }
        $file.Dispose()
    }
    return $snapshot
}

function Get-VerifiedReleaseArchiveMembers {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][ValidateSet('zip', 'tar.gz')][string]$Format,
        [Parameter(Mandatory = $true)][string[]]$ExpectedNames
    )

    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0 -or
        $item.Length -le 0 -or $item.Length -gt 536870912) {
        throw 'release archive is not one bounded regular file'
    }
    if ($ExpectedNames.Count -le 0 -or
        $ExpectedNames.Count -gt $script:ReleaseArchiveMaximumMembers) {
        throw 'release archive expected member count is outside the bound'
    }
    $allowedNames = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal
    )
    foreach ($expectedName in $ExpectedNames) {
        if (-not $allowedNames.Add($expectedName)) {
            throw 'release archive expected names contain a duplicate'
        }
    }
    $snapshot = if ($Format -ceq 'zip') {
        Get-VerifiedZipReleaseMembers $item.FullName $allowedNames
    } else { Get-VerifiedTarGzReleaseMembers $item.FullName $allowedNames }
    $actual = @($snapshot.Keys | Sort-Object)
    $expected = @($ExpectedNames | Sort-Object)
    if (($actual -join "`n") -cne ($expected -join "`n")) {
        throw 'release archive members differ from the exact allowlist'
    }
    return $snapshot
}
