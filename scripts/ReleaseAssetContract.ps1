Set-StrictMode -Version Latest

function Get-V1BetaReleaseInputNames {
    param([Parameter(Mandatory = $true)][string]$Version)

    return @(
        "serctl-$Version-linux-x86_64-xfer-symbols.tar.gz",
        "serctl-$Version-linux-x86_64.provenance.json",
        "serctl-$Version-linux-x86_64-xfer.tar.gz",
        "serctl-$Version-serctl-cli.sbom.cdx.json",
        "serctl-$Version-serctl-cli.sbom.cdx.xml",
        "serctl-$Version-serctl-daemon.sbom.cdx.json",
        "serctl-$Version-serctl-daemon.sbom.cdx.xml",
        "serctl-$Version-serctl-xfer.sbom.cdx.json",
        "serctl-$Version-serctl-xfer.sbom.cdx.xml",
        "serctl-$Version-windows-x86_64-symbols.zip",
        "serctl-$Version-windows-x86_64.provenance.json",
        "serctl-$Version-windows-x86_64.zip"
    ) | Sort-Object
}

function Get-V1BetaHashedReleaseNames {
    param([Parameter(Mandatory = $true)][string]$Version)

    return @(
        (Get-V1BetaReleaseInputNames -Version $Version) +
        'release-provenance.json'
    ) | Sort-Object
}

function Get-V1BetaFinalReleaseNames {
    param([Parameter(Mandatory = $true)][string]$Version)

    return @(
        (Get-V1BetaHashedReleaseNames -Version $Version) +
        'SHA256SUMS'
    ) | Sort-Object
}
