[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Assert-SelfTest {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Message
    )

    if (-not $Condition) {
        throw "runtime dependency boundary self-test failed: $Message"
    }
}

function Write-Utf8Fixture {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Content
    )

    [System.IO.File]::WriteAllText(
        $Path,
        $Content,
        [System.Text.UTF8Encoding]::new($false)
    )
}

function New-DependencyKind {
    param([object]$Kind)

    return [ordered]@{
        kind = $Kind
        target = $null
    }
}

function New-MetadataFixture {
    param(
        [string]$Root = 'serctl-cli',
        [string]$Target = 'common',
        [object]$Kind = $null,
        [string]$TransitiveTarget
    )

    $names = @(
        'serctl-cli',
        'serctl-daemon',
        'serctl-xfer',
        'common',
        'serctl-remote',
        'serctl-jobs',
        'serctl-policy',
        'serctl-remote-protocol'
    )
    $packages = @(
        $names | ForEach-Object {
            [ordered]@{ id = "fixture#$_"; name = $_ }
        }
    )
    $nodes = @(
        $names | ForEach-Object {
            [ordered]@{ id = "fixture#$_"; deps = @() }
        }
    )
    $rootNode = @($nodes | Where-Object id -ceq "fixture#$Root")[0]
    $rootNode.deps = @(
        [ordered]@{
            name = $Target
            pkg = "fixture#$Target"
            dep_kinds = @(New-DependencyKind -Kind $Kind)
        }
    )
    if (-not [string]::IsNullOrWhiteSpace($TransitiveTarget)) {
        $commonNode = @($nodes | Where-Object id -ceq 'fixture#common')[0]
        $commonNode.deps = @(
            [ordered]@{
                name = $TransitiveTarget
                pkg = "fixture#$TransitiveTarget"
                dep_kinds = @(New-DependencyKind -Kind $null)
            }
        )
    }
    return [ordered]@{
        version = 1
        packages = $packages
        workspace_members = @($packages | ForEach-Object { $_.id })
        resolve = [ordered]@{ nodes = $nodes }
    }
}

function Invoke-BoundaryFixture {
    param(
        [Parameter(Mandatory = $true)][string]$Metadata,
        [string]$Sbom
    )

    $arguments = @(
        '-NoProfile',
        '-File',
        $boundaryScript,
        '-MetadataPath',
        $Metadata
    )
    if (-not [string]::IsNullOrWhiteSpace($Sbom)) {
        $arguments += @('-SbomPath', $Sbom)
    }
    $savedErrorActionPreference = $ErrorActionPreference
    try {
        # Windows PowerShell 5.1 promotes native stderr to ErrorRecord. Expected
        # negative fixtures must be observed through the child exit code rather
        # than terminated by this script's global Stop preference.
        $ErrorActionPreference = 'Continue'
        & $powershell @arguments *> $null
        $childExit = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $savedErrorActionPreference
    }
    return $childExit
}

$boundaryScript = Join-Path $PSScriptRoot 'Test-RuntimeDependencyBoundary.ps1'
$powershell = (Get-Process -Id $PID).Path
$temporaryRoot = Join-Path ([System.IO.Path]::GetTempPath()) (
    'serctl-runtime-boundary-selftest-' + [System.Guid]::NewGuid().ToString('N')
)
[System.IO.Directory]::CreateDirectory($temporaryRoot) | Out-Null
try {
    $metadataPath = Join-Path $temporaryRoot 'metadata.json'
    $allowed = New-MetadataFixture -Root 'serctl-cli' -Target 'common'
    Write-Utf8Fixture `
        -Path $metadataPath `
        -Content ($allowed | ConvertTo-Json -Depth 20)
    Assert-SelfTest ((Invoke-BoundaryFixture -Metadata $metadataPath) -eq 0) (
        'allowed normal dependency graph was rejected'
    )

    $devOnly = New-MetadataFixture `
        -Root 'serctl-xfer' `
        -Target 'serctl-policy' `
        -Kind 'dev'
    Write-Utf8Fixture `
        -Path $metadataPath `
        -Content ($devOnly | ConvertTo-Json -Depth 20)
    Assert-SelfTest ((Invoke-BoundaryFixture -Metadata $metadataPath) -eq 0) (
        'dev-only source package edge was treated as a runtime edge'
    )

    $unknownKind = New-MetadataFixture `
        -Root 'serctl-xfer' `
        -Target 'serctl-policy' `
        -Kind 'runtime'
    Write-Utf8Fixture `
        -Path $metadataPath `
        -Content ($unknownKind | ConvertTo-Json -Depth 20)
    Assert-SelfTest ((Invoke-BoundaryFixture -Metadata $metadataPath) -ne 0) (
        'unknown dependency kind was silently treated as dev-only'
    )

    $mixedUnknownKind = New-MetadataFixture `
        -Root 'serctl-xfer' `
        -Target 'common' `
        -Kind 'build'
    $mixedUnknownKind.resolve.nodes[2].deps[0].dep_kinds +=
        (New-DependencyKind -Kind 'future-kind')
    Write-Utf8Fixture `
        -Path $metadataPath `
        -Content ($mixedUnknownKind | ConvertTo-Json -Depth 20)
    Assert-SelfTest ((Invoke-BoundaryFixture -Metadata $metadataPath) -ne 0) (
        'unknown dependency kind after a build edge was ignored'
    )

    $invalidTarget = New-MetadataFixture -Root 'serctl-xfer' -Target 'common'
    $invalidTarget.resolve.nodes[2].deps[0].dep_kinds[0].target = 7
    Write-Utf8Fixture `
        -Path $metadataPath `
        -Content ($invalidTarget | ConvertTo-Json -Depth 20)
    Assert-SelfTest ((Invoke-BoundaryFixture -Metadata $metadataPath) -ne 0) (
        'numeric cargo dependency target was accepted'
    )

    $mixedKinds = New-MetadataFixture `
        -Root 'serctl-xfer' `
        -Target 'serctl-policy' `
        -Kind 'dev'
    $mixedKinds.resolve.nodes[2].deps[0].dep_kinds = @(
        (New-DependencyKind -Kind 'dev'),
        (New-DependencyKind -Kind 'build')
    )
    Write-Utf8Fixture `
        -Path $metadataPath `
        -Content ($mixedKinds | ConvertTo-Json -Depth 20)
    Assert-SelfTest ((Invoke-BoundaryFixture -Metadata $metadataPath) -ne 0) (
        'mixed dev/build source-only dependency was treated as dev-only'
    )

    foreach ($case in @(
        @{ Name = 'normal'; Root = 'serctl-cli'; Target = 'serctl-remote'; Kind = $null },
        @{ Name = 'build'; Root = 'serctl-daemon'; Target = 'serctl-jobs'; Kind = 'build' }
    )) {
        $fixture = New-MetadataFixture `
            -Root $case.Root `
            -Target $case.Target `
            -Kind $case.Kind
        Write-Utf8Fixture `
            -Path $metadataPath `
            -Content ($fixture | ConvertTo-Json -Depth 20)
        Assert-SelfTest ((Invoke-BoundaryFixture -Metadata $metadataPath) -ne 0) (
            "$($case.Name) source-only dependency did not fail closed"
        )
    }

    $transitive = New-MetadataFixture `
        -Root 'serctl-cli' `
        -Target 'common' `
        -TransitiveTarget 'serctl-remote-protocol'
    Write-Utf8Fixture `
        -Path $metadataPath `
        -Content ($transitive | ConvertTo-Json -Depth 20)
    Assert-SelfTest ((Invoke-BoundaryFixture -Metadata $metadataPath) -ne 0) (
        'transitive source-only dependency did not fail closed'
    )

    $missingRoot = New-MetadataFixture
    $missingRoot.packages = @(
        $missingRoot.packages | Where-Object name -cne 'serctl-xfer'
    )
    $missingRoot.resolve.nodes = @(
        $missingRoot.resolve.nodes | Where-Object id -cne 'fixture#serctl-xfer'
    )
    Write-Utf8Fixture `
        -Path $metadataPath `
        -Content ($missingRoot | ConvertTo-Json -Depth 20)
    Assert-SelfTest ((Invoke-BoundaryFixture -Metadata $metadataPath) -ne 0) (
        'missing runtime root did not fail closed'
    )

    $stringVersion = New-MetadataFixture
    $stringVersion.version = '1'
    Write-Utf8Fixture -Path $metadataPath -Content ($stringVersion | ConvertTo-Json -Depth 20)
    Assert-SelfTest ((Invoke-BoundaryFixture -Metadata $metadataPath) -ne 0) (
        'string cargo metadata version was accepted'
    )

    $orphanNode = New-MetadataFixture
    $orphanNode.resolve.nodes += [ordered]@{ id = 'fixture#orphan'; deps = @() }
    Write-Utf8Fixture -Path $metadataPath -Content ($orphanNode | ConvertTo-Json -Depth 20)
    Assert-SelfTest ((Invoke-BoundaryFixture -Metadata $metadataPath) -ne 0) (
        'orphan cargo metadata resolve node was accepted'
    )

    $packageWithoutNode = New-MetadataFixture
    $packageWithoutNode.resolve.nodes = @(
        $packageWithoutNode.resolve.nodes | Where-Object id -cne 'fixture#serctl-policy'
    )
    Write-Utf8Fixture `
        -Path $metadataPath `
        -Content ($packageWithoutNode | ConvertTo-Json -Depth 20)
    Assert-SelfTest ((Invoke-BoundaryFixture -Metadata $metadataPath) -ne 0) (
        'cargo metadata package without a resolve node was accepted'
    )

    $missingSourceWorkspace = New-MetadataFixture
    $missingSourceWorkspace.workspace_members = @(
        $missingSourceWorkspace.workspace_members |
            Where-Object { $_ -cne 'fixture#serctl-remote' }
    )
    Write-Utf8Fixture `
        -Path $metadataPath `
        -Content ($missingSourceWorkspace | ConvertTo-Json -Depth 20)
    Assert-SelfTest ((Invoke-BoundaryFixture -Metadata $metadataPath) -ne 0) (
        'missing source-only workspace member was accepted'
    )

    Write-Utf8Fixture -Path $metadataPath -Content '{not-json'
    Assert-SelfTest ((Invoke-BoundaryFixture -Metadata $metadataPath) -ne 0) (
        'malformed metadata did not fail closed'
    )

    [System.IO.File]::WriteAllBytes(
        $metadataPath,
        [byte[]](0x7B, 0x22, 0x78, 0x22, 0x3A, 0x22, 0xC3, 0x28, 0x22, 0x7D)
    )
    Assert-SelfTest ((Invoke-BoundaryFixture -Metadata $metadataPath) -ne 0) (
        'invalid UTF-8 metadata did not fail closed'
    )

    Write-Utf8Fixture -Path $metadataPath -Content (
        '{"packages":[],"Packages":[],"resolve":{"nodes":[]}}'
    )
    Assert-SelfTest ((Invoke-BoundaryFixture -Metadata $metadataPath) -ne 0) (
        'case-colliding metadata key did not fail closed'
    )

    Write-Utf8Fixture -Path $metadataPath -Content (
        '{"packages":{},"resolve":{"nodes":[]}}'
    )
    Assert-SelfTest ((Invoke-BoundaryFixture -Metadata $metadataPath) -ne 0) (
        'metadata packages object was accepted as an array'
    )

    $allowed = New-MetadataFixture
    Write-Utf8Fixture `
        -Path $metadataPath `
        -Content ($allowed | ConvertTo-Json -Depth 20)
    $allowedJson = Join-Path $temporaryRoot 'allowed.json'
    $forbiddenJson = Join-Path $temporaryRoot 'forbidden.json'
    Write-Utf8Fixture -Path $allowedJson -Content (
        @{
            bomFormat = 'CycloneDX'
            specVersion = '1.5'
            version = 1
            components = @(@{ type = 'library'; name = 'serde' })
        } |
            ConvertTo-Json -Depth 10
    )
    Write-Utf8Fixture -Path $forbiddenJson -Content (
        @{
            bomFormat = 'CycloneDX'
            specVersion = '1.5'
            version = 1
            components = @(
                @{
                    type = 'library'
                    name = 'container'
                    components = @(@{ type = 'library'; name = 'serctl_policy' })
                }
            )
        } | ConvertTo-Json -Depth 10
    )
    Assert-SelfTest (
        (Invoke-BoundaryFixture -Metadata $metadataPath -Sbom $allowedJson) -eq 0
    ) 'allowed CycloneDX JSON was rejected'
    Assert-SelfTest (
        (Invoke-BoundaryFixture -Metadata $metadataPath -Sbom $forbiddenJson) -ne 0
    ) 'nested source-only CycloneDX JSON component did not fail closed'

    $hiddenPrimaryJson = Join-Path $temporaryRoot 'hidden-primary.json'
    Write-Utf8Fixture -Path $hiddenPrimaryJson -Content (
        @{
            bomFormat = 'CycloneDX'
            specVersion = '1.5'
            version = 1
            metadata = @{ component = @{ type = 'application'; name = 'serctl_remote' } }
            components = @(@{ type = 'library'; name = 'serde' })
        } | ConvertTo-Json -Depth 10
    )
    Assert-SelfTest (
        (Invoke-BoundaryFixture -Metadata $metadataPath -Sbom $hiddenPrimaryJson) -ne 0
    ) 'source-only metadata.component did not fail closed'

    $hiddenToolJson = Join-Path $temporaryRoot 'hidden-tool.json'
    Write-Utf8Fixture -Path $hiddenToolJson -Content (
        @{
            bomFormat = 'CycloneDX'
            specVersion = '1.5'
            version = 1
            metadata = @{
                tools = @{
                    components = @(@{ type = 'application'; name = 'serctl_remote' })
                }
            }
            components = @(@{ type = 'library'; name = 'serde' })
        } | ConvertTo-Json -Depth 10
    )
    Assert-SelfTest (
        (Invoke-BoundaryFixture -Metadata $metadataPath -Sbom $hiddenToolJson) -ne 0
    ) 'source-only metadata.tools.components entry did not fail closed'

    $purlMismatchJson = Join-Path $temporaryRoot 'purl-mismatch.json'
    Write-Utf8Fixture -Path $purlMismatchJson -Content (
        @{
            bomFormat = 'CycloneDX'
            specVersion = '1.5'
            version = 1
            components = @(
                @{
                    type = 'library'
                    name = 'wrapper'
                    purl = 'pkg:cargo/serctl-remote@1.0.0'
                }
            )
        } | ConvertTo-Json -Depth 10
    )
    Assert-SelfTest (
        (Invoke-BoundaryFixture -Metadata $metadataPath -Sbom $purlMismatchJson) -ne 0
    ) 'source-only Cargo purl hidden behind a different name did not fail closed'

    $danglingDependencyJson = Join-Path $temporaryRoot 'dangling-dependency.json'
    Write-Utf8Fixture -Path $danglingDependencyJson -Content (
        @{
            bomFormat = 'CycloneDX'
            specVersion = '1.5'
            version = 1
            components = @(
                @{
                    type = 'library'
                    name = 'serde'
                    'bom-ref' = 'pkg:cargo/serde@1.0.0'
                }
            )
            dependencies = @(
                @{
                    ref = 'pkg:cargo/serde@1.0.0'
                    dependsOn = @('pkg:cargo/serctl-policy@1.0.0')
                }
            )
        } | ConvertTo-Json -Depth 10
    )
    Assert-SelfTest (
        (Invoke-BoundaryFixture -Metadata $metadataPath -Sbom $danglingDependencyJson) -ne 0
    ) 'dangling source-only CycloneDX dependency reference did not fail closed'

    $wrongShapeJson = Join-Path $temporaryRoot 'wrong-shape.json'
    Write-Utf8Fixture -Path $wrongShapeJson -Content (
        '{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,"components":{}}'
    )
    Assert-SelfTest (
        (Invoke-BoundaryFixture -Metadata $metadataPath -Sbom $wrongShapeJson) -ne 0
    ) 'CycloneDX components object was accepted as an array'

    $duplicateKeyJson = Join-Path $temporaryRoot 'duplicate-key.json'
    Write-Utf8Fixture -Path $duplicateKeyJson -Content (
        '{"bomFormat":"CycloneDX","specVersion":"1.5","version":1,' +
        '"components":[],"Components":[]}'
    )
    Assert-SelfTest (
        (Invoke-BoundaryFixture -Metadata $metadataPath -Sbom $duplicateKeyJson) -ne 0
    ) 'case-colliding CycloneDX key did not fail closed'

    $invalidUtf8Json = Join-Path $temporaryRoot 'invalid-utf8.json'
    [System.IO.File]::WriteAllBytes(
        $invalidUtf8Json,
        [byte[]](0x7B, 0x22, 0x78, 0x22, 0x3A, 0x22, 0xC3, 0x28, 0x22, 0x7D)
    )
    Assert-SelfTest (
        (Invoke-BoundaryFixture -Metadata $metadataPath -Sbom $invalidUtf8Json) -ne 0
    ) 'invalid UTF-8 CycloneDX JSON did not fail closed'

    $allowedXml = Join-Path $temporaryRoot 'allowed.xml'
    $forbiddenXml = Join-Path $temporaryRoot 'forbidden.xml'
    Write-Utf8Fixture -Path $allowedXml -Content (
        '<?xml version="1.0"?><bom xmlns="http://cyclonedx.org/schema/bom/1.5" version="1">' +
        '<components><component type="library" bom-ref="pkg:cargo/serde@1.0.0">' +
        '<name>serde</name><purl>pkg:cargo/serde@1.0.0</purl></component></components></bom>'
    )
    Write-Utf8Fixture -Path $forbiddenXml -Content (
        '<?xml version="1.0"?><bom xmlns="http://cyclonedx.org/schema/bom/1.5" version="1">' +
        '<components><component type="library"><name>serctl-jobs</name></component></components></bom>'
    )
    Assert-SelfTest (
        (Invoke-BoundaryFixture -Metadata $metadataPath -Sbom $allowedXml) -eq 0
    ) 'allowed CycloneDX XML was rejected'
    Assert-SelfTest (
        (Invoke-BoundaryFixture -Metadata $metadataPath -Sbom $forbiddenXml) -ne 0
    ) 'source-only CycloneDX XML component did not fail closed'

    $wrongNamespaceXml = Join-Path $temporaryRoot 'wrong-namespace.xml'
    Write-Utf8Fixture -Path $wrongNamespaceXml -Content (
        '<?xml version="1.0"?><bom xmlns="urn:not-cyclonedx" version="1">' +
        '<components><component type="library"><name>serde</name></component></components></bom>'
    )
    Assert-SelfTest (
        (Invoke-BoundaryFixture -Metadata $metadataPath -Sbom $wrongNamespaceXml) -ne 0
    ) 'wrong CycloneDX XML namespace was accepted'

    $dtdXml = Join-Path $temporaryRoot 'dtd.xml'
    Write-Utf8Fixture -Path $dtdXml -Content (
        '<?xml version="1.0"?><!DOCTYPE bom [<!ENTITY x "serde">]>' +
        '<bom xmlns="http://cyclonedx.org/schema/bom/1.5" version="1">' +
        '<components><component type="library"><name>&x;</name></component></components></bom>'
    )
    Assert-SelfTest (
        (Invoke-BoundaryFixture -Metadata $metadataPath -Sbom $dtdXml) -ne 0
    ) 'CycloneDX XML DTD was accepted'

    $oversizedXml = Join-Path $temporaryRoot 'oversized.xml'
    $oversizedFile = [System.IO.File]::Create($oversizedXml)
    try {
        $oversizedFile.SetLength(8388609)
    }
    finally {
        $oversizedFile.Dispose()
    }
    Assert-SelfTest (
        (Invoke-BoundaryFixture -Metadata $metadataPath -Sbom $oversizedXml) -ne 0
    ) 'oversized CycloneDX XML was accepted'
}
finally {
    if (Test-Path -LiteralPath $temporaryRoot -PathType Container) {
        [System.IO.Directory]::Delete($temporaryRoot, $true)
    }
}

Write-Host 'Runtime dependency boundary self-tests passed.'
