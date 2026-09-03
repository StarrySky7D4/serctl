[CmdletBinding()]
param(
    [string]$RepositoryRoot,

    [string]$MetadataPath,

    [string[]]$SbomPath = @(),

    [switch]$Offline
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'StrictJson.ps1')

$runtimePackages = @(
    'serctl-cli',
    'serctl-daemon',
    'serctl-xfer'
)
$sourceOnlyPackages = @(
    'serctl-remote',
    'serctl-jobs',
    'serctl-policy',
    'serctl-remote-protocol'
)

function ConvertTo-NormalizedPackageName {
    param([Parameter(Mandatory = $true)][string]$Name)

    return $Name.Replace('_', '-').ToLowerInvariant()
}

function Test-NormalOrBuildEdge {
    param([Parameter(Mandatory = $true)][object]$Dependency)

    if (-not (Test-StrictJsonObject $Dependency)) {
        throw 'cargo metadata dependency edge is not a JSON object'
    }
    $packageProperty = $Dependency.PSObject.Properties['pkg']
    if ($null -eq $packageProperty -or -not (Test-StrictJsonString $Dependency.pkg) -or
        [string]::IsNullOrWhiteSpace([string]$Dependency.pkg)) {
        throw 'cargo metadata dependency edge has no string pkg field'
    }
    $kindsProperty = $Dependency.PSObject.Properties['dep_kinds']
    if ($null -eq $kindsProperty) {
        throw "cargo metadata dependency edge has no dep_kinds field"
    }
    if (-not (Test-StrictJsonArray $Dependency.dep_kinds)) {
        throw 'cargo metadata dependency edge dep_kinds is not a JSON array'
    }
    $kinds = @($Dependency.dep_kinds)
    if ($kinds.Count -eq 0) {
        throw "cargo metadata dependency edge has an empty dep_kinds field"
    }
    $runtimeEdge = $false
    foreach ($kind in $kinds) {
        if (-not (Test-StrictJsonObject $kind)) {
            throw 'cargo metadata dependency kind is not a JSON object'
        }
        $kindProperty = $kind.PSObject.Properties['kind']
        $targetProperty = $kind.PSObject.Properties['target']
        if ($null -eq $kindProperty -or $null -eq $targetProperty) {
            throw "cargo metadata dependency kind lacks kind or target"
        }
        if ($null -ne $kind.kind -and -not (Test-StrictJsonString $kind.kind)) {
            throw 'cargo metadata dependency kind is neither null nor a JSON string'
        }
        if ($null -ne $kind.target -and -not (Test-StrictJsonString $kind.target)) {
            throw 'cargo metadata dependency target is neither null nor a JSON string'
        }
        if ($null -ne $kind.kind -and
            $kind.kind -cne 'build' -and $kind.kind -cne 'dev') {
            throw "cargo metadata contains an unknown dependency kind"
        }
        if ($null -eq $kind.kind -or $kind.kind -ceq 'build') {
            $runtimeEdge = $true
        }
    }
    return $runtimeEdge
}

function Read-CargoMetadata {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [string]$Path,
        [switch]$UseOffline
    )

    if (-not [string]::IsNullOrWhiteSpace($Path)) {
        $fullPath = [System.IO.Path]::GetFullPath($Path)
        if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
            throw "cargo metadata file does not exist: $fullPath"
        }
        $item = Get-Item -LiteralPath $fullPath -Force
        if ($item.Length -le 0 -or $item.Length -gt 16777216 -or
            ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw 'cargo metadata file is empty, oversized, or a reparse point'
        }
        try {
            $json = Read-StrictUtf8Text -Path $fullPath
        }
        catch {
            throw 'cargo metadata is not valid UTF-8'
        }
    }
    else {
        $arguments = @(
            'metadata',
            '--locked',
            '--all-features',
            '--format-version',
            '1'
        )
        if ($UseOffline) {
            $arguments += '--offline'
        }
        Push-Location -LiteralPath $Root
        try {
            $lines = @(& cargo @arguments 2>&1)
            $cargoExit = $LASTEXITCODE
        }
        finally {
            Pop-Location
        }
        if ($cargoExit -ne 0) {
            throw "cargo metadata failed with exit $cargoExit"
        }
        $json = ($lines | Out-String).Trim()
    }

    if ([string]::IsNullOrWhiteSpace($json)) {
        throw 'cargo metadata is empty'
    }
    try {
        return (ConvertFrom-StrictJson `
            -Json $json `
            -Label 'cargo metadata' `
            -MaxChars 8388608)
    }
    catch {
        throw "cargo metadata is not valid JSON: $($_.Exception.Message)"
    }
}

function Assert-RuntimeDependencyGraph {
    param([Parameter(Mandatory = $true)][object]$Metadata)

    if (-not (Test-StrictJsonObject $Metadata)) {
        throw 'cargo metadata root is not a JSON object'
    }
    $versionProperty = $Metadata.PSObject.Properties['version']
    $packagesProperty = $Metadata.PSObject.Properties['packages']
    $resolveProperty = $Metadata.PSObject.Properties['resolve']
    $workspaceMembersProperty = $Metadata.PSObject.Properties['workspace_members']
    if ($null -eq $versionProperty -or $null -eq $packagesProperty -or
        $null -eq $resolveProperty -or $null -eq $workspaceMembersProperty -or
        $null -eq $Metadata.resolve) {
        throw 'cargo metadata lacks version, packages, workspace_members, or a resolved graph'
    }
    if (-not (Test-StrictJsonInteger $Metadata.version) -or $Metadata.version -ne 1) {
        throw 'cargo metadata version is not integer 1'
    }
    if (-not (Test-StrictJsonArray $Metadata.packages) -or
        -not (Test-StrictJsonArray $Metadata.workspace_members) -or
        -not (Test-StrictJsonObject $Metadata.resolve)) {
        throw 'cargo metadata packages/workspace_members/resolve use the wrong JSON shape'
    }
    $nodesProperty = $Metadata.resolve.PSObject.Properties['nodes']
    if ($null -eq $nodesProperty -or -not (Test-StrictJsonArray $Metadata.resolve.nodes)) {
        throw 'cargo metadata resolve.nodes is not a JSON array'
    }

    $packageById = @{}
    $idsByName = @{}
    foreach ($package in @($Metadata.packages)) {
        if (-not (Test-StrictJsonObject $package) -or
            $null -eq $package.PSObject.Properties['id'] -or
            $null -eq $package.PSObject.Properties['name'] -or
            -not (Test-StrictJsonString $package.id) -or
            -not (Test-StrictJsonString $package.name) -or
            [string]::IsNullOrWhiteSpace([string]$package.id) -or
            [string]::IsNullOrWhiteSpace([string]$package.name)) {
            throw 'cargo metadata contains a package without id or name'
        }
        $id = [string]$package.id
        if ($packageById.ContainsKey($id)) {
            throw "cargo metadata contains duplicate package id '$id'"
        }
        $packageById[$id] = $package
        $name = ConvertTo-NormalizedPackageName -Name ([string]$package.name)
        if (-not $idsByName.ContainsKey($name)) {
            $idsByName[$name] = [System.Collections.Generic.List[string]]::new()
        }
        $idsByName[$name].Add($id)
    }

    $nodeById = @{}
    foreach ($node in @($Metadata.resolve.nodes)) {
        if (-not (Test-StrictJsonObject $node) -or
            $null -eq $node.PSObject.Properties['id'] -or
            -not (Test-StrictJsonString $node.id) -or
            $null -eq $node.PSObject.Properties['deps'] -or
            -not (Test-StrictJsonArray $node.deps)) {
            throw 'cargo metadata resolve node has the wrong JSON shape'
        }
        $id = [string]$node.id
        if ([string]::IsNullOrWhiteSpace($id) -or $nodeById.ContainsKey($id)) {
            throw "cargo metadata contains a missing or duplicate resolve node id '$id'"
        }
        $nodeById[$id] = $node
    }

    $packageIds = @($packageById.Keys | Sort-Object)
    $nodeIds = @($nodeById.Keys | Sort-Object)
    if (($packageIds -join "`n") -cne ($nodeIds -join "`n")) {
        throw 'cargo metadata package and resolve-node identity sets are not closed'
    }
    $workspaceIds = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal
    )
    foreach ($member in @($Metadata.workspace_members)) {
        if (-not (Test-StrictJsonString $member) -or
            [string]::IsNullOrWhiteSpace([string]$member) -or
            -not $workspaceIds.Add([string]$member) -or
            -not $packageById.ContainsKey([string]$member)) {
            throw 'cargo metadata workspace_members contains an invalid, duplicate, or unknown id'
        }
    }
    foreach ($requiredWorkspaceName in @($runtimePackages + $sourceOnlyPackages)) {
        if (-not $idsByName.ContainsKey($requiredWorkspaceName) -or
            $idsByName[$requiredWorkspaceName].Count -ne 1 -or
            -not $workspaceIds.Contains($idsByName[$requiredWorkspaceName][0])) {
            throw "expected exactly one workspace package named '$requiredWorkspaceName'"
        }
    }

    $forbidden = @{}
    foreach ($name in $sourceOnlyPackages) {
        $forbidden[$name] = $true
    }

    $violations = [System.Collections.Generic.List[string]]::new()
    foreach ($rootName in $runtimePackages) {
        if (-not $idsByName.ContainsKey($rootName) -or
            $idsByName[$rootName].Count -ne 1) {
            throw "expected exactly one runtime package named '$rootName'"
        }
        $rootId = $idsByName[$rootName][0]
        if (-not $nodeById.ContainsKey($rootId)) {
            throw "runtime package '$rootName' has no resolve node"
        }

        $queue = [System.Collections.Generic.Queue[object]]::new()
        $queue.Enqueue([pscustomobject]@{
            Id = $rootId
            Path = @($rootName)
        })
        $visited = @{}
        $visited[$rootId] = $true

        while ($queue.Count -gt 0) {
            $current = $queue.Dequeue()
            if (-not $nodeById.ContainsKey([string]$current.Id)) {
                throw "resolve graph references missing node '$($current.Id)'"
            }
            foreach ($dependency in @($nodeById[[string]$current.Id].deps)) {
                if (-not (Test-NormalOrBuildEdge -Dependency $dependency)) {
                    continue
                }
                $dependencyId = [string]$dependency.pkg
                if (-not $packageById.ContainsKey($dependencyId)) {
                    throw "resolve graph references missing package '$dependencyId'"
                }
                $dependencyName = ConvertTo-NormalizedPackageName `
                    -Name ([string]$packageById[$dependencyId].name)
                $dependencyPath = @($current.Path) + @($dependencyName)
                if ($forbidden.ContainsKey($dependencyName)) {
                    $violations.Add(($dependencyPath -join ' -> '))
                    continue
                }
                if (-not $visited.ContainsKey($dependencyId)) {
                    $visited[$dependencyId] = $true
                    $queue.Enqueue([pscustomobject]@{
                        Id = $dependencyId
                        Path = $dependencyPath
                    })
                }
            }
        }
    }

    if ($violations.Count -gt 0) {
        throw (
            'runtime normal/build dependency graph reaches source-only package(s): ' +
            (($violations | Sort-Object -Unique) -join '; ')
        )
    }
}

function Get-CargoPackageNameFromPurl {
    param(
        [Parameter(Mandatory = $true)][string]$Value,
        [Parameter(Mandatory = $true)][string]$Label
    )
    if (-not $Value.StartsWith('pkg:cargo/', [System.StringComparison]::Ordinal)) {
        return $null
    }
    $match = [regex]::Match(
        $Value,
        '^pkg:cargo/(?<name>[^@/?#]+)(?:@[^?#]+)?(?:\?[^#]*)?(?:#.*)?$',
        [System.Text.RegularExpressions.RegexOptions]::CultureInvariant
    )
    if (-not $match.Success -or $match.Groups['name'].Value -match '%(?![0-9A-Fa-f]{2})') {
        throw "$Label is not a canonical Cargo purl"
    }
    try {
        $name = [Uri]::UnescapeDataString($match.Groups['name'].Value)
    }
    catch {
        throw "$Label contains invalid percent encoding"
    }
    if ($name -cnotmatch '^[A-Za-z0-9][A-Za-z0-9_.-]*$') {
        throw "$Label contains an invalid Cargo package name"
    }
    return $name
}

function Get-JsonComponentNames {
    param(
        [Parameter(Mandatory = $true)][object]$Value,
        [Parameter(Mandatory = $true)]$References,
        [string]$Label = 'CycloneDX component',
        [int]$Depth = 0
    )
    if ($Depth -gt 64) { throw 'CycloneDX component nesting exceeds 64 levels' }
    if (-not (Test-StrictJsonObject $Value)) { throw "$Label is not a JSON object" }
    foreach ($field in @('type', 'name')) {
        if ($null -eq $Value.PSObject.Properties[$field] -or
            -not (Test-StrictJsonString $Value.$field) -or
            [string]::IsNullOrWhiteSpace([string]$Value.$field)) {
            throw "$Label has no nonempty string $field field"
        }
    }
    $componentName = [string]$Value.name
    if ($componentName -cne $componentName.Trim() -or
        $componentName -cnotmatch '^[A-Za-z0-9][A-Za-z0-9_.-]*$') {
        throw "$Label has a noncanonical package name"
    }
    Write-Output $componentName
    $purlProperty = $Value.PSObject.Properties['purl']
    if ($null -ne $purlProperty) {
        if (-not (Test-StrictJsonString $Value.purl)) {
            throw "$Label purl is not a JSON string"
        }
        $purlName = Get-CargoPackageNameFromPurl -Value ([string]$Value.purl) -Label "$Label.purl"
        if ($null -ne $purlName) {
            if ((ConvertTo-NormalizedPackageName $purlName) -cne
                (ConvertTo-NormalizedPackageName $componentName)) {
                throw "$Label Cargo purl does not match its component name"
            }
            Write-Output $purlName
        }
    }
    $referenceProperty = $Value.PSObject.Properties['bom-ref']
    if ($null -ne $referenceProperty) {
        if (-not (Test-StrictJsonString $Value.'bom-ref') -or
            [string]::IsNullOrWhiteSpace([string]$Value.'bom-ref') -or
            ([string]$Value.'bom-ref').Length -gt 1024 -or
            -not $References.Add([string]$Value.'bom-ref')) {
            throw "$Label has an invalid or duplicate bom-ref"
        }
        $referenceName = Get-CargoPackageNameFromPurl `
            -Value ([string]$Value.'bom-ref') `
            -Label "$Label.bom-ref"
        if ($null -ne $referenceName) {
            if ((ConvertTo-NormalizedPackageName $referenceName) -cne
                (ConvertTo-NormalizedPackageName $componentName)) {
                throw "$Label Cargo bom-ref does not match its component name"
            }
            Write-Output $referenceName
        }
    }
    $nestedProperty = $Value.PSObject.Properties['components']
    if ($null -ne $nestedProperty) {
        if (-not (Test-StrictJsonArray $Value.components)) {
            throw "$Label components is not a JSON array"
        }
        $index = 0
        foreach ($component in @($Value.components)) {
            Get-JsonComponentNames `
                -Value $component `
                -References $References `
                -Label "$Label.components[$index]" `
                -Depth ($Depth + 1)
            $index++
        }
    }
}

function Get-CycloneDxJsonComponentNames {
    param([Parameter(Mandatory = $true)]$Document)
    if (-not (Test-StrictJsonObject $Document)) {
        throw 'CycloneDX JSON root is not a JSON object'
    }
    if ($null -eq $Document.PSObject.Properties['bomFormat'] -or
        -not (Test-StrictJsonString $Document.bomFormat) -or
        $Document.bomFormat -cne 'CycloneDX') {
        throw 'JSON SBOM is not a CycloneDX document'
    }
    if ($null -eq $Document.PSObject.Properties['specVersion'] -or
        -not (Test-StrictJsonString $Document.specVersion) -or
        $Document.specVersion -cnotmatch '^1\.[0-9]+$') {
        throw 'CycloneDX JSON specVersion is missing or invalid'
    }
    if ($null -eq $Document.PSObject.Properties['version'] -or
        -not (Test-StrictJsonInteger $Document.version) -or $Document.version -lt 1) {
        throw 'CycloneDX JSON version is missing or invalid'
    }
    if ($null -eq $Document.PSObject.Properties['components'] -or
        -not (Test-StrictJsonArray $Document.components) -or
        @($Document.components).Count -eq 0) {
        throw 'CycloneDX JSON components is not a nonempty JSON array'
    }
    $references = [System.Collections.Generic.HashSet[string]]::new(
        [System.StringComparer]::Ordinal
    )
    $index = 0
    foreach ($component in @($Document.components)) {
        Get-JsonComponentNames `
            -Value $component `
            -References $references `
            -Label "CycloneDX components[$index]"
        $index++
    }
    $metadataProperty = $Document.PSObject.Properties['metadata']
    if ($null -ne $metadataProperty) {
        if (-not (Test-StrictJsonObject $Document.metadata)) {
            throw 'CycloneDX JSON metadata is not a JSON object'
        }
        $primaryProperty = $Document.metadata.PSObject.Properties['component']
        if ($null -ne $primaryProperty) {
            Get-JsonComponentNames `
                -Value $Document.metadata.component `
                -References $references `
                -Label 'CycloneDX metadata.component'
        }
        $toolsProperty = $Document.metadata.PSObject.Properties['tools']
        if ($null -ne $toolsProperty) {
            if (Test-StrictJsonArray $Document.metadata.tools) {
                $legacyTools = @($Document.metadata.tools)
                if ($legacyTools.Count -eq 0) {
                    throw 'CycloneDX JSON metadata.tools legacy array is empty'
                }
                $index = 0
                $allowedLegacyToolFields = [System.Collections.Generic.HashSet[string]]::new(
                    [System.StringComparer]::Ordinal
                )
                foreach ($allowedToolField in @('vendor', 'name', 'version')) {
                    [void]$allowedLegacyToolFields.Add($allowedToolField)
                }
                foreach ($tool in $legacyTools) {
                    if (-not (Test-StrictJsonObject $tool)) {
                        throw "CycloneDX JSON metadata.tools[$index] is not a JSON object"
                    }
                    foreach ($toolProperty in $tool.PSObject.Properties) {
                        if (-not $allowedLegacyToolFields.Contains($toolProperty.Name)) {
                            throw (
                                "CycloneDX JSON metadata.tools[$index] has unsupported " +
                                "legacy field $($toolProperty.Name)"
                            )
                        }
                    }
                    foreach ($requiredToolField in @('name', 'version')) {
                        if ($null -eq $tool.PSObject.Properties[$requiredToolField] -or
                            -not (Test-StrictJsonString $tool.$requiredToolField) -or
                            [string]::IsNullOrWhiteSpace([string]$tool.$requiredToolField)) {
                            throw (
                                "CycloneDX JSON metadata.tools[$index] has no nonempty " +
                                "string $requiredToolField field"
                            )
                        }
                    }
                    $vendorProperty = $tool.PSObject.Properties['vendor']
                    if ($null -ne $vendorProperty -and
                        (-not (Test-StrictJsonString $tool.vendor) -or
                            [string]::IsNullOrWhiteSpace([string]$tool.vendor))) {
                        throw "CycloneDX JSON metadata.tools[$index] has an invalid vendor"
                    }
                    $index++
                }
            }
            elseif (Test-StrictJsonObject $Document.metadata.tools) {
                $toolComponents = $Document.metadata.tools.PSObject.Properties['components']
                if ($null -ne $toolComponents) {
                    if (-not (Test-StrictJsonArray $Document.metadata.tools.components)) {
                        throw 'CycloneDX JSON metadata.tools.components is not a JSON array'
                    }
                    $index = 0
                    foreach ($component in @($Document.metadata.tools.components)) {
                        Get-JsonComponentNames `
                            -Value $component `
                            -References $references `
                            -Label "CycloneDX metadata.tools.components[$index]"
                        $index++
                    }
                }
            }
            else {
                throw 'CycloneDX JSON metadata.tools is neither an object nor a legacy array'
            }
        }
    }
    $dependenciesProperty = $Document.PSObject.Properties['dependencies']
    if ($null -ne $dependenciesProperty) {
        if (-not (Test-StrictJsonArray $Document.dependencies)) {
            throw 'CycloneDX JSON dependencies is not a JSON array'
        }
        foreach ($dependency in @($Document.dependencies)) {
            if (-not (Test-StrictJsonObject $dependency) -or
                $null -eq $dependency.PSObject.Properties['ref'] -or
                -not (Test-StrictJsonString $dependency.ref)) {
                throw 'CycloneDX JSON dependency has the wrong JSON shape'
            }
            $dependsOnProperty = $dependency.PSObject.Properties['dependsOn']
            if ($null -ne $dependsOnProperty -and
                -not (Test-StrictJsonArray $dependency.dependsOn)) {
                throw 'CycloneDX JSON dependency dependsOn is not a JSON array'
            }
            $dependencyRef = [string]$dependency.ref
            $dependencyRefName = Get-CargoPackageNameFromPurl `
                -Value $dependencyRef `
                -Label 'CycloneDX dependency ref'
            if ($null -ne $dependencyRefName) { Write-Output $dependencyRefName }
            if (-not $references.Contains($dependencyRef)) {
                throw 'CycloneDX JSON dependency ref does not resolve to a component'
            }
            $dependencyReferences = if ($null -eq $dependsOnProperty) {
                @()
            }
            else {
                @($dependency.dependsOn)
            }
            foreach ($reference in $dependencyReferences) {
                if (-not (Test-StrictJsonString $reference) -or
                    -not $references.Contains([string]$reference)) {
                    throw 'CycloneDX JSON dependsOn contains a non-string or unresolved reference'
                }
                $referenceName = Get-CargoPackageNameFromPurl `
                    -Value ([string]$reference) `
                    -Label 'CycloneDX dependency target ref'
                if ($null -ne $referenceName) { Write-Output $referenceName }
            }
        }
    }
}

function Assert-SbomHasNoSourceOnlyComponent {
    param([Parameter(Mandatory = $true)][string]$Path)

    $fullPath = [System.IO.Path]::GetFullPath($Path)
    if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
        throw "SBOM does not exist: $fullPath"
    }
    $item = Get-Item -LiteralPath $fullPath -Force
    if ($item.Length -le 0 -or $item.Length -gt 8388608 -or
        ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw 'CycloneDX document is empty, oversized, or a reparse point'
    }
    $extension = [System.IO.Path]::GetExtension($fullPath).ToLowerInvariant()
    $names = @()
    if ($extension -ceq '.json') {
        try {
            $json = Read-StrictUtf8Text -Path $fullPath
            $document = ConvertFrom-StrictJson `
                -Json $json `
                -Label 'CycloneDX JSON' `
                -MaxChars 8388608
        }
        catch {
            throw 'CycloneDX JSON is invalid'
        }
        $names = @(Get-CycloneDxJsonComponentNames -Document $document)
    }
    elseif ($extension -ceq '.xml') {
        $settings = [System.Xml.XmlReaderSettings]::new()
        $settings.DtdProcessing = [System.Xml.DtdProcessing]::Prohibit
        $settings.XmlResolver = $null
        $settings.MaxCharactersInDocument = 8388608
        $reader = [System.Xml.XmlReader]::Create($fullPath, $settings)
        try {
            $document = [System.Xml.XmlDocument]::new()
            $document.XmlResolver = $null
            $document.Load($reader)
        }
        finally {
            $reader.Dispose()
        }
        $namespace = 'http://cyclonedx.org/schema/bom/1.5'
        if ($document.DocumentElement.LocalName -cne 'bom' -or
            $document.DocumentElement.NamespaceURI -cne $namespace) {
            throw "XML SBOM is not a CycloneDX document: $fullPath"
        }
        $xmlVersion = 0
        if (-not [int]::TryParse(
            $document.DocumentElement.GetAttribute('version'),
            [Globalization.NumberStyles]::None,
            [Globalization.CultureInfo]::InvariantCulture,
            [ref]$xmlVersion
        ) -or $xmlVersion -lt 1) {
            throw 'CycloneDX XML version is missing or invalid'
        }
        $namespaceManager = [System.Xml.XmlNamespaceManager]::new($document.NameTable)
        $namespaceManager.AddNamespace('cdx', $namespace)
        $components = @($document.SelectNodes('//cdx:component', $namespaceManager))
        if ($components.Count -eq 0) {
            throw 'CycloneDX XML contains no components'
        }
        $references = [System.Collections.Generic.HashSet[string]]::new(
            [System.StringComparer]::Ordinal
        )
        foreach ($component in $components) {
            $nameNodes = @($component.SelectNodes('./cdx:name', $namespaceManager))
            $componentType = [string]$component.GetAttribute('type')
            if ($nameNodes.Count -ne 1 -or [string]::IsNullOrWhiteSpace($componentType)) {
                throw 'CycloneDX XML component lacks an exact name or type'
            }
            $componentName = [string]$nameNodes[0].InnerText
            if ($componentName -cne $componentName.Trim() -or
                $componentName -cnotmatch '^[A-Za-z0-9][A-Za-z0-9_.-]*$') {
                throw 'CycloneDX XML component has a noncanonical package name'
            }
            $names += $componentName
            $purlNodes = @($component.SelectNodes('./cdx:purl', $namespaceManager))
            if ($purlNodes.Count -gt 1) {
                throw 'CycloneDX XML component contains duplicate purl values'
            }
            if ($purlNodes.Count -eq 1) {
                $purlName = Get-CargoPackageNameFromPurl `
                    -Value ([string]$purlNodes[0].InnerText) `
                    -Label 'CycloneDX XML component purl'
                if ($null -ne $purlName) {
                    if ((ConvertTo-NormalizedPackageName $purlName) -cne
                        (ConvertTo-NormalizedPackageName $componentName)) {
                        throw 'CycloneDX XML Cargo purl does not match its component name'
                    }
                    $names += $purlName
                }
            }
            $reference = [string]$component.GetAttribute('bom-ref')
            if (-not [string]::IsNullOrEmpty($reference)) {
                if ($reference.Length -gt 1024 -or -not $references.Add($reference)) {
                    throw 'CycloneDX XML component has an invalid or duplicate bom-ref'
                }
                $referenceName = Get-CargoPackageNameFromPurl `
                    -Value $reference `
                    -Label 'CycloneDX XML component bom-ref'
                if ($null -ne $referenceName) {
                    if ((ConvertTo-NormalizedPackageName $referenceName) -cne
                        (ConvertTo-NormalizedPackageName $componentName)) {
                        throw 'CycloneDX XML Cargo bom-ref does not match its component name'
                    }
                    $names += $referenceName
                }
            }
        }
        foreach ($dependency in @($document.SelectNodes('//cdx:dependency', $namespaceManager))) {
            $reference = [string]$dependency.GetAttribute('ref')
            if ([string]::IsNullOrWhiteSpace($reference) -or
                -not $references.Contains($reference)) {
                throw 'CycloneDX XML dependency ref does not resolve to a component'
            }
            $referenceName = Get-CargoPackageNameFromPurl `
                -Value $reference `
                -Label 'CycloneDX XML dependency ref'
            if ($null -ne $referenceName) { $names += $referenceName }
        }
    }
    else {
        throw "SBOM must use a .json or .xml extension: $fullPath"
    }

    $forbiddenNames = @{}
    foreach ($name in $sourceOnlyPackages) {
        $forbiddenNames[$name] = $true
    }
    $found = @(
        $names |
            ForEach-Object { ConvertTo-NormalizedPackageName -Name $_ } |
            Where-Object { $forbiddenNames.ContainsKey($_) } |
            Sort-Object -Unique
    )
    if ($found.Count -gt 0) {
        throw (
            "SBOM '$fullPath' contains source-only component(s): " +
            ($found -join ', ')
        )
    }
}

if ([string]::IsNullOrWhiteSpace($RepositoryRoot)) {
    $RepositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
}
else {
    $RepositoryRoot = [System.IO.Path]::GetFullPath($RepositoryRoot)
}
if (-not (Test-Path -LiteralPath $RepositoryRoot -PathType Container)) {
    throw "repository root does not exist: $RepositoryRoot"
}

$metadata = Read-CargoMetadata `
    -Root $RepositoryRoot `
    -Path $MetadataPath `
    -UseOffline:$Offline
Assert-RuntimeDependencyGraph -Metadata $metadata
foreach ($path in @($SbomPath)) {
    Assert-SbomHasNoSourceOnlyComponent -Path $path
}

Write-Host (
    'Runtime dependency boundary passed for serctl-cli, serctl-daemon, and ' +
    'serctl-xfer (normal/build edges only).'
)
if (@($SbomPath).Count -gt 0) {
    Write-Host "CycloneDX source-only component checks passed: $(@($SbomPath).Count) file(s)."
}
