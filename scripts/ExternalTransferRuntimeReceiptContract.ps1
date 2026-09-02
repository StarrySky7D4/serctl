Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# The authoritative ledger lives in module-private state. The returned handle
# contains no token, mutable set, observation, details object, or seal bit.
$adapterPath = Join-Path $PSScriptRoot 'ExternalTransferRuntimeAdapter.ps1'
$supervisorPath = Join-Path $PSScriptRoot 'ExternalRuntimeProcessSupervisor.ps1'
$strictJsonPath = Join-Path $PSScriptRoot 'StrictJson.ps1'

$contractModule = New-Module `
    -Name 'Serctl.ExternalTransferRuntimeReceiptContract' `
    -ArgumentList @($adapterPath, $supervisorPath, $strictJsonPath) `
    -ScriptBlock {
    param($AdapterPath, $SupervisorPath, $StrictJsonPath)
    Set-StrictMode -Version Latest
    $ErrorActionPreference = 'Stop'

    . $StrictJsonPath
    . $SupervisorPath
    . $AdapterPath

    $script:IsWindows = [System.Runtime.InteropServices.RuntimeInformation]::IsOSPlatform(
        [System.Runtime.InteropServices.OSPlatform]::Windows
    )
    $script:LedgerStates = [System.Collections.Generic.Dictionary[Guid, object]]::new()
    $script:CaseSets = [ordered]@{
        native_transfer_real_host = @(
            'push_21', 'push_1298223', 'push_67108864', 'push_1073741824',
            'pull_21', 'pull_1298223', 'pull_67108864', 'pull_1073741824',
            'resume_25', 'resume_75', 'lost_ack', 'helper_crash', 'disconnect',
            'daemon_restart', 'disk_full', 'permission_denied', 'target_race',
            'target_symlink_or_reparse', 'unknown_cleanup', 'registry_window'
        )
        openssh_dropbear_interop = @(
            'OpenSSH_exec', 'OpenSSH_directory', 'OpenSSH_tunnel_local',
            'OpenSSH_tunnel_remote', 'OpenSSH_tunnel_dynamic',
            'OpenSSH_sftp', 'OpenSSH_native',
            'Dropbear_exec', 'Dropbear_sftp', 'Dropbear_native'
        )
    }
    $script:NativeFixedTransferCases = [ordered]@{
        push_21 = @('push', 21, '75AEE9DCC9FBE7DDC9394F5BC5D38D9F5AD361F0520F7CEAB59616E38F5950B5')
        push_1298223 = @('push', 1298223, '27C51BE520501C692C8981A8331DE45467D9B7A64B63DD4D3E2CFC2C134F0FAD')
        push_67108864 = @('push', 67108864, '5C8A41A9B8D7FC418BA77B0312EFC461DE86740EF476F4B53ADAB9313C4D1562')
        push_1073741824 = @('push', 1073741824, 'E18E3F358B46EAE9266AC36A5FF6347F6BF09711DFF389597F237D5FE83111D8')
        pull_21 = @('pull', 21, '75AEE9DCC9FBE7DDC9394F5BC5D38D9F5AD361F0520F7CEAB59616E38F5950B5')
        pull_1298223 = @('pull', 1298223, '27C51BE520501C692C8981A8331DE45467D9B7A64B63DD4D3E2CFC2C134F0FAD')
        pull_67108864 = @('pull', 67108864, '5C8A41A9B8D7FC418BA77B0312EFC461DE86740EF476F4B53ADAB9313C4D1562')
        pull_1073741824 = @('pull', 1073741824, 'E18E3F358B46EAE9266AC36A5FF6347F6BF09711DFF389597F237D5FE83111D8')
    }
    $script:InteropTransferCases = [ordered]@{
        OpenSSH_sftp = @('OpenSSH', 'sftp')
        OpenSSH_native = @('OpenSSH', 'native')
        Dropbear_sftp = @('Dropbear', 'sftp')
        Dropbear_native = @('Dropbear', 'native')
    }
    $script:NativeFaultCases = [ordered]@{
        resume_25 = @('completed', 25, 'complete', 1, 0)
        resume_75 = @('completed', 75, 'complete', 1, 0)
        lost_ack = @('outcome_unknown', 0, 'owned_partial_preserved', 0, 1)
        helper_crash = @('outcome_unknown', 0, 'owned_partial_preserved', 0, 1)
        disconnect = @('outcome_unknown', 0, 'owned_partial_preserved', 0, 1)
        daemon_restart = @('outcome_unknown', 0, 'owned_partial_preserved', 0, 1)
        disk_full = @('transfer_failed', 0, 'owned_partial_removed', 0, 0)
        permission_denied = @('transfer_failed', 0, 'owned_partial_removed', 0, 0)
        target_race = @('transfer_failed', 0, 'owned_partial_removed', 0, 0)
        target_symlink_or_reparse = @('transfer_failed', 0, 'no_owned_partial_created', 0, 0)
        unknown_cleanup = @('cleanup_incomplete', 0, 'cleanup_incomplete', 0, 1)
    }

    function Assert-Contract {
        param(
            [Parameter(Mandatory = $true)][bool]$Condition,
            [Parameter(Mandatory = $true)][string]$Message
        )
        if (-not $Condition) {
            throw "external transfer runtime receipt contract failed: $Message"
        }
    }

    function Assert-StrictRetainedString {
        param(
            [Parameter(Mandatory = $true)][string]$Value,
            [Parameter(Mandatory = $true)][string]$Label,
            [ValidateRange(1, 512)][int]$MaximumLength = 512
        )
        Assert-Contract (
            -not [string]::IsNullOrWhiteSpace($Value) -and
            $Value.Length -le $MaximumLength
        ) "$Label is empty or too long"
        Assert-Contract ($Value -notmatch '[\x00-\x1F\x7F]') (
            "$Label contains a control character"
        )
        Assert-Contract (
            $Value -notmatch '^[A-Za-z]:' -and
            $Value -notmatch '^[\\/]' -and
            $Value -notmatch '(^|[\\/])\.\.([\\/]|$)'
        ) "$Label contains a local or traversal-shaped path"
        Assert-Contract (
            $Value -notmatch '(?i)(authorization\s*:|bearer\s+|password|passphrase|' +
                'private.?key|api[_-]?key|access[_-]?token|refresh[_-]?token|' +
                'client[_-]?secret|credential)'
        ) "$Label contains a credential-bearing shape"
    }

    function Assert-ControlledArgumentVector {
        param([Parameter(Mandatory = $true)][string[]]$ArgumentVector)

        Assert-Contract (
            $ArgumentVector.Count -gt 0 -and $ArgumentVector.Count -le 32
        ) 'controlled command argument count is outside 1..32'
        $totalCharacters = 0
        foreach ($argument in $ArgumentVector) {
            Assert-StrictRetainedString `
                -Value $argument `
                -Label 'controlled command argument' `
                -MaximumLength 512
            Assert-Contract ($argument -notmatch '(?i)^-(i|oidentityfile)$') (
                'controlled command uses a forbidden identity-file option'
            )
            Assert-Contract ($argument -notmatch '(?i)^--?(grant|identity-file)(=|$)') (
                'controlled command uses a forbidden credential option'
            )
            $totalCharacters += $argument.Length
        }
        Assert-Contract ($totalCharacters -le 4096) (
            'controlled command argument vector exceeds 4096 characters'
        )
        $leaf = [System.IO.Path]::GetFileName($ArgumentVector[0]).ToLowerInvariant()
        Assert-Contract (
            $leaf -notin @(
                'sh', 'bash', 'dash', 'zsh', 'fish', 'cmd', 'cmd.exe',
                'powershell', 'powershell.exe', 'pwsh', 'pwsh.exe'
            )
        ) 'controlled command uses a forbidden shell wrapper'
    }

    function Get-CanonicalSha256 {
        param([Parameter(Mandatory = $true)][byte[]]$Bytes)
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        try {
            return ([System.BitConverter]::ToString($sha256.ComputeHash($Bytes))).Replace('-', '')
        }
        finally { $sha256.Dispose() }
    }

    function Get-ControlledArgumentDigest {
        param([Parameter(Mandatory = $true)][string[]]$ArgumentVector)
        Assert-ControlledArgumentVector -ArgumentVector $ArgumentVector
        $canonical = [string]::Join([char]0, $ArgumentVector) + [char]0
        $bytes = [System.Text.UTF8Encoding]::new($false, $true).GetBytes($canonical)
        return Get-CanonicalSha256 -Bytes $bytes
    }

    function Test-ExternalTransferRuntimeArgumentVector {
        [CmdletBinding()]
        param([Parameter(Mandatory = $true)][string[]]$ArgumentVector)
        Assert-ControlledArgumentVector -ArgumentVector $ArgumentVector
        return $true
    }

    function Resolve-LedgerState {
        param([Parameter(Mandatory = $true)]$Ledger)
        Assert-Contract ($null -ne $Ledger) 'runtime ledger handle is absent'
        $actual = @($Ledger.PSObject.Properties.Name | Sort-Object)
        $expected = @('category', 'contract_version', 'ledger_id') | Sort-Object
        Assert-Contract (($actual -join "`n") -ceq ($expected -join "`n")) (
            'runtime ledger handle does not use the exact opaque schema'
        )
        Assert-Contract ([int]$Ledger.contract_version -eq 2) (
            'runtime ledger handle version is unsupported'
        )
        $ledgerId = [Guid]::Empty
        Assert-Contract ([Guid]::TryParseExact(
            [string]$Ledger.ledger_id,
            'N',
            [ref]$ledgerId
        )) 'runtime ledger handle id is invalid'
        Assert-Contract $script:LedgerStates.ContainsKey($ledgerId) (
            'runtime ledger handle was not created by this contract module'
        )
        $state = $script:LedgerStates[$ledgerId]
        Assert-Contract ([string]$Ledger.category -ceq [string]$state.category) (
            'runtime ledger handle category was modified'
        )
        return $state
    }

    function New-ExternalTransferRuntimeLedger {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)]
            [ValidateSet('native_transfer_real_host', 'openssh_dropbear_interop')]
            [string]$Category
        )
        $ledgerId = [Guid]::NewGuid()
        $state = [pscustomobject]@{
            ledger_id = $ledgerId
            category = $Category
            expected_case_ids = @($script:CaseSets[$Category])
            observations = [ordered]@{}
            blocked_case_ids = [System.Collections.Generic.HashSet[string]]::new(
                [System.StringComparer]::Ordinal
            )
            # These remain null until an isolated formal owner can supply both
            # objects through a protected in-process channel. They are never
            # accepted as public command parameters or reconstructed from paths.
            protected_formal_config = $null
            exact_release_components = $null
            # The aggregate evidence context binds the exact release/tag,
            # runner, remote and component set.  It is deliberately distinct
            # from the per-operation connection context carried by each child
            # receipt; OpenSSH and Dropbear cases cannot share one operation
            # context.
            expected_evidence_context_sha256 = $null
            bound_evidence_context_sha256 = $null
            operation_context_sha256_by_case = [ordered]@{}
            bound_component_set_sha256 = $null
            bound_component_bytes = $null
            immutable_transfer_cases = [ordered]@{}
            immutable_transfer_details = $null
            immutable_native_fault_cases = [ordered]@{}
            immutable_native_registry = $null
            immutable_native_performance = $null
            # A repository-fixed local child may exercise the native fault,
            # registry and measurement parsers, but it is not remote or
            # exact-tag evidence.  Keep its immutable projection in a distinct
            # slot that Complete never treats as a formal observation.
            immutable_native_fixture_projection = $null
            sealed = $false
            sealed_details = $null
        }
        foreach ($caseId in $state.expected_case_ids) {
            [void]$state.blocked_case_ids.Add($caseId)
        }
        $script:LedgerStates.Add($ledgerId, $state)
        return [pscustomobject]@{
            contract_version = 2
            ledger_id = $ledgerId.ToString('N')
            category = $Category
        }
    }

    function Get-ExternalTransferRuntimeLedgerStatus {
        [CmdletBinding()]
        param([Parameter(Mandatory = $true)]$Ledger)
        $state = Resolve-LedgerState -Ledger $Ledger
        return [pscustomobject]@{
            category = [string]$state.category
            expected = [int]$state.expected_case_ids.Count
            completed = [int]$state.observations.Count
            blocked = [int]$state.blocked_case_ids.Count
            sealed = [bool]$state.sealed
        }
    }

    function Invoke-ExternalTransferRuntimeCase {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)]$Ledger,
            [Parameter(Mandatory = $true)]
            [ValidatePattern('^[A-Za-z0-9_]{1,64}$')]
            [string]$CaseId
        )
        $state = Resolve-LedgerState -Ledger $Ledger
        Assert-Contract (-not $state.sealed) 'runtime ledger is already sealed'
        Assert-Contract ($CaseId -cin $state.expected_case_ids) (
            "runtime case '$CaseId' is outside the exact case set"
        )
        Assert-Contract (-not $state.observations.Contains($CaseId)) (
            "runtime case '$CaseId' is already complete"
        )

        # The adapter owns the exact recipe and exposes no executable, argv,
        # Passed boolean, StructuredResult, result JSON, script block, callback,
        # or receipt input. It currently fails closed before process launch
        # because no isolated formal owner currently provisions the required
        # protected config and exact component set; consequently every real case remains BLOCKED
        # before process launch.
        $observation = Invoke-SerctlFormalRuntimeAdapter `
            -Category ([string]$state.category) `
            -CaseId $CaseId `
            -ProtectedFormalConfig $state.protected_formal_config `
            -ExactReleaseComponents $state.exact_release_components
        try {
            Accept-ExternalTransferRuntimeAdapterObservation `
                -State $state `
                -Observation $observation
        }
        finally {
            if ($null -ne $observation -and $observation.receipt_bytes -is [byte[]]) {
                [Array]::Clear(
                    [byte[]]$observation.receipt_bytes,
                    0,
                    ([byte[]]$observation.receipt_bytes).Length
                )
            }
        }
    }

    function Invoke-ExternalTransferFormalOwnerCase {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)]$Ledger,
            [Parameter(Mandatory = $true)]
            [ValidatePattern('^[A-Za-z0-9_]{1,64}$')]
            [string]$CaseId,
            [Parameter(Mandatory = $true)][byte[]]$VerifiedWindowsProvenanceBytes,
            [Parameter(Mandatory = $true)][byte[]]$VerifiedLinuxProvenanceBytes,
            [Parameter(Mandatory = $true)]$VerifiedComponentPaths,
            [Parameter(Mandatory = $true)]$ExpectedContext,
            [Parameter(Mandatory = $true)][Runtime.InteropServices.SafeHandle]$GrantInputHandle,
            [ValidateRange(1, 3600000)][int]$DeadlineMilliseconds = 30000
        )

        # Exact-tag trusted-script TCB boundary: PowerShell module-private state
        # cannot resist arbitrary code already executing in this process. This
        # owner therefore consumes only provenance bytes retained after the
        # downloaded-set verifier, exact component byte paths, and an already-
        # open purpose-bound Grant handle. It accepts no result, pass Boolean,
        # expected stdout, receipt bytes, executable, argv, or Grant path.
        $state = $null
        $requestBytes = $null
        try {
            $state = Resolve-LedgerState -Ledger $Ledger
            Assert-Contract (-not $state.sealed) 'runtime ledger is already sealed'
            Assert-Contract ($CaseId -cin $state.expected_case_ids) (
                "runtime case '$CaseId' is outside the exact case set"
            )
            Assert-Contract (-not $state.observations.Contains($CaseId)) (
                "runtime case '$CaseId' is already complete"
            )
            Assert-Contract (
                $null -eq $state.protected_formal_config -and
                $null -eq $state.exact_release_components
            ) 'formal owner is already active for this ledger'
            Assert-Contract (
                $null -ne $GrantInputHandle -and
                -not $GrantInputHandle.IsInvalid -and
                -not $GrantInputHandle.IsClosed
            ) 'formal owner Grant handle is unavailable'
            $components = Get-SerctlFormalComponentsFromVerifiedProvenanceInternal `
                -WindowsProvenanceBytes $VerifiedWindowsProvenanceBytes `
                -LinuxProvenanceBytes $VerifiedLinuxProvenanceBytes
            $requestBytes = New-SerctlFormalRuntimeRequestBytesInternal `
                -Category ([string]$state.category) `
                -CaseId $CaseId
            $state.exact_release_components = $components
            $state.protected_formal_config = [pscustomobject][ordered]@{
                schema_version = 'serctl-protected-formal-runtime-config-v1'
                category = [string]$state.category
                case_id = $CaseId
                component_paths = $VerifiedComponentPaths
                request_bytes = $requestBytes
                expected_context = $ExpectedContext
                deadline_ms = $DeadlineMilliseconds
                grant_input_handle = $GrantInputHandle
            }
            Invoke-ExternalTransferRuntimeCase -Ledger $Ledger -CaseId $CaseId
            return Get-ExternalTransferRuntimeLedgerStatus -Ledger $Ledger
        }
        finally {
            if ($null -ne $state) {
                $state.protected_formal_config = $null
                $state.exact_release_components = $null
            }
            if ($null -ne $requestBytes) {
                [Array]::Clear($requestBytes, 0, $requestBytes.Length)
            }
            [Array]::Clear(
                $VerifiedWindowsProvenanceBytes,
                0,
                $VerifiedWindowsProvenanceBytes.Length
            )
            [Array]::Clear(
                $VerifiedLinuxProvenanceBytes,
                0,
                $VerifiedLinuxProvenanceBytes.Length
            )
            if ($null -ne $GrantInputHandle) { $GrantInputHandle.Dispose() }
        }
    }

    function Invoke-ExternalTransferFormalOwnerConcurrentTransferCase {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)]$Ledger,
            [Parameter(Mandatory = $true)]
            [ValidatePattern('^(?:push|pull)_(?:21|1298223|67108864|1073741824)$')]
            [string]$CaseId,
            [Parameter(Mandatory = $true)][byte[]]$VerifiedWindowsProvenanceBytes,
            [Parameter(Mandatory = $true)][byte[]]$VerifiedLinuxProvenanceBytes,
            [Parameter(Mandatory = $true)]$VerifiedComponentPaths,
            [Parameter(Mandatory = $true)]$ExpectedContext,
            [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$LocalPath,
            [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$RemotePath,
            [Parameter(Mandatory = $true)][Runtime.InteropServices.SafeHandle]$TransferGrantInputHandle,
            [Parameter(Mandatory = $true)][Runtime.InteropServices.SafeHandle]$StatusGrantInputHandle,
            [ValidateRange(1, 3600000)][int]$TransferDeadlineMilliseconds = 300000,
            [ValidateRange(1, 3600000)][int]$StatusDeadlineMilliseconds = 30000
        )

        # The exact-tag trusted owner constructs both request streams and the
        # transfer id. Callers provide operation inputs and two already-open,
        # distinct one-shot Grant handles, never transcript/result/receipt data.
        $state = $null
        $primaryBytes = $null
        $statusBytes = $null
        $concurrent = $null
        try {
            $state = Resolve-LedgerState $Ledger
            Assert-Contract ([string]$state.category -ceq 'native_transfer_real_host') (
                'concurrent transfer owner requires the native transfer category'
            )
            Assert-Contract (
                -not $state.sealed -and $CaseId -cin $state.expected_case_ids -and
                -not $state.observations.Contains($CaseId) -and
                $null -eq $state.protected_formal_config -and
                $null -eq $state.exact_release_components
            ) 'concurrent transfer owner ledger state is unavailable'
            foreach ($handle in @($TransferGrantInputHandle, $StatusGrantInputHandle)) {
                Assert-Contract (
                    $null -ne $handle -and -not $handle.IsInvalid -and -not $handle.IsClosed
                ) 'concurrent transfer owner Grant handle is unavailable'
            }
            Assert-Contract (
                $TransferGrantInputHandle.DangerousGetHandle().ToInt64() -ne
                    $StatusGrantInputHandle.DangerousGetHandle().ToInt64()
            ) 'concurrent transfer owner requires distinct Grant handles'
            $components = Get-SerctlFormalComponentsFromVerifiedProvenanceInternal `
                $VerifiedWindowsProvenanceBytes $VerifiedLinuxProvenanceBytes
            # Pin all three downloaded component byte streams before deriving
            # the native helper expectation. The nested identity below is not
            # accepted from the caller: it is copied only from the exact Linux
            # provenance record whose helper bytes were just re-hashed.
            Assert-SerctlFormalComponentSetInternal $components $VerifiedComponentPaths
            $expectedHelperIdentity = [pscustomobject][ordered]@{
                name = [string]$components.helper.name
                binary_size = [long]$components.helper.binary_size
                sha256 = ([string]$components.helper.sha256).ToLowerInvariant()
                version = [string]$components.helper.version
            }
            $random = [byte[]]::new(16)
            $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
            try { $rng.GetBytes($random) } finally { $rng.Dispose() }
            try { $transferId = ([BitConverter]::ToString($random)).Replace('-', '').ToLowerInvariant() }
            finally { [Array]::Clear($random, 0, $random.Length) }
            $direction = if ($CaseId.StartsWith('pull_', [StringComparison]::Ordinal)) {
                'pull'
            } else { 'push' }
            $operation = if ($direction -ceq 'pull') { 'transfer-pull' } else { 'transfer-push' }
            $transferRequest = [pscustomobject][ordered]@{
                schema_version = 1; request_id = [uint64]2; op = $operation
                transfer_id = $transferId; remote = $RemotePath; local = $LocalPath
                backend = 'native'; resume = 'never'; idle_timeout_ms = [uint64]30000
                deadline_ms = [uint64]$TransferDeadlineMilliseconds
                expected_helper_identity = $expectedHelperIdentity
            }
            $primaryText = ((@(
                [pscustomobject][ordered]@{
                    schema_version = 1; request_id = [uint64]1
                    op = 'ssh-connection-identity'
                },
                $transferRequest
            ) | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 8 }) -join "`n") + "`n"
            $statusText = (([pscustomobject][ordered]@{
                schema_version = 1; request_id = [uint64]3; op = 'transfer-status'
                transfer_id = $transferId
            } | ConvertTo-Json -Compress) + "`n")
            $primaryBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes($primaryText)
            $statusBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes($statusText)
            $primaryConfig = [pscustomobject][ordered]@{
                category = [string]$state.category; case_id = $CaseId
                component_paths = $VerifiedComponentPaths; request_bytes = $primaryBytes
                grant_input_handle = $TransferGrantInputHandle
                deadline_ms = $TransferDeadlineMilliseconds
            }
            $statusConfig = [pscustomobject][ordered]@{
                category = [string]$state.category; case_id = $CaseId
                component_paths = $VerifiedComponentPaths; request_bytes = $statusBytes
                grant_input_handle = $StatusGrantInputHandle
                deadline_ms = $StatusDeadlineMilliseconds
            }
            $state.protected_formal_config = [pscustomobject]@{ concurrent_transfer = $true }
            $state.exact_release_components = $components
            $concurrent = Invoke-SerctlFormalConcurrentTransferInternal `
                $primaryConfig $statusConfig $components $transferId $ExpectedContext
            Accept-ExternalTransferRuntimeAdapterObservation $state $concurrent.observation
            return Get-ExternalTransferRuntimeLedgerStatus $Ledger
        }
        finally {
            if ($null -ne $state) {
                $state.protected_formal_config = $null
                $state.exact_release_components = $null
            }
            foreach ($bytes in @(
                $primaryBytes, $statusBytes, $VerifiedWindowsProvenanceBytes,
                $VerifiedLinuxProvenanceBytes
            )) {
                if ($null -ne $bytes -and $bytes -is [byte[]]) {
                    [Array]::Clear($bytes, 0, $bytes.Length)
                }
            }
            if ($null -ne $concurrent -and $concurrent.observation.receipt_bytes -is [byte[]]) {
                [Array]::Clear(
                    $concurrent.observation.receipt_bytes,
                    0,
                    $concurrent.observation.receipt_bytes.Length
                )
            }
            foreach ($handle in @($TransferGrantInputHandle, $StatusGrantInputHandle)) {
                if ($null -ne $handle) { $handle.Dispose() }
            }
        }
    }

    function Get-CanonicalRuntimeComponentBytesInternal {
        param([Parameter(Mandatory = $true)]$Components)

        Assert-SerctlClosedObject $Components @('cli', 'daemon', 'helper') (
            'formal receipt component set'
        )
        $expectedNames = [ordered]@{
            cli = 'serctl_cli.exe'; daemon = 'serctl_daemon.exe'; helper = 'serctl-xfer'
        }
        $versionPatterns = [ordered]@{
            cli = '^serctl_cli 1\.0\.0-beta \(git [0-9a-f]{12}; vault-storage read=v4\.\.=v5 write=v5\)$'
            daemon = '^serctl_daemon 1\.0\.0-beta \(git [0-9a-f]{12}; IPC v9\.\.=v9; vault-storage read=v4\.\.=v5 write=v5\)$'
            helper = '^serctl-xfer 1\.0\.0-beta \(git [0-9a-f]{12}; transfer protocol v1\)$'
        }
        $copy = [ordered]@{}
        foreach ($role in @('cli', 'daemon', 'helper')) {
            $component = $Components.$role
            Assert-SerctlClosedObject $component @('name', 'binary_size', 'sha256', 'version') (
                "formal receipt component $role"
            )
            Assert-Contract (
                [string]$component.name -ceq [string]$expectedNames[$role] -and
                (Test-StrictJsonInteger $component.binary_size) -and
                [long]$component.binary_size -gt 0 -and
                [long]$component.binary_size -le 536870912 -and
                [string]$component.sha256 -cmatch '^[0-9A-F]{64}$' -and
                [string]$component.version -cmatch [string]$versionPatterns[$role]
            ) "formal receipt component $role is invalid"
            $copy[$role] = [pscustomobject][ordered]@{
                name = [string]$component.name
                binary_size = [long]$component.binary_size
                sha256 = [string]$component.sha256
                version = [string]$component.version
            }
        }
        $json = ([pscustomobject]$copy | ConvertTo-Json -Compress -Depth 6) + "`n"
        return ,([Text.UTF8Encoding]::new($false, $true).GetBytes($json))
    }

    function New-ImmutableTransferCaseBytesInternal {
        param(
            [Parameter(Mandatory = $true)][string]$Category,
            [Parameter(Mandatory = $true)][string]$CaseId,
            [Parameter(Mandatory = $true)]$Receipt,
            [Parameter(Mandatory = $true)][string]$ReceiptSha256,
            [Parameter(Mandatory = $true)][string]$ComponentSetSha256,
            [Parameter(Mandatory = $true)]$Helper
        )

        $kind = $null
        $specific = [ordered]@{}
        if ($Category -ceq 'native_transfer_real_host' -and
            $script:NativeFixedTransferCases.Contains($CaseId)) {
            $definition = $script:NativeFixedTransferCases[$CaseId]
            $kind = 'fixed_payload'
            $specific.direction = [string]$definition[0]
            $specific.size_bytes = [uint64]$definition[1]
            $specific.payload_sha256 = [string]$definition[2]
            $specific.implementation = 'native'
            $specific.expected_helper_identity = [pscustomobject][ordered]@{
                name = [string]$Helper.name
                binary_size = [long]$Helper.binary_size
                sha256 = ([string]$Helper.sha256).ToLowerInvariant()
                version = [string]$Helper.version
            }
        }
        elseif ($Category -ceq 'openssh_dropbear_interop' -and
            $script:InteropTransferCases.Contains($CaseId)) {
            $definition = $script:InteropTransferCases[$CaseId]
            $kind = 'interop_transfer'
            $specific.implementation = [string]$definition[0]
            $specific.backend = [string]$definition[1]
            $specific.expected_helper_identity = if ([string]$definition[1] -ceq 'native') {
                [pscustomobject][ordered]@{
                    name = [string]$Helper.name
                    binary_size = [long]$Helper.binary_size
                    sha256 = ([string]$Helper.sha256).ToLowerInvariant()
                    version = [string]$Helper.version
                }
            }
            else { $null }
        }
        else { return $null }

        $case = [ordered]@{
            schema_version = 1
            kind = $kind
            category = $Category
            case_id = $CaseId
        }
        foreach ($field in $specific.Keys) { $case[$field] = $specific[$field] }
        $case.component_set_sha256 = $ComponentSetSha256
        $case.context_sha256 = [string]$Receipt.context_sha256
        $case.command_sha256 = [string]$Receipt.command_sha256
        $case.terminal_sha256 = [string]$Receipt.terminal_sha256
        $case.result_code = [string]$Receipt.result_code
        $case.passed = [bool]$Receipt.passed
        $case.receipt_sha256 = $ReceiptSha256
        $json = ([pscustomobject]$case | ConvertTo-Json -Compress -Depth 8) + "`n"
        return ,([Text.UTF8Encoding]::new($false, $true).GetBytes($json))
    }

    function Get-ImmutableTransferPrerequisitesInternal {
        param([Parameter(Mandatory = $true)]$State)

        $required = if ([string]$State.category -ceq 'native_transfer_real_host') {
            @($script:NativeFixedTransferCases.Keys)
        }
        else { @($script:InteropTransferCases.Keys) }
        $completed = @(
            $required | Where-Object { $State.immutable_transfer_cases.Contains($_) }
        )
        return [pscustomobject][ordered]@{
            category = [string]$State.category
            expected = [int]$required.Count
            completed = [int]$completed.Count
            ready = [bool](
                $completed.Count -eq $required.Count -and
                $null -ne $State.bound_evidence_context_sha256 -and
                $null -ne $State.bound_component_set_sha256 -and
                $null -ne $State.bound_component_bytes
            )
        }
    }

    function Update-ImmutableTransferPrerequisiteDetailsInternal {
        param([Parameter(Mandatory = $true)]$State)

        $prerequisites = Get-ImmutableTransferPrerequisitesInternal $State
        if (-not $prerequisites.ready) { return }
        Assert-Contract ($null -eq $State.immutable_transfer_details) (
            'formal transfer prerequisite details were already constructed'
        )
        $required = if ([string]$State.category -ceq 'native_transfer_real_host') {
            @($script:NativeFixedTransferCases.Keys)
        }
        else { @($script:InteropTransferCases.Keys) }
        $caseRecords = @()
        foreach ($caseId in $required) {
            $record = $State.immutable_transfer_cases[$caseId]
            Assert-Contract (
                $record.bytes -is [byte[]] -and
                [string]$record.sha256 -cmatch '^[0-9A-F]{64}$' -and
                (Get-CanonicalSha256 -Bytes $record.bytes) -ceq [string]$record.sha256
            ) "formal transfer prerequisite case '$caseId' changed in memory"
            $caseRecords += [pscustomobject][ordered]@{
                case_id = $caseId
                state_sha256 = [string]$record.sha256
                state_base64 = [Convert]::ToBase64String($record.bytes)
            }
        }
        Assert-Contract (
            (Get-CanonicalSha256 -Bytes $State.bound_component_bytes) -ceq
                [string]$State.bound_component_set_sha256
        ) 'formal transfer prerequisite component bytes changed in memory'
        $details = [pscustomobject][ordered]@{
            schema_version = 1
            contract = 'serctl-transfer-receipt-prerequisites-v1'
            category = [string]$State.category
            release_sealable = $false
            context_sha256 = [string]$State.bound_evidence_context_sha256
            component_set_sha256 = [string]$State.bound_component_set_sha256
            component_set_base64 = [Convert]::ToBase64String($State.bound_component_bytes)
            cases = $caseRecords
        }
        $State.immutable_transfer_details = [Text.UTF8Encoding]::new(
            $false, $true
        ).GetBytes(($details | ConvertTo-Json -Compress -Depth 8) + "`n")
    }

    function Assert-NativeRawObservationBindingInternal {
        param(
            [Parameter(Mandatory = $true)]$State,
            [Parameter(Mandatory = $true)]$Raw,
            [Parameter(Mandatory = $true)][string[]]$Fields,
            [Parameter(Mandatory = $true)][string]$Label
        )
        Assert-Contract ([string]$State.category -ceq 'native_transfer_real_host') (
            "$Label requires the native runtime category"
        )
        Assert-Contract (
            $null -ne $State.bound_evidence_context_sha256 -and
            $null -ne $State.bound_component_set_sha256 -and
            $State.bound_component_bytes -is [byte[]]
        ) "$Label has no accepted child/component binding"
        Assert-SerctlClosedObject $Raw $Fields $Label
        Assert-Contract (
            (Test-StrictJsonInteger $Raw.schema_version) -and
            [int]$Raw.schema_version -eq 1 -and
            [string]$Raw.source -ceq 'private_actual_capture_v1' -and
            [string]$Raw.context_sha256 -ceq
                [string]$State.bound_evidence_context_sha256 -and
            [string]$Raw.component_set_sha256 -ceq
                [string]$State.bound_component_set_sha256
        ) "$Label identity differs from its accepted child binding"
        Assert-SerctlClosedObject $Raw.helper_identity @(
            'name', 'binary_size', 'sha256', 'version'
        ) "$Label helper_identity"
        $componentText = [Text.UTF8Encoding]::new($false, $true).GetString(
            $State.bound_component_bytes
        )
        $components = ConvertFrom-StrictJson `
            -Json $componentText.Substring(0, $componentText.Length - 1) `
            -Label "$Label bound components"
        $helper = $components.helper
        Assert-Contract (
            [string]$Raw.helper_identity.name -ceq [string]$helper.name -and
            (Test-StrictJsonInteger $Raw.helper_identity.binary_size) -and
            [long]$Raw.helper_identity.binary_size -eq [long]$helper.binary_size -and
            [string]$Raw.helper_identity.sha256 -ceq
                ([string]$helper.sha256).ToLowerInvariant() -and
            [string]$Raw.helper_identity.version -ceq [string]$helper.version
        ) "$Label helper identity differs from exact provenance"
    }

    function Add-NativeFaultActualObservationInternal {
        param(
            [Parameter(Mandatory = $true)]$State,
            [Parameter(Mandatory = $true)]$Raw
        )
        $fields = @(
            'schema_version', 'source', 'case_id', 'context_sha256',
            'component_set_sha256', 'helper_identity', 'terminal_result_code',
            'resume_percent_observed', 'cleanup_state_observed', 'ack_events',
            'confirmed_bytes_before_first_ack', 'target_identity_before_sha256',
            'target_identity_after_sha256', 'foreign_partial_before_sha256',
            'foreign_partial_after_sha256', 'owned_partial_count_before',
            'owned_partial_count_after'
        )
        Assert-NativeRawObservationBindingInternal $State $Raw $fields (
            'native fault actual observation'
        )
        $caseId = [string]$Raw.case_id
        Assert-Contract (
            $script:NativeFaultCases.Contains($caseId) -and
            $State.observations.Contains($caseId) -and
            -not $State.immutable_native_fault_cases.Contains($caseId)
        ) 'native fault actual observation is unknown, lacks a child receipt, or is duplicated'
        $expected = $script:NativeFaultCases[$caseId]
        foreach ($field in @(
            'resume_percent_observed', 'ack_events',
            'confirmed_bytes_before_first_ack', 'owned_partial_count_before',
            'owned_partial_count_after'
        )) {
            Assert-Contract (
                (Test-StrictJsonInteger $Raw.$field) -and [int64]$Raw.$field -ge 0
            ) "native fault actual observation $field is invalid"
        }
        foreach ($field in @(
            'target_identity_before_sha256', 'target_identity_after_sha256',
            'foreign_partial_before_sha256', 'foreign_partial_after_sha256'
        )) {
            Assert-Contract ([string]$Raw.$field -cmatch '^[0-9A-F]{64}$') (
                "native fault actual observation $field is invalid"
            )
        }
        Assert-Contract (
            [string]$Raw.terminal_result_code -ceq [string]$expected[0] -and
            [int64]$Raw.resume_percent_observed -eq [int64]$expected[1] -and
            [string]$Raw.cleanup_state_observed -ceq [string]$expected[2] -and
            [int64]$Raw.owned_partial_count_before -eq [int64]$expected[3] -and
            [int64]$Raw.owned_partial_count_after -eq [int64]$expected[4] -and
            (
                ($caseId -ceq 'lost_ack' -and [int64]$Raw.ack_events -eq 0) -or
                ($caseId -cne 'lost_ack' -and [int64]$Raw.ack_events -gt 0)
            ) -and
            [int64]$Raw.confirmed_bytes_before_first_ack -eq 0 -and
            [string]$Raw.target_identity_before_sha256 -ceq
                [string]$Raw.target_identity_after_sha256 -and
            [string]$Raw.foreign_partial_before_sha256 -ceq
                [string]$Raw.foreign_partial_after_sha256
        ) 'native fault actual observation does not prove the required outcome'
        $rawBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes(
            ($Raw | ConvertTo-Json -Compress -Depth 8) + "`n"
        )
        $derived = [pscustomobject][ordered]@{
            scenario = $caseId
            result_code = [string]$expected[0]
            resume_percent = [int64]$expected[1]
            cleanup_state = [string]$expected[2]
            confirmed_advanced_without_ack = $false
            target_overwritten = $false
            foreign_partial_deleted = $false
            passed = $true
            context_sha256 = [string]$State.bound_evidence_context_sha256
            component_set_sha256 = [string]$State.bound_component_set_sha256
            helper_identity = $Raw.helper_identity
            raw_observation_sha256 = Get-CanonicalSha256 $rawBytes
        }
        $bytes = [Text.UTF8Encoding]::new($false, $true).GetBytes(
            ($derived | ConvertTo-Json -Compress -Depth 8) + "`n"
        )
        $State.immutable_native_fault_cases[$caseId] = [pscustomobject][ordered]@{
            sha256 = Get-CanonicalSha256 $bytes
            bytes = $bytes
        }
        [Array]::Clear($rawBytes, 0, $rawBytes.Length)
    }

    function Set-NativeRegistryWindowActualObservationInternal {
        param(
            [Parameter(Mandatory = $true)]$State,
            [Parameter(Mandatory = $true)]$Raw
        )
        $fields = @(
            'schema_version', 'source', 'case_id', 'context_sha256',
            'component_set_sha256', 'helper_identity', 'active_per_profile',
            'active_global', 'terminal_per_profile', 'terminal_global',
            'retention_max_seconds', 'sftp_write_bytes', 'sftp_inflight_writes',
            'native_chunk_bytes', 'native_ack_window_bytes',
            'cross_profile_visible_count', 'oversize_control_frames_accepted',
            'confirmed_bytes_before_first_ack'
        )
        Assert-NativeRawObservationBindingInternal $State $Raw $fields (
            'native registry/window actual observation'
        )
        Assert-Contract (
            [string]$Raw.case_id -ceq 'registry_window' -and
            $State.observations.Contains('registry_window') -and
            $null -eq $State.immutable_native_registry
        ) 'native registry/window actual observation lacks one accepted child receipt'
        $expected = [ordered]@{
            active_per_profile = 8; active_global = 48; terminal_per_profile = 16
            terminal_global = 256; retention_max_seconds = 900
            sftp_write_bytes = 2048; sftp_inflight_writes = 1
            native_chunk_bytes = 32768; native_ack_window_bytes = 32768
        }
        foreach ($field in @(
            $expected.Keys + @(
                'cross_profile_visible_count', 'oversize_control_frames_accepted',
                'confirmed_bytes_before_first_ack'
            )
        )) {
            Assert-Contract (
                (Test-StrictJsonInteger $Raw.$field) -and [int64]$Raw.$field -ge 0
            ) "native registry/window actual observation $field is invalid"
        }
        foreach ($field in $expected.Keys) {
            Assert-Contract ([int64]$Raw.$field -eq [int64]$expected[$field]) (
                "native registry/window actual observation $field differs from its fixed limit"
            )
        }
        Assert-Contract (
            [int64]$Raw.cross_profile_visible_count -eq 0 -and
            [int64]$Raw.oversize_control_frames_accepted -eq 0 -and
            [int64]$Raw.confirmed_bytes_before_first_ack -eq 0
        ) 'native registry/window actual observation violates isolation, bounds, or ACK order'
        $rawBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes(
            ($Raw | ConvertTo-Json -Compress -Depth 8) + "`n"
        )
        $derived = [ordered]@{}
        foreach ($field in $expected.Keys) { $derived[$field] = [int64]$expected[$field] }
        $derived.profile_isolation_passed = $true
        $derived.control_frame_bound_passed = $true
        $derived.confirmed_before_ack = $false
        $derived.context_sha256 = [string]$State.bound_evidence_context_sha256
        $derived.component_set_sha256 = [string]$State.bound_component_set_sha256
        $derived.helper_identity = $Raw.helper_identity
        $derived.raw_observation_sha256 = Get-CanonicalSha256 $rawBytes
        $bytes = [Text.UTF8Encoding]::new($false, $true).GetBytes(
            ([pscustomobject]$derived | ConvertTo-Json -Compress -Depth 8) + "`n"
        )
        $State.immutable_native_registry = [pscustomobject][ordered]@{
            sha256 = Get-CanonicalSha256 $bytes
            bytes = $bytes
        }
        [Array]::Clear($rawBytes, 0, $rawBytes.Length)
    }

    function Set-NativePerformanceActualMeasurementsInternal {
        param(
            [Parameter(Mandatory = $true)]$State,
            [Parameter(Mandatory = $true)]$Raw
        )
        $fields = @(
            'schema_version', 'source', 'context_sha256', 'component_set_sha256',
            'helper_identity', 'chunk_bytes', 'window_bytes',
            'native_samples', 'scp_samples'
        )
        Assert-NativeRawObservationBindingInternal $State $Raw $fields (
            'native performance actual measurements'
        )
        Assert-Contract (
            $null -ne $State.immutable_native_registry -and
            $null -eq $State.immutable_native_performance -and
            (Test-StrictJsonInteger $Raw.chunk_bytes) -and
            [int64]$Raw.chunk_bytes -eq 32768 -and
            (Test-StrictJsonInteger $Raw.window_bytes) -and
            [int64]$Raw.window_bytes -eq 32768
        ) 'native performance measurements lack registry evidence or fixed one-ACK limits'
        $sampleFields = @(
            'sample_index', 'size_bytes', 'elapsed_microseconds',
            'cpu_basis_points', 'peak_rss_bytes', 'rtt_microseconds'
        )
        $rates = [ordered]@{}
        $retainedSamples = [ordered]@{}
        foreach ($kind in @('native', 'scp')) {
            $field = "${kind}_samples"
            Assert-Contract (Test-StrictJsonArray $Raw.$field) (
                "native performance $field is not an array"
            )
            $samples = @($Raw.$field)
            Assert-Contract ($samples.Count -eq 5) (
                "native performance $field must contain exactly five samples"
            )
            $kindRates = @()
            $copies = @()
            for ($index = 0; $index -lt $samples.Count; $index++) {
                $sample = $samples[$index]
                Assert-SerctlClosedObject $sample $sampleFields (
                    "native performance $field sample"
                )
                foreach ($sampleField in $sampleFields) {
                    Assert-Contract (
                        (Test-StrictJsonInteger $sample.$sampleField) -and
                        [int64]$sample.$sampleField -gt 0
                    ) "native performance $field.$sampleField is invalid"
                }
                Assert-Contract (
                    [int64]$sample.sample_index -eq ($index + 1) -and
                    [int64]$sample.size_bytes -eq 67108864 -and
                    [int64]$sample.cpu_basis_points -le 10000 -and
                    [int64]$sample.peak_rss_bytes -le 16777216
                ) "native performance $field sample is outside the fixed envelope"
                try {
                    $rate = [decimal]::Floor(
                        ([decimal]$sample.size_bytes * [decimal]1000000) /
                        [decimal]$sample.elapsed_microseconds
                    )
                }
                catch { throw 'external transfer runtime receipt contract failed: performance arithmetic overflowed' }
                Assert-Contract ($rate -gt 0 -and $rate -le [decimal][uint64]::MaxValue) (
                    "native performance $field rate is outside its integer bound"
                )
                $kindRates += [uint64]$rate
                $copies += [pscustomobject][ordered]@{
                    sample_index = [int64]$sample.sample_index
                    size_bytes = [int64]$sample.size_bytes
                    elapsed_microseconds = [int64]$sample.elapsed_microseconds
                    cpu_basis_points = [int64]$sample.cpu_basis_points
                    peak_rss_bytes = [int64]$sample.peak_rss_bytes
                    rtt_microseconds = [int64]$sample.rtt_microseconds
                }
            }
            $rates[$kind] = @($kindRates | Sort-Object)
            $retainedSamples[$kind] = $copies
        }
        $nativeRates = @($rates.native)
        $scpRates = @($rates.scp)
        $nativeSamples = @($retainedSamples.native)
        $nativeP50 = [uint64]$nativeRates[2]
        $nativeP95 = [uint64]$nativeRates[4]
        $scpP50 = [uint64]$scpRates[2]
        try {
            $ratio = [uint64][decimal]::Floor(
                ([decimal]$nativeP50 * [decimal]100) / [decimal]$scpP50
            )
        }
        catch { throw 'external transfer runtime receipt contract failed: performance ratio overflowed' }
        Assert-Contract ($ratio -ge 80) 'native performance misses the 80 percent throughput floor'
        $performance = [pscustomobject][ordered]@{
            native_p50_bytes_per_second = $nativeP50
            native_p95_bytes_per_second = $nativeP95
            scp_bytes_per_second = $scpP50
            throughput_ratio_percent = $ratio
            cpu_basis_points = [int64](
                ($nativeSamples.cpu_basis_points | Measure-Object -Maximum).Maximum
            )
            peak_rss_bytes = [int64](
                ($nativeSamples.peak_rss_bytes | Measure-Object -Maximum).Maximum
            )
            rtt_microseconds = [int64](@($nativeSamples.rtt_microseconds | Sort-Object)[2])
            chunk_bytes = [int64]32768
            window_bytes = [int64]32768
            native_samples = $retainedSamples.native
            scp_samples = $retainedSamples.scp
        }
        $rawBytes = [Text.UTF8Encoding]::new($false, $true).GetBytes(
            ($Raw | ConvertTo-Json -Compress -Depth 8) + "`n"
        )
        $derived = [pscustomobject][ordered]@{
            schema_version = 1
            context_sha256 = [string]$State.bound_evidence_context_sha256
            component_set_sha256 = [string]$State.bound_component_set_sha256
            helper_identity = $Raw.helper_identity
            raw_measurement_sha256 = Get-CanonicalSha256 $rawBytes
            performance = $performance
        }
        $bytes = [Text.UTF8Encoding]::new($false, $true).GetBytes(
            ($derived | ConvertTo-Json -Compress -Depth 10) + "`n"
        )
        $State.immutable_native_performance = [pscustomobject][ordered]@{
            sha256 = Get-CanonicalSha256 $bytes
            bytes = $bytes
        }
        [Array]::Clear($rawBytes, 0, $rawBytes.Length)
    }

    function Accept-ExternalTransferRuntimeAdapterObservation {
        param(
            [Parameter(Mandatory = $true)]$State,
            [Parameter(Mandatory = $true)]$Observation,
            [string]$ProtectedChildReceiptPath
        )
        $actual = @($Observation.PSObject.Properties.Name | Sort-Object)
        $expected = @(
            'internal_contract', 'category', 'case_id', 'context_sha256',
            'command_sha256', 'terminal_sha256', 'receipt_bytes'
        ) | Sort-Object
        Assert-Contract (($actual -join "`n") -ceq ($expected -join "`n")) (
            'adapter observation does not use the exact private schema'
        )
        Assert-Contract (
            [string]$Observation.internal_contract -ceq
                'serctl-runtime-adapter-observation-v1'
        ) 'adapter observation does not carry the internal contract marker'
        $caseId = [string]$Observation.case_id
        Assert-Contract (
            [string]$Observation.category -ceq [string]$State.category -and
            $caseId -cin $State.expected_case_ids -and
            -not $State.observations.Contains($caseId)
        ) 'adapter observation is outside the private ledger scope'
        foreach ($field in @('context_sha256', 'command_sha256', 'terminal_sha256')) {
            Assert-Contract ([string]$Observation.$field -cmatch '^[0-9A-F]{64}$') (
                "adapter observation $field is invalid"
            )
        }
        Assert-Contract ($Observation.receipt_bytes -is [byte[]]) (
            'adapter observation receipt is not a byte array'
        )
        $bytes = [byte[]]$Observation.receipt_bytes
        Assert-Contract ($bytes.Length -gt 0 -and $bytes.Length -le 1048576) (
            'adapter observation receipt is outside its byte bound'
        )
        $utf8 = [System.Text.UTF8Encoding]::new($false, $true)
        try { $json = $utf8.GetString($bytes) }
        catch { throw 'external transfer runtime receipt contract failed: child receipt is not strict UTF-8' }
        Assert-Contract ($json.EndsWith("`n") -and -not $json.Contains("`r")) (
            'child receipt does not use one canonical LF terminator'
        )
        $document = ConvertFrom-StrictJson `
            -Json $json.Substring(0, $json.Length - 1) `
            -Label 'protected child receipt'
        $receiptFields = @(
            'schema_version', 'category', 'case_id', 'context_sha256',
            'command_sha256', 'terminal_sha256', 'result_code', 'passed'
        )
        $receiptActual = @($document.PSObject.Properties.Name | Sort-Object)
        Assert-Contract (
            ($receiptActual -join "`n") -ceq (($receiptFields | Sort-Object) -join "`n")
        ) 'protected child receipt does not use the exact schema'
        Assert-Contract (
            (Test-StrictJsonInteger $document.schema_version) -and
            [int]$document.schema_version -eq 1 -and
            [string]$document.category -ceq [string]$State.category -and
            [string]$document.case_id -ceq $caseId -and
            [string]$document.context_sha256 -ceq [string]$Observation.context_sha256 -and
            [string]$document.command_sha256 -ceq [string]$Observation.command_sha256 -and
            [string]$document.terminal_sha256 -ceq [string]$Observation.terminal_sha256 -and
            [string]$document.result_code -ceq 'completed' -and
            (Test-StrictJsonBoolean $document.passed) -and [bool]$document.passed
        ) 'protected child receipt does not bind the private adapter observation'
        $canonical = (($document | ConvertTo-Json -Compress) + "`n")
        Assert-Contract ($canonical -ceq $json) 'protected child receipt bytes are not canonical JSON'
        $sha256 = Get-CanonicalSha256 -Bytes $bytes
        Assert-Contract ($null -ne $State.exact_release_components) (
            'formal child receipt has no exact release component binding'
        )
        $componentBytes = Get-CanonicalRuntimeComponentBytesInternal `
            -Components $State.exact_release_components
        $componentSetSha256 = Get-CanonicalSha256 -Bytes $componentBytes
        Assert-Contract (
            -not $State.operation_context_sha256_by_case.Contains($caseId)
        ) 'formal child receipt operation context is duplicated'
        if ($null -ne $State.bound_component_set_sha256) {
            Assert-Contract (
                [string]$State.bound_component_set_sha256 -ceq $componentSetSha256
            ) 'formal child receipt component set differs from the ledger binding'
        }
        $caseBytes = New-ImmutableTransferCaseBytesInternal `
            -Category ([string]$State.category) `
            -CaseId $caseId `
            -Receipt $document `
            -ReceiptSha256 $sha256 `
            -ComponentSetSha256 $componentSetSha256 `
            -Helper $State.exact_release_components.helper

        if (-not [string]::IsNullOrEmpty($ProtectedChildReceiptPath)) {
            Get-ProtectedReceiptBytes -Bytes $bytes -Path $ProtectedChildReceiptPath
            $persisted = [System.IO.File]::ReadAllBytes(
                [System.IO.Path]::GetFullPath($ProtectedChildReceiptPath)
            )
            try {
                Assert-Contract (
                    $persisted.Length -eq $bytes.Length -and
                    (Get-CanonicalSha256 -Bytes $persisted) -ceq $sha256
                ) 'protected child receipt changed after create-new persistence'
            }
            finally { [Array]::Clear($persisted, 0, $persisted.Length) }
        }
        $State.observations[$caseId] = [pscustomobject][ordered]@{
            case_id = $caseId
            receipt_sha256 = $sha256
            receipt_base64 = [Convert]::ToBase64String($bytes)
        }
        $State.operation_context_sha256_by_case[$caseId] =
            [string]$document.context_sha256
        if ($null -eq $State.bound_component_set_sha256) {
            $State.bound_component_set_sha256 = $componentSetSha256
            $State.bound_component_bytes = $componentBytes
        }
        else { [Array]::Clear($componentBytes, 0, $componentBytes.Length) }
        if ($null -ne $caseBytes) {
            $State.immutable_transfer_cases[$caseId] = [pscustomobject][ordered]@{
                sha256 = Get-CanonicalSha256 -Bytes $caseBytes
                bytes = $caseBytes
            }
            Update-ImmutableTransferPrerequisiteDetailsInternal $State
        }
        [void]$State.blocked_case_ids.Remove($caseId)
    }

    # INTERNAL-ONLY handoff from the exact downloaded-set verifier into the
    # isolated-owner importer.  Neither this function nor its component object
    # is exported.  The public importer below cannot choose paths, digests,
    # versions, a result summary, or a pass bit.
    function Set-IsolatedOwnerExpectedBindingInternal {
        param(
            [Parameter(Mandatory = $true)]$State,
            [Parameter(Mandatory = $true)]$ExactReleaseComponents,
            [Parameter(Mandatory = $true)][string]$EvidenceContextSha256
        )

        Assert-Contract (
            [string]$State.category -ceq 'openssh_dropbear_interop' -and
            $State.observations.Count -eq 0 -and
            $State.blocked_case_ids.Count -eq $State.expected_case_ids.Count -and
            $null -eq $State.exact_release_components -and
            $null -eq $State.expected_evidence_context_sha256 -and
            $null -eq $State.bound_evidence_context_sha256 -and
            $null -eq $State.bound_component_set_sha256 -and
            $null -eq $State.bound_component_bytes
        ) 'isolated owner expected binding requires one fresh interop ledger'
        Assert-Contract ($EvidenceContextSha256 -cmatch '^[0-9A-F]{64}$') (
            'isolated owner aggregate evidence context is invalid'
        )
        $componentBytes = Get-CanonicalRuntimeComponentBytesInternal $ExactReleaseComponents
        $componentText = [Text.UTF8Encoding]::new($false, $true).GetString($componentBytes)
        $componentCopy = ConvertFrom-StrictJson `
            -Json $componentText.Substring(0, $componentText.Length - 1) `
            -Label 'isolated owner expected exact components'
        $State.exact_release_components = $componentCopy
        $State.expected_evidence_context_sha256 = $EvidenceContextSha256
        $State.bound_component_set_sha256 = Get-CanonicalSha256 $componentBytes
        $State.bound_component_bytes = $componentBytes
    }

    function Get-CanonicalBoundedBase64BytesInternal {
        param(
            [Parameter(Mandatory = $true)]$Value,
            [Parameter(Mandatory = $true)][int]$MaximumBytes,
            [Parameter(Mandatory = $true)][string]$Label
        )
        Assert-Contract (
            (Test-StrictJsonString $Value) -and
            [string]$Value -cmatch '^[A-Za-z0-9+/]+={0,2}$' -and
            ([string]$Value).Length -gt 0 -and
            ([string]$Value).Length -le (($MaximumBytes * 4) + 8) -and
            ([string]$Value).Length % 4 -eq 0
        ) "$Label is not bounded canonical Base64"
        try { $bytes = [Convert]::FromBase64String([string]$Value) }
        catch { throw "external transfer runtime receipt contract failed: $Label is invalid Base64" }
        Assert-Contract (
            $bytes.Length -gt 0 -and $bytes.Length -le $MaximumBytes -and
            [Convert]::ToBase64String($bytes) -ceq [string]$Value
        ) "$Label does not use one canonical byte encoding"
        return ,$bytes
    }

    function Get-NativeFixtureNormalizedPerformanceInternal {
        param([Parameter(Mandatory = $true)]$RawPerformance)

        Assert-NativeFixtureOrderedObjectInternal $RawPerformance @('native', 'scp') (
            'native fixture raw performance'
        )
        $retained = [ordered]@{}
        $rates = [ordered]@{}
        foreach ($backend in @('native', 'scp')) {
            Assert-Contract (Test-StrictJsonArray $RawPerformance.$backend) (
                "native fixture $backend samples are not an array"
            )
            $samples = @($RawPerformance.$backend)
            Assert-Contract ($samples.Count -eq 5) (
                "native fixture $backend must contain exactly five samples"
            )
            $copies = @()
            $backendRates = @()
            for ($index = 0; $index -lt 5; $index++) {
                $sample = $samples[$index]
                Assert-NativeFixtureOrderedObjectInternal $sample @(
                    'backend', 'sample_index', 'size_bytes', 'work_repetitions',
                    'elapsed_microseconds',
                    'cpu_microseconds', 'peak_working_set_bytes', 'rtt_microseconds',
                    'checksum'
                ) "native fixture $backend sample"
                Assert-Contract (
                    (Test-StrictJsonString $sample.backend) -and
                    [string]$sample.backend -ceq $backend -and
                    (Test-StrictJsonInteger $sample.sample_index) -and
                    [int64]$sample.sample_index -eq ($index + 1) -and
                    (Test-StrictJsonInteger $sample.size_bytes) -and
                    [int64]$sample.size_bytes -eq 67108864 -and
                    (Test-StrictJsonInteger $sample.work_repetitions) -and
                    [int]$sample.work_repetitions -eq 16 -and
                    (Test-StrictJsonInteger $sample.elapsed_microseconds) -and
                    [int64]$sample.elapsed_microseconds -gt 0 -and
                    (Test-StrictJsonInteger $sample.cpu_microseconds) -and
                    [int64]$sample.cpu_microseconds -gt 0 -and
                    (Test-StrictJsonInteger $sample.peak_working_set_bytes) -and
                    [int64]$sample.peak_working_set_bytes -gt 0 -and
                    (Test-StrictJsonInteger $sample.rtt_microseconds) -and
                    [int64]$sample.rtt_microseconds -gt 0 -and
                    (Test-StrictJsonInteger $sample.checksum) -and
                    [int64]$sample.checksum -ge 0
                ) "native fixture $backend sample has invalid typed facts"
                try {
                    $rate = [int64][decimal]::Floor(
                        ([decimal][int64]$sample.size_bytes *
                            [decimal][int]$sample.work_repetitions * [decimal]1000000) /
                        [decimal][int64]$sample.elapsed_microseconds
                    )
                    $cpu = [int64][decimal]::Floor(
                        ([decimal][int64]$sample.cpu_microseconds * [decimal]10000) /
                        [decimal][int64]$sample.elapsed_microseconds
                    )
                }
                catch {
                    throw 'external transfer runtime receipt contract failed: native fixture performance arithmetic overflowed'
                }
                Assert-Contract ($rate -gt 0) (
                    "native fixture $backend sample derived a non-positive byte rate"
                )
                Assert-Contract ($cpu -gt 0) (
                    "native fixture $backend sample did not cross the CPU accounting quantum"
                )
                $backendRates += $rate
                $copies += [pscustomobject][ordered]@{
                    sample_index = [int]$sample.sample_index
                    size_bytes = [int64]$sample.size_bytes
                    work_repetitions = [int]$sample.work_repetitions
                    elapsed_microseconds = [int64]$sample.elapsed_microseconds
                    bytes_per_second = $rate
                    cpu_basis_points = $cpu
                    peak_rss_bytes = [int64]$sample.peak_working_set_bytes
                    rtt_microseconds = [int64]$sample.rtt_microseconds
                }
            }
            $retained[$backend] = $copies
            $rates[$backend] = @($backendRates | Sort-Object)
        }
        $nativeP50 = [int64]$rates.native[2]
        $nativeP95 = [int64]$rates.native[4]
        $scpMedian = [int64]$rates.scp[2]
        $ratio = [int64][decimal]::Floor(
            ([decimal]$nativeP50 * [decimal]100) / [decimal]$scpMedian
        )
        Assert-Contract ($ratio -ge 80) (
            'native fixture local-copy ratio is below its non-network guard'
        )
        return [pscustomobject][ordered]@{
            evidence_kind = 'local_copy_workload_not_network_throughput'
            native_samples = $retained.native
            scp_samples = $retained.scp
            native_p50_bytes_per_second = $nativeP50
            native_p95_bytes_per_second = $nativeP95
            scp_median_bytes_per_second = $scpMedian
            native_to_scp_ratio_percent = $ratio
            native_cpu_basis_points = [int64](
                ($retained.native.cpu_basis_points | Measure-Object -Maximum).Maximum
            )
            native_peak_rss_bytes = [int64](
                ($retained.native.peak_rss_bytes | Measure-Object -Maximum).Maximum
            )
            native_median_rtt_microseconds = [int64](
                @($retained.native.rtt_microseconds | Sort-Object)[2]
            )
        }
    }

    function Assert-NativeFixtureOrderedObjectInternal {
        param(
            [Parameter(Mandatory = $true)]$Value,
            [Parameter(Mandatory = $true)][string[]]$Fields,
            [Parameter(Mandatory = $true)][string]$Label
        )
        Assert-SerctlClosedObject $Value $Fields $Label
        Assert-Contract (
            (@($Value.PSObject.Properties.Name) -join "`n") -ceq ($Fields -join "`n")
        ) "$Label does not use the fixed canonical field order"
    }

    # Imports only canonical bytes emitted by the repository-fixed local owner.
    # It deliberately has no path, digest, summary, pass bit, result or raw-fact
    # parameter.  All summaries are recomputed from the child stdout bytes.
    function Import-NativeFaultRegistryPerformanceFixtureReceipt {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)]$Ledger,
            [Parameter(Mandatory = $true)][byte[]]$OwnerReceiptBytes
        )

        $state = Resolve-LedgerState $Ledger
        Assert-Contract (
            [string]$state.category -ceq 'native_transfer_real_host' -and
            -not $state.sealed -and $state.observations.Count -eq 0 -and
            $state.blocked_case_ids.Count -eq $state.expected_case_ids.Count -and
            $null -eq $state.immutable_native_fixture_projection
        ) 'native fixture receipt requires one fresh, fully blocked native ledger'
        Assert-Contract (
            $null -ne $OwnerReceiptBytes -and $OwnerReceiptBytes.Length -gt 0 -and
            $OwnerReceiptBytes.Length -le 4194304
        ) 'native fixture owner receipt is outside its byte bound'

        $utf8 = [Text.UTF8Encoding]::new($false, $true)
        try { $ownerText = $utf8.GetString($OwnerReceiptBytes) }
        catch { throw 'external transfer runtime receipt contract failed: native fixture owner receipt is not strict UTF-8' }
        Assert-Contract (
            $ownerText.EndsWith("`n") -and -not $ownerText.Contains("`r") -and
            $ownerText.IndexOf("`n") -eq ($ownerText.Length - 1)
        ) 'native fixture owner receipt is not one canonical JSON line'
        $owner = ConvertFrom-StrictJson `
            $ownerText.Substring(0, $ownerText.Length - 1) `
            'native fixture owner receipt'
        $ownerFields = @(
            'schema_version', 'owner_contract', 'category', 'sealability',
            'formal_complete_allowed', 'evidence_source', 'limitations',
            'child_script_sha256', 'child_capture', 'fault_cases',
            'registry_window', 'performance'
        )
        Assert-NativeFixtureOrderedObjectInternal `
            $owner $ownerFields 'native fixture owner receipt'
        Assert-Contract (
            (@($owner.PSObject.Properties.Name) -join "`n") -ceq ($ownerFields -join "`n") -and
            (Test-StrictJsonInteger $owner.schema_version) -and
            [int]$owner.schema_version -eq 1 -and
            (Test-StrictJsonString $owner.owner_contract) -and
            [string]$owner.owner_contract -ceq 'serctl-native-fixture-actual-capture-owner-v1' -and
            (Test-StrictJsonString $owner.category) -and
            [string]$owner.category -ceq 'native_fault_registry_performance_fixture' -and
            (Test-StrictJsonString $owner.sealability) -and
            [string]$owner.sealability -ceq 'unsealable_fixture_only' -and
            (Test-StrictJsonBoolean $owner.formal_complete_allowed) -and
            -not [bool]$owner.formal_complete_allowed -and
            (Test-StrictJsonString $owner.evidence_source) -and
            [string]$owner.evidence_source -ceq 'repository_fixed_local_child_process' -and
            (Test-StrictJsonArray $owner.limitations) -and
            (@($owner.limitations) -join ',') -ceq
                'not_real_remote,not_exact_tag,not_release_provenance,not_network_performance' -and
            (Test-StrictJsonString $owner.child_script_sha256) -and
            [string]$owner.child_script_sha256 -cmatch '^[0-9a-f]{64}$'
        ) 'native fixture owner identity or unsealable limitations changed'
        Assert-Contract (
            (($owner | ConvertTo-Json -Compress -Depth 12) + "`n") -ceq $ownerText
        ) 'native fixture owner receipt bytes are not canonical JSON'

        $captureFields = @(
            'exit_category', 'exit_code', 'elapsed_ms', 'deadline_ms',
            'process_tree_exited', 'raw_stdout_sha256', 'raw_stdout_base64'
        )
        Assert-NativeFixtureOrderedObjectInternal $owner.child_capture $captureFields (
            'native fixture child capture'
        )
        $capture = $owner.child_capture
        Assert-Contract (
            (Test-StrictJsonString $capture.exit_category) -and
            [string]$capture.exit_category -ceq 'completed_success' -and
            (Test-StrictJsonInteger $capture.exit_code) -and [int]$capture.exit_code -eq 0 -and
            (Test-StrictJsonInteger $capture.elapsed_ms) -and [int64]$capture.elapsed_ms -ge 0 -and
            (Test-StrictJsonInteger $capture.deadline_ms) -and [int64]$capture.deadline_ms -eq 300000 -and
            (Test-StrictJsonBoolean $capture.process_tree_exited) -and
            [bool]$capture.process_tree_exited -and
            (Test-StrictJsonString $capture.raw_stdout_sha256) -and
            [string]$capture.raw_stdout_sha256 -cmatch '^[0-9a-f]{64}$'
        ) 'native fixture child capture terminal or typed facts are invalid'
        $rawBytes = Get-CanonicalBoundedBase64BytesInternal `
            $capture.raw_stdout_base64 4194304 'native fixture raw stdout'
        try {
            Assert-Contract (
                (Get-CanonicalSha256 $rawBytes).ToLowerInvariant() -ceq
                    [string]$capture.raw_stdout_sha256
            ) 'native fixture raw stdout digest differs from its actual bytes'
            try { $rawText = $utf8.GetString($rawBytes) }
            catch { throw 'external transfer runtime receipt contract failed: native fixture raw stdout is not strict UTF-8' }
            Assert-Contract (
                $rawText.EndsWith("`n") -and -not $rawText.Contains("`r") -and
                $rawText.IndexOf("`n") -eq ($rawText.Length - 1)
            ) 'native fixture raw stdout is not one canonical JSON line'
            $raw = ConvertFrom-StrictJson `
                $rawText.Substring(0, $rawText.Length - 1) `
                'native fixture raw stdout'
            Assert-NativeFixtureOrderedObjectInternal $raw @(
                'schema_version', 'fault_events', 'registry_events', 'performance_samples'
            ) 'native fixture raw stdout'
            Assert-Contract (
                (($raw | ConvertTo-Json -Compress -Depth 12) + "`n") -ceq $rawText -and
                (Test-StrictJsonString $raw.schema_version) -and
                [string]$raw.schema_version -ceq 'serctl-native-fixture-raw-v1'
            ) 'native fixture raw stdout is not canonical or uses an unknown schema'

            Assert-Contract (
                (Test-StrictJsonArray $raw.fault_events) -and
                @($raw.fault_events).Count -eq 11
            ) 'native fixture must contain exactly eleven fault events'
            $faultFields = @(
                'scenario', 'resume_percent', 'terminal_event', 'acknowledged_offset',
                'confirmed_offset', 'owned_partial_created', 'owned_partial_removed',
                'foreign_partial_touched', 'target_replaced', 'cleanup_attempted',
                'cleanup_confirmed'
            )
            $faultCases = @()
            $faultIndex = 0
            foreach ($fault in @($raw.fault_events)) {
                Assert-NativeFixtureOrderedObjectInternal `
                    $fault $faultFields 'native fixture fault event'
                $caseId = [string]$fault.scenario
                Assert-Contract (
                    $faultIndex -lt $script:NativeFaultCases.Count -and
                    $caseId -ceq [string]@($script:NativeFaultCases.Keys)[$faultIndex] -and
                    (Test-StrictJsonString $fault.scenario) -and
                    (Test-StrictJsonString $fault.terminal_event) -and
                    (Test-StrictJsonInteger $fault.resume_percent) -and
                    (Test-StrictJsonInteger $fault.acknowledged_offset) -and
                    [int64]$fault.acknowledged_offset -ge 0 -and
                    (Test-StrictJsonInteger $fault.confirmed_offset) -and
                    [int64]$fault.confirmed_offset -ge 0
                ) 'native fixture fault set, order, terminal type, or offset type changed'
                foreach ($field in @(
                    'owned_partial_created', 'owned_partial_removed',
                    'foreign_partial_touched', 'target_replaced',
                    'cleanup_attempted', 'cleanup_confirmed'
                )) {
                    Assert-Contract (Test-StrictJsonBoolean $fault.$field) (
                        "native fixture fault '$caseId' $field is not Boolean"
                    )
                }
                $terminalCode = switch ([string]$fault.terminal_event) {
                    'completed' { 'completed' }
                    'unknown' { 'outcome_unknown' }
                    'failed' { 'transfer_failed' }
                    'cleanup_incomplete' { 'cleanup_incomplete' }
                    default { throw 'external transfer runtime receipt contract failed: native fixture fault terminal is unknown' }
                }
                $cleanup = if ([bool]$fault.owned_partial_removed -and [bool]$fault.cleanup_confirmed) {
                    'owned_partial_removed'
                } elseif (-not [bool]$fault.owned_partial_created) {
                    'no_owned_partial_created'
                } elseif ([bool]$fault.cleanup_attempted -and -not [bool]$fault.cleanup_confirmed) {
                    'cleanup_incomplete'
                } else { 'owned_partial_preserved' }
                if ($terminalCode -ceq 'completed') { $cleanup = 'complete' }
                $expected = $script:NativeFaultCases[$caseId]
                $confirmedWithoutAck = [int64]$fault.confirmed_offset -gt
                    [int64]$fault.acknowledged_offset
                Assert-Contract (
                    $terminalCode -ceq [string]$expected[0] -and
                    [int64]$fault.resume_percent -eq [int64]$expected[1] -and
                    $cleanup -ceq [string]$expected[2] -and
                    -not $confirmedWithoutAck -and -not [bool]$fault.target_replaced -and
                    -not [bool]$fault.foreign_partial_touched
                ) "native fixture fault '$caseId' violated its fixed semantics"
                $faultCases += [pscustomobject][ordered]@{
                    scenario = $caseId
                    result_code = $terminalCode
                    resume_percent = [int]$fault.resume_percent
                    cleanup_state = $cleanup
                    confirmed_advanced_without_ack = $confirmedWithoutAck
                    target_overwritten = [bool]$fault.target_replaced
                    foreign_partial_deleted = [bool]$fault.foreign_partial_touched
                    passed = $true
                }
                $faultIndex++
            }
            Assert-Contract (
                (Test-StrictJsonArray $owner.fault_cases) -and
                (($faultCases | ConvertTo-Json -Compress -Depth 8) -ceq
                    ($owner.fault_cases | ConvertTo-Json -Compress -Depth 8))
            ) 'native fixture outer fault summary differs from recomputed raw events'

            $registry = $raw.registry_events
            Assert-NativeFixtureOrderedObjectInternal $registry @(
                'active_attempts', 'terminal_attempts', 'retention_seconds_observed',
                'ack_trace', 'control_frame_lengths', 'negotiated'
            ) 'native fixture registry events'
            Assert-Contract (
                (Test-StrictJsonArray $registry.active_attempts) -and
                @($registry.active_attempts).Count -eq 54 -and
                (Test-StrictJsonArray $registry.terminal_attempts) -and
                @($registry.terminal_attempts).Count -eq 272
            ) 'native fixture registry cardinality changed'
            $activeAccepted = 0
            for ($index = 0; $index -lt 54; $index++) {
                $event = @($registry.active_attempts)[$index]
                Assert-NativeFixtureOrderedObjectInternal $event @(
                    'profile', 'slot', 'accepted', 'visible_to_profile'
                ) 'native fixture active registry event'
                $profileIndex = [Math]::Floor($index / 9)
                $slot = ($index % 9) + 1
                $profile = "profile-$profileIndex"
                Assert-Contract (
                    (Test-StrictJsonString $event.profile) -and
                    [string]$event.profile -ceq $profile -and
                    (Test-StrictJsonInteger $event.slot) -and [int]$event.slot -eq $slot -and
                    (Test-StrictJsonBoolean $event.accepted) -and
                    [bool]$event.accepted -eq ($slot -le 8) -and
                    (Test-StrictJsonString $event.visible_to_profile) -and
                    [string]$event.visible_to_profile -ceq $profile
                ) 'native fixture active registry isolation or limit changed'
                if ([bool]$event.accepted) { $activeAccepted++ }
            }
            $terminalRetained = 0
            for ($index = 0; $index -lt 272; $index++) {
                $event = @($registry.terminal_attempts)[$index]
                Assert-NativeFixtureOrderedObjectInternal $event @(
                    'profile', 'slot', 'retained', 'visible_to_profile'
                ) 'native fixture terminal registry event'
                $profileIndex = [Math]::Floor($index / 17)
                $slot = ($index % 17) + 1
                $profile = "profile-$profileIndex"
                Assert-Contract (
                    (Test-StrictJsonString $event.profile) -and
                    [string]$event.profile -ceq $profile -and
                    (Test-StrictJsonInteger $event.slot) -and [int]$event.slot -eq $slot -and
                    (Test-StrictJsonBoolean $event.retained) -and
                    [bool]$event.retained -eq ($slot -le 16) -and
                    (Test-StrictJsonString $event.visible_to_profile) -and
                    [string]$event.visible_to_profile -ceq $profile
                ) 'native fixture terminal registry isolation or limit changed'
                if ([bool]$event.retained) { $terminalRetained++ }
            }
            Assert-Contract (
                (Test-StrictJsonArray $registry.retention_seconds_observed) -and
                (@($registry.retention_seconds_observed) -join ',') -ceq '0,300,899,900' -and
                @($registry.retention_seconds_observed | Where-Object {
                    -not (Test-StrictJsonInteger $_)
                }).Count -eq 0 -and
                (Test-StrictJsonArray $registry.control_frame_lengths) -and
                (@($registry.control_frame_lengths) -join ',') -ceq '64,128,512,1024' -and
                @($registry.control_frame_lengths | Where-Object {
                    -not (Test-StrictJsonInteger $_) -or [int64]$_ -gt 1048576
                }).Count -eq 0 -and
                (Test-StrictJsonArray $registry.ack_trace) -and
                @($registry.ack_trace).Count -eq 2
            ) 'native fixture registry retention, control bounds, or ACK trace changed'
            $expectedAck = @(@(2048, 0, 0), @(2048, 2048, 2048))
            $confirmedBeforeAck = $false
            for ($index = 0; $index -lt 2; $index++) {
                $ack = @($registry.ack_trace)[$index]
                Assert-NativeFixtureOrderedObjectInternal `
                    $ack @('queued', 'acknowledged', 'confirmed') (
                    'native fixture ACK event'
                )
                foreach ($field in @('queued', 'acknowledged', 'confirmed')) {
                    Assert-Contract (
                        (Test-StrictJsonInteger $ack.$field) -and [int64]$ack.$field -ge 0
                    ) "native fixture ACK $field is invalid"
                }
                Assert-Contract (
                    [int64]$ack.queued -eq $expectedAck[$index][0] -and
                    [int64]$ack.acknowledged -eq $expectedAck[$index][1] -and
                    [int64]$ack.confirmed -eq $expectedAck[$index][2]
                ) 'native fixture ACK sequence changed'
                if ([int64]$ack.confirmed -gt [int64]$ack.acknowledged) {
                    $confirmedBeforeAck = $true
                }
            }
            Assert-NativeFixtureOrderedObjectInternal $registry.negotiated @(
                'sftp_write_bytes', 'sftp_inflight_writes', 'native_chunk_bytes',
                'native_ack_window_bytes'
            ) 'native fixture negotiated limits'
            $limits = [ordered]@{
                sftp_write_bytes = 2048; sftp_inflight_writes = 1
                native_chunk_bytes = 32768; native_ack_window_bytes = 32768
            }
            foreach ($field in $limits.Keys) {
                Assert-Contract (
                    (Test-StrictJsonInteger $registry.negotiated.$field) -and
                    [int64]$registry.negotiated.$field -eq [int64]$limits[$field]
                ) "native fixture negotiated $field changed"
            }
            $registryWindow = [pscustomobject][ordered]@{
                active_per_profile = [int64]8
                active_global = [int64]$activeAccepted
                terminal_per_profile = [int64]16
                terminal_global = [int64]$terminalRetained
                retention_max_seconds = [int64]900
                sftp_write_bytes = [int]2048
                sftp_inflight_writes = [int]1
                native_chunk_bytes = [int]32768
                native_ack_window_bytes = [int]32768
                profile_isolation_passed = $true
                control_frame_bound_passed = $true
                confirmed_before_ack = $confirmedBeforeAck
            }
            Assert-Contract (
                $activeAccepted -eq 48 -and $terminalRetained -eq 256 -and
                -not $confirmedBeforeAck -and
                (($registryWindow | ConvertTo-Json -Compress -Depth 8) -ceq
                    ($owner.registry_window | ConvertTo-Json -Compress -Depth 8))
            ) 'native fixture outer registry summary differs from raw events'

            $performance = Get-NativeFixtureNormalizedPerformanceInternal `
                $raw.performance_samples
            Assert-Contract (
                (($performance | ConvertTo-Json -Compress -Depth 10) -ceq
                    ($owner.performance | ConvertTo-Json -Compress -Depth 10))
            ) 'native fixture outer performance summary differs from raw samples'

            $projection = [pscustomobject][ordered]@{
                schema_version = 1
                projection_contract = 'serctl-native-fixture-unsealable-projection-v1'
                category = 'native_transfer_real_host'
                release_sealable = $false
                sealability = 'unsealable_fixture_only'
                formal_complete_allowed = $false
                evidence_source = 'repository_fixed_local_child_process'
                limitations = @($owner.limitations)
                owner_receipt_sha256 = Get-CanonicalSha256 $OwnerReceiptBytes
                owner_receipt_base64 = [Convert]::ToBase64String($OwnerReceiptBytes)
                child_script_sha256 = [string]$owner.child_script_sha256
                child_stdout_sha256 = [string]$capture.raw_stdout_sha256
                fault_cases = $faultCases
                registry_window = $registryWindow
                performance = $performance
            }
            $projectionBytes = $utf8.GetBytes(
                ($projection | ConvertTo-Json -Compress -Depth 12) + "`n"
            )
            Assert-Contract ($projectionBytes.Length -le 8388608) (
                'native fixture unsealable projection exceeds its byte bound'
            )
            $state.immutable_native_fixture_projection = [pscustomobject][ordered]@{
                sha256 = Get-CanonicalSha256 $projectionBytes
                bytes = $projectionBytes
            }
        }
        finally { if ($null -ne $rawBytes) { [Array]::Clear($rawBytes, 0, $rawBytes.Length) } }

        return Get-ExternalTransferRuntimeLedgerStatus $Ledger
    }

    function Get-ExternalTransferNativeFixtureUnsealableProjection {
        [CmdletBinding()]
        param([Parameter(Mandatory = $true)]$Ledger)

        $state = Resolve-LedgerState $Ledger
        Assert-Contract (
            [string]$state.category -ceq 'native_transfer_real_host' -and
            $null -ne $state.immutable_native_fixture_projection -and
            $state.immutable_native_fixture_projection.bytes -is [byte[]] -and
            (Get-CanonicalSha256 $state.immutable_native_fixture_projection.bytes) -ceq
                [string]$state.immutable_native_fixture_projection.sha256
        ) 'native fixture unsealable projection is unavailable or changed'
        return ,([byte[]]$state.immutable_native_fixture_projection.bytes.Clone())
    }

    # Public admission point for the output of the isolated owner.  It accepts
    # only canonical owner receipt bytes plus the opaque ledger.  The exact
    # component/helper identity and aggregate evidence context must already be
    # present in module-private state from Set-IsolatedOwnerExpectedBindingInternal.
    # Consequently no caller-supplied summary, pass/result object, path, digest,
    # version, helper identity or component record can be substituted here.
    function Import-ExternalTransferIsolatedOwnerReceiptV2 {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)]$Ledger,
            [Parameter(Mandatory = $true)][byte[]]$OwnerReceiptBytes
        )

        $state = Resolve-LedgerState $Ledger
        $temporary = $null
        $componentBytes = $null
        $committed = $false
        try {
            Assert-Contract (
                [string]$state.category -ceq 'openssh_dropbear_interop' -and
                -not $state.sealed -and $state.observations.Count -eq 0 -and
                $state.blocked_case_ids.Count -eq $state.expected_case_ids.Count -and
                $null -ne $state.exact_release_components -and
                [string]$state.expected_evidence_context_sha256 -cmatch '^[0-9A-F]{64}$' -and
                $null -eq $state.bound_evidence_context_sha256 -and
                [string]$state.bound_component_set_sha256 -cmatch '^[0-9A-F]{64}$' -and
                $state.bound_component_bytes -is [byte[]]
            ) 'isolated owner receipt has no protected expected binding'
            Assert-Contract (
                $null -ne $OwnerReceiptBytes -and $OwnerReceiptBytes.Length -gt 0 -and
                $OwnerReceiptBytes.Length -le 1048576
            ) 'isolated owner receipt is outside its byte bound'
            $utf8 = [Text.UTF8Encoding]::new($false, $true)
            try { $ownerText = $utf8.GetString($OwnerReceiptBytes) }
            catch { throw 'external transfer runtime receipt contract failed: isolated owner receipt is not strict UTF-8' }
            Assert-Contract ($ownerText.EndsWith("`n") -and -not $ownerText.Contains("`r")) (
                'isolated owner receipt does not use one canonical LF terminator'
            )
            $owner = ConvertFrom-StrictJson `
                -Json $ownerText.Substring(0, $ownerText.Length - 1) `
                -Label 'isolated owner receipt v2'
            $ownerFields = @(
                'schema_version', 'owner_contract', 'category',
                'evidence_context_sha256', 'component_set_sha256',
                'component_set_base64', 'case_receipts'
            )
            Assert-SerctlClosedObject $owner $ownerFields 'isolated owner receipt v2'
            Assert-Contract (
                (@($owner.PSObject.Properties.Name) -join "`n") -ceq ($ownerFields -join "`n") -and
                (Test-StrictJsonInteger $owner.schema_version) -and
                [int]$owner.schema_version -eq 2 -and
                [string]$owner.owner_contract -ceq 'serctl-isolated-formal-owner-receipt-v2' -and
                [string]$owner.category -ceq 'openssh_dropbear_interop' -and
                [string]$owner.evidence_context_sha256 -ceq
                    [string]$state.expected_evidence_context_sha256 -and
                [string]$owner.evidence_context_sha256 -cmatch '^[0-9A-F]{64}$' -and
                [string]$owner.component_set_sha256 -cmatch '^[0-9A-F]{64}$' -and
                (Test-StrictJsonArray $owner.case_receipts)
            ) 'isolated owner receipt v2 identity or aggregate binding is invalid'
            $canonicalOwnerText = ($owner | ConvertTo-Json -Compress -Depth 10) + "`n"
            Assert-Contract ($canonicalOwnerText -ceq $ownerText) (
                'isolated owner receipt v2 bytes are not canonical JSON'
            )

            $componentBytes = Get-CanonicalBoundedBase64BytesInternal `
                $owner.component_set_base64 65536 'isolated owner component set'
            Assert-Contract (
                (Get-CanonicalSha256 $componentBytes) -ceq
                    [string]$owner.component_set_sha256 -and
                [string]$owner.component_set_sha256 -ceq
                    [string]$state.bound_component_set_sha256 -and
                $componentBytes.Length -eq $state.bound_component_bytes.Length
            ) 'isolated owner component set differs from the protected exact binding'
            Assert-Contract (
                [Convert]::ToBase64String($componentBytes) -ceq
                    [Convert]::ToBase64String($state.bound_component_bytes)
            ) 'isolated owner component bytes differ from the protected exact binding'
            $componentText = $utf8.GetString($componentBytes)
            Assert-Contract ($componentText.EndsWith("`n") -and -not $componentText.Contains("`r")) (
                'isolated owner component set is not canonical text'
            )
            $componentDocument = ConvertFrom-StrictJson `
                -Json $componentText.Substring(0, $componentText.Length - 1) `
                -Label 'isolated owner exact components'
            $canonicalComponents = Get-CanonicalRuntimeComponentBytesInternal $componentDocument
            try {
                Assert-Contract (
                    [Convert]::ToBase64String($canonicalComponents) -ceq
                        [Convert]::ToBase64String($componentBytes)
                ) 'isolated owner component set is not canonical or changed helper identity'
            }
            finally { [Array]::Clear($canonicalComponents, 0, $canonicalComponents.Length) }

            $entries = @($owner.case_receipts)
            Assert-Contract ($entries.Count -eq $state.expected_case_ids.Count) (
                'isolated owner receipt v2 does not contain the exact ten-case set'
            )
            $temporary = [pscustomobject]@{
                category = [string]$state.category
                expected_case_ids = @($state.expected_case_ids)
                observations = [ordered]@{}
                blocked_case_ids = [Collections.Generic.HashSet[string]]::new(
                    [StringComparer]::Ordinal
                )
                exact_release_components = $state.exact_release_components
                expected_evidence_context_sha256 =
                    [string]$state.expected_evidence_context_sha256
                bound_evidence_context_sha256 =
                    [string]$owner.evidence_context_sha256
                operation_context_sha256_by_case = [ordered]@{}
                bound_component_set_sha256 = [string]$state.bound_component_set_sha256
                bound_component_bytes = [byte[]]$state.bound_component_bytes.Clone()
                immutable_transfer_cases = [ordered]@{}
                immutable_transfer_details = $null
            }
            foreach ($caseId in $temporary.expected_case_ids) {
                [void]$temporary.blocked_case_ids.Add($caseId)
            }
            $seenReceiptDigests = [Collections.Generic.HashSet[string]]::new(
                [StringComparer]::Ordinal
            )
            $seenCases = [Collections.Generic.HashSet[string]]::new(
                [StringComparer]::Ordinal
            )
            for ($index = 0; $index -lt $entries.Count; $index++) {
                $entry = $entries[$index]
                $entryFields = @(
                    'case_id', 'operation_context_sha256',
                    'receipt_base64', 'receipt_sha256'
                )
                Assert-SerctlClosedObject $entry $entryFields (
                    'isolated owner receipt v2 case entry'
                )
                $caseId = [string]$entry.case_id
                Assert-Contract (
                    (@($entry.PSObject.Properties.Name) -join "`n") -ceq
                        ($entryFields -join "`n") -and
                    $caseId -cin $temporary.expected_case_ids -and
                    $seenCases.Add($caseId) -and
                    [string]$entry.operation_context_sha256 -cmatch '^[0-9A-F]{64}$' -and
                    [string]$entry.receipt_sha256 -cmatch '^[0-9A-F]{64}$' -and
                    $seenReceiptDigests.Add([string]$entry.receipt_sha256)
                ) 'isolated owner receipt v2 case identity is invalid, unknown, duplicated, or reused'
                $childBytes = Get-CanonicalBoundedBase64BytesInternal `
                    $entry.receipt_base64 65536 "isolated owner case '$caseId' receipt"
                try {
                    Assert-Contract (
                        (Get-CanonicalSha256 $childBytes) -ceq [string]$entry.receipt_sha256
                    ) "isolated owner case '$caseId' receipt digest differs from its bytes"
                    $childText = $utf8.GetString($childBytes)
                    Assert-Contract (
                        $childText.EndsWith("`n") -and -not $childText.Contains("`r")
                    ) "isolated owner case '$caseId' receipt text is not canonical"
                    $child = ConvertFrom-StrictJson `
                        -Json $childText.Substring(0, $childText.Length - 1) `
                        -Label "isolated owner case '$caseId' receipt"
                    Assert-Contract (
                        [string]$child.context_sha256 -ceq
                            [string]$entry.operation_context_sha256
                    ) "isolated owner case '$caseId' operation context differs from its child receipt"
                    $observation = [pscustomobject][ordered]@{
                        internal_contract = 'serctl-runtime-adapter-observation-v1'
                        category = 'openssh_dropbear_interop'
                        case_id = $caseId
                        context_sha256 = [string]$entry.operation_context_sha256
                        command_sha256 = [string]$child.command_sha256
                        terminal_sha256 = [string]$child.terminal_sha256
                        receipt_bytes = $childBytes
                    }
                    Accept-ExternalTransferRuntimeAdapterObservation $temporary $observation
                }
                finally { [Array]::Clear($childBytes, 0, $childBytes.Length) }
            }
            Assert-Contract (
                $temporary.observations.Count -eq 10 -and
                $temporary.blocked_case_ids.Count -eq 0 -and
                $temporary.operation_context_sha256_by_case.Count -eq 10 -and
                (($seenCases | Sort-Object) -join "`n") -ceq
                    (($temporary.expected_case_ids | Sort-Object) -join "`n") -and
                $temporary.immutable_transfer_details -is [byte[]]
            ) 'isolated owner receipt v2 did not derive the complete immutable ten-case state'

            [Array]::Clear(
                $state.bound_component_bytes, 0, $state.bound_component_bytes.Length
            )
            $state.observations = $temporary.observations
            $state.blocked_case_ids = $temporary.blocked_case_ids
            $state.bound_evidence_context_sha256 =
                [string]$temporary.bound_evidence_context_sha256
            $state.operation_context_sha256_by_case =
                $temporary.operation_context_sha256_by_case
            $state.bound_component_set_sha256 =
                [string]$temporary.bound_component_set_sha256
            $state.bound_component_bytes = $temporary.bound_component_bytes
            $state.immutable_transfer_cases = $temporary.immutable_transfer_cases
            $state.immutable_transfer_details = $temporary.immutable_transfer_details
            $temporary.bound_component_bytes = $null
            $temporary.immutable_transfer_details = $null
            $state.exact_release_components = $null
            $state.expected_evidence_context_sha256 = $null
            $committed = $true
            return Get-ExternalTransferRuntimeLedgerStatus $Ledger
        }
        finally {
            if ($null -ne $OwnerReceiptBytes) {
                [Array]::Clear($OwnerReceiptBytes, 0, $OwnerReceiptBytes.Length)
            }
            if ($null -ne $componentBytes) {
                [Array]::Clear($componentBytes, 0, $componentBytes.Length)
            }
            if ($null -ne $temporary -and -not $committed) {
                foreach ($record in @($temporary.immutable_transfer_cases.Values)) {
                    if ($null -ne $record -and $record.bytes -is [byte[]]) {
                        [Array]::Clear($record.bytes, 0, $record.bytes.Length)
                    }
                }
                if ($temporary.bound_component_bytes -is [byte[]]) {
                    [Array]::Clear(
                        $temporary.bound_component_bytes, 0,
                        $temporary.bound_component_bytes.Length
                    )
                }
                if ($temporary.immutable_transfer_details -is [byte[]]) {
                    [Array]::Clear(
                        $temporary.immutable_transfer_details, 0,
                        $temporary.immutable_transfer_details.Length
                    )
                }
            }
            if (-not $committed) {
                if ($state.bound_component_bytes -is [byte[]]) {
                    [Array]::Clear(
                        $state.bound_component_bytes, 0,
                        $state.bound_component_bytes.Length
                    )
                }
                $state.exact_release_components = $null
                $state.expected_evidence_context_sha256 = $null
                $state.bound_evidence_context_sha256 = $null
                $state.bound_component_set_sha256 = $null
                $state.bound_component_bytes = $null
            }
        }
    }

    # Deterministic, unsealable projection of the ledger-owned portion of the
    # external OpenSSH/Dropbear details.  Runner, remote and implementation
    # identity are intentionally absent: those values must come from the future
    # exact-tag isolated owner and may not be supplied to this function.
    function Get-ExternalTransferInteropUnsealableProjection {
        [CmdletBinding()]
        param([Parameter(Mandatory = $true)]$Ledger)

        $state = Resolve-LedgerState $Ledger
        Assert-Contract (
            [string]$state.category -ceq 'openssh_dropbear_interop' -and
            -not $state.sealed -and
            $state.observations.Count -eq 10 -and
            $state.blocked_case_ids.Count -eq 0 -and
            [string]$state.bound_evidence_context_sha256 -cmatch '^[0-9A-F]{64}$' -and
            [string]$state.bound_component_set_sha256 -cmatch '^[0-9A-F]{64}$' -and
            $state.bound_component_bytes -is [byte[]] -and
            $state.operation_context_sha256_by_case.Count -eq 10
        ) 'interop projection requires one complete imported owner-v2 ledger'
        Assert-Contract (
            (Get-CanonicalSha256 $state.bound_component_bytes) -ceq
                [string]$state.bound_component_set_sha256
        ) 'interop projection exact component bytes changed in memory'
        $utf8 = [Text.UTF8Encoding]::new($false, $true)
        $componentText = $utf8.GetString($state.bound_component_bytes)
        Assert-Contract (
            $componentText.EndsWith("`n") -and -not $componentText.Contains("`r")
        ) 'interop projection component set is not canonical text'
        $components = ConvertFrom-StrictJson `
            -Json $componentText.Substring(0, $componentText.Length - 1) `
            -Label 'interop projection exact components'
        $canonicalComponents = Get-CanonicalRuntimeComponentBytesInternal $components
        try {
            Assert-Contract (
                [Convert]::ToBase64String($canonicalComponents) -ceq
                    [Convert]::ToBase64String($state.bound_component_bytes)
            ) 'interop projection exact components are not canonical'
        }
        finally { [Array]::Clear($canonicalComponents, 0, $canonicalComponents.Length) }

        $caseReceipts = @()
        $seenOperationContexts = [Collections.Generic.HashSet[string]]::new(
            [StringComparer]::Ordinal
        )
        foreach ($caseId in $state.expected_case_ids) {
            Assert-Contract (
                $state.observations.Contains($caseId) -and
                $state.operation_context_sha256_by_case.Contains($caseId)
            ) "interop projection case '$caseId' is missing"
            $record = $state.observations[$caseId]
            $operationContext = [string]$state.operation_context_sha256_by_case[$caseId]
            Assert-Contract (
                [string]$record.case_id -ceq $caseId -and
                [string]$record.receipt_sha256 -cmatch '^[0-9A-F]{64}$' -and
                $operationContext -cmatch '^[0-9A-F]{64}$' -and
                $operationContext -cne [string]$state.bound_evidence_context_sha256 -and
                $seenOperationContexts.Add($operationContext)
            ) "interop projection case '$caseId' binding is invalid or reused"
            $childBytes = Get-CanonicalBoundedBase64BytesInternal `
                $record.receipt_base64 65536 "interop projection case '$caseId' receipt"
            try {
                Assert-Contract (
                    (Get-CanonicalSha256 $childBytes) -ceq [string]$record.receipt_sha256
                ) "interop projection case '$caseId' receipt bytes changed"
                $childText = $utf8.GetString($childBytes)
                Assert-Contract (
                    $childText.EndsWith("`n") -and -not $childText.Contains("`r")
                ) "interop projection case '$caseId' receipt is not canonical text"
                $child = ConvertFrom-StrictJson `
                    -Json $childText.Substring(0, $childText.Length - 1) `
                    -Label "interop projection case '$caseId' receipt"
                Assert-Contract (
                    [string]$child.category -ceq 'openssh_dropbear_interop' -and
                    [string]$child.case_id -ceq $caseId -and
                    [string]$child.context_sha256 -ceq $operationContext -and
                    [string]$child.result_code -ceq 'completed' -and
                    (Test-StrictJsonBoolean $child.passed) -and [bool]$child.passed
                ) "interop projection case '$caseId' child identity changed"
            }
            finally { [Array]::Clear($childBytes, 0, $childBytes.Length) }
            $caseReceipts += [pscustomobject][ordered]@{
                case_id = $caseId
                operation_context_sha256 = $operationContext
                receipt_base64 = [string]$record.receipt_base64
                receipt_sha256 = [string]$record.receipt_sha256
            }
        }
        $projection = [pscustomobject][ordered]@{
            schema_version = 1
            projection_contract = 'serctl-openssh-dropbear-interop-details-projection-v1'
            category = 'openssh_dropbear_interop'
            release_sealable = $false
            missing_formal_fields = @('runner', 'remote', 'implementations', 'exact_tag_envelope')
            details = [pscustomobject][ordered]@{
                evidence_context_sha256 = [string]$state.bound_evidence_context_sha256
                components = $components
                case_receipts = $caseReceipts
            }
        }
        $bytes = $utf8.GetBytes(($projection | ConvertTo-Json -Compress -Depth 12) + "`n")
        Assert-Contract ($bytes.Length -gt 0 -and $bytes.Length -le 1048576) (
            'interop unsealable projection is outside its byte bound'
        )
        return ,$bytes
    }

    function Complete-ExternalTransferRuntimeLedger {
        [CmdletBinding()]
        param([Parameter(Mandatory = $true)]$Ledger)
        $state = Resolve-LedgerState -Ledger $Ledger
        Assert-Contract (-not $state.sealed) 'runtime ledger is already sealed'
        Assert-Contract ($state.blocked_case_ids.Count -eq 0) (
            "runtime ledger remains BLOCKED for $($state.blocked_case_ids.Count) case(s)"
        )
        Assert-Contract (
            $state.observations.Count -eq $state.expected_case_ids.Count
        ) 'runtime ledger lacks the exact complete controlled observation set'
        $prerequisites = Get-ImmutableTransferPrerequisitesInternal $state
        Assert-Contract ($prerequisites.ready) (
            'runtime ledger lacks its exact immutable transfer case prerequisite set'
        )
        Assert-Contract (
            $state.immutable_transfer_details -is [byte[]] -and
            $state.immutable_transfer_details.Length -gt 0 -and
            $state.immutable_transfer_details.Length -le 1048576
        ) 'runtime ledger lacks immutable transfer prerequisite details'
        $detailsText = [Text.UTF8Encoding]::new($false, $true).GetString(
            $state.immutable_transfer_details
        )
        Assert-Contract (
            $detailsText.EndsWith("`n") -and -not $detailsText.Contains("`r")
        ) 'runtime transfer prerequisite details are not canonical text'
        $details = ConvertFrom-StrictJson `
            -Json $detailsText.Substring(0, $detailsText.Length - 1) `
            -Label 'immutable transfer prerequisite details'
        Assert-SerctlClosedObject $details @(
            'schema_version', 'contract', 'category', 'release_sealable',
            'context_sha256', 'component_set_sha256', 'component_set_base64', 'cases'
        ) 'immutable transfer prerequisite details'
        Assert-Contract (
            (Test-StrictJsonInteger $details.schema_version) -and
            [int]$details.schema_version -eq 1 -and
            [string]$details.contract -ceq 'serctl-transfer-receipt-prerequisites-v1' -and
            [string]$details.category -ceq [string]$state.category -and
            (Test-StrictJsonBoolean $details.release_sealable) -and
            -not [bool]$details.release_sealable
        ) 'immutable transfer prerequisite details attempted to claim a seal'
        $remaining = if ([string]$state.category -ceq 'native_transfer_real_host') {
            $missingFaults = @(
                $script:NativeFaultCases.Keys | Where-Object {
                    -not $state.immutable_native_fault_cases.Contains($_)
                }
            )
            Assert-Contract ($missingFaults.Count -eq 0) (
                'native fault actual observations are incomplete: ' +
                ($missingFaults -join ',')
            )
            foreach ($caseId in $script:NativeFaultCases.Keys) {
                $record = $state.immutable_native_fault_cases[$caseId]
                Assert-Contract (
                    $record.bytes -is [byte[]] -and
                    (Get-CanonicalSha256 $record.bytes) -ceq [string]$record.sha256
                ) "native fault actual observation '$caseId' changed in memory"
            }
            Assert-Contract (
                $null -ne $state.immutable_native_registry -and
                $state.immutable_native_registry.bytes -is [byte[]] -and
                (Get-CanonicalSha256 $state.immutable_native_registry.bytes) -ceq
                    [string]$state.immutable_native_registry.sha256
            ) 'native registry/window actual observation is missing or changed'
            Assert-Contract (
                $null -ne $state.immutable_native_performance -and
                $state.immutable_native_performance.bytes -is [byte[]] -and
                (Get-CanonicalSha256 $state.immutable_native_performance.bytes) -ceq
                    [string]$state.immutable_native_performance.sha256
            ) 'native performance raw measurements are missing or changed'
            'private raw structures cannot substitute for an isolated actual-capture owner'
        }
        else {
            'isolated owner case receipts are only immutable prerequisites; ' +
                'formal runner and remote projections remain unavailable'
        }
        throw "external transfer runtime receipt contract failed: $remaining; release seal refused"
    }

    function Add-ReceiptFullControlRule {
        param(
            [Parameter(Mandatory = $true)]$Acl,
            [Parameter(Mandatory = $true)]$Sid
        )
        $Acl.AddAccessRule([System.Security.AccessControl.FileSystemAccessRule]::new(
            $Sid,
            [System.Security.AccessControl.FileSystemRights]::FullControl,
            [System.Security.AccessControl.AccessControlType]::Allow
        ))
    }

    function Get-ProtectedReceiptBytes {
        param(
            [Parameter(Mandatory = $true)][byte[]]$Bytes,
            [Parameter(Mandatory = $true)][string]$Path
        )
        Assert-Contract ($Bytes.Length -gt 0 -and $Bytes.Length -le 8388608) (
            'receipt size is outside 1..8388608 bytes'
        )
        $expectedSha256 = Get-CanonicalSha256 -Bytes $Bytes
        $fullPath = [System.IO.Path]::GetFullPath($Path)
        $parentPath = [System.IO.Path]::GetDirectoryName($fullPath)
        $parent = Get-Item -LiteralPath $parentPath -Force -ErrorAction Stop
        Assert-Contract (
            $parent.PSIsContainer -and
            ($parent.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0
        ) 'receipt parent is not a regular directory'
        Assert-Contract (-not (Test-Path -LiteralPath $fullPath)) (
            'receipt destination already exists'
        )
        $stream = [System.IO.FileStream]::new(
            $fullPath,
            [System.IO.FileMode]::CreateNew,
            [System.IO.FileAccess]::Write,
            [System.IO.FileShare]::None,
            4096,
            [System.IO.FileOptions]::WriteThrough
        )
        try {
            if ($script:IsWindows) {
                $currentSid = [System.Security.Principal.WindowsIdentity]::GetCurrent().User
                $acl = [System.Security.AccessControl.FileSecurity]::new()
                $acl.SetOwner($currentSid)
                $acl.SetAccessRuleProtection($true, $false)
                Add-ReceiptFullControlRule -Acl $acl -Sid $currentSid
                Add-ReceiptFullControlRule -Acl $acl -Sid (
                    [System.Security.Principal.SecurityIdentifier]::new('S-1-5-18')
                )
                Add-ReceiptFullControlRule -Acl $acl -Sid (
                    [System.Security.Principal.SecurityIdentifier]::new('S-1-5-32-544')
                )
                Set-Acl -LiteralPath $fullPath -AclObject $acl -ErrorAction Stop
            }
            else {
                [System.IO.File]::SetUnixFileMode(
                    $fullPath,
                    [System.IO.UnixFileMode]::UserRead -bor
                        [System.IO.UnixFileMode]::UserWrite
                )
            }
            $stream.Write($Bytes, 0, $Bytes.Length)
            $stream.Flush($true)
        }
        catch {
            $stream.Dispose()
            try { Remove-Item -LiteralPath $fullPath -Force -ErrorAction Stop } catch {}
            throw 'protected external transfer receipt write failed; diagnostic details withheld'
        }
        finally { $stream.Dispose() }
        $item = Get-Item -LiteralPath $fullPath -Force -ErrorAction Stop
        Assert-Contract (
            -not $item.PSIsContainer -and
            ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0 -and
            $item.Length -eq $Bytes.Length -and
            (Get-FileHash -LiteralPath $fullPath -Algorithm SHA256).Hash -ceq $expectedSha256
        ) 'protected receipt bytes do not match the same-process receipt digest'
    }

    function Write-ProtectedExternalTransferRuntimeReceipt {
        [CmdletBinding()]
        param(
            [Parameter(Mandatory = $true)]$Ledger,
            [Parameter(Mandatory = $true)][ValidateNotNullOrEmpty()][string]$Path
        )
        $state = Resolve-LedgerState -Ledger $Ledger
        Assert-Contract $state.sealed 'runtime ledger is not sealed'
        Assert-Contract ($null -ne $state.sealed_details) (
            'runtime ledger has no immutable sealed details'
        )
        # Callers never supply a Receipt/details/result object to this function.
        Get-ProtectedReceiptBytes -Bytes $state.sealed_details -Path $Path
    }

    Export-ModuleMember -Function @(
        'New-ExternalTransferRuntimeLedger',
        'Get-ExternalTransferRuntimeLedgerStatus',
        'Test-ExternalTransferRuntimeArgumentVector',
        'Invoke-ExternalTransferRuntimeCase',
        'Invoke-ExternalTransferFormalOwnerCase',
        'Invoke-ExternalTransferFormalOwnerConcurrentTransferCase',
        'Import-ExternalTransferIsolatedOwnerReceiptV2',
        'Get-ExternalTransferInteropUnsealableProjection',
        'Import-NativeFaultRegistryPerformanceFixtureReceipt',
        'Get-ExternalTransferNativeFixtureUnsealableProjection',
        'Complete-ExternalTransferRuntimeLedger',
        'Write-ProtectedExternalTransferRuntimeReceipt'
    )
}

Import-Module $contractModule -Global -Force
