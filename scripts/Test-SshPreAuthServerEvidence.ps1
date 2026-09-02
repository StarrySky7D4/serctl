[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Path,

    [string]$ExpectedCorrelationId,
    [string]$ExpectedProbeId,
    [string]$ExpectedClientRecordSha256,
    [string]$ExpectedTargetBindingSha256,
    [int]$ExpectedConfiguredPort = 0
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'StrictJson.ps1')

function Assert-EvidenceCondition {
    param(
        [Parameter(Mandatory = $true)][bool]$Condition,
        [Parameter(Mandatory = $true)][string]$Code
    )

    if (-not $Condition) {
        throw "evidence-invalid:$Code"
    }
}

function Assert-ExactProperties {
    param(
        [Parameter(Mandatory = $true)][object]$Object,
        [Parameter(Mandatory = $true)][string[]]$Expected,
        [Parameter(Mandatory = $true)][string]$Code
    )

    Assert-EvidenceCondition ($Object -is [pscustomobject]) "$Code.object"
    $actual = @($Object.PSObject.Properties | ForEach-Object { $_.Name })
    Assert-EvidenceCondition ($actual.Count -eq $Expected.Count) "$Code.property-count"
    foreach ($name in $Expected) {
        Assert-EvidenceCondition ($actual -ccontains $name) "$Code.missing-property"
    }
}

function Assert-Boolean {
    param([object]$Value, [string]$Code)

    Assert-EvidenceCondition ($Value -is [bool]) "$Code.boolean"
}

function Assert-IntegerRange {
    param(
        [object]$Value,
        [long]$Minimum,
        [long]$Maximum,
        [string]$Code
    )

    $integer =
        $Value -is [byte] -or
        $Value -is [sbyte] -or
        $Value -is [int16] -or
        $Value -is [uint16] -or
        $Value -is [int32] -or
        $Value -is [uint32] -or
        $Value -is [int64]
    Assert-EvidenceCondition $integer "$Code.integer"
    $converted = [long]$Value
    Assert-EvidenceCondition (
        $converted -ge $Minimum -and $converted -le $Maximum
    ) "$Code.range"
}

function Assert-EnumValue {
    param(
        [object]$Value,
        [string[]]$Allowed,
        [string]$Code
    )

    Assert-EvidenceCondition ($Value -is [string]) "$Code.string"
    Assert-EvidenceCondition ($Allowed -ccontains [string]$Value) "$Code.enum"
}

function ConvertFrom-StrictUtcTimestamp {
    param([object]$Value, [string]$Code)

    Assert-EvidenceCondition ($Value -is [string]) "$Code.string"
    Assert-EvidenceCondition (
        [string]$Value -cmatch '^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$'
    ) "$Code.format"
    try {
        return [DateTimeOffset]::ParseExact(
            [string]$Value,
            "yyyy-MM-dd'T'HH:mm:ss.fff'Z'",
            [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AssumeUniversal -bor
                [Globalization.DateTimeStyles]::AdjustToUniversal
        )
    }
    catch {
        throw "evidence-invalid:$Code.timestamp"
    }
}

function Assert-CorrelationId {
    param([object]$Value)

    Assert-EvidenceCondition ($Value -is [string]) 'correlation-id.string'
    Assert-EvidenceCondition (
        [string]$Value -cmatch '^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'
    ) 'correlation-id.uuid-v4'
}

function Assert-NoSensitiveStrings {
    param([object]$Value)

    if ($null -eq $Value) {
        return
    }
    if ($Value -is [string]) {
        $text = [string]$Value
        # Canonical opaque SHA-256 bindings are schema-checked separately.
        # .NET accepts a long all-numeric hexadecimal string as a legacy
        # integer-form IP address, so do not misclassify a digest as topology.
        if ($text -cmatch '^[0-9a-f]{64}$') {
            return
        }
        $parsedAddress = $null
        Assert-EvidenceCondition (
            -not [Net.IPAddress]::TryParse($text, [ref]$parsedAddress)
        ) 'sensitive.ip-address'
        Assert-EvidenceCondition (
            $text -notmatch '(^[A-Za-z]:[\\/])|(^/)|[\\/]'
        ) 'sensitive.path'
        Assert-EvidenceCondition ($text -notmatch '^SSH-[0-9]') 'sensitive.banner'
        Assert-EvidenceCondition (
            $text -notmatch '^(SHA256|MD5):'
        ) 'sensitive.fingerprint'
        return
    }
    if ($Value -is [pscustomobject]) {
        foreach ($property in $Value.PSObject.Properties) {
            Assert-NoSensitiveStrings $property.Value
        }
        return
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        foreach ($item in $Value) {
            Assert-NoSensitiveStrings $item
        }
    }
}

try {
    $fullPath = [IO.Path]::GetFullPath($Path)
    Assert-EvidenceCondition (Test-Path -LiteralPath $fullPath -PathType Leaf) 'file.missing'
    $item = Get-Item -LiteralPath $fullPath -Force
    Assert-EvidenceCondition (
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -eq 0
    ) 'file.reparse'
    Assert-EvidenceCondition (
        $item.Length -gt 0 -and $item.Length -le 65536
    ) 'file.size'
    $raw = Read-StrictUtf8Text -Path $fullPath
    $evidence = ConvertFrom-StrictJson `
        -Json $raw `
        -Label 'SSH pre-auth server evidence' `
        -MaxChars 65536 `
        -MaxDepth 16 `
        -MaxKeyChars 64

    Assert-ExactProperties $evidence @(
        'schema_version',
        'evidence_status',
        'correlation',
        'listener',
        'sshd_admission',
        'events',
        'counters',
        'classification'
    ) 'root'
    Assert-IntegerRange $evidence.schema_version 2 2 'schema-version'
    Assert-EnumValue $evidence.evidence_status @('template', 'server_observation') 'status'

    $externalBindingPresence = @(
        -not [string]::IsNullOrWhiteSpace($ExpectedCorrelationId),
        -not [string]::IsNullOrWhiteSpace($ExpectedProbeId),
        -not [string]::IsNullOrWhiteSpace($ExpectedClientRecordSha256),
        -not [string]::IsNullOrWhiteSpace($ExpectedTargetBindingSha256),
        $ExpectedConfiguredPort -ne 0
    )
    $externalBindingCount = @($externalBindingPresence | Where-Object { $_ }).Count
    Assert-EvidenceCondition (
        $externalBindingCount -eq 0 -or $externalBindingCount -eq 5
    ) 'external-binding.partial'
    $externalBindingVerified = $externalBindingCount -eq 5
    if ($externalBindingVerified) {
        Assert-CorrelationId $ExpectedCorrelationId
        Assert-CorrelationId $ExpectedProbeId
        Assert-EvidenceCondition (
            $ExpectedClientRecordSha256 -cmatch '^[0-9a-f]{64}$'
        ) 'expected-client-record-sha256'
        Assert-EvidenceCondition (
            $ExpectedTargetBindingSha256 -cmatch '^[0-9a-f]{64}$'
        ) 'expected-target-binding-sha256'
        Assert-IntegerRange $ExpectedConfiguredPort 1 65535 'expected-configured-port'
    }

    $correlation = $evidence.correlation
    Assert-ExactProperties $correlation @(
        'correlation_id',
        'probe_id',
        'client_record_sha256',
        'target_binding_sha256',
        'configured_port',
        'client_observation',
        'attempt_count',
        'probe_start_utc',
        'probe_end_utc',
        'window_start_utc',
        'window_end_utc',
        'server_clock_offset_ms',
        'clock_uncertainty_ms',
        'probe_count',
        'exclusive_window',
        'client_record_bound',
        'connection_binding'
    ) 'correlation'
    Assert-CorrelationId $correlation.correlation_id
    Assert-CorrelationId $correlation.probe_id
    foreach ($field in @('client_record_sha256', 'target_binding_sha256')) {
        Assert-EvidenceCondition (
            $correlation.$field -is [string] -and
            [string]$correlation.$field -cmatch '^[0-9a-f]{64}$'
        ) "correlation.$field"
    }
    Assert-IntegerRange $correlation.configured_port 1 65535 'configured-port'
    Assert-EnumValue $correlation.client_observation @(
        'tcp_not_connected',
        'tcp_connected_no_ssh_bytes',
        'client_identification_sent_server_silent',
        'transport_closed_before_server_identification',
        'peer_bytes_without_valid_server_identification',
        'ssh_identification_observed_no_host_key',
        'remote_ssh_disconnect_before_host_key',
        'host_key_observed'
    ) 'client-observation'
    Assert-IntegerRange $correlation.attempt_count 1 2 'attempt-count'
    if ($externalBindingVerified) {
        Assert-EvidenceCondition (
            $correlation.correlation_id -ceq $ExpectedCorrelationId -and
            $correlation.probe_id -ceq $ExpectedProbeId -and
            $correlation.client_record_sha256 -ceq $ExpectedClientRecordSha256 -and
            $correlation.target_binding_sha256 -ceq $ExpectedTargetBindingSha256 -and
            [long]$correlation.configured_port -eq [long]$ExpectedConfiguredPort
        ) 'external-binding.mismatch'
    }
    $probeStart = ConvertFrom-StrictUtcTimestamp $correlation.probe_start_utc 'probe-start'
    $probeEnd = ConvertFrom-StrictUtcTimestamp $correlation.probe_end_utc 'probe-end'
    $windowStart = ConvertFrom-StrictUtcTimestamp $correlation.window_start_utc 'window-start'
    $windowEnd = ConvertFrom-StrictUtcTimestamp $correlation.window_end_utc 'window-end'
    $probeDurationMs = [long]($probeEnd - $probeStart).TotalMilliseconds
    $durationMs = [long]($windowEnd - $windowStart).TotalMilliseconds
    Assert-EvidenceCondition (
        $probeDurationMs -gt 0 -and $probeDurationMs -le 300000
    ) 'probe-window.duration'
    Assert-EvidenceCondition ($durationMs -gt 0 -and $durationMs -le 900000) 'window.duration'
    Assert-IntegerRange $correlation.server_clock_offset_ms -300000 300000 'clock-offset'
    Assert-IntegerRange $correlation.clock_uncertainty_ms 0 5000 'clock-uncertainty'
    $adjustedProbeStart = $probeStart.AddMilliseconds(
        [long]$correlation.server_clock_offset_ms
    )
    $adjustedProbeEnd = $probeEnd.AddMilliseconds(
        [long]$correlation.server_clock_offset_ms
    )
    $clockUncertaintyMs = [long]$correlation.clock_uncertainty_ms
    Assert-EvidenceCondition (
        $windowStart -le $adjustedProbeStart.AddMilliseconds(-$clockUncertaintyMs) -and
        $windowEnd -ge $adjustedProbeEnd.AddMilliseconds($clockUncertaintyMs)
    ) 'window.probe-clock-coverage'
    Assert-IntegerRange $correlation.probe_count 1 1 'probe-count'
    Assert-Boolean $correlation.exclusive_window 'exclusive-window'
    Assert-Boolean $correlation.client_record_bound 'client-record-bound'
    Assert-EnumValue $correlation.connection_binding @(
        'matched_expected_service',
        'not_observed',
        'ambiguous'
    ) 'connection-binding'

    $listener = $evidence.listener
    Assert-ExactProperties $listener @(
        'expected_owner',
        'service',
        'protocol',
        'port'
    ) 'listener'
    Assert-Boolean $listener.expected_owner 'listener-owner'
    Assert-EnumValue $listener.service @(
        'openssh_sshd',
        'dropbear',
        'other_ssh_service',
        'unknown'
    ) 'listener-service'
    Assert-EnumValue $listener.protocol @('tcp') 'listener-protocol'
    Assert-IntegerRange $listener.port 1 65535 'listener-port'
    Assert-EvidenceCondition (
        [long]$listener.port -eq [long]$correlation.configured_port
    ) 'listener.configured-port-mismatch'

    $admission = $evidence.sshd_admission
    Assert-ExactProperties $admission @(
        'max_startups_start',
        'max_startups_rate_percent',
        'max_startups_full',
        'per_source_max_startups',
        'per_source_penalties_supported',
        'per_source_penalties_enabled',
        'login_grace_time_ms',
        'max_sessions',
        'port',
        'address_family',
        'log_level',
        'non_default_listen_address_configured',
        'banner_configured'
    ) 'sshd-admission'
    Assert-IntegerRange $admission.max_startups_start 1 65535 'max-startups-start'
    Assert-IntegerRange $admission.max_startups_rate_percent 1 100 'max-startups-rate'
    Assert-IntegerRange $admission.max_startups_full 1 65535 'max-startups-full'
    Assert-EvidenceCondition (
        [long]$admission.max_startups_full -ge [long]$admission.max_startups_start
    ) 'max-startups.order'
    Assert-IntegerRange $admission.per_source_max_startups -1 65535 'per-source-max-startups'
    Assert-Boolean $admission.per_source_penalties_supported 'penalties-supported'
    Assert-Boolean $admission.per_source_penalties_enabled 'penalties-enabled'
    if (-not $admission.per_source_penalties_supported) {
        Assert-EvidenceCondition (-not $admission.per_source_penalties_enabled) 'penalties.unsupported-enabled'
    }
    Assert-IntegerRange $admission.login_grace_time_ms 0 3600000 'login-grace-time'
    Assert-IntegerRange $admission.max_sessions 1 65535 'max-sessions'
    Assert-IntegerRange $admission.port 1 65535 'sshd-port'
    Assert-EvidenceCondition (
        [long]$admission.port -eq [long]$listener.port
    ) 'port.mismatch'
    Assert-EnumValue $admission.address_family @('any', 'inet', 'inet6') 'address-family'
    Assert-EnumValue $admission.log_level @(
        'QUIET', 'FATAL', 'ERROR', 'INFO', 'VERBOSE', 'DEBUG', 'DEBUG1', 'DEBUG2', 'DEBUG3'
    ) 'log-level'
    Assert-Boolean $admission.non_default_listen_address_configured 'listen-address-flag'
    Assert-Boolean $admission.banner_configured 'banner-flag'

    Assert-EvidenceCondition (Test-StrictJsonArray $evidence.events) 'events.array'
    $events = @($evidence.events)
    Assert-EvidenceCondition ($events.Count -ge 1 -and $events.Count -le 64) 'events.count'
    $eventCategories = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $previousRelativeMs = -1L
    foreach ($event in $events) {
        Assert-ExactProperties $event @(
            'relative_ms',
            'category',
            'admission_decision',
            'phase',
            'count'
        ) 'event'
        Assert-IntegerRange $event.relative_ms 0 $durationMs 'event-relative-ms'
        Assert-EnumValue $event.category @(
            'listener_accept',
            'admission_reject',
            'admission_penalty',
            'identification_sent',
            'kex_started',
            'connection_closed',
            'resource_pressure',
            'firewall_or_ban',
            'no_matching_event'
        ) 'event-category'
        Assert-EnumValue $event.admission_decision @(
            'accepted', 'rejected', 'penalized', 'not_applicable', 'unknown'
        ) 'event-admission-decision'
        Assert-EnumValue $event.phase @(
            'listener', 'pre_identification', 'identification', 'kex', 'pre_auth', 'closed', 'unknown'
        ) 'event-phase'
        Assert-IntegerRange $event.count 1 1000000 'event-count'
        Assert-EvidenceCondition (
            [long]$event.relative_ms -ge $previousRelativeMs
        ) 'event.order'
        $previousRelativeMs = [long]$event.relative_ms
        switch -CaseSensitive ([string]$event.category) {
            'listener_accept' {
                Assert-EvidenceCondition (
                    $event.admission_decision -ceq 'accepted' -and
                    $event.phase -ceq 'listener'
                ) 'event.listener-accept-shape'
            }
            'admission_reject' {
                Assert-EvidenceCondition (
                    $event.admission_decision -ceq 'rejected' -and
                    @('listener', 'pre_identification', 'pre_auth') -ccontains
                    [string]$event.phase
                ) 'event.admission-reject-shape'
            }
            'admission_penalty' {
                Assert-EvidenceCondition (
                    $event.admission_decision -ceq 'penalized' -and
                    @('listener', 'pre_identification', 'pre_auth') -ccontains
                    [string]$event.phase
                ) 'event.admission-penalty-shape'
            }
            'identification_sent' {
                Assert-EvidenceCondition (
                    @('accepted', 'not_applicable') -ccontains
                    [string]$event.admission_decision -and
                    $event.phase -ceq 'identification'
                ) 'event.identification-shape'
            }
            'kex_started' {
                Assert-EvidenceCondition (
                    @('accepted', 'not_applicable') -ccontains
                    [string]$event.admission_decision -and
                    $event.phase -ceq 'kex'
                ) 'event.kex-shape'
            }
            'connection_closed' {
                Assert-EvidenceCondition (
                    @('not_applicable', 'unknown') -ccontains
                    [string]$event.admission_decision -and
                    $event.phase -ceq 'closed'
                ) 'event.connection-closed-shape'
            }
            'no_matching_event' {
                Assert-EvidenceCondition (
                    $event.admission_decision -ceq 'unknown' -and
                    $event.phase -ceq 'unknown' -and
                    [long]$event.count -eq 1
                ) 'event.no-match-shape'
            }
        }
        [void]$eventCategories.Add([string]$event.category)
    }
    if ($eventCategories.Contains('no_matching_event')) {
        Assert-EvidenceCondition (
            $events.Count -eq 1 -and $eventCategories.Count -eq 1
        ) 'event.no-match-not-exclusive'
    }

    $counters = $evidence.counters
    Assert-ExactProperties $counters @(
        'established_connections',
        'pending_connections',
        'process_fd_used',
        'process_fd_limit',
        'admission_rejections',
        'penalty_drops',
        'firewall_or_ban_decision'
    ) 'counters'
    Assert-IntegerRange $counters.established_connections 0 1000000 'established-connections'
    Assert-IntegerRange $counters.pending_connections 0 1000000 'pending-connections'
    Assert-IntegerRange $counters.process_fd_used 0 2147483647 'process-fd-used'
    Assert-IntegerRange $counters.process_fd_limit 1 2147483647 'process-fd-limit'
    Assert-EvidenceCondition (
        [long]$counters.process_fd_used -le [long]$counters.process_fd_limit
    ) 'process-fd.order'
    Assert-IntegerRange $counters.admission_rejections 0 1000000 'admission-rejections'
    Assert-IntegerRange $counters.penalty_drops 0 1000000 'penalty-drops'
    Assert-EnumValue $counters.firewall_or_ban_decision @(
        'none', 'allow', 'deny', 'rate_limit', 'unknown'
    ) 'firewall-or-ban-decision'
    $admissionRejectEvent = @(
        $events | Where-Object { $_.category -ceq 'admission_reject' }
    ).Count -gt 0
    $admissionPenaltyEvent = @(
        $events | Where-Object { $_.category -ceq 'admission_penalty' }
    ).Count -gt 0
    if ($admissionRejectEvent) {
        Assert-EvidenceCondition (
            [long]$counters.admission_rejections -gt 0
        ) 'counter.admission-reject-event-mismatch'
    }
    if ($admissionPenaltyEvent) {
        Assert-EvidenceCondition (
            [long]$counters.penalty_drops -gt 0
        ) 'counter.admission-penalty-event-mismatch'
    }
    if (@('deny', 'rate_limit') -ccontains [string]$counters.firewall_or_ban_decision) {
        Assert-EvidenceCondition (
            $eventCategories.Contains('firewall_or_ban')
        ) 'counter.firewall-decision-event-mismatch'
    }

    Assert-EnumValue $evidence.classification @(
        'connect_path_failure',
        'unexpected_listener_or_network_path',
        'sshd_pre_auth_admission_control',
        'sshd_pre_identification_stall',
        'non_ssh_or_pre_identification_policy_bytes',
        'ssh_kex_stall_or_failure',
        'undetermined_path_or_listener'
    ) 'classification'
    $zeroDigest = '0' * 64
    if ($evidence.evidence_status -ceq 'server_observation') {
        Assert-EvidenceCondition (
            $correlation.client_record_sha256 -cne $zeroDigest -and
            $correlation.target_binding_sha256 -cne $zeroDigest
        ) 'correlation.placeholder-digest'
    }
    if ($correlation.connection_binding -ceq 'matched_expected_service') {
        Assert-EvidenceCondition (
            $listener.expected_owner -and $listener.service -cne 'unknown'
        ) 'connection-binding.expected-service-owner'
    }
    if ($correlation.connection_binding -ceq 'ambiguous') {
        Assert-EvidenceCondition (
            $evidence.classification -ceq 'undetermined_path_or_listener'
        ) 'classification.ambiguous'
    }
    switch -CaseSensitive ([string]$evidence.classification) {
        'connect_path_failure' {
            Assert-EvidenceCondition (
                $correlation.client_observation -ceq 'tcp_not_connected' -and
                $correlation.connection_binding -ceq 'not_observed' -and
                -not $eventCategories.Contains('listener_accept') -and
                -not $eventCategories.Contains('kex_started')
            ) 'classification.connect-path-coherence'
        }
        'unexpected_listener_or_network_path' {
            Assert-EvidenceCondition (
                @(
                    'tcp_connected_no_ssh_bytes',
                    'client_identification_sent_server_silent',
                    'transport_closed_before_server_identification'
                ) -ccontains [string]$correlation.client_observation -and
                $correlation.connection_binding -ceq 'not_observed'
            ) 'classification.unexpected-path-coherence'
        }
        'sshd_pre_auth_admission_control' {
            Assert-EvidenceCondition (
                @(
                    'client_identification_sent_server_silent',
                    'transport_closed_before_server_identification',
                    'remote_ssh_disconnect_before_host_key'
                ) -ccontains [string]$correlation.client_observation -and
                $correlation.connection_binding -ceq 'matched_expected_service'
            ) 'classification.admission-binding'
            Assert-EvidenceCondition (
                $admissionRejectEvent -or $admissionPenaltyEvent
            ) 'classification.admission-event'
        }
        'sshd_pre_identification_stall' {
            Assert-EvidenceCondition (
                $correlation.client_observation -ceq
                'client_identification_sent_server_silent' -and
                $correlation.connection_binding -ceq 'matched_expected_service' -and
                $eventCategories.Contains('listener_accept') -and
                -not $admissionRejectEvent -and
                -not $admissionPenaltyEvent
            ) 'classification.pre-identification-coherence'
        }
        'non_ssh_or_pre_identification_policy_bytes' {
            Assert-EvidenceCondition (
                $correlation.client_observation -ceq
                'peer_bytes_without_valid_server_identification' -and
                $correlation.connection_binding -ceq 'matched_expected_service' -and
                $eventCategories.Contains('listener_accept')
            ) 'classification.non-ssh-policy-coherence'
        }
        'ssh_kex_stall_or_failure' {
            Assert-EvidenceCondition (
                $correlation.client_observation -ceq
                'ssh_identification_observed_no_host_key' -and
                $correlation.connection_binding -ceq 'matched_expected_service' -and
                $eventCategories.Contains('kex_started')
            ) 'classification.kex-event'
        }
    }

    Assert-NoSensitiveStrings $evidence

    $attributionEligible =
        $evidence.evidence_status -eq 'server_observation' -and
        $correlation.probe_count -eq 1 -and
        $correlation.exclusive_window -and
        $correlation.client_record_bound -and
        $externalBindingVerified -and
        $correlation.connection_binding -ne 'ambiguous' -and
        $evidence.classification -ne 'undetermined_path_or_listener'
    $summary = [ordered]@{
        schema_version = 2
        valid = $true
        evidence_status = $evidence.evidence_status
        attribution_eligible = [bool]$attributionEligible
        contains_sensitive_fields = $false
    }
    Write-Output ($summary | ConvertTo-Json -Compress)
    exit 0
}
catch {
    [Console]::Error.WriteLine(
        'SSH pre-auth server evidence rejected: schema or policy violation; input values withheld.'
    )
    exit 1
}
