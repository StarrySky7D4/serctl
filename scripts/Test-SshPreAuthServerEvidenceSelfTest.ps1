[CmdletBinding()]
param()

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'StrictJson.ps1')

function Assert-SelfTest {
    param([bool]$Condition, [string]$Message)

    if (-not $Condition) {
        throw "SSH pre-auth evidence self-test failed: $Message"
    }
}

function Copy-JsonObject {
    param([object]$Value)

    $parameters = @{}
    if ((Get-Command ConvertFrom-Json).Parameters.ContainsKey('DateKind')) {
        $parameters['DateKind'] = 'String'
    }
    return (ConvertFrom-Json -InputObject ($Value | ConvertTo-Json -Depth 30) @parameters)
}

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$verifier = Join-Path $PSScriptRoot 'Test-SshPreAuthServerEvidence.ps1'
$templatePath = Join-Path $repositoryRoot 'docs/ssh-preauth-server-evidence.template.json'
$engine = (Get-Process -Id $PID).Path
$temporaryBase = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$temporaryRoot = Join-Path $temporaryBase (
    'serctl-ssh-preauth-evidence-selftest-' + [Guid]::NewGuid().ToString('N')
)
[void](New-Item -ItemType Directory -Path $temporaryRoot -ErrorAction Stop)

function Write-Fixture {
    param([object]$Value, [string]$Name)

    $path = Join-Path $temporaryRoot $Name
    $json = $Value | ConvertTo-Json -Depth 30
    [IO.File]::WriteAllText($path, $json, [Text.UTF8Encoding]::new($false))
    return $path
}

function Invoke-Fixture {
    param(
        [string]$FixturePath,
        [object]$ExpectedBinding
    )

    $previousErrorAction = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $arguments = @('-NoProfile', '-NonInteractive', '-File', $verifier, '-Path', $FixturePath)
        if ($null -ne $ExpectedBinding) {
            $arguments += @(
                '-ExpectedCorrelationId',
                [string]$ExpectedBinding.correlation.correlation_id,
                '-ExpectedProbeId',
                [string]$ExpectedBinding.correlation.probe_id,
                '-ExpectedClientRecordSha256',
                [string]$ExpectedBinding.correlation.client_record_sha256,
                '-ExpectedTargetBindingSha256',
                [string]$ExpectedBinding.correlation.target_binding_sha256,
                '-ExpectedConfiguredPort',
                [string]$ExpectedBinding.correlation.configured_port
            )
        }
        $output = @(& $engine @arguments 2>&1)
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorAction
    }
    return [pscustomobject]@{
        ExitCode = $exitCode
        Output = ($output | Out-String).Trim()
    }
}

try {
    $template = ConvertFrom-StrictJson `
        -Json (Read-StrictUtf8Text -Path $templatePath) `
        -Label 'SSH pre-auth evidence self-test template'
    $templateResult = Invoke-Fixture $templatePath
    Assert-SelfTest ($templateResult.ExitCode -eq 0) 'valid template was rejected'
    $templateSummary = $templateResult.Output | ConvertFrom-Json
    Assert-SelfTest $templateSummary.valid 'template did not validate structurally'
    Assert-SelfTest (-not $templateSummary.attribution_eligible) (
        'template was incorrectly treated as attributable server evidence'
    )

    $observation = Copy-JsonObject $template
    $observation.evidence_status = 'server_observation'
    $observation.correlation.correlation_id = '12345678-1234-4abc-8def-1234567890ab'
    $observation.correlation.probe_id = '87654321-4321-4cba-9fed-ba0987654321'
    $observation.correlation.client_record_sha256 = '1' * 64
    $observation.correlation.target_binding_sha256 = '2' * 64
    $observation.correlation.exclusive_window = $true
    $observation.correlation.client_record_bound = $true
    $observation.correlation.connection_binding = 'matched_expected_service'
    $observation.listener.expected_owner = $true
    $observation.listener.service = 'openssh_sshd'
    $observation.sshd_admission.per_source_penalties_supported = $true
    $observation.sshd_admission.per_source_penalties_enabled = $true
    $observation.events = @(
        [pscustomobject]@{
            relative_ms = 12
            category = 'listener_accept'
            admission_decision = 'accepted'
            phase = 'listener'
            count = 1
        },
        [pscustomobject]@{
            relative_ms = 14
            category = 'admission_penalty'
            admission_decision = 'penalized'
            phase = 'pre_identification'
            count = 1
        }
    )
    $observation.counters.admission_rejections = 1
    $observation.counters.penalty_drops = 1
    $observation.classification = 'sshd_pre_auth_admission_control'
    $observationPath = Write-Fixture $observation 'valid-observation.json'
    $observationResult = Invoke-Fixture $observationPath
    Assert-SelfTest ($observationResult.ExitCode -eq 0) 'valid observation was rejected'
    $observationSummary = $observationResult.Output | ConvertFrom-Json
    Assert-SelfTest (-not $observationSummary.attribution_eligible) (
        'observation without an independently supplied client binding was marked eligible'
    )
    $boundObservationResult = Invoke-Fixture $observationPath $observation
    Assert-SelfTest ($boundObservationResult.ExitCode -eq 0) (
        'valid observation with exact external client binding was rejected'
    )
    $boundObservationSummary = $boundObservationResult.Output | ConvertFrom-Json
    Assert-SelfTest $boundObservationSummary.attribution_eligible (
        'fully correlated synthetic observation was not marked eligible'
    )

    $wrongExternalProbe = Copy-JsonObject $observation
    $wrongExternalProbe.correlation.probe_id = 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa'
    $wrongExternalProbeResult = Invoke-Fixture $observationPath $wrongExternalProbe
    Assert-SelfTest ($wrongExternalProbeResult.ExitCode -ne 0) (
        'evidence accepted an external binding for a different client probe'
    )

    $forbiddenCases = @(
        @{
            Name = 'username'
            Marker = 'SENSITIVE_USER_MARKER'
            Mutate = { param($value) $value | Add-Member username 'SENSITIVE_USER_MARKER' }
        },
        @{
            Name = 'ip'
            Marker = 'policy from 192.0.2.44'
            Mutate = { param($value) $value.listener.service = 'policy from 192.0.2.44' }
        },
        @{
            Name = 'banner'
            Marker = 'SSH-2.0-SENSITIVE_BANNER'
            Mutate = { param($value) $value.listener.service = 'SSH-2.0-SENSITIVE_BANNER' }
        },
        @{
            Name = 'path'
            Marker = '/sensitive/banner/path'
            Mutate = { param($value) $value | Add-Member banner_path '/sensitive/banner/path' }
        },
        @{
            Name = 'fingerprint'
            Marker = 'SHA256:SENSITIVE_FINGERPRINT'
            Mutate = { param($value) $value | Add-Member fingerprint 'SHA256:SENSITIVE_FINGERPRINT' }
        },
        @{
            Name = 'raw-message'
            Marker = 'SENSITIVE_RAW_MESSAGE'
            Mutate = {
                param($value)
                @($value.events)[0] | Add-Member raw_message 'SENSITIVE_RAW_MESSAGE'
            }
        },
        @{
            Name = 'payload'
            Marker = 'SENSITIVE_PAYLOAD'
            Mutate = {
                param($value)
                @($value.events)[0] | Add-Member payload 'SENSITIVE_PAYLOAD'
            }
        }
    )
    foreach ($case in $forbiddenCases) {
        $invalid = Copy-JsonObject $observation
        & $case.Mutate $invalid
        $invalidPath = Write-Fixture $invalid ("invalid-$($case.Name).json")
        $result = Invoke-Fixture $invalidPath
        Assert-SelfTest ($result.ExitCode -ne 0) "$($case.Name) was accepted"
        Assert-SelfTest (-not $result.Output.Contains([string]$case.Marker)) (
            "$($case.Name) rejected value leaked through verifier output"
        )
    }

    $ambiguous = Copy-JsonObject $observation
    $ambiguous.correlation.connection_binding = 'ambiguous'
    $ambiguous.classification = 'sshd_pre_auth_admission_control'
    $ambiguousResult = Invoke-Fixture (Write-Fixture $ambiguous 'invalid-ambiguous.json')
    Assert-SelfTest ($ambiguousResult.ExitCode -ne 0) (
        'ambiguous server window accepted an attributable classification'
    )

    $multipleProbes = Copy-JsonObject $observation
    $multipleProbes.correlation.probe_count = 2
    $multipleResult = Invoke-Fixture (Write-Fixture $multipleProbes 'invalid-multiple-probes.json')
    Assert-SelfTest ($multipleResult.ExitCode -ne 0) 'multiple probes were accepted'

    $wrongPort = Copy-JsonObject $observation
    $wrongPort.correlation.configured_port = 2222
    $wrongPortResult = Invoke-Fixture (Write-Fixture $wrongPort 'invalid-target-port.json')
    Assert-SelfTest ($wrongPortResult.ExitCode -ne 0) (
        'client target port did not bind listener and sshd admission ports'
    )

    $wrongProbeWindow = Copy-JsonObject $observation
    $wrongProbeWindow.correlation.probe_start_utc = '2026-01-01T00:00:06.000Z'
    $wrongProbeWindow.correlation.probe_end_utc = '2026-01-01T00:00:07.000Z'
    $wrongProbeWindowResult = Invoke-Fixture (
        Write-Fixture $wrongProbeWindow 'invalid-probe-window.json'
    )
    Assert-SelfTest ($wrongProbeWindowResult.ExitCode -ne 0) (
        'server evidence window accepted a non-overlapping client probe'
    )

    $uncoveredClockSkew = Copy-JsonObject $observation
    $uncoveredClockSkew.correlation.clock_uncertainty_ms = 5000
    $uncoveredClockSkewResult = Invoke-Fixture (
        Write-Fixture $uncoveredClockSkew 'invalid-clock-uncertainty.json'
    )
    Assert-SelfTest ($uncoveredClockSkewResult.ExitCode -ne 0) (
        'server evidence window failed to cover declared clock uncertainty'
    )

    $placeholderDigest = Copy-JsonObject $observation
    $placeholderDigest.correlation.client_record_sha256 = '0' * 64
    $placeholderDigestResult = Invoke-Fixture (
        Write-Fixture $placeholderDigest 'invalid-placeholder-client-digest.json'
    )
    Assert-SelfTest ($placeholderDigestResult.ExitCode -ne 0) (
        'attributable observation accepted a placeholder client record digest'
    )

    $wrongClientObservation = Copy-JsonObject $observation
    $wrongClientObservation.correlation.client_observation =
        'ssh_identification_observed_no_host_key'
    $wrongClientObservationResult = Invoke-Fixture (
        Write-Fixture $wrongClientObservation 'invalid-client-observation.json'
    )
    Assert-SelfTest ($wrongClientObservationResult.ExitCode -ne 0) (
        'admission classification accepted an incompatible client observation'
    )

    $unknownMatchedService = Copy-JsonObject $observation
    $unknownMatchedService.listener.expected_owner = $false
    $unknownMatchedService.listener.service = 'unknown'
    $unknownMatchedServiceResult = Invoke-Fixture (
        Write-Fixture $unknownMatchedService 'invalid-matched-unknown-service.json'
    )
    Assert-SelfTest ($unknownMatchedServiceResult.ExitCode -ne 0) (
        'matched expected service accepted an unknown/unowned listener'
    )

    $wrongAdmissionShape = Copy-JsonObject $observation
    @($wrongAdmissionShape.events)[1].admission_decision = 'accepted'
    $wrongAdmissionShapeResult = Invoke-Fixture (
        Write-Fixture $wrongAdmissionShape 'invalid-admission-event-shape.json'
    )
    Assert-SelfTest ($wrongAdmissionShapeResult.ExitCode -ne 0) (
        'admission penalty event accepted an incompatible decision'
    )

    $unorderedEvents = Copy-JsonObject $observation
    @($unorderedEvents.events)[0].relative_ms = 15
    @($unorderedEvents.events)[1].relative_ms = 14
    $unorderedEventsResult = Invoke-Fixture (
        Write-Fixture $unorderedEvents 'invalid-event-order.json'
    )
    Assert-SelfTest ($unorderedEventsResult.ExitCode -ne 0) (
        'out-of-order server events were accepted'
    )

    $mixedNoMatch = Copy-JsonObject $observation
    $mixedNoMatch.events += [pscustomobject]@{
        relative_ms = 15
        category = 'no_matching_event'
        admission_decision = 'unknown'
        phase = 'unknown'
        count = 1
    }
    $mixedNoMatchResult = Invoke-Fixture (
        Write-Fixture $mixedNoMatch 'invalid-no-match-mixed-events.json'
    )
    Assert-SelfTest ($mixedNoMatchResult.ExitCode -ne 0) (
        'no_matching_event was accepted alongside positive events'
    )

    $scalarEvents = Copy-JsonObject $observation
    $scalarEvents.events = @($scalarEvents.events)[0]
    $scalarEventsResult = Invoke-Fixture (
        Write-Fixture $scalarEvents 'invalid-scalar-events.json'
    )
    Assert-SelfTest ($scalarEventsResult.ExitCode -ne 0) 'scalar events value was accepted'

    $duplicateKeyPath = Join-Path $temporaryRoot 'invalid-duplicate-key.json'
    $duplicateKeyJson = (Read-StrictUtf8Text -Path $templatePath).Replace(
        '"schema_version": 2',
        '"schema_version": 2, "schema_version": 2'
    )
    [IO.File]::WriteAllText(
        $duplicateKeyPath,
        $duplicateKeyJson,
        [Text.UTF8Encoding]::new($false)
    )
    $duplicateKeyResult = Invoke-Fixture $duplicateKeyPath
    Assert-SelfTest ($duplicateKeyResult.ExitCode -ne 0) 'duplicate JSON key was accepted'

    $caseCollisionPath = Join-Path $temporaryRoot 'invalid-case-collision.json'
    $caseCollisionJson = (Read-StrictUtf8Text -Path $templatePath).Replace(
        '"schema_version": 2',
        '"schema_version": 2, "Schema_Version": 2'
    )
    [IO.File]::WriteAllText(
        $caseCollisionPath,
        $caseCollisionJson,
        [Text.UTF8Encoding]::new($false)
    )
    $caseCollisionResult = Invoke-Fixture $caseCollisionPath
    Assert-SelfTest ($caseCollisionResult.ExitCode -ne 0) 'case-colliding JSON key was accepted'

    $invalidAdmissionBinding = Copy-JsonObject $observation
    $invalidAdmissionBinding.correlation.connection_binding = 'not_observed'
    $invalidAdmissionBindingResult = Invoke-Fixture (
        Write-Fixture $invalidAdmissionBinding 'invalid-admission-binding.json'
    )
    Assert-SelfTest ($invalidAdmissionBindingResult.ExitCode -ne 0) (
        'admission classification without expected-service binding was accepted'
    )

    $invalidPreIdentification = Copy-JsonObject $observation
    $invalidPreIdentification.classification = 'sshd_pre_identification_stall'
    $invalidPreIdentification.listener.expected_owner = $false
    $invalidPreIdentificationResult = Invoke-Fixture (
        Write-Fixture $invalidPreIdentification 'invalid-pre-identification-owner.json'
    )
    Assert-SelfTest ($invalidPreIdentificationResult.ExitCode -ne 0) (
        'pre-identification classification without expected listener owner was accepted'
    )

    $invalidKex = Copy-JsonObject $observation
    $invalidKex.classification = 'ssh_kex_stall_or_failure'
    $invalidKexResult = Invoke-Fixture (Write-Fixture $invalidKex 'invalid-kex-event.json')
    Assert-SelfTest ($invalidKexResult.ExitCode -ne 0) (
        'KEX classification without kex_started event was accepted'
    )

    $validKex = Copy-JsonObject $observation
    $validKex.correlation.client_observation = 'ssh_identification_observed_no_host_key'
    $validKex.events = @(
        [pscustomobject]@{
            relative_ms = 10
            category = 'listener_accept'
            admission_decision = 'accepted'
            phase = 'listener'
            count = 1
        },
        [pscustomobject]@{
            relative_ms = 12
            category = 'identification_sent'
            admission_decision = 'not_applicable'
            phase = 'identification'
            count = 1
        },
        [pscustomobject]@{
            relative_ms = 14
            category = 'kex_started'
            admission_decision = 'not_applicable'
            phase = 'kex'
            count = 1
        }
    )
    $validKex.counters.admission_rejections = 0
    $validKex.counters.penalty_drops = 0
    $validKex.classification = 'ssh_kex_stall_or_failure'
    $validKexResult = Invoke-Fixture (Write-Fixture $validKex 'valid-kex.json') $validKex
    Assert-SelfTest ($validKexResult.ExitCode -eq 0) 'coherent KEX observation was rejected'
    $validKexSummary = $validKexResult.Output | ConvertFrom-Json
    Assert-SelfTest $validKexSummary.attribution_eligible (
        'coherent KEX observation was not marked attribution eligible'
    )

    Write-Host (
        'SSH pre-auth server evidence self-tests passed; fixtures are synthetic and ' +
        'do not constitute server, network, OpenSSH, Dropbear, or release evidence.'
    )
}
finally {
    $resolvedTemporary = [IO.Path]::GetFullPath($temporaryRoot)
    if ($resolvedTemporary.StartsWith(
        $temporaryBase,
        [StringComparison]::OrdinalIgnoreCase
    )) {
        Remove-Item -LiteralPath $resolvedTemporary -Recurse -Force -ErrorAction SilentlyContinue
    }
}
