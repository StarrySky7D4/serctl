# SSH pre-authentication diagnosis

This runbook applies when serctl reports a failure before password authentication. It is a diagnostic boundary, not authority to retry, read credentials, bypass the broker, or run a direct SSH client.

## What the client record proves

The attempt record is deliberately limited to bounded phase labels, byte counters, cleanup flags/timings, and a sanitized SSH disconnect reason code. It never retains a peer address, identification/banner text, host key, fingerprint, username, or credential:

- `tcp_connected=false` means no resolved endpoint completed TCP connect.
- `client_identification_sent_server_silent` means TCP connected, `tx_bytes>0`, `rx_bytes=0`, no valid server identification was observed, and there is no pre-cleanup EOF/terminal-close evidence. The byte count means one or more client writes were accepted by the local OS socket; it is not proof that the full client identification was written or that the peer received it.
- `peer_eof_before_local_shutdown=true` means the peer-side transport closed before serctl began local cleanup.
- `rx_bytes>0` with no valid identification means some peer bytes arrived, but they did not form a valid SSH identification line. Their contents are not retained.
- `server_identification_observed=true`, `host_key_observed=false` means the bounded tracker saw a valid CRLF-terminated SSH-2.0/1.99 identification, without retaining its text; only then may the failure be described as reaching key exchange.
- `host_key_observed=true` means the host-key callback was reached. It does not mean the pin was accepted, TOFU persistence succeeded, or authentication began, and no key or fingerprint is included in the record.
- `peer_disconnect_reason` contains only a bounded protocol reason category. The remote description and language strings are discarded.
- `remote_ssh_disconnect_before_host_key` means a valid SSH identification was observed and russh parsed a standard `SSH_MSG_DISCONNECT` before the host-key callback. This is distinct from a silent TCP peer or unauthenticated plaintext policy text: the diagnostic retains only the protocol reason enum, never the remote description or language. An explicit protocol disconnect is terminal for that request and does not authorize the single silent-transport reconnect.

`tx_bytes` is neither a semantic SSH-stage marker nor a delivery receipt from sshd. A silent post-connect record cannot by itself distinguish sshd admission control, an accept backlog, a transparent proxy, a non-SSH listener, host pressure, firewall tarpit behavior, or packet loss. It is therefore incorrect to call this an algorithm-negotiation or KEX failure when no valid server identification was observed; serctl labels that deadline as the `SSH server identification phase`.

### Existing single-reconnect boundary

The existing client policy may make at most one pre-authentication reconnect; this is transport recovery, not server attribution. A first-attempt `transport_closed_before_server_identification` is eligible when the TCP connection received zero peer bytes, observed neither a server identification nor a host key or parsed `SSH_MSG_DISCONNECT`, the peer EOF preceded local shutdown, transport shutdown and stream release both completed, and enough of the caller's original absolute deadline remains. The client's 22-byte identification write does not change that decision because `tx_bytes` proves neither peer receipt nor any server-side SSH progress. A silent local deadline without peer EOF is eligible only through the separately pre-reserved normal retry window; the clean early-EOF path may reuse the bounded remainder of the same original deadline. Neither path mints a new deadline or permits more than two total attempts.

Any received peer byte, including unauthenticated plaintext policy text or an invalid identification, suppresses the reconnect. So do a parsed standard `SSH_MSG_DISCONNECT`, any host-key observation, a local policy/protocol rejection, incomplete shutdown or stream release, and insufficient remaining budget. A valid server identification necessarily moves the diagnostic to the key-exchange phase and is not the zero-byte early-EOF case.

If the second attempt also fails, the combined diagnostic must preserve `first_failure` and `first_attempt=[SSH attempt 1: ...]` from the first record, and `second_failure` and `second_attempt=[SSH attempt 2: ...]` from the second record. The top-level phase is derived from the second attempt. Reconnect must not overwrite, renumber, or relabel the first observation.

## Evidence required before another candidate or retry-policy change

An authorized server operator should collect a bounded, read-only evidence window synchronized with exactly one later probe. Do not include usernames, passwords, host keys, fingerprints, banners, peer IP addresses, command payloads, or packet payloads in the retained report.

1. Before the probe, record separate random correlation and probe UUIDs in the sanitized client record. Record its canonical SHA-256 and an opaque target-binding SHA-256 produced for that exact profile generation/target without retaining the host or address in this report. The acceptance owner must carry those two digests, the configured port and both UUIDs independently of the server evidence file.
2. Record client probe start/end UTC, the server-clock offset (`server UTC - client UTC`) and a bounded measurement uncertainty. The server evidence window must enclose the entire offset-adjusted client interval plus that uncertainty; a merely overlapping window is insufficient.
3. Confirm which process and socket own the configured SSH port on the server. Record only service name, protocol, port, and whether the expected sshd process owns the listener.
4. Query effective sshd configuration and retain only these normalized fields: `MaxStartups`, `PerSourceMaxStartups`, `PerSourcePenalties`, `LoginGraceTime`, `MaxSessions`, `Port`, `AddressFamily`, `LogLevel`, plus booleans stating whether a non-default listen address or banner is configured. Retain never the configured listen address, banner path, banner content, conditional `Match` selectors, or other configuration.
5. Read the ssh service journal for the bounded window. Reduce each matching event to timestamp, service unit, event category, admission decision, and connection lifecycle phase. Redact identities, addresses and remote-controlled text.
6. If the journal is insufficient, capture metadata-only TCP events for the configured port: SYN/SYN-ACK/ACK, payload length, FIN/RST, retransmission and relative timing. Never capture or retain payload bytes. Replace endpoints with stable per-run labels before attaching evidence.
7. Record server resource/admission counters for the same window: established and pending connections on the port, process/file-descriptor pressure, and any firewall/ban decision category. Do not export unrelated rules or addresses.
8. Correlate the server window with serctl attempt 1 and attempt 2. A result is attributable only if the server observed the same connection and the evidence fields match the independently retained client binding; otherwise it remains `undetermined_path_or_listener`.

### Bounded evidence record

Use [the server evidence template](ssh-preauth-server-evidence.template.json) for the reduced record, then validate the completed copy offline:

```powershell
pwsh -NoProfile -File scripts/Test-SshPreAuthServerEvidence.ps1 -Path C:\outside-repo\ssh-preauth-evidence.json
```

That command validates structure only and therefore reports
`attribution_eligible=false`, even for a coherent `server_observation`. For the
formal binding check, supply all five independently retained client values;
supplying only a subset fails closed:

```powershell
pwsh -NoProfile -File scripts/Test-SshPreAuthServerEvidence.ps1 `
  -Path C:\outside-repo\ssh-preauth-evidence.json `
  -ExpectedCorrelationId 12345678-1234-4abc-8def-1234567890ab `
  -ExpectedProbeId 87654321-4321-4cba-9fed-ba0987654321 `
  -ExpectedClientRecordSha256 1111111111111111111111111111111111111111111111111111111111111111 `
  -ExpectedTargetBindingSha256 2222222222222222222222222222222222222222222222222222222222222222 `
  -ExpectedConfiguredPort 22
```

The verifier accepts only schema v2: independent correlation/probe UUIDs; canonical client-record and opaque target-binding SHA-256 values; configured port; bounded client observation/attempt count; client and server UTC windows with signed clock offset and uncertainty; one-probe binding booleans; listener-owner/service/protocol/port; normalized admission settings; typed, time-ordered event categories and counters; and one decision-table classification. The configured, listener and effective-sshd ports must match. `events` must remain a JSON array, `no_matching_event` must be exclusive, and event decision/phase plus admission/firewall counters must be coherent. Duplicate or case-colliding keys and unrecognized fields fail closed. Strings containing usernames, IP addresses, SSH identification text, paths, fingerprints, raw messages or payloads are rejected, and rejected values are never echoed.

`evidence_status=template` is structurally testable but never attribution eligible. Placeholder digests are allowed only in that template. A `server_observation` becomes eligible only when all five external client-binding arguments match exactly, its adjusted probe window is fully covered, and the record describes an exclusive, client-record-bound, exactly-one-probe window with a non-ambiguous expected-service binding and classification-specific client/server observations. A matching-service claim additionally requires a known, expected listener owner. Admission control requires a compatible silent/closed/disconnect client observation plus a shaped rejection/penalty event and counter; a pre-identification stall requires client silence, an accepted listener event and no rejection/penalty; invalid identification and KEX classifications must match their respective client observation and server phase. Run the offline cross-engine fixture checks with:

```powershell
pwsh -NoProfile -File scripts/Test-SshPreAuthServerEvidenceSelfTest.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File scripts/Test-SshPreAuthServerEvidenceSelfTest.ps1
```

The template and self-test use synthetic data. They are not server, network, OpenSSH, Dropbear, exact-tag or release evidence; a server operator must still collect and bind the real observation.

## Decision table

| Client observation | Server evidence | Classification | Allowed product response |
| --- | --- | --- | --- |
| no TCP connect | no accepted connection | `connect_path_failure` | report; no pre-auth retry beyond the existing bounded policy |
| TCP connect, no peer bytes | connection not observed by expected sshd | `unexpected_listener_or_network_path` | correct routing/listener; do not change KEX algorithms |
| TCP connect, no peer bytes | sshd admission rejection/penalty recorded | `sshd_pre_auth_admission_control` | correct server policy/load; do not add client retries |
| TCP connect, no peer bytes | expected sshd accepts, then remains silent | `sshd_pre_identification_stall` | investigate server resources/version; keep client fail-closed |
| peer bytes, invalid identification | server or intermediary emits policy/non-SSH text | `non_ssh_or_pre_identification_policy_bytes` | correct endpoint/policy; never log the text |
| valid identification, no host key | sshd reaches KEX | `ssh_kex_stall_or_failure` | only here investigate negotiated algorithms and KEX framing |
| server window cannot bind the connection | incomplete or ambiguous | `undetermined_path_or_listener` | no new candidate and no retry/deadline expansion |

## Acceptance boundary

A local raw-peer test, template verification or verifier self-test proves only its local classification/redaction/schema behavior. It cannot close a real OpenSSH/Dropbear or network-path gate. A failed candidate stays failed; correcting diagnostic wording does not turn its remote result into a pass. Any later real-host evidence must be attached to the exact clean tag commit and matching CLI/daemon/helper set.

The deterministic core regressions include a silent peer, peer close before identification, non-SSH policy text, valid identification followed by a stall/close, complete-cleanup and retry-budget gates, two-attempt label preservation, and a wire-level `SSH_MSG_DISCONNECT` whose untrusted description must be redacted and must not trigger reconnect. The raw close-then-silence regression specifically requires attempt 1 to remain `transport_closed_before_server_identification` and attempt 2 to remain `client_identification_sent_server_silent`. These tests distinguish client-side classifications; they do not attribute a real server's admission decision without the synchronized evidence above.
