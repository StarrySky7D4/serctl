# serctl v1 beta Agent JSONL contract

<!-- target-release: v1.0.0-beta -->

Target release: `v1.0.0-beta` (candidate, not accepted or published)

Agent transfer/tunnel/connection-identity source readiness: `implemented-unreleased`

This contract describes the candidate source tree. The current workspace/release marker remains `v0.3.0-beta.2` until the exact-tag acceptance gates pass. A handler is not a supported capability by itself: an Agent operation is available only when the request handler and the daemon's grantable-operation list both exist, their scope mapping is tested, and the exact tag passes end-to-end acceptance.

## 1. Transport and envelope

`serctl_cli agent (--grant FILE|--grant-handle HANDLE_OR_FD)` reads newline-delimited JSON from stdin and writes newline-delimited JSON to stdout. The two Grant sources are mutually exclusive. `--grant-handle` receives only a non-secret decimal Windows `HANDLE` or Unix fd in argv, takes ownership of that inherited already-open object, reads at most 64 KiB to EOF, and closes it without path resolution or reopening. The caller must not retain a duplicate handle. Each bounded non-blank input line is exactly one request and produces exactly one result line. stdout contains no ANSI control sequences. After removal of the line terminator, request payload is bounded to 1 MiB; the reader's transport bound additionally accommodates one LF byte (a CR in CRLF consumes payload budget). Exceeding the bound fails closed and terminates the gateway instead of attempting to echo or parse an unbounded line.

Every request must contain:

- `schema_version`: integer `1`;
- `request_id`: caller-selected unsigned integer used only to correlate the result;
- `op`: one operation name from the table below.

Request objects reject unknown fields. Unknown operations, missing fields, wrong JSON types and malformed JSON use the invalid-request result. A malformed request cannot supply a trustworthy id and therefore receives `request_id: 0`. A well-formed request with an unsupported schema preserves its request id and does not start a daemon or remote operation.

Invalid JSON/shape failures return only the fixed diagnostic `invalid request (diagnostic detail withheld)`; serde/parser details and the rejected line are never echoed.

Every result has `schema_version: 1`, the result `request_id`, and `ok`. On success, `data` is present while `error_code` and `error` are absent. On failure, `error_code` and a human diagnostic `error` are present while `data` is absent.

## 2. Operations and exact Grant scopes

| Agent `op` | Required OperationGrant scope | Request-specific fields | Notes |
| --- | --- | --- | --- |
| `status` | `daemon.status` | none | Metadata-only daemon/profile status. |
| `exec` | `ssh.exec` | `cmd`; optional `timeout_ms` | stdout/stderr in result data are Base64. This is not a recoverable typed job. |
| `list-dir` | `sftp.list` | `path`; optional `timeout_ms` | Directory listing only. |
| `create-dir` | `sftp.write` | `path`; optional `timeout_ms` | `sftp.write` is create-directory only; it does not authorize upload. |
| `transfer-push` | `transfer.write` | `local`, `remote`; optional `transfer_id`, `backend`, `resume`, `idle_timeout_ms`, `deadline_ms`, `expected_helper_identity` | The caller may predeclare the opaque object id before starting the blocking request. The exact scope is checked before the local source is opened or hashed. Formal native runners obtain the helper identity only from verified downloaded Linux platform provenance. |
| `transfer-pull` | `transfer.read` | `remote`, `local`; optional `transfer_id`, `backend`, `resume`, `idle_timeout_ms`, `deadline_ms`, `expected_helper_identity` | The caller may predeclare the opaque object id before starting the blocking request. The exact scope is checked before remote-path validation, local-target resolution/existence checks, journal access or daemon discovery. Formal native runners obtain the helper identity only from verified downloaded Linux platform provenance. |
| `transfer-status` | `transfer.status` | optional `transfer_id`, `operation_context_id` | The first lookup for one predeclared id may omit context to discover the daemon-generated binding. Every later lookup for that object supplies the returned context. Profile/generation isolation is always enforced. |
| `transfer-cancel` | `transfer.cancel` | `transfer_id`, `operation_context_id` | Both fields are required. Success confirms a revisioned cancellation request for the bound object, not an invented remote cleanup result. |
| `forward-local-open` | `forward.local/open` | `bind_port`, `target_port`, `deadline_unix_ms`; optional `max_connections` | Opens a daemon-owned local forward only after it is ready. The listener and fixed target are both `127.0.0.1`; addresses are not request fields. |
| `forward-remote-open` | `forward.remote/open` | `bind_port`, `target_port`, `deadline_unix_ms`; optional `max_connections` | Opens a daemon-owned remote forward only after it is ready. The SSH-side listener and fixed local target are both `127.0.0.1`. |
| `forward-dynamic-open` | `forward.dynamic/open` | `bind_port`, `deadline_unix_ms`; optional `max_connections` | Opens a daemon-owned loopback SOCKS5 listener. Loopback limits listener exposure, not the destinations requested by a same-host SOCKS client. |
| `forward-status` | `forward.status` | `deadline_unix_ms`; optional `tunnel_id`, `operation_context_id` | A first exact lookup by tunnel id may omit context to discover it; later exact lookups supply it. A no-id compatibility listing is not a formal object receipt. |
| `forward-cancel` | `forward.cancel` | `tunnel_id`, `operation_context_id`, `deadline_unix_ms` | Context is required. Waits for terminal `closed` or `unknown`; uncertain cleanup is never relabelled as closed. |
| `ssh-connection-identity` | `ssh.connection-identity` | none | Returns a closed, read-only projection of an authenticated, host-key-pinned SSH session. It may establish/reuse/reconnect the SSH transport, so it is not an offline metadata query. |

After envelope parsing and the schema-version check, **all 14 operations** perform their exact-scope check as the first operation-specific gate. A missing scope is rejected before command/path/port/deadline validation, local file opening, target resolution/existence checks or hashing, daemon discovery/start, IPC, listener creation, SSH or SFTP. This ordering is a confidentiality and least-authority boundary, not merely a daemon-side authorization optimization; the daemon still repeats authorization against the signed root intent.

`transfer_id` and `tunnel_id` are opaque 32-character lowercase hexadecimal values. A transfer may use a caller-predeclared `transfer_id`; that identifier names the object but grants no authority. For Grant-backed accepted transfers and managed tunnels, the daemon derives an opaque 64-character lowercase hexadecimal `operation_context_id` and owns its positive monotonic `revision`. Object terminal/status snapshots preserve that context; first exact status-by-id discovery may omit it, later exact status and every cancel supply it. Context substitution, rollback, cross-profile/generation reuse and post-restart reuse fail closed. Successful `status`, `ssh-connection-identity`, `exec`, `list-dir` and `create-dir` terminals contain distinct daemon-generated contexts and exactly `revision=1`. `daemon.status` performs no SSH probe, so its HMAC uses an explicit domain-separated no-SSH-transport marker rather than inventing an attempt. Formal acceptance remains blocked by missing exact-tag runtime evidence, not a known local context-schema gap. `sftp.read` and every `job.*` operation remain unavailable.

`transfer-pull` has a closed request schema: `remote` and `local` are required; only `transfer_id`, `backend`, `resume`, `idle_timeout_ms`, `deadline_ms` and `expected_helper_identity` are optional. `transfer-push` uses the same optional helper field. The nested helper record is itself closed and contains exactly `name`, positive integer `binary_size`, lowercase `sha256` and the complete `version` line. A missing target/source, unknown field, nested unknown field, type-confused size, or unknown backend/resume value is an invalid request and cannot be treated as a default or forwarded to the daemon. `backend=native` requires this record; `backend=auto` without it takes the explicit SFTP fallback without starting an unbound helper. Supplying the record with an explicit SFTP backend is rejected.

Grant budget is charged to each authenticated root request. Transfer chunks and acknowledgements are descendants of one `transfer.write` push or `transfer.read` pull root and do not consume independent budget entries. A Grant is bound to its exact profile name/id/generation, holder key, expiry and daemon instance; daemon restart invalidates its in-memory registration. The protected Grant file contains the holder private key. Its serialized profile/scope/budget/expiry metadata is advisory Agent-side fail-fast state, not the authoritative grant registry: the daemon repeats authorization against the signed root intent and its current-instance registry, so file metadata edits cannot expand remote authority.

## 3. Request examples

```json
{"op":"status","schema_version":1,"request_id":1}
{"op":"exec","schema_version":1,"request_id":2,"cmd":"uname -a","timeout_ms":30000}
{"op":"list-dir","schema_version":1,"request_id":3,"path":"/tmp","timeout_ms":30000}
{"op":"create-dir","schema_version":1,"request_id":4,"path":"/tmp/example","timeout_ms":30000}
{"op":"transfer-push","schema_version":1,"request_id":5,"transfer_id":"0123456789abcdef0123456789abcdef","local":"C:\\staging\\archive.tar.zst","remote":"/tmp/archive.tar.zst","backend":"auto","resume":"never","idle_timeout_ms":30000,"deadline_ms":300000}
{"op":"transfer-pull","schema_version":1,"request_id":15,"transfer_id":"fedcba9876543210fedcba9876543210","remote":"/srv/evidence.bin","local":"evidence.bin","backend":"sftp","resume":"never","idle_timeout_ms":30000,"deadline_ms":300000}
{"op":"transfer-status","schema_version":1,"request_id":6}
{"op":"transfer-status","schema_version":1,"request_id":7,"transfer_id":"0123456789abcdef0123456789abcdef"}
{"op":"transfer-status","schema_version":1,"request_id":16,"transfer_id":"0123456789abcdef0123456789abcdef","operation_context_id":"abababababababababababababababababababababababababababababababab"}
{"op":"transfer-cancel","schema_version":1,"request_id":8,"transfer_id":"0123456789abcdef0123456789abcdef","operation_context_id":"abababababababababababababababababababababababababababababababab"}
{"op":"forward-local-open","schema_version":1,"request_id":9,"bind_port":0,"target_port":5432,"max_connections":32,"deadline_unix_ms":1900000000000}
{"op":"forward-remote-open","schema_version":1,"request_id":10,"bind_port":0,"target_port":8080,"max_connections":32,"deadline_unix_ms":1900000000000}
{"op":"forward-dynamic-open","schema_version":1,"request_id":11,"bind_port":0,"max_connections":32,"deadline_unix_ms":1900000000000}
{"op":"forward-status","schema_version":1,"request_id":12,"deadline_unix_ms":1900000000000}
{"op":"forward-cancel","schema_version":1,"request_id":13,"tunnel_id":"fedcba9876543210fedcba9876543210","deadline_unix_ms":1900000000000}
{"op":"ssh-connection-identity","schema_version":1,"request_id":14}
```

## 4. Result examples and stable error codes

```json
{"schema_version":1,"request_id":5,"ok":true,"data":{"transfer_id":"0123456789abcdef0123456789abcdef","operation_context_id":"abababababababababababababababababababababababababababababababab","revision":4,"bytes":21,"backend_requested":"auto","backend":"sftp_fallback","chunk_bytes":2048,"window_bytes":2048}}
{"schema_version":1,"request_id":16,"ok":true,"data":{"transfers":[{"schema_version":1,"event":"completed","transfer_id":"0123456789abcdef0123456789abcdef","operation_context_id":"abababababababababababababababababababababababababababababababab","revision":4,"direction":"push","stage":"completed","total_bytes":21,"confirmed_bytes":21,"durable_bytes":21,"window_bps":0.0,"average_bps":1.0,"eta_ms":null,"backend":"sftp_fallback","chunk_bytes":2048,"window_bytes":2048,"updated_unix_ms":1900000000000}]}}
{"schema_version":1,"request_id":8,"ok":true,"data":{"transfer_id":"0123456789abcdef0123456789abcdef","operation_context_id":"abababababababababababababababababababababababababababababababab","revision":5,"cancel_requested":true}}
{"schema_version":1,"request_id":8,"ok":false,"error_code":"agent.scope_denied","error":"grant does not authorize transfer.cancel"}
{"schema_version":1,"request_id":9,"ok":true,"data":{"tunnel_id":"fedcba9876543210fedcba9876543210","mode":"local","stage":"ready","bind_host":"127.0.0.1","bind_port":15432,"deadline_unix_ms":1900000000000,"operation_context_id":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","revision":1}}
{"schema_version":1,"request_id":2,"ok":true,"data":{"stdout":"","stderr":"","code":0,"operation_context_id":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","revision":1}}
{"schema_version":1,"request_id":3,"ok":true,"data":{"path":"/tmp","entries":[],"operation_context_id":"cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","revision":1}}
{"schema_version":1,"request_id":14,"ok":true,"data":{"profile_id":"00112233445566778899aabbccddeeff","profile_generation":1,"observed_host_key_sha256":"SHA256:47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU","pin_match":true,"server_identification":"SSH-2.0-example","transport_attempt_id":"00112233445566778899AABBCCDDEEFF","operation_context_id":"dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","revision":1}}
```

The v1 beta line reserves these stable machine categories:

| `error_code` | Meaning | Retry rule |
| --- | --- | --- |
| `agent.invalid_request` | JSON, operation, fields or types are invalid. | Correct the request; do not retry unchanged. |
| `agent.schema_unsupported` | `schema_version` is not supported. | Use schema 1 with a matching CLI; never downgrade IPC or bypass the gateway. |
| `agent.scope_denied` | Any of the 14 requests lacks its exact scope. | Obtain a new least-privilege Grant; do not substitute another scope. |
| `agent.operation_failed` | The authorized operation failed for another reason. | Treat mutating timeout/disconnect/unknown outcomes conservatively and inspect status before retrying. |

Automation must branch only on `error_code`, never on `error`. A scope rejection may name only the required public operation kind (`grant does not authorize …`). Every non-scope operation failure is reduced to a fixed operation-level diagnostic ending in `diagnostic detail withheld`; lower anyhow/daemon/SSH/SFTP/parser chains and request values are not relayed. The human diagnostic is not a compatibility surface and may be redacted or reworded. Transfer progress uses the closed event vocabulary `preflight/hash/progress/resumed/stalled/completed/failed/cancelled`; the CLI clears and rejects any other event before CLI, UI, status JSON or Agent output, even when it passes the wire-level length and control-character checks. Exact-tag acceptance must prove that result/error/progress data do not expose the Grant private key, profile or SSH passwords, protected-state paths, local absolute transfer paths, rejected JSON, or lower sensitive error chains.

## 5. Stateful-control and identity safety semantics

`transfer-push` performs the exact-scope check before local file access. `transfer-pull` checks `transfer.read` before validating the remote path, resolving or probing the local target, consulting a resume journal, discovering the daemon or doing remote I/O. It derives a domain-separated SHA-256 local-target commitment from the absolute target bytes plus the Grant profile id/generation; only that commitment enters the authenticated download root, so neither Agent stdout nor daemon IPC receives the raw local target path. The download path retains the existing protected `CREATE_NEW` partial, handle-bound rollback and final local no-overwrite commit: an existing destination fails without overwrite. The same fail-fast ordering applies to every other operation before its operation-specific validation or daemon access. The daemon repeats authorization against the signed root intent. Transfer and tunnel open/status/cancel actions are separately authorized; possession of a read/write/open scope does not grant observation or cancellation. Profile id/generation isolation applies even when a transfer or tunnel id is known.

Progress is cumulative remote-confirmed/durable state, not bytes merely read from the local file or written into IPC. The public event vocabulary is `accepted`, `preflight`, `hash`, `progress`, `resumed`, `stalled`, `completed`, `failed`, `cancelled`; Grant-backed progress/status always carries `operation_context_id` and a positive monotonic `revision`. Final 100% remains reserved for verified and committed completion. Cancellation success means the daemon accepted the cancellation request and returns the same context with a later revision. Where daemon restart, disconnect, SSH/helper or commit state is uncertain, the result must remain explicit unknown/a new context transition rather than impersonating the old operation or claiming success, deletion or rollback.

Agent operations are request/result NDJSON, not an interleaved progress stream. Push and pull retain terminal-only stdout and return `transfer_id`, `operation_context_id` and `revision` in their success terminal. A controller may generate the transfer id first, start the blocking push/pull, then use a separate `transfer-status` Agent request authorized with `transfer.status`. Its first lookup for that exact id may omit context to discover the daemon-generated binding; all subsequent status requests use that context, and cancel always requires it. The current external runtime adapter validates synthetic terminal/status context and revision consistency but has not wired this concurrent supervisor/Grant path, so these source and parser checks do not close real-time progress, Linux, macOS, real-host, native-helper or release acceptance.

A managed tunnel is registered only after ready, then remains daemon-owned. Its context binds daemon instance, Grant/request, profile generation, root commitment, actual authenticated transport attempt, tunnel id and action. Stage changes advance revision. A first exact status may discover context; later status and every cancel require it. Fixed listeners/targets remain loopback-only, results omit profile identity and remote addresses, and uncertain cleanup returns `unknown`. Exact-tag OpenSSH/Dropbear L/R/D evidence is still required.

`ssh-connection-identity` succeeds only for an authenticated session whose observed host key passed the stored pin. Its result contains exactly `profile_id`, `profile_generation`, `observed_host_key_sha256`, `pin_match` (which must be true), a bounded sanitized `server_identification`, an opaque uppercase 32-hex `transport_attempt_id`, a daemon-generated lowercase 64-hex `operation_context_id`, and exactly `revision=1`. Successful `exec` and `list-dir` terminals add the same two context fields to their otherwise closed projections. These one-shot contexts bind the daemon instance, Grant/profile generation, root intent and authenticated transport attempt without exposing them; they are not caller-selected and cannot be replaced by a context from another accepted root. Identity still omits host/port, username, paths, pre-banner/raw banner bytes and credentials. Failure before authentication, missing/mismatched pin, unsafe identification text or profile-generation mismatch returns no partial identity. Local protocol/mock coverage does not establish real OpenSSH/Dropbear interoperability.

## 6. IPC and typed-job boundary

The v1 candidate CLI/daemon wire is IPC v9 only. A v0.3 IPC v8 descriptor or mixed binary set fails closed before a business frame; there is no direct-connect or old-wire fallback.

`serctl-remote`, jobs, their protocol crates and the policy crate are source-only experimental foundations with known security blockers. They remain in workspace check/test/strict-Clippy and applicable build.rs fixture coverage, but v1 beta does not build or publish a distributable helper/package and provides no runtime support. They are not part of this Agent schema, every `job.*` Grant kind remains unsupported, and ordinary `exec` is not recoverable. Accidental appearance of an experimental remote/job/policy component in release staging, symbols, manifests or SBOMs is a release failure, not evidence that the feature became available.

## 7. Acceptance rule

`scripts/Test-V1BetaDocumentation.ps1` compares this document with the Agent request enum, stable error-code literals, IPC v9 constant and daemon grantable-operation list. That static check detects contract drift; it does not replace compilation, security tests, daemon lifecycle E2E, cross-platform CI, real-host transfer tests or the exact-tag release record in [the acceptance matrix](v1-beta-acceptance-matrix.md).
