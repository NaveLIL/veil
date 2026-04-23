# Roadmap & engineering notes (post Phase-4A hardening sprint)

> Last updated: 2026-04-22. Tracks what's done in the security/observability
> sprint and what's queued next. Memory snapshots live under
> `/memories/repo/` (deploy-vps, observability, http-middleware-gotchas,
> phase4a-groups, tauri-ui-notes).

## Recently shipped

### W7 — Fail-closed WebSocket Origin allow-list (2026-04-23)
- `gateway.ConfigureFromEnv` now returns an error when `VEIL_WS_ORIGINS`
  is unset; `cmd/gateway` fails fast on startup. Empty allow-list rejects
  every browser request (native clients with no `Origin` are still
  allowed — Tauri/mobile path is unaffected). Explicit `*` keeps legacy
  permissive behaviour and emits a warning log. New tests:
  `TestWS_OriginAllowList_FailClosed`,
  `TestWS_ConfigureFromEnv_RequiresOrigins`. Commit `da334ab`.
- VPS deploy still pending — needs `VEIL_WS_ORIGINS` set in compose env
  before the next gateway rebuild (currently unreachable).

### W3 — Deleted `allowUnsigned` legacy bypass (2026-04-23)
- `authmw.New()` lost the bool parameter; the `if m.allowUnsigned &&
  X-User-ID != ""` branch is gone. Every REST handler now requires the
  `X-Veil-{User,Timestamp,Signature}` triplet. Updated `cmd/{auth,chat,
  gateway}` constructors and tests.
- Migrated 4 group REST commands in `veil-desktop/src-tauri/src/lib.rs`
  (`create_group`, `add_group_member`, `remove_group_member`,
  `get_group_members`) to the signing-aware `rest_send_json` helper.
  `rest_send_json` no longer falls back to unsigned when local identity
  is missing — surfaces a clear error instead.
- New invariant test `internal/authmw/lint_test.go` walks
  `internal/{auth,chat,servers}` and fails CI when any file reads
  `r.Header.Get("X-User-ID")` without the package also wrapping a route
  in `mw.RequireSigned(...)`. Locks in the contract for future handlers.
- Replaced `LegacyAllowedWhenConfigured`/`LegacyBlockedWhenStrict` with
  `TestRequireSigned_RejectsBareXUserID` asserting unconditional reject.
  Commit `9413892`.

### W2 — Integration test harness for chat/servers (in progress, 2026-04-23)
- Added `internal/integration/` package guarded by the `integration`
  build tag. `harness.New(t)` spins up a Postgres container via
  testcontainers-go, applies every SQL file under `migrations/` in
  lexicographic order, mounts the production REST mux (auth + chat +
  servers all gated by the real `authmw` middleware), and exposes
  `CreateUser` / `Do` (signed) / `DoUnsigned` helpers.
- Initial test suite: 6 tests in `servers_integration_test.go`
  (`CreateAndGet`, `RejectsUnsigned`, `NonOwnerCannotDelete`,
  `ListIncludesNew`, `Channels_CreateAndList`, `InvitePreviewIsPublic`)
  and 6 tests in `chat_integration_test.go` (`CreateDMHappyPath`,
  `GetMessagesForbiddenForNonMember`, `GetMessagesEmptyForNew`,
  `CreateGroupAndAddMember`, `RejectsUnsigned`,
  `AddGroupMember_NonMemberCannotAdd`).
- Run with `go test -tags=integration ./internal/integration/...`
  (requires a running Docker daemon). Tests are excluded from the
  default `go test ./...` so unit tests still run without Docker.
- TODO before marking W2 complete: add coverage for the rest of the
  servers surface (roles, invites use, channel reorder, member kick),
  reach the ROADMAP's ≥80% target, wire `-tags=integration` into CI.

## Recently shipped

### Security / signed REST
- Ed25519 request signing across `auth/`, `chat/`, `servers/` handlers via
  shared `internal/authmw` package.
- Replay-nonce cache (in-memory, GC swept).
- Per-user (or per-IP fallback) token-bucket rate limit (240/min).
- Body size cap (4 MiB → 413) — also applied on the `allowUnsigned=true`
  legacy bypass path so it can't be weaponised as a DoS vector.
- Migration mode: `allowUnsigned=true` keeps old clients working until UI
  rollout is verified end-to-end. Flip to `false` is a 1-line change in
  each `cmd/*/main.go`.

### Observability (`internal/httpmw`, `internal/metrics`)
- Structured slog access log with method, path, status, bytes, duration,
  user, ip — emitted as JSON in production via
  `slog.SetDefault(slog.NewJSONHandler(...))`.
- Security headers: `X-Content-Type-Options`, `X-Frame-Options`,
  `Referrer-Policy`, `Cross-Origin-Resource-Policy`, `Permissions-Policy`.
- CORS allow-list via `VEIL_CORS_ORIGINS` (CSV, default `*`). Preflight
  short-circuits with 204 + the right Allow-Headers set.
- Prometheus `/metrics` endpoint (no auth — protect at edge):
  - `veil_http_requests_total{method,path,status}` (path uses Go 1.22+
    `r.Pattern`, low cardinality).
  - `veil_http_request_duration_seconds` (12-bucket histogram).
  - `veil_ws_connections_active|_total|_auth_failures_total|_refused_total{reason}`.
  - `veil_ws_messages_total{kind=send_message|presence|...}`.
- Standard Go runtime metrics (heap, GC, goroutines) come for free from
  `promhttp`.

### WebSocket hardening (`internal/gateway`)
- Origin allow-list (`VEIL_WS_ORIGINS`, CSV; default `*`). Native clients
  without `Origin` are always allowed (Tauri/mobile aren't browsers and
  the WS Origin check exists for browser CSRF only).
- Per-IP connection cap (`VEIL_WS_MAX_CONNS_PER_IP`, default 64). Refuse
  *before* the Upgrade so floods from one IP cost nearly nothing.
- IP detection honours `X-Forwarded-For` (first hop) so a future reverse
  proxy doesn't break the cap.
- Cap release is wired into `unregister`, verified by unit test.
- `httpmw.AccessLog`'s `responseRecorder` forwards `http.Hijacker`, so WS
  Upgrade still works (this was a regression fixed mid-sprint).

## Operational

- Production deploy: VPS `5.144.181.72:9080` (gateway) + `:5433` (postgres).
- Compose root: `/opt/veil/`. Build context: `./veil-server`.
- Re-deploy: `rsync -az --exclude=target veil-server/ erez-vps:/opt/veil/veil-server/ && ssh erez-vps 'cd /opt/veil && docker compose up -d --build gateway'`.
- Smoke checks: `/health` → 200; `/ws` Upgrade → 101; `/metrics` exposes
  `veil_*` series. WS flood (80 conns from one IP) → 64 ok / 16 refused
  with `veil_ws_refused_total{reason="ip_cap"}` incremented.

## Next candidates (no fixed order — pick by impact)

1. **Tests for `chat/` and `servers/` handlers.** `auth/` is covered;
   chat/servers handlers are not. Highest ROI for catching regressions
   in the most-touched code.

2. **Flip `allowUnsigned=false`** once Tauri + mobile clients are
   verified to send the signed-request triplet end-to-end. After flip,
   delete the legacy bypass branch in `authmw/signed.go`.

3. **Wire `httpmw` into `cmd/auth/main.go` and `cmd/chat/main.go`** for
   parity with `cmd/gateway`. These standalone binaries are not in the
   compose deploy today, so it's purely consistency / future-proofing.

4. **Grafana dashboard + Prometheus scrape config** to actually consume
   the metrics we now expose. Suggested panels: req rate by status,
   p50/p95/p99 latency by route, active WS, auth-failure rate, refused
   reasons stacked.

5. **Hub sharding for >10k concurrent WS.** Today the entire hub is one
   `sync.RWMutex`. Shard by `fnv(userID) % N` into N maps; fan-out work
   shrinks contention by N. See "scaling" notes below — this is the
   single biggest change before we hit the architectural ceiling.

6. **Distributed hub (Redis Streams or NATS JetStream).** Required for
   horizontal scaling beyond ~25k conn / single node. Each gateway node
   keeps only its own conns; cross-node fan-out goes through the broker.
   Pair with an outbox pattern so DB write + broker publish are atomic.

7. **Postgres tuning for fan-out load**: PgBouncer (transaction mode),
   read replica for history fetches, composite index on
   `(conversation_id, created_at desc)` if not already there.

8. **Sysctl + ulimit tuning on the VPS** (`fs.file-max`,
   `net.core.somaxconn`, `tcp_max_syn_backlog`, `nofile=1048576`). Cheap,
   needed before any real load test.

9. **Sender-Key rotation policy + UX surface** (Phase-4B). Currently
   keys are minted on first message; document when they rotate
   (member leave / configurable interval) and surface "encryption updated"
   notices in the chat island.

10. **Coverage**: `cargo tarpaulin` already produces output under
    `target/tarpaulin/coverage.json`; wire a CI step that fails on
    coverage drop for `veil-crypto` (the highest-stakes crate).

## Known weak spots (audited 2026-04-22) and ideal fixes

Honest list of architectural and quality gaps observed in the current
codebase, paired with the *ideal* (not minimal) remediation. "Ideal"
here means: the fix that would not need to be redone when the next
scaling or compliance milestone hits.

### W1. Single in-process hub (architectural ceiling ~25k WS)
- **Symptom**: all WebSocket state — `clients`, `userClients`, `ipConns`
  — lives behind one `sync.RWMutex` in `internal/gateway/Hub`. Fan-out
  walks `userClients[uid]` while holding it. Mutex contention starts
  hurting around 10k concurrent conns and becomes the wall ~25k.
- **Ideal fix**: two-step migration.
  1. **Sharded hub** (item 5 below) as the local-process win.
  2. **Distributed gateway tier**: each `cmd/gateway` node holds only
     its own connections; cross-node fan-out goes through **NATS
     JetStream** (preferred over Redis Streams: per-subject ordering,
     consumer groups, durable history with TTL). DB write + broker
     publish wrapped in a **transactional outbox** so we never lose a
     message on a node crash. Sticky-session not required — any node
     can deliver to any user once it subscribes to that user's
     subject. Goal: stateless gateway nodes behind a TCP load
     balancer (Hetzner/AWS NLB), zero-downtime rolling deploys.

### W2. Test coverage uneven across packages
- **Symptom**: `veil-crypto` is well-tested (X3DH, ratchet, sender
  keys, AEAD round-trips). `authmw`/`httpmw`/`gateway` have focused
  unit tests. **`chat/` and `servers/` have zero handler tests**, and
  these are the most-edited packages with the most business logic
  (permissions, history pagination, role checks).
- **Ideal fix**: in-process integration test harness. Spin up an
  ephemeral Postgres (testcontainers-go), apply `migrations/`, mount
  the full mux including `authmw`, drive it with the real
  signed-request helper. One file per handler exercising: happy path,
  unauthorised user, missing permission, malformed body, body too
  large, replay rejection. Target ≥80% line coverage on
  `internal/{chat,servers,auth}` and gate it in CI.

### W3. `allowUnsigned=true` still in production
- **Symptom**: the legacy bypass in `authmw/signed.go` is a backdoor
  by design. Until it's flipped, the entire signed-request
  infrastructure is *opt-in* per request, not enforced.
- **Ideal fix**: not just flip the boolean — **delete the branch and
  the `allowUnsigned` parameter entirely**. Add a CI lint that fails
  if `X-User-ID` is read without a prior signed-request verification
  on the same handler. Verification end-to-end: drive both Tauri and
  React-Native through a smoke suite that asserts every REST call
  carries the X-Veil-{User,Timestamp,Signature} triplet.

### W4. `/metrics` exposed without auth
- **Symptom**: `GET /metrics` returns the full Prometheus surface to
  the open internet. Helpful for debugging today, leak vector
  tomorrow (per-user request rates, internal route names, hostnames).
- **Ideal fix**: bind a separate **internal-only listener** (e.g.
  `127.0.0.1:9090`) for `/metrics` and `/debug/pprof/*`, never
  exposed by the docker-compose `ports:` mapping. Prometheus scrapes
  it via `docker exec` or via a sidecar on the same compose network.
  Public port keeps only `/health` and `/ws`. As a stop-gap before
  that: TLS-terminating reverse proxy with HTTP basic auth on
  `/metrics`.

### W5. No frontend tests (desktop or mobile)
- **Symptom**: state is non-trivial (optimistic message inserts,
  reconnect with replay, sender-key distribution timing, presence
  fan-in). Right now any regression is caught by the user.
- **Ideal fix**: **Vitest + React Testing Library** for store logic
  and pure components, **Playwright** for end-to-end flows running
  against a disposable gateway (`docker compose -f
  docker-compose.test.yml up`). Target the four flows that hurt most
  on regression: onboarding (mnemonic → keychain → first connect),
  send-and-receive in DM, group create + sender-key handshake,
  reconnect after offline. Frontend coverage gate at ≥60% for
  `stores/`.

### W6. Single-host deploy, no redundancy
- **Symptom**: one VPS runs gateway + Postgres in compose. Loss of
  the host = loss of the service and possibly data.
- **Ideal fix**: managed Postgres with point-in-time recovery
  (Hetzner managed PG / Neon / RDS). Two gateway nodes minimum
  behind a TCP LB once W1 step 2 is done. Daily restic-style backup
  of `pgdata` to S3-compatible object storage with a documented
  restore drill. Until then: at minimum, an automated nightly
  `pg_dump` to a separate region.

### W7. WS `CheckOrigin` allow-all by default in production
- **Symptom**: code path is *implemented* (`VEIL_WS_ORIGINS`), but
  the env var isn't set on the VPS — falls back to `*`. A malicious
  third-party web page could open a WS to the gateway from any
  user's browser.
- **Ideal fix**: make the empty default **deny browser origins**
  (still allow native clients with no `Origin`). Gateway main
  refuses to start without an explicit `VEIL_WS_ORIGINS` *or* an
  explicit `VEIL_WS_ORIGINS=*` opt-out flag — fail-closed pattern.

### W8. Sender-Key rotation not surfaced
- **Symptom**: keys are minted on first message and never explicitly
  rotated on member departure. Forward secrecy for groups is weaker
  than the protocol allows.
- **Ideal fix**: rotate sender-key on every group membership change
  (add/remove), and additionally on a configurable interval (e.g.
  24h or 1000 messages, whichever first). Surface a non-intrusive
  "encryption updated" pill in the chat island. Document the
  guarantee in `VEIL_DESIGN.md`.

### W9. Logging may leak high-cardinality user data
- **Symptom**: `httpmw.AccessLog` writes `user=<userID>` on every
  request. In high volume that's a per-user activity ledger sitting
  in `docker logs`. For a privacy-first messenger that's an
  uncomfortable artifact.
- **Ideal fix**: log a per-process **HMAC of the userID** (key
  derived from a server-side secret rotated daily). Operators can
  still correlate within a day's worth of logs; an attacker
  exfiltrating logs cannot tie entries back to user accounts.
  Configure log retention at 7 days max in compose / journald.

### W10. No rate-limit on WS message types
- **Symptom**: REST has per-user token-bucket. WS messages flow
  freely once authenticated — a compromised account can flood
  `send_message` or `typing` events at line speed.
- **Ideal fix**: per-`(userID, kind)` token bucket inside the hub,
  evaluated in `handleEnvelope` before dispatch. Tighter limits for
  cheap-to-spam kinds (`typing`, `presence`) than for `send_message`.
  Drop with `veil_ws_messages_rejected_total{kind,reason}` metric;
  disconnect on sustained abuse.

---

## Capacity target (rough numbers, current architecture)

- One 4 vCPU / 8 GB VPS: ~5k concurrent WS, ~500 msg/s.
- Single big node (16 cores): ~15–20k WS, mutex-bound.
- Hard single-node ceiling: ~25k WS regardless of CPU.
- After hub sharding (item 5): ~50k WS feasible per node.
- After distributed hub (item 6): bounded by Postgres + broker, not Go.
