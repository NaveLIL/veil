# Roadmap & engineering notes (post Phase-4A hardening sprint)

> Last updated: 2026-04-22. Tracks what's done in the security/observability
> sprint and what's queued next. Memory snapshots live under
> `/memories/repo/` (deploy-vps, observability, http-middleware-gotchas,
> phase4a-groups, tauri-ui-notes).

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

## Capacity target (rough numbers, current architecture)

- One 4 vCPU / 8 GB VPS: ~5k concurrent WS, ~500 msg/s.
- Single big node (16 cores): ~15–20k WS, mutex-bound.
- Hard single-node ceiling: ~25k WS regardless of CPU.
- After hub sharding (item 5): ~50k WS feasible per node.
- After distributed hub (item 6): bounded by Postgres + broker, not Go.
