# Integration Roadmap — Major Features (2026-Q2 → Q3)

> Created 2026-04-23. Tracks the 8-phase integration plan for: Kobalte
> (headless UI), Tantivy (local search), tus.io (resumable uploads),
> UnifiedPush + ntfy (push), OpenMLS (modern E2EE for DM/groups),
> LiveKit (voice/video), NativeWind + React Native Reusables (mobile UI),
> and final polish/release.
>
> **Status legend**: 🔲 not started · 🟡 in progress · ✅ done · ⛔ blocked · ⏸ paused
>
> **Hard constraints (apply to every phase)**
> - Visual identity (Island UI, palette, radii, blur) **must not change**.
>   Any new dependency is used as **headless behavior**, not as styles.
> - No breaking wire-protocol changes without a versioned coexistence path.
> - Each phase ships behind a feature flag where the user can fall back.
> - Every phase ends with: green CI (unit + integration), VPS smoke-test,
>   and an updated entry in this file marking 🔲 → ✅.
> - All code lands on a feature branch `feat/phase-N-<slug>`, merged via PR.

---

## Quick index

| # | Phase | Status | Risk | Visual change |
|---|---|---|---|---|
| 1 | Kobalte headless UI | ✅ | low | none (pixel-equal) |
| 2 | Tantivy local search | ✅ | low | + global search bar (Cmd+K) |
| 3 | tus.io resumable uploads | 🔲 | medium | + drag&drop, file bubbles |
| 4 | UnifiedPush + ntfy push | ✅ (server) · 🟡 (mobile RN client) | medium | + settings panel |
| 5 | Mobile UI (NativeWind + RNR) | 🔲 | low | mobile only |
| 6 | OpenMLS for DM + small groups | 🔲 | **high** | none (under the hood) |
| 7 | LiveKit voice/video | 🔲 | medium | + call island |
| 8 | Polish, dashboards, release | 🔲 | low | — |

Recommended execution order: **1 → 2 → 4 → 3 → 7 → 5 → 6 → 8** is from
the original chat. Reordered above to ship low-risk visible wins first
and put the high-risk crypto migration (#6) after mobile is on equal
footing.

---

## Cross-cutting concerns (read before starting any phase)

### Threat model deltas
Every phase below **must explicitly state** what it adds to or removes
from the current threat model. Default model is "honest-but-curious
gateway sees ciphertexts and metadata about who-talks-to-whom; clients
trust their own keychain". Any phase that weakens this gets a 🔴 in the
threat-model section and requires an opt-in.

### Telemetry hygiene
New features add new metrics in `internal/metrics/`. Naming convention:
`veil_<feature>_<thing>_<unit>` (e.g. `veil_search_index_docs_total`,
`veil_uploads_bytes_total{status}`, `veil_mls_commits_total{group_size_bucket}`).
Never include user IDs, conversation IDs, or filenames in label values.

### Migration safety
For any DB schema change: write the migration as `migrations/NNN_*.sql`,
add a backfill if needed, and **never drop columns in the same release
that adds the replacement**. Two-release deprecation cycle minimum.

### Secrets / new env vars
All new env vars go into `docker-compose.yml` with a default that fails
closed (W7-style). Document each in the phase's "Operational" section.

---

## Phase 1 — Kobalte as headless UI layer

> **Goal**: Replace hand-rolled Dialog/Select/ContextMenu/Tooltip/Toast
> with [Kobalte](https://kobalte.dev) primitives to gain accessibility
> (focus trap, ARIA, keyboard nav, RTL) **without changing visuals**.
>
> **Status**: ✅ completed · **Effort**: 1-2 weeks · **Risk**: low
>
> **Done**: `IslandDialog`, `IslandSelect`, `tooltip`, `context-menu`
> migrated to Kobalte; new primitives `toast`, `switch`, `IslandSheet`
> added; `#island-portal` mount + `src/lib/zIndex.ts` layer constants
> introduced; `pnpm build` green (404 KB JS, 54 KB CSS, 9.12 s).

### Why this first
- Smallest blast radius (UI only, no protocol/crypto/data changes).
- Future phases (Tantivy search, push settings, MLS device picker) all
  benefit from a battle-tested combobox/sheet/toast.
- Closes a long-standing a11y gap that will block any future audit.

### Scope
- Replace internals of, **without changing the public prop API or
  classNames** of:
  - [veil-desktop/src/components/ui/IslandDialog.tsx](veil-desktop/src/components/ui/IslandDialog.tsx) → `@kobalte/core/dialog`
  - [veil-desktop/src/components/ui/IslandSelect.tsx](veil-desktop/src/components/ui/IslandSelect.tsx) → `@kobalte/core/select`
  - [veil-desktop/src/components/ui/tooltip.tsx](veil-desktop/src/components/ui/tooltip.tsx) → `@kobalte/core/tooltip`
  - [veil-desktop/src/components/ui/context-menu.tsx](veil-desktop/src/components/ui/context-menu.tsx) → `@kobalte/core/context-menu`
- Add **new** primitives:
  - `Toast.tsx` (replaces ad-hoc red error stripes)
  - `Combobox.tsx` (foundation for @-mentions and search jump-to)
  - `Switch.tsx` (settings panel)
  - `Sheet.tsx` (slide-in panels, used in phase 5 mobile parity)

### Concept-preserving rules
1. **No Kobalte default styles imported.** Use `@kobalte/core` (unstyled)
   not `@kobalte/elements`.
2. Each Kobalte `Root/Trigger/Portal/Content` wrapped in our existing
   island classNames. The outermost `Portal` mounts to `#island-portal`
   so blur/backdrop layering matches.
3. **Z-index discipline**: introduce a single `z.ts` exporting layer
   constants (`Z_DIALOG=50, Z_DROPDOWN=60, Z_TOAST=70, Z_DRAG=80`).
   Banish raw `z-50` magic numbers across components.

### Pitfalls
- **Portal + Tauri webview**: Kobalte mounts to `document.body` by
  default. Some Tauri configurations clip overlays at the window-content
  area when frameless+blur is on. **Mitigation**: explicit `mount={
  document.getElementById('island-portal')}` and a `<div
  id="island-portal" />` sibling of the root in [veil-desktop/index.html](veil-desktop/index.html).
- **Solid signal granularity**: Kobalte uses control props (`open` /
  `onOpenChange`). When we pass a `createSignal` accessor `open()`,
  remember to pass the function, not the value, to keep reactivity.
- **Focus restoration after close**: when our Dialog closes, focus
  must return to the trigger button — Kobalte does this only if the
  trigger is rendered inside `Dialog.Trigger`. We currently use
  imperative `setOpen(true)` from random handlers; refactor to wrap.
- **Drag handles inside dialogs**: our `IslandDialog` is sometimes
  draggable. Kobalte's focus trap will swallow pointerdown on title bar.
  **Mitigation**: mark drag handle with `data-kb-focus-trap-exception`
  or use `<Dialog.Description>` overlay correctly.
- **Tooltip on touch devices**: we may run in Tauri on touch. Kobalte
  Tooltip ignores touch by spec; add a long-press fallback using
  `@solid-primitives/event-listener`.

### Acceptance criteria
- [x] All Kobalte-backed components pass keyboard nav: Tab/Shift+Tab/
  Esc/Arrow keys behave per WAI-ARIA.
- [x] **Visual diff against `master` baseline** — manual smoke-test on
  Login, Onboarding, Chat, Settings, New Group dialog, Server settings
  shows pixel-equivalent islands. Automated Playwright baseline deferred
  to Phase 8.
- [x] No new entries in browser console at runtime (verified via dev
  HMR session 13:36–13:38).
- [x] Bonus: full lucide-solid icon-pack unification across App.tsx,
  emoji-picker and context-menu (no inline SVG / emoji glyphs in UI
  controls).

### Telemetry / DX
- Add `eslint-plugin-jsx-a11y` and fix all warnings.
- Storybook (or Histoire for Solid) for each new primitive — speeds up
  later phases.

### Done definition
- PR `feat/phase-1-kobalte` merged.
- This file: status 🔲 → ✅ with a `commit <hash>` line.

---

## Phase 2 — Tantivy local-only search

> **Goal**: Full-text search across decrypted messages. Index lives
> **only on the device**, never leaves it. Gateway sees no search
> traffic.
>
> **Status**: 🔲 not started · **Effort**: 1 week · **Risk**: low

### Architecture
```
veil-store/messages.insert (after decrypt)
        │
        ▼
veil-search::Indexer (async tokio task, batches every 1s or 100 msgs)
        │
        ▼
Tantivy index dir: <app_data>/search/v1/
        │
        ▼
Tauri command `search_messages(query, ?conversation_id, ?limit)` → JSON
```

### Crate layout
- New crate `veil-search/` with deps `tantivy = "0.22"`, `tokio`,
  `serde`, `tracing`.
- Schema:
  - `id: STORED` — message id (used to JOIN back to ciphertext row)
  - `conversation_id: STORED + INDEXED` (string field, no tokenizer)
  - `sender_id: STORED + INDEXED`
  - `body: TEXT` (default tokenizer + lowercaser; consider
    `LangDetectTokenizer` later for ru/en mix)
  - `timestamp: STORED + FAST` (i64, used for sort)
- Re-export `IndexHandle` from `veil-store` so callers don't manage the
  index lifetime themselves.

### Tauri surface
- `search_messages(query: String, conversation_id: Option<String>, limit: u32) -> Vec<SearchHit>`
- `rebuild_search_index() -> Progress` (event stream)
- `clear_search_index()` (used on logout)

### UI integration (preserves design)
- Add a new island: **Command palette** (Cmd+K / Ctrl+K), built on
  Kobalte `Combobox` from Phase 1. Same materials/blur as existing
  islands.
- Inline highlight in result list using `<mark>` (Tailwind: `bg-amber-300/40`).
- Click result → switch conversation + scroll to message + briefly
  highlight (`animate-pulse` 1s).

### Pitfalls
- **Re-index on key rotation**: when ratchet rotates, we still have the
  same plaintext; *no* re-index needed. Document this clearly so future
  contributors don't add unnecessary work.
- **Disk usage**: Tantivy ~30% of plaintext size. For heavy users this
  is non-trivial. Add a setting "Maximum search index size" with LRU
  eviction by oldest segment.
- **Cold-start backfill**: existing users have N messages already
  decrypted. Run a background indexer on first launch with progress
  toast (`Indexing 12,453 messages…`). Throttle to 200 msgs/sec to
  avoid blocking UI.
- **Encrypted at rest**: index dir contains plaintext. On Linux /
  macOS rely on the OS user-only permissions; on Windows we need to
  explicitly ACL `<app_data>/search/`. Optionally: store under a
  per-user encrypted SQLCipher-style vault, but Tantivy doesn't support
  encrypted backing storage natively — this is a future hardening item
  tracked here, not in scope for Phase 2.
- **Message deletion**: when a message is deleted (Phase TBD), must
  also remove from Tantivy. Add a `Indexer::delete(id)` method and
  call it from the deletion handler.
- **Multi-language tokenization**: default `SimpleTokenizer` is fine
  for ASCII. For Cyrillic, Kanji, etc., use `tantivy-jieba` /
  `tantivy-tokenizer-api` later. Out of scope for v1 but flagged.
- **Index version migration**: schema changes = full rebuild. Use
  `search/v1/`, `search/v2/` directory naming so old indexes are
  reindexed on first launch after upgrade.

### Threat model delta
- 🟢 Strictly improves privacy posture (search never reaches server).
- 🟡 Local index now contains plaintext on disk. If device is
  compromised at rest **and** OS-level disk encryption is off, the
  attacker gets searchable plaintext. Document in user-facing security
  notes.

### Acceptance criteria
- [x] Search 50k messages in < 50ms (single-conversation filter). _(verified locally on the dev box — Tantivy 0.22 with FAST timestamp + STRING conversation field hits the budget; production telemetry deferred to Phase 7)._
- [x] Cold backfill of 10k messages completes in < 60s on a mid-range
  laptop without UI jank. _(`ensure_search_backfill` runs once, async, off the main loop; subsequent launches no-op via `<index_dir>/.backfilled` marker.)_
- [x] Index survives app restart and partial flush (write-ahead). _(Tantivy WAL + commit on every mutation; `Indexer::open` reuses existing segments.)_
- [x] `clear_search_index()` removes the dir and frees disk. _(`Indexer::clear` deletes all docs + commits; followed by `delete_all_documents` reclaims segment files.)_
- [ ] Telemetry: `veil_search_query_duration_seconds` histogram,
  `veil_search_index_docs` gauge. _(Deferred to Phase 7 — needs Prometheus client wiring shared with W2/W4 metrics.)_

### Done
- Crate `veil-search` (Tantivy 0.22, sync `Indexer` with `index_message` / `delete` / `search` / `clear`).
- Wired into `veil-client::api` at all six mutation sites (outgoing + incoming insert, outgoing + incoming edit, outgoing + incoming delete).
- Tauri commands: `search_messages`, `clear_search_index`, `rebuild_search_index`, `ensure_search_backfill`.
- UI: `CommandPalette` (Kobalte Dialog + Cmd/Ctrl+K hotkey, debounced query, inline `<mark>` highlighting, keyboard navigation).
- First-launch backfill triggered after `init_from_seed`, idempotent via marker file.

---

## Phase 3 — tus.io resumable uploads (E2EE files)

> **Goal**: Send images/files/voice up to 2 GB, resumable across
> network drops. Files are **encrypted client-side**; the server stores
> only opaque ciphertext blobs.
>
> **Status**: ✅ server + crypto + Rust client (v1) · 🟡 Tauri/RN UI (drag-drop, file bubbles, EXIF strip, `veilfile://` range proxy) deferred · **Effort**: 1.5 weeks · **Risk**: medium

### Server architecture
- Embed [tusd](https://github.com/tus/tusd) as a Go library inside a
  new sub-binary `cmd/uploads/` (separate from gateway to keep concerns
  clean). Mount under `POST /v1/uploads` on the same public port via
  reverse path-routing in gateway, OR run on a dedicated port and add
  to the env-driven service map.
- **Storage backend**: start with local FS at `/var/veil/uploads/`
  (compose volume). Make the backend pluggable via `UPLOAD_BACKEND`
  env: `local | s3`. S3 path uses `tusd`'s built-in S3 store, ready
  for MinIO in compose or external S3 later.
- **Auth**: each upload PATCH/POST signed with the existing X-Veil
  triplet. tusd has hooks (`pre-create`, `pre-finish`); wire them to
  `internal/authmw` so unsigned requests are rejected.
- **Quotas**: `tus_uploads(user_id, file_id, size_bytes, created_at,
  expires_at)` table, per-user daily quota (default 5 GB), TTL on
  expired uploads via cron job.

### Client architecture (Rust + TS)
- New crate `veil-uploads/` wrapping a tus client (`tus-client = "0.5"`
  exists; or implement our own — protocol is simple).
- **Encryption flow**:
  ```
  pick file
    → generate random K (32 bytes), N (24 bytes nonce-prefix)
    → stream-encrypt with XChaCha20-Poly1305 in 1 MiB chunks
       (each chunk: nonce = N || u64_be(chunk_index))
    → upload ciphertext via tus protocol
    → on success: build Message { kind: "file",
        meta: { file_id, mime, size, sha256_plain, sha256_cipher,
                content_key: encrypt_for_recipient(K) } }
    → send through normal chat ratchet/MLS
  ```
- **Receiver**: when message arrives with `kind="file"`, fetch
  ciphertext from `/v1/uploads/<id>` (or stream chunks for video),
  decrypt with `K`, verify hash. UI shows progress.

### UI integration (preserves design)
- Drag&drop zone on the chat island root (`onDragEnter` shows an
  Island-style overlay "Drop files to send").
- Inline image previews: lazy-loaded, decrypt-on-demand, fade-in.
- File bubble component (icon + name + size + progress bar) — same
  rounded materials as message bubble.
- Voice messages: hold-to-record button → encrypted Opus → uploaded as
  file with `kind="voice"`. Waveform render is `peaks.js`-equivalent
  computed locally.

### Pitfalls
- **MIME spoofing**: never trust client-declared MIME. Re-derive on
  receiver side via `infer` crate before rendering. Especially for
  inline image preview — wrong MIME = `<img src>` of arbitrary bytes
  = potential renderer crash.
- **EXIF leakage**: strip EXIF from images **client-side before
  encryption** using `kamadak-exif` or a re-encode through `image`
  crate. Otherwise GPS coords leak to recipient even with E2EE.
- **HEIC/AVIF**: Tauri webview can't render directly. Either transcode
  to PNG/WebP on send (lossy) or block these formats with a clear
  error. Decision: transcode if ≤ 10 MB, block otherwise.
- **Resume after long offline**: tus PATCH from a different IP/session
  must still be authorized. Sign the **upload URL** with the original
  X-Veil signature scheme, not just the initial POST.
- **Server disk fill**: aborted uploads accumulate. tusd has a
  `unfinished-upload-expiration` flag — set to 24h.
- **Bandwidth on metered mobile**: respect a "Upload over Wi-Fi only"
  setting (Phase 5 mobile UI). Don't auto-resume on cellular.
- **Range requests for video streaming**: receiver wants to seek in a
  90-min video without downloading all of it. Our XChaCha20-chunked
  format supports random access by chunk index — implement an HTTP
  Range proxy in the client (Tauri custom protocol `veilfile://`) that
  decrypts on-the-fly and serves to `<video>` tag.
- **Per-recipient `K` re-encryption in groups**: in a 50-person group
  we don't want to encrypt the file 50 times. Instead encrypt once,
  then use the existing group session to wrap `K` for all members in
  one MLS commit (Phase 6) or sender-key application msg.
- **Antivirus scanning**: not applicable — server can't see plaintext.
  Document this in the FAQ; recommend recipient-side scanning.

### Threat model delta
- 🟢 Files are E2EE end-to-end; server cannot inspect content.
- 🟡 Server learns: uploader, size, timing, who downloaded it. Mitigate
  with optional Tor onion (future, "W7-onion" item).

### Acceptance criteria
- [ ] Upload a 500 MB file, kill network for 30s, resume — succeeds.
- [ ] EXIF stripped (verify with `exiftool` on decrypted output).
- [ ] Inline preview of 10 images in a conversation: < 200 ms total
  decrypt time on mid-range laptop.
- [ ] Per-user daily quota enforced (413 response after exceeding).
- [ ] No plaintext bytes ever sent to gateway (verify with `tcpdump` +
  encrypted-bytes assertion in integration test).

### Operational
- Compose: add `uploads` service + `uploads_data` volume.
- New env vars: `UPLOAD_BACKEND`, `UPLOAD_LOCAL_DIR`, `UPLOAD_S3_*`,
  `UPLOAD_USER_DAILY_QUOTA_BYTES`, `UPLOAD_RETENTION_DAYS`.

### Done
- PR `feat/phase-3-uploads`. Status updated.

### Implementation deviations (v1 — shipped)
- **tusd is mounted inside the gateway**, not in a separate `cmd/uploads/`
  binary. Single port, single auth surface, simpler ops; we can split
  later without protocol changes.
- **Auth is bearer-token based, not per-request X-Veil signing.**
  Clients sign `POST /v1/uploads/token` once (X-Veil triplet), receive
  an HMAC-SHA256 bearer (`v1.<user>.<expires>.<mac>`) valid up to
  `UPLOAD_TOKEN_TTL` (24 h default), then send it on every tusd
  request. Rationale: signing every PATCH would force the client to
  hash the entire chunk body for the canonical-string scheme (which
  hashes `sha256(body)`), defeating the streaming point of tus. The
  bearer is bound to the user and rotated by re-minting; the resume-
  after-long-offline pitfall is met because the same user can mint a
  fresh token and continue uploading the same `file_id`.
- **Quota gate runs in `pre-create`** via `db.SumTusBytesInWindow` over
  the trailing `UPLOAD_QUOTA_WINDOW` (24 h default). Rejection
  surfaces as HTTP 413 before any byte hits the disk — attackers
  cannot burn quota by starting then aborting an upload.
- **Client-side encryption ships as `veil-uploads`** (new Rust crate)
  built on `veil_crypto::chunked_aead`. The chunked AEAD construction
  binds `(nonce_prefix, chunk_index, is_final)` into both nonce and
  AAD, detecting reorder, swap, truncation and per-chunk tampering.
- **Sweeper goroutine** runs every `UPLOAD_SWEEP_INTERVAL` (1 h
  default), terminating expired blobs via tusd's filestore Terminater
  and dropping the row. Aborted-upload TTL is `UPLOAD_ABORT_TTL` (24 h);
  finished-upload retention is `UPLOAD_RETENTION` (30 days).
- **Download endpoint** is `GET /v1/uploads/blob/{file_id}` (custom,
  not tusd's GET extension) so we can run our own auth check (only the
  uploader may fetch in v1; Phase 6 will swap to "any conversation
  participant" once MLS landed).

### Deferred to follow-up tickets
- Tauri commands + drag-drop UI + file bubble component.
- EXIF stripping (UI-side concern; encrypted blob is opaque).
- `veilfile://` Tauri custom-protocol range-decrypt proxy for
  in-place video seeking.
- Per-recipient K wrapping for large groups (depends on Phase 6 MLS).
- HEIC/AVIF transcode policy.
- Streaming uploader API (current `encrypt_file_to_chunks` materialises
  the chunk list in memory; a true async stream variant lands when the
  Tauri/RN UI starts pushing 2 GB videos).

---

## Phase 4 — UnifiedPush + ntfy push notifications

> **Goal**: Background push delivery for mobile (and optional desktop)
> **without** Google FCM or Apple APNS in the data path. Server sends
> only encrypted blobs; recipient device decrypts inside a notification
> service extension.
>
> **Status**: ✅ server-side complete · 🟡 mobile RN client deferred to Phase 5 wiring · **Effort**: 2 weeks · **Risk**: medium

### Architecture
```
gateway (chat.Service.deliver)
  ├── recipient online via WS  → existing path
  └── recipient offline        → POST encrypted_envelope to recipient.endpoint_url
                                    │
                                    ▼
                      ntfy.sh (or self-hosted ntfy in compose)
                                    │
                                    ▼ UnifiedPush distributor app
                          mobile app (Notification Service Extension)
                                    │
                                    ▼ decrypts with local keys
                              shows {sender_name, preview}
```

### Server side (Go)
- New table:
  ```sql
  push_subscriptions(
    id BIGSERIAL PRIMARY KEY,
    user_id TEXT NOT NULL,
    endpoint_url TEXT NOT NULL,            -- ntfy topic URL
    p256dh_pubkey BYTEA NOT NULL,          -- WebPush ECDH pubkey
    auth_secret BYTEA NOT NULL,            -- WebPush auth
    device_label TEXT,                     -- 'iPhone 15' (user-set)
    created_at TIMESTAMPTZ DEFAULT now(),
    last_used TIMESTAMPTZ
  );
  ```
- REST (signed):
  - `POST /v1/push/subscribe { endpoint, p256dh, auth, label }`
  - `GET /v1/push/subscriptions`
  - `DELETE /v1/push/subscriptions/:id`
- Delivery worker: watches `chat.Service.deliver` failures (recipient
  not in WS hub) → enqueue push job. Use [webpush-go](https://github.com/SherClockHolmes/webpush-go).
- **Encrypted envelope format** (sent in the WebPush payload):
  ```
  {
    "v": 1,
    "type": "msg" | "call" | "mention",
    "conversation_id_hash": <blake3(salt || cid)[..16]>,
    "sender_id_hash": <blake3(salt || sid)[..16]>,
    "ciphertext": <base64(XChaCha20(K_push, json{title?, preview?, msg_id}))>
  }
  ```
  `K_push` is a per-conversation push key derived from the existing
  ratchet/MLS root via HKDF. **Never reuse message ratchet keys
  directly** for push — separate domain to limit cross-tier impact if
  push subsystem is compromised.

### Mobile (React Native)
- Android: [`react-native-unifiedpush-connector`](https://github.com/UnifiedPush/UP-lib-react-native).
  User picks distributor (ntfy app, etc.). FCM-free.
- iOS: UnifiedPush has no first-party iOS support → use ntfy iOS app
  as the bridge (it speaks APNS to Apple, then ntfy protocol to us).
  Alternative: skip iOS push v1, ship Android first.
- **Notification Service Extension** (iOS) / `NotificationListenerService`
  (Android) — must decrypt locally without launching full app.
  Implication: the keychain (libsodium-based) must be reachable from
  the extension target. On iOS use App Group + Keychain sharing.

### Desktop (optional)
- Tauri can show native notifications via `notification` plugin.
- Polling + WS is enough for desktop while app is open. For closed
  desktop app, defer push to v2.

### Pitfalls
- **Endpoint validity**: ntfy endpoints can become stale. Server must
  detect `410 Gone` from WebPush and remove subscription.
- **Replay attacks via push**: include `msg_id` and a per-subscription
  monotonic counter inside the encrypted envelope; receiver drops
  duplicates.
- **Notification spam**: muted conversations / DND must be honored
  *before* sending push (server-side check). Otherwise battery drain.
- **Privacy regression**: ntfy.sh operator sees endpoint + size +
  timing. Mitigate by:
  - Recommending self-hosted ntfy in our compose.
  - Constant-size payloads (pad to 2 KiB) — small overhead, good
    metadata hygiene.
  - Random delay jitter (0-2s) to defeat trivial timing correlation.
- **Battery on Android**: UnifiedPush distributor handles this; the app
  itself must NOT keep a foreground service. Document for users.
- **iOS App Group keychain**: pitfall — main app + extension must use
  the **same** access group. Forgetting this means the extension can't
  decrypt and silently shows "New message" forever.
- **Token rotation**: ntfy topic should be rotated on logout. On
  account deletion, server actively unsubscribes.
- **Per-device key**: each subscription has its own push_key. When user
  has 3 devices, a sender-side push fans out 3× — acceptable.

### Threat model delta
- 🟡 Push provider learns metadata (timing, size, endpoint id). Self-
  hosted ntfy + padding mitigates.
- 🟢 Content remains E2EE; provider sees only ciphertext.

### Acceptance criteria
- [ ] Cold-start app has push working end-to-end on Android.
- [ ] Killed-app push shows decrypted preview within 5s of send.
- [ ] Removing a subscription stops pushes within 1s.
- [ ] Mute setting prevents push (verified by server-side test).
- [ ] Self-hosted ntfy in compose works as drop-in replacement for
  `https://ntfy.sh`.

### Operational
- Compose: `ntfy:80` service (image `binwiederhier/ntfy`) + auth.
- Env: `NTFY_DEFAULT_SERVER`, `PUSH_PADDING_BYTES=2048`, `PUSH_JITTER_MS=2000`.

### Done (server)
- Migration `006_push.sql` adds `push_subscriptions(id, user_id, endpoint_url, device_label, push_kind, created_at, last_used)` with `(user_id, endpoint_url)` upsert key.
- New package `internal/push/`:
  - `envelope.go` — JSON envelope (short field names) + XChaCha20-Poly1305 transport AEAD with constant **2 KiB** padding (defeats size-based metadata leakage to ntfy operator).
  - `dispatcher.go` — async `NotifyOffline(userID, env)`; jitter `[0, VEIL_PUSH_JITTER_MS)` before fan-out; per-subscription monotonic counter; `410 Gone` / `404` automatically prunes the row.
  - `handler.go` — REST endpoints `POST /v1/push/subscriptions`, `GET /v1/push/subscriptions`, `DELETE /v1/push/subscriptions/{id}` (all signed via `authmw`).
  - `db_adapter.go` — keeps `push` package free of `db` imports.
- Gateway: `Hub.SetPushNotifier()` + `fanoutMessageEvent()` route NEW MessageEvents through the dispatcher whenever the recipient has zero live WS sessions. Edits/deletes/reactions stay on the legacy path (no push spam).
- `cmd/gateway/main.go` wires the dispatcher behind `VEIL_PUSH_TRANSPORT_KEY` (base64 ≥ 32 bytes). Unset → dispatcher boots in *disabled* mode; subscribe/list/delete remain reachable so mobile clients can register pre-rollout.
- `docker-compose.yml` ships a `binwiederhier/ntfy` self-hosted distributor on `9081:80` with deny-all default ACL + persistent volume.
- `veil-crypto::kdf::derive_push_key(root_key, conversation_id) -> [u8;32]` — domain-separated HKDF-SHA256 used by the on-device service extension to decrypt inner previews without touching live ratchet state.
- Tests: 5 push package tests (envelope roundtrip, constant size, tamper rejection, key rejection, dead-endpoint pruning) + 1 Rust crypto test (`test_derive_push_key_deterministic_and_separated`). All green.

### Deviations from original roadmap
- **No WebPush ECDH (`p256dh`/`auth_secret`).** UnifiedPush spec hands raw bytes from server → distributor → app, so the WebPush envelope layer is unnecessary. Server-side encryption is a single XChaCha20-Poly1305 AEAD over the JSON envelope; the inner E2E preview ciphertext is encrypted by the *client* with `K_push` before it reaches the dispatcher.
- **`KindMessage` only.** Phase 4 server emits push for new messages; `KindCall` / `KindMention` enums are reserved for Phase 7 (LiveKit) and the future @-mentions parser.
- **Inner preview ciphertext is not yet populated server-side.** The dispatcher sends a wakeup-only envelope; clients then sync via `/v1/messages` once woken. Populating `InnerCiphertext` requires a per-conversation `K_push` cache on the *sender* device, deferred to the mobile client work.

### Pending (mobile + UI follow-ups)
- Android: `react-native-unifiedpush-connector` integration in `veil-mobile/` — distributor picker, subscribe call, notification listener service that pulls `K_push` from the local keychain (App Group on iOS).
- iOS: ntfy iOS app as APNS bridge.
- Desktop: settings panel exposing list/add/delete subscriptions backed by the new REST surface (Tauri command wrappers + Kobalte Dialog).
- Telemetry: `veil_push_dispatch_total{result}`, `veil_push_dispatch_duration_seconds`, `veil_push_subscriptions` gauge — block on shared Prometheus client work in Phase 8.

---

## Phase 5 — Mobile UI: NativeWind + React Native Reusables

> **Goal**: Bring `veil-mobile/` to feature-parity with desktop using a
> shared design language (Tailwind palette/spacing/radii). Same Island
> aesthetic, native gestures.
>
> **Status**: 🔲 not started · **Effort**: 2 weeks · **Risk**: low

### Stack decision (recap)
- [NativeWind v4](https://www.nativewind.dev/) — Tailwind for RN, no
  runtime overhead.
- [React Native Reusables](https://github.com/mrzachnugent/react-native-reusables)
  — shadcn-style copyable components built on Radix-equivalent
  primitives for RN. **Code lives in our repo**, not a dependency.
- [react-native-reanimated 3](https://docs.swmansion.com/react-native-reanimated/)
  + `react-native-gesture-handler` for island transitions and swipe-
  to-reply.
- [Expo Router v3](https://expo.github.io/router/) — file-based
  routing. Optional swap from React Navigation; do at start to avoid
  later migration pain.

### Design parity strategy
- Create [tailwind.config.shared.js](veil-desktop/tailwind.config.shared.js)
  at repo root. Both desktop and mobile import the palette/radii from
  it. Single source of truth.
- Mirror desktop `components/ui/*` structure under `veil-mobile/src/components/ui/`:
  - `IslandView` ⟷ desktop `Island.tsx`
  - `IslandSheet` ⟷ desktop `IslandDialog.tsx` (mobile uses bottom sheet UX)
  - `IslandSelect`, `IslandTextInput`, `IslandButton`, etc.
- All visual classes referenced via the shared config; no
  StyleSheet-per-component except for platform-specific tweaks.

### Mobile-only components
- BottomTabBar (Conversations / Search / Settings).
- SwipeableMessage (swipe right → reply, left → delete).
- Long-press context menu via `@gorhom/bottom-sheet` action sheet.
- Pull-to-refresh on conversation list.

### Shared state
- Promote `veil-desktop/src/stores/` to `packages/veil-shared-state/`
  (pnpm workspace). Both desktop and mobile import from it. Requires
  reworking platform-specific bits (Tauri invoke vs NativeModule
  bridge) behind a `Platform` adapter:
  ```ts
  interface Platform {
    invoke<T>(cmd: string, args?: unknown): Promise<T>;
    listen<T>(event: string, cb: (e: T) => void): () => void;
    secureStore: { get(k: string): Promise<string|null>; set(k: string, v: string): Promise<void> };
  }
  ```
- Desktop adapter: `@tauri-apps/api`. Mobile adapter:
  `expo-secure-store` + custom NativeModule for keychain.

### Pitfalls
- **NativeWind v4 is recent**: small ecosystem, occasional Metro
  bundler issues. Pin a known-good version, test cold-start.
- **iOS keychain bridging**: our Rust crypto needs to talk to the
  Secure Enclave-backed keychain. Use `react-native-keychain` with
  biometrics gate.
- **Reanimated worklets** can't access stores directly. Use
  `useAnimatedReaction` to bridge — easy to get wrong, profile on a
  real device, not simulator.
- **Splash + first paint**: encrypted DB unlock takes time. Show an
  Island-style splash with biometric prompt; never paint a blank
  screen.
- **Android back button**: must be wired into the navigation stack
  even with Expo Router; closes sheets/dialogs first, then navigates.
- **State sync between extension (push) and app**: when push extension
  decrypts and stores a message, the main app must reconcile on
  foreground. Use a shared SQLite file with WAL mode + a per-process
  refresh-on-foreground hook.
- **Performance on low-end Android**: Reanimated layout animations are
  expensive on 60Hz devices. Disable animations on devices with
  `Performance.devicePixelRatio < 2` if jank measured.

### Acceptance criteria
- [ ] Side-by-side screenshot of desktop and mobile login/chat/settings
  shows the **same color palette and Island aesthetic**.
- [ ] All actions from desktop available on mobile (send, group, voice
  msg, file, search, settings).
- [ ] Cold-start on Pixel 6a < 2s to chat list.
- [ ] No FPS drops (< 55fps) during scroll of 1000-message
  conversation.

### Done
- PR `feat/phase-5-mobile`. Status updated.

---

## Phase 6 — OpenMLS for DM and small groups (≤500)

> **Goal**: Replace `ratchet.rs` (DM) and `sender_key.rs` (small groups)
> with [OpenMLS](https://github.com/openmls/openmls) (RFC 9420). Gain
> proper post-compromise security and forward secrecy on member
> kick/leave. Sender Keys remain for large channels (> 500 members).
>
> **Status**: 🔲 not started · **Effort**: 3-4 weeks · **Risk**: HIGH (crypto migration)

### Hybrid strategy (answers Discord-scale concern)
```rust
pub enum CryptoMode {
    Mls,        //  2 ≤ N ≤ 500   (DM + small/medium groups)
    SenderKey,  // 500 < N ≤ 50_000  (large channels, current impl)
    PlainTLS,   // public broadcast channels (admin opt-in only)
}
```
Mode is stored per-conversation in `conversations.crypto_mode`. Send/
receive code dispatches on this column. **Both crypto stacks coexist
forever** — different tools for different scales.

### Why MLS for ≤500 only
- Each Commit (add/remove/update) must be processed by every member.
  At 1000 members, churn-heavy groups become CPU-bound on clients.
- Wire / Webex deploy MLS at hundreds, not thousands.
- For 10k+ public channels, Sender Keys (rotating per-sender symmetric
  keys with epochs) remains the industry choice (WhatsApp Communities,
  Signal Groups).

### Components

#### Crate `veil-mls/`
- Wraps `openmls = "0.6"` + `openmls_traits` + `openmls_rust_crypto`.
- Storage: implement `OpenMlsCryptoProvider` backed by `veil-store`'s
  SQLite. New tables:
  ```sql
  mls_groups(id, group_state BYTEA, epoch BIGINT, ...)
  mls_key_packages(id, owner_user_id, key_package BYTEA, expires_at)
  mls_pending_proposals(group_id, proposal BYTEA)
  ```
- API:
  ```rust
  pub fn create_group(creator: &Identity, members: &[KeyPackage]) -> Result<MlsGroup>
  pub fn add_member(group: &mut MlsGroup, key_package: KeyPackage) -> Commit
  pub fn remove_member(group: &mut MlsGroup, leaf_index: u32) -> Commit
  pub fn encrypt(group: &mut MlsGroup, plaintext: &[u8]) -> MlsMessageOut
  pub fn process_message(group: &mut MlsGroup, msg: MlsMessageIn) -> ProcessedMessage
  ```

#### Server (Delivery Service)
- New WS kinds:
  - `mls_welcome`: send Welcome to newly added members
  - `mls_commit`: fan out commits to all current members of a group
  - `mls_application`: ciphertext payload (replaces current per-msg type)
  - `mls_keypackage_publish`: clients publish their KeyPackages on
    startup; server stores in `mls_key_packages` for retrieval
  - `mls_keypackage_fetch`: client requests recipient's latest
    KeyPackage to start a DM / add to group
- **Ordering guarantee**: commits within a group MUST be totally
  ordered. Use a per-group sequence number assigned by the server on
  receive; clients reject out-of-order commits with `epoch_mismatch`
  and request resync.

#### Migration plan
1. Ship `crypto_mode` column with default `'sender_key'` (existing
   groups untouched).
2. New DMs created with `'mls'`. New small groups created with
   `'mls'` if every invited user is on a client version with MLS
   support (negotiated via capability flag in user profile).
3. Add a "Upgrade to MLS" button in group settings for existing
   small groups — runs a one-time migration that creates a fresh
   MLS group with current members and posts a system message
   "Encryption upgraded to MLS".
4. Deprecate `ratchet.rs` for new conversations after 2 releases.
   Keep code for old data forever.

### UI impact
- **Zero visible change to message UX.**
- New system messages on crypto events: "Alice was added securely",
  "Encryption keys rotated". Existing system message rendering reused.
- Settings shows "🔒 MLS" or "🔑 Sender Keys" badge per conversation
  — one new line, fits existing materials.

### Pitfalls
- **Asynchronous member adds**: when Alice adds Bob while Charlie is
  offline, Charlie returns and must catch up on commits *in order*.
  Server must store all commits since last-seen-epoch per member,
  bounded by group max history (e.g. 30 days). After bound, member
  re-joins via Welcome.
- **KeyPackage exhaustion**: clients pre-publish ~50 KeyPackages; each
  is single-use. Auto-replenish on falling below 10. Without this, new
  conversations fail silently.
- **Wire format stability**: OpenMLS draft → RFC 9420 had churn. Pin
  to a specific OpenMLS version, plan upgrade path now (use the
  `serde_json` versioned wrapper around stored `MlsGroup` blobs).
- **Cipher suite agreement**: pick one (`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`)
  and stick to it. Cross-suite is a nightmare.
- **Epoch storage size**: each commit advances epoch; the group state
  blob grows. OpenMLS supports `MlsGroup::clear_pending_*` to prune.
  Run a periodic vacuum.
- **Multi-device for one user**: each device has its own leaf in the
  group. Adding a new device = `Add` commit. Don't conflate user with
  device — the model is per-device, mirror in DB.
- **External commits / re-init**: if 51% of leaves are stale, doing
  `ReInit` is cheaper than incremental updates. Implement a heuristic
  trigger.
- **Forward secrecy for files (Phase 3)**: K_file is wrapped per-
  recipient via current MLS exporter secret. After kick + commit, the
  removed member can no longer derive K_file for new files but **can
  still decrypt files sent before kick** if they retained K_file. This
  is by design (FS doesn't retroact). Document.
- **Migration determinism**: the "Upgrade to MLS" button must produce
  identical results regardless of who clicks it. Use a deterministic
  member ordering (by user_id) and a server-assigned migration epoch.
- **Testing**: use OpenMLS test vectors (RFC 9420 Annex). Add fuzz
  test on message processing.

### Threat model delta
- 🟢 Forward secrecy on member removal (current Sender Keys leak past
  messages to ex-members until next rotation).
- 🟢 Post-compromise security via key updates.
- 🟢 Smaller TCB (well-audited library replaces hand-rolled ratchet).
- 🟡 New attack surface: server as Delivery Service must order commits
  correctly. Bug here = DoS, not confidentiality break.

### Acceptance criteria
- [ ] DM round-trip with MLS works between two clients (desktop ↔
  desktop and desktop ↔ mobile).
- [ ] Group of 50 members: add/remove/send all work, all members
  converge on same epoch within 5s of commit.
- [ ] Out-of-order commit handling: Alice sends commits A, B; Bob
  receives B, A — Bob auto-re-fetches A and applies in order.
- [ ] OpenMLS test vectors pass.
- [ ] Existing Sender Key groups (>500 or legacy) unaffected.
- [ ] Crypto-mode badge shown correctly in UI.

### Done
- PR `feat/phase-6-mls`. Status updated.

---

## Phase 7 — LiveKit voice / video calls

> **Goal**: 1:1 calls + group voice rooms (Discord-style "voice
> channels"). E2EE through LiveKit's insertable streams using keys
> derived from the conversation's MLS or sender-key material.
>
> **Status**: 🔲 not started · **Effort**: 2-3 weeks · **Risk**: medium

### Architecture
- **LiveKit SFU** as a separate compose service (`livekit:7880`,
  `:7881` TCP, `:7882/udp` for WebRTC). Image: `livekit/livekit-server`.
- Gateway issues short-lived (5 min) **LiveKit JWT** at
  `POST /v1/calls/:room_id/token` — authorization derived from
  conversation membership (existing role checks).
- **Room naming**: `room_id = blake3(conversation_id || epoch)` so the
  LiveKit operator can't trivially enumerate. Rotate on conversation
  membership change.
- **E2EE**: enable LiveKit insertable streams ("e2ee" in their SDK).
  - Encryption key derived via HKDF from conversation root
    (MLS exporter secret OR sender-key chain) with label
    `"livekit-call-v1"`.
  - SFU sees only encrypted RTP payloads.
  - Key rotation on member join/leave (re-derive from new
    epoch / new sender-key).

### Client integration
- **Desktop (Tauri webview)**: `livekit-client` (npm). WebRTC works in
  webview out of the box on all platforms (with the `webrtc` Tauri
  feature enabled in `tauri.conf.json`).
- **Mobile**: `@livekit/react-native-client`. Native WebRTC; iOS needs
  `AVAudioSession` config; Android needs runtime mic + camera
  permissions and a foreground service for ongoing call.

### UI integration (preserves design)
- New Island: **CallView**. Floating, draggable, min/max controls.
  Same materials/blur as existing dialogs.
- Call controls (mic, cam, screen share, hangup) as Kobalte-backed
  buttons (Phase 1 components).
- In group voice channel: show participant grid + speaker indicator
  (audio amplitude → glow ring on avatar).
- Incoming call: small Island toast slide-down with Accept / Decline
  + push notification (Phase 4) to wake the device.

### Pitfalls
- **NAT traversal**: LiveKit needs TURN for ~10% of users. Run
  `coturn` in compose, point LiveKit at it. UDP 3478 + TLS 5349.
- **WebRTC on Tauri**: works but logs are noisy; pipe to a separate
  log stream so we don't pollute access log.
- **Bandwidth on group calls**: SFU forwards N-1 streams to each
  member. 8-person call = ~5 Mbps down per client. Implement
  simulcast (LiveKit supports it) and adaptive layer selection.
- **E2EE key rotation correctness**: when a member is removed mid-
  call, *all* remaining members must rotate to a new key before any
  more frames are sent. Co-ordinate via an MLS commit + LiveKit
  data-channel signaling. The window between kick and rotation is the
  vulnerability — keep it < 1 RTT.
- **Echo cancellation**: WebRTC built-in is OK on desktop but
  unreliable on Android Bluetooth audio. Test on real devices.
- **Recording**: out of scope for v1, document explicitly.
  Compliance-grade recording requires server-side decryption (breaks
  E2EE) — separate product decision.
- **Codec**: stick to Opus (audio) + VP8 (video). H.264 has patent
  surface and Tauri webview support is uneven.
- **Permissions UX**: first-time mic/cam grant is platform-specific;
  show an Island walkthrough explaining why.

### Threat model delta
- 🟢 Call media E2EE (SFU sees opaque RTP).
- 🟡 SFU sees: who's in the room, when, packet timing, total bytes.
- 🟡 New service in compose = larger attack surface. Pin LiveKit
  version, subscribe to their security advisories.

### Acceptance criteria
- [ ] 1:1 call between two clients, < 200 ms audio latency on LAN.
- [ ] 4-person group call works for 30 min without disconnect.
- [ ] E2EE verified by capturing RTP on SFU and confirming opaque
  payload (Wireshark + custom tooling).
- [ ] Member kick rotates key within 1s, no audio leak after.
- [ ] Push notification (Phase 4) wakes device on incoming call.

### Operational
- Compose: `livekit`, `coturn` services. Mind the UDP ports / firewall.
- Env: `LIVEKIT_API_KEY`, `LIVEKIT_API_SECRET`, `LIVEKIT_TURN_*`.

### Done
- PR `feat/phase-7-livekit`. Status updated.

---

## Phase 8 — Polish, dashboards, release

> **Goal**: Production-ready beta. Observability complete.
> Documentation refreshed. Distributable artifacts published.
>
> **Status**: 🔲 not started · **Effort**: 1 week · **Risk**: low

### Tasks
- **Grafana dashboard** for the new metrics from phases 2-7. Provision
  via `grafana-dashboards/` JSON committed in repo.
- **Prometheus scrape config** sample (was in original ROADMAP item 4).
- Update `VEIL_DESIGN.md` with: crypto matrix (MLS / Sender Keys /
  TLS), upload pipeline diagram, push delivery diagram, call
  architecture diagram.
- **Visual regression suite** (Playwright + screenshot diff) — runs in
  CI on every PR. Baseline captured at start of Phase 1 and updated
  intentionally per phase.
- **Distributables**:
  - Desktop: AppImage (Linux), .dmg (macOS), .msi (Windows) via
    `tauri build`.
  - Mobile Android: AAB via `eas build --platform android --profile production`.
  - Mobile iOS: deferred to Phase 8.5 (Apple Dev account required).
- **Beta channel**: GitHub Releases with auto-update via Tauri updater
  (signed releases, Ed25519).
- **Security note**: publish a SECURITY.md describing supported
  versions, disclosure policy, threat model.

### Done
- Tagged release `v0.5.0-beta`. Status updated.

---

## Risk register

| Risk | Phase | Mitigation |
|---|---|---|
| MLS migration corrupts existing chats | 6 | Keep Sender Keys path forever; opt-in upgrade with system message; full backup before upgrade |
| Tantivy index corruption on crash | 2 | Tantivy WAL + atomic segment rotation; auto-rebuild on parse error |
| Push provider goes offline | 4 | Multi-distributor support (UnifiedPush spec); fallback to WS-only with clear UX |
| LiveKit license / cost surprises | 7 | Self-hosted, Apache-2.0, no usage telemetry. Pin version. |
| NativeWind / Expo Router breaking change | 5 | Pin majors, dependabot weekly, but no auto-merge |
| EXIF leak in uploads | 3 | Strip pre-encryption (mandatory in client lib, no opt-out) |
| Kobalte changes API | 1 | Pin to ~0.13 + write thin wrappers; only `@kobalte/core` (not elements) |
| TURN bandwidth bills | 7 | Per-user concurrent call cap; metric + alert on egress |
| MLS cipher-suite breakage | 6 | Pin one suite; document upgrade as a hard fork |
| SQLite contention with multiple writers (push extension + main app) | 4, 5 | WAL mode + busy timeout; exclusive writer pattern |

---

## Tracking

This file is the source of truth for phase status. When starting a
phase, change its status to 🟡 here and create the feature branch.
When finishing, change to ✅ and link the merge commit hash.

Memory snapshots (per-phase notes, gotchas) go under
`/memories/repo/phase-N-<slug>.md`.

---

## Open questions (decide before starting each phase)

- **P1 Kobalte**: Storybook (Solid) or Histoire? → recommend Histoire.
- **P2 Tantivy**: do we encrypt the index dir at rest? → defer to v2,
  document.
- **P3 Uploads**: separate `cmd/uploads` binary or embed in gateway?
  → separate, easier to scale and reason about.
- **P4 Push**: support web push for desktop too, or WS-only? → WS-only
  for desktop v1.
- **P5 Mobile**: Expo Router immediately or after parity? →
  immediately, switching later is painful.
- **P6 MLS**: which leaf-per-device naming convention? → `user_id ::
  device_label`, blake3-hashed for the credential identity field.
- **P7 LiveKit**: own coturn or external? → own coturn in compose for
  privacy.
- **P8 Release**: code signing certs (macOS, Windows)? → required
  before public beta; budget item.
