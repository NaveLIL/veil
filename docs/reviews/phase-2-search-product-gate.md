# Phase 2 — Search Product Gate

Дата проверки: 2026-07-14

Статус: **CLOSED — final verification PASS**.

Закрытая реализация покрывает RAM-only index, bounded live/rebuild coverage и
exact SQLCipher navigation. Независимый review обнаружил и до закрытия проверил
исправления гонок live mutation ↔ rebuild/coverage и lock ↔ pre-existing send.
Финальный delta-verdict: `SHIP`, `P0=0`, `P1=0`, `P2=0`. Полная проверочная
матрица ниже относится к тому же неизменному candidate.

## Решение

Veil выполняет полнотекстовый поиск только на native устройстве. SQLCipher
остаётся единственным durable источником расшифрованной истории, а Tantivy —
производным process-memory snapshot для текущего authenticated account/origin.
Поисковый запрос, plaintext index и search analytics на Veil Node не уходят.

Browser client, server-side message search и persistent plaintext index в Phase
2 запрещены.

## Обязательная граница безопасности

- `veil-search` использует только `RamDirectory` и не предоставляет public
  disk-backed constructor. Lock/account/origin transition уничтожает текущий
  snapshot; если создание пустой замены падает, старый plaintext уже недоступен
  и поиск остаётся fail closed.
- SQLCipher projection выбирает только непустые сообщения exact authenticated
  `canonical_server_origin`. Originless development rows и строки другого Veil
  Node не получают текущий origin по догадке.
- Один RAM hit не является message, navigation или identity authority. Перед
  возвратом renderer native повторно открывает exact
  `message_id + conversation_id + canonical_server_origin` из SQLCipher и
  сверяет body, conversation и 32-byte sender identity key.
- Author profile публикуется только из сохранённой exact-origin SQLCipher
  snapshot, совпадающей с sender key. Голая строка sender из Tantivy не
  превращается в account locator и не получает trust status.
- Rebuild строится как отдельный полный candidate. Cancel, ошибка, lock, смена
  session/account/origin или новый rebuild не публикуют частичный candidate и
  сохраняют прежний complete snapshot, кроме явной fail-closed очистки.
- Live insert/edit/delete и rebuild используют один hard budget внутри
  `veil-search`. Monotonic mutation generation не позволяет prepared candidate
  затереть live mutation, произошедшую во время SQLCipher extraction или
  Tantivy build.
- Coverage берётся из того же committed index state, который видит search, и
  публикуется только вместе с exact native session/account/origin binding.
  Параллельный приблизительный счётчик не является authority.
- Renderer отклоняет malformed DTO, stale async completion и ответы другого UI
  session/binding generation. Ошибка не маскируется под пустую выдачу.

## Hard budget и coverage contract

- На один exact origin индексируется максимум **250 000** сообщений и
  **64 MiB** оценённого decrypted source.
- В source estimate входят UTF-8 body, message ID, conversation ID, 32-byte raw
  sender key и фиксированные 64 bytes per-document overhead. Это bounded input,
  а не утверждение, что Tantivy/allocator используют ровно 64 MiB RAM.
- Rebuild читает newest-first через SQLCipher keyset pages по 512 строк в
  порядке `(effective message timestamp, canonical message UUID)`; этот же
  порядок и UUID tie-break использует live budget. Поэтому поздняя вставка
  старой строки не вытесняет действительно новую историю, а прежнего
  per-conversation `LIMIT 100000` нет.
- При достижении count/byte bound остаётся непрерывный newest slice. Live
  insertion более нового сообщения вытесняет самое старое; слишком старое
  сообщение не вытесняет более новый slice. `truncated` остаётся sticky после
  delete и сбрасывается только полной очисткой/rebuild.
- Count/source bytes изменяются только после успешного Tantivy commit. Replace,
  delete, eviction, cancel, failed publication и clear не имеют права выдавать
  coverage, расходящуюся с searchable snapshot.
- Edit заменяет только body уже удерживаемого сообщения и сохраняет исходные
  conversation/sender/timestamp. Старое сообщение за пределами bounded slice
  не реинсертится как новое; такой miss честно делает coverage partial до
  следующего полного rebuild.
- UI постоянно показывает partial-coverage warning, пока опубликованный
  snapshot truncated; transient coverage IPC failure не подменяет последнюю
  authoritative snapshot ложным «полным» состоянием.

## Exact navigation contract

- Клик по hit повторно запрашивает SQLCipher context по exact
  `message_id + conversation_id + origin`; deleted/moved/cross-origin target
  завершает действие ошибкой.
- Native возвращает chronological window не более 200 сообщений с обязательной
  target message и authoritative `dm | group | channel`.
- Для `channel` обязателен canonical `server_id`. Desktop обновляет exact Space
  и Room directory, проверяет `server_id + conversation_id` и никогда не
  fallback-ит недоступный Room в Direct.
- Для Direct/Circle renderer сверяет фактический conversation type; UUID сам по
  себе не определяет контекст.
- Палитра остаётся modal во время перехода. Она закрывается только когда exact
  route опубликован и target DOM подтверждён в authenticated conversation;
  после закрытия сообщение центрируется, получает focus/highlight, а reduced
  motion отключает плавное перемещение.
- Failure сохраняет палитру открытой, показывает явную ошибку и возвращает focus
  в search input. Duplicate Enter, Escape, backdrop и Ctrl/Cmd+K не запускают
  второй переход во время in-flight navigation.

## Product и accessibility contract

- Cmd/Ctrl+K открывает Kobalte Dialog/combobox/listbox с debounce, loading,
  empty, error и rebuild/cancel states; keyboard поддерживает Arrow/Home/End,
  Enter и корректный focus return.
- UI запрашивает не более 30 hits. Query и native result bounds проверяются до
  renderer publication; text выводится как text nodes с безопасным highlight.
- Поиск охватывает Direct, Circles и text Rooms текущего Veil Node. Результат
  может открыть Identity Island автора только при полном exact locator из
  SQLCipher author snapshot.
- Автоматический backfill после unlock/offline sync и ручной rebuild используют
  одну atomic publication модель. Ручной Cancel не очищает рабочий snapshot.

## Source evidence в закрытой реализации

| Boundary | Проверяемое evidence |
|---|---|
| `veil-search/src/lib.rs` | `RamDirectory`, отсутствие disk constructor, hard live/rebuild bounds, exact metadata accounting, sticky truncation, atomic candidate publication, mutation generation и fail-closed clear tests |
| `veil-store/src/db.rs` | exact-origin newest-first projection, keyset continuation и chronological ≤200 message context с обязательной целью/author validation |
| `veil-desktop/src-tauri/src/lib.rs` | origin/session-bound rebuild, hit rehydration, exact context, index/coverage publication и Tauri command registration |
| `veil-desktop/src/lib/identityIpcBoundary.ts` | strict hit/context/coverage DTO validation и fixed renderer bounds |
| `veil-desktop/src/stores/app.ts` | latest-generation exact context publication без удаления unrelated/optimistic messages |
| `veil-desktop/src/App.tsx` | authoritative route resolution, no Room→Direct fallback, rendered-target confirmation, centering/focus и stale action rejection |
| `veil-desktop/src/components/ui/CommandPalette.tsx` | loading/error/empty/coverage UX, async generations, rebuild Cancel и in-flight interaction lock |
| `veil-desktop/src/test/` | command palette, IPC boundary, store publication, exact route/render/focus и accessibility regression tests |

Эта таблица подтверждает расположение проверок, но не заменяет их запуск.

## Final verification matrix

| Проверка | Статус |
|---|---|
| Независимый security re-review: live budget, mutation/rebuild race, lock order, exact navigation | **PASS — SHIP; P0=0, P1=0, P2=0** |
| `git diff --check` | **PASS** |
| `cargo fmt --all -- --check` | **PASS** |
| `cargo clippy --workspace --all-targets -- -D warnings` | **PASS** |
| `cargo test --workspace --all-targets` | **PASS — 337 passed, 12 intentionally ignored, 0 failed** |
| `go test ./...` и `go vet ./...` | **PASS** |
| Docker `go test -count=1 -tags=integration -timeout 15m ./internal/integration/...` | **PASS — 201.311s** |
| `pnpm test:run` | **PASS — 25 files, 142 tests** |
| `pnpm build` | **PASS — production TypeScript/Vite build** |
| `pnpm test:visual` | **PASS — 29 passed, 4 viewport-conditional skipped** |
| Windows native build/smoke с ASCII `CARGO_TARGET_DIR` | **PASS — release PE32+ Windows GUI, MSI и NSIS bundles** |

Опциональное воспроизводимое performance evidence:

```text
cargo test -p veil-search --release measures_large_profile_atomic_rebuild -- --ignored --nocapture
```

Результат зависит от hardware и не является SLA. Он не заменяет correctness,
memory-bound или race tests.

На текущей Windows-машине 2026-07-14 release-profile run построил 100 000
synthetic документов за **0.410s**.

## Exit decision

Phase 2 закрыта, потому что:

1. все строки final verification matrix имеют свежий `PASS`;
2. независимый review не оставляет P0/P1 и подтверждает отсутствие reverse lock
   order/deadlock path;
3. published coverage доказуемо соответствует committed searchable state также
   после live replace/delete/eviction и конкурирующего rebuild;
4. exact Direct/Circle/Room navigation, stale session и missing target проходят
   component/native/storage regression tests;
5. roadmap и README обновлены тем же checkpoint commit, а branch отправлена в
   remote без включения несвязанных mobile WIP.

Все пять условий выполнены одним checkpoint candidate; несвязанный mobile WIP
не входит в его commit scope.

## Не входит в Phase 2

- server-side search, query analytics и persistent plaintext index;
- morphology/stemming для всех языков и полная локализация;
- поиск по ещё не загруженной с Veil Node истории;
- browser messenger;
- Community posts/comments/reactions/polls search до отдельного Community
  contract.
