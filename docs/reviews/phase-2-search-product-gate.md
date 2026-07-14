# Phase 2 — Search Product Gate

Дата: 2026-07-14

Статус: **implementation complete; automated gate green**.

## Граница безопасности

- Tantivy использует только `RamDirectory`. Decrypted body не записывается в
  отдельный search-файл и не отправляется на сервер.
- SQLCipher projection выбирает сообщения только exact authenticated
  `canonical_server_origin`. Originless legacy rows и строки другого Veil Node
  в rebuild не попадают.
- Search hit не является identity authority. Перед возвратом renderer native
  слой повторно загружает exact `message_id + conversation_id + origin` из
  SQLCipher и сравнивает body/sender key с RAM hit.
- Lock, смена account/origin/session epoch и новый rebuild инвалидируют
  кандидат. Native lock дополнительно заменяет опубликованный RAM index пустым.
- Ошибка или Cancel сохраняет предыдущий полный snapshot. Частичный candidate
  никогда не становится видимым поиску.

## Product contract

- Rebuild читает непустые сообщения newest-first через rowid keyset pages по
  512 строк; старого per-conversation `LIMIT 100000` нет.
- Один origin ограничен 64 MiB оценённого decrypted source и 250 000
  документами. В оценку входят body, message/conversation IDs, sender key и
  фиксированный overhead. Tantivy/allocator overhead не выдаётся за ровно
  64 MiB RAM.
- При достижении лимита индекс покрывает непрерывный новый срез истории, а UI
  явно сообщает, что более старая история не вошла.
- Ручной rebuild имеет Cancel. Completion DTO проверяется renderer по типам,
  безопасным целым числам и фиксированным bounds до отображения.

## Evidence

- `veil-search`: atomic replace, cancelled-candidate preservation, Cyrillic/
  prefix search и insert/delete tests.
- `veil-store`: exact-origin projection, exclusion пустых строк и keyset page
  continuation.
- `veil-desktop` native: source/document budget boundary и invalid sender-key
  rejection.
- Frontend: Kobalte combobox/listbox/focus contract, keyboard navigation,
  origin-scoped author identity и Cancel UX.
- Manual reproducible performance command:
  `cargo test -p veil-search --release measures_large_profile_atomic_rebuild -- --ignored --nocapture`.
  На текущей Windows-машине 2026-07-14: 100 000 документов, 0.192 s; результат
  hardware-specific и не является SLA.

## Не входит

- Серверный поиск, analytics по запросам и persistent plaintext index запрещены.
- Morphology/stemming для каждого языка и полная локализация относятся к
  поздней product/localization работе, а не к ослаблению privacy boundary.
