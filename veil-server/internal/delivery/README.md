# R11 River transaction experiment

Status: the River adapter passes the PostgreSQL experiment gate and is the
selected implementation candidate for R12. It is **not connected to the live
gateway**, push dispatcher, or deployment migrator. No second queue engine was
introduced. Production delivery still requires R07/R08 event semantics, R14a
device-bound registration, and authorization/retry/expiry contracts.

## Version and dependency inventory

River and riverpgxv5 are pinned to **v0.47.0**, upstream commit
`48c0036dcb12b1e2bb65c355593388bb7ff9926e` (verified through the Go module origin
and [upstream release](https://github.com/riverqueue/river/releases/tag/v0.47.0)).
The version uses Go 1.26 and pgx v5.10.0, matching Veil. The main migration line
is pinned to **TargetVersion 7**.

License files shipped in the exact downloaded modules were reviewed:

| Module | Version | Upstream license |
| --- | --- | --- |
| river, riverdriver, riverpgxv5, rivershared, rivertype | v0.47.0 | MPL-2.0 |
| tidwall/gjson | v1.19.0 | MIT |
| tidwall/sjson | v1.2.5 | MIT |
| tidwall/match | v1.2.0 | MIT |
| tidwall/pretty | v1.2.1 | MIT |
| golang.org/x/text | v0.41.0, upgraded from v0.40.0 | BSD-3-Clause |
| stretchr/testify, test dependencies | v1.12.1, upgraded from v1.11.1 | MIT |
| go.yaml.in/yaml/v3, test dependencies | v3.0.5 | MIT / Apache-2.0, per upstream file mapping |

See [River's exact license](https://github.com/riverqueue/river/blob/v0.47.0/LICENSE).
The adapter is not referenced by cmd/gateway; River modules are therefore not
linked into the gateway artifact yet. Its generated notice inventory still has
28 entries. Only the linked x/text version changed in the exact release allow
baseline. Production wiring must regenerate notices and review/add the actual
linked River/transitive module set at that time. River Pro is not used.

## Transaction boundary

`db.StoreMessageTx` extracts the existing StoreMessage implementation without
committing or rolling back its caller-owned pgx transaction. Existing
StoreMessage still owns begin/commit/retry. Secure transactions must remain
serializable. Security snapshots, reply scope and encrypted upload checks are
preserved. Message fields assigned inside the transaction cannot be published
until commit.

`Producer.InsertTx` verifies the reference resolves to the same stored message
and conversation inside that transaction, then calls River InsertTx. Args contain
only the two opaque UUID references. There are no copied keys, plaintext,
ciphertext, usernames or recipient lists. Queue uniqueness includes retained
completed jobs; it cannot replace Veil's longer-lived exact-send ledger.

The production idempotent send path still owns its separate transaction. R12
must join its existing ledger claim, mutation and InsertTx before the same
commit. The duplicate-send test checks real ledger replay plus queue dedup in
separate transactions; it does not claim this production join is implemented.

`Worker` calls an idempotent ReferenceHandler outside any caller-owned SQL lock,
with a bounded context and experiment retry policy. No production handler or
external network delivery is supplied. A future handler must load and check
current ACL, device binding, registration epoch and expiry before delivery.
An external HTTP effect is at least once even if local effect dedup is atomic.

## Migration boundary

`MigrateExperiment` uses a bounded advisory lock in one pool connection and
`rivermigrate.Migrate` in separate upstream transactions in another connection.
It requires at least two slots, pins target 7, validates that target and is safe
to rerun. The schema is `veil_delivery_experiment` in an isolated test database.

Do not put the combined `--all` export inside Veil's single-file transaction:
upstream enum and immutable-function migrations need separate commits. This is
documented by the [official migration guide](https://riverqueue.com/docs/migrations).
For deployment adoption, add an explicit pinned migration phase under the same
coordination used by the deployment migrator, before workers start; retain one
upstream transaction per step and run validation before readiness. The current
experiment lock is deliberately not advertised as production-wide coordination.

## Reproduction and evidence

Use Docker through the shared test harness, or set TEST_DATABASE_URL to a
dedicated local PostgreSQL server. The harness provisions and removes its own
temporary database; it does not apply experiment migrations to the supplied
maintenance database.

```powershell
cd D:/repos/veil/veil-server
$env:TEST_DATABASE_URL='postgres://postgres@127.0.0.1:55432/postgres?sslmode=disable'
go test -tags=integration ./internal/delivery -count=1 -v
```

Validated on PostgreSQL 16.15:

| Scenario | Evidence |
| --- | --- |
| Fresh migration and rerun | Pinned steps 1–7 apply and target validation succeeds twice |
| Rollback / visibility | Before commit another connection sees neither message nor job; rollback leaves neither |
| Job SQL insertion failure | Forced queue CHECK failure aborts the same transaction; no orphan message or job |
| Commit | One real StoreMessageTx row and one River job become visible together |
| Duplicate reference | Same reference returns the same job, before commit and in retained completed state |
| Duplicate send | Real HandleSendMessageResult exact replay retains the same message ID; repeated intent gives one row/job |
| Process crash | A child worker exits with code 42 after a committed idempotent effect and before River completion; job remains running |
| Restore | Fresh River worker and upstream leader/rescuer complete the same job with at least two attempts and one effect |
| Cleanup | Worker shutdown is bounded; schema and job rows are removed with the isolated harness database |

Crash recovery advances only attempted_at to make a stale attempt eligible.
The test does not manually transition the job to available/retryable: upstream
River rescue performs recovery. It does not simulate a PostgreSQL power loss,
test an actual push provider, or prove multi-gateway WebSocket fan-out.

## Choice after the experiment

| Candidate | Evidence / cost | Decision |
| --- | --- | --- |
| River + riverpgxv5 | Passed actual transaction, duplicate and process-death recovery checks; version and schema are pinned; reusable leases/rescue/maintenance | Keep this adapter as R12 candidate |
| Custom pgx outbox | Same database transaction is possible, but leases, fencing, rescue, retry and cleanup would need our own implementation and equivalent tests | No fallback is needed for the tested requirements |

References: [transactional enqueueing](https://riverqueue.com/docs/transactional-enqueueing),
[reliable workers](https://riverqueue.com/docs/reliable-workers),
[pinned InsertTx example](https://github.com/riverqueue/river/blob/v0.47.0/example_insert_and_work_test.go).
