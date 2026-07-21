# PostgreSQL 18 upgrade gate

The beta integration history contains the PostgreSQL 18 Dependabot changes,
but the active development and production Compose defaults remain on
PostgreSQL 16. This is intentional and prevents an automatic major-version
cutover from presenting an empty database or making an existing volume
unusable.

The official PostgreSQL 18 container changes its default `PGDATA` to
`/var/lib/postgresql/18/docker` and its persistent-volume mount point to
`/var/lib/postgresql`. Existing Veil volumes were created with PostgreSQL 16 at
`/var/lib/postgresql/data`; changing only the image tag is not an upgrade.

PostgreSQL 18 may become the default only after all of the following evidence
is attached to a dedicated migration PR:

1. Stop gateway writes and create a custom-format `pg_dump` from PostgreSQL 16.
2. Verify the dump with `pg_restore --list` and copy it off host.
3. Create a fresh, separately named PostgreSQL 18 volume mounted at
   `/var/lib/postgresql`; never reuse or delete the PostgreSQL 16 volume.
4. Restore into the fresh cluster, run the complete Veil migration ledger, and
   compare row counts and integrity checks for every security-critical table.
5. Run gateway readiness, Go integration tests, desktop and Android message,
   attachment, restart, and backup/restore smoke tests against the restored
   cluster.
6. Prove rollback by stopping PostgreSQL 18 and restarting the previous Veil
   release against the untouched PostgreSQL 16 volume. PostgreSQL 16 must never
   be pointed at PostgreSQL 18 data files.

Until that gate is green, operators can evaluate PostgreSQL 18 only with a
disposable database and an explicit image override. Production deployments
must retain the pinned PostgreSQL 16 image from `deploy/.env.example`.
