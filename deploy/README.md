# Veil production deployment

This directory is the production path for `veil.erez.pro`. It deliberately
does not use the root development Compose file or its Caddy profile. The VPS
already owns public ports 80/443 with Nginx and routes TLS by SNI, so Veil uses
the following chain:

```text
internet :443 -> existing Nginx stream/SNI router
              -> PROXY protocol -> 127.0.0.1:4443 (Veil TLS vhost)
              -> 127.0.0.1:9080 (gateway container)

/downloads/*  -> Nginx static files under /srv/veil/releases/current/
```

The instructions assume the repository is checked out at `/opt/veil`, Docker
Compose v2 is installed, and all commands are run from `/opt/veil`.

## 1. DNS, secrets, and release directories

Point the `A` record for `veil.erez.pro` at the VPS. Add an `AAAA` record only
when IPv6 is actually routed to this host and the stream listener also binds
IPv6. Public firewall rules should allow TCP 80/443; ports 4443, 9080, 9081,
and PostgreSQL must not be public.

Create the deployment environment and replace every placeholder:

```sh
cp deploy/.env.example deploy/.env
chmod 0600 deploy/.env
openssl rand -hex 32       # VEIL_DB_PASSWORD
openssl rand -base64 32    # VEIL_UPLOAD_TOKEN_KEY
```

`VEIL_GATEWAY_IMAGE` is mandatory and must contain an immutable digest, for
example `ghcr.io/navelil/veil-gateway@sha256:...`; do not use `latest` or only a
tag. Set `VEIL_RELEASE_ID` to the matching Git tag or Git commit SHA and change
it for every rollout. This makes Compose recreate the completed migration job
when a release changes.

Keep `VEIL_ALLOW_REGISTRATION=false` while the managed Node is in closed
Preview. This setting blocks creation of first-time accounts but does not lock
out identities already registered on that Node. Opening registration is an
explicit operator decision and must be coordinated with the site's published
privacy and support information.

Closed Preview uses one-time Node Access links instead of opening public
registration. After migration `026_node_access_invites.sql` is applied, the
operator can generate a private batch from the running gateway image:

```sh
umask 077
docker compose -f deploy/compose.prod.yml --env-file deploy/.env exec -T gateway \
  /app/veil-admin invite create --count 20 --expires 168h \
  > node-access-invites.txt
```

Each output line is one independently random, single-use enrollment URL such
as `https://veil.erez.pro/enroll#invite=...`. The 256-bit bearer token is in the
URL fragment, so browsers do not send it in the HTTP request or Nginx access
logs. The database stores only its SHA-256 digest. Deliver each line privately
to exactly one tester; do not paste the batch into chat rooms, tickets, CI
output, or container logs. Securely delete the local file after distribution.
Expired, invalid, and already-used links have the same client-visible result.
Existing accounts continue to authenticate without a link, and
`VEIL_ALLOW_REGISTRATION=false` remains unchanged. One link authorizes exactly
one new account identity. Reconnecting that registered identity never needs
another link, and if an existing identity presents an unused link the server
does not consume it.

Make the GHCR package public, or authenticate Docker once with a dedicated
token that has only `read:packages`. Do not store that token in `deploy/.env`:

```sh
printf '%s' "$GHCR_READ_TOKEN" | docker login ghcr.io -u YOUR_GITHUB_USER --password-stdin
unset GHCR_READ_TOKEN
```

Create a dedicated account for release-file synchronization and the static
release and backup locations. The account name must match the `VPS_USER`
GitHub Actions secret used by the desktop release workflow:

```sh
if ! id -u veil-deploy >/dev/null 2>&1; then
  sudo useradd --system --create-home --home-dir /var/lib/veil-deploy \
    --shell /bin/sh veil-deploy
fi
sudo install -d -o veil-deploy -g www-data -m 0755 /srv/veil/releases
sudo install -d -o root -g root -m 0700 /srv/veil/backups
sudo install -d -o root -g root -m 0755 /var/www/letsencrypt/.well-known/acme-challenge
```

Install a release-only SSH public key in
`/var/lib/veil-deploy/.ssh/authorized_keys`, with the directory owned by
`veil-deploy` and modes `0700`/`0600`. Configure these repository secrets:

- `VPS_HOST=veil.erez.pro` (or the VPS address);
- `VPS_USER=veil-deploy`;
- `VPS_SSH_PRIVATE_KEY` containing the matching private key;
- `VPS_SSH_KNOWN_HOSTS` containing the independently verified host-key line;
- optional `VPS_SSH_PORT` (defaults to `22`).

Do not accept an unverified `ssh-keyscan` result inside CI: compare the
fingerprint against the host key over the existing trusted `erez-vps` session
before saving `VPS_SSH_KNOWN_HOSTS`.

Validate configuration before contacting a registry or starting containers:

```sh
docker compose -f deploy/compose.prod.yml --env-file deploy/.env config --quiet
```

## 2. First certificate and the existing Nginx SNI router

Confirm that the selected loopback listener is unused:

```sh
sudo ss -ltnp | grep ':4443 ' || true
```

Any listener in that output is a conflict; choose another free loopback port
and update both the final vhost and stream map together.

For the first certificate, install the HTTP-only bootstrap vhost:

```sh
sudo install -m 0644 deploy/nginx/veil.erez.pro.acme.conf /etc/nginx/sites-available/veil.erez.pro
sudo ln -sfn /etc/nginx/sites-available/veil.erez.pro /etc/nginx/sites-enabled/veil.erez.pro
sudo nginx -t
sudo systemctl reload nginx

ACME_EMAIL=security@erez.pro
sudo certbot certonly --webroot -w /var/www/letsencrypt \
  -d veil.erez.pro --email "$ACME_EMAIL" --agree-tos --no-eff-email
```

Replace the bootstrap vhost with the final loopback TLS vhost:

```sh
sudo install -m 0644 deploy/nginx/veil.erez.pro.conf /etc/nginx/sites-available/veil.erez.pro
sudo nginx -t
sudo systemctl reload nginx
```

Before publishing the managed-service privacy notice, verify that the host's
existing Nginx logrotate policy covers `/var/log/nginx/veil.erez.pro.*.log`
with `daily` and `rotate 14` (the Debian/Ubuntu Nginx package normally uses one
global rule for `/var/log/nginx/*.log`):

```sh
sudo sed -n '1,120p' /etc/logrotate.d/nginx
sudo logrotate --debug /etc/logrotate.d/nginx
```

Do not install a second rule for the same files: logrotate rejects duplicate
log entries. If the host policy differs, change it deliberately and update the
privacy notice before accepting accounts.

In `/etc/nginx/stream.d/sni_routing.conf`, add the Veil destination to the
existing `map $ssl_preread_server_name $backend` block:

```nginx
veil.erez.pro 127.0.0.1:4443;
```

The existing stream listener must continue to use its current `$backend` route,
`ssl_preread on`, and PROXY protocol:

```nginx
proxy_pass $backend;
proxy_protocol on;
ssl_preread on;
```

Do not create a second public 80/443 listener and do not enable the repository's
Caddy profile. After editing the stream map, run `sudo nginx -t` before reload.
The final HTTP vhost accepts PROXY protocol only, so a direct TLS connection to
127.0.0.1:4443 without the stream frontend is expected to fail.

Test certificate renewal after installation:

```sh
sudo certbot renew --dry-run
```

## 3. Backup gate before migrations

Start only PostgreSQL first:

```sh
docker compose -f deploy/compose.prod.yml --env-file deploy/.env up -d postgres
docker compose -f deploy/compose.prod.yml --env-file deploy/.env exec -T postgres \
  pg_isready -U veil -d veil
```

For a fresh empty database, continue to the next section. For every existing
database, stop writes and make an off-host-capable backup before changing the
checkout, `VEIL_RELEASE_ID`, or running migrations:

```sh
docker compose -f deploy/compose.prod.yml --env-file deploy/.env stop gateway
BACKUP_ID="$(date -u +%Y%m%dT%H%M%SZ)"
docker compose -f deploy/compose.prod.yml --env-file deploy/.env exec -T postgres \
  pg_dump -U veil -d veil -Fc | sudo tee "/srv/veil/backups/veil-${BACKUP_ID}.dump" >/dev/null
sudo test -s "/srv/veil/backups/veil-${BACKUP_ID}.dump"

docker run --rm \
  -v veil_uploadsdata:/source:ro \
  -v /srv/veil/backups:/backup \
  alpine:3.21 sh -c "cd /source && tar -czf /backup/veil-uploads-${BACKUP_ID}.tar.gz ."
```

If the `push` profile has been used, back up `veil_ntfydata` the same way. Copy the
dump and archives to separate storage, and verify the PostgreSQL dump with
`pg_restore --list` before proceeding. A live copy of `veil_pgdata` is not a
substitute for `pg_dump` or a coordinated filesystem snapshot.

Three migrations are intentionally destructive and require explicit acceptance:

- `023_veil_links_and_bans.sql` drops/recreates invite data, removes voice-room
  channel rows, and drops `servers.icon_url`;
- `025_webpush_cutover.sql` deletes all existing push subscriptions;
- `028_reaction_history_bound.sql` removes invalid legacy reaction-scope rows
  and deterministically retains only the oldest 256 reactions per message.

If any of that data must survive, stop here and write a conversion migration.
An application image rollback cannot undo these database changes.

## 4. Migrate and start

The checked-out SQL files and `VEIL_GATEWAY_IMAGE` must represent the same
release. Force removal of an old completed migration container, then start the
stack. Gateway startup is gated on a successful one-shot migration:

The gateway runs as the fixed unprivileged UID/GID `10001:10001`. Fresh named
volumes receive the correct ownership automatically. If `veil_uploadsdata` was
created by an older root-running image, repair it once before the rollout:

```sh
docker compose -f deploy/compose.prod.yml --env-file deploy/.env run --rm \
  --no-deps --user 0 --cap-add CHOWN --entrypoint sh gateway \
  -c 'chown -R 10001:10001 /var/veil/uploads'
```

`CHOWN` is restored only for this one-shot repair; the normal gateway keeps
`cap_drop: [ALL]`. Do not make the uploads volume world-writable as a shortcut.

```sh
docker compose -f deploy/compose.prod.yml --env-file deploy/.env rm -sf migrate
docker compose -f deploy/compose.prod.yml --env-file deploy/.env pull postgres gateway
docker compose -f deploy/compose.prod.yml --env-file deploy/.env up -d
docker compose -f deploy/compose.prod.yml --env-file deploy/.env ps --all
docker compose -f deploy/compose.prod.yml --env-file deploy/.env logs --no-log-prefix migrate
```

Expected state: PostgreSQL and gateway are healthy, and `migrate` exited with
code 0. If migration fails, do not bypass the dependency or force-start the new
gateway. Inspect the failed SQL and the migration ledger; earlier migration
files may already have committed.

The ntfy service is disabled by default. Enable it only after provisioning a
separate public TLS vhost such as `push.veil.erez.pro` that proxies to loopback
9081:

```sh
docker compose -f deploy/compose.prod.yml --env-file deploy/.env \
  --profile push up -d ntfy
```

## 5. Publish release files atomically

Place one complete release in a versioned directory, including its generated
`latest.json`, verify checksums, and then switch the relative `current` symlink
atomically:

```sh
RELEASE_ID=v0.1.0
sudo install -d -o root -g www-data -m 0755 "/srv/veil/releases/${RELEASE_ID}"
# Copy stable-name assets, SHA256SUMS, and latest.json into this directory.
cd "/srv/veil/releases/${RELEASE_ID}"
sha256sum -c SHA256SUMS
cd /srv/veil/releases
sudo ln -sfn "${RELEASE_ID}" .current.next
sudo mv -Tf .current.next current
```

Nginx serves `/downloads/` directly and supports byte ranges; release files are
not baked into the gateway image. `latest.json` is the atomic machine-readable
version/asset manifest used by the landing page. CI should upload the complete
directory first and move `current` only after checksum verification.

## 6. Health and smoke checks

```sh
docker compose -f deploy/compose.prod.yml --env-file deploy/.env ps --all
# Process liveness:
curl -fsS http://127.0.0.1:9080/health
# Database-backed readiness, locally and through the public TLS route:
curl -fsS http://127.0.0.1:9080/readyz
curl -fsS https://veil.erez.pro/readyz
openssl s_client -connect veil.erez.pro:443 -servername veil.erez.pro </dev/null

# Expect HTTP 206 and Content-Range for an existing release file.
curl -fsS -D - -o /dev/null -H 'Range: bytes=0-1023' \
  https://veil.erez.pro/downloads/Veil-linux-x86_64.AppImage

curl -fsS https://veil.erez.pro/downloads/latest.json

# Expect HTTP 101 Switching Protocols.
curl --http1.1 -i --max-time 5 \
  -H 'Connection: Upgrade' -H 'Upgrade: websocket' \
  -H 'Sec-WebSocket-Version: 13' \
  -H 'Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==' \
  https://veil.erez.pro/ws
```

Also verify that `ss -ltnp` shows 4443, 9080, and optional 9081 only on
127.0.0.1 and that PostgreSQL has no host port. Container logs rotate at 10 MiB
with five files per service, but disk and offsite-backup monitoring remain host
operator responsibilities.
