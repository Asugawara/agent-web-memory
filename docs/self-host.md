# Self-hosting the awm team server

This guide takes a first-time admin from an empty host to a running team server, a first admin and an approved second device, and then covers what an operator has to keep doing: backups, restore drills, upgrades, rotation and the `awm serve check` audit.

The server is one binary, `awm serve`. It terminates TLS itself (Let's Encrypt, no proxy needed), writes its own backups and refuses unsafe settings at start. Everything it stores is end-to-end encrypted by the members' machines; the operator cannot read the team's notes (see [what the operator can see](#what-the-operator-can-and-cannot-see)).

Contents: [Choose a path](#choose-a-path) · [Before you start](#before-you-start) · [Path A](#path-a-managed-on-google-cloud) · [Path B](#path-b-a-vm-on-google-cloud) · [Path C: systemd](#path-c-any-linux-host-with-systemd) · [Path D: docker compose](#path-d-docker-compose) · [First admin](#create-the-team-first-admin-and-first-member) · [TLS](#tls) · [Backup](#backup) · [Restore](#restore-and-re-seed) · [check](#awm-serve-check) · [Upgrades](#upgrades) · [Rotation and removal](#rotation-and-removal) · [IAP](#identity-aware-proxy-a-later-option) · [Threat model](#threat-model-summary)

## Choose a path

| | path | you run | about | needs |
|---|---|---|---|---|
| A | Managed on Google Cloud (recommended; **not yet available (TM28)**) | `scripts/selfhost/gcp/cloudrun.sh --project P` in Cloud Shell | 20 min | a Google account with a billing account; no domain |
| B | A VM on Google Cloud (**not yet available (TM28)**) | `scripts/selfhost/gcp/vm.sh --project P [--domain HOST]` in Cloud Shell | 10 min | the same; a domain is optional |
| C | Any Linux host | the release binary and `deploy/systemd/awm-serve.service` | 10 min | a host with a public IPv4 address and port 443; a domain or a static address; a bucket or a second disk for backups |
| D | docker compose on any host | `deploy/compose/docker-compose.yml` and a `.env` | 10 min | a Docker host as in C |

All four run the same binary and the same protocol, and all four end with `awm serve check` and the three client commands of [Create the team](#create-the-team-first-admin-and-first-member). The minutes are targets, not measurements; the first measurement is the DT1 report.

## Before you start

- **One organisation per server.** A self-hosted server serves one team. Several teams, several servers.
- **Members need to reach it over HTTPS.** The server is meant to be reachable from the public internet: invites, device tokens and end-to-end encryption are the access model, and no VPN is assumed. The client refuses `http://` URLs except on loopback.
- **A name or an address that stays.** A DNS name is best. A bare IP address works (an IP certificate, see [TLS](#tls)) only if the address is static. Wildcard-DNS names such as `sslip.io`, `nip.io`, `xip.io` and `traefik.me` are refused by the server (see [TLS](#tls) for why).
- **Port 443 reachable from the internet** (path C and D without your own proxy): Let's Encrypt validates your certificate there. Port 80 stays closed unless you choose the HTTP-01 challenge.
- **A backup target.** Without one, `awm serve check` prints `WARN backup` and a disk loss destroys membership, invites and key wraps. Decide before you go live; see [Backup](#backup).
- **The client.** Every admin and member needs the `awm` client with sync support (`awm team --help` lists `create`, `invite`, `join`, `approve`). The server binary and the client are the same executable.

## Path A: managed on Google Cloud

*The scripts land in TM28; this section uses the command names of the plan and will be completed against the scripts' own output.*

1. Sign in to Google Cloud with a billing account and open Cloud Shell. Creating a billing account is not part of the 25 minutes.
2. Run `scripts/selfhost/gcp/cloudrun.sh --project P` (add `--dry-run` first to print every `gcloud` command without running it). It enables the APIs, creates a Cloud SQL for PostgreSQL instance with backups and point-in-time recovery, two database users, a runtime service account, a Cloud Run service and a budget alert. Cloud SQL takes 5-12 minutes to create: install `awm` on your machine meanwhile.
3. The script prints the `https://...run.app` URL and the bootstrap command. Continue with [Create the team](#create-the-team-first-admin-and-first-member).
4. Admin commands run as a Cloud Run job: `gcloud run jobs execute awm-admin --args=serve,check,--json` (likewise `promote HANDLE`, `restore --mark-restored`, `backup --verify`).

On this path Google terminates TLS, restarts the process and patches the platform; the `files`, `listen` and reboot checks do not apply and `awm serve check` reports Cloud Run and Cloud SQL settings instead.

## Path B: a VM on Google Cloud

*The script lands in TM28.*

Run `scripts/selfhost/gcp/vm.sh --project P [--domain HOST]` in Cloud Shell. It creates an e2-micro Debian VM with a static IPv4 address, a firewall that opens 443 only, SSH through IAP TCP forwarding only, unattended security upgrades, a Cloud Storage bucket for backups writable only by the VM's service account, and installs the release binary under the unit of [path C](#path-c-any-linux-host-with-systemd) running `awm serve --domain HOST --data /var/lib/awm --backup gs://BUCKET/awm`. Without `--domain` the VM's static address gets an IP certificate. Then continue with [Create the team](#create-the-team-first-admin-and-first-member).

## Path C: any Linux host with systemd

You need root on the host, port 443 open to the internet, and DNS for your name pointing at the host (or a static public IP address).

**1. Get the binary and check it.** Download the release archive for your platform and `SHA256SUMS` from the project's releases page, and verify:

```sh
sha256sum --check --ignore-missing SHA256SUMS
tar xzf awm-VERSION-x86_64-unknown-linux-gnu.tar.gz
install -m 0755 awm /usr/local/bin/awm
awm --version
```

(Building from a checkout works too: `cargo build --release --locked --features sync,serve -p agent-web-memory`, then install `target/release/awm`.)

**2. Create the service user and the state directory.**

```sh
useradd --system --home-dir /var/lib/awm --shell /usr/sbin/nologin awm
install -d -m 0700 -o awm -g awm /var/lib/awm
```

**3. Write the configuration.** The unit reads `/etc/awm/serve.env`; `awm serve` reads these variables itself.

```sh
install -d -m 0755 /etc/awm
install -m 0600 /dev/null /etc/awm/serve.env
```

Put in `/etc/awm/serve.env` (one line each):

```text
AWM_DOMAIN=awm.example.com
AWM_BACKUP=gs://example-awm-backup/awm
AWM_ACME_EMAIL=you@example.com
```

`AWM_DOMAIN` can be a static IP address instead. `AWM_BACKUP` is `gs://`, `s3://` or `file:///PATH`; see [Backup](#backup). If your own TLS proxy sits in front on the same host, leave out `AWM_DOMAIN` and set `AWM_BEHIND_TLS_PROXY=1` and `AWM_TRUSTED_PROXY=127.0.0.1/32` instead; the server then listens on `127.0.0.1:8787` (plain HTTP, the default) and the proxy forwards to it.

**For Postgres** (instead of the SQLite database in `/var/lib/awm`): the server does not read the URL from a variable of that name. `AWM_DATABASE_URL_ENV=NAME` names the variable that holds it, so put both in `serve.env`:

```text
AWM_DATABASE_URL_ENV=PG_URL
PG_URL=postgres://awm:PASSWORD@HOST/awm
AWM_DATABASE_URL_OWNER_ENV=PG_OWNER_URL
PG_OWNER_URL=postgres://awm_owner:PASSWORD@HOST/awm
AWM_BEHIND_TLS_PROXY=1
AWM_TRUSTED_PROXY=127.0.0.1/32
```

`AWM_DATABASE_URL_OWNER_ENV` (optional) names the variable with the URL used for migrations. `--data` and a database URL are exclusive (exit 2), and the shipped unit passes `--data`, so Postgres needs a systemd drop-in that replaces `ExecStart=` with one that has no `--data`; install it in step 5 instead of changing the unit:

```sh
install -d /etc/systemd/system/awm-serve.service.d
install -m 0644 deploy/systemd/awm-serve-postgres.conf.example /etc/systemd/system/awm-serve.service.d/postgres.conf
```

(`systemctl edit awm-serve` with the two lines of that file does the same.) Postgres also means `AWM_BEHIND_TLS_PROXY=1` and your own TLS proxy: `--domain` is refused because the ACME account and certificate live in `{data}/acme`, and there is no data directory. Leave out `AWM_DOMAIN`. In step 4 run `init` without `--data`, with the same settings loaded as in step 6 (`sh -c 'set -a; . /etc/awm/serve.env; exec sudo --preserve-env -u awm awm serve init'`). `AWM_DATABASE_INSECURE_NETWORK=1` permits a Postgres host that is not loopback, a private range or the Cloud SQL socket; without it such hosts are refused and `awm serve check` reports `WARN` when it is set.

**4. Create the database and the bootstrap token.** Run this in a terminal; it prints the token once, and never into a log:

```sh
sudo -u awm awm serve init --data /var/lib/awm
```

The output ends with `bootstrap token (single use, valid 24 h, shown once)`. Copy it. If you lose it, run the command again (it replaces the unused token).

**5. Install and start the unit.**

```sh
install -m 0644 deploy/systemd/awm-serve.service /etc/systemd/system/awm-serve.service
systemctl daemon-reload
systemctl enable --now awm-serve
journalctl -u awm-serve -n 50
```

The unit grants only `CAP_NET_BIND_SERVICE` (to bind 443 as the unprivileged `awm` user), restarts the process whenever it stops, and makes everything except `/var/lib/awm` read-only; the reasons for each line are in the file's comments. For a `file://` backup target on another disk add `ReadWritePaths=/mnt/your-backup-disk` to the unit.

**6. Check it.**

```sh
sudo -u awm awm serve check --data /var/lib/awm
```

Right after a first start the certificate may still be on its way: wait a minute and run it again. Read [`awm serve check`](#awm-serve-check) for what each line means. Then continue with [Create the team](#create-the-team-first-admin-and-first-member).

`check` is a separate process, so it must see the same settings as the server. The command above does not read `/etc/awm/serve.env`; load it first (as root):

```sh
sh -c 'set -a; . /etc/awm/serve.env; exec sudo --preserve-env -u awm awm serve check --data /var/lib/awm'
```

Or put the settings in `/var/lib/awm/server.toml` (mode 0600, owned by `awm`; the keys are the flag names with underscores, for example `domain`, `backup`, `acme_email`) so the server and every command read the same file. Without the settings `check` describes a different configuration (for example "loopback only").

## Path D: docker compose

You need Docker with the compose plugin, port 443 open to the internet and DNS for your name pointing at the host.

```sh
cd deploy/compose
cp env.example .env
chmod 600 .env
$EDITOR .env          # set AWM_DOMAIN and AWM_BACKUP
docker compose up -d
docker compose exec awm awm serve init
docker compose exec awm awm serve check
```

- The image runs as a non-root user (uid 65532), keeps its state in the named volume `awm-data` mounted at `/data`, listens on 8443 inside (published as 443) and restarts with `restart: unless-stopped`. Its health check is `awm serve healthcheck`, which asks the local `/healthz`.
- `docker compose exec` allocates a terminal, which `awm serve init` needs to print the token. Do not add `-T` and do not pipe the output; without a terminal it prints nothing secret.
- To build the image from a checkout instead of pulling it: `docker compose up -d --build` (or `docker build -t awm:dev .` in the repository root and `AWM_IMAGE=awm:dev` in `.env`).
- **A named volume starts with the right owner.** If you replace it with a host directory (`./data:/data`), make it owned by uid 65532 with mode 0700: `chown 65532:65532 ./data && chmod 0700 ./data`. The server refuses to start on a data directory that others can read.
- **HTTP-01 instead of TLS-ALPN-01** (only when something in front of 443 cannot pass the ALPN challenge): in `.env` set `AWM_ACME_CHALLENGE=http-01` and `AWM_ACME_HTTP_LISTEN=0.0.0.0:8080`, and uncomment `"80:8080"` in the compose file.
- **A team with its own TLS proxy** (Caddy, nginx, a load balancer): in `.env` leave `AWM_DOMAIN` empty and set `AWM_BEHIND_TLS_PROXY=1` and `AWM_TRUSTED_PROXY=` (the proxy's address range, for example `172.18.0.0/16`); in the compose file replace `"443:8443"` by `"127.0.0.1:8443:8443"` (or put the proxy on the same compose network) and point the proxy at `http://127.0.0.1:8443`. The server then speaks plain HTTP to the proxy only, and believes `X-Forwarded-For` only from the range you named. The certificate, HSTS and renewal are the proxy's job.
- **With Cloud Run's managed proxy**: set `AWM_TRUSTED_PROXY=cloud-run` (requires `K_SERVICE` environment variable to be set by Cloud Run).
- **The container refuses to start** (and compose restarts it every few seconds) when neither `AWM_DOMAIN` nor `AWM_BEHIND_TLS_PROXY` is set: the log says why (`docker compose logs awm`). That is the safe default, not a bug.

Continue with [Create the team](#create-the-team-first-admin-and-first-member).

## Create the team: first admin and first member

On your own machine (the one that will be the first admin), with the URL of your server and the bootstrap token from `awm serve init`:

```sh
awm team create https://awm.example.com --token awm_b_... --handle yourname
awm team invite --handle alf
```

`create` makes the team's key on your machine and registers you as the admin. A used or expired token is refused with "run awm serve init for a new one". `invite` prints a command to send to `alf` through a channel you trust (a direct message, not a public channel):

```sh
awm team join https://awm.example.com --token awmi1_...
```

The invite works once and for 7 days (`--expires 1d` to `30d`; `--admin` makes an admin). `alf`'s `join` prints a 6-digit code and a fingerprint and waits. Read the code to you by voice or in a call (not the same channel as the invite): that comparison is what stops a server that swaps keys. Then:

```sh
awm team approve alf --code 123456
```

After the next `awm sync` on `alf`'s machine the member is in. `awm team members` and `awm team status` show the roster and the state on either machine.

A background `awm sync` also runs after your agents capture, so a manual run can print `pushed 0` although everything is on the server. `awm team status` shows the last successful sync and the outbox (0 means nothing is waiting).

Then do three things today:

1. **Make a second admin**, so that losing your laptop is not losing the team: invite one with `awm team invite --handle second --admin`, then approve as above. The `tokens` line of the check warns while there is one admin.
2. **Run `awm serve check`** and fix every `FAIL`; read every `WARN`.
3. **Run a restore drill** ([Restore](#restore-and-re-seed)) on a scratch host before real notes arrive.

**First backfill with many records:** The default rate limits are 60 requests per minute and 5,000 records per member per day; importing more than 5,000 records as a first backfill takes days. To speed it up as an admin, set higher limits temporarily in `server.toml`: `requests_per_minute = 300` and `records_per_day = 50000` at the top level (not under a `[table]`), then restore the defaults afterwards. Restart the server for the changes to take effect.

## TLS

- **The default is a Let's Encrypt certificate that the binary gets and renews itself**, for the name in `AWM_DOMAIN` / `--domain`, over TLS-ALPN-01 on port 443. Nothing else needs to be open. It is kept in `{data}/acme/` (`account.json`, `cert.pem`, `key.pem`, mode 0600 in a 0700 directory) so restarts, upgrades and container re-creation never re-issue. Renewal follows the CA's renewal information window; after a failed order the server backs off 1, 10 and 60 minutes. TLS 1.2 and 1.3 only; `Strict-Transport-Security` on every response.
- **A bare IP address** (`AWM_DOMAIN=203.0.113.7`) gets an IP-address certificate, which Let's Encrypt issues only under its `shortlived` profile (valid about 160 hours, renewed every few days). The address must be static and public. `check` fails when fewer than 2 days remain (7 for a DNS name).
- **HTTP-01** (`--acme-challenge http-01`, `AWM_ACME_CHALLENGE=http-01`) for hosts where something in front of 443 cannot pass the ALPN challenge. It opens a listener on port 80 (`--acme-http-listen`, default `0.0.0.0:80`) that answers only `/.well-known/acme-challenge/` and redirects everything else to HTTPS. DNS-01 is not offered: it would put DNS credentials on the server.
- **Your own proxy**: `--behind-tls-proxy` with `--trusted-proxy CIDR` (repeatable). Exclusive with `--domain`. `awm serve` sends `Strict-Transport-Security` on every response whether it terminates TLS itself or the proxy does.
- **Why `sslip.io`, `nip.io`, `xip.io` and `traefik.me` are refused**: Let's Encrypt limits certificates per registered domain (50 a week), and those services are not on the Public Suffix List, so every user of one shares a single budget; your issuance would fail on someone else's traffic. Use a domain you own (a subdomain of one is fine) or a static IP address.
- **Rate limits and restores.** A restore onto a new host re-issues the certificate (the certificate and key are never in the backup), which counts against Let's Encrypt's 5 certificates per identical name per week. Drills should use `--acme-staging` (`AWM_ACME_STAGING=1`) or a drill hostname.
- **A server behind an internal CA**: members pass `--ca-file PEM` to `awm team create` and `awm team join`.

## Backup

The server writes its own backups when `--backup` (`AWM_BACKUP`) is set:

- **Targets**: `gs://BUCKET/PREFIX` (Google Cloud Storage), `s3://BUCKET/PREFIX` (Amazon S3, or an S3-compatible store through `AWS_ENDPOINT_URL`), `file:///PATH` (a directory, ideally on another disk or machine). No credentials in the URL; the server uses the host's identity.
- **What it writes**: a full snapshot at start, daily, after a migration and after a restore, and a small incremental change set every 60 seconds when something changed. Full snapshots are kept 7 days with the change sets since the oldest kept one; the server deletes older objects itself. A recovery point of about a minute for membership changes; the research records lost in that minute are re-pushed by their authors' machines (see [re-seed](#restore-and-re-seed)).
- **What is not in it**: the ACME account and certificate (re-issued on restore), `server.toml`.
- **Uploads are create-only**: two servers writing to one prefix fail loudly (`FAIL backup`, "another server writes to ...") instead of interleaving. One prefix per server.
- **Verification**: weekly the server restores its own latest chain into a temporary directory and compares row counts and table hashes. Run it on demand with `awm serve backup --verify`. `check` warns after 30 days without a success and fails after a failed one.
- **Memory**: an object is buffered in memory for its single upload, so a full snapshot needs about its own size in RAM while it uploads. A year-old 10-member server is a few hundred MiB: size a tiny VM accordingly.

**Google Cloud Storage bucket settings** the server assumes (the commands below were not run by TM29; the TM28 scripts create the bucket this way):

| setting | value | why |
|---|---|---|
| soft delete | 0 days | otherwise deleted objects survive and the 8-day deletion promise does not hold |
| object versioning | off | the same |
| access | uniform bucket-level access, public access prevention enforced | a backup is private metadata and ciphertext |
| lifecycle | delete objects older than 30 days | a backstop only; a server stopped for more than 30 days then loses its last snapshot, so do not leave it stopped |
| identity | the VM's service account with `roles/storage.objectUser` on this bucket only | the server must create, read, list and delete; `objectCreator` alone cannot list or read. No key file: `gcloud iam service-accounts keys list --managed-by=user` should print nothing |

```sh
gcloud storage buckets create gs://example-awm-backup --location=us-central1 \
  --uniform-bucket-level-access --public-access-prevention --soft-delete-duration=0
gcloud storage buckets add-iam-policy-binding gs://example-awm-backup \
  --member=serviceAccount:awm-vm@PROJECT.iam.gserviceaccount.com --role=roles/storage.objectUser
```

Add the 30-day lifecycle rule with `gcloud storage buckets update gs://example-awm-backup --lifecycle-file=lifecycle.json`, where the file holds `{"rule":[{"action":{"type":"Delete"},"condition":{"age":30}}]}`.

**Amazon S3 and others**: the bucket must support conditional writes (`If-None-Match: *`); Amazon S3 does. A store without them fails every upload and `check` reports `FAIL backup`. Credentials come from an instance role or the standard `AWS_*` environment variables (set them in `/etc/awm/serve.env` or `.env` only when no role is available). Keep the bucket private and encrypted.

**`file://`**: the target directory is created 0700, objects 0600. On Docker mount a second disk and use `AWM_BACKUP=file:///backup`; a directory inside the same volume protects against a corrupted database but not against losing the disk.

**Migration copies.** Before a schema migration the server keeps `server.db.bak-vN` next to the database. They hold every record of that moment, including ones deleted later. The hourly task removes them by the rule under [Restore](#restore-and-re-seed) (once older than the oldest kept full snapshot, or after 8 days without a backup target); there is nothing to delete by hand.

**Disk encryption**: backup objects hold the same ciphertext and metadata as the database and are not encrypted again by awm. Use an encrypted disk for the data directory and a private bucket.

## Restore and re-seed

A restore drill takes minutes; do one before you rely on the server. On a fresh host (or an empty data directory) with the same binary:

```sh
awm serve restore --from gs://example-awm-backup/awm --data /var/lib/awm
```

- It picks the latest full snapshot at or before `--at TIME` (Unix seconds or RFC 3339) and the change sets that follow, verifies every object against its manifest and `PRAGMA integrity_check`, writes a **new `generation`** and prints the counts and the date by which the retention task removes the `pre-restore` copy. Nothing is written until every check passes. Corruption exits 3.
- The server holds `{data}/server.lock` while running. Stop the server (`systemctl stop awm-serve`, `docker compose down`) before `--force`: the command refuses while `{data}/server.lock` is held; that lock is its only check for a running server.
- It refuses a directory that already holds `server.db` (exit 2) unless `--force`, which first renames the old `server.db` to `server.db.pre-restore-TIME`. After `restore --force`, the `server.db.pre-restore-*` copy (and any `server.db.bak-vN` files from migrations) are removed once they are older than the oldest kept full snapshot, or after 8 days when no backup target is configured.
- Run it as the service user (`sudo -u awm ...`) so the files are owned correctly. Then start the server (`systemctl start awm-serve`, `docker compose up -d`). Its first snapshot after a restore is written to the target in the new generation; the old generation stays in the lineage, so it is not mistaken for a second writer.
- A restore onto a new host issues a new certificate (see [TLS](#tls)). Point DNS at the new host first.

**What members' machines do**: every machine holds its owner's own records, so a server restored from a slightly older backup is repaired by its clients. A client that sees the new `generation` re-pushes its own records above the server's head and re-sends its deletions. Until an **admin** machine has synced, removals and token revocations made after the backup point are not yet in force and non-admin pushes get `503 restore_pending`: **run `awm sync` on an admin's machine immediately after a restore**. Devices and invites created after the backup point stop working (`awm doctor` on that machine says to ask an admin for a new invite).

After a Cloud SQL restore or clone (path A), only the generation changes: `awm serve restore --mark-restored --database-url-env NAME`.

## `awm serve check`

`awm serve check [--json] [--external]` audits the configuration and the store and prints one line per check. Exit codes: 0 all `OK`, 1 at least one `WARN`, 2 at least one `FAIL`. `--json` gives the same as objects (use it from monitoring). `--external` also fetches `https://DOMAIN/v1/info` from this host, a check that the public name reaches the server. Run it after install, after every upgrade and after every restore, and as the same user and environment as the server (see [path C](#path-c-any-linux-host-with-systemd), step 6).

```text
awm serve check  (awm 0.2.0, proto 1, store sqlite /var/lib/awm/server.db)
OK    listen       0.0.0.0:443 (tls), no other listener of this process; host listeners on public addresses: 22/tcp (sshd)
OK    tls          acme tls-alpn-01, awm.example.com, expires in 41 d, ARI window 2026-11-02..2026-11-05, cache 0700/0600
OK    files        /var/lib/awm 0700, server.db 0600, server.toml 0600, owner awm
OK    database     integrity ok, schema 1, 12.4 MB, disk 71% free
WARN  backup       NO BACKUP TARGET: a disk loss destroys membership, invites, key wraps and every record
                   no member still holds; set --backup gs://... (docs/self-host.md#backup)
OK    versions     min_client 0.2.0 (release floor 0.2.0)
WARN  tokens       1 admin (promote a second: awm serve promote HANDLE); 2 devices unseen for 90 d; 0 open invites
OK    credentials  no key file; Google identity from the metadata server
OK    limits       per-IP and per-token limits on; trusted proxies: none
OK    retention    last run 2026-10-02 14:00 (hourly), 365 d
OK    health       /healthz 200
result: 2 warnings, 0 failures
```

| line | what it checks | `WARN` / `FAIL`: meaning and fix |
|---|---|---|
| `listen` | the addresses this process listens on and whether they are public; the host's other public listeners | **FAIL** plain HTTP on a public address: start with `--domain` or `--behind-tls-proxy` (the server refuses this at start, exit 2, so FAIL means a different process or an old config). |
| `tls` | built-in ACME: challenge, name, days left, renewal window, cache modes; or "terminated by the proxy in front" | **FAIL** no certificate yet (first start: wait and re-run; still failing: port 443 not reachable from the internet, DNS wrong, or the CA refused: read the log), expiry within 7 days (2 for IP certificates), or an ACME error older than a day; **WARN** an ACME error under a day old, or port 80 open while the challenge is TLS-ALPN-01 (close it; it is not needed). |
| `files` | modes of the data directory, `server.db`, `acme/*` and `server.toml`, and the owner | **FAIL** any readable by group or others: `chmod 700` the directory and `chmod 600` the files (the server also refuses to start on this). Not applicable on Postgres. |
| `database` | `PRAGMA integrity_check`, schema version, size, free disk | **FAIL** integrity failure (restore from backup, see above) or no database (run `awm serve init`); **WARN** under 20% free disk: grow the disk. |
| `backup` | the backup target and its recent history | **WARN** no target (set `--backup`), or no successful `awm serve backup --verify` in 30 days (run it, then read the error). **FAIL** the last upload failing for over an hour (permissions, bucket settings, connectivity: the line carries the error), no full snapshot in 48 hours, another server writing to the same prefix (stop one; each server needs its own prefix, restart the survivor), or the last verification failed (the backup cannot be trusted: fix and re-run `--verify`). |
| `versions` | the server's `min_client` against the release floor | **FAIL** `min_client` below the floor shipped with this binary: raise it with `awm team policy set min_client=VERSION` (it can only be raised). |
| `tokens` | admins, devices unseen for 90 days, open invites | **WARN** no admin yet (run `awm serve init` and `awm team create`), one admin only (promote a second), or devices unseen for 90 days (remove the member or the device if it is gone, see [Rotation and removal](#rotation-and-removal)). |
| `credentials` | key files in the environment | **WARN** `GOOGLE_APPLICATION_CREDENTIALS` (or another key-file variable) is set: use the host's attached service account or an instance role instead, delete the key. |
| `limits` | rate limits and trusted proxies | always `OK`; shows what is configured. With a proxy, confirm your proxy range is listed. |
| `retention` | the hourly retention job | always `OK`; **FAIL** only when its state cannot be read. `no run yet` right after a first start is normal. |
| `health` | `GET /healthz` on the local listener; a pending reboot | **FAIL** `/healthz` answers something other than 200; **WARN** not reachable (is the server running? run `check` as the same user) or `/var/run/reboot-required` is present (restart the host when you can). |
| `external` (only with `--external`) | `https://DOMAIN/v1/info` from this host | **FAIL** no answer or a wrong answer: DNS, firewall or certificate. |

On Postgres (path A) the lines `files` and the integrity pragma are skipped, open invites are "not counted", and point-in-time recovery and deletion protection are "not checked".

## Upgrades

**The binary never updates itself and never calls home.** You decide when. `awm serve check` prints the version and the `min_client` the server enforces.

- **systemd**: download the new release, verify it against `SHA256SUMS`, `install -m 0755 awm /usr/local/bin/awm`, `systemctl restart awm-serve`, `awm serve check`. The server runs its migrations at start and keeps `server.db.bak-vN` first. A server refuses a database from a newer version (exit 3): downgrade by restoring a backup, not by running an old binary on a new database.
- **docker compose**: `docker compose pull && docker compose up -d` (or `--build`). The certificate and data live in the volume and survive.
- **Members** update their `awm` when they like. To require a minimum client version (after a protocol or redaction fix), raise `min_client` as an admin: `awm team policy set min_client=0.2.1`. Older clients then stop syncing with a message; hooks and local use are untouched. Check the release notes for fixes that matter to you.
- After an upgrade: `awm serve check`, and one `awm sync` from a member machine.

## Rotation and removal

| what | how |
|---|---|
| a member leaves or a device is lost | an admin runs `awm team remove HANDLE` (revokes every token and rotates the team key; `--delete-records` also deletes the member's shared records). `awm team members` shows the result. |
| rotate the team key without removing anyone | an admin runs `awm team rotate-key` |
| a device token may be exposed | on that device: `awm team token rotate` (the old token stops at once) |
| a member's next machine | `awm team add-device`, then `awm team approve` with the 6-digit code |
| a lost bootstrap token, no admin yet | `awm serve init` again; it replaces the unused one |
| the admin account is lost | `awm serve promote HANDLE` on the server (a recovery path, run on the host: `sudo -u awm awm serve promote HANDLE --data /var/lib/awm`, `docker compose exec awm awm serve promote HANDLE`); clients then need `awm team members --trust-admin @HANDLE` |
| the TLS certificate | automatic; nothing to do. To force a re-issue, stop the server and delete `{data}/acme/cert.pem`, mind the rate limit. |
| the retention period | `awm team policy set retention_days=N` (a server setting) |
| the backup target changes | change `AWM_BACKUP`, restart. A new prefix starts with a full snapshot. Do not point two servers at one prefix. |

## Identity-Aware Proxy: a later option

A team that self-hosts on Google Cloud could put Identity-Aware Proxy in front of the server as a second layer, so only identities in the team's Google Cloud organisation reach it at all. **Not implemented in v1.** Design, not verified against IAP's documentation: `awm sync` would run a command named in `team.auth_command` (for example `gcloud auth print-identity-token --audiences=<IAP client id>`), cache the OIDC identity token until shortly before it expires, and send it in `Proxy-Authorization: Bearer ...`, leaving `Authorization` for the device token. The cost is a global external HTTPS load balancer in front of the VM (from about $18 a month), `gcloud` signed in on every member's machine, and a second credential path whose expiry can fail in the background. The device tokens, per-IP limits and end-to-end encryption already bound what public exposure gives an attacker, so v1 does not need it unless your organisation requires IAP for every internal app. If you need it, open an issue.

## What the operator can and cannot see

The server sees: handles and roles; counts and times of members, devices and invites; per stream the record count, padded sizes (256-byte buckets) and the hours records arrived; deletion counts; key epochs; and request logs (IP address, token prefix, path, status, latency). Because pushes follow captures, push times reveal each member's research activity to about a minute, and `link` records can be told from `full` ones by size.

The server never sees: record plaintext, keys, invite secrets, or members' email addresses. The organisation (your team) is the controller of the notes, and you, the operator, are responsible for the host, the backup bucket and who has access to both.

## Threat model summary

- **Defended**: a network observer (TLS 1.2/1.3); a curious or breached server host or bucket (records are end-to-end encrypted; backups hold the same ciphertext); a stolen device token (revoke it, rotate the key); a leaked invite (single use, 7 days, and the 6-digit comparison); a misconfigured public listener (refused at start, `check` FAILs); two servers on one backup prefix.
- **Not defended**: a compromised member machine (it holds the team key and the plaintext); a malicious teammate pushing poisoned notes (bounds are the sanitiser, quarantine and removal); an operator who tampers with traffic *and* controls a device approval without the code comparison (so compare codes); denial of service by someone who can reach port 443 (limits are per IP and per token, not a shield); anything on a host you do not patch. Backups are not encrypted a second time; use disk encryption and a private bucket.
- **Your duties**: keep the host patched (unattended upgrades; restart when `health` says a reboot is pending), keep backups on, run `--verify`, drill restores, keep a second admin, remove departed members, and read `check`.

The security model of the client and the reporting address are in [SECURITY.md](../SECURITY.md).
