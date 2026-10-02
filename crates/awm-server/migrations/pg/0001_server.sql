-- awm-server Postgres schema, version 1 (plan-v3-team §4.2; TM26).
--
-- The same tables, columns, CHECKs and defaults as `migrations/sqlite/0001_server.sql` (the
-- canonical format), each with an `org_id` column leading its primary key and every unique
-- constraint, so one database holds many organisations (the cloud) or one (self-host path A).
-- `org_id` is the organisation scope's key (`PgStore::for_org`); `org.id` is the organisation
-- id inside it, copied as it is by the canonical export and import. `backup_log` is
-- `SqliteStore`'s change log and is absent here (TM27 uses the daily canonical export on
-- Postgres). `claim` is Postgres-only: the cross-instance hourly claims (TM9 P2).
--
-- Types: ids, handles, tags, keys and values are TEXT with the "C" collation, so ORDER BY
-- compares bytes as SQLite does; every SQLite INTEGER is BIGINT; every BLOB is BYTEA.
--
-- Isolation (§4.2): row-level security is enabled and forced on every table (the owner is
-- subject to it too), with one policy per table that admits only the rows of the scope set
-- per transaction by `SET LOCAL awm.org` (`set_config('awm.org', $1, true)`). Without the
-- setting, `current_setting('awm.org', true)` is NULL or '' and no row matches. Foreign keys
-- and unique constraints are checked without row-level security, as Postgres always does.
--
-- Roles: the owner role (`awm_owner`) runs this file and owns every table; the application
-- role (`awm_app`, passed by the runner as `awm.app_role`, the user of the application URL)
-- gets USAGE on the schema and SELECT, INSERT, UPDATE, DELETE on the tables, nothing else.
--
-- The runner (`store::pg::migrate`) applies this file inside one transaction under
-- `pg_advisory_xact_lock`, after creating `schema_migrations` (version, name, checksum); it
-- checks the checksums of applied files and refuses a newer database (no downgrade). Foreign
-- keys are DEFERRABLE so that the canonical import can insert `device` before `invite`.

-- The organisation: one row per scope, created by `POST /v1/bootstrap` or the import.
CREATE TABLE org (
  org_id                 TEXT   COLLATE "C" NOT NULL CHECK (org_id <> ''),
  id                     TEXT   COLLATE "C" NOT NULL,
  created_at             BIGINT NOT NULL,
  current_epoch          BIGINT NOT NULL DEFAULT 0 CHECK (current_epoch >= 0),
  rotation_needed        BIGINT NOT NULL DEFAULT 0 CHECK (rotation_needed IN (0, 1)),
  retention_days         BIGINT NOT NULL CHECK (retention_days >= 30),
  min_client             TEXT   COLLATE "C" NOT NULL,
  max_members            BIGINT NOT NULL CHECK (max_members >= 1),
  -- A decrease of retention_days waiting for its 7 days (`docs/sync-v1.md` §10.4).
  pending_retention_days BIGINT CHECK (pending_retention_days >= 30),
  pending_retention_at   BIGINT,
  CHECK ((pending_retention_days IS NULL) = (pending_retention_at IS NULL)),
  PRIMARY KEY (org_id, id),
  -- One organisation per scope (SQLite: one per file, enforced by `bootstrap`).
  UNIQUE (org_id)
);

-- Members: no email. A removed member keeps its row.
CREATE TABLE member (
  org_id     TEXT   COLLATE "C" NOT NULL CHECK (org_id <> ''),
  id         TEXT   COLLATE "C" NOT NULL,
  handle     TEXT   COLLATE "C" NOT NULL,
  role       TEXT   COLLATE "C" NOT NULL CHECK (role IN ('member', 'admin')),
  created_at BIGINT NOT NULL,
  revoked_at BIGINT,
  PRIMARY KEY (org_id, id)
);
CREATE UNIQUE INDEX member_handle_active ON member (org_id, handle) WHERE revoked_at IS NULL;

-- Devices: tokens, keys and approval are per device. `token_hash` is looked up by hash only.
-- The foreign key to `invite` is added after `invite` exists.
CREATE TABLE device (
  org_id        TEXT   COLLATE "C" NOT NULL CHECK (org_id <> ''),
  id            TEXT   COLLATE "C" NOT NULL,
  member_id     TEXT   COLLATE "C" NOT NULL,
  token_hash    TEXT   COLLATE "C" NOT NULL CHECK (token_hash ~ '^[0-9a-f]{64}$'),
  pubkey        BYTEA  NOT NULL CHECK (octet_length(pubkey) = 32),
  join_mac      BYTEA  CHECK (octet_length(join_mac) = 32),  -- NULL for the bootstrap device
  invite_id     TEXT   COLLATE "C",                          -- NULL for the bootstrap device
  approved      BIGINT NOT NULL DEFAULT 0 CHECK (approved IN (0, 1)),
  created_at    BIGINT NOT NULL,
  revoked_at    BIGINT,
  last_seen_day BIGINT,                                      -- Unix day (seconds / 86,400)
  CHECK ((join_mac IS NULL) = (invite_id IS NULL)),
  PRIMARY KEY (org_id, id),
  UNIQUE (org_id, token_hash),
  FOREIGN KEY (org_id, member_id) REFERENCES member (org_id, id) DEFERRABLE
);
CREATE INDEX device_member ON device (org_id, member_id);

-- Invites: the server's half only; the invite secret S never reaches the server (§5.1).
CREATE TABLE invite (
  org_id     TEXT   COLLATE "C" NOT NULL CHECK (org_id <> ''),
  id         TEXT   COLLATE "C" NOT NULL,
  token_hash TEXT   COLLATE "C" NOT NULL CHECK (token_hash ~ '^[0-9a-f]{64}$'),
  handle     TEXT   COLLATE "C" NOT NULL,
  role       TEXT   COLLATE "C" CHECK (role IN ('member', 'admin')),  -- member invites only
  kind       TEXT   COLLATE "C" NOT NULL CHECK (kind IN ('member', 'device')),
  member_id  TEXT   COLLATE "C",              -- device invites: the existing member
  created_by TEXT   COLLATE "C" NOT NULL,     -- the creating device (holds S)
  created_at BIGINT NOT NULL,
  expires_at BIGINT NOT NULL,
  used_at    BIGINT,
  revoked_at BIGINT,
  CHECK ((kind = 'member') = (role IS NOT NULL)),
  CHECK ((kind = 'device') = (member_id IS NOT NULL)),
  PRIMARY KEY (org_id, id),
  UNIQUE (org_id, token_hash),
  FOREIGN KEY (org_id, member_id) REFERENCES member (org_id, id) DEFERRABLE,
  FOREIGN KEY (org_id, created_by) REFERENCES device (org_id, id) DEFERRABLE
);
ALTER TABLE device ADD FOREIGN KEY (org_id, invite_id) REFERENCES invite (org_id, id) DEFERRABLE;

-- Records: streams (member, device, tag) with contiguous indexes from 0 (§4.3.4). A deleted
-- record keeps its row as a marker: `blob` NULL, `deleted_at` set, `id` kept. Rows are never
-- deleted (except with the whole organisation).
CREATE TABLE record (
  org_id      TEXT   COLLATE "C" NOT NULL CHECK (org_id <> ''),
  member_id   TEXT   COLLATE "C" NOT NULL,
  device_id   TEXT   COLLATE "C" NOT NULL,
  tag         TEXT   COLLATE "C" NOT NULL,
  idx         BIGINT NOT NULL CHECK (idx >= 0),
  id          TEXT   COLLATE "C" NOT NULL,
  epoch       BIGINT CHECK (epoch >= 0),
  size        BIGINT NOT NULL CHECK (size >= 0),
  received_at BIGINT NOT NULL,                             -- hour
  blob        BYTEA,
  deleted_at  BIGINT,                                      -- hour
  CHECK ((blob IS NULL) <> (deleted_at IS NULL)),
  PRIMARY KEY (org_id, member_id, device_id, tag, idx),
  -- Named: a concurrent push of one id into two streams maps this violation to `id_conflict`.
  CONSTRAINT record_id_unique UNIQUE (org_id, id),
  FOREIGN KEY (org_id, member_id) REFERENCES member (org_id, id) DEFERRABLE,
  FOREIGN KEY (org_id, device_id) REFERENCES device (org_id, id) DEFERRABLE
);
CREATE INDEX record_retention ON record (org_id, received_at) WHERE blob IS NOT NULL;

-- The server-written deletion stream, contiguous from 0 (§4.3.4).
CREATE TABLE deletion (
  org_id     TEXT   COLLATE "C" NOT NULL CHECK (org_id <> ''),
  idx        BIGINT NOT NULL CHECK (idx >= 0),
  record_id  TEXT   COLLATE "C" NOT NULL,
  member_id  TEXT   COLLATE "C" NOT NULL,
  deleted_at BIGINT NOT NULL,                              -- hour
  PRIMARY KEY (org_id, idx),
  UNIQUE (org_id, record_id),
  FOREIGN KEY (org_id, member_id) REFERENCES member (org_id, id) DEFERRABLE
);
CREATE INDEX deletion_deleted_at ON deletion (org_id, deleted_at);

-- Wrapped epoch keys, one per (device, epoch); the first stored wrap stays (§9.2).
CREATE TABLE wrap (
  org_id     TEXT   COLLATE "C" NOT NULL CHECK (org_id <> ''),
  device_id  TEXT   COLLATE "C" NOT NULL,
  epoch      BIGINT NOT NULL CHECK (epoch >= 0),
  wrap       BYTEA  NOT NULL,
  auth       BYTEA  NOT NULL CHECK (octet_length(auth) = 32),
  created_by TEXT   COLLATE "C" NOT NULL,
  PRIMARY KEY (org_id, device_id, epoch),
  FOREIGN KEY (org_id, device_id) REFERENCES device (org_id, id) DEFERRABLE,
  FOREIGN KEY (org_id, created_by) REFERENCES device (org_id, id) DEFERRABLE
);

-- The audit log (§5.5): never record content.
CREATE TABLE audit (
  org_id TEXT   COLLATE "C" NOT NULL CHECK (org_id <> ''),
  idx    BIGINT NOT NULL CHECK (idx >= 0),
  at     BIGINT NOT NULL,
  actor  TEXT   COLLATE "C",                               -- member id; NULL for the server
  action TEXT   COLLATE "C" NOT NULL,
  target TEXT   COLLATE "C",
  detail TEXT   COLLATE "C",
  PRIMARY KEY (org_id, idx)
);
CREATE INDEX audit_at ON audit (org_id, at);

-- Server state per organisation: `generation`, `restore_pending` (both written by
-- `PgStore::create_org`), `restored_at`, `last_retention`, the bootstrap token's hash and
-- expiry, the backup cursor and last verification. The schema version is global
-- (`schema_migrations`), not per organisation.
CREATE TABLE meta (
  org_id TEXT COLLATE "C" NOT NULL CHECK (org_id <> ''),
  key    TEXT COLLATE "C" NOT NULL,
  value  TEXT COLLATE "C" NOT NULL,
  PRIMARY KEY (org_id, key)
);

-- Cross-instance claims (TM9 P2; Postgres only, not part of the canonical format): the time
-- of the last claimed run of `name` (`retention`), compare-and-set under the organisation's
-- advisory lock, so two instances cannot both start a run within one hour.
CREATE TABLE claim (
  org_id TEXT   COLLATE "C" NOT NULL CHECK (org_id <> ''),
  name   TEXT   COLLATE "C" NOT NULL,
  at     BIGINT NOT NULL,
  PRIMARY KEY (org_id, name)
);

-- Row-level security on every table, forced for the owner too, one policy each.
DO $$
DECLARE
  t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['org', 'member', 'device', 'invite', 'record', 'deletion', 'wrap',
                           'audit', 'meta', 'claim'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant ON %I '
                   'USING (org_id = current_setting(''awm.org'', true)) '
                   'WITH CHECK (org_id = current_setting(''awm.org'', true))', t);
  END LOOP;
END
$$;

-- The application role: data access only. It owns nothing and may create nothing.
DO $$
DECLARE
  app text := current_setting('awm.app_role');
BEGIN
  EXECUTE format('REVOKE ALL ON org, member, device, invite, record, deletion, wrap, audit, '
                 'meta, claim FROM PUBLIC');
  EXECUTE format('GRANT USAGE ON SCHEMA %I TO %I', current_schema(), app);
  EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON org, member, device, invite, record, '
                 'deletion, wrap, audit, meta, claim TO %I', app);
END
$$;
