-- awm-server SQLite schema, version 1 (plan-v3-team §4.2; TM6).
--
-- This schema is also the canonical export format (§4.2): `GET /v1/export`, `awm serve backup
-- --to FILE` and the cloud's tenant export write a SQLite file in it, and either store imports it.
-- One file holds one organisation, so no table carries `org_id` (PgStore's tables do, TM26).
--
-- Conventions: ids are canonical UUID text (`docs/sync-v1.md` §1); times are Unix seconds, and
-- the columns named "hour" in §4.2 are rounded down to a multiple of 3,600 by the store; token
-- hashes are SHA-256 as 64 lower-case hex characters, so no column can hold a token (§4.10);
-- public keys, MACs and wrap authenticators are 32 raw bytes; blobs are the raw envelope bytes.
--
-- The runner (`store::sqlite`) applies this file inside `BEGIN IMMEDIATE` with foreign keys off
-- and runs `PRAGMA foreign_key_check` before `COMMIT`, under the client's rules (plan-v2 §6.2).
-- The schema version and this file's checksum live in `meta` (`schema_version`,
-- `schema_checksum.1`), written by the runner after this file.

-- The organisation: one row per file, created by `POST /v1/bootstrap`.
CREATE TABLE org (
  id                     TEXT    NOT NULL PRIMARY KEY,
  created_at             INTEGER NOT NULL,
  current_epoch          INTEGER NOT NULL DEFAULT 0 CHECK (current_epoch >= 0),
  rotation_needed        INTEGER NOT NULL DEFAULT 0 CHECK (rotation_needed IN (0, 1)),
  retention_days         INTEGER NOT NULL CHECK (retention_days >= 30),
  min_client             TEXT    NOT NULL,
  max_members            INTEGER NOT NULL CHECK (max_members >= 1),
  -- A decrease of retention_days waiting for its 7 days (`docs/sync-v1.md` §10.4).
  pending_retention_days INTEGER CHECK (pending_retention_days >= 30),
  pending_retention_at   INTEGER,
  CHECK ((pending_retention_days IS NULL) = (pending_retention_at IS NULL))
);

-- Members: no email. A removed member keeps its row (its records stay with the organisation).
CREATE TABLE member (
  id         TEXT    NOT NULL PRIMARY KEY,
  handle     TEXT    NOT NULL,
  role       TEXT    NOT NULL CHECK (role IN ('member', 'admin')),
  created_at INTEGER NOT NULL,
  revoked_at INTEGER
);
CREATE UNIQUE INDEX member_handle_active ON member(handle) WHERE revoked_at IS NULL;

-- Devices: tokens, keys and approval are per device. `token_hash` is looked up by hash only.
CREATE TABLE device (
  id            TEXT    NOT NULL PRIMARY KEY,
  member_id     TEXT    NOT NULL REFERENCES member(id),
  token_hash    TEXT    NOT NULL UNIQUE
                CHECK (length(token_hash) = 64 AND token_hash NOT GLOB '*[^0-9a-f]*'),
  pubkey        BLOB    NOT NULL CHECK (length(pubkey) = 32),
  join_mac      BLOB    CHECK (length(join_mac) = 32),   -- NULL for the bootstrap device
  invite_id     TEXT    REFERENCES invite(id),           -- NULL for the bootstrap device
  approved      INTEGER NOT NULL DEFAULT 0 CHECK (approved IN (0, 1)),
  created_at    INTEGER NOT NULL,
  revoked_at    INTEGER,
  last_seen_day INTEGER,                                  -- Unix day (seconds / 86,400)
  CHECK ((join_mac IS NULL) = (invite_id IS NULL))
);
CREATE INDEX device_member ON device(member_id);

-- Invites: the server's half only; the invite secret S never reaches the server (§5.1).
CREATE TABLE invite (
  id         TEXT    NOT NULL PRIMARY KEY,
  token_hash TEXT    NOT NULL UNIQUE
             CHECK (length(token_hash) = 64 AND token_hash NOT GLOB '*[^0-9a-f]*'),
  handle     TEXT    NOT NULL,
  role       TEXT    CHECK (role IN ('member', 'admin')),  -- member invites only
  kind       TEXT    NOT NULL CHECK (kind IN ('member', 'device')),
  member_id  TEXT    REFERENCES member(id),                -- device invites: the existing member
  created_by TEXT    NOT NULL REFERENCES device(id),       -- the creating device (holds S)
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at    INTEGER,
  revoked_at INTEGER,
  CHECK ((kind = 'member') = (role IS NOT NULL)),
  CHECK ((kind = 'device') = (member_id IS NOT NULL))
);

-- Records: streams (member, device, tag) with contiguous indexes from 0 (§4.3.4). A deleted
-- record keeps its row as a marker: `blob` NULL, `deleted_at` set, `id` kept. A marker pushed
-- as a marker (re-seed, §3.9.5) has no `epoch` and `size` 0. Rows are never deleted.
CREATE TABLE record (
  member_id   TEXT    NOT NULL REFERENCES member(id),
  device_id   TEXT    NOT NULL REFERENCES device(id),
  tag         TEXT    NOT NULL,
  idx         INTEGER NOT NULL CHECK (idx >= 0),
  id          TEXT    NOT NULL UNIQUE,
  epoch       INTEGER CHECK (epoch >= 0),
  size        INTEGER NOT NULL CHECK (size >= 0),
  received_at INTEGER NOT NULL,                             -- hour
  blob        BLOB,
  deleted_at  INTEGER,                                      -- hour
  PRIMARY KEY (member_id, device_id, tag, idx),
  CHECK ((blob IS NULL) <> (deleted_at IS NULL))
);
CREATE INDEX record_retention ON record(received_at) WHERE blob IS NOT NULL;

-- The server-written deletion stream, contiguous from 0 (§4.3.4). `member_id` is the record's
-- member, or the member that deleted an id the server never stored (`docs/sync-v1.md` §10.3).
CREATE TABLE deletion (
  idx        INTEGER NOT NULL PRIMARY KEY CHECK (idx >= 0),
  record_id  TEXT    NOT NULL UNIQUE,
  member_id  TEXT    NOT NULL REFERENCES member(id),
  deleted_at INTEGER NOT NULL                               -- hour
);
CREATE INDEX deletion_deleted_at ON deletion(deleted_at);

-- Wrapped epoch keys, one per (device, epoch); the first stored wrap stays (§9.2).
CREATE TABLE wrap (
  device_id  TEXT    NOT NULL REFERENCES device(id),
  epoch      INTEGER NOT NULL CHECK (epoch >= 0),
  wrap       BLOB    NOT NULL,
  auth       BLOB    NOT NULL CHECK (length(auth) = 32),
  created_by TEXT    NOT NULL REFERENCES device(id),
  PRIMARY KEY (device_id, epoch)
);

-- The audit log (§5.5): never record content.
CREATE TABLE audit (
  idx    INTEGER NOT NULL PRIMARY KEY CHECK (idx >= 0),
  at     INTEGER NOT NULL,
  actor  TEXT,                                              -- member id; NULL for the server
  action TEXT    NOT NULL,
  target TEXT,
  detail TEXT
);
CREATE INDEX audit_at ON audit(at);

-- Server state: `generation` (§3.9.5), `restore_pending`, `restored_at`, `last_retention`,
-- the bootstrap token's hash and expiry, the backup cursor and last verification (§6.2), and
-- the schema version with each migration's checksum.
CREATE TABLE meta (
  key   TEXT NOT NULL PRIMARY KEY,
  value TEXT NOT NULL
);

-- Change log for the incremental backup (§6.2): one row per inserted, updated or deleted row
-- of every table above, written by the triggers below. `key` is the row's key: `id` (org,
-- member, device, invite, record), `idx` (deletion, audit), `device_id/epoch` (wrap) or `key`
-- (meta). Keys of `meta` that start with `backup_` describe the backup itself and are not
-- logged, so that writing the cursor does not make the next change set non-empty.
CREATE TABLE backup_log (
  seq INTEGER PRIMARY KEY AUTOINCREMENT,
  tbl TEXT NOT NULL,
  key TEXT NOT NULL,
  op  TEXT NOT NULL CHECK (op IN ('i', 'u', 'd'))
);

INSERT INTO meta (key, value)
SELECT 'generation',
       substr(h, 1, 8) || '-' || substr(h, 9, 4) || '-4' || substr(h, 14, 3) || '-' ||
       substr('89ab', 1 + (abs(random()) % 4), 1) || substr(h, 18, 3) || '-' || substr(h, 21, 12)
  FROM (SELECT lower(hex(randomblob(16))) AS h);
INSERT INTO meta (key, value) VALUES ('restore_pending', '0');

CREATE TRIGGER bl_org_i AFTER INSERT ON org BEGIN
  INSERT INTO backup_log (tbl, key, op) VALUES ('org', new.id, 'i'); END;
CREATE TRIGGER bl_org_u AFTER UPDATE ON org BEGIN
  INSERT INTO backup_log (tbl, key, op) VALUES ('org', new.id, 'u'); END;
CREATE TRIGGER bl_org_d AFTER DELETE ON org BEGIN
  INSERT INTO backup_log (tbl, key, op) VALUES ('org', old.id, 'd'); END;

CREATE TRIGGER bl_member_i AFTER INSERT ON member BEGIN
  INSERT INTO backup_log (tbl, key, op) VALUES ('member', new.id, 'i'); END;
CREATE TRIGGER bl_member_u AFTER UPDATE ON member BEGIN
  INSERT INTO backup_log (tbl, key, op) VALUES ('member', new.id, 'u'); END;
CREATE TRIGGER bl_member_d AFTER DELETE ON member BEGIN
  INSERT INTO backup_log (tbl, key, op) VALUES ('member', old.id, 'd'); END;

CREATE TRIGGER bl_device_i AFTER INSERT ON device BEGIN
  INSERT INTO backup_log (tbl, key, op) VALUES ('device', new.id, 'i'); END;
CREATE TRIGGER bl_device_u AFTER UPDATE ON device BEGIN
  INSERT INTO backup_log (tbl, key, op) VALUES ('device', new.id, 'u'); END;
CREATE TRIGGER bl_device_d AFTER DELETE ON device BEGIN
  INSERT INTO backup_log (tbl, key, op) VALUES ('device', old.id, 'd'); END;

CREATE TRIGGER bl_invite_i AFTER INSERT ON invite BEGIN
  INSERT INTO backup_log (tbl, key, op) VALUES ('invite', new.id, 'i'); END;
CREATE TRIGGER bl_invite_u AFTER UPDATE ON invite BEGIN
  INSERT INTO backup_log (tbl, key, op) VALUES ('invite', new.id, 'u'); END;
CREATE TRIGGER bl_invite_d AFTER DELETE ON invite BEGIN
  INSERT INTO backup_log (tbl, key, op) VALUES ('invite', old.id, 'd'); END;

CREATE TRIGGER bl_record_i AFTER INSERT ON record BEGIN
  INSERT INTO backup_log (tbl, key, op) VALUES ('record', new.id, 'i'); END;
CREATE TRIGGER bl_record_u AFTER UPDATE ON record BEGIN
  INSERT INTO backup_log (tbl, key, op) VALUES ('record', new.id, 'u'); END;
CREATE TRIGGER bl_record_d AFTER DELETE ON record BEGIN
  INSERT INTO backup_log (tbl, key, op) VALUES ('record', old.id, 'd'); END;

CREATE TRIGGER bl_deletion_i AFTER INSERT ON deletion BEGIN
  INSERT INTO backup_log (tbl, key, op) VALUES ('deletion', new.idx, 'i'); END;
CREATE TRIGGER bl_deletion_u AFTER UPDATE ON deletion BEGIN
  INSERT INTO backup_log (tbl, key, op) VALUES ('deletion', new.idx, 'u'); END;
CREATE TRIGGER bl_deletion_d AFTER DELETE ON deletion BEGIN
  INSERT INTO backup_log (tbl, key, op) VALUES ('deletion', old.idx, 'd'); END;

CREATE TRIGGER bl_wrap_i AFTER INSERT ON wrap BEGIN
  INSERT INTO backup_log (tbl, key, op) VALUES ('wrap', new.device_id || '/' || new.epoch, 'i'); END;
CREATE TRIGGER bl_wrap_u AFTER UPDATE ON wrap BEGIN
  INSERT INTO backup_log (tbl, key, op) VALUES ('wrap', new.device_id || '/' || new.epoch, 'u'); END;
CREATE TRIGGER bl_wrap_d AFTER DELETE ON wrap BEGIN
  INSERT INTO backup_log (tbl, key, op) VALUES ('wrap', old.device_id || '/' || old.epoch, 'd'); END;

CREATE TRIGGER bl_audit_i AFTER INSERT ON audit BEGIN
  INSERT INTO backup_log (tbl, key, op) VALUES ('audit', new.idx, 'i'); END;
CREATE TRIGGER bl_audit_u AFTER UPDATE ON audit BEGIN
  INSERT INTO backup_log (tbl, key, op) VALUES ('audit', new.idx, 'u'); END;
CREATE TRIGGER bl_audit_d AFTER DELETE ON audit BEGIN
  INSERT INTO backup_log (tbl, key, op) VALUES ('audit', old.idx, 'd'); END;

CREATE TRIGGER bl_meta_i AFTER INSERT ON meta WHEN new.key NOT LIKE 'backup\_%' ESCAPE '\' BEGIN
  INSERT INTO backup_log (tbl, key, op) VALUES ('meta', new.key, 'i'); END;
CREATE TRIGGER bl_meta_u AFTER UPDATE ON meta WHEN new.key NOT LIKE 'backup\_%' ESCAPE '\' BEGIN
  INSERT INTO backup_log (tbl, key, op) VALUES ('meta', new.key, 'u'); END;
CREATE TRIGGER bl_meta_d AFTER DELETE ON meta WHEN old.key NOT LIKE 'backup\_%' ESCAPE '\' BEGIN
  INSERT INTO backup_log (tbl, key, op) VALUES ('meta', old.key, 'd'); END;
