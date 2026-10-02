-- Applied by db::migrate() in one transaction, after the VACUUM INTO backup. Never edit after release.
-- Team sync columns and tables (plan-v3-team §4.4). Rows from before this migration are
-- origin 'local' and shareable 'no': nothing recorded earlier is shared without a backfill.
-- The runner turns foreign_keys off around the transaction and runs foreign_key_check
-- before COMMIT, as SQLite's table-rebuild procedure requires (injection_item below).

ALTER TABLE event ADD COLUMN origin TEXT NOT NULL DEFAULT 'local'
  CHECK (origin IN ('local','team'));
ALTER TABLE event ADD COLUMN member TEXT;            -- team rows: author's member id; local rows: NULL
ALTER TABLE event ADD COLUMN repo_key TEXT;          -- keyed hash of the normalised git remote, when known
ALTER TABLE event ADD COLUMN shareable TEXT NOT NULL DEFAULT 'no'
  CHECK (shareable IN ('no','full','link'));         -- local rows: decided at push; team rows: as received
ALTER TABLE event ADD COLUMN sync_id TEXT;           -- record id on the wire (random UUIDv4)
ALTER TABLE event ADD COLUMN pushed_at INTEGER;      -- local rows: when the server accepted the record
ALTER TABLE event ADD COLUMN sync_idx INTEGER;       -- local rows: idx in this device's rec stream (re-seed)
CREATE UNIQUE INDEX event_sync_id ON event(sync_id) WHERE sync_id IS NOT NULL;
CREATE INDEX event_origin ON event(origin, created_at);

CREATE TABLE sync_state (
  key    TEXT PRIMARY KEY,   -- last_spawn, last_ok, backoff_until, last_error, deletion_head,
  value  TEXT NOT NULL       -- generation, policy_version, skipped.{reason} counters
);

CREATE TABLE sync_stream (
  member_id  TEXT    NOT NULL,
  device_id  TEXT    NOT NULL,
  tag        TEXT    NOT NULL,
  head_idx   INTEGER NOT NULL,   -- highest contiguous idx applied (pull) or accepted (push)
  PRIMARY KEY (member_id, device_id, tag)
);

CREATE TABLE sync_outbox (
  id          INTEGER PRIMARY KEY,
  kind        TEXT    NOT NULL CHECK (kind IN ('record','delete','flag','stats','policy')),
  ref         TEXT    NOT NULL,  -- event id, sync_id or a JSON body
  created_at  INTEGER NOT NULL,
  attempts    INTEGER NOT NULL DEFAULT 0,
  last_error  TEXT
);

-- The roster this client has verified (plan-v3-team §5.1).
CREATE TABLE team_member (
  member_id   TEXT    PRIMARY KEY,
  handle      TEXT    NOT NULL,
  role        TEXT    NOT NULL CHECK (role IN ('member','admin')),
  active      INTEGER NOT NULL DEFAULT 1 CHECK (active IN (0,1)),
  updated_at  INTEGER NOT NULL
);

CREATE TABLE team_device (
  device_id   TEXT    PRIMARY KEY,
  member_id   TEXT    NOT NULL,
  pubkey      TEXT    NOT NULL,  -- base64url of the 32-byte X25519 public key
  verified    INTEGER NOT NULL CHECK (verified IN (0,1)),   -- a verified roster entry exists
  revoked     INTEGER NOT NULL DEFAULT 0 CHECK (revoked IN (0,1)),
  approver    TEXT,              -- device id that approved it (roster entry); NULL for genesis or unverified
  updated_at  INTEGER NOT NULL
);

CREATE TABLE project (
  cwd_hash    TEXT    PRIMARY KEY,
  repo_key    TEXT,
  updated_at  INTEGER NOT NULL
);

CREATE TABLE share_rule (
  kind        TEXT    NOT NULL CHECK (kind IN ('repo','cwd')),
  value       TEXT    NOT NULL,  -- repo_key or cwd_hash
  created_at  INTEGER NOT NULL,  -- records captured earlier are not eligible without a backfill
  PRIMARY KEY (kind, value)
);

-- injection_item: event_id becomes nullable with ON DELETE SET NULL, so a deleted record
-- leaves the item, its outcome label and its origin behind without text. Rebuilt under a
-- new name and renamed, so outcome's foreign key keeps naming injection_item.
CREATE TABLE injection_item_new (
  injection_id  INTEGER NOT NULL REFERENCES injection(id) ON DELETE CASCADE,
  position      INTEGER NOT NULL,                 -- 1..3, order in the block
  event_id      INTEGER REFERENCES event(id) ON DELETE SET NULL,  -- NULL once the record is deleted
  score         REAL    NOT NULL,                 -- negated bm25, 1.0 for url matches
  origin        TEXT    NOT NULL DEFAULT 'local' CHECK (origin IN ('local','team')),  -- event.origin at insert
  PRIMARY KEY (injection_id, position)
);
INSERT INTO injection_item_new (injection_id, position, event_id, score, origin)
  SELECT ii.injection_id, ii.position, ii.event_id, ii.score, COALESCE(e.origin, 'local')
  FROM injection_item ii LEFT JOIN event e ON e.id = ii.event_id;
DROP TABLE injection_item;
ALTER TABLE injection_item_new RENAME TO injection_item;
CREATE INDEX injection_item_event ON injection_item(event_id);

-- Copies event.origin at insert, so writers that name only the 0001 columns stay correct.
CREATE TRIGGER injection_item_origin_ai AFTER INSERT ON injection_item
  WHEN new.event_id IS NOT NULL BEGIN
  UPDATE injection_item
     SET origin = COALESCE((SELECT origin FROM event WHERE id = new.event_id), new.origin)
   WHERE injection_id = new.injection_id AND position = new.position;
END;
