-- Applied by db::migrate() in one transaction. Connection pragmas live in db::open().
-- Times are unix milliseconds, UTC.

CREATE TABLE schema_version (
  version     INTEGER PRIMARY KEY,
  name        TEXT    NOT NULL,                 -- '0001_init'
  checksum    TEXT    NOT NULL,                 -- sha256 hex of the migration file
  applied_at  INTEGER NOT NULL
);

CREATE TABLE meta (
  key    TEXT PRIMARY KEY,  -- consent.record, consent.import, cutoff.query, cutoff.prompt,
  value  TEXT NOT NULL      -- calibrated_at, calibrated_n, purged_before, first_notice_shown
);

CREATE TABLE import_source (
  id               INTEGER PRIMARY KEY,
  path             TEXT    NOT NULL UNIQUE,      -- absolute transcript path
  head_sha256      TEXT    NOT NULL,             -- sha256 of the first 4096 bytes
  file_size        INTEGER NOT NULL,
  file_mtime       INTEGER NOT NULL,
  last_offset      INTEGER NOT NULL DEFAULT 0,   -- bytes fully processed
  events_found     INTEGER NOT NULL DEFAULT 0,
  events_inserted  INTEGER NOT NULL DEFAULT 0,
  status           TEXT    NOT NULL CHECK (status IN ('ok','partial','error')),
  error            TEXT,
  imported_at      INTEGER NOT NULL
);

CREATE TABLE event (
  id                INTEGER PRIMARY KEY,
  tool_use_id       TEXT    NOT NULL UNIQUE,     -- same id in hook stdin and transcript
  tool              TEXT    NOT NULL CHECK (tool IN ('WebSearch','WebFetch')),
  session_id        TEXT    NOT NULL,
  agent_id          TEXT,                         -- NULL = main agent
  agent_type        TEXT,
  cwd_hash          TEXT    NOT NULL,             -- sha256 hex of cwd
  created_at        INTEGER NOT NULL,
  query             TEXT,                         -- WebSearch tool_input.query, redacted
  url               TEXT,                         -- WebFetch tool_input.url
  url_norm          TEXT,
  fetch_prompt      TEXT,                         -- WebFetch tool_input.prompt, redacted
  http_code         INTEGER,
  bytes             INTEGER,
  duration_ms       INTEGER,
  status            TEXT    NOT NULL CHECK (status IN ('ok','dead_end','refusal','placeholder')),
  summary           TEXT,                         -- redacted tool summary, at most 8000 chars
  match_text        TEXT    NOT NULL,             -- FTS document, record::match_text()
  source            TEXT    NOT NULL CHECK (source IN ('hook','import')),
  import_source_id  INTEGER REFERENCES import_source(id) ON DELETE SET NULL,
  quarantined       INTEGER NOT NULL DEFAULT 0 CHECK (quarantined IN (0,1)),
  quarantine_reason TEXT,
  CHECK ((tool = 'WebSearch' AND query IS NOT NULL)
      OR (tool = 'WebFetch' AND url IS NOT NULL AND url_norm IS NOT NULL))
);
CREATE INDEX event_url_norm   ON event(url_norm) WHERE url_norm IS NOT NULL;
CREATE INDEX event_created_at ON event(created_at);
CREATE INDEX event_session    ON event(session_id, agent_id);

CREATE TABLE result (
  event_id  INTEGER NOT NULL REFERENCES event(id) ON DELETE CASCADE,
  rank      INTEGER NOT NULL,                     -- 1-based order in tool_response
  url       TEXT    NOT NULL,
  url_norm  TEXT    NOT NULL,
  title     TEXT,                                 -- matching only, never rendered in v0.1
  PRIMARY KEY (event_id, rank)
);
CREATE INDEX result_url_norm ON result(url_norm);

CREATE VIRTUAL TABLE event_fts USING fts5(
  match_text,
  content = 'event',
  content_rowid = 'id',
  tokenize = 'unicode61'
);
CREATE TRIGGER event_fts_ai AFTER INSERT ON event BEGIN
  INSERT INTO event_fts(rowid, match_text) VALUES (new.id, new.match_text);
END;
CREATE TRIGGER event_fts_ad AFTER DELETE ON event BEGIN
  INSERT INTO event_fts(event_fts, rowid, match_text) VALUES ('delete', old.id, old.match_text);
END;
CREATE TRIGGER event_fts_au AFTER UPDATE OF match_text ON event BEGIN
  INSERT INTO event_fts(event_fts, rowid, match_text) VALUES ('delete', old.id, old.match_text);
  INSERT INTO event_fts(rowid, match_text) VALUES (new.id, new.match_text);
END;

CREATE TABLE injection (
  id               INTEGER PRIMARY KEY,
  ref              TEXT    NOT NULL UNIQUE,       -- 8 hex chars, printed in the wrapper tag
  created_at       INTEGER NOT NULL,
  hook             TEXT    NOT NULL CHECK (hook IN ('UserPromptSubmit','PreToolUse','PostToolUse')),
  channel          TEXT    NOT NULL CHECK (channel IN ('url','query','prompt_url','prompt_bm25')),
  mode             TEXT    NOT NULL CHECK (mode IN ('inject','shadow','deny','shadow_deny','below_cutoff')),
  session_id       TEXT    NOT NULL,
  agent_id         TEXT,
  tool_use_id      TEXT,                          -- triggering call; NULL for prompts
  transcript_path  TEXT,                          -- from hook stdin; used by doctor --delivery
  trigger_text     TEXT,                          -- first 200 chars of query, fetch prompt or prompt
  cutoff           REAL,
  rendered         TEXT,                          -- exact text given to the model (inject, deny)
  rendered_chars   INTEGER NOT NULL DEFAULT 0,
  latency_ms       INTEGER NOT NULL
);
CREATE INDEX injection_created_at ON injection(created_at);
CREATE INDEX injection_agent      ON injection(session_id, agent_id);

CREATE TABLE injection_item (
  injection_id  INTEGER NOT NULL REFERENCES injection(id) ON DELETE CASCADE,
  position      INTEGER NOT NULL,                 -- 1..3, order in the block
  event_id      INTEGER NOT NULL REFERENCES event(id) ON DELETE CASCADE,
  score         REAL    NOT NULL,                 -- negated bm25, 1.0 for url matches
  PRIMARY KEY (injection_id, position)
);
CREATE INDEX injection_item_event ON injection_item(event_id);

CREATE TABLE outcome (
  injection_id  INTEGER NOT NULL,
  position      INTEGER NOT NULL,
  label         TEXT    NOT NULL CHECK (label IN ('2','1','0','h')),
  labelled_at   INTEGER NOT NULL,
  PRIMARY KEY (injection_id, position),
  FOREIGN KEY (injection_id, position)
    REFERENCES injection_item(injection_id, position) ON DELETE CASCADE
);

CREATE TABLE hook_run (
  id          INTEGER PRIMARY KEY,
  started_at  INTEGER NOT NULL,
  hook        TEXT    NOT NULL CHECK (hook IN ('session-start','prompt','pre-fetch','post-tool','capture')),
  session_id  TEXT,
  agent_kind  TEXT    NOT NULL CHECK (agent_kind IN ('main','subagent')),
  total_ms    INTEGER NOT NULL,                   -- process start to output written
  search_ms   INTEGER,                            -- matching only
  outcome     TEXT    NOT NULL CHECK (outcome IN ('injected','shadow','denied','no_match','gated',
                        'deadline','locked','error','off','captured','skipped','spooled')),
  error       TEXT
);
CREATE INDEX hook_run_started_at ON hook_run(started_at);

CREATE TABLE tombstone (
  kind        TEXT    NOT NULL CHECK (kind IN ('tool_use_id','url_hash')),
  value       TEXT    NOT NULL,                   -- tool_use_id, or sha256 hex of url_norm
  created_at  INTEGER NOT NULL,
  PRIMARY KEY (kind, value)
);
