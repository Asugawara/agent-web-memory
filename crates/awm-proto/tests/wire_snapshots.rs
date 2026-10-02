//! Sync protocol v1 snapshots (TM2, `docs/sync-v1.md` §17).
//!
//! - every fixture in `tests/fixtures/v1/` validates against its JSON Schema snapshot in
//!   `schemas/v1/`, decodes into its Rust type and serialises back to the same JSON after
//!   canonicalisation (sorted keys, no whitespace);
//! - each schema agrees with its Rust type: removing any field, or adding an unknown one, at any
//!   depth of any fixture is accepted by the schema exactly when it is accepted by serde;
//! - requests refuse unknown fields, responses and plaintexts ignore them, and a plaintext with
//!   a higher `schema` decodes as `Newer`.
//!
//! No JSON Schema crate is a dependency (TM1), so `schema` below validates the subset of draft
//! 2020-12 the snapshots use and fails on any other keyword, so nothing is silently skipped.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use awm_proto::wire::*;
use serde::de::DeserializeOwned;
use serde::Serialize;
use serde_json::{json, Map, Value};

// ---------------------------------------------------------------------------------------------
// Fixtures, schemas and the Rust type of each

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    /// Strict: unknown fields refused.
    Request,
    /// Lenient: unknown fields ignored.
    Response,
    /// Lenient, and decoded through `decode_plaintext`.
    Plaintext,
}

type RoundTrip = fn(&Value) -> Result<Value, String>;

fn rt<T: DeserializeOwned + Serialize>(v: &Value) -> Result<Value, String> {
    let t: T = serde_json::from_value(v.clone()).map_err(|e| e.to_string())?;
    serde_json::to_value(&t).map_err(|e| e.to_string())
}

struct Case {
    fixture: &'static str,
    schema: &'static str,
    kind: Kind,
    rt: RoundTrip,
}

macro_rules! cases {
    ($($fixture:literal => $schema:literal, $kind:ident, $ty:ty;)*) => {
        vec![$(Case { fixture: $fixture, schema: $schema, kind: Kind::$kind, rt: rt::<$ty> },)*]
    };
}

fn cases() -> Vec<Case> {
    let mut v = cases! {
        "info.response" => "info.response", Response, InfoResponse;
        "bootstrap.request" => "bootstrap.request", Request, BootstrapRequest;
        "bootstrap.response" => "bootstrap.response", Response, BootstrapResponse;
        "join.request" => "join.request", Request, JoinRequest;
        "join.response" => "join.response", Response, JoinResponse;
        "status.response" => "status.response", Response, StatusResponse;
        "records.push.request" => "records.push.request", Request, PushRequest;
        "records.push.response" => "records.push.response", Response, PushResponse;
        "records.query" => "records.query", Request, RecordsQuery;
        "records.response" => "records.response", Response, StreamRecords;
        "pull.request" => "pull.request", Request, PullRequest;
        "pull.response" => "pull.response", Response, PullResponse;
        "deletions.query" => "deletions.query", Request, DeletionsQuery;
        "deletions.response" => "deletions.response", Response, DeletionsResponse;
        "delete.request.ids" => "delete.request", Request, DeleteRequest;
        "delete.request.all_mine" => "delete.request", Request, DeleteRequest;
        "delete.request.member" => "delete.request", Request, DeleteRequest;
        "delete.response" => "delete.response", Response, DeleteResponse;
        "members.response" => "members.response", Response, MembersResponse;
        "invites.request.member" => "invites.request", Request, InviteRequest;
        "invites.request.device" => "invites.request", Request, InviteRequest;
        "invites.response" => "invites.response", Response, InviteResponse;
        "approve.request" => "approve.request", Request, ApproveRequest;
        "members.remove.request" => "members.remove.request", Request, RemoveRequest;
        "members.role.request" => "members.role.request", Request, RoleRequest;
        "keys.response" => "keys.response", Response, KeysResponse;
        "keys.rotate.request" => "keys.rotate.request", Request, RotateRequest;
        "token.rotate.response" => "token.rotate.response", Response, TokenRotateResponse;
        "audit.query" => "audit.query", Request, AuditQuery;
        "audit.response" => "audit.response", Response, AuditResponse;
        "settings.response" => "settings.response", Response, OrgSettings;
        "settings.put.request" => "settings.put.request", Request, SettingsUpdate;
        "settings.put.request.cancel" => "settings.put.request", Request, SettingsUpdate;
        "restore.complete.request" => "restore.complete.request", Request, RestoreCompleteRequest;
        "plaintext.rec.search" => "plaintext.rec", Plaintext, RecPlaintext;
        "plaintext.rec.fetch" => "plaintext.rec", Plaintext, RecPlaintext;
        "plaintext.rec.link" => "plaintext.rec", Plaintext, RecPlaintext;
        "plaintext.flag" => "plaintext.flag", Plaintext, FlagPlaintext;
        "plaintext.stats" => "plaintext.stats", Plaintext, StatsPlaintext;
        "plaintext.policy" => "plaintext.policy", Plaintext, PolicyPlaintext;
        "plaintext.roster.approve" => "plaintext.roster", Plaintext, RosterPlaintext;
        "plaintext.roster.revoke" => "plaintext.roster", Plaintext, RosterPlaintext;
        "plaintext.roster.epoch" => "plaintext.roster", Plaintext, RosterPlaintext;
    };
    for name in error_fixtures() {
        v.push(Case {
            fixture: name,
            schema: "error",
            kind: Kind::Response,
            rt: rt::<ErrorBody>,
        });
    }
    v
}

/// One error fixture per v1 error code: `error.{status}.{code}`.
fn error_fixtures() -> Vec<&'static str> {
    vec![
        "error.400.malformed",
        "error.400.unknown_field",
        "error.400.invalid_value",
        "error.400.bad_client_header",
        "error.401.unauthenticated",
        "error.402.payment_required",
        "error.403.forbidden",
        "error.403.not_approved",
        "error.404.not_found",
        "error.409.stream_conflict",
        "error.409.id_conflict",
        "error.409.stale_epoch",
        "error.409.epoch_conflict",
        "error.409.device_conflict",
        "error.409.last_admin",
        "error.410.deleted",
        "error.410.invite_gone",
        "error.413.too_large",
        "error.422.bad_envelope",
        "error.426.client_too_old",
        "error.429.rate_limited",
        "error.503.maintenance",
        "error.503.restore_pending",
    ]
}

fn crate_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn fixture_dir() -> PathBuf {
    crate_dir().join("tests/fixtures/v1")
}

fn schema_dir() -> PathBuf {
    crate_dir().join("schemas/v1")
}

fn read_json(path: &Path) -> Value {
    let text = fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn fixture(name: &str) -> Value {
    read_json(&fixture_dir().join(format!("{name}.json")))
}

fn stems(dir: &Path, suffix: &str) -> BTreeSet<String> {
    fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .filter_map(|n| n.strip_suffix(suffix).map(str::to_string))
        .collect()
}

/// Sorted keys, no whitespace: the form fixtures and Rust output are compared in.
fn canon(v: &Value) -> String {
    fn sort(v: &Value) -> Value {
        match v {
            Value::Object(m) => {
                let sorted: BTreeMap<&String, Value> =
                    m.iter().map(|(k, v)| (k, sort(v))).collect();
                Value::Object(sorted.into_iter().map(|(k, v)| (k.clone(), v)).collect())
            }
            Value::Array(a) => Value::Array(a.iter().map(sort).collect()),
            other => other.clone(),
        }
    }
    serde_json::to_string(&sort(v)).unwrap()
}

// ---------------------------------------------------------------------------------------------
// A JSON Schema subset (draft 2020-12): exactly the keywords the snapshots use

mod schema {
    use super::*;

    const KEYWORDS: &[&str] = &[
        "$schema",
        "$id",
        "$defs",
        "$ref",
        "title",
        "description",
        "type",
        "properties",
        "required",
        "additionalProperties",
        "items",
        "minItems",
        "maxItems",
        "enum",
        "const",
        "minimum",
        "maximum",
        "multipleOf",
        "minLength",
        "maxLength",
        "pattern",
        "oneOf",
    ];

    pub struct Set {
        docs: BTreeMap<String, Value>,
    }

    impl Set {
        pub fn load() -> Set {
            let docs = stems(&schema_dir(), ".schema.json")
                .into_iter()
                .map(|s| {
                    let file = format!("{s}.schema.json");
                    let v = read_json(&schema_dir().join(&file));
                    (file, v)
                })
                .collect();
            Set { docs }
        }

        pub fn files(&self) -> impl Iterator<Item = (&String, &Value)> {
            self.docs.iter()
        }

        pub fn validate(&self, name: &str, inst: &Value) -> Result<(), Vec<String>> {
            let file = format!("{name}.schema.json");
            let root = self
                .docs
                .get(&file)
                .unwrap_or_else(|| panic!("no schema {file}"));
            let mut errs = Vec::new();
            self.check(&file, root, inst, "", &mut errs);
            if errs.is_empty() {
                Ok(())
            } else {
                Err(errs)
            }
        }

        fn resolve<'a>(&'a self, file: &str, r: &str) -> (String, &'a Value) {
            let (f, pointer) = r.split_once('#').expect("$ref with #");
            let f = if f.is_empty() {
                file.to_string()
            } else {
                f.to_string()
            };
            let doc = self
                .docs
                .get(&f)
                .unwrap_or_else(|| panic!("$ref to missing {f}"));
            let target = doc
                .pointer(pointer)
                .unwrap_or_else(|| panic!("$ref {r} does not resolve"));
            (f, target)
        }

        fn check(&self, file: &str, s: &Value, v: &Value, at: &str, errs: &mut Vec<String>) {
            let s = match s {
                Value::Bool(true) => return,
                Value::Bool(false) => return errs.push(format!("{at}: not allowed")),
                Value::Object(m) => m,
                _ => panic!("{file}: schema at {at} is neither object nor boolean"),
            };
            for k in s.keys() {
                assert!(
                    KEYWORDS.contains(&k.as_str()),
                    "{file}: unsupported keyword {k}"
                );
            }
            if let Some(Value::String(r)) = s.get("$ref") {
                let (f, target) = self.resolve(file, r);
                self.check(&f, target, v, at, errs);
            }
            if let Some(t) = s.get("type") {
                let ok = match t.as_str().expect("type is a string") {
                    "object" => v.is_object(),
                    "array" => v.is_array(),
                    "string" => v.is_string(),
                    "integer" => v.is_i64() || v.is_u64(),
                    "number" => v.is_number(),
                    "boolean" => v.is_boolean(),
                    "null" => v.is_null(),
                    other => panic!("{file}: type {other}"),
                };
                if !ok {
                    return errs.push(format!("{at}: expected {t}"));
                }
            }
            if let Some(Value::Array(options)) = s.get("enum") {
                if !options.contains(v) {
                    errs.push(format!("{at}: {v} not in enum"));
                }
            }
            if let Some(c) = s.get("const") {
                if c != v {
                    errs.push(format!("{at}: expected const {c}"));
                }
            }
            if let Some(n) = v.as_f64() {
                if let Some(min) = s.get("minimum").and_then(Value::as_f64) {
                    if n < min {
                        errs.push(format!("{at}: below {min}"));
                    }
                }
                if let Some(max) = s.get("maximum").and_then(Value::as_f64) {
                    if n > max {
                        errs.push(format!("{at}: above {max}"));
                    }
                }
                if let Some(m) = s.get("multipleOf").and_then(Value::as_i64) {
                    if v.as_i64().is_none_or(|i| i % m != 0) {
                        errs.push(format!("{at}: not a multiple of {m}"));
                    }
                }
            }
            if let Some(text) = v.as_str() {
                let chars = text.chars().count() as u64;
                if let Some(min) = s.get("minLength").and_then(Value::as_u64) {
                    if chars < min {
                        errs.push(format!("{at}: shorter than {min}"));
                    }
                }
                if let Some(max) = s.get("maxLength").and_then(Value::as_u64) {
                    if chars > max {
                        errs.push(format!("{at}: longer than {max}"));
                    }
                }
                if let Some(Value::String(p)) = s.get("pattern") {
                    if !super::pattern::Pattern::compile(p).matches(text) {
                        errs.push(format!("{at}: {text:?} does not match {p}"));
                    }
                }
            }
            if let Some(items) = v.as_array() {
                if let Some(min) = s.get("minItems").and_then(Value::as_u64) {
                    if (items.len() as u64) < min {
                        errs.push(format!("{at}: fewer than {min} items"));
                    }
                }
                if let Some(max) = s.get("maxItems").and_then(Value::as_u64) {
                    if items.len() as u64 > max {
                        errs.push(format!("{at}: more than {max} items"));
                    }
                }
                if let Some(item_schema) = s.get("items") {
                    for (i, item) in items.iter().enumerate() {
                        self.check(file, item_schema, item, &format!("{at}/{i}"), errs);
                    }
                }
            }
            if let Some(o) = v.as_object() {
                let props = s.get("properties").and_then(Value::as_object);
                if let Some(Value::Array(req)) = s.get("required") {
                    for r in req {
                        let r = r.as_str().unwrap();
                        if !o.contains_key(r) {
                            errs.push(format!("{at}: missing {r}"));
                        }
                    }
                }
                for (k, val) in o {
                    match props.and_then(|p| p.get(k)) {
                        Some(ps) => self.check(file, ps, val, &format!("{at}/{k}"), errs),
                        None => {
                            if s.get("additionalProperties") == Some(&Value::Bool(false)) {
                                errs.push(format!("{at}: unknown field {k}"));
                            }
                        }
                    }
                }
            }
            if let Some(Value::Array(branches)) = s.get("oneOf") {
                let passing = branches
                    .iter()
                    .filter(|b| {
                        let mut e = Vec::new();
                        self.check(file, b, v, at, &mut e);
                        e.is_empty()
                    })
                    .count();
                if passing != 1 {
                    errs.push(format!("{at}: {passing} oneOf branches match"));
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Anchored patterns: literals, `\` escapes, `[...]` classes, `(a|b)` groups, `? * + {n} {n,m}`

mod pattern {
    #[derive(Debug)]
    enum Atom {
        Lit(char),
        Class(Vec<(char, char)>),
        Group(Vec<Vec<Piece>>),
    }

    #[derive(Debug)]
    struct Piece {
        atom: Atom,
        min: usize,
        max: usize,
    }

    pub struct Pattern(Vec<Piece>);

    impl Pattern {
        /// Panics on anything outside the subset, so a schema cannot use an unchecked construct.
        pub fn compile(p: &str) -> Pattern {
            let inner = p
                .strip_prefix('^')
                .and_then(|x| x.strip_suffix('$'))
                .unwrap_or_else(|| panic!("pattern {p} must be anchored with ^ and $"));
            let chars: Vec<char> = inner.chars().collect();
            let mut pos = 0;
            let alts = parse_alts(&chars, &mut pos, p);
            assert_eq!(pos, chars.len(), "pattern {p}: unbalanced )");
            Pattern(vec![Piece {
                atom: Atom::Group(alts),
                min: 1,
                max: 1,
            }])
        }

        pub fn matches(&self, s: &str) -> bool {
            let input: Vec<char> = s.chars().collect();
            ends(&self.0, &input, 0).contains(&input.len())
        }
    }

    fn parse_alts(c: &[char], pos: &mut usize, p: &str) -> Vec<Vec<Piece>> {
        let mut alts = vec![Vec::new()];
        while *pos < c.len() {
            match c[*pos] {
                ')' => break,
                '|' => {
                    *pos += 1;
                    alts.push(Vec::new());
                }
                _ => {
                    let atom = parse_atom(c, pos, p);
                    let (min, max) = parse_quant(c, pos, p);
                    alts.last_mut().unwrap().push(Piece { atom, min, max });
                }
            }
        }
        alts
    }

    fn parse_atom(c: &[char], pos: &mut usize, p: &str) -> Atom {
        let ch = c[*pos];
        *pos += 1;
        match ch {
            '\\' => {
                let e = c[*pos];
                *pos += 1;
                assert!("\\.-()[]{}|?*+^$".contains(e), "pattern {p}: escape \\{e}");
                Atom::Lit(e)
            }
            '(' => {
                let alts = parse_alts(c, pos, p);
                assert_eq!(c.get(*pos), Some(&')'), "pattern {p}: missing )");
                *pos += 1;
                Atom::Group(alts)
            }
            '[' => {
                assert_ne!(c.get(*pos), Some(&'^'), "pattern {p}: negated class");
                let mut ranges = Vec::new();
                while c[*pos] != ']' {
                    let mut lo = c[*pos];
                    *pos += 1;
                    if lo == '\\' {
                        lo = c[*pos];
                        *pos += 1;
                    }
                    if c[*pos] == '-' && c[*pos + 1] != ']' {
                        let hi = c[*pos + 1];
                        *pos += 2;
                        ranges.push((lo, hi));
                    } else {
                        ranges.push((lo, lo));
                    }
                }
                *pos += 1;
                Atom::Class(ranges)
            }
            '.' | '*' | '+' | '?' | '{' | '}' | ']' | '^' | '$' => {
                panic!("pattern {p}: unsupported {ch}")
            }
            other => Atom::Lit(other),
        }
    }

    fn parse_quant(c: &[char], pos: &mut usize, p: &str) -> (usize, usize) {
        match c.get(*pos) {
            Some('?') => {
                *pos += 1;
                (0, 1)
            }
            Some('*') => {
                *pos += 1;
                (0, usize::MAX)
            }
            Some('+') => {
                *pos += 1;
                (1, usize::MAX)
            }
            Some('{') => {
                let close = c[*pos..].iter().position(|&x| x == '}').unwrap() + *pos;
                let body: String = c[*pos + 1..close].iter().collect();
                *pos = close + 1;
                let num = |s: &str| s.parse::<usize>().unwrap_or_else(|_| panic!("pattern {p}"));
                match body.split_once(',') {
                    Some((a, b)) => (num(a), num(b)),
                    None => (num(&body), num(&body)),
                }
            }
            _ => (1, 1),
        }
    }

    fn atom_ends(a: &Atom, input: &[char], pos: usize) -> Vec<usize> {
        match a {
            Atom::Lit(ch) => {
                if input.get(pos) == Some(ch) {
                    vec![pos + 1]
                } else {
                    vec![]
                }
            }
            Atom::Class(ranges) => match input.get(pos) {
                Some(ch) if ranges.iter().any(|(lo, hi)| lo <= ch && ch <= hi) => vec![pos + 1],
                _ => vec![],
            },
            Atom::Group(alts) => {
                let mut out: Vec<usize> = alts.iter().flat_map(|s| ends(s, input, pos)).collect();
                out.sort_unstable();
                out.dedup();
                out
            }
        }
    }

    /// Every position at which matching `seq` from `pos` can end.
    fn ends(seq: &[Piece], input: &[char], pos: usize) -> Vec<usize> {
        let mut current = vec![pos];
        for piece in seq {
            let mut reached = Vec::new();
            let mut frontier = current.clone();
            if piece.min == 0 {
                reached.extend(current.iter().copied());
            }
            let mut count = 0;
            // Every repetition of a non-empty atom consumes a character, so input.len() + 1
            // repetitions bound `*` and `+`.
            while !frontier.is_empty() && count < piece.max && count <= input.len() {
                count += 1;
                let mut next: Vec<usize> = frontier
                    .iter()
                    .flat_map(|&p| atom_ends(&piece.atom, input, p))
                    .collect();
                next.sort_unstable();
                next.dedup();
                if count >= piece.min {
                    reached.extend(next.iter().copied());
                }
                frontier = next;
            }
            reached.sort_unstable();
            reached.dedup();
            current = reached;
            if current.is_empty() {
                break;
            }
        }
        current
    }

    #[test]
    fn the_pattern_subset_matches_like_a_regex() {
        let uuid = "^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$";
        let p = Pattern::compile(uuid);
        assert!(p.matches("6f1c2a4e-8b3d-4e5f-9a7b-1c2d3e4f5a6b"));
        assert!(!p.matches("6F1C2A4E-8B3D-4E5F-9A7B-1C2D3E4F5A6B"));
        assert!(!p.matches("6f1c2a4e8b3d4e5f9a7b1c2d3e4f5a6b"));
        let v = Pattern::compile(
            "^(0|[1-9][0-9]{0,4})\\.(0|[1-9][0-9]{0,4})\\.(0|[1-9][0-9]{0,4})(-[0-9A-Za-z.-]{1,32})?$",
        );
        for ok in ["0.2.0", "10.0.1", "0.2.0-rc.1", "1.2.3-dev-4"] {
            assert!(v.matches(ok), "{ok}");
        }
        for bad in ["0.2", "01.2.3", "0.2.0-", "0.2.0+b", "v0.2.0"] {
            assert!(!v.matches(bad), "{bad}");
        }
        let h = Pattern::compile("^[a-z0-9_-]{1,24}$");
        assert!(h.matches("a-b_c9"));
        assert!(!h.matches(""));
        assert!(!h.matches(&"a".repeat(25)));
        assert!(Pattern::compile("^[A-Za-z0-9_-]*$").matches(""));
        assert!(Pattern::compile("^a+b?$").matches("aaab"));
        assert!(!Pattern::compile("^a+b?$").matches("b"));
    }
}

// ---------------------------------------------------------------------------------------------
// Snapshot tests

#[test]
fn every_fixture_and_schema_is_listed() {
    let listed: BTreeSet<String> = cases().iter().map(|c| c.fixture.to_string()).collect();
    assert_eq!(
        listed,
        stems(&fixture_dir(), ".json"),
        "fixtures on disk vs the case table"
    );
    let mut used: BTreeSet<String> = cases().iter().map(|c| c.schema.to_string()).collect();
    used.insert("common".to_string());
    assert_eq!(
        used,
        stems(&schema_dir(), ".schema.json"),
        "schemas on disk vs the case table"
    );
}

#[test]
fn every_fixture_validates_against_its_schema() {
    let set = schema::Set::load();
    for c in cases() {
        if let Err(e) = set.validate(c.schema, &fixture(c.fixture)) {
            panic!("{} against {}: {e:?}", c.fixture, c.schema);
        }
    }
}

#[test]
fn every_fixture_round_trips_byte_for_byte_after_canonicalisation() {
    for c in cases() {
        let v = fixture(c.fixture);
        let back = (c.rt)(&v).unwrap_or_else(|e| panic!("{}: {e}", c.fixture));
        assert_eq!(canon(&back), canon(&v), "{}", c.fixture);
    }
}

#[test]
fn rust_output_validates_against_the_schema() {
    let set = schema::Set::load();
    for c in cases() {
        let back = (c.rt)(&fixture(c.fixture)).unwrap();
        if let Err(e) = set.validate(c.schema, &back) {
            panic!("{}: serialised value fails {}: {e:?}", c.fixture, c.schema);
        }
    }
}

/// Every object inside `v`, by JSON pointer.
fn object_paths(v: &Value, at: String, out: &mut Vec<String>) {
    match v {
        Value::Object(m) => {
            out.push(at.clone());
            for (k, x) in m {
                object_paths(x, format!("{at}/{k}"), out);
            }
        }
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                object_paths(x, format!("{at}/{i}"), out);
            }
        }
        _ => {}
    }
}

fn object_at<'a>(v: &'a mut Value, path: &str) -> &'a mut Map<String, Value> {
    v.pointer_mut(path).unwrap().as_object_mut().unwrap()
}

#[test]
fn every_schema_agrees_with_its_rust_type_on_every_missing_or_unknown_field() {
    let set = schema::Set::load();
    let mut mutations = 0;
    for c in cases() {
        let base = fixture(c.fixture);
        let mut paths = Vec::new();
        object_paths(&base, String::new(), &mut paths);
        for path in paths {
            let keys: Vec<String> = base
                .pointer(&path)
                .unwrap()
                .as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect();
            let mut variants = Vec::new();
            for k in keys {
                let mut m = base.clone();
                object_at(&mut m, &path).remove(&k);
                variants.push((format!("{path} without {k}"), m));
            }
            let mut m = base.clone();
            object_at(&mut m, &path).insert("zz_future".into(), json!({"x": 1}));
            variants.push((format!("{path} with zz_future"), m));
            for (what, m) in variants {
                mutations += 1;
                let by_schema = set.validate(c.schema, &m).is_ok();
                let by_serde = (c.rt)(&m).is_ok();
                assert_eq!(
                    by_schema, by_serde,
                    "{} ({}): schema says {by_schema}, serde says {by_serde}",
                    c.fixture, what
                );
            }
        }
    }
    assert!(mutations > 500, "only {mutations} mutations");
}

#[test]
fn every_schema_property_appears_in_a_fixture() {
    fn props(v: &Value, out: &mut BTreeSet<String>) {
        match v {
            Value::Object(m) => {
                if let Some(Value::Object(p)) = m.get("properties") {
                    out.extend(p.keys().cloned());
                }
                m.values().for_each(|x| props(x, out));
            }
            Value::Array(a) => a.iter().for_each(|x| props(x, out)),
            _ => {}
        }
    }
    fn keys(v: &Value, out: &mut BTreeSet<String>) {
        match v {
            Value::Object(m) => {
                out.extend(m.keys().cloned());
                m.values().for_each(|x| keys(x, out));
            }
            Value::Array(a) => a.iter().for_each(|x| keys(x, out)),
            _ => {}
        }
    }
    let set = schema::Set::load();
    let all = cases();
    for (file, doc) in set.files() {
        let name = file.strip_suffix(".schema.json").unwrap();
        if name == "common" {
            continue;
        }
        let mut declared = BTreeSet::new();
        props(doc, &mut declared);
        let mut seen = BTreeSet::new();
        for c in all.iter().filter(|c| c.schema == name) {
            keys(&fixture(c.fixture), &mut seen);
        }
        // Properties whose schema is `false` exist only to be absent.
        let forbidden = ["epoch", "blob", "received_at", "deleted"];
        let missing: Vec<_> = declared
            .difference(&seen)
            .filter(|p| !(name.ends_with("response") && forbidden.contains(&p.as_str())))
            .collect();
        assert!(missing.is_empty(), "{name}: no fixture sets {missing:?}");
    }
}

// ---------------------------------------------------------------------------------------------
// Compatibility rules (`docs/sync-v1.md` §14)

fn inject_everywhere(v: &Value) -> Value {
    let mut m = v.clone();
    let mut paths = Vec::new();
    object_paths(v, String::new(), &mut paths);
    for p in paths {
        object_at(&mut m, &p).insert("zz_future".into(), json!(["added", "in", "v1.1"]));
    }
    m
}

#[test]
fn unknown_fields_are_ignored_in_responses_and_plaintexts() {
    for c in cases().iter().filter(|c| c.kind != Kind::Request) {
        let v = fixture(c.fixture);
        let back = (c.rt)(&inject_everywhere(&v)).unwrap_or_else(|e| panic!("{}: {e}", c.fixture));
        assert_eq!(canon(&back), canon(&v), "{}", c.fixture);
    }
}

#[test]
fn unknown_fields_are_refused_in_requests() {
    for c in cases().iter().filter(|c| c.kind == Kind::Request) {
        let err = (c.rt)(&inject_everywhere(&fixture(c.fixture))).unwrap_err();
        assert!(
            err.contains("unknown field") && err.contains("zz_future"),
            "{}: {err}",
            c.fixture
        );
    }
}

#[test]
fn unknown_tags_roles_and_error_codes_decode() {
    let mut status = fixture("status.response");
    status["streams"][0]["tag"] = json!("digest");
    let s: StatusResponse = serde_json::from_value(status.clone()).unwrap();
    assert_eq!(s.streams[0].tag.known(), None);
    assert_eq!(s.streams[1].tag.known(), Some(KnownTag::Roster));
    assert_eq!(canon(&serde_json::to_value(&s).unwrap()), canon(&status));
    // The cursor of an unknown tag is still sent.
    let c = Cursor {
        member: s.streams[0].member,
        device: s.streams[0].device,
        tag: s.streams[0].tag.clone(),
        from: 44,
    };
    assert_eq!(serde_json::to_value(&c).unwrap()["tag"], json!("digest"));

    let mut members = fixture("members.response");
    members["members"][1]["role"] = json!("owner");
    let m: MembersResponse = serde_json::from_value(members).unwrap();
    assert_eq!(m.members[1].role, Role::Unknown);

    let e: ErrorBody =
        serde_json::from_value(json!({"error": "quota_exceeded", "message": "x"})).unwrap();
    assert_eq!(e.error, ErrorCode::Unknown);
    assert_eq!(e.error.status(), None);
}

#[test]
fn a_plaintext_with_a_higher_schema_decodes_as_newer() {
    for c in cases().iter().filter(|c| c.kind == Kind::Plaintext) {
        let v = fixture(c.fixture);
        let bytes = serde_json::to_vec(&v).unwrap();
        let known = match c.schema {
            "plaintext.rec" => matches!(
                decode_plaintext::<RecPlaintext>(&bytes),
                Ok(Decoded::Known(_))
            ),
            "plaintext.flag" => matches!(
                decode_plaintext::<FlagPlaintext>(&bytes),
                Ok(Decoded::Known(_))
            ),
            "plaintext.stats" => matches!(
                decode_plaintext::<StatsPlaintext>(&bytes),
                Ok(Decoded::Known(_))
            ),
            "plaintext.policy" => matches!(
                decode_plaintext::<PolicyPlaintext>(&bytes),
                Ok(Decoded::Known(_))
            ),
            "plaintext.roster" => matches!(
                decode_plaintext::<RosterPlaintext>(&bytes),
                Ok(Decoded::Known(_))
            ),
            other => panic!("{other}"),
        };
        assert!(known, "{}", c.fixture);
    }
    // A schema-2 record whose fields a v1 reader would not parse: no error, the index is skipped.
    let future = json!({
        "schema": 2, "tool": "WebBrowse", "status": {"code": "ok"}, "results": "none",
        "created_at": "2027-01-01T00:00:00Z"
    });
    let bytes = serde_json::to_vec(&future).unwrap();
    assert_eq!(
        decode_plaintext::<RecPlaintext>(&bytes),
        Ok(Decoded::Newer { schema: 2 })
    );
    assert_eq!(
        decode_plaintext::<RosterPlaintext>(br#"{"schema":7}"#),
        Ok(Decoded::Newer { schema: 7 })
    );
    // Schema 1 must parse; schema 0 and a missing schema are errors (dropped and counted).
    let mut broken = fixture("plaintext.rec.search");
    broken.as_object_mut().unwrap().remove("status");
    assert!(decode_plaintext::<RecPlaintext>(&serde_json::to_vec(&broken).unwrap()).is_err());
    assert!(decode_plaintext::<RecPlaintext>(br#"{"schema":0}"#).is_err());
    assert!(decode_plaintext::<RecPlaintext>(br#"{"tool":"WebFetch"}"#).is_err());
}

// ---------------------------------------------------------------------------------------------
// Scalars, header, tokens, limits

#[test]
fn ids_must_be_canonical() {
    let ok = "6f1c2a4e-8b3d-4e5f-9a7b-1c2d3e4f5a6b";
    assert_eq!(Id::parse(ok).unwrap().to_string(), ok);
    for bad in [
        "6F1C2A4E-8B3D-4E5F-9A7B-1C2D3E4F5A6B",
        "{6f1c2a4e-8b3d-4e5f-9a7b-1c2d3e4f5a6b}",
        "6f1c2a4e8b3d4e5f9a7b1c2d3e4f5a6b",
        "urn:uuid:6f1c2a4e-8b3d-4e5f-9a7b-1c2d3e4f5a6b",
        "",
    ] {
        assert!(Id::parse(bad).is_err(), "{bad}");
        assert!(serde_json::from_value::<Id>(json!(bad)).is_err(), "{bad}");
    }
    assert!(Handle::parse("alf").is_ok());
    for bad in ["", "Alf", "a b", "á", &"a".repeat(25)] {
        assert!(Handle::parse(bad).is_err(), "{bad}");
    }
    assert!(Tag::parse("rec").is_ok() && Tag::parse("new_tag2").is_ok());
    for bad in ["", "Rec", "2rec", "rec-x", "abcdefghijklmnopq"] {
        assert!(Tag::parse(bad).is_err(), "{bad}");
    }
    // Padding and non-canonical trailing bits are refused, so a blob has one encoding.
    assert!(serde_json::from_value::<B64>(json!("AQ")).is_ok());
    assert!(serde_json::from_value::<B64>(json!("AQ==")).is_err());
    assert!(serde_json::from_value::<B64>(json!("AR")).is_err());
    assert!(serde_json::from_value::<B64>(json!("A+/=")).is_err());
}

#[test]
fn the_client_header_parses_and_gates_writes() {
    let h = ClientHeader::parse("awm/0.2.0 proto/1 redact/3").unwrap();
    assert_eq!(h.awm, Version::new(0, 2, 0));
    assert_eq!((h.proto, h.redact), (1, 3));
    assert_eq!(h.to_string(), "awm/0.2.0 proto/1 redact/3");
    let ext = ClientHeader::parse("awm/0.3.0-rc.1 proto/2 redact/4 os/macos arch/aarch64").unwrap();
    assert_eq!(ext.awm.pre.as_deref(), Some("rc.1"));
    for bad in [
        "",
        "awm/0.2.0",
        "awm/0.2.0 proto/1",
        "awm/0.2.0  proto/1 redact/3",
        "proto/1 awm/0.2.0 redact/3",
        "awm/0.2 proto/1 redact/3",
        "awm/0.2.0 proto/0 redact/3",
        "awm/0.2.0 proto/01 redact/3",
        "awm/0.2.0+build proto/1 redact/3",
        "awm/0.2.0 proto/1 redact/3 junk",
        "awm/0.2.0 proto/1 redact/3 Os/x",
    ] {
        assert!(ClientHeader::parse(bad).is_err(), "{bad:?}");
    }
    let long = format!("awm/0.2.0 proto/1 redact/3 x/{}", "a".repeat(240));
    assert!(ClientHeader::parse(&long).is_err());

    let min = Version::parse("0.2.1").unwrap();
    let below = |s: &str| {
        ClientHeader::parse(&format!("awm/{s} proto/1 redact/3"))
            .unwrap()
            .below(&min)
    };
    assert!(below("0.2.0"));
    assert!(below("0.2.1-rc.1"));
    assert!(!below("0.2.1"));
    assert!(!below("0.10.0"));
    assert!(!below("1.0.0-alpha"));
    let v = |s: &str| Version::parse(s).unwrap();
    assert!(v("1.0.0-alpha") < v("1.0.0-alpha.1"));
    assert!(v("1.0.0-alpha.1") < v("1.0.0-beta"));
    assert!(v("1.0.0-beta.2") < v("1.0.0-beta.11"));
    assert!(v("1.0.0-rc.1") < v("1.0.0"));
}

#[test]
fn tokens_carry_the_org_and_hide_the_secret() {
    let org = Id::parse("6f1c2a4e-8b3d-4e5f-9a7b-1c2d3e4f5a6b").unwrap();
    // 0xfb 0xff… encodes to "-_…": base64url's own characters next to the `_` separator.
    let secret = [0xfb_u8; 32];
    let t = DeviceToken::new(org, &secret);
    assert!(t
        .as_str()
        .starts_with("awm_t_6f1c2a4e-8b3d-4e5f-9a7b-1c2d3e4f5a6b_-"));
    assert_eq!(DeviceToken::parse(t.as_str()).unwrap().org(), org);
    let debug = format!("{t:?}");
    assert!(!debug.contains(&t.as_str()[43..]), "{debug}");
    let inv = InviteToken::new(org, &[7; 32]);
    assert_eq!(inv.org(), org);
    assert!(
        DeviceToken::parse(inv.as_str()).is_err(),
        "an invite token is not a device token"
    );
    let boot = BootstrapToken::new(&[9; 32]);
    assert!(!format!("{boot:?}").contains(&boot.as_str()[6..]));
    for bad in [
        "awm_t_6f1c2a4e-8b3d-4e5f-9a7b-1c2d3e4f5a6b",
        "awm_t_6F1C2A4E-8B3D-4E5F-9A7B-1C2D3E4F5A6B_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "awm_t_6f1c2a4e-8b3d-4e5f-9a7b-1c2d3e4f5a6b-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "awm_t_6f1c2a4e-8b3d-4e5f-9a7b-1c2d3e4f5a6b_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB",
        "awm_t_6f1c2a4e-8b3d-4e5f-9a7b-1c2d3e4f5a6b_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    ] {
        assert!(DeviceToken::parse(bad).is_err(), "{bad}");
    }
    assert!(DeviceToken::parse(
        "awm_t_6f1c2a4e-8b3d-4e5f-9a7b-1c2d3e4f5a6b_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    )
    .is_ok());
}

#[test]
fn the_published_limits_are_the_constants() {
    let info: InfoResponse = serde_json::from_value(fixture("info.response")).unwrap();
    assert_eq!(info.limits, Limits::v1());
    assert_eq!(info.protocols, vec![PROTOCOL_VERSION]);
}

#[test]
fn the_envelope_check_separates_413_from_422() {
    use limits::*;
    let shaped = |len: usize| {
        let mut b = vec![0xa5; len];
        b[0] = ENVELOPE_VERSION;
        b
    };
    let smallest = ENVELOPE_OVERHEAD + PAD_BUCKET;
    let largest = ENVELOPE_OVERHEAD + PAD_BUCKET * ((BLOB_BYTES - ENVELOPE_OVERHEAD) / PAD_BUCKET);
    assert_eq!((smallest, largest), (297, 16_169));
    assert_eq!(check_envelope(&shaped(smallest)), Ok(()));
    assert_eq!(check_envelope(&shaped(largest)), Ok(()));
    assert_eq!(
        check_envelope(&shaped(smallest - 1)),
        Err(ErrorCode::BadEnvelope)
    );
    assert_eq!(
        check_envelope(&shaped(smallest + 1)),
        Err(ErrorCode::BadEnvelope)
    );
    assert_eq!(
        check_envelope(&shaped(largest + PAD_BUCKET)),
        Err(ErrorCode::TooLarge)
    );
    assert_eq!(
        check_envelope(&shaped(BLOB_BYTES + 1)),
        Err(ErrorCode::TooLarge)
    );
    assert_eq!(check_envelope(&[]), Err(ErrorCode::BadEnvelope));
    let mut v2 = shaped(smallest);
    v2[0] = 2;
    assert_eq!(check_envelope(&v2), Err(ErrorCode::BadEnvelope));
    // The schema's blob lengths are these sizes in unpadded base64url.
    let b64_len = |n: usize| (n * 4).div_ceil(3);
    assert_eq!((b64_len(smallest), b64_len(BLOB_BYTES)), (396, 21_846));
    let common = read_json(&schema_dir().join("common.schema.json"));
    assert_eq!(common["$defs"]["blob"]["minLength"], json!(396));
    assert_eq!(common["$defs"]["blob"]["maxLength"], json!(21_846));
}

#[test]
fn the_batch_byte_limit_binds_before_the_record_limit_for_large_blobs() {
    use limits::*;
    let largest = ENVELOPE_OVERHEAD + PAD_BUCKET * ((BLOB_BYTES - ENVELOPE_OVERHEAD) / PAD_BUCKET);
    let item = |idx: u64| {
        PushItem::Record(PushRecord {
            tag: KnownTag::Rec.into(),
            idx,
            id: Id::parse("7e6d5c4b-3a29-4180-9f7e-6d5c4b3a2918").unwrap(),
            epoch: 12,
            blob: B64(vec![1; largest]),
        })
    };
    let body = |n: u64| {
        serde_json::to_vec(&PushRequest {
            records: (0..n).map(|i| item(100_000 + i)).collect(),
        })
        .unwrap()
        .len()
    };
    // Indexes keep six digits, so every item has the same length.
    let per_item = body(2) - body(1);
    let fits = ((BATCH_BYTES - (body(1) - per_item)) / per_item) as u64;
    assert!(body(fits) <= BATCH_BYTES && body(fits + 1) > BATCH_BYTES);
    // `docs/sync-v1.md` §12: at most 72 envelopes of the largest size fit one push.
    assert_eq!(fits, 72);
    assert!(body(BATCH_RECORDS as u64) > BATCH_BYTES);
    assert!(body(BATCH_RECORDS as u64) < BODY_BYTES * 2);
    // Smallest envelopes: 100 records fit easily.
    let small = serde_json::to_vec(&PushRequest {
        records: (0..100)
            .map(|i| {
                PushItem::Record(PushRecord {
                    tag: KnownTag::Rec.into(),
                    idx: i,
                    id: Id::new_v4(),
                    epoch: 0,
                    blob: B64(vec![1; 297]),
                })
            })
            .collect(),
    })
    .unwrap();
    assert!(small.len() < BATCH_BYTES / 30);
}

#[test]
fn every_error_code_has_a_fixture_with_its_status() {
    let mut seen = BTreeSet::new();
    for name in error_fixtures() {
        let parts: Vec<&str> = name.split('.').collect();
        let body: ErrorBody = serde_json::from_value(fixture(name)).unwrap();
        assert_ne!(body.error, ErrorCode::Unknown, "{name}");
        assert_eq!(
            body.error.status(),
            Some(parts[1].parse().unwrap()),
            "{name}"
        );
        assert_eq!(
            serde_json::to_value(body.error).unwrap(),
            json!(parts[2]),
            "{name}"
        );
        seen.insert(parts[2].to_string());
    }
    let schema = read_json(&schema_dir().join("error.schema.json"));
    let listed: BTreeSet<String> = schema["properties"]["error"]["enum"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(seen, listed);
    assert_eq!(seen.len(), 23);
}

#[test]
fn push_and_pull_items_are_records_or_markers_never_both() {
    let pushed: PushRequest = serde_json::from_value(fixture("records.push.request")).unwrap();
    assert!(matches!(pushed.records[0], PushItem::Record(_)));
    assert!(matches!(pushed.records[1], PushItem::Deleted(_)));
    for bad in [
        json!({"tag": "rec", "idx": 1, "id": "7e6d5c4b-3a29-4180-9f7e-6d5c4b3a2918", "deleted": false}),
        json!({"tag": "rec", "idx": 1, "id": "7e6d5c4b-3a29-4180-9f7e-6d5c4b3a2918", "epoch": 1}),
        json!({"tag": "rec", "idx": 1, "id": "7e6d5c4b-3a29-4180-9f7e-6d5c4b3a2918", "epoch": 1,
               "blob": "AQ", "deleted": true}),
    ] {
        assert!(
            serde_json::from_value::<PushItem>(bad.clone()).is_err(),
            "{bad}"
        );
    }
    let pulled: StreamRecords = serde_json::from_value(fixture("records.response")).unwrap();
    let idx: Vec<u64> = pulled.records.iter().map(PulledItem::idx).collect();
    assert_eq!(idx, vec![5, 6, 7], "contiguous, ascending");
    assert!(matches!(pulled.records[1], PulledItem::Deleted(_)));
    for bad in [
        json!({"ids": []}),
        json!({"all_mine": false}),
        json!({"ids": ["7e6d5c4b-3a29-4180-9f7e-6d5c4b3a2918"], "all_mine": true}),
        json!({}),
    ] {
        assert!(
            serde_json::from_value::<DeleteRequest>(bad.clone()).is_err(),
            "{bad}"
        );
    }
    // Count limits are the server's (413 `delete_ids`, `batch_records`), not parse errors.
    let ids: Vec<String> = (0..1001).map(|_| Id::new_v4().to_string()).collect();
    assert!(serde_json::from_value::<DeleteRequest>(json!({ "ids": ids })).is_ok());
}
