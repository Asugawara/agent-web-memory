//! `PgStore`: pooled Postgres with `org_id` row-level security (plan-v3-team §4.2).
//!
//! Stub until TM26: it compiles against the final [`Store`] trait (TM6) and every method
//! panics. TM26 implements it and runs `tests/store_conformance.rs` unchanged against it.

use std::path::PathBuf;

use awm_proto::wire::{
    AuditResponse, Cursor, DeleteRequest, DeleteResponse, DeletionHeads, DeletionsResponse,
    DeviceWrap, EpochWrap, Handle, Id, KeysResponse, MemberInfo, OrgSettings, PullResponse,
    PushResponse, Role, SettingsUpdate, StatusResponse, StreamRecords, Tag, Version,
};

use super::{
    Actor, AuditEntry, AuthDevice, DeviceRow, InviteRow, Joined, LogicalDump, MemberRow,
    NewBootstrap, NewInvite, NewJoin, OrgRow, PushBatch, RestoreState, Store, StoreFuture,
    StoreResult, TableCounts,
};

/// The Postgres-backed store (path A and the cloud).
pub struct PgStore {
    _private: (),
}

impl PgStore {
    /// Connects to `url` with a pool of at most 10 connections.
    pub fn connect(_url: &str) -> StoreResult<PgStore> {
        todo!("TM26: PgStore")
    }
}

impl Store for PgStore {
    fn restore_state(&self) -> StoreFuture<'_, RestoreState> {
        todo!("TM26: PgStore")
    }
    fn renew_generation(&self, _now: i64) -> StoreFuture<'_, Id> {
        todo!("TM26: PgStore")
    }
    fn complete_restore(&self, _generation: Id, _by: Actor, _now: i64) -> StoreFuture<'_, ()> {
        todo!("TM26: PgStore")
    }
    fn meta_get(&self, _key: String) -> StoreFuture<'_, Option<String>> {
        todo!("TM26: PgStore")
    }
    fn meta_set(&self, _key: String, _value: String) -> StoreFuture<'_, ()> {
        todo!("TM26: PgStore")
    }
    fn org(&self, _now: i64) -> StoreFuture<'_, Option<OrgRow>> {
        todo!("TM26: PgStore")
    }
    fn set_bootstrap(&self, _token_hash: String, _expires_at: i64) -> StoreFuture<'_, ()> {
        todo!("TM26: PgStore")
    }
    fn bootstrap(&self, _req: NewBootstrap) -> StoreFuture<'_, Id> {
        todo!("TM26: PgStore")
    }
    fn auth_device(&self, _token_hash: String) -> StoreFuture<'_, Option<AuthDevice>> {
        todo!("TM26: PgStore")
    }
    fn touch_device(&self, _device_id: Id, _day: i64) -> StoreFuture<'_, ()> {
        todo!("TM26: PgStore")
    }
    fn rotate_token(&self, _device_id: Id, _token_hash: String, _now: i64) -> StoreFuture<'_, ()> {
        todo!("TM26: PgStore")
    }
    fn device(&self, _device_id: Id) -> StoreFuture<'_, Option<DeviceRow>> {
        todo!("TM26: PgStore")
    }
    fn member(&self, _member_id: Id) -> StoreFuture<'_, Option<MemberRow>> {
        todo!("TM26: PgStore")
    }
    fn member_by_handle(&self, _handle: Handle) -> StoreFuture<'_, Option<MemberRow>> {
        todo!("TM26: PgStore")
    }
    fn create_invite(&self, _invite: NewInvite) -> StoreFuture<'_, ()> {
        todo!("TM26: PgStore")
    }
    fn invite(&self, _invite_id: Id) -> StoreFuture<'_, Option<InviteRow>> {
        todo!("TM26: PgStore")
    }
    fn revoke_invite(&self, _invite_id: Id, _by: Actor, _now: i64) -> StoreFuture<'_, ()> {
        todo!("TM26: PgStore")
    }
    fn join(&self, _req: NewJoin) -> StoreFuture<'_, Joined> {
        todo!("TM26: PgStore")
    }
    fn approve_device(
        &self,
        _device_id: Id,
        _wraps: Vec<EpochWrap>,
        _by: Actor,
        _now: i64,
    ) -> StoreFuture<'_, ()> {
        todo!("TM26: PgStore")
    }
    fn revoke_device(&self, _device_id: Id, _by: Actor, _now: i64) -> StoreFuture<'_, ()> {
        todo!("TM26: PgStore")
    }
    fn remove_member(
        &self,
        _member_id: Id,
        _delete_records: bool,
        _by: Actor,
        _now: i64,
    ) -> StoreFuture<'_, u64> {
        todo!("TM26: PgStore")
    }
    fn set_role(
        &self,
        _member_id: Id,
        _role: Role,
        _by: Option<Actor>,
        _now: i64,
    ) -> StoreFuture<'_, ()> {
        todo!("TM26: PgStore")
    }
    fn members(&self) -> StoreFuture<'_, Vec<MemberInfo>> {
        todo!("TM26: PgStore")
    }
    fn keys(&self, _device_id: Id) -> StoreFuture<'_, KeysResponse> {
        todo!("TM26: PgStore")
    }
    fn rotate_keys(
        &self,
        _epoch: u32,
        _wraps: Vec<DeviceWrap>,
        _by: Actor,
        _now: i64,
    ) -> StoreFuture<'_, ()> {
        todo!("TM26: PgStore")
    }
    fn status(&self, _device_id: Id, _now: i64) -> StoreFuture<'_, StatusResponse> {
        todo!("TM26: PgStore")
    }
    fn update_settings(
        &self,
        _update: SettingsUpdate,
        _floor: Version,
        _by: Option<Actor>,
        _now: i64,
    ) -> StoreFuture<'_, OrgSettings> {
        todo!("TM26: PgStore")
    }
    fn push(&self, _batch: PushBatch) -> StoreFuture<'_, PushResponse> {
        todo!("TM26: PgStore")
    }
    fn stream_head(&self, _member_id: Id, _device_id: Id, _tag: Tag) -> StoreFuture<'_, i64> {
        todo!("TM26: PgStore")
    }
    fn records(
        &self,
        _member_id: Id,
        _device_id: Id,
        _tag: Tag,
        _from: u64,
        _limit: u32,
        _max_bytes: usize,
    ) -> StoreFuture<'_, StreamRecords> {
        todo!("TM26: PgStore")
    }
    fn pull(
        &self,
        _cursors: Vec<Cursor>,
        _limit: u32,
        _max_bytes: usize,
    ) -> StoreFuture<'_, PullResponse> {
        todo!("TM26: PgStore")
    }
    fn pushed_since(&self, _member_id: Id, _since: i64) -> StoreFuture<'_, u64> {
        todo!("TM26: PgStore")
    }
    fn delete(
        &self,
        _req: DeleteRequest,
        _by: Actor,
        _now: i64,
    ) -> StoreFuture<'_, DeleteResponse> {
        todo!("TM26: PgStore")
    }
    fn retention_batch(&self, _cutoff: i64, _limit: u32, _now: i64) -> StoreFuture<'_, u64> {
        todo!("TM26: PgStore")
    }
    fn prune_deletions(&self, _before: i64) -> StoreFuture<'_, u64> {
        todo!("TM26: PgStore")
    }
    fn prune_audit(&self, _before: i64) -> StoreFuture<'_, u64> {
        todo!("TM26: PgStore")
    }
    fn checkpoint(&self) -> StoreFuture<'_, ()> {
        todo!("TM26: PgStore")
    }
    fn deletions(&self, _from: u64, _limit: u32) -> StoreFuture<'_, DeletionsResponse> {
        todo!("TM26: PgStore")
    }
    fn deletion_heads(&self) -> StoreFuture<'_, DeletionHeads> {
        todo!("TM26: PgStore")
    }
    fn append_audit(&self, _entry: AuditEntry) -> StoreFuture<'_, u64> {
        todo!("TM26: PgStore")
    }
    fn audit(&self, _from: u64, _limit: u32) -> StoreFuture<'_, AuditResponse> {
        todo!("TM26: PgStore")
    }
    fn export_canonical(&self, _dest: PathBuf) -> StoreFuture<'_, TableCounts> {
        todo!("TM26: PgStore")
    }
    fn import_canonical(&self, _src: PathBuf) -> StoreFuture<'_, TableCounts> {
        todo!("TM26: PgStore")
    }
    fn dump(&self) -> StoreFuture<'_, LogicalDump> {
        todo!("TM26: PgStore")
    }
}
