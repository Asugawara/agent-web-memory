//! Record deletion and the deletion stream (plan-v3-team §4.3.4, §5.6).

/// Deletes the record `record_id` and appends a marker to the deletion stream.
///
/// Implements plan-v3-team §4.3.4.
pub fn delete_record(_record_id: &str) -> Result<(), crate::store::StoreError> {
    todo!("deletion (§4.3.4)")
}
