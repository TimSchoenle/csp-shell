//! Helpers shared by more than one module: order-preserving deduplication.

use alloc::vec::Vec;

/// Appends `value` unless an equal value is already present.
///
/// The vectors this is used on hold a handful of entries — the inline scripts of one shell, the
/// source expressions of one directive — so the linear scan costs less than the hash set that
/// would replace it, and it preserves insertion order, which both callers depend on.
pub(crate) fn push_unique<T: PartialEq>(values: &mut Vec<T>, value: T) {
    if !values.contains(&value) {
        values.push(value);
    }
}
