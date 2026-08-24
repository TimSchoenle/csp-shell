//! Order-preserving deduplication for the short vectors the scanner accumulates.

use alloc::vec::Vec;

/// Appends `value` unless an equal value is already present.
///
/// The vectors this is used on hold a handful of entries — the inline-script hashes of one shell,
/// and the warnings raised scanning it — so the linear scan costs less than the hash set that
/// would replace it, and it preserves insertion order, which both callers depend on.
pub(crate) fn push_unique<T: PartialEq>(values: &mut Vec<T>, value: T) {
    if !values.contains(&value) {
        values.push(value);
    }
}
