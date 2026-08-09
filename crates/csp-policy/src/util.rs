//! Helpers shared by more than one module.

use alloc::vec::Vec;

/// Append `value` unless an equal value is already present.
///
/// The vectors this is used on hold a handful of entries — the source expressions of one
/// directive, the tokens of one `sandbox` — so the linear scan costs less than the hash set that
/// would replace it, and it preserves insertion order, which the rendering depends on.
pub(crate) fn push_unique<T: PartialEq>(values: &mut Vec<T>, value: T) {
    if !values.contains(&value) {
        values.push(value);
    }
}

/// Bytes that may appear in a rendered policy outside the separators the renderer emits itself.
///
/// `%x21-2B` ∪ `%x2D-3A` ∪ `%x3C-7E`: printable ASCII less SP (`%x20`), `,` (`%x2C`) and `;`
/// (`%x3B`), which separate a source, a policy and a directive respectively. Also excludes DEL,
/// every C0 and C1 control byte, and every non-ASCII byte — none of which can appear in an HTTP
/// field value without a smuggling risk.
///
/// Every leaf type in this crate validates against this set or a subset of it, which is what makes
/// rendering infallible rather than a second place to get quoting right.
#[inline]
pub(crate) const fn is_policy_byte(byte: u8) -> bool {
    matches!(byte, 0x21..=0x2b | 0x2d..=0x3a | 0x3c..=0x7e)
}
