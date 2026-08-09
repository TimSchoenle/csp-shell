//! The policy itself: an ordered set of directives, and the one place they become a string.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use crate::directive::Directive;
use crate::name::{DirectiveName, SourceDirective};
use crate::source::{Source, SourceList};

/// A Content-Security-Policy under construction. Directives, not a string.
///
/// Directives render in the order they were first introduced, and a name can appear only once: a
/// repeated directive is ignored by every browser with nothing but a console warning, so the
/// second one is a restriction the author believes is in force and is not.
///
/// # Examples
///
/// ```
/// use csp_policy::{Directive, Policy, Source, SourceDirective, SourceList};
///
/// let policy = Policy::new()
///     .with(Directive::sources(SourceDirective::DefaultSrc, [Source::SelfOrigin]))
///     .with(Directive::sources(SourceDirective::ObjectSrc, SourceList::None))
///     .with(Directive::UpgradeInsecureRequests);
///
/// assert_eq!(
///     policy.to_header_value(),
///     "default-src 'self'; object-src 'none'; upgrade-insecure-requests"
/// );
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Policy {
    directives: Vec<Directive>,
}

impl Policy {
    /// An empty policy. Every directive is opt-in.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            directives: Vec::new(),
        }
    }

    /// Set a directive, replacing any existing one of the same name in place.
    ///
    /// Replacement keeps the original's position, so a policy's order stays the order its
    /// directives were introduced rather than the order they were last edited.
    pub fn set(&mut self, directive: Directive) -> &mut Self {
        match self.position(directive.name()) {
            Some(index) => self.directives[index] = directive,
            None => self.directives.push(directive),
        }
        self
    }

    /// [`Policy::set`], for chaining from a value rather than through a binding.
    #[must_use]
    pub fn with(mut self, directive: Directive) -> Self {
        self.set(directive);
        self
    }

    /// Add source expressions to a directive, creating it if it is absent.
    ///
    /// Sources already present are not added twice, and adding to a `'none'` list replaces the
    /// `'none'` — a list cannot hold it alongside anything else.
    pub fn extend_sources(
        &mut self,
        directive: SourceDirective,
        sources: impl IntoIterator<Item = Source>,
    ) -> &mut Self {
        if self.contains(directive.name()) {
            if let Some(list) = self.source_list_mut(directive) {
                for source in sources {
                    list.push(source);
                }
            }
        } else {
            self.directives
                .push(Directive::Sources(directive, SourceList::of(sources)));
        }
        self
    }

    /// The source list of `directive`, if the policy sets it.
    pub fn source_list_mut(&mut self, directive: SourceDirective) -> Option<&mut SourceList> {
        let index = self.position(directive.name())?;
        self.directives[index].source_list_mut()
    }

    /// The directive stored under `name`.
    #[must_use]
    pub fn get(&self, name: DirectiveName) -> Option<&Directive> {
        self.position(name).map(|index| &self.directives[index])
    }

    /// The source list stored under `directive`, without creating one.
    #[must_use]
    pub fn source_list(&self, directive: SourceDirective) -> Option<&SourceList> {
        self.get(directive.name())?.source_list()
    }

    /// Whether the policy sets this directive.
    #[must_use]
    pub fn contains(&self, name: DirectiveName) -> bool {
        self.position(name).is_some()
    }

    /// Remove the directive stored under `name`, keeping the order of the rest.
    pub fn remove(&mut self, name: DirectiveName) -> Option<Directive> {
        self.position(name)
            .map(|index| self.directives.remove(index))
    }

    /// The directives, in render order.
    pub fn iter(&self) -> core::slice::Iter<'_, Directive> {
        self.directives.iter()
    }

    /// How many directives the policy sets.
    #[must_use]
    pub fn len(&self) -> usize {
        self.directives.len()
    }

    /// Whether the policy sets no directives at all, and so restricts nothing.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.directives.is_empty()
    }

    /// Render the policy as a `Content-Security-Policy` header value.
    ///
    /// Infallible, and that is a property of the types rather than of this function: every
    /// component was checked when it was built, so there is no input here that could put a `;`,
    /// a `,` or a control byte into the result that this method did not write itself.
    #[must_use]
    pub fn to_header_value(&self) -> String {
        let mut rendered = String::new();
        for (index, directive) in self.directives.iter().enumerate() {
            if index > 0 {
                rendered.push_str("; ");
            }
            directive.render_into(&mut rendered);
        }

        debug_assert!(
            rendered.bytes().all(|byte| (0x20..=0x7e).contains(&byte)),
            "a rendered policy must be a valid HTTP field value: {rendered:?}"
        );
        rendered
    }

    /// Index of the directive stored under `name`.
    fn position(&self, name: DirectiveName) -> Option<usize> {
        self.directives
            .iter()
            .position(|directive| directive.name() == name)
    }
}

impl fmt::Display for Policy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, directive) in self.directives.iter().enumerate() {
            if index > 0 {
                f.write_str("; ")?;
            }
            directive.fmt(f)?;
        }
        Ok(())
    }
}

impl FromIterator<Directive> for Policy {
    /// Later directives replace earlier ones of the same name, in the earlier one's position.
    fn from_iter<I: IntoIterator<Item = Directive>>(directives: I) -> Self {
        let mut policy = Self::new();
        for directive in directives {
            policy.set(directive);
        }
        policy
    }
}

impl<'a> IntoIterator for &'a Policy {
    type Item = &'a Directive;
    type IntoIter = core::slice::Iter<'a, Directive>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::{String, ToString};

    use super::Policy;
    use crate::directive::Directive;
    use crate::name::{DirectiveName, SourceDirective};
    use crate::source::{Source, SourceList};

    fn scripts(policy: &Policy) -> String {
        policy
            .source_list(SourceDirective::ScriptSrc)
            .expect("script-src must be set")
            .to_string()
    }

    #[test]
    fn a_replacement_keeps_the_original_position() {
        let mut policy = Policy::new();
        policy
            .set(Directive::sources(
                SourceDirective::DefaultSrc,
                [Source::SelfOrigin],
            ))
            .set(Directive::sources(
                SourceDirective::ScriptSrc,
                [Source::SelfOrigin],
            ))
            .set(Directive::sources(
                SourceDirective::ObjectSrc,
                SourceList::None,
            ))
            .set(Directive::sources(
                SourceDirective::ScriptSrc,
                [Source::WasmUnsafeEval],
            ));

        assert_eq!(
            policy.to_header_value(),
            "default-src 'self'; script-src 'wasm-unsafe-eval'; object-src 'none'"
        );
        assert_eq!(policy.len(), 3);
    }

    /// A repeated directive is ignored by the browser with only a console warning, so the policy
    /// must never render one however it was assembled.
    #[test]
    fn a_name_appears_at_most_once() {
        let policy: Policy = SourceDirective::ALL
            .iter()
            .chain(SourceDirective::ALL)
            .map(|&directive| Directive::sources(directive, [Source::SelfOrigin]))
            .collect();

        assert_eq!(policy.len(), SourceDirective::ALL.len());

        // `script-src` is a prefix of `script-src-attr`, so occurrences are counted over whole
        // segments rather than over the rendered text.
        let rendered = policy.to_header_value();
        for &directive in SourceDirective::ALL {
            let occurrences = rendered
                .split("; ")
                .filter(|segment| segment.split(' ').next() == Some(directive.as_str()))
                .count();
            assert_eq!(occurrences, 1, "{directive} must render exactly once");
        }
    }

    #[test]
    fn extending_creates_deduplicates_and_replaces_none() {
        let mut policy = Policy::new();
        policy.set(Directive::sources(
            SourceDirective::ScriptSrc,
            SourceList::None,
        ));
        policy.extend_sources(
            SourceDirective::ScriptSrc,
            [Source::SelfOrigin, Source::SelfOrigin],
        );
        assert_eq!(scripts(&policy), "'self'");

        policy.extend_sources(SourceDirective::ConnectSrc, [Source::SelfOrigin]);
        assert_eq!(
            policy.to_header_value(),
            "script-src 'self'; connect-src 'self'"
        );
    }

    /// Every source-list name has to survive the create-if-absent path, which is the one place a
    /// directive is built from a name rather than from a caller's value.
    #[test]
    fn every_source_directive_can_be_created_by_extending() {
        for &directive in SourceDirective::ALL {
            let mut policy = Policy::new();
            policy.extend_sources(directive, [Source::SelfOrigin]);
            assert_eq!(
                policy.to_header_value(),
                alloc::format!("{} 'self'", directive.as_str())
            );
        }
    }

    #[test]
    fn removing_keeps_the_order_of_the_rest() {
        let mut policy: Policy = [
            Directive::sources(SourceDirective::DefaultSrc, [Source::SelfOrigin]),
            Directive::sources(SourceDirective::ScriptSrc, [Source::SelfOrigin]),
            Directive::UpgradeInsecureRequests,
        ]
        .into_iter()
        .collect();

        assert!(policy.remove(DirectiveName::ScriptSrc).is_some());
        assert!(policy.remove(DirectiveName::ScriptSrc).is_none());
        assert!(!policy.contains(DirectiveName::ScriptSrc));
        assert_eq!(
            policy.to_header_value(),
            "default-src 'self'; upgrade-insecure-requests"
        );
    }

    #[test]
    fn an_empty_policy_renders_to_nothing() {
        assert!(Policy::new().is_empty());
        assert_eq!(Policy::new().to_header_value(), "");
    }

    #[test]
    fn display_and_to_header_value_agree() {
        let policy = Policy::new()
            .with(Directive::sources(
                SourceDirective::DefaultSrc,
                [Source::SelfOrigin],
            ))
            .with(Directive::UpgradeInsecureRequests);
        assert_eq!(alloc::format!("{policy}"), policy.to_header_value());
    }
}
