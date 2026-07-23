//! OAuth scopes in the AT Protocol profile.
//!
//! The profile defines a small closed set. `atproto` is mandatory on every
//! request — it is what signals the client understands the atproto profile at
//! all — and the `transition:*` scopes grant the broad, pre-granular permissions
//! that today's clients need.

use std::collections::BTreeSet;
use std::fmt;

use crate::oauth::OAuthError;

/// The mandatory base scope.
pub const ATPROTO: &str = "atproto";

/// Scopes this server will grant.
///
/// A closed allow-list rather than free-form strings: an unknown scope must be
/// rejected, not stored and later interpreted by something downstream that
/// assumes it was checked here.
const SUPPORTED: [&str; 4] = [
    ATPROTO,
    // Broad read/write over the account's repo and the AppView, minus chat and
    // email. This is what a general-purpose client asks for today.
    "transition:generic",
    // Adds the bsky chat (DM) surface.
    "transition:chat.bsky",
    // Adds the account's email address to `getSession` responses.
    "transition:email",
];

/// A validated, de-duplicated scope set.
///
/// Backed by a `BTreeSet` so the serialized form is deterministic — the scope
/// string ends up inside signed access tokens, and an unstable ordering would
/// make otherwise-identical grants compare unequal.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Scope(BTreeSet<String>);

impl Scope {
    /// Parse a space-delimited scope string, enforcing the profile's rules.
    pub fn parse(s: &str) -> Result<Self, OAuthError> {
        let mut set = BTreeSet::new();
        for token in s.split_ascii_whitespace() {
            if !SUPPORTED.contains(&token) {
                return Err(OAuthError::InvalidScope(format!("unknown scope: {token}")));
            }
            set.insert(token.to_string());
        }

        if set.is_empty() {
            return Err(OAuthError::InvalidScope("scope is required".into()));
        }
        if !set.contains(ATPROTO) {
            return Err(OAuthError::InvalidScope(
                "the `atproto` scope is required".into(),
            ));
        }
        Ok(Self(set))
    }

    /// Whether this set contains `scope`.
    pub fn contains(&self, scope: &str) -> bool {
        self.0.contains(scope)
    }

    /// True when every scope in `self` is also in `other`.
    ///
    /// Used on refresh: a client may narrow its grant but must never widen it,
    /// so the requested set has to be a subset of the originally granted one.
    pub fn is_subset_of(&self, other: &Scope) -> bool {
        self.0.is_subset(&other.0)
    }

    pub fn iter(&self) -> impl Iterator<Item = &str> {
        self.0.iter().map(|s| s.as_str())
    }

    /// Every scope this server advertises, for the metadata document.
    pub fn supported() -> &'static [&'static str] {
        &SUPPORTED
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let joined: Vec<&str> = self.0.iter().map(|s| s.as_str()).collect();
        write!(f, "{}", joined.join(" "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_normalizes() {
        let s = Scope::parse("transition:generic atproto").unwrap();
        // Sorted and deterministic regardless of input order.
        assert_eq!(s.to_string(), "atproto transition:generic");
        assert_eq!(
            Scope::parse("atproto transition:generic")
                .unwrap()
                .to_string(),
            s.to_string(),
            "input order must not affect the serialized form"
        );
    }

    #[test]
    fn deduplicates() {
        let s = Scope::parse("atproto atproto atproto").unwrap();
        assert_eq!(s.to_string(), "atproto");
    }

    #[test]
    fn handles_irregular_whitespace() {
        let s = Scope::parse("  atproto \t transition:generic  ").unwrap();
        assert_eq!(s.to_string(), "atproto transition:generic");
    }

    #[test]
    fn atproto_is_mandatory() {
        assert!(
            Scope::parse("transition:generic").is_err(),
            "a scope set without `atproto` must be rejected"
        );
    }

    #[test]
    fn empty_scope_is_rejected() {
        assert!(Scope::parse("").is_err());
        assert!(Scope::parse("   ").is_err());
    }

    #[test]
    fn unknown_scopes_are_rejected() {
        assert!(Scope::parse("atproto admin").is_err());
        assert!(
            Scope::parse("atproto transition:everything").is_err(),
            "an unrecognised transition scope must not pass through"
        );
    }

    #[test]
    fn subset_check_allows_narrowing_and_blocks_widening() {
        let granted = Scope::parse("atproto transition:generic transition:chat.bsky").unwrap();
        let narrower = Scope::parse("atproto transition:generic").unwrap();
        assert!(narrower.is_subset_of(&granted), "narrowing is allowed");
        assert!(
            !granted.is_subset_of(&narrower),
            "widening on refresh must be blocked"
        );
        assert!(granted.is_subset_of(&granted), "identical sets are subsets");
    }

    #[test]
    fn contains_works() {
        let s = Scope::parse("atproto transition:email").unwrap();
        assert!(s.contains("atproto"));
        assert!(s.contains("transition:email"));
        assert!(!s.contains("transition:chat.bsky"));
    }
}
