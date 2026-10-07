//! The authorization token cache of draft-22 §8.9 and §9.1.3.
//!
//! A peer may register a token under an alias once and refer to it by alias
//! afterwards. The receiver holds what was registered, bounded by the
//! `MAX_AUTH_TOKEN_CACHE_SIZE` it advertised in SETUP: each entry costs 16
//! bytes plus its Token Value, and the default of zero prohibits aliases
//! altogether. Each direction has its own alias space, so a session keeps one
//! cache for what its peer registers.
//!
//! This is the bookkeeping and nothing else. Whether a resolved token
//! authorizes anything is the caller's question, and so is what to do with an
//! error, though [`TokenError::session_code`] says what §8.9 requires.

use std::collections::HashMap;

use bytes::Bytes;

use crate::control::codes;
use crate::control::typed::Token;

/// What one registered token costs against the cache limit, per §9.1.3.
#[must_use]
pub fn entry_size(value: &Bytes) -> u64 {
    16 + value.len() as u64
}

/// Why a token could not be applied to the cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum TokenError {
    /// `REGISTER` of an alias that is already registered.
    #[error("token alias {0} is already registered")]
    DuplicateAlias(u64),
    /// `DELETE` or `USE_ALIAS` of an alias that is not registered.
    #[error("token alias {0} is not registered")]
    UnknownAlias(u64),
    /// A registration outside SETUP that the advertised limit cannot hold.
    #[error("registering token alias {0} would exceed the token cache")]
    CacheOverflow(u64),
}

impl TokenError {
    /// The session error §8.9 closes the session with.
    #[must_use]
    pub const fn session_code(self) -> u32 {
        match self {
            Self::DuplicateAlias(_) => codes::session::DUPLICATE_AUTH_TOKEN_ALIAS,
            Self::UnknownAlias(_) => codes::session::UNKNOWN_AUTH_TOKEN_ALIAS,
            Self::CacheOverflow(_) => codes::session::AUTH_TOKEN_CACHE_OVERFLOW,
        }
    }
}

/// A token resolved to the type and value it stands for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resolved {
    /// Token Type.
    pub token_type: u64,
    /// Token Value.
    pub value: Bytes,
}

/// The tokens one peer has registered with this endpoint.
#[derive(Debug, Clone, Default)]
pub struct TokenCache {
    limit: u64,
    used: u64,
    entries: HashMap<u64, Resolved>,
}

impl TokenCache {
    /// A cache holding at most `limit` bytes: what this endpoint sent as
    /// `MAX_AUTH_TOKEN_CACHE_SIZE`, or 0 if it sent none.
    #[must_use]
    pub fn new(limit: u64) -> Self {
        Self {
            limit,
            used: 0,
            entries: HashMap::new(),
        }
    }

    /// The advertised limit.
    #[must_use]
    pub const fn limit(&self) -> u64 {
        self.limit
    }

    /// Bytes in use, by §9.1.3's accounting.
    #[must_use]
    pub const fn used(&self) -> u64 {
        self.used
    }

    /// Apply a token from a message other than SETUP, and return what it
    /// stands for.
    ///
    /// `REGISTER` and `USE_VALUE` resolve to their own type and value,
    /// `USE_ALIAS` to what was registered, and `DELETE` to nothing. A
    /// registration is kept even if the message it arrived in goes on to fail,
    /// as §8.9 requires so that a sender can pipeline.
    ///
    /// # Errors
    /// [`TokenError`], each of which §8.9 makes fatal to the session.
    pub fn apply(&mut self, token: &Token) -> Result<Option<Resolved>, TokenError> {
        match token {
            Token::UseValue { token_type, value } => Ok(Some(Resolved {
                token_type: *token_type,
                value: value.clone(),
            })),
            Token::UseAlias { alias } => self
                .entries
                .get(alias)
                .cloned()
                .map(Some)
                .ok_or(TokenError::UnknownAlias(*alias)),
            Token::Delete { alias } => {
                let removed = self
                    .entries
                    .remove(alias)
                    .ok_or(TokenError::UnknownAlias(*alias))?;
                self.used -= entry_size(&removed.value);
                Ok(None)
            }
            Token::Register {
                alias,
                token_type,
                value,
            } => {
                if self.entries.contains_key(alias) {
                    return Err(TokenError::DuplicateAlias(*alias));
                }
                let size = entry_size(value);
                if self.used.saturating_add(size) > self.limit {
                    return Err(TokenError::CacheOverflow(*alias));
                }
                let resolved = Resolved {
                    token_type: *token_type,
                    value: value.clone(),
                };
                self.used += size;
                self.entries.insert(*alias, resolved.clone());
                Ok(Some(resolved))
            }
        }
    }

    /// Apply a token from the peer's SETUP.
    ///
    /// §9.1.4 differs from [`Self::apply`] in two places: a registration the
    /// cache cannot hold is used as a `USE_VALUE` rather than ending the
    /// session, since the peer may have sent SETUP before seeing the limit;
    /// and `DELETE` or `USE_ALIAS` are refused, there being nothing yet to
    /// refer to.
    ///
    /// # Errors
    /// [`SetupTokenError::AliasReference`] for `DELETE` or `USE_ALIAS`, which
    /// is a `PROTOCOL_VIOLATION`; [`SetupTokenError::Token`] for a duplicate
    /// registration within SETUP.
    pub fn apply_in_setup(&mut self, token: &Token) -> Result<Resolved, SetupTokenError> {
        match token {
            Token::Delete { .. } | Token::UseAlias { .. } => Err(SetupTokenError::AliasReference),
            Token::Register {
                token_type, value, ..
            } => match self.apply(token) {
                Ok(resolved) => Ok(resolved.unwrap_or(Resolved {
                    token_type: *token_type,
                    value: value.clone(),
                })),
                Err(TokenError::CacheOverflow(_)) => Ok(Resolved {
                    token_type: *token_type,
                    value: value.clone(),
                }),
                Err(error) => Err(SetupTokenError::Token(error)),
            },
            Token::UseValue { token_type, value } => Ok(Resolved {
                token_type: *token_type,
                value: value.clone(),
            }),
        }
    }
}

/// Why a token in SETUP could not be applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SetupTokenError {
    /// `DELETE` or `USE_ALIAS` in SETUP: a `PROTOCOL_VIOLATION`.
    #[error("SETUP may not delete or use a token alias")]
    AliasReference,
    /// As for any other message.
    #[error(transparent)]
    Token(TokenError),
}

impl SetupTokenError {
    /// The session error to close with.
    #[must_use]
    pub const fn session_code(self) -> u32 {
        match self {
            Self::AliasReference => codes::session::PROTOCOL_VIOLATION,
            Self::Token(error) => error.session_code(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn register(alias: u64, value: &'static [u8]) -> Token {
        Token::Register {
            alias,
            token_type: 0,
            value: Bytes::from_static(value),
        }
    }

    fn resolved(value: &'static [u8]) -> Resolved {
        Resolved {
            token_type: 0,
            value: Bytes::from_static(value),
        }
    }

    #[test]
    fn a_registered_alias_resolves_until_deleted() {
        let mut cache = TokenCache::new(1024);
        assert_eq!(
            cache.apply(&register(1, b"ticket")),
            Ok(Some(resolved(b"ticket")))
        );
        assert_eq!(cache.used(), 16 + 6);
        assert_eq!(
            cache.apply(&Token::UseAlias { alias: 1 }),
            Ok(Some(resolved(b"ticket")))
        );
        assert_eq!(cache.apply(&Token::Delete { alias: 1 }), Ok(None));
        assert_eq!(cache.used(), 0);
        assert_eq!(
            cache.apply(&Token::UseAlias { alias: 1 }),
            Err(TokenError::UnknownAlias(1))
        );
        // Retiring an alias frees it to be registered again.
        assert_eq!(
            cache.apply(&register(1, b"other")),
            Ok(Some(resolved(b"other")))
        );
    }

    #[test]
    fn each_misuse_maps_to_the_code_the_draft_names() {
        let mut cache = TokenCache::new(1024);
        cache.apply(&register(1, b"ticket")).expect("registers");
        let duplicate = cache.apply(&register(1, b"again")).expect_err("duplicate");
        assert_eq!(duplicate, TokenError::DuplicateAlias(1));
        assert_eq!(
            duplicate.session_code(),
            codes::session::DUPLICATE_AUTH_TOKEN_ALIAS
        );
        let unknown = cache
            .apply(&Token::Delete { alias: 9 })
            .expect_err("unknown");
        assert_eq!(
            unknown.session_code(),
            codes::session::UNKNOWN_AUTH_TOKEN_ALIAS
        );
    }

    #[test]
    fn the_limit_counts_sixteen_bytes_plus_the_value() {
        let mut cache = TokenCache::new(16 + 6);
        cache.apply(&register(1, b"ticket")).expect("exactly fits");
        let overflow = cache.apply(&register(2, b"")).expect_err("16 more bytes");
        assert_eq!(overflow, TokenError::CacheOverflow(2));
        assert_eq!(
            overflow.session_code(),
            codes::session::AUTH_TOKEN_CACHE_OVERFLOW
        );
    }

    #[test]
    fn the_default_limit_of_zero_prohibits_aliases() {
        let mut cache = TokenCache::default();
        assert_eq!(
            cache.apply(&register(1, b"t")),
            Err(TokenError::CacheOverflow(1))
        );
        assert_eq!(
            cache.apply(&Token::UseValue {
                token_type: 0,
                value: Bytes::from_static(b"t"),
            }),
            Ok(Some(resolved(b"t")))
        );
    }

    #[test]
    fn setup_uses_an_unfittable_registration_as_a_value_and_refuses_references() {
        let mut cache = TokenCache::default();
        assert_eq!(
            cache.apply_in_setup(&register(1, b"ticket")),
            Ok(resolved(b"ticket"))
        );
        assert_eq!(cache.used(), 0, "nothing was registered");
        let reference = cache
            .apply_in_setup(&Token::UseAlias { alias: 1 })
            .expect_err("no alias in SETUP");
        assert_eq!(reference.session_code(), codes::session::PROTOCOL_VIOLATION);

        let mut roomy = TokenCache::new(1024);
        roomy.apply_in_setup(&register(1, b"ticket")).expect("fits");
        assert_eq!(
            roomy.apply(&Token::UseAlias { alias: 1 }),
            Ok(Some(resolved(b"ticket")))
        );
    }
}
