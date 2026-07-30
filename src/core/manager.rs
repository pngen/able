use crate::core::authority::AuthorityUnit;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use thiserror::Error;

#[derive(Debug, Error, Clone)]
pub enum ManagerError {
    #[error("authority with ID {0} already exists")]
    DuplicateAuthority(String),
    #[error("invalid authority: {0}")]
    InvalidAuthority(String),
    #[error("internal lock error")]
    LockError,
}

pub struct AuthorityManager {
    authorities: Arc<RwLock<HashMap<String, AuthorityUnit>>>,
    max_age_seconds: i64,
}

impl Default for AuthorityManager {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthorityManager {
    pub fn new() -> Self {
        AuthorityManager {
            authorities: Arc::new(RwLock::new(HashMap::new())),
            max_age_seconds: 3600,
        }
    }

    pub fn with_max_age(max_age_seconds: i64) -> Self {
        AuthorityManager {
            authorities: Arc::new(RwLock::new(HashMap::new())),
            max_age_seconds,
        }
    }

    pub fn issue_authority(&self, au: AuthorityUnit) -> Result<(), ManagerError> {
        au.validate_invariants()
            .map_err(|err| ManagerError::InvalidAuthority(err.to_string()))?;
        let mut guard = self
            .authorities
            .write()
            .map_err(|_| ManagerError::LockError)?;
        if guard.contains_key(&au.id) {
            return Err(ManagerError::DuplicateAuthority(au.id.clone()));
        }

        if au.prev_hash.is_none() && au.delegation_chain.len() != 1 {
            return Err(ManagerError::InvalidAuthority(
                "root authority must contain exactly one delegation principal".to_string(),
            ));
        }

        if let Some(previous_hash) = &au.prev_hash {
            let parent = guard
                .values()
                .find(|candidate| candidate.hash() == *previous_hash)
                .ok_or_else(|| {
                    ManagerError::InvalidAuthority(
                        "previous hash does not identify an issued authority".to_string(),
                    )
                })?;
            let expected_length =
                parent
                    .delegation_chain
                    .len()
                    .checked_add(1)
                    .ok_or_else(|| {
                        ManagerError::InvalidAuthority("delegation chain is too long".to_string())
                    })?;
            if au.delegation_chain.len() != expected_length
                || !au.delegation_chain.starts_with(&parent.delegation_chain)
            {
                return Err(ManagerError::InvalidAuthority(
                    "delegation chain must extend its predecessor by exactly one principal"
                        .to_string(),
                ));
            }
            if parent.scope != "any" && au.scope != parent.scope {
                return Err(ManagerError::InvalidAuthority(
                    "delegated authority cannot broaden or substitute its predecessor scope"
                        .to_string(),
                ));
            }
            if au.timestamp != parent.timestamp {
                return Err(ManagerError::InvalidAuthority(
                    "delegated authority must inherit its predecessor timestamp".to_string(),
                ));
            }
            if au.price < parent.price {
                return Err(ManagerError::InvalidAuthority(
                    "delegated authority cannot reduce its predecessor price".to_string(),
                ));
            }
        }

        let parent = au.prev_hash.as_ref().and_then(|previous_hash| {
            guard
                .values()
                .find(|candidate| candidate.hash() == *previous_hash)
                .map(|authority| (authority, previous_hash.as_str()))
        });
        crate::core::gate::register_manager_policy(au.hash(), self.max_age_seconds, parent)
            .map_err(|error| match error {
                crate::core::gate::ManagerPolicyError::Lock => ManagerError::LockError,
                crate::core::gate::ManagerPolicyError::Clock => ManagerError::InvalidAuthority(
                    "system clock is unavailable or regressed".to_string(),
                ),
                crate::core::gate::ManagerPolicyError::MissingParent => {
                    ManagerError::InvalidAuthority(
                        "predecessor has no registered authority policy".to_string(),
                    )
                }
                crate::core::gate::ManagerPolicyError::ConsumedParent => {
                    ManagerError::InvalidAuthority(
                        "cannot delegate from a consumed authority".to_string(),
                    )
                }
                crate::core::gate::ManagerPolicyError::ExpiredParent => {
                    ManagerError::InvalidAuthority(
                        "cannot delegate from an authority that is not currently valid".to_string(),
                    )
                }
            })?;
        guard.insert(au.id.clone(), au);
        Ok(())
    }

    pub fn validate_authority(&self, au: &AuthorityUnit) -> bool {
        let current_time = match crate::core::gate::trusted_current_timestamp() {
            Some(timestamp) => timestamp,
            None => return false,
        };
        let guard = match self.authorities.read() {
            Ok(g) => g,
            Err(_) => return false,
        };
        let is_valid = match guard.get(&au.id) {
            Some(stored_au)
                if stored_au == au
                    && au.validate_invariants().is_ok()
                    && stored_au.validate_invariants().is_ok()
                    && stored_au.hash() == au.hash() =>
            {
                stored_au.is_valid(current_time, self.max_age_seconds)
            }
            _ => false,
        };
        is_valid
    }

    pub fn get_authority(&self, au_id: &str) -> Option<AuthorityUnit> {
        self.authorities.read().ok()?.get(au_id).cloned()
    }
}
