use crate::core::authority::{AuthorityUnit, current_timestamp};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use thiserror::Error;

#[derive(Debug, Error, Clone)]
pub enum ManagerError {
    #[error("authority with ID {0} already exists")]
    DuplicateAuthority(String),
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
        let mut guard = self.authorities.write().map_err(|_| ManagerError::LockError)?;
        if guard.contains_key(&au.id) {
            return Err(ManagerError::DuplicateAuthority(au.id.clone()));
        }
        guard.insert(au.id.clone(), au);
        Ok(())
    }

    pub fn validate_authority(&self, au: &AuthorityUnit) -> bool {
        let guard = match self.authorities.read() {
            Ok(g) => g,
            Err(_) => return false,
        };
        match guard.get(&au.id) {
            Some(stored_au) if stored_au == au => {
                stored_au.is_valid(current_timestamp(), self.max_age_seconds)
            }
            _ => false,
        }
    }

    pub fn get_authority(&self, au_id: &str) -> Option<AuthorityUnit> {
        self.authorities.read().ok()?.get(au_id).cloned()
    }
}