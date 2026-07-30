use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error, Clone)]
pub enum AuthorityError {
    #[error("authority ID must be provided")]
    EmptyId,
    #[error("price cannot be negative: {0}")]
    NegativePrice(i64),
    #[error("scope must be provided")]
    EmptyScope,
    #[error("delegation chain must not be empty")]
    EmptyDelegationChain,
    #[error("delegation chain entries must not be empty")]
    EmptyDelegationEntry,
    #[error("delegation chain must not contain duplicate principals: {0}")]
    DuplicateDelegationEntry(String),
    #[error("timestamp must be finite and non-negative")]
    InvalidTimestamp,
    #[error("previous hash must be a 64-character hexadecimal SHA-256 digest")]
    InvalidPreviousHash,
}

pub fn current_timestamp() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(f64::NAN, |duration| duration.as_secs_f64())
}

#[derive(Debug, Clone, PartialEq)]
pub struct AuthorityUnit {
    pub id: String,
    pub scope: String,
    pub delegation_chain: Vec<String>,
    pub price: i64,
    pub timestamp: f64,
    pub prev_hash: Option<String>,
}

impl AuthorityUnit {
    pub fn new(
        id: String,
        scope: String,
        delegation_chain: Vec<String>,
        price: i64,
        timestamp: f64,
        prev_hash: Option<String>,
    ) -> Result<Self, AuthorityError> {
        let au = AuthorityUnit {
            id,
            scope,
            delegation_chain,
            price,
            timestamp,
            prev_hash,
        };
        au.validate_invariants()?;
        Ok(au)
    }

    pub fn validate_invariants(&self) -> Result<(), AuthorityError> {
        if self.id.trim().is_empty() {
            return Err(AuthorityError::EmptyId);
        }
        if self.price < 0 {
            return Err(AuthorityError::NegativePrice(self.price));
        }
        if self.scope.trim().is_empty() {
            return Err(AuthorityError::EmptyScope);
        }
        if self.delegation_chain.is_empty() {
            return Err(AuthorityError::EmptyDelegationChain);
        }
        if self
            .delegation_chain
            .iter()
            .any(|entry| entry.trim().is_empty())
        {
            return Err(AuthorityError::EmptyDelegationEntry);
        }
        for (index, entry) in self.delegation_chain.iter().enumerate() {
            if self.delegation_chain[..index].contains(entry) {
                return Err(AuthorityError::DuplicateDelegationEntry(entry.clone()));
            }
        }
        if !self.timestamp.is_finite()
            || self.timestamp < 0.0
            || (self.timestamp == 0.0 && self.timestamp.is_sign_negative())
        {
            return Err(AuthorityError::InvalidTimestamp);
        }
        if let Some(hash) = &self.prev_hash {
            if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(AuthorityError::InvalidPreviousHash);
            }
        }
        Ok(())
    }

    pub fn hash(&self) -> String {
        let mut hasher = Sha256::new();

        fn update_part(hasher: &mut Sha256, label: &str, value: &str) {
            hasher.update(label.as_bytes());
            hasher.update(b":");
            hasher.update(value.len().to_string().as_bytes());
            hasher.update(b":");
            hasher.update(value.as_bytes());
            hasher.update(b";");
        }

        update_part(&mut hasher, "id", &self.id);
        update_part(&mut hasher, "scope", &self.scope);
        update_part(
            &mut hasher,
            "delegation_len",
            &self.delegation_chain.len().to_string(),
        );
        for entry in &self.delegation_chain {
            update_part(&mut hasher, "delegation", entry);
        }
        update_part(&mut hasher, "price", &self.price.to_string());
        update_part(
            &mut hasher,
            "timestamp",
            &self.timestamp.to_bits().to_string(),
        );
        match &self.prev_hash {
            Some(previous_hash) => {
                update_part(&mut hasher, "prev_hash_present", "true");
                update_part(&mut hasher, "prev_hash", previous_hash);
            }
            None => update_part(&mut hasher, "prev_hash_present", "false"),
        }
        let result = hasher.finalize();
        format!("{:x}", result)
    }

    pub fn is_valid(&self, current_time: f64, max_age_seconds: i64) -> bool {
        if self.validate_invariants().is_err()
            || !current_time.is_finite()
            || max_age_seconds < 0
            || self.timestamp > current_time
        {
            return false;
        }
        if current_time - self.timestamp > max_age_seconds as f64 {
            return false;
        }
        true
    }

    pub fn can_consume(&self, action_scope: &str) -> bool {
        !action_scope.trim().is_empty() && (self.scope == action_scope || self.scope == "any")
    }
}
