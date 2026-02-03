use sha2::{Sha256, Digest};
use thiserror::Error;

#[derive(Debug, Error, Clone)]
pub enum AuthorityError {
    #[error("price cannot be negative: {0}")]
    NegativePrice(i64),
    #[error("scope must be provided")]
    EmptyScope,
    #[error("delegation chain must not be empty")]
    EmptyDelegationChain,
}

pub fn current_timestamp() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system time before UNIX epoch")
        .as_secs_f64()
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
        if price < 0 {
            return Err(AuthorityError::NegativePrice(price));
        }
        if scope.is_empty() {
            return Err(AuthorityError::EmptyScope);
        }
        if delegation_chain.is_empty() {
            return Err(AuthorityError::EmptyDelegationChain);
        }

        Ok(AuthorityUnit {
            id,
            scope,
            delegation_chain,
            price,
            timestamp,
            prev_hash,
        })
    }

    pub fn hash(&self) -> String {
        let chain_str = self.delegation_chain.join(",");
        let mut hasher = Sha256::new();
        hasher.update(
            format!(
                "{}|{}|{}|{}|{}|{:?}",
                self.id,
                self.scope,
                chain_str,
                self.price,
                self.timestamp,
                self.prev_hash
            )
            .as_bytes(),
        );
        let result = hasher.finalize();
        format!("{:x}", result)
    }

    pub fn is_valid(&self, current_time: f64, max_age_seconds: i64) -> bool {
        if current_time - self.timestamp > max_age_seconds as f64 {
            return false;
        }
        true
    }

    pub fn can_consume(&self, action_scope: &str) -> bool {
        self.scope == action_scope || self.scope == "any"
    }
}