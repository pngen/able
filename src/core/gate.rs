use crate::core::authority::AuthorityUnit;
use crate::core::trace::{DecisionTrace, LiabilityRecord};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use thiserror::Error;

#[derive(Debug, Error, Clone)]
pub enum ExecutionGateError {
    #[error("invalid authority unit: {0}")]
    InvalidAuthority(String),
    #[error("authority unit already consumed: {0}")]
    AlreadyConsumed(String),
    #[error("authority scope '{authority_scope}' cannot perform action scope '{action_scope}'")]
    ScopeMismatch {
        authority_scope: String,
        action_scope: String,
    },
    #[error("action execution failed: {0}")]
    ActionFailed(String),
    #[error("internal lock error")]
    LockError,
}

pub struct ExecutionGate<F: Fn(&AuthorityUnit) -> bool + Send + Sync> {
    validator: F,
    consumed_au_ids: Arc<Mutex<HashSet<String>>>,
}

impl<F: Fn(&AuthorityUnit) -> bool + Send + Sync> ExecutionGate<F> {
    pub fn new(validator: F) -> Self {
        ExecutionGate {
            validator,
            consumed_au_ids: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    pub fn is_consumed(&self, au_id: &str) -> Result<bool, ExecutionGateError> {
        let guard = self.consumed_au_ids.lock().map_err(|_| ExecutionGateError::LockError)?;
        Ok(guard.contains(au_id))
    }

    pub fn execute_with_authority(
        &self,
        au: &AuthorityUnit,
        action_fn: &dyn Fn() -> Result<String, String>,
        action_name: &str,
        action_scope: &str,
    ) -> Result<(DecisionTrace, LiabilityRecord), ExecutionGateError> {
        if !(self.validator)(au) {
            return Err(ExecutionGateError::InvalidAuthority(au.id.clone()));
        }

        let mut guard = self.consumed_au_ids.lock().map_err(|_| ExecutionGateError::LockError)?;

        if guard.contains(&au.id) {
            return Err(ExecutionGateError::AlreadyConsumed(au.id.clone()));
        }

        if !au.can_consume(action_scope) {
            return Err(ExecutionGateError::ScopeMismatch {
                authority_scope: au.scope.clone(),
                action_scope: action_scope.to_string(),
            });
        }

        guard.insert(au.id.clone());
        drop(guard);

        match action_fn() {
            Ok(result) => {
                let dt = DecisionTrace::new(
                    action_name.to_string(),
                    au.id.clone(),
                    result,
                );
                let lr = LiabilityRecord::new(
                    dt.id.clone(),
                    au.id.clone(),
                    au.price,
                    au.scope.clone(),
                );
                Ok((dt, lr))
            }
            Err(e) => {
                if let Ok(mut guard) = self.consumed_au_ids.lock() {
                    guard.remove(&au.id);
                }
                Err(ExecutionGateError::ActionFailed(e))
            }
        }
    }
}