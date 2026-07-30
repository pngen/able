use crate::core::authority::{current_timestamp, AuthorityUnit};
use crate::core::trace::{DecisionTrace, LiabilityRecord};
use lazy_static::lazy_static;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::Mutex;
use thiserror::Error;

const MAX_CLOCK_JITTER_SECONDS: f64 = 0.01;

lazy_static! {
    // Exhaustion and its evidence share one lifetime and one commit lock. The full authority
    // commitment prevents an unrelated authority that merely reuses an ID from poisoning it.
    static ref ENFORCEMENT_STATE: Mutex<AuditJournal> = Mutex::new(AuditJournal::default());
}

#[derive(Debug, Error, Clone)]
pub enum ExecutionGateError {
    #[error("invalid authority unit: {0}")]
    InvalidAuthority(String),
    #[error("authority validator panicked for unit: {0}")]
    ValidatorPanicked(String),
    #[error("authority unit already consumed: {0}")]
    AlreadyConsumed(String),
    #[error("authority scope '{authority_scope}' cannot perform action scope '{action_scope}'")]
    ScopeMismatch {
        authority_scope: String,
        action_scope: String,
    },
    #[error("action name must be provided")]
    EmptyActionName,
    #[error("action scope must be provided")]
    EmptyActionScope,
    #[error("action execution failed: {0}")]
    ActionFailed(String),
    #[error("action execution panicked")]
    ActionPanicked,
    #[error("system clock is unavailable")]
    InvalidClock,
    #[error("internal lock error")]
    LockError,
}

#[derive(Default)]
struct AuditJournal {
    consumed: Vec<ConsumedAuthority>,
    manager_policies: Vec<ManagerPolicy>,
    traces: Vec<DecisionTrace>,
    liabilities: Vec<LiabilityRecord>,
    next_sequence: u64,
    head_hash: Option<String>,
    high_water_timestamp: f64,
}

struct ManagerPolicy {
    authority_hash: String,
    max_age_seconds: i64,
    parent_hash: Option<String>,
}

struct ConsumedAuthority {
    id: String,
    authority_hash: String,
    terminal: bool,
    timestamp: f64,
}

pub(crate) fn trusted_current_timestamp() -> Option<f64> {
    let mut timestamp = current_timestamp();
    let mut state = ENFORCEMENT_STATE.lock().ok()?;
    if !timestamp.is_finite() || timestamp + MAX_CLOCK_JITTER_SECONDS < state.high_water_timestamp {
        return None;
    }
    timestamp = timestamp.max(state.high_water_timestamp);
    state.high_water_timestamp = timestamp;
    Some(timestamp)
}

pub(crate) enum ManagerPolicyError {
    Lock,
    Clock,
    MissingParent,
    ConsumedParent,
    ExpiredParent,
}

fn effective_manager_max_age(state: &AuditJournal, authority_hash: &str) -> Option<i64> {
    let mut current_hash = authority_hash.to_string();
    let mut effective_max_age = i64::MAX;
    for _ in 0..=state.manager_policies.len() {
        let policy = state
            .manager_policies
            .iter()
            .find(|policy| policy.authority_hash == current_hash)?;
        effective_max_age = effective_max_age.min(policy.max_age_seconds);
        match &policy.parent_hash {
            Some(parent_hash) => current_hash = parent_hash.clone(),
            None => return Some(effective_max_age),
        }
    }
    None
}

pub(crate) fn register_manager_policy(
    authority_hash: String,
    max_age_seconds: i64,
    parent: Option<(&AuthorityUnit, &str)>,
) -> Result<(), ManagerPolicyError> {
    let mut state = ENFORCEMENT_STATE
        .lock()
        .map_err(|_| ManagerPolicyError::Lock)?;
    let parent_hash = parent.map(|(_, parent_hash)| parent_hash.to_string());
    if let Some((parent_authority, parent_hash)) = parent {
        let parent_max_age = effective_manager_max_age(&state, parent_hash)
            .ok_or(ManagerPolicyError::MissingParent)?;
        if state
            .consumed
            .iter()
            .any(|entry| entry.authority_hash == parent_hash)
        {
            return Err(ManagerPolicyError::ConsumedParent);
        }
        let mut timestamp = current_timestamp();
        if !timestamp.is_finite()
            || timestamp + MAX_CLOCK_JITTER_SECONDS < state.high_water_timestamp
        {
            return Err(ManagerPolicyError::Clock);
        }
        timestamp = timestamp.max(state.high_water_timestamp);
        state.high_water_timestamp = timestamp;
        if !parent_authority.is_valid(timestamp, parent_max_age) {
            return Err(ManagerPolicyError::ExpiredParent);
        }
    }
    match state
        .manager_policies
        .iter_mut()
        .find(|policy| policy.authority_hash == authority_hash)
    {
        Some(policy) => {
            policy.max_age_seconds = policy.max_age_seconds.min(max_age_seconds);
        }
        None => state.manager_policies.push(ManagerPolicy {
            authority_hash,
            max_age_seconds,
            parent_hash,
        }),
    }
    Ok(())
}

pub struct ExecutionGate<F: Fn(&AuthorityUnit) -> bool + Send + Sync> {
    validator: F,
}

impl<F: Fn(&AuthorityUnit) -> bool + Send + Sync> ExecutionGate<F> {
    pub fn new(validator: F) -> Self {
        ExecutionGate { validator }
    }

    pub fn is_consumed(&self, au_id: &str) -> Result<bool, ExecutionGateError> {
        let guard = ENFORCEMENT_STATE
            .lock()
            .map_err(|_| ExecutionGateError::LockError)?;
        Ok(guard.consumed.iter().any(|entry| entry.id == au_id))
    }

    pub fn is_authority_consumed(
        &self,
        authority: &AuthorityUnit,
    ) -> Result<bool, ExecutionGateError> {
        let guard = ENFORCEMENT_STATE
            .lock()
            .map_err(|_| ExecutionGateError::LockError)?;
        let authority_hash = authority.hash();
        Ok(guard
            .consumed
            .iter()
            .any(|entry| entry.authority_hash == authority_hash))
    }

    pub fn audit_records(&self) -> Result<Vec<DecisionTrace>, ExecutionGateError> {
        let guard = ENFORCEMENT_STATE
            .lock()
            .map_err(|_| ExecutionGateError::LockError)?;
        Ok(guard.traces.clone())
    }

    pub fn liability_records(&self) -> Result<Vec<LiabilityRecord>, ExecutionGateError> {
        let guard = ENFORCEMENT_STATE
            .lock()
            .map_err(|_| ExecutionGateError::LockError)?;
        Ok(guard.liabilities.clone())
    }

    pub fn contains_audit_record(&self, trace: &DecisionTrace) -> Result<bool, ExecutionGateError> {
        let guard = ENFORCEMENT_STATE
            .lock()
            .map_err(|_| ExecutionGateError::LockError)?;
        Ok(guard.traces.iter().any(|stored| stored == trace))
    }

    pub fn verify_audit_chain(&self) -> Result<bool, ExecutionGateError> {
        let guard = ENFORCEMENT_STATE
            .lock()
            .map_err(|_| ExecutionGateError::LockError)?;

        let mut previous_hash: Option<&str> = None;
        let mut previous_timestamp = 0.0;
        for (index, trace) in guard.traces.iter().enumerate() {
            if trace.sequence != index as u64
                || trace.previous_hash.as_deref() != previous_hash
                || trace.timestamp < previous_timestamp
                || !trace.verify_integrity()
            {
                return Ok(false);
            }
            previous_hash = Some(&trace.integrity_hash);
            previous_timestamp = trace.timestamp;
        }

        for liability in &guard.liabilities {
            if !liability.verify_integrity()
                || !guard.traces.iter().any(|trace| {
                    trace.id == liability.trace_id
                        && trace.integrity_hash == liability.trace_hash
                        && trace.authority_id == liability.authority_id
                        && trace.authority_hash == liability.authority_hash
                        && trace.action_scope == liability.action_scope
                        && trace.timestamp == liability.timestamp
                })
            {
                return Ok(false);
            }
        }

        for consumed in &guard.consumed {
            let has_started = guard.traces.iter().any(|trace| {
                trace.authority_hash == consumed.authority_hash && trace.outcome == "started"
            });
            let has_terminal = guard.traces.iter().any(|trace| {
                trace.authority_hash == consumed.authority_hash
                    && matches!(trace.outcome.as_str(), "succeeded" | "failed" | "panicked")
            });
            if !has_started || consumed.terminal != has_terminal {
                return Ok(false);
            }
        }

        Ok(guard.head_hash.as_deref() == previous_hash)
    }

    pub fn execute_with_authority(
        &self,
        au: &AuthorityUnit,
        action_fn: &dyn Fn() -> Result<String, String>,
        action_name: &str,
        action_scope: &str,
    ) -> Result<(DecisionTrace, LiabilityRecord), ExecutionGateError> {
        if action_name.trim().is_empty() {
            return Err(ExecutionGateError::EmptyActionName);
        }
        if action_scope.trim().is_empty() {
            return Err(ExecutionGateError::EmptyActionScope);
        }
        if let Err(error) = au.validate_invariants() {
            return Err(ExecutionGateError::InvalidAuthority(format!(
                "{} ({error})",
                au.id
            )));
        }

        let authority_hash = au.hash();
        let validation = catch_unwind(AssertUnwindSafe(|| (self.validator)(au)));
        match validation {
            Ok(true) => {}
            Ok(false) => {
                self.append_event(
                    au,
                    &authority_hash,
                    action_name,
                    action_scope,
                    "rejected",
                    "validator rejected authority",
                )?;
                return Err(ExecutionGateError::InvalidAuthority(au.id.clone()));
            }
            Err(_) => {
                self.append_event(
                    au,
                    &authority_hash,
                    action_name,
                    action_scope,
                    "rejected",
                    "validator panicked",
                )?;
                return Err(ExecutionGateError::ValidatorPanicked(au.id.clone()));
            }
        }
        if !au.can_consume(action_scope) {
            self.append_event(
                au,
                &authority_hash,
                action_name,
                action_scope,
                "rejected",
                "scope mismatch",
            )?;
            return Err(ExecutionGateError::ScopeMismatch {
                authority_scope: au.scope.clone(),
                action_scope: action_scope.to_string(),
            });
        }

        self.reserve_and_record_start(au, &authority_hash, action_name, action_scope)?;

        match catch_unwind(AssertUnwindSafe(action_fn)) {
            Ok(Ok(result)) => {
                let records = self.append_terminal_records(
                    au,
                    &authority_hash,
                    action_name,
                    action_scope,
                    "succeeded",
                    result,
                )?;
                Ok(records)
            }
            Ok(Err(error)) => {
                self.append_terminal_records(
                    au,
                    &authority_hash,
                    action_name,
                    action_scope,
                    "failed",
                    error.clone(),
                )?;
                Err(ExecutionGateError::ActionFailed(error))
            }
            Err(_) => {
                self.append_terminal_records(
                    au,
                    &authority_hash,
                    action_name,
                    action_scope,
                    "panicked",
                    "action panicked".to_string(),
                )?;
                Err(ExecutionGateError::ActionPanicked)
            }
        }
    }

    fn reserve_and_record_start(
        &self,
        au: &AuthorityUnit,
        authority_hash: &str,
        action_name: &str,
        action_scope: &str,
    ) -> Result<(), ExecutionGateError> {
        let mut state = ENFORCEMENT_STATE
            .lock()
            .map_err(|_| ExecutionGateError::LockError)?;
        let mut timestamp = current_timestamp();
        if !timestamp.is_finite()
            || timestamp + MAX_CLOCK_JITTER_SECONDS < state.high_water_timestamp
        {
            return Err(ExecutionGateError::InvalidClock);
        }
        timestamp = timestamp.max(state.high_water_timestamp);
        let manager_max_age = effective_manager_max_age(&state, authority_hash);
        if let Some(max_age_seconds) = manager_max_age {
            if !au.is_valid(timestamp, max_age_seconds) {
                Self::append_event_locked(
                    &mut state,
                    au,
                    authority_hash,
                    action_name,
                    action_scope,
                    "rejected",
                    "manager validation expired before reservation",
                    timestamp,
                )?;
                return Err(ExecutionGateError::InvalidAuthority(au.id.clone()));
            }
        }
        if state
            .consumed
            .iter()
            .any(|entry| entry.authority_hash == authority_hash)
        {
            drop(state);
            self.append_event(
                au,
                authority_hash,
                action_name,
                action_scope,
                "rejected",
                "authority already consumed",
            )?;
            return Err(ExecutionGateError::AlreadyConsumed(au.id.clone()));
        }

        Self::append_event_locked(
            &mut state,
            au,
            authority_hash,
            action_name,
            action_scope,
            "started",
            "",
            timestamp,
        )?;
        state.consumed.push(ConsumedAuthority {
            id: au.id.clone(),
            authority_hash: authority_hash.to_string(),
            terminal: false,
            timestamp,
        });
        Ok(())
    }

    fn append_terminal_records(
        &self,
        au: &AuthorityUnit,
        authority_hash: &str,
        action_name: &str,
        action_scope: &str,
        outcome: &str,
        result: String,
    ) -> Result<(DecisionTrace, LiabilityRecord), ExecutionGateError> {
        let mut journal = ENFORCEMENT_STATE
            .lock()
            .map_err(|_| ExecutionGateError::LockError)?;
        let reservation_timestamp = journal
            .consumed
            .iter()
            .find(|entry| entry.authority_hash == authority_hash)
            .map(|entry| entry.timestamp)
            .ok_or(ExecutionGateError::LockError)?;
        let observed_timestamp = current_timestamp();
        let timestamp = if observed_timestamp.is_finite()
            && observed_timestamp + MAX_CLOCK_JITTER_SECONDS >= journal.high_water_timestamp
        {
            observed_timestamp
                .max(reservation_timestamp)
                .max(journal.high_water_timestamp)
        } else {
            // Execution may already have committed external effects. Preserve terminal evidence
            // at the last trusted logical time instead of losing it to a post-action clock fault.
            reservation_timestamp.max(journal.high_water_timestamp)
        };
        let trace = Self::append_event_locked(
            &mut journal,
            au,
            authority_hash,
            action_name,
            action_scope,
            outcome,
            &result,
            timestamp,
        )?;
        let liability = LiabilityRecord::from_trace(
            &trace,
            au.price,
            au.scope.clone(),
            au.delegation_chain.clone(),
        );
        journal.liabilities.push(liability.clone());
        let consumed = journal
            .consumed
            .iter_mut()
            .find(|entry| entry.authority_hash == authority_hash)
            .ok_or(ExecutionGateError::LockError)?;
        consumed.terminal = true;
        Ok((trace, liability))
    }

    #[allow(clippy::too_many_arguments)]
    fn append_event(
        &self,
        au: &AuthorityUnit,
        authority_hash: &str,
        action_name: &str,
        action_scope: &str,
        outcome: &str,
        result: &str,
    ) -> Result<DecisionTrace, ExecutionGateError> {
        let mut journal = ENFORCEMENT_STATE
            .lock()
            .map_err(|_| ExecutionGateError::LockError)?;
        let timestamp = current_timestamp();
        Self::append_event_locked(
            &mut journal,
            au,
            authority_hash,
            action_name,
            action_scope,
            outcome,
            result,
            timestamp,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn append_event_locked(
        journal: &mut AuditJournal,
        au: &AuthorityUnit,
        authority_hash: &str,
        action_name: &str,
        action_scope: &str,
        outcome: &str,
        result: &str,
        mut timestamp: f64,
    ) -> Result<DecisionTrace, ExecutionGateError> {
        if !timestamp.is_finite() || timestamp < 0.0 {
            return Err(ExecutionGateError::InvalidClock);
        }
        if timestamp + MAX_CLOCK_JITTER_SECONDS < journal.high_water_timestamp {
            return Err(ExecutionGateError::InvalidClock);
        }
        timestamp = timestamp.max(journal.high_water_timestamp);
        let next_sequence = journal
            .next_sequence
            .checked_add(1)
            .ok_or(ExecutionGateError::LockError)?;
        let trace = DecisionTrace::from_event(
            action_name.to_string(),
            action_scope.to_string(),
            au.id.clone(),
            authority_hash.to_string(),
            result.to_string(),
            outcome.to_string(),
            timestamp,
            journal.next_sequence,
            journal.head_hash.clone(),
        );
        journal.next_sequence = next_sequence;
        journal.head_hash = Some(trace.integrity_hash.clone());
        journal.high_water_timestamp = timestamp;
        journal.traces.push(trace.clone());
        Ok(trace)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_clock_high_water_rejects_regression() {
        let authority = AuthorityUnit::new(
            "clock-high-water".to_string(),
            "read".to_string(),
            vec!["root".to_string()],
            1,
            1.0,
            None,
        )
        .unwrap();
        let authority_hash = authority.hash();
        let mut journal = AuditJournal::default();

        ExecutionGate::<fn(&AuthorityUnit) -> bool>::append_event_locked(
            &mut journal,
            &authority,
            &authority_hash,
            "read",
            "read",
            "started",
            "",
            2.0,
        )
        .unwrap();
        let regressed = ExecutionGate::<fn(&AuthorityUnit) -> bool>::append_event_locked(
            &mut journal,
            &authority,
            &authority_hash,
            "read",
            "read",
            "succeeded",
            "ok",
            1.0,
        );

        assert!(matches!(regressed, Err(ExecutionGateError::InvalidClock)));
    }
}
