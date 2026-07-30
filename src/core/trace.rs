use crate::core::authority::current_timestamp;
use sha2::{Digest, Sha256};

fn update_part(hasher: &mut Sha256, label: &str, value: &str) {
    hasher.update(label.as_bytes());
    hasher.update(b":");
    hasher.update(value.len().to_string().as_bytes());
    hasher.update(b":");
    hasher.update(value.as_bytes());
    hasher.update(b";");
}

fn hash_reference(domain: &str, value: &str) -> String {
    let mut hasher = Sha256::new();
    update_part(&mut hasher, "domain", domain);
    update_part(&mut hasher, "value", value);
    format!("{:x}", hasher.finalize())
}

#[derive(Debug, Clone, PartialEq)]
pub struct DecisionTrace {
    pub action_name: String,
    pub authority_id: String,
    pub timestamp: f64,
    pub result: String,
    pub id: String,
    pub action_scope: String,
    pub authority_hash: String,
    pub outcome: String,
    pub sequence: u64,
    pub previous_hash: Option<String>,
    pub integrity_hash: String,
}

impl DecisionTrace {
    pub fn new(action_name: String, authority_id: String, result: String) -> Self {
        let authority_hash = hash_reference("ABLE-AUTHORITY-REFERENCE-v1", &authority_id);
        Self::from_event(
            action_name,
            "unspecified".to_string(),
            authority_id,
            authority_hash,
            result,
            "succeeded".to_string(),
            current_timestamp(),
            0,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_event(
        action_name: String,
        action_scope: String,
        authority_id: String,
        authority_hash: String,
        result: String,
        outcome: String,
        timestamp: f64,
        sequence: u64,
        previous_hash: Option<String>,
    ) -> Self {
        let mut trace = DecisionTrace {
            action_name,
            authority_id,
            timestamp,
            result,
            id: String::new(),
            action_scope,
            authority_hash,
            outcome,
            sequence,
            previous_hash,
            integrity_hash: String::new(),
        };
        trace.integrity_hash = trace.compute_integrity_hash();
        trace.id = trace.integrity_hash.clone();
        trace
    }

    fn compute_integrity_hash(&self) -> String {
        let mut hasher = Sha256::new();
        update_part(&mut hasher, "domain", "ABLE-DECISION-TRACE-v1");
        update_part(&mut hasher, "action_name", &self.action_name);
        update_part(&mut hasher, "action_scope", &self.action_scope);
        update_part(&mut hasher, "authority_id", &self.authority_id);
        update_part(&mut hasher, "authority_hash", &self.authority_hash);
        update_part(
            &mut hasher,
            "timestamp_bits",
            &self.timestamp.to_bits().to_string(),
        );
        update_part(&mut hasher, "result", &self.result);
        update_part(&mut hasher, "outcome", &self.outcome);
        update_part(&mut hasher, "sequence", &self.sequence.to_string());
        match &self.previous_hash {
            Some(previous_hash) => {
                update_part(&mut hasher, "previous_hash_present", "true");
                update_part(&mut hasher, "previous_hash", previous_hash);
            }
            None => update_part(&mut hasher, "previous_hash_present", "false"),
        }
        format!("{:x}", hasher.finalize())
    }

    pub fn verify_integrity(&self) -> bool {
        self.timestamp.is_finite()
            && self.timestamp >= 0.0
            && self.id == self.integrity_hash
            && self.integrity_hash == self.compute_integrity_hash()
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct LiabilityRecord {
    pub trace_id: String,
    pub authority_id: String,
    pub price: i64,
    pub scope: String,
    pub timestamp: f64,
    pub id: String,
    pub action_scope: String,
    pub authority_hash: String,
    pub accountable_parties: Vec<String>,
    pub trace_hash: String,
    pub integrity_hash: String,
}

impl LiabilityRecord {
    pub fn new(trace_id: String, authority_id: String, price: i64, scope: String) -> Self {
        let authority_hash = hash_reference("ABLE-AUTHORITY-REFERENCE-v1", &authority_id);
        let action_scope = scope.clone();
        Self::from_parts(
            trace_id.clone(),
            authority_id,
            price,
            scope,
            current_timestamp(),
            action_scope,
            authority_hash,
            Vec::new(),
            trace_id,
        )
    }

    pub(crate) fn from_trace(
        trace: &DecisionTrace,
        price: i64,
        authority_scope: String,
        accountable_parties: Vec<String>,
    ) -> Self {
        Self::from_parts(
            trace.id.clone(),
            trace.authority_id.clone(),
            price,
            authority_scope,
            trace.timestamp,
            trace.action_scope.clone(),
            trace.authority_hash.clone(),
            accountable_parties,
            trace.integrity_hash.clone(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn from_parts(
        trace_id: String,
        authority_id: String,
        price: i64,
        scope: String,
        timestamp: f64,
        action_scope: String,
        authority_hash: String,
        accountable_parties: Vec<String>,
        trace_hash: String,
    ) -> Self {
        let mut record = LiabilityRecord {
            trace_id,
            authority_id,
            price,
            scope,
            timestamp,
            id: String::new(),
            action_scope,
            authority_hash,
            accountable_parties,
            trace_hash,
            integrity_hash: String::new(),
        };
        record.integrity_hash = record.compute_integrity_hash();
        record.id = record.integrity_hash.clone();
        record
    }

    fn compute_integrity_hash(&self) -> String {
        let mut hasher = Sha256::new();
        update_part(&mut hasher, "domain", "ABLE-LIABILITY-RECORD-v1");
        update_part(&mut hasher, "trace_id", &self.trace_id);
        update_part(&mut hasher, "trace_hash", &self.trace_hash);
        update_part(&mut hasher, "authority_id", &self.authority_id);
        update_part(&mut hasher, "authority_hash", &self.authority_hash);
        update_part(&mut hasher, "price", &self.price.to_string());
        update_part(&mut hasher, "scope", &self.scope);
        update_part(&mut hasher, "action_scope", &self.action_scope);
        update_part(
            &mut hasher,
            "timestamp_bits",
            &self.timestamp.to_bits().to_string(),
        );
        update_part(
            &mut hasher,
            "accountable_parties_len",
            &self.accountable_parties.len().to_string(),
        );
        for party in &self.accountable_parties {
            update_part(&mut hasher, "accountable_party", party);
        }
        format!("{:x}", hasher.finalize())
    }

    pub fn verify_integrity(&self) -> bool {
        self.timestamp.is_finite()
            && self.timestamp >= 0.0
            && self.price >= 0
            && self.id == self.integrity_hash
            && self.integrity_hash == self.compute_integrity_hash()
    }
}
