use uuid::Uuid;
use crate::core::authority::current_timestamp;

#[derive(Debug, Clone)]
pub struct DecisionTrace {
    pub action_name: String,
    pub authority_id: String,
    pub timestamp: f64,
    pub result: String,
    pub id: String,
}

impl DecisionTrace {
    pub fn new(action_name: String, authority_id: String, result: String) -> Self {
        let timestamp = current_timestamp();
        DecisionTrace {
            action_name,
            authority_id,
            timestamp,
            result,
            id: Uuid::new_v4().to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct LiabilityRecord {
    pub trace_id: String,
    pub authority_id: String,
    pub price: i64,
    pub scope: String,
    pub timestamp: f64,
    pub id: String,
}

impl LiabilityRecord {
    pub fn new(trace_id: String, authority_id: String, price: i64, scope: String) -> Self {
        let timestamp = current_timestamp();
        LiabilityRecord {
            trace_id,
            authority_id,
            price,
            scope,
            timestamp,
            id: Uuid::new_v4().to_string(),
        }
    }
}