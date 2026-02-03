//! # Authority-Bound Liability Engine (ABLE)
//!
//! ABLE provides deterministic enforcement of autonomous actions through
//! consumable authority units, ensuring accountability and traceability.

pub mod core;

pub use core::authority::{AuthorityUnit, AuthorityError, current_timestamp};
pub use core::gate::{ExecutionGate, ExecutionGateError};
pub use core::manager::{AuthorityManager, ManagerError};
pub use core::trace::{DecisionTrace, LiabilityRecord};

#[cfg(test)]
mod tests {
    use crate::*;

    #[test]
    fn test_authority_unit_creation() {
        let au = AuthorityUnit::new(
            "test-123".to_string(),
            "read".to_string(),
            vec!["root".to_string(), "user".to_string()],
            10,
            1640995200.0,
            None,
        ).unwrap();

        assert_eq!(au.id, "test-123");
        assert_eq!(au.scope, "read");
        assert_eq!(au.price, 10);
        assert_eq!(au.delegation_chain.len(), 2);
    }

    #[test]
    fn test_authority_unit_invalid_price() {
        let result = AuthorityUnit::new(
            "test-123".to_string(),
            "read".to_string(),
            vec!["root".to_string()],
            -5,
            1640995200.0,
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_authority_unit_empty_scope() {
        let result = AuthorityUnit::new(
            "test-123".to_string(),
            "".to_string(),
            vec!["root".to_string()],
            10,
            1640995200.0,
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_authority_unit_empty_delegation() {
        let result = AuthorityUnit::new(
            "test-123".to_string(),
            "read".to_string(),
            vec![],
            10,
            1640995200.0,
            None,
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_authority_unit_hash() {
        let au = AuthorityUnit::new(
            "test-123".to_string(),
            "read".to_string(),
            vec!["root".to_string()],
            10,
            1640995200.0,
            None,
        ).unwrap();

        assert_eq!(au.hash().len(), 64);
    }

    #[test]
    fn test_authority_unit_validity() {
        let au = AuthorityUnit::new(
            "test-123".to_string(),
            "read".to_string(),
            vec!["root".to_string()],
            10,
            1640995200.0,
            None,
        ).unwrap();

        assert!(au.is_valid(1640995200.0 + 1000.0, 3600));
        assert!(!au.is_valid(1640995200.0 + 3700.0, 3600));
    }

    #[test]
    fn test_authority_unit_consumption() {
        let au = AuthorityUnit::new(
            "test-123".to_string(),
            "read".to_string(),
            vec!["root".to_string()],
            10,
            1640995200.0,
            None,
        ).unwrap();

        assert!(au.can_consume("read"));
        assert!(!au.can_consume("write"));

        let au_any = AuthorityUnit::new(
            "test-456".to_string(),
            "any".to_string(),
            vec!["root".to_string()],
            10,
            1640995200.0,
            None,
        ).unwrap();

        assert!(au_any.can_consume("read"));
        assert!(au_any.can_consume("write"));
    }

    #[test]
    fn test_execution_gate_valid_authority() {
        let gate = ExecutionGate::new(|_| true);

        let au = AuthorityUnit::new(
            "test-123".to_string(),
            "read".to_string(),
            vec!["root".to_string()],
            10,
            1640995200.0,
            None,
        ).unwrap();

        let result = gate.execute_with_authority(
            &au,
            &|| Ok("success".to_string()),
            "test_action",
            "read"
        );

        assert!(result.is_ok());
        let (trace, liability) = result.unwrap();
        assert_eq!(trace.action_name, "test_action");
        assert_eq!(trace.authority_id, "test-123");
        assert_eq!(liability.authority_id, "test-123");
        assert_eq!(liability.price, 10);
    }

    #[test]
    fn test_execution_gate_invalid_authority() {
        let gate = ExecutionGate::new(|_| false);

        let au = AuthorityUnit::new(
            "test-123".to_string(),
            "read".to_string(),
            vec!["root".to_string()],
            10,
            1640995200.0,
            None,
        ).unwrap();

        let result = gate.execute_with_authority(
            &au,
            &|| Ok("success".to_string()),
            "test_action",
            "read"
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_execution_gate_already_consumed() {
        let gate = ExecutionGate::new(|_| true);

        let au = AuthorityUnit::new(
            "test-123".to_string(),
            "read".to_string(),
            vec!["root".to_string()],
            10,
            1640995200.0,
            None,
        ).unwrap();

        // First execution should succeed
        let result1 = gate.execute_with_authority(
            &au,
            &|| Ok("success".to_string()),
            "test_action",
            "read"
        );
        assert!(result1.is_ok());

        // Second execution with same authority should fail
        let result2 = gate.execute_with_authority(
            &au,
            &|| Ok("success".to_string()),
            "test_action_2",
            "read"
        );
        assert!(result2.is_err());
    }

    #[test]
    fn test_execution_gate_action_failure() {
        let gate = ExecutionGate::new(|_| true);

        let au = AuthorityUnit::new(
            "test-123".to_string(),
            "read".to_string(),
            vec!["root".to_string()],
            10,
            1640995200.0,
            None,
        ).unwrap();

        let result = gate.execute_with_authority(
            &au,
            &|| Err("Action failed".to_string()),
            "failing_action",
            "read"
        );

        assert!(result.is_err());
        // Verify that the authority was not consumed (since it was rolled back)
        assert!(!gate.is_consumed(&au.id).unwrap());
    }

    #[test]
    fn test_execution_gate_scope_validation() {
        let gate = ExecutionGate::new(|_| true);

        let au = AuthorityUnit::new(
            "test-123".to_string(),
            "read".to_string(),
            vec!["root".to_string()],
            10,
            1640995200.0,
            None,
        ).unwrap();

        // Should succeed - matching scope
        let result1 = gate.execute_with_authority(
            &au,
            &|| Ok("success".to_string()),
            "fetch_data",
            "read"
        );
        assert!(result1.is_ok());

        // Should fail - mismatched scope
        let result2 = gate.execute_with_authority(
            &au,
            &|| Ok("success".to_string()),
            "write_data",
            "write"
        );
        assert!(result2.is_err());
    }

    #[test]
    fn test_execution_gate_any_scope() {
        let gate = ExecutionGate::new(|_| true);

        let au1 = AuthorityUnit::new(
            "test-123".to_string(),
            "any".to_string(),
            vec!["root".to_string()],
            10,
            1640995200.0,
            None,
        ).unwrap();

        let au2 = AuthorityUnit::new(
            "test-456".to_string(),
            "any".to_string(),
            vec!["root".to_string()],
            10,
            1640995200.0,
            None,
        ).unwrap();

        // Should succeed for any action scope
        let result1 = gate.execute_with_authority(
            &au1,
            &|| Ok("success".to_string()),
            "fetch_data",
            "read"
        );
        assert!(result1.is_ok());

        let result2 = gate.execute_with_authority(
            &au2,
            &|| Ok("success".to_string()),
            "write_data",
            "write"
        );
        assert!(result2.is_ok());
    }

    #[test]
    fn test_authority_manager_issue_authority() {
        let manager = AuthorityManager::new();

        let au = AuthorityUnit::new(
            "test-123".to_string(),
            "read".to_string(),
            vec!["root".to_string()],
            10,
            1640995200.0,
            None,
        ).unwrap();

        manager.issue_authority(au).unwrap();

        assert!(manager.get_authority("test-123").is_some());
    }

    #[test]
    fn test_authority_manager_duplicate_issue() {
        let manager = AuthorityManager::new();

        let au = AuthorityUnit::new(
            "test-123".to_string(),
            "read".to_string(),
            vec!["root".to_string()],
            10,
            1640995200.0,
            None,
        ).unwrap();

        manager.issue_authority(au.clone()).unwrap();

        let result = manager.issue_authority(au);
        assert!(result.is_err());
    }

    #[test]
    fn test_authority_manager_validate_valid() {
        let manager = AuthorityManager::with_max_age(i64::MAX);
        let ts = current_timestamp();

        let au = AuthorityUnit::new(
            "test-123".to_string(),
            "read".to_string(),
            vec!["root".to_string()],
            10,
            ts,
            None,
        ).unwrap();

        manager.issue_authority(au.clone()).unwrap();
        assert!(manager.validate_authority(&au));
    }

    #[test]
    fn test_authority_manager_validate_invalid() {
        let manager = AuthorityManager::new();

        let au = AuthorityUnit::new(
            "test-123".to_string(),
            "read".to_string(),
            vec!["root".to_string()],
            10,
            1640995200.0,
            None,
        ).unwrap();

        // Don't issue it, so validation should fail
        assert!(!manager.validate_authority(&au));
    }

    #[test]
    fn test_authority_manager_validate_mismatched() {
        let manager = AuthorityManager::with_max_age(i64::MAX);
        let ts = current_timestamp();

        let au1 = AuthorityUnit::new(
            "test-123".to_string(),
            "read".to_string(),
            vec!["root".to_string()],
            10,
            ts,
            None,
        ).unwrap();

        manager.issue_authority(au1).unwrap();

        // Create a copy with different price (mutated)
        let au2 = AuthorityUnit::new(
            "test-123".to_string(),
            "read".to_string(),
            vec!["root".to_string()],
            20, // Different price
            ts,
            None,
        ).unwrap();

        // Should not validate because it's a different authority unit
        assert!(!manager.validate_authority(&au2));
    }

    #[test]
    fn test_authority_manager_get_nonexistent() {
        let manager = AuthorityManager::new();
        assert!(manager.get_authority("nonexistent").is_none());
    }
}