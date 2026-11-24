//! # Authority-Bound Liability Engine (ABLE)
//!
//! ABLE provides deterministic enforcement of autonomous actions through
//! consumable authority units, ensuring accountability and traceability.

pub mod core;

pub use core::authority::{current_timestamp, AuthorityError, AuthorityUnit};
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
        )
        .unwrap();

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
        )
        .unwrap();

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
        )
        .unwrap();

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
        )
        .unwrap();

        assert!(au.can_consume("read"));
        assert!(!au.can_consume("write"));

        let au_any = AuthorityUnit::new(
            "test-456".to_string(),
            "any".to_string(),
            vec!["root".to_string()],
            10,
            1640995200.0,
            None,
        )
        .unwrap();

        assert!(au_any.can_consume("read"));
        assert!(au_any.can_consume("write"));
    }

    #[test]
    fn test_execution_gate_valid_authority() {
        let gate = ExecutionGate::new(|_| true);

        let au = AuthorityUnit::new(
            "gate-valid-authority".to_string(),
            "read".to_string(),
            vec!["root".to_string()],
            10,
            1640995200.0,
            None,
        )
        .unwrap();

        let result =
            gate.execute_with_authority(&au, &|| Ok("success".to_string()), "test_action", "read");

        assert!(result.is_ok());
        let (trace, liability) = result.unwrap();
        assert_eq!(trace.action_name, "test_action");
        assert_eq!(trace.authority_id, "gate-valid-authority");
        assert_eq!(liability.authority_id, "gate-valid-authority");
        assert_eq!(liability.price, 10);
    }

    #[test]
    fn test_execution_gate_invalid_authority() {
        let gate = ExecutionGate::new(|_| false);

        let au = AuthorityUnit::new(
            "gate-invalid-authority".to_string(),
            "read".to_string(),
            vec!["root".to_string()],
            10,
            1640995200.0,
            None,
        )
        .unwrap();

        let result =
            gate.execute_with_authority(&au, &|| Ok("success".to_string()), "test_action", "read");

        assert!(result.is_err());
    }

    #[test]
    fn test_execution_gate_already_consumed() {
        let gate = ExecutionGate::new(|_| true);

        let au = AuthorityUnit::new(
            "gate-already-consumed".to_string(),
            "read".to_string(),
            vec!["root".to_string()],
            10,
            1640995200.0,
            None,
        )
        .unwrap();

        // First execution should succeed
        let result1 =
            gate.execute_with_authority(&au, &|| Ok("success".to_string()), "test_action", "read");
        assert!(result1.is_ok());

        // Second execution with same authority should fail
        let result2 = gate.execute_with_authority(
            &au,
            &|| Ok("success".to_string()),
            "test_action_2",
            "read",
        );
        assert!(result2.is_err());
    }

    #[test]
    fn test_execution_gate_action_failure() {
        let gate = ExecutionGate::new(|_| true);

        let au = AuthorityUnit::new(
            "gate-action-failure".to_string(),
            "read".to_string(),
            vec!["root".to_string()],
            10,
            1640995200.0,
            None,
        )
        .unwrap();

        let result = gate.execute_with_authority(
            &au,
            &|| Err("Action failed".to_string()),
            "failing_action",
            "read",
        );

        assert!(result.is_err());
        // Execution may have produced external side effects before reporting failure, so
        // authority is exhausted fail-closed rather than made replayable.
        assert!(gate.is_consumed(&au.id).unwrap());
    }

    #[test]
    fn test_execution_gate_scope_validation() {
        let gate = ExecutionGate::new(|_| true);

        let au = AuthorityUnit::new(
            "gate-scope-validation".to_string(),
            "read".to_string(),
            vec!["root".to_string()],
            10,
            1640995200.0,
            None,
        )
        .unwrap();

        // Should succeed - matching scope
        let result1 =
            gate.execute_with_authority(&au, &|| Ok("success".to_string()), "fetch_data", "read");
        assert!(result1.is_ok());

        // Should fail - mismatched scope
        let result2 =
            gate.execute_with_authority(&au, &|| Ok("success".to_string()), "write_data", "write");
        assert!(result2.is_err());
    }

    #[test]
    fn test_execution_gate_any_scope() {
        let gate = ExecutionGate::new(|_| true);

        let au1 = AuthorityUnit::new(
            "gate-any-read".to_string(),
            "any".to_string(),
            vec!["root".to_string()],
            10,
            1640995200.0,
            None,
        )
        .unwrap();

        let au2 = AuthorityUnit::new(
            "gate-any-write".to_string(),
            "any".to_string(),
            vec!["root".to_string()],
            10,
            1640995200.0,
            None,
        )
        .unwrap();

        // Should succeed for any action scope
        let result1 =
            gate.execute_with_authority(&au1, &|| Ok("success".to_string()), "fetch_data", "read");
        assert!(result1.is_ok());

        let result2 =
            gate.execute_with_authority(&au2, &|| Ok("success".to_string()), "write_data", "write");
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
        )
        .unwrap();

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
        )
        .unwrap();

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
        )
        .unwrap();

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
        )
        .unwrap();

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
        )
        .unwrap();

        manager.issue_authority(au1).unwrap();

        // Create a copy with different price (mutated)
        let au2 = AuthorityUnit::new(
            "test-123".to_string(),
            "read".to_string(),
            vec!["root".to_string()],
            20, // Different price
            ts,
            None,
        )
        .unwrap();

        // Should not validate because it's a different authority unit
        assert!(!manager.validate_authority(&au2));
    }

    #[test]
    fn test_authority_manager_get_nonexistent() {
        let manager = AuthorityManager::new();
        assert!(manager.get_authority("nonexistent").is_none());
    }

    #[test]
    fn test_authority_unit_rejects_empty_id_and_invalid_timestamp() {
        let empty_id = AuthorityUnit::new(
            "".to_string(),
            "read".to_string(),
            vec!["root".to_string()],
            10,
            1640995200.0,
            None,
        );
        assert!(matches!(empty_id, Err(AuthorityError::EmptyId)));

        let non_finite_timestamp = AuthorityUnit::new(
            "test-123".to_string(),
            "read".to_string(),
            vec!["root".to_string()],
            10,
            f64::NAN,
            None,
        );
        assert!(matches!(
            non_finite_timestamp,
            Err(AuthorityError::InvalidTimestamp)
        ));
    }

    #[test]
    fn test_authority_unit_future_timestamp_is_invalid() {
        let au = AuthorityUnit::new(
            "test-123".to_string(),
            "read".to_string(),
            vec!["root".to_string()],
            10,
            2000.0,
            None,
        )
        .unwrap();

        assert!(!au.is_valid(1999.0, 3600));
    }

    #[test]
    fn test_authority_hash_disambiguates_delegation_chain_entries() {
        let au1 = AuthorityUnit::new(
            "test-123".to_string(),
            "read".to_string(),
            vec!["root,user".to_string(), "approver".to_string()],
            10,
            1640995200.0,
            None,
        )
        .unwrap();

        let au2 = AuthorityUnit::new(
            "test-123".to_string(),
            "read".to_string(),
            vec!["root".to_string(), "user,approver".to_string()],
            10,
            1640995200.0,
            None,
        )
        .unwrap();

        assert_ne!(au1.hash(), au2.hash());
    }

    #[test]
    fn test_authority_manager_rejects_invalid_public_authority() {
        let manager = AuthorityManager::new();
        let au = AuthorityUnit {
            id: "".to_string(),
            scope: "read".to_string(),
            delegation_chain: vec!["root".to_string()],
            price: 10,
            timestamp: 1640995200.0,
            prev_hash: None,
        };

        assert!(matches!(
            manager.issue_authority(au),
            Err(ManagerError::InvalidAuthority(_))
        ));
    }

    #[test]
    fn test_gate_rejects_malformed_authority_even_when_validator_accepts() {
        let gate = ExecutionGate::new(|_| true);
        let malformed = AuthorityUnit {
            id: "gate-malformed-authority".to_string(),
            scope: "any".to_string(),
            delegation_chain: Vec::new(),
            price: -1,
            timestamp: f64::NAN,
            prev_hash: None,
        };

        let result = gate.execute_with_authority(
            &malformed,
            &|| Ok("must not run".to_string()),
            "malformed_action",
            "write",
        );

        assert!(matches!(
            result,
            Err(ExecutionGateError::InvalidAuthority(_))
        ));
        assert!(!gate.is_consumed(&malformed.id).unwrap());
    }

    #[test]
    fn test_authority_rejects_ambiguous_previous_hash_and_negative_zero_time() {
        let empty_previous_hash = AuthorityUnit::new(
            "invalid-empty-previous-hash".to_string(),
            "read".to_string(),
            vec!["root".to_string()],
            10,
            1.0,
            Some(String::new()),
        );
        assert!(matches!(
            empty_previous_hash,
            Err(AuthorityError::InvalidPreviousHash)
        ));

        let negative_zero_time = AuthorityUnit::new(
            "invalid-negative-zero-time".to_string(),
            "read".to_string(),
            vec!["root".to_string()],
            10,
            -0.0,
            None,
        );
        assert!(matches!(
            negative_zero_time,
            Err(AuthorityError::InvalidTimestamp)
        ));
    }

    #[test]
    fn test_manager_validates_delegation_predecessor_and_scope_narrowing() {
        let manager = AuthorityManager::with_max_age(i64::MAX);
        let timestamp = current_timestamp();
        let parent = AuthorityUnit::new(
            "delegation-parent".to_string(),
            "read".to_string(),
            vec!["root".to_string()],
            10,
            timestamp,
            None,
        )
        .unwrap();
        manager.issue_authority(parent.clone()).unwrap();

        let unlinked_chain = AuthorityUnit::new(
            "delegation-unlinked-chain".to_string(),
            "read".to_string(),
            vec!["root".to_string(), "attacker".to_string()],
            10,
            timestamp,
            None,
        )
        .unwrap();
        assert!(matches!(
            manager.issue_authority(unlinked_chain),
            Err(ManagerError::InvalidAuthority(_))
        ));

        let child = AuthorityUnit::new(
            "delegation-child".to_string(),
            "read".to_string(),
            vec!["root".to_string(), "reader".to_string()],
            10,
            timestamp,
            Some(parent.hash()),
        )
        .unwrap();
        manager.issue_authority(child.clone()).unwrap();
        assert!(manager.validate_authority(&child));

        let forged_parent = AuthorityUnit::new(
            "delegation-forged-parent".to_string(),
            "read".to_string(),
            vec!["root".to_string(), "attacker".to_string()],
            10,
            timestamp,
            Some("0".repeat(64)),
        )
        .unwrap();
        assert!(matches!(
            manager.issue_authority(forged_parent),
            Err(ManagerError::InvalidAuthority(_))
        ));

        let broadened_scope = AuthorityUnit::new(
            "delegation-broadened-scope".to_string(),
            "any".to_string(),
            vec!["root".to_string(), "administrator".to_string()],
            10,
            timestamp,
            Some(parent.hash()),
        )
        .unwrap();
        assert!(matches!(
            manager.issue_authority(broadened_scope),
            Err(ManagerError::InvalidAuthority(_))
        ));

        let reduced_price = AuthorityUnit::new(
            "delegation-reduced-price".to_string(),
            "read".to_string(),
            vec!["root".to_string(), "discounted-reader".to_string()],
            9,
            timestamp,
            Some(parent.hash()),
        )
        .unwrap();
        assert!(matches!(
            manager.issue_authority(reduced_price),
            Err(ManagerError::InvalidAuthority(_))
        ));

        let extended_lifetime = AuthorityUnit::new(
            "delegation-extended-lifetime".to_string(),
            "read".to_string(),
            vec!["root".to_string(), "late-reader".to_string()],
            10,
            timestamp + 1.0,
            Some(parent.hash()),
        )
        .unwrap();
        assert!(matches!(
            manager.issue_authority(extended_lifetime),
            Err(ManagerError::InvalidAuthority(_))
        ));

        let expiring_manager = AuthorityManager::new();
        let expired_parent = AuthorityUnit::new(
            "delegation-expired-parent".to_string(),
            "read".to_string(),
            vec!["root".to_string()],
            10,
            current_timestamp() - 7200.0,
            None,
        )
        .unwrap();
        expiring_manager
            .issue_authority(expired_parent.clone())
            .unwrap();
        let rejuvenated_child = AuthorityUnit::new(
            "delegation-rejuvenated-child".to_string(),
            "read".to_string(),
            vec!["root".to_string(), "reader".to_string()],
            10,
            expired_parent.timestamp,
            Some(expired_parent.hash()),
        )
        .unwrap();
        assert!(matches!(
            expiring_manager.issue_authority(rejuvenated_child),
            Err(ManagerError::InvalidAuthority(_))
        ));
    }

    #[test]
    fn test_consumption_is_shared_across_gate_instances() {
        let au = AuthorityUnit::new(
            "cross-gate-exhaustion".to_string(),
            "read".to_string(),
            vec!["root".to_string()],
            10,
            current_timestamp(),
            None,
        )
        .unwrap();
        let first_gate = ExecutionGate::new(|_| true);
        let second_gate = ExecutionGate::new(|_| true);

        first_gate
            .execute_with_authority(
                &au,
                &|| Ok("first".to_string()),
                "cross_gate_action",
                "read",
            )
            .unwrap();
        assert!(matches!(
            second_gate.execute_with_authority(
                &au,
                &|| Ok("second".to_string()),
                "cross_gate_action",
                "read"
            ),
            Err(ExecutionGateError::AlreadyConsumed(_))
        ));
    }

    #[test]
    fn test_failed_action_is_not_replayable_after_a_possible_side_effect() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let effects = AtomicUsize::new(0);
        let gate = ExecutionGate::new(|_| true);
        let au = AuthorityUnit::new(
            "failed-action-exhaustion".to_string(),
            "write".to_string(),
            vec!["root".to_string()],
            50,
            current_timestamp(),
            None,
        )
        .unwrap();

        let first = gate.execute_with_authority(
            &au,
            &|| {
                effects.fetch_add(1, Ordering::SeqCst);
                Err("commit outcome unknown".to_string())
            },
            "write_once",
            "write",
        );
        assert!(matches!(first, Err(ExecutionGateError::ActionFailed(_))));

        let retry = gate.execute_with_authority(
            &au,
            &|| {
                effects.fetch_add(1, Ordering::SeqCst);
                Ok("replayed".to_string())
            },
            "write_once",
            "write",
        );
        assert!(matches!(retry, Err(ExecutionGateError::AlreadyConsumed(_))));
        assert_eq!(effects.load(Ordering::SeqCst), 1);
        assert!(gate
            .audit_records()
            .unwrap()
            .iter()
            .any(|trace| trace.outcome == "failed"));
    }

    #[test]
    fn test_action_panic_is_contained_recorded_and_exhausts_authority() {
        let gate = ExecutionGate::new(|_| true);
        let au = AuthorityUnit::new(
            "panicking-action-exhaustion".to_string(),
            "write".to_string(),
            vec!["root".to_string()],
            50,
            current_timestamp(),
            None,
        )
        .unwrap();

        let result = gate.execute_with_authority(
            &au,
            &|| -> Result<String, String> { panic!("executor panic") },
            "panicking_action",
            "write",
        );
        assert!(matches!(result, Err(ExecutionGateError::ActionPanicked)));
        assert!(gate.is_consumed(&au.id).unwrap());
        assert!(gate
            .audit_records()
            .unwrap()
            .iter()
            .any(|trace| trace.outcome == "panicked"));
        assert!(gate.verify_audit_chain().unwrap());
    }

    #[test]
    fn test_action_metadata_must_be_attributable() {
        let gate = ExecutionGate::new(|_| true);
        let au = AuthorityUnit::new(
            "blank-action-metadata".to_string(),
            "any".to_string(),
            vec!["root".to_string()],
            10,
            current_timestamp(),
            None,
        )
        .unwrap();

        assert!(matches!(
            gate.execute_with_authority(&au, &|| Ok("x".to_string()), "", "read"),
            Err(ExecutionGateError::EmptyActionName)
        ));
        assert!(matches!(
            gate.execute_with_authority(&au, &|| Ok("x".to_string()), "read_action", " "),
            Err(ExecutionGateError::EmptyActionScope)
        ));
        assert!(!gate.is_consumed(&au.id).unwrap());
    }

    #[test]
    fn test_evidence_binds_actual_scope_authority_and_audit_chain() {
        let gate = ExecutionGate::new(|_| true);
        let au = AuthorityUnit::new(
            "bound-execution-evidence".to_string(),
            "any".to_string(),
            vec!["root".to_string(), "operator".to_string()],
            75,
            current_timestamp(),
            None,
        )
        .unwrap();

        let (trace, liability) = gate
            .execute_with_authority(&au, &|| Ok("written".to_string()), "write_record", "write")
            .unwrap();

        assert_eq!(trace.action_scope, "write");
        assert_eq!(trace.authority_hash, au.hash());
        assert_eq!(liability.action_scope, "write");
        assert_eq!(liability.authority_hash, au.hash());
        assert_eq!(liability.accountable_parties, au.delegation_chain);
        assert_eq!(liability.timestamp, trace.timestamp);
        assert!(trace.verify_integrity());
        assert!(liability.verify_integrity());
        assert!(gate.verify_audit_chain().unwrap());
        let authority_records: Vec<_> = gate
            .audit_records()
            .unwrap()
            .into_iter()
            .filter(|record| record.authority_hash == au.hash())
            .collect();
        let started_timestamp = authority_records
            .iter()
            .find(|record| record.outcome == "started")
            .unwrap()
            .timestamp;
        let terminal_timestamp = authority_records
            .iter()
            .find(|record| record.outcome == "succeeded")
            .unwrap()
            .timestamp;
        assert!(terminal_timestamp >= started_timestamp);

        let mut altered = trace.clone();
        altered.result = "tampered".to_string();
        assert!(!altered.verify_integrity());
        assert!(gate.verify_audit_chain().unwrap());

        let derived_again = LiabilityRecord::from_trace(
            &trace,
            au.price,
            au.scope.clone(),
            au.delegation_chain.clone(),
        );
        assert_eq!(liability, derived_again);
    }

    #[test]
    fn test_concurrent_execution_invokes_authority_once() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        fn accept(_: &AuthorityUnit) -> bool {
            true
        }

        let gate = Arc::new(ExecutionGate::new(accept as fn(&AuthorityUnit) -> bool));
        let au = Arc::new(
            AuthorityUnit::new(
                "concurrent-authority-exhaustion".to_string(),
                "write".to_string(),
                vec!["root".to_string()],
                10,
                current_timestamp(),
                None,
            )
            .unwrap(),
        );
        let invocations = Arc::new(AtomicUsize::new(0));
        let mut workers = Vec::new();

        for _ in 0..2 {
            let gate = Arc::clone(&gate);
            let au = Arc::clone(&au);
            let invocations = Arc::clone(&invocations);
            workers.push(std::thread::spawn(move || {
                gate.execute_with_authority(
                    &au,
                    &|| {
                        invocations.fetch_add(1, Ordering::SeqCst);
                        Ok("done".to_string())
                    },
                    "concurrent_write",
                    "write",
                )
            }));
        }

        let successful = workers
            .into_iter()
            .map(|worker| worker.join().unwrap().is_ok())
            .filter(|success| *success)
            .count();
        assert_eq!(successful, 1);
        assert_eq!(invocations.load(Ordering::SeqCst), 1);
        assert!(gate.verify_audit_chain().unwrap());
    }

    #[test]
    fn test_consumption_and_evidence_survive_gate_drop_together() {
        let au = AuthorityUnit::new(
            "persistent-process-evidence".to_string(),
            "read".to_string(),
            vec!["root".to_string()],
            10,
            current_timestamp(),
            None,
        )
        .unwrap();
        let authority_hash = au.hash();
        {
            let temporary_gate = ExecutionGate::new(|_| true);
            temporary_gate
                .execute_with_authority(
                    &au,
                    &|| Ok("observed".to_string()),
                    "persistent_evidence_action",
                    "read",
                )
                .unwrap();
        }

        let replacement_gate = ExecutionGate::new(|_| true);
        assert!(replacement_gate.is_authority_consumed(&au).unwrap());
        assert!(replacement_gate
            .audit_records()
            .unwrap()
            .iter()
            .any(|trace| trace.authority_hash == authority_hash && trace.outcome == "succeeded"));
        assert!(replacement_gate.verify_audit_chain().unwrap());
    }

    #[test]
    fn test_consumption_uses_full_authority_commitment_not_id_alone() {
        let timestamp = current_timestamp();
        let first = AuthorityUnit::new(
            "shared-id-distinct-authorities".to_string(),
            "read".to_string(),
            vec!["first-root".to_string()],
            10,
            timestamp,
            None,
        )
        .unwrap();
        let second = AuthorityUnit::new(
            "shared-id-distinct-authorities".to_string(),
            "write".to_string(),
            vec!["second-root".to_string()],
            20,
            timestamp,
            None,
        )
        .unwrap();
        let first_gate = ExecutionGate::new(|_| true);
        let second_gate = ExecutionGate::new(|_| true);

        first_gate
            .execute_with_authority(&first, &|| Ok("read".to_string()), "distinct_read", "read")
            .unwrap();
        second_gate
            .execute_with_authority(
                &second,
                &|| Ok("write".to_string()),
                "distinct_write",
                "write",
            )
            .unwrap();
        assert!(first_gate.is_authority_consumed(&first).unwrap());
        assert!(second_gate.is_authority_consumed(&second).unwrap());
    }

    #[test]
    fn test_consumed_parent_cannot_issue_fresh_delegation() {
        let manager = AuthorityManager::with_max_age(i64::MAX);
        let timestamp = current_timestamp();
        let parent = AuthorityUnit::new(
            "consumed-delegation-parent".to_string(),
            "read".to_string(),
            vec!["root".to_string()],
            10,
            timestamp,
            None,
        )
        .unwrap();
        manager.issue_authority(parent.clone()).unwrap();
        let gate = ExecutionGate::new(|candidate| manager.validate_authority(candidate));
        gate.execute_with_authority(
            &parent,
            &|| Ok("used".to_string()),
            "consume_parent",
            "read",
        )
        .unwrap();

        let child = AuthorityUnit::new(
            "child-of-consumed-parent".to_string(),
            "read".to_string(),
            vec!["root".to_string(), "reader".to_string()],
            10,
            timestamp,
            Some(parent.hash()),
        )
        .unwrap();
        assert!(matches!(
            manager.issue_authority(child),
            Err(ManagerError::InvalidAuthority(_))
        ));
    }

    #[test]
    fn test_delegation_issued_before_parent_consumption_is_exhausted_with_it() {
        let manager = AuthorityManager::with_max_age(i64::MAX);
        let timestamp = current_timestamp();
        let parent = AuthorityUnit::new(
            "early-delegation-parent".to_string(),
            "read".to_string(),
            vec!["root".to_string()],
            10,
            timestamp,
            None,
        )
        .unwrap();
        manager.issue_authority(parent.clone()).unwrap();
        let child = AuthorityUnit::new(
            "early-delegation-child".to_string(),
            "read".to_string(),
            vec!["root".to_string(), "reader".to_string()],
            10,
            timestamp,
            Some(parent.hash()),
        )
        .unwrap();
        manager.issue_authority(child.clone()).unwrap();
        let grandchild = AuthorityUnit::new(
            "early-delegation-grandchild".to_string(),
            "read".to_string(),
            vec![
                "root".to_string(),
                "reader".to_string(),
                "agent".to_string(),
            ],
            10,
            timestamp,
            Some(child.hash()),
        )
        .unwrap();
        manager.issue_authority(grandchild.clone()).unwrap();

        let gate = ExecutionGate::new(|candidate| manager.validate_authority(candidate));
        gate.execute_with_authority(
            &parent,
            &|| Ok("used".to_string()),
            "consume_parent",
            "read",
        )
        .unwrap();

        // Delegating first and consuming the parent afterwards must not leave
        // the consumed authority usable through its delegations.
        let invoked = std::sync::atomic::AtomicBool::new(false);
        for delegated in [&child, &grandchild] {
            let result = gate.execute_with_authority(
                delegated,
                &|| {
                    invoked.store(true, std::sync::atomic::Ordering::SeqCst);
                    Ok("escaped".to_string())
                },
                "use_delegation",
                "read",
            );
            assert!(
                matches!(result, Err(ExecutionGateError::InvalidAuthority(_))),
                "{} executed after its predecessor was consumed",
                delegated.id
            );
            assert!(!gate.is_authority_consumed(delegated).unwrap());
        }
        assert!(!invoked.load(std::sync::atomic::Ordering::SeqCst));
        assert!(gate.verify_audit_chain().unwrap());
    }

    #[test]
    fn test_standalone_integrity_is_not_gate_provenance() {
        let gate = ExecutionGate::new(|_| true);
        let standalone = DecisionTrace::new(
            "standalone".to_string(),
            "nonexistent-authority".to_string(),
            "fabricated".to_string(),
        );

        assert!(standalone.verify_integrity());
        assert!(!gate.contains_audit_record(&standalone).unwrap());
    }

    #[test]
    fn test_manager_freshness_is_rechecked_at_reservation() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::time::Duration;

        let strict_manager = AuthorityManager::with_max_age(1);
        let permissive_manager = AuthorityManager::with_max_age(i64::MAX);
        let au = AuthorityUnit::new(
            "expiring-during-validation".to_string(),
            "read".to_string(),
            vec!["root".to_string()],
            10,
            current_timestamp(),
            None,
        )
        .unwrap();
        strict_manager.issue_authority(au.clone()).unwrap();
        permissive_manager.issue_authority(au.clone()).unwrap();
        let action_ran = AtomicBool::new(false);
        let gate = ExecutionGate::new(|candidate| {
            let strict = strict_manager.validate_authority(candidate);
            let permissive = permissive_manager.validate_authority(candidate);
            std::thread::sleep(Duration::from_millis(1100));
            strict && permissive
        });

        let result = gate.execute_with_authority(
            &au,
            &|| {
                action_ran.store(true, Ordering::SeqCst);
                Ok("too late".to_string())
            },
            "expiring_read",
            "read",
        );

        assert!(matches!(
            result,
            Err(ExecutionGateError::InvalidAuthority(_))
        ));
        assert!(!action_ran.load(Ordering::SeqCst));
        assert!(!gate.is_authority_consumed(&au).unwrap());
    }

    #[test]
    fn test_terminal_trace_uses_observed_completion_time() {
        use std::time::Duration;

        let gate = ExecutionGate::new(|_| true);
        let au = AuthorityUnit::new(
            "terminal-completion-time".to_string(),
            "read".to_string(),
            vec!["root".to_string()],
            10,
            current_timestamp(),
            None,
        )
        .unwrap();
        let (terminal, _) = gate
            .execute_with_authority(
                &au,
                &|| {
                    std::thread::sleep(Duration::from_millis(20));
                    Ok("complete".to_string())
                },
                "timed_read",
                "read",
            )
            .unwrap();
        let started = gate
            .audit_records()
            .unwrap()
            .into_iter()
            .find(|record| record.authority_hash == au.hash() && record.outcome == "started")
            .unwrap();

        assert!(terminal.timestamp > started.timestamp);
        assert!(gate.verify_audit_chain().unwrap());
    }

    #[test]
    fn test_delegation_inherits_strictest_registered_parent_age() {
        let strict_manager = AuthorityManager::with_max_age(1);
        let permissive_manager = AuthorityManager::with_max_age(i64::MAX);
        let timestamp = current_timestamp() - 2.0;
        let parent = AuthorityUnit::new(
            "strict-policy-delegation-parent".to_string(),
            "read".to_string(),
            vec!["root".to_string()],
            10,
            timestamp,
            None,
        )
        .unwrap();
        strict_manager.issue_authority(parent.clone()).unwrap();
        permissive_manager.issue_authority(parent.clone()).unwrap();
        let child = AuthorityUnit::new(
            "strict-policy-delegation-child".to_string(),
            "read".to_string(),
            vec!["root".to_string(), "reader".to_string()],
            10,
            timestamp,
            Some(parent.hash()),
        )
        .unwrap();

        assert!(matches!(
            permissive_manager.issue_authority(child),
            Err(ManagerError::InvalidAuthority(_))
        ));
    }

    #[test]
    fn test_late_parent_policy_tightening_reaches_existing_child() {
        use std::sync::atomic::{AtomicBool, Ordering};

        let permissive_manager = AuthorityManager::with_max_age(i64::MAX);
        let strict_manager = AuthorityManager::with_max_age(1);
        let timestamp = current_timestamp() - 2.0;
        let parent = AuthorityUnit::new(
            "late-strict-policy-parent".to_string(),
            "read".to_string(),
            vec!["root".to_string()],
            10,
            timestamp,
            None,
        )
        .unwrap();
        permissive_manager.issue_authority(parent.clone()).unwrap();
        let child = AuthorityUnit::new(
            "late-strict-policy-child".to_string(),
            "read".to_string(),
            vec!["root".to_string(), "reader".to_string()],
            10,
            timestamp,
            Some(parent.hash()),
        )
        .unwrap();
        permissive_manager.issue_authority(child.clone()).unwrap();
        let grandchild = AuthorityUnit::new(
            "late-strict-policy-grandchild".to_string(),
            "read".to_string(),
            vec![
                "root".to_string(),
                "reader".to_string(),
                "auditor".to_string(),
            ],
            10,
            timestamp,
            Some(child.hash()),
        )
        .unwrap();
        permissive_manager
            .issue_authority(grandchild.clone())
            .unwrap();
        strict_manager.issue_authority(parent).unwrap();

        let action_ran = AtomicBool::new(false);
        let gate = ExecutionGate::new(|_| true);
        let result = gate.execute_with_authority(
            &grandchild,
            &|| {
                action_ran.store(true, Ordering::SeqCst);
                Ok("must not run".to_string())
            },
            "late_policy_read",
            "read",
        );

        assert!(matches!(
            result,
            Err(ExecutionGateError::InvalidAuthority(_))
        ));
        assert!(!action_ran.load(Ordering::SeqCst));
        assert!(!gate.is_authority_consumed(&grandchild).unwrap());
    }
}
