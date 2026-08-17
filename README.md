# Authority-Bound Liability Engine (ABLE)

In-process enforcement of autonomous actions through consumable authority units, with integrity-verifiable accountability records.

## Overview

ABLE binds autonomous execution to consumable authority and priced accountability. Applications opt in by routing actions through an execution gate, supplying an authority validator, and separately supplying canonical trusted `action_scope` metadata.

## Architecture

<pre>
                   ┌───────────────┐
                   │ Authority     │
                   │ Manager       │
                   │  ┌─────────┐  │
                   │  │ Issue   │  │
                   │  │ AU      │  │
                   │  └─────────┘  │
                   │  ┌─────────┐  │
                   │  │ Validate│  │
                   │  │ AU      │  │
                   │  └─────────┘  │
                   │  ┌─────────┐  │
                   │  │ Get     │  │
                   │  │ AU      │  │
                   │  └─────────┘  │
                   └───────┬───────┘
                           │ validates
┌─────────────┐    ┌───────▼─────────┐    ┌───────────────┐
│  Action     │───▶│ Execution       │───▶│ Decision      │
│  Request    │    │ Gate            │    │ Trace         │
│  + AU       │    │                 │    ├───────────────┤
└─────────────┘    │  Consume AU     │───▶│ Liability     │
                   │  Execute Action │    │ Record        │
                   └─────────────────┘    └───────────────┘
</pre>

## Components

### AuthorityUnit (AU)  
A validated unit encoding scope, delegation chain, and price. Once execution starts, the exact AU commitment cannot be reused by another gate in the same process, including after an executor error or panic. Exhaustion and evidence share one process-wide state. Hosts that require exhaustion across restarts must persist consumed commitments and evidence outside this in-memory library.

### ExecutionGate (EG)  
The interception point for integrated autonomous actions. Invariant checks, caller-supplied validation, scope checks, authority reservation, and a `started` trace occur before the executor is invoked. Arbitrary external callback effects cannot be rolled back atomically; integrations needing exactly-once effects must use transactional or idempotent executors.

### DecisionTrace (DT)  
A hash-chained record retained in process-wide enforcement state. Invoked actions receive `started` and terminal success, failure, or panic records bound to the authority commitment and claimed action scope. Terminal records use observed completion time when the clock remains trustworthy and the last trusted logical time if it fails after invocation. Returned copies expose public fields for compatibility. `verify_integrity` checks only a record's self-consistency; `contains_audit_record` and `verify_audit_chain` establish membership in the retained journal.

### LiabilityRecord (LR)  
A deterministic mapping from a terminal DecisionTrace to the authority delegation chain, actual claimed action scope, and price.

### AuthorityManager  
Manages authority unit issuance and validation. Manager-issued age policies are bound to the full authority commitment; the strictest registered ancestor policy is rechecked when authority is delegated or reserved.

## Build

```bash
cargo build --release
```

## Test

```bash
cargo test
```

## Run

```bash
cargo build --release
./target/release/able # Linux/macOS
.\target\release\able.exe # Windows
```

The packaged binary is the supervised AIGOS layer process: it emits the canonical startup line and remains alive until the supervisor terminates it.

## Runtime integration

ABLE enforces in-process through `ExecutionGate` in host applications. The standalone layer binary provides the AIGOSD-supervised runtime presence; enforcement state remains in-process.

## Design Principles

1. **Deterministic Commitments** - Authority, trace, and liability commitments use unambiguous SHA-256 encodings.
2. **Traceability** - Integrated execution attempts are retained in a verifiable process-wide hash chain.
3. **Fail-Closed Reservation** - Validation and authority reservation precede invocation; ambiguous failures never restore authority.
4. **In-Process Exhaustion** - An invoked authority commitment cannot be replayed through another gate in the same process.
5. **Explicit Boundary** - Applications must make the Execution Gate the exclusive path to privileged resources.

## Requirements

- Rust 1.71+
