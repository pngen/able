# Authority-Bound Liability Engine (ABLE)

Deterministic enforcement of autonomous actions through consumable authority units, ensuring accountability and traceability.

## Overview

ABLE binds autonomous execution to consumable authority and priced accountability. It prevents unauthorized actions by construction through mandatory interception points, atomic execution, and immutable tracing.

## Architecture

<pre>
┌─────────────┐    ┌────────────────┐    ┌───────────────┐
│  Action     │───▶│ Execution      │───▶│ Authority     │
│  Request    │    │ Gate           │    │ Manager       │
└─────────────┘    │                │    │               │
                   │                │    │               │
                   │  ┌──────────┐  │    │  ┌─────────┐  │
                   │  │ Validate │  │    │  │ Issue   │  │
                   │  │ Authority│  │    │  │ AU      │  │
                   │  └──────────┘  │    │  └─────────┘  │
                   │                │    │               │
                   │  ┌─────────┐   │    │  ┌─────────┐  │
                   │  │ Consume │   │    │  │ Validate│  │
                   │  │ AU      │   │    │  │ AU      │  │
                   │  └─────────┘   │    │  └─────────┘  │
                   │                │    │               │
                   │  ┌─────────┐   │    │  ┌─────────┐  │
                   │  │ Execute │   │    │  │ Get     │  │
                   │  │ Action  │   │    │  │ AU      │  │
                   │  └─────────┘   │    │  └─────────┘  │
                   │                │    └───────────────┘
                   │  ┌─────────┐   │    
                   │  │ Emit    │   │    
                   │  │ Trace   │   │    
                   │  └─────────┘   │    
                   │                │    
                   │  ┌──────────┐  │    
                   │  │ Emit     │  │    
                   │  │ Liability│  │    
                   │  └──────────┘  │    
                   └────────────────┘    
</pre>

## Components

### AuthorityUnit (AU)  
A consumable, immutable unit encoding scope, delegation chain, and price. Once consumed, an AU cannot be reused, replayed, or partially applied.

### ExecutionGate (EG)  
The mandatory interception point for any autonomous action. Authority validation, execution, and trace emission occur as a single atomic operation. No bypass path exists.

### DecisionTrace (DT)  
An append-only record emitted at execution. Every action yields an immutable trace bound to the authority consumed.

### LiabilityRecord (LR)  
A deterministic mapping from a DecisionTrace to accountable parties and price. Establishes priced accountability for every authorized action.

### AuthorityManager  
Manages authority unit issuance and validation. Authority issuance and validation are explicit responsibilities within a scoped enforcement core.

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
./able
```

On Windows:
```bash
.\able.exe
```

## Design Principles
1. **Deterministic Enforcement** - Given identical inputs and authority state, outcomes are identical.
2. **Traceability** - Every action yields an immutable trace bound to the authority consumed.
3. **Atomicity** - Authority validation, execution, and trace emission occur as a single atomic operation.
4. **Exhaustion** - Consumed authority cannot be reused, replayed, or partially applied.
5. **No Bypass** - All autonomous actions must go through the Execution Gate.

## Requirements
- Rust 1.56+
- No external dependencies beyond standard library