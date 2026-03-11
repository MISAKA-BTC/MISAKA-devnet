// ============================================================
// MISAKA Network — Seraphis/Jamtis Transaction Model (v2)
// ============================================================
//
// modules:
//   types   — type definitions, constants, binding hash chain
//   builder — TX construction pipeline
//   verify  — stateless verification (legacy, kept for compatibility)
//   state   — TxStateStore trait + store-backed verify + atomic apply
//
// ============================================================

pub mod types;
pub mod builder;
pub mod verify;
pub mod state;

pub use types::*;
pub use builder::{build_transaction, estimate_tx_size, PlannedInput, PlannedOutput};
pub use verify::{verify_transaction, compute_actual_size, VerifyResult};
pub use state::{
    TxStateStore, StoredEnote, TxEffects,
    StoreVerifyResult, verify_with_store, extract_effects,
    apply_tx_effects, verify_and_apply,
};
