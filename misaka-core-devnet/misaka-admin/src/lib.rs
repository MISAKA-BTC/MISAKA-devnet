// ============================================================
// MISAKA Network — Two-Layer Token Distribution
// ============================================================
//
// Accounting model:
//   total_supply is FIXED at genesis. No inflation.
//   treasury + Σbalances == total_supply (invariant, always holds)
//
//   Fee redistribution:
//     collect_fee()           sender balance → treasury  (supply unchanged)
//     distribute_block_fees() treasury → validators      (supply unchanged)
//
//   admin_mint: the ONLY supply-increasing operation.
//     - Protected by mint_enabled flag (default: true for testnet)
//     - freeze_mint() permanently disables — IRREVERSIBLE
//     - Every mint is logged with "TESTNET_MINT" tag
//     - Intended for testnet bootstrapping; freeze before public launch
//
// Admin auth:
//   Nonce-based replay prevention. Each admin op includes:
//     op_hash = H("MISAKA_TX" || op || details || nonce)
//   The nonce is a monotonic counter, incremented on every admin op.
//   Caller queries nonce(), computes hash, signs, submits.
//   No state-dependency (treasury, log.len) in the hash.
//
// ============================================================

use misaka_crypto::falcon;
use misaka_crypto::hash::{Domain, domain_hash_32};
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

pub const ONE_STMISAKA: u64 = 1_000_000_000;

const FEE_VALIDATOR_PCT: u64 = 80;
const FEE_ARCHIVE_PCT: u64 = 20;

#[derive(Debug, thiserror::Error)]
pub enum AdminError {
    #[error("Invalid admin signature")]
    InvalidSignature,
    #[error("Op hash mismatch: expected {expected}, got {got}")]
    OpHashMismatch { expected: String, got: String },
    #[error("Insufficient treasury: have {have}, need {need}")]
    InsufficientTreasury { have: u64, need: u64 },
    #[error("Insufficient balance: have {have}, need {need}")]
    InsufficientBalance { have: u64, need: u64 },
    #[error("Amount must be > 0")]
    ZeroAmount,
    #[error("Total ratio must be > 0")]
    ZeroRatio,
    #[error("Duplicate recipient")]
    DuplicateRecipient,
    #[error("Mint permanently disabled (freeze_mint was called)")]
    MintFrozen,
    #[error("Falcon error: {0}")]
    Falcon(#[from] falcon::FalconError),
}

/// A signed admin command.
///
/// The caller:
///   1. Reads `nonce = ledger.nonce()`
///   2. Computes `op_hash = Ledger::compute_op_hash(op, details, nonce)`
///   3. Signs: `signature = falcon_sign(admin_sk, &op_hash)`
///   4. Submits `AdminSig { op_hash, signature }`
///
/// The Ledger recomputes the hash from (op, details, self.nonce),
/// verifies it matches, verifies the Falcon signature, then
/// increments nonce. This means:
///   - No state-dependency in the hash (treasury, balances don't matter)
///   - Replay: same nonce can never be used twice
///   - UX: caller only needs to know the nonce, not the full state
pub struct AdminSig {
    pub op_hash: [u8; 32],
    pub signature: Vec<u8>,
}

#[derive(Clone)]
pub struct AdminConfig {
    pub fingerprint: [u8; 32],
    pub falcon_pk: Vec<u8>,
}

#[derive(Clone)]
pub struct ValidatorEntry {
    pub fingerprint: [u8; 32],
    pub stake: u64,
    pub is_archive: bool,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct LedgerOp {
    pub op_type: String,
    pub timestamp: u64,
    pub nonce: u64,
    pub details: String,
    pub signature: Vec<u8>,
}

// ── Ledger ──

pub struct Ledger {
    admin: AdminConfig,
    treasury: u64,
    balances: HashMap<[u8; 32], u64>,
    total_supply: u64,
    validators: Vec<ValidatorEntry>,
    total_fee_rewards: u64,
    total_admin_distributed: u64,
    /// Monotonic counter for admin operations (replay prevention).
    nonce: u64,
    /// When false, admin_mint permanently rejects.
    /// Set via freeze_mint() — irreversible.
    mint_enabled: bool,
    log: Vec<LedgerOp>,
}

impl Ledger {
    /// Create a new Ledger.
    ///
    /// `mint_enabled`: set `true` for testnet, `false` for mainnet genesis.
    /// Once frozen via `freeze_mint()`, minting can NEVER be re-enabled.
    pub fn new(admin: AdminConfig, initial_supply: u64, mint_enabled: bool) -> Self {
        let mut ledger = Self {
            admin,
            treasury: initial_supply,
            balances: HashMap::new(),
            total_supply: initial_supply,
            validators: Vec::new(),
            total_fee_rewards: 0,
            total_admin_distributed: 0,
            nonce: 0,
            mint_enabled,
            log: Vec::new(),
        };
        ledger.log.push(LedgerOp {
            op_type: "genesis".into(),
            timestamp: now_secs(),
            nonce: 0,
            details: format!("supply={} mint_enabled={}", initial_supply, mint_enabled),
            signature: Vec::new(),
        });
        ledger
    }

    // ── Queries ──

    pub fn treasury(&self) -> u64 { self.treasury }
    pub fn total_supply(&self) -> u64 { self.total_supply }
    pub fn total_fee_rewards(&self) -> u64 { self.total_fee_rewards }
    pub fn total_admin_distributed(&self) -> u64 { self.total_admin_distributed }
    pub fn balance_of(&self, addr: &[u8; 32]) -> u64 { *self.balances.get(addr).unwrap_or(&0) }
    pub fn all_balances(&self) -> &HashMap<[u8; 32], u64> { &self.balances }
    pub fn op_log(&self) -> &[LedgerOp] { &self.log }
    pub fn mint_enabled(&self) -> bool { self.mint_enabled }

    /// Current nonce. Callers use this to compute op_hash for signing.
    pub fn nonce(&self) -> u64 { self.nonce }

    /// Invariant: treasury + Σbalances == total_supply
    pub fn verify_invariant(&self) -> bool {
        let sum: u64 = self.balances.values().sum();
        self.treasury + sum == self.total_supply
    }

    /// Compute op_hash from (op, details, nonce).
    ///
    /// This is a pure function — no dependency on ledger state.
    /// Callers can compute it offline if they know the nonce.
    pub fn compute_op_hash(op: &str, details: &str, nonce: u64) -> [u8; 32] {
        let mut data = Vec::new();
        data.extend_from_slice(op.as_bytes());
        data.extend_from_slice(b"\x00");
        data.extend_from_slice(details.as_bytes());
        data.extend_from_slice(b"\x00");
        data.extend_from_slice(&nonce.to_le_bytes());
        domain_hash_32(Domain::Tx, &data)
    }

    /// Convenience: compute op_hash using the ledger's current nonce.
    pub fn op_hash(&self, op: &str, details: &str) -> [u8; 32] {
        Self::compute_op_hash(op, details, self.nonce)
    }

    // ── Validator Registration ──

    pub fn register_validator(&mut self, entry: ValidatorEntry) {
        self.validators.retain(|v| v.fingerprint != entry.fingerprint);
        self.validators.push(entry);
    }

    // ════════════════════════════════════════════
    // Mint freeze
    // ════════════════════════════════════════════

    /// Permanently disable admin_mint. IRREVERSIBLE.
    ///
    /// Call this before transitioning from private testnet to public testnet,
    /// or at mainnet genesis. Once frozen, the only way to enable minting
    /// is to redeploy the chain from a new genesis.
    pub fn freeze_mint(&mut self, sig: &AdminSig) -> Result<(), AdminError> {
        let details = "freeze_mint";
        let expected = Self::compute_op_hash("freeze_mint", details, self.nonce);
        self.verify_admin_sig(sig, &expected)?;

        self.mint_enabled = false;
        self.push_log("FREEZE_MINT", details, &sig.signature);
        self.nonce += 1;
        Ok(())
    }

    // ════════════════════════════════════════════
    // Layer 1: Fee Redistribution (自動)
    // ════════════════════════════════════════════

    /// Collect fee from sender into treasury. Supply unchanged.
    pub fn collect_fee(&mut self, sender: &[u8; 32], fee: u64) -> Result<(), AdminError> {
        if fee == 0 { return Ok(()); }
        let bal = self.balance_of(sender);
        if bal < fee {
            return Err(AdminError::InsufficientBalance { have: bal, need: fee });
        }
        *self.balances.get_mut(sender).unwrap() -= fee;
        self.treasury += fee;
        Ok(())
    }

    /// Redistribute collected fees. Supply unchanged.
    pub fn distribute_block_fees(
        &mut self,
        total_fees: u64,
        proposer_id: &[u8; 32],
    ) -> Result<Vec<([u8; 32], u64)>, AdminError> {
        if total_fees == 0 { return Ok(Vec::new()); }
        if self.treasury < total_fees {
            return Err(AdminError::InsufficientTreasury { have: self.treasury, need: total_fees });
        }

        let active_validators: Vec<&ValidatorEntry> = self.validators.iter()
            .filter(|v| !v.is_archive && v.stake > 0)
            .collect();
        let archive_nodes: Vec<&ValidatorEntry> = self.validators.iter()
            .filter(|v| v.is_archive)
            .collect();

        if active_validators.is_empty() {
            return Ok(Vec::new());
        }

        let validator_pool = total_fees * FEE_VALIDATOR_PCT / 100;
        let archive_pool = total_fees * FEE_ARCHIVE_PCT / 100;

        let mut distributions = Vec::new();
        let mut total_moved = 0u64;

        let total_stake: u64 = active_validators.iter().map(|v| v.stake).sum();
        if total_stake > 0 {
            let mut validator_distributed = 0u64;
            for (i, v) in active_validators.iter().enumerate() {
                let share = if i == active_validators.len() - 1 {
                    validator_pool - validator_distributed
                } else {
                    (validator_pool as u128 * v.stake as u128 / total_stake as u128) as u64
                };
                if share > 0 {
                    self.treasury -= share;
                    *self.balances.entry(v.fingerprint).or_insert(0) += share;
                    distributions.push((v.fingerprint, share));
                    validator_distributed += share;
                    total_moved += share;
                }
            }
        }

        if !archive_nodes.is_empty() {
            let per_archive = archive_pool / archive_nodes.len() as u64;
            for a in &archive_nodes {
                if per_archive > 0 {
                    self.treasury -= per_archive;
                    *self.balances.entry(a.fingerprint).or_insert(0) += per_archive;
                    distributions.push((a.fingerprint, per_archive));
                    total_moved += per_archive;
                }
            }
        }

        self.total_fee_rewards += total_moved;

        self.log.push(LedgerOp {
            op_type: "fee_reward".into(),
            timestamp: now_secs(),
            nonce: 0, // fee ops don't consume admin nonce
            details: format!(
                "fees={} moved={} proposer={}",
                total_fees, total_moved, hex::encode(proposer_id),
            ),
            signature: Vec::new(),
        });

        Ok(distributions)
    }

    // ════════════════════════════════════════════
    // Layer 2: Admin Operations (nonce-based)
    // ════════════════════════════════════════════

    /// Admin mint: increase total_supply and treasury.
    ///
    /// TESTNET ONLY. Permanently disabled after freeze_mint().
    /// Every execution is logged with op_type "TESTNET_MINT"
    /// so it is clearly visible in the ledger history.
    pub fn admin_mint(&mut self, amount: u64, sig: &AdminSig) -> Result<(), AdminError> {
        if !self.mint_enabled {
            return Err(AdminError::MintFrozen);
        }
        if amount == 0 { return Err(AdminError::ZeroAmount); }

        let details = format!("amount={}", amount);
        let expected = Self::compute_op_hash("mint", &details, self.nonce);
        self.verify_admin_sig(sig, &expected)?;

        self.treasury += amount;
        self.total_supply += amount;
        self.push_log("TESTNET_MINT", &format!("amount={} new_supply={} new_treasury={}", amount, self.total_supply, self.treasury), &sig.signature);
        self.nonce += 1;
        Ok(())
    }

    /// Admin distribute: treasury → recipient.
    pub fn admin_distribute(
        &mut self,
        recipient: &[u8; 32],
        amount: u64,
        sig: &AdminSig,
    ) -> Result<(), AdminError> {
        if amount == 0 { return Err(AdminError::ZeroAmount); }
        if self.treasury < amount {
            return Err(AdminError::InsufficientTreasury { have: self.treasury, need: amount });
        }
        let details = format!("to={} amount={}", hex::encode(recipient), amount);
        let expected = Self::compute_op_hash("distribute", &details, self.nonce);
        self.verify_admin_sig(sig, &expected)?;

        self.treasury -= amount;
        *self.balances.entry(*recipient).or_insert(0) += amount;
        self.total_admin_distributed += amount;
        self.push_log("admin_distribute", &details, &sig.signature);
        self.nonce += 1;
        Ok(())
    }

    /// Admin batch distribute by ratio.
    pub fn admin_distribute_by_ratio(
        &mut self,
        total_pool: u64,
        ratios: &[([u8; 32], u32)],
        sig: &AdminSig,
    ) -> Result<Vec<([u8; 32], u64)>, AdminError> {
        if total_pool == 0 { return Err(AdminError::ZeroAmount); }
        if self.treasury < total_pool {
            return Err(AdminError::InsufficientTreasury { have: self.treasury, need: total_pool });
        }

        let mut seen = std::collections::HashSet::new();
        for (addr, _) in ratios {
            if !seen.insert(*addr) { return Err(AdminError::DuplicateRecipient); }
        }

        let total_ratio: u64 = ratios.iter().map(|(_, r)| *r as u64).sum();
        if total_ratio == 0 { return Err(AdminError::ZeroRatio); }

        let mut distributions = Vec::new();
        let mut distributed = 0u64;
        for (i, (addr, ratio)) in ratios.iter().enumerate() {
            let amount = if i == ratios.len() - 1 {
                total_pool - distributed
            } else {
                (total_pool as u128 * *ratio as u128 / total_ratio as u128) as u64
            };
            distributions.push((*addr, amount));
            distributed += amount;
        }

        let plan_str = distributions.iter()
            .map(|(a, v)| format!("{}:{}", hex::encode(a), v))
            .collect::<Vec<_>>().join(",");
        let details = format!("pool={} plan={}", total_pool, plan_str);
        let expected = Self::compute_op_hash("ratio", &details, self.nonce);
        self.verify_admin_sig(sig, &expected)?;

        for (addr, amount) in &distributions {
            self.treasury -= amount;
            *self.balances.entry(*addr).or_insert(0) += amount;
        }
        self.total_admin_distributed += total_pool;
        self.push_log("admin_ratio", &format!("pool={} n={}", total_pool, distributions.len()), &sig.signature);
        self.nonce += 1;
        Ok(distributions)
    }

    /// Admin correction: move balance between accounts.
    pub fn admin_correction(
        &mut self,
        from: &[u8; 32],
        to: &[u8; 32],
        amount: u64,
        reason: &str,
        sig: &AdminSig,
    ) -> Result<(), AdminError> {
        if amount == 0 { return Err(AdminError::ZeroAmount); }
        let bal = self.balance_of(from);
        if bal < amount { return Err(AdminError::InsufficientBalance { have: bal, need: amount }); }

        let details = format!("from={} to={} amt={} r={}", hex::encode(from), hex::encode(to), amount, reason);
        let expected = Self::compute_op_hash("correction", &details, self.nonce);
        self.verify_admin_sig(sig, &expected)?;

        *self.balances.get_mut(from).unwrap() -= amount;
        *self.balances.entry(*to).or_insert(0) += amount;
        self.push_log("correction", &details, &sig.signature);
        self.nonce += 1;
        Ok(())
    }

    /// Admin clawback: return balance to treasury.
    pub fn admin_clawback(
        &mut self,
        from: &[u8; 32],
        amount: u64,
        reason: &str,
        sig: &AdminSig,
    ) -> Result<(), AdminError> {
        if amount == 0 { return Err(AdminError::ZeroAmount); }
        let bal = self.balance_of(from);
        if bal < amount { return Err(AdminError::InsufficientBalance { have: bal, need: amount }); }

        let details = format!("from={} amt={} r={}", hex::encode(from), amount, reason);
        let expected = Self::compute_op_hash("clawback", &details, self.nonce);
        self.verify_admin_sig(sig, &expected)?;

        *self.balances.get_mut(from).unwrap() -= amount;
        self.treasury += amount;
        self.push_log("clawback", &details, &sig.signature);
        self.nonce += 1;
        Ok(())
    }

    /// Admin subsidy: treasury → recipient.
    pub fn admin_subsidy(
        &mut self,
        recipient: &[u8; 32],
        amount: u64,
        reason: &str,
        sig: &AdminSig,
    ) -> Result<(), AdminError> {
        if amount == 0 { return Err(AdminError::ZeroAmount); }
        if self.treasury < amount {
            return Err(AdminError::InsufficientTreasury { have: self.treasury, need: amount });
        }

        let details = format!("to={} amt={} reason={}", hex::encode(recipient), amount, reason);
        let expected = Self::compute_op_hash("subsidy", &details, self.nonce);
        self.verify_admin_sig(sig, &expected)?;

        self.treasury -= amount;
        *self.balances.entry(*recipient).or_insert(0) += amount;
        self.total_admin_distributed += amount;
        self.push_log("admin_subsidy", &details, &sig.signature);
        self.nonce += 1;
        Ok(())
    }

    pub fn export_state(&self) -> serde_json::Value {
        let bals: HashMap<String, u64> = self.balances.iter().map(|(k, v)| (hex::encode(k), *v)).collect();
        serde_json::json!({
            "admin": hex::encode(self.admin.fingerprint),
            "treasury": self.treasury,
            "total_supply": self.total_supply,
            "total_fee_rewards": self.total_fee_rewards,
            "total_admin_distributed": self.total_admin_distributed,
            "nonce": self.nonce,
            "mint_enabled": self.mint_enabled,
            "accounts": bals.len(),
            "balances": bals,
            "validators": self.validators.len(),
            "ops": self.log.len(),
        })
    }

    // ── Internal ──

    fn verify_admin_sig(&self, sig: &AdminSig, expected_hash: &[u8; 32]) -> Result<(), AdminError> {
        let mut diff = 0u8;
        for (a, b) in sig.op_hash.iter().zip(expected_hash.iter()) {
            diff |= a ^ b;
        }
        if diff != 0 {
            return Err(AdminError::OpHashMismatch {
                expected: hex::encode(expected_hash),
                got: hex::encode(sig.op_hash),
            });
        }
        let valid = falcon::falcon_verify(&self.admin.falcon_pk, expected_hash, &sig.signature)?;
        if !valid { return Err(AdminError::InvalidSignature); }
        Ok(())
    }

    fn push_log(&mut self, op: &str, details: &str, signature: &[u8]) {
        self.log.push(LedgerOp {
            op_type: op.into(),
            timestamp: now_secs(),
            nonce: self.nonce,
            details: details.into(),
            signature: signature.to_vec(),
        });
    }
}

/// Sign an admin operation externally.
pub fn sign_admin_op(admin_sk: &[u8], op_hash: &[u8; 32]) -> Result<AdminSig, falcon::FalconError> {
    let signature = falcon::falcon_sign(admin_sk, op_hash)?;
    Ok(AdminSig { op_hash: *op_hash, signature })
}

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup() -> (Ledger, falcon::FalconKeyPair) {
        let kp = falcon::falcon_keygen().unwrap();
        let cfg = AdminConfig { fingerprint: kp.fingerprint, falcon_pk: kp.public_key.clone() };
        (Ledger::new(cfg, 10_000_000 * ONE_STMISAKA, true), kp) // mint_enabled=true for tests
    }

    fn admin_sign(ledger: &Ledger, kp: &falcon::FalconKeyPair, op: &str, details: &str) -> AdminSig {
        let hash = ledger.op_hash(op, details);
        sign_admin_op(&kp.secret_key, &hash).unwrap()
    }

    // ── Nonce-based replay prevention ──

    #[test]
    fn test_nonce_increments() {
        let (mut ledger, kp) = setup();
        assert_eq!(ledger.nonce(), 0);

        let alice = [0xAA; 32];
        let details = format!("to={} amount={}", hex::encode(alice), 100 * ONE_STMISAKA);
        let sig = admin_sign(&ledger, &kp, "distribute", &details);
        ledger.admin_distribute(&alice, 100 * ONE_STMISAKA, &sig).unwrap();
        assert_eq!(ledger.nonce(), 1);

        let details2 = format!("to={} amount={}", hex::encode(alice), 200 * ONE_STMISAKA);
        let sig2 = admin_sign(&ledger, &kp, "distribute", &details2);
        ledger.admin_distribute(&alice, 200 * ONE_STMISAKA, &sig2).unwrap();
        assert_eq!(ledger.nonce(), 2);
    }

    #[test]
    fn test_replay_rejected_nonce() {
        let (mut ledger, kp) = setup();
        let alice = [0xAA; 32];
        let amount = 100 * ONE_STMISAKA;
        let details = format!("to={} amount={}", hex::encode(alice), amount);
        let sig = admin_sign(&ledger, &kp, "distribute", &details);
        ledger.admin_distribute(&alice, amount, &sig).unwrap();

        // Same sig, but nonce is now 1 → hash mismatch
        let result = ledger.admin_distribute(&alice, amount, &sig);
        assert!(result.is_err());
    }

    #[test]
    fn test_offline_hash_computation() {
        let (ledger, _) = setup();
        let nonce = ledger.nonce();

        // Caller can compute offline
        let offline_hash = Ledger::compute_op_hash("distribute", "to=aa amount=100", nonce);
        let online_hash = ledger.op_hash("distribute", "to=aa amount=100");
        assert_eq!(offline_hash, online_hash);
    }

    // ── Mint freeze ──

    #[test]
    fn test_mint_works_when_enabled() {
        let (mut ledger, kp) = setup();
        assert!(ledger.mint_enabled());
        let sig = admin_sign(&ledger, &kp, "mint", "amount=1000000000");
        ledger.admin_mint(ONE_STMISAKA, &sig).unwrap();
        assert!(ledger.verify_invariant());
    }

    #[test]
    fn test_mint_frozen_permanently() {
        let (mut ledger, kp) = setup();

        // Freeze
        let sig = admin_sign(&ledger, &kp, "freeze_mint", "freeze_mint");
        ledger.freeze_mint(&sig).unwrap();
        assert!(!ledger.mint_enabled());

        // Mint now fails
        let sig2 = admin_sign(&ledger, &kp, "mint", "amount=1");
        let result = ledger.admin_mint(1, &sig2);
        assert!(matches!(result, Err(AdminError::MintFrozen)));
    }

    #[test]
    fn test_mint_log_tagged_testnet() {
        let (mut ledger, kp) = setup();
        let sig = admin_sign(&ledger, &kp, "mint", "amount=1000000000");
        ledger.admin_mint(ONE_STMISAKA, &sig).unwrap();

        let last_op = ledger.op_log().last().unwrap();
        assert_eq!(last_op.op_type, "TESTNET_MINT");
    }

    #[test]
    fn test_mainnet_genesis_no_mint() {
        let kp = falcon::falcon_keygen().unwrap();
        let cfg = AdminConfig { fingerprint: kp.fingerprint, falcon_pk: kp.public_key.clone() };
        let mut ledger = Ledger::new(cfg, 10_000_000 * ONE_STMISAKA, false); // mainnet mode

        let sig = admin_sign(&ledger, &kp, "mint", "amount=1");
        let result = ledger.admin_mint(1, &sig);
        assert!(matches!(result, Err(AdminError::MintFrozen)));
    }

    // ── Fee lifecycle ──

    #[test]
    fn test_fee_redistribution_no_supply_change() {
        let (mut ledger, kp) = setup();
        let sender = [0xEE; 32];
        let v1 = [0x01; 32]; let v2 = [0x02; 32]; let a1 = [0xA1; 32];

        let details = format!("to={} amount={}", hex::encode(sender), 10_000 * ONE_STMISAKA);
        let sig = admin_sign(&ledger, &kp, "distribute", &details);
        ledger.admin_distribute(&sender, 10_000 * ONE_STMISAKA, &sig).unwrap();

        let supply_before = ledger.total_supply();

        ledger.register_validator(ValidatorEntry { fingerprint: v1, stake: 70_000 * ONE_STMISAKA, is_archive: false });
        ledger.register_validator(ValidatorEntry { fingerprint: v2, stake: 30_000 * ONE_STMISAKA, is_archive: false });
        ledger.register_validator(ValidatorEntry { fingerprint: a1, stake: 0, is_archive: true });

        let fees = 1000 * ONE_STMISAKA;
        ledger.collect_fee(&sender, fees).unwrap();
        ledger.distribute_block_fees(fees, &v1).unwrap();

        assert_eq!(ledger.total_supply(), supply_before);
        assert!(ledger.verify_invariant());
    }

    #[test]
    fn test_wrong_signer_rejected() {
        let (mut ledger, _kp) = setup();
        let attacker = falcon::falcon_keygen().unwrap();
        let hash = ledger.op_hash("mint", "amount=1");
        let bad_sig = sign_admin_op(&attacker.secret_key, &hash).unwrap();
        assert!(ledger.admin_mint(1, &bad_sig).is_err());
    }
}
