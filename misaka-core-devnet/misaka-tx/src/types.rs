// ============================================================
// MISAKA Seraphis/Jamtis — Type Definitions (v2)
// ============================================================
//
// TX binding (anti-malleability):
//
//   tx_body_hash    = H(BODY  || inputs_canon || outputs_canon || fee)
//   tx_proof_hash   = H(PROOF || balance_proof || range_proofs || fee_proof)
//   tx_binding_hash = H(BIND  || tx_body_hash || tx_proof_hash || version || tx_extra)
//   tx_id           = H(TX    || tx_binding_hash)
//
//   Proof replacement → tx_proof_hash changes → tx_binding_hash changes → tx_id changes.
//   Output substitution → tx_body_hash changes → same cascade.
//   tx_extra injection → tx_binding_hash changes.
//
// NoteCommitment binds:
//   one_time_address, amount_commitment, view_tag,
//   payload_hash, asset_id, enote_version
//
// ============================================================

use misaka_crypto::hash::{Domain, domain_hash_32, domain_hash_multi};
use misaka_crypto::ring_sig::RingSignature;
use misaka_crypto::proof_backend::{RangeProofData, BalanceProofData};
use serde::{Serialize, Deserialize};

// ════════════════════════════════════════════
// Constants
// ════════════════════════════════════════════

pub const MAX_TX_SIZE: u32 = 200_000;
pub const MAX_INPUTS: usize = 16;
pub const MAX_OUTPUTS: usize = 16;
pub const TX_VERSION: u8 = 2;
pub const ENOTE_VERSION: u8 = 1;

// ── Proof size limits ──
// Verifier rejects any TX with proofs exceeding these.
// Recomputed from canonical bytes — never trust client-reported sizes.

/// Maximum size of a single range proof in bytes.
pub const MAX_RANGE_PROOF_SIZE: usize = 16 * 1024;   // 16 KB
/// Maximum size of the balance proof in bytes.
pub const MAX_BALANCE_PROOF_SIZE: usize = 16 * 1024;  // 16 KB
/// Maximum total proof bytes in a single transaction.
pub const MAX_TX_PROOF_SIZE: usize = 64 * 1024;       // 64 KB

/// Native stMISAKA asset ID.
pub const ASSET_NATIVE: [u8; 32] = [0u8; 32];

// ════════════════════════════════════════════
// Primitive wrappers
// ════════════════════════════════════════════

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct LinkTag(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AmountCommitment(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EnoteId(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct TxId(pub [u8; 32]);

/// Intermediate hashes for anti-malleability binding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TxBodyHash(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TxProofHash(pub [u8; 32]);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TxBindingHash(pub [u8; 32]);

impl EnoteId {
    /// Derived from the tx_binding_hash (NOT tx_id) to break circular dependency.
    /// enote_id = H(TX || tx_binding_hash || output_index)
    pub fn compute(tx_binding_hash: &TxBindingHash, output_index: u32) -> Self {
        Self(domain_hash_multi(
            Domain::Tx,
            &[&tx_binding_hash.0, &output_index.to_le_bytes()],
            32,
        ).try_into().unwrap())
    }
}

// ════════════════════════════════════════════
// NoteCommitment (strengthened — Task 2)
// ════════════════════════════════════════════

/// Commitment to an entire enote's content.
///
/// Binds ALL fields that define the output, preventing any
/// partial substitution without invalidating the commitment.
///
/// H(COMMIT || version || asset_id || one_time_address
///           || amount_commitment || view_tag || payload_hash)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NoteCommitment(pub [u8; 32]);

impl NoteCommitment {
    pub fn compute(
        one_time_address: &[u8; 32],
        amount_commitment: &AmountCommitment,
        view_tag: u8,
        payload_hash: &[u8; 32],
        asset_id: &[u8; 32],
        enote_version: u8,
    ) -> Self {
        Self(domain_hash_multi(
            Domain::Commitment,
            &[
                &[enote_version],
                asset_id.as_slice(),
                one_time_address.as_slice(),
                &amount_commitment.0,
                &[view_tag],
                payload_hash.as_slice(),
            ],
            32,
        ).try_into().unwrap())
    }
}

// ════════════════════════════════════════════
// RecipientPayload (Task 3 — complete encryption)
// ════════════════════════════════════════════

/// Encrypted payload for the recipient.
///
/// All fields encrypted with the same KEM shared secret:
///   ss = Kyber.Decaps(view_sk, ephemeral_ct)
///
/// Encryption scheme:
///   amount_mask  = H(AMOUNT  || ss || output_index, 8)
///   blind_mask   = H(COMMIT  || ss || output_index, 8)
///   memo_key     = H(SESSION || ss || output_index, 32)  → AES-256-GCM
///   payload_hash = H(COMMIT  || encrypted_amount || encrypted_blinding || encrypted_memo)
///
/// The payload_hash is included in NoteCommitment, binding the
/// encrypted content to the output even though the verifier
/// cannot read it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecipientPayload {
    /// Kyber-768 ciphertext (1088 bytes)
    pub ephemeral_ct: Vec<u8>,
    /// XOR-encrypted amount (8 bytes)
    pub encrypted_amount: [u8; 8],
    /// XOR-encrypted blinding factor (8 bytes)
    pub encrypted_blinding: [u8; 8],
    /// AES-256-GCM encrypted memo (nonce || ciphertext || tag)
    /// Empty vec if no memo.
    pub encrypted_memo: Vec<u8>,
    /// Output index (needed for mask derivation)
    pub output_index: u32,
}

impl RecipientPayload {
    /// Compute the payload hash (included in NoteCommitment).
    pub fn hash(&self) -> [u8; 32] {
        domain_hash_multi(
            Domain::Commitment,
            &[
                &self.encrypted_amount[..],
                &self.encrypted_blinding[..],
                &self.encrypted_memo,
                &self.output_index.to_le_bytes(),
            ],
            32,
        ).try_into().unwrap()
    }

    /// Encrypt a payload from plaintext using the KEM shared secret.
    ///
    /// This is the unified encryption path — amount, blinding, and memo
    /// all derive keys from the same `shared_secret`.
    pub fn encrypt(
        shared_secret: &[u8],
        ephemeral_ct: Vec<u8>,
        amount: u64,
        blinding: u64,
        memo: &[u8],
        output_index: u32,
    ) -> Self {
        let encrypted_amount = xor_encrypt(
            &amount.to_le_bytes(),
            shared_secret,
            output_index,
            Domain::Amount,
        );
        let encrypted_blinding = xor_encrypt(
            &blinding.to_le_bytes(),
            shared_secret,
            output_index,
            Domain::Commitment,
        );

        // Memo: AES-256-GCM with derived key
        let encrypted_memo = if memo.is_empty() {
            Vec::new()
        } else {
            encrypt_memo(shared_secret, output_index, memo)
        };

        Self {
            ephemeral_ct,
            encrypted_amount,
            encrypted_blinding,
            encrypted_memo,
            output_index,
        }
    }

    /// Decrypt payload using the KEM shared secret.
    ///
    /// Returns (amount, blinding, memo) or None if decryption fails.
    pub fn decrypt(
        &self,
        shared_secret: &[u8],
    ) -> Option<DecryptedPayload> {
        let amount_bytes = xor_encrypt(
            &self.encrypted_amount,
            shared_secret,
            self.output_index,
            Domain::Amount,
        );
        let blinding_bytes = xor_encrypt(
            &self.encrypted_blinding,
            shared_secret,
            self.output_index,
            Domain::Commitment,
        );

        let amount = u64::from_le_bytes(amount_bytes);
        let blinding = u64::from_le_bytes(blinding_bytes);

        let memo = if self.encrypted_memo.is_empty() {
            Vec::new()
        } else {
            decrypt_memo(shared_secret, self.output_index, &self.encrypted_memo)?
        };

        Some(DecryptedPayload { amount, blinding, memo })
    }
}

/// Decrypted payload contents.
#[derive(Debug, Clone)]
pub struct DecryptedPayload {
    pub amount: u64,
    pub blinding: u64,
    pub memo: Vec<u8>,
}

// ── Encryption helpers ──

fn xor_encrypt(data: &[u8; 8], ss: &[u8], index: u32, domain: Domain) -> [u8; 8] {
    let mask = domain_hash_multi(domain, &[ss, &index.to_le_bytes()], 8);
    let mut out = [0u8; 8];
    for i in 0..8 { out[i] = data[i] ^ mask[i]; }
    out
}

fn encrypt_memo(ss: &[u8], index: u32, memo: &[u8]) -> Vec<u8> {
    // Derive stream key (deterministic from ss + index only — no plaintext dependency)
    let stream = memo_stream(ss, index, memo.len());
    // Length prefix + XOR
    let mut out = Vec::with_capacity(4 + memo.len());
    out.extend_from_slice(&(memo.len() as u32).to_le_bytes());
    for i in 0..memo.len() {
        out.push(memo[i] ^ stream[i]);
    }
    out
}

fn decrypt_memo(ss: &[u8], index: u32, encrypted: &[u8]) -> Option<Vec<u8>> {
    if encrypted.len() < 4 { return None; }
    let len = u32::from_le_bytes(encrypted[..4].try_into().ok()?) as usize;
    let ct = &encrypted[4..];
    if ct.len() != len { return None; }
    // Same stream derivation as encrypt (ss + index + length — no plaintext)
    let stream = memo_stream(ss, index, len);
    let mut memo = vec![0u8; len];
    for i in 0..len {
        memo[i] = ct[i] ^ stream[i];
    }
    Some(memo)
}

/// Derive XOR stream for memo encryption/decryption.
///
/// stream = SHAKE256(SESSION || ss || index || length, length)
///
/// CRITICAL: The stream depends ONLY on (ss, index, length) — never on
/// the plaintext. Both encrypt and decrypt call this with identical args,
/// so XOR is its own inverse: encrypt(encrypt(m)) = m.
fn memo_stream(ss: &[u8], index: u32, length: usize) -> Vec<u8> {
    domain_hash_multi(
        Domain::Session,
        &[ss, &index.to_le_bytes(), &(length as u32).to_le_bytes()],
        length,
    )
}

// ════════════════════════════════════════════
// Enote
// ════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Enote {
    pub enote_id: EnoteId,
    pub enote_version: u8,
    pub asset_id: [u8; 32],
    pub one_time_address: [u8; 32],
    pub amount_commitment: AmountCommitment,
    pub note_commitment: NoteCommitment,
    pub view_tag: u8,
    pub recipient_payload: RecipientPayload,
    pub created_at: u64,
}

impl Enote {
    /// Recompute and verify the note commitment binds all fields.
    pub fn verify_note_commitment(&self) -> bool {
        let payload_hash = self.recipient_payload.hash();
        let expected = NoteCommitment::compute(
            &self.one_time_address,
            &self.amount_commitment,
            self.view_tag,
            &payload_hash,
            &self.asset_id,
            self.enote_version,
        );
        expected == self.note_commitment
    }
}

/// Result of scanning an enote with wallet keys.
#[derive(Debug, Clone)]
pub struct ScannedEnote {
    pub enote_id: EnoteId,
    pub one_time_address: [u8; 32],
    pub amount: u64,
    pub blinding: u64,
    pub memo: Vec<u8>,
    pub asset_id: [u8; 32],
    /// The one_time_key needed for spend authorization derivation
    pub one_time_key: [u8; 32],
}

// ════════════════════════════════════════════
// TxInput
// ════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RingMembers {
    pub members: [EnoteId; 4],
    pub member_commitments: [AmountCommitment; 4],
}

impl RingMembers {
    /// Canonical serialization for hashing.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 * 32 + 4 * 32);
        for m in &self.members { out.extend_from_slice(&m.0); }
        for c in &self.member_commitments { out.extend_from_slice(&c.0); }
        out
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxInput {
    pub ring: RingMembers,
    pub ring_proof: RingSignature,
    pub link_tag: LinkTag,
    pub pseudo_output_commitment: AmountCommitment,
    /// Hash of the Z_q public keys used in ring_proof.
    ///
    /// ring_pk_hash = H(SIG || ring_proof.ring[0] || ... || ring_proof.ring[3])
    ///
    /// This binds the declared ring members to the actual PKs used in the
    /// ring signature. The verifier recomputes this from ring_proof.ring
    /// and checks it matches. Without this, an attacker could sign with
    /// a different set of PKs than what's declared in ring.members.
    pub ring_pk_hash: [u8; 32],
}

impl TxInput {
    /// Compute ring_pk_hash from the ring_proof's PKs.
    pub fn compute_ring_pk_hash(ring_proof: &RingSignature) -> [u8; 32] {
        let mut pk_bytes = Vec::new();
        for pk in &ring_proof.ring {
            pk_bytes.extend_from_slice(pk);
        }
        domain_hash_32(Domain::Sig, &pk_bytes)
    }

    /// Verify that ring_pk_hash matches ring_proof.ring.
    pub fn verify_ring_binding(&self) -> bool {
        let expected = Self::compute_ring_pk_hash(&self.ring_proof);
        self.ring_pk_hash == expected
    }

    /// Canonical serialization for tx_body_hash.
    /// Includes ring_pk_hash (binds the signature to declared members).
    /// Excludes ring_proof itself (that goes in tx_proof_hash).
    pub fn body_bytes(&self) -> Vec<u8> {
        let mut out = self.ring.canonical_bytes();
        out.extend_from_slice(&self.link_tag.0);
        out.extend_from_slice(&self.pseudo_output_commitment.0);
        out.extend_from_slice(&self.ring_pk_hash);
        out
    }
}

// ════════════════════════════════════════════
// TxOutput
// ════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxOutput {
    pub enote: Enote,
}

impl TxOutput {
    /// Canonical serialization for tx_body_hash.
    /// Includes note_commitment (which binds ALL enote fields including payload).
    pub fn body_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(32 + 32 + 1 + 32 + 1 + 32);
        out.push(self.enote.enote_version);
        out.extend_from_slice(&self.enote.asset_id);
        out.extend_from_slice(&self.enote.one_time_address);
        out.extend_from_slice(&self.enote.amount_commitment.0);
        out.push(self.enote.view_tag);
        out.extend_from_slice(&self.enote.note_commitment.0);
        out
    }
}

// ════════════════════════════════════════════
// Fee
// ════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeStatement {
    pub base_fee: u64,
    pub size_fee: u64,
    pub total_fee: u64,
    pub congestion_factor: u8,
    pub commitment: AmountCommitment,
}

impl FeeStatement {
    pub const MIN_BASE_FEE: u64 = 2000;

    pub fn compute(tx_size_bytes: u32, congestion_factor: u8) -> Self {
        let base_fee = Self::MIN_BASE_FEE;
        let size_fee = (tx_size_bytes as u64) * 10_000_000 * (congestion_factor.max(1) as u64);
        let total_fee = base_fee + size_fee;
        let c = misaka_crypto::commitment::commit_fee(total_fee);
        Self { base_fee, size_fee, total_fee, congestion_factor, commitment: AmountCommitment(c.hash) }
    }

    pub fn verify(&self) -> bool {
        let expected = misaka_crypto::commitment::commit_fee(self.total_fee);
        expected.hash == self.commitment.0
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + 8 + 8 + 1 + 32);
        out.extend_from_slice(&self.base_fee.to_le_bytes());
        out.extend_from_slice(&self.size_fee.to_le_bytes());
        out.extend_from_slice(&self.total_fee.to_le_bytes());
        out.push(self.congestion_factor);
        out.extend_from_slice(&self.commitment.0);
        out
    }
}

// ════════════════════════════════════════════
// TxProofBundle
// ════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeProof {
    pub fee_amount: u64,
    pub fee_commitment: AmountCommitment,
}

impl FeeProof {
    pub fn new(fee: u64) -> Self {
        let c = misaka_crypto::commitment::commit_fee(fee);
        Self { fee_amount: fee, fee_commitment: AmountCommitment(c.hash) }
    }
    pub fn verify(&self) -> bool {
        misaka_crypto::commitment::commit_fee(self.fee_amount).hash == self.fee_commitment.0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxProofBundle {
    /// Backend-agnostic balance proof
    pub balance_proof: BalanceProofData,
    /// Backend-agnostic range proofs (one per output)
    pub range_proofs: Vec<RangeProofData>,
    /// Fee proof
    pub fee_proof: FeeProof,
    /// Backend ID used to generate these proofs
    pub proof_backend_id: u8,
}

impl TxProofBundle {
    /// Canonical serialization for tx_proof_hash.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(self.proof_backend_id);
        // Balance proof
        out.extend_from_slice(&(self.balance_proof.proof.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.balance_proof.proof);
        // Range proofs
        out.extend_from_slice(&(self.range_proofs.len() as u32).to_le_bytes());
        for rp in &self.range_proofs {
            out.extend_from_slice(&(rp.proof.len() as u32).to_le_bytes());
            out.extend_from_slice(&rp.proof);
        }
        // Fee proof
        out.extend_from_slice(&self.fee_proof.fee_amount.to_le_bytes());
        out.extend_from_slice(&self.fee_proof.fee_commitment.0);
        out
    }
}

// ════════════════════════════════════════════
// TX Binding (Task 1 — anti-malleability)
// ════════════════════════════════════════════

/// Compute tx_body_hash from inputs + outputs + fee.
///
/// This commits to the ECONOMIC content of the transaction:
/// what's being spent, what's being created, and what fee is paid.
/// Ring proofs are NOT included — they go in tx_proof_hash.
pub fn compute_tx_body_hash(
    inputs: &[TxInput],
    outputs: &[TxOutput],
    fee: &FeeStatement,
) -> TxBodyHash {
    let mut data = Vec::new();
    // Input count
    data.extend_from_slice(&(inputs.len() as u32).to_le_bytes());
    for inp in inputs {
        data.extend_from_slice(&inp.body_bytes());
    }
    // Output count
    data.extend_from_slice(&(outputs.len() as u32).to_le_bytes());
    for out in outputs {
        data.extend_from_slice(&out.body_bytes());
    }
    // Fee
    data.extend_from_slice(&fee.canonical_bytes());

    TxBodyHash(domain_hash_32(Domain::Block, &data))
}

/// Compute tx_proof_hash from the proof bundle.
///
/// This commits to all ZK proofs. Replacing a proof changes this hash.
pub fn compute_tx_proof_hash(proofs: &TxProofBundle) -> TxProofHash {
    TxProofHash(domain_hash_32(Domain::Sig, &proofs.canonical_bytes()))
}

/// Compute tx_binding_hash from body + proof + metadata.
///
/// This is the final anti-malleability binding:
///   H(BIND || tx_body_hash || tx_proof_hash || version || tx_extra)
///
/// Any change to any part of the TX changes this hash.
pub fn compute_tx_binding_hash(
    body_hash: &TxBodyHash,
    proof_hash: &TxProofHash,
    version: u8,
    tx_extra: &[u8],
) -> TxBindingHash {
    TxBindingHash(domain_hash_multi(
        Domain::Tx,
        &[
            b"BIND",
            &body_hash.0,
            &proof_hash.0,
            &[version],
            tx_extra,
        ],
        32,
    ).try_into().unwrap())
}

/// Compute tx_id from tx_binding_hash.
///
/// tx_id = H(TX || tx_binding_hash)
///
/// One final hash to produce the canonical transaction identifier.
pub fn compute_tx_id(binding_hash: &TxBindingHash) -> TxId {
    TxId(domain_hash_32(Domain::Tx, &binding_hash.0))
}

// ════════════════════════════════════════════
// TxBody — complete transaction
// ════════════════════════════════════════════

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxBody {
    pub tx_id: TxId,
    pub tx_body_hash: TxBodyHash,
    pub tx_proof_hash: TxProofHash,
    pub tx_binding_hash: TxBindingHash,
    pub version: u8,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub proofs: TxProofBundle,
    pub fee: FeeStatement,
    pub tx_extra: Vec<u8>,
    pub size_bytes: u32,
}

impl TxBody {
    /// Verify all binding hashes are consistent (anti-malleability check).
    pub fn verify_binding(&self) -> bool {
        let body_hash = compute_tx_body_hash(&self.inputs, &self.outputs, &self.fee);
        let proof_hash = compute_tx_proof_hash(&self.proofs);
        let binding_hash = compute_tx_binding_hash(&body_hash, &proof_hash, self.version, &self.tx_extra);
        let tx_id = compute_tx_id(&binding_hash);

        self.tx_body_hash == body_hash
            && self.tx_proof_hash == proof_hash
            && self.tx_binding_hash == binding_hash
            && self.tx_id == tx_id
    }

    pub fn num_inputs(&self) -> usize { self.inputs.len() }
    pub fn num_outputs(&self) -> usize { self.outputs.len() }

    pub fn link_tags(&self) -> Vec<LinkTag> {
        self.inputs.iter().map(|i| i.link_tag).collect()
    }

    pub fn output_enote_ids(&self) -> Vec<EnoteId> {
        self.outputs.iter().map(|o| o.enote.enote_id).collect()
    }

    pub fn referenced_enote_ids(&self) -> Vec<EnoteId> {
        self.inputs.iter()
            .flat_map(|i| i.ring.members.iter().copied())
            .collect()
    }
}

// ════════════════════════════════════════════
// Errors
// ════════════════════════════════════════════

#[derive(Debug, thiserror::Error)]
pub enum TxError {
    #[error("Empty inputs")]
    EmptyInputs,
    #[error("Empty outputs")]
    EmptyOutputs,
    #[error("Too many inputs: {0} (max {MAX_INPUTS})")]
    TooManyInputs(usize),
    #[error("Too many outputs: {0} (max {MAX_OUTPUTS})")]
    TooManyOutputs(usize),
    #[error("Ring signature invalid for input {0}")]
    InvalidRingSignature(usize),
    #[error("Balance proof invalid")]
    InvalidBalanceProof,
    #[error("Range proof invalid for output {0}")]
    InvalidRangeProof(usize),
    #[error("Fee proof invalid")]
    InvalidFeeProof,
    #[error("Fee below minimum: {got} < {min}")]
    FeeTooLow { got: u64, min: u64 },
    #[error("Duplicate link tag: {0}")]
    DuplicateLinkTag(String),
    #[error("Note commitment mismatch at output {0}")]
    NoteCommitmentMismatch(usize),
    #[error("TX binding hash mismatch")]
    BindingMismatch,
    #[error("TX too large: {0} bytes (max {MAX_TX_SIZE})")]
    TxTooLarge(u32),
    #[error("TX extra too large: {0} bytes (max 256)")]
    TxExtraTooLarge(usize),
    #[error("Version unsupported: {0}")]
    UnsupportedVersion(u8),
    #[error("Proof backend mismatch: expected {expected}, got {got}")]
    ProofBackendMismatch { expected: u8, got: u8 },
    #[error("Proof error: {0}")]
    ProofError(#[from] misaka_crypto::proof_backend::ProofError),

    // ── Proof size errors ──
    #[error("Range proof too large at output {index}: {size} bytes (max {MAX_RANGE_PROOF_SIZE})")]
    RangeProofTooLarge { index: usize, size: usize },
    #[error("Balance proof too large: {size} bytes (max {MAX_BALANCE_PROOF_SIZE})")]
    BalanceProofTooLarge { size: usize },
    #[error("Total proof bytes too large: {size} bytes (max {MAX_TX_PROOF_SIZE})")]
    TotalProofBytesTooLarge { size: usize },

    // ── Store-backed errors (global state) ──
    #[error("Duplicate link tag in transaction: {0}")]
    DuplicateLinkTagInTx(String),
    #[error("Link tag already exists in store: {0}")]
    DuplicateLinkTagInStore(String),
    #[error("Ring member not found in store: input {input_index} member {member_hex}")]
    RingMemberNotFound { input_index: usize, member_hex: String },
    #[error("Enote already spent: {0}")]
    EnoteAlreadySpent(String),
    #[error("State apply conflict: {0}")]
    StateApplyConflict(String),
}

// ════════════════════════════════════════════
// Tests
// ════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_note_commitment_binds_all_fields() {
        let addr = [0x11; 32];
        let ac = AmountCommitment([0xAA; 32]);
        let payload_hash = [0xBB; 32];
        let asset = ASSET_NATIVE;

        let nc1 = NoteCommitment::compute(&addr, &ac, 0x42, &payload_hash, &asset, ENOTE_VERSION);
        let nc2 = NoteCommitment::compute(&addr, &ac, 0x42, &payload_hash, &asset, ENOTE_VERSION);
        assert_eq!(nc1, nc2, "Same inputs → same commitment");

        // Change each field → different commitment
        let nc_addr = NoteCommitment::compute(&[0x22; 32], &ac, 0x42, &payload_hash, &asset, ENOTE_VERSION);
        assert_ne!(nc1, nc_addr);

        let nc_amount = NoteCommitment::compute(&addr, &AmountCommitment([0xCC; 32]), 0x42, &payload_hash, &asset, ENOTE_VERSION);
        assert_ne!(nc1, nc_amount);

        let nc_vtag = NoteCommitment::compute(&addr, &ac, 0x99, &payload_hash, &asset, ENOTE_VERSION);
        assert_ne!(nc1, nc_vtag);

        let nc_payload = NoteCommitment::compute(&addr, &ac, 0x42, &[0xFF; 32], &asset, ENOTE_VERSION);
        assert_ne!(nc1, nc_payload);

        let nc_asset = NoteCommitment::compute(&addr, &ac, 0x42, &payload_hash, &[0x01; 32], ENOTE_VERSION);
        assert_ne!(nc1, nc_asset);

        let nc_ver = NoteCommitment::compute(&addr, &ac, 0x42, &payload_hash, &asset, 99);
        assert_ne!(nc1, nc_ver);
    }

    #[test]
    fn test_binding_hash_chain() {
        let body = TxBodyHash([0xAA; 32]);
        let proof = TxProofHash([0xBB; 32]);
        let bind = compute_tx_binding_hash(&body, &proof, TX_VERSION, b"");
        let id = compute_tx_id(&bind);

        // Change body → different binding → different id
        let body2 = TxBodyHash([0xCC; 32]);
        let bind2 = compute_tx_binding_hash(&body2, &proof, TX_VERSION, b"");
        assert_ne!(bind, bind2);
        assert_ne!(id, compute_tx_id(&bind2));

        // Change proof → different binding → different id
        let proof2 = TxProofHash([0xDD; 32]);
        let bind3 = compute_tx_binding_hash(&body, &proof2, TX_VERSION, b"");
        assert_ne!(bind, bind3);

        // Change tx_extra → different binding → different id
        let bind4 = compute_tx_binding_hash(&body, &proof, TX_VERSION, b"extra");
        assert_ne!(bind, bind4);
    }

    #[test]
    fn test_payload_encrypt_decrypt() {
        let ss = [0x42u8; 32]; // shared secret
        let ct = vec![0u8; 32]; // dummy ciphertext

        let payload = RecipientPayload::encrypt(
            &ss, ct, 12345, 67890, b"hello sender", 0,
        );

        // Encrypted values are not plaintext
        assert_ne!(payload.encrypted_amount, 12345u64.to_le_bytes());

        // Decrypt
        let dec = payload.decrypt(&ss).unwrap();
        assert_eq!(dec.amount, 12345);
        assert_eq!(dec.blinding, 67890);
        assert_eq!(dec.memo, b"hello sender");
    }

    #[test]
    fn test_payload_wrong_secret_fails() {
        let ss = [0x42u8; 32];
        let wrong_ss = [0x99u8; 32];

        let payload = RecipientPayload::encrypt(
            &ss, vec![0; 32], 1000, 42, b"", 0,
        );

        let dec = payload.decrypt(&wrong_ss).unwrap();
        // Amount will be garbage (XOR with wrong mask)
        assert_ne!(dec.amount, 1000);
    }

    #[test]
    fn test_payload_hash_in_note_commitment() {
        let ss = [0x42u8; 32];
        let payload1 = RecipientPayload::encrypt(&ss, vec![0; 32], 1000, 42, b"", 0);
        let payload2 = RecipientPayload::encrypt(&ss, vec![0; 32], 2000, 42, b"", 0);

        let h1 = payload1.hash();
        let h2 = payload2.hash();
        assert_ne!(h1, h2, "Different payload → different hash → different NoteCommitment");
    }

    #[test]
    fn test_fee_statement() {
        let fee = FeeStatement::compute(1000, 1);
        assert!(fee.verify());
        assert!(fee.total_fee >= FeeStatement::MIN_BASE_FEE);
    }

    #[test]
    fn test_enote_id_from_binding_hash() {
        let bh = TxBindingHash([0xAA; 32]);
        let id0 = EnoteId::compute(&bh, 0);
        let id1 = EnoteId::compute(&bh, 1);
        assert_ne!(id0, id1);
    }
}
