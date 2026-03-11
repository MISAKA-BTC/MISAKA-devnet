// ============================================================
// MISAKA Network — C ABI FFI for Node.js
// ============================================================
//
// Exported functions (C ABI):
//   misaka_falcon_keygen()
//   misaka_falcon_sign()
//   misaka_falcon_verify()
//   misaka_falcon_fingerprint()
//   misaka_kyber_keygen()
//   misaka_kyber_encaps()
//   misaka_kyber_decaps()
//   misaka_hybrid_keygen()
//   misaka_hybrid_sign()
//   misaka_hybrid_verify()
//
// Build:
//   cargo build --release
//   → target/release/libmisaka_ffi.so (Linux)
//   → target/release/libmisaka_ffi.dylib (macOS)
//
// Node.js usage:
//   const ffi = require('ffi-napi');
//   const lib = ffi.Library('./libmisaka_ffi', { ... });
//   // or: via WASM (wasm-pack build --target nodejs)
//
// ============================================================

use misaka_crypto::{falcon, kyber, dilithium, hybrid_sig};
use std::slice;

/// Return code: success
const OK: i32 = 0;
/// Return code: error
const ERR: i32 = -1;

// ── Falcon-512 ──

/// Generate a Falcon-512 keypair.
/// Writes public key to pk_out (897 bytes) and secret key to sk_out (1281 bytes).
#[no_mangle]
pub unsafe extern "C" fn misaka_falcon_keygen(
    pk_out: *mut u8,
    pk_len: usize,
    sk_out: *mut u8,
    sk_len: usize,
) -> i32 {
    if pk_out.is_null() || sk_out.is_null() {
        return ERR;
    }
    if pk_len < falcon::FALCON_PK_SIZE || sk_len < falcon::FALCON_SK_SIZE {
        return ERR;
    }

    match falcon::falcon_keygen() {
        Ok(kp) => {
            let pk_slice = slice::from_raw_parts_mut(pk_out, pk_len);
            let sk_slice = slice::from_raw_parts_mut(sk_out, sk_len);
            pk_slice[..kp.public_key.len()].copy_from_slice(&kp.public_key);
            sk_slice[..kp.secret_key.len()].copy_from_slice(&kp.secret_key);
            OK
        }
        Err(_) => ERR,
    }
}

/// Sign a message with Falcon-512.
/// Returns the signature length written to sig_out, or -1 on error.
#[no_mangle]
pub unsafe extern "C" fn misaka_falcon_sign(
    sk: *const u8,
    sk_len: usize,
    msg: *const u8,
    msg_len: usize,
    sig_out: *mut u8,
    sig_max_len: usize,
    sig_actual_len: *mut usize,
) -> i32 {
    if sk.is_null() || msg.is_null() || sig_out.is_null() || sig_actual_len.is_null() {
        return ERR;
    }

    let sk_slice = slice::from_raw_parts(sk, sk_len);
    let msg_slice = slice::from_raw_parts(msg, msg_len);

    match falcon::falcon_sign(sk_slice, msg_slice) {
        Ok(sig) => {
            if sig.len() > sig_max_len {
                return ERR;
            }
            let out_slice = slice::from_raw_parts_mut(sig_out, sig_max_len);
            out_slice[..sig.len()].copy_from_slice(&sig);
            *sig_actual_len = sig.len();
            OK
        }
        Err(_) => ERR,
    }
}

/// Verify a Falcon-512 signature. Returns 0 if valid, -1 if invalid.
#[no_mangle]
pub unsafe extern "C" fn misaka_falcon_verify(
    pk: *const u8,
    pk_len: usize,
    msg: *const u8,
    msg_len: usize,
    sig: *const u8,
    sig_len: usize,
) -> i32 {
    if pk.is_null() || msg.is_null() || sig.is_null() {
        return ERR;
    }

    let pk_slice = slice::from_raw_parts(pk, pk_len);
    let msg_slice = slice::from_raw_parts(msg, msg_len);
    let sig_slice = slice::from_raw_parts(sig, sig_len);

    match falcon::falcon_verify(pk_slice, msg_slice, sig_slice) {
        Ok(true) => OK,
        _ => ERR,
    }
}

/// Compute SHA3-256 fingerprint of a Falcon public key.
#[no_mangle]
pub unsafe extern "C" fn misaka_falcon_fingerprint(
    pk: *const u8,
    pk_len: usize,
    fp_out: *mut u8,
    fp_len: usize,
) -> i32 {
    if pk.is_null() || fp_out.is_null() || fp_len < 32 {
        return ERR;
    }
    let pk_slice = slice::from_raw_parts(pk, pk_len);
    let fp = falcon::falcon_fingerprint(pk_slice);
    let out = slice::from_raw_parts_mut(fp_out, fp_len);
    out[..32].copy_from_slice(&fp);
    OK
}

// ── Kyber-768 ──

/// Generate ML-KEM-768 keypair.
#[no_mangle]
pub unsafe extern "C" fn misaka_kyber_keygen(
    pk_out: *mut u8,
    pk_len: usize,
    sk_out: *mut u8,
    sk_len: usize,
) -> i32 {
    if pk_out.is_null() || sk_out.is_null() {
        return ERR;
    }
    if pk_len < kyber::KYBER_PK_SIZE || sk_len < kyber::KYBER_SK_SIZE {
        return ERR;
    }

    match kyber::kyber_keygen() {
        Ok(kp) => {
            let pk_slice = slice::from_raw_parts_mut(pk_out, pk_len);
            let sk_slice = slice::from_raw_parts_mut(sk_out, sk_len);
            pk_slice[..kp.public_key.len()].copy_from_slice(&kp.public_key);
            sk_slice[..kp.secret_key.len()].copy_from_slice(&kp.secret_key);
            OK
        }
        Err(_) => ERR,
    }
}

/// ML-KEM-768 encapsulate.
#[no_mangle]
pub unsafe extern "C" fn misaka_kyber_encaps(
    pk: *const u8,
    pk_len: usize,
    ct_out: *mut u8,
    ct_len: usize,
    ss_out: *mut u8,
    ss_len: usize,
) -> i32 {
    if pk.is_null() || ct_out.is_null() || ss_out.is_null() {
        return ERR;
    }
    if ct_len < kyber::KYBER_CT_SIZE || ss_len < kyber::KYBER_SS_SIZE {
        return ERR;
    }

    let pk_slice = slice::from_raw_parts(pk, pk_len);
    match kyber::kyber_encaps(pk_slice) {
        Ok((ct, ss)) => {
            let ct_out = slice::from_raw_parts_mut(ct_out, ct_len);
            let ss_out = slice::from_raw_parts_mut(ss_out, ss_len);
            ct_out[..ct.len()].copy_from_slice(&ct);
            ss_out[..ss.len()].copy_from_slice(&ss);
            OK
        }
        Err(_) => ERR,
    }
}

/// ML-KEM-768 decapsulate (with proper implicit rejection).
#[no_mangle]
pub unsafe extern "C" fn misaka_kyber_decaps(
    sk: *const u8,
    sk_len: usize,
    ct: *const u8,
    ct_len: usize,
    ss_out: *mut u8,
    ss_len: usize,
) -> i32 {
    if sk.is_null() || ct.is_null() || ss_out.is_null() || ss_len < kyber::KYBER_SS_SIZE {
        return ERR;
    }

    let sk_slice = slice::from_raw_parts(sk, sk_len);
    let ct_slice = slice::from_raw_parts(ct, ct_len);

    match kyber::kyber_decaps(sk_slice, ct_slice) {
        Ok(ss) => {
            let out = slice::from_raw_parts_mut(ss_out, ss_len);
            out[..ss.len()].copy_from_slice(&ss);
            OK
        }
        Err(_) => ERR,
    }
}

// ── Hybrid Signature (Falcon-512 || Dilithium5) ──

/// Generate hybrid keypair: Falcon-512 + Dilithium5.
/// Writes Falcon PK/SK + Dilithium PK/SK + fingerprint.
#[no_mangle]
pub unsafe extern "C" fn misaka_hybrid_keygen(
    falcon_pk_out: *mut u8, falcon_pk_len: usize,
    falcon_sk_out: *mut u8, falcon_sk_len: usize,
    dilithium_pk_out: *mut u8, dilithium_pk_len: usize,
    dilithium_sk_out: *mut u8, dilithium_sk_len: usize,
    fingerprint_out: *mut u8, fingerprint_len: usize,
) -> i32 {
    if falcon_pk_out.is_null() || falcon_sk_out.is_null()
        || dilithium_pk_out.is_null() || dilithium_sk_out.is_null()
        || fingerprint_out.is_null()
    {
        return ERR;
    }
    if falcon_pk_len < falcon::FALCON_PK_SIZE
        || falcon_sk_len < falcon::FALCON_SK_SIZE
        || dilithium_pk_len < dilithium::DILITHIUM_PK_SIZE
        || dilithium_sk_len < dilithium::DILITHIUM_SK_SIZE
        || fingerprint_len < 32
    {
        return ERR;
    }

    match hybrid_sig::hybrid_keygen() {
        Ok(kp) => {
            let fpk = slice::from_raw_parts_mut(falcon_pk_out, falcon_pk_len);
            let fsk = slice::from_raw_parts_mut(falcon_sk_out, falcon_sk_len);
            let dpk = slice::from_raw_parts_mut(dilithium_pk_out, dilithium_pk_len);
            let dsk = slice::from_raw_parts_mut(dilithium_sk_out, dilithium_sk_len);
            let fp = slice::from_raw_parts_mut(fingerprint_out, fingerprint_len);

            fpk[..kp.falcon.public_key.len()].copy_from_slice(&kp.falcon.public_key);
            fsk[..kp.falcon.secret_key.len()].copy_from_slice(&kp.falcon.secret_key);
            dpk[..kp.dilithium.public_key.len()].copy_from_slice(&kp.dilithium.public_key);
            dsk[..kp.dilithium.secret_key.len()].copy_from_slice(&kp.dilithium.secret_key);
            fp[..32].copy_from_slice(&kp.fingerprint);
            OK
        }
        Err(_) => ERR,
    }
}

/// Hybrid sign: Falcon-512 || Dilithium5 combined signature.
/// Returns the combined signature length written to sig_out, or -1 on error.
#[no_mangle]
pub unsafe extern "C" fn misaka_hybrid_sign(
    falcon_sk: *const u8, falcon_sk_len: usize,
    dilithium_sk: *const u8, dilithium_sk_len: usize,
    msg: *const u8, msg_len: usize,
    sig_out: *mut u8, sig_max_len: usize,
    sig_actual_len: *mut usize,
) -> i32 {
    if falcon_sk.is_null() || dilithium_sk.is_null()
        || msg.is_null() || sig_out.is_null() || sig_actual_len.is_null()
    {
        return ERR;
    }

    let fsk = slice::from_raw_parts(falcon_sk, falcon_sk_len);
    let dsk = slice::from_raw_parts(dilithium_sk, dilithium_sk_len);
    let msg_slice = slice::from_raw_parts(msg, msg_len);

    match hybrid_sig::hybrid_sign(fsk, dsk, msg_slice) {
        Ok(sig) => {
            if sig.len() > sig_max_len {
                return ERR;
            }
            let out = slice::from_raw_parts_mut(sig_out, sig_max_len);
            out[..sig.len()].copy_from_slice(&sig);
            *sig_actual_len = sig.len();
            OK
        }
        Err(_) => ERR,
    }
}

/// Hybrid verify: both Falcon-512 AND Dilithium5 must pass.
/// Returns 0 if valid, -1 if invalid or error.
#[no_mangle]
pub unsafe extern "C" fn misaka_hybrid_verify(
    falcon_pk: *const u8, falcon_pk_len: usize,
    dilithium_pk: *const u8, dilithium_pk_len: usize,
    msg: *const u8, msg_len: usize,
    sig: *const u8, sig_len: usize,
) -> i32 {
    if falcon_pk.is_null() || dilithium_pk.is_null()
        || msg.is_null() || sig.is_null()
    {
        return ERR;
    }

    let fpk = slice::from_raw_parts(falcon_pk, falcon_pk_len);
    let dpk = slice::from_raw_parts(dilithium_pk, dilithium_pk_len);
    let msg_slice = slice::from_raw_parts(msg, msg_len);
    let sig_slice = slice::from_raw_parts(sig, sig_len);

    match hybrid_sig::hybrid_verify(fpk, dpk, msg_slice, sig_slice) {
        Ok(true) => OK,
        _ => ERR,
    }
}
