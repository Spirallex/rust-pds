//! Device-approval sign-in ("Sign in with Stelyph").
//!
//! The portable core of a passwordless authentication step: the account holder's
//! device approves a sign-in by signing a per-request challenge, in place of a
//! password typed into a login page. This module owns the parts that must be
//! identical wherever they run — the challenge bytes and the signature check —
//! and deliberately owns no storage and no randomness, because both differ
//! between the wasm Worker and the on-device server.
//!
//! See `rust-worker/SIGN-IN-WITH-STELYPH.md` for the whole flow.

use atrium_crypto::verify::verify_signature;

/// Status of a pending sign-in request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigninStatus {
    Pending,
    Approved,
    Denied,
    Expired,
}

impl SigninStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            SigninStatus::Pending => "pending",
            SigninStatus::Approved => "approved",
            SigninStatus::Denied => "denied",
            SigninStatus::Expired => "expired",
        }
    }
}

/// Bytes the device signs to approve a request.
///
/// Domain-separated and bound to the request id and user code, so a signature is
/// valid for exactly one request and cannot be lifted onto another. The prefix
/// makes an approval signature unmistakable for any other thing the same key
/// might sign (a repo commit, say) — cross-protocol signature reuse is a real
/// attack class, and a fixed domain tag is the standard defence.
pub fn approval_challenge(request_id: &str, user_code: &str) -> Vec<u8> {
    let mut v = Vec::with_capacity(64);
    v.extend_from_slice(b"stelyph-signin-approval:v1:");
    v.extend_from_slice(request_id.as_bytes());
    v.push(b':');
    v.extend_from_slice(user_code.as_bytes());
    v
}

/// Whether `signature` is a valid approval of `(request_id, user_code)` by the
/// device identified by `device_did_key` (a `did:key:…` string).
///
/// The algorithm and curve come from the `did:key` itself, so a caller cannot
/// force a weaker check by lying about the key type — `verify_signature` reads
/// both from the multicodec prefix.
pub fn verify_approval(
    device_did_key: &str,
    request_id: &str,
    user_code: &str,
    signature: &[u8],
) -> bool {
    let challenge = approval_challenge(request_id, user_code);
    verify_signature(device_did_key, &challenge, signature).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use atrium_crypto::keypair::{Did as _, Secp256k1Keypair};
    use rand::rngs::OsRng;

    #[test]
    fn a_valid_signature_over_the_challenge_approves() {
        let key = Secp256k1Keypair::create(&mut OsRng);
        let did_key = key.did();
        let sig = key
            .sign(&approval_challenge("req-123", "WXYZ-1234"))
            .unwrap();
        assert!(verify_approval(&did_key, "req-123", "WXYZ-1234", &sig));
    }

    #[test]
    fn a_signature_for_another_request_does_not_approve() {
        let key = Secp256k1Keypair::create(&mut OsRng);
        let did_key = key.did();
        // Signed the challenge for req-123, presented against req-999.
        let sig = key
            .sign(&approval_challenge("req-123", "WXYZ-1234"))
            .unwrap();
        assert!(!verify_approval(&did_key, "req-999", "WXYZ-1234", &sig));
        // Right request id, wrong user code — also rejected, since the code is
        // part of the signed bytes.
        assert!(!verify_approval(&did_key, "req-123", "0000-0000", &sig));
    }

    #[test]
    fn another_devices_signature_does_not_approve() {
        let enrolled = Secp256k1Keypair::create(&mut OsRng);
        let attacker = Secp256k1Keypair::create(&mut OsRng);
        let sig = attacker
            .sign(&approval_challenge("req-123", "WXYZ-1234"))
            .unwrap();
        // Verified against the *enrolled* device's key, not the signer's.
        assert!(!verify_approval(&enrolled.did(), "req-123", "WXYZ-1234", &sig));
    }

    #[test]
    fn a_garbage_signature_does_not_panic_and_is_rejected() {
        let key = Secp256k1Keypair::create(&mut OsRng);
        assert!(!verify_approval(&key.did(), "req-123", "WXYZ-1234", &[0u8; 64]));
        assert!(!verify_approval(&key.did(), "req-123", "WXYZ-1234", &[]));
    }
}
