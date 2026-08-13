//! Hybrid digital signatures: Ed25519 combined with Dilithium3 (ML-DSA predecessor).
//!
//! Security rationale: this is a "strong" (AND) combiner — a message is only accepted if
//! *both* signatures verify. Forging a hybrid signature therefore requires breaking both
//! Ed25519 and Dilithium3 simultaneously. This matches the approach in the IETF LAMPS
//! composite-signatures draft: never accept on a single component passing.

use ed25519_dalek::{Signature as Ed25519Signature, Signer, SigningKey, Verifier, VerifyingKey};
use pqcrypto_dilithium::dilithium3;
use rand_core::OsRng;

pub struct HybridSigPublicKey {
    pub ed25519: VerifyingKey,
    pub dilithium: dilithium3::PublicKey,
}

pub struct HybridSigKeypair {
    ed25519_secret: SigningKey,
    dilithium_secret: dilithium3::SecretKey,
    pub public: HybridSigPublicKey,
}

pub struct HybridSignature {
    pub ed25519: Ed25519Signature,
    pub dilithium: dilithium3::DetachedSignature,
}

impl HybridSigKeypair {
    pub fn generate() -> Self {
        let ed25519_secret = SigningKey::generate(&mut OsRng);
        let (dilithium_public, dilithium_secret) = dilithium3::keypair();

        Self {
            public: HybridSigPublicKey {
                ed25519: ed25519_secret.verifying_key(),
                dilithium: dilithium_public,
            },
            ed25519_secret,
            dilithium_secret,
        }
    }

    pub fn sign(&self, message: &[u8]) -> HybridSignature {
        HybridSignature {
            ed25519: self.ed25519_secret.sign(message),
            dilithium: dilithium3::detached_sign(message, &self.dilithium_secret),
        }
    }
}

/// Verify a hybrid signature. Returns `true` only if BOTH component signatures are valid.
pub fn verify(public: &HybridSigPublicKey, message: &[u8], sig: &HybridSignature) -> bool {
    let ed25519_ok = public.ed25519.verify(message, &sig.ed25519).is_ok();
    let dilithium_ok =
        dilithium3::verify_detached_signature(&sig.dilithium, message, &public.dilithium).is_ok();

    ed25519_ok && dilithium_ok
}
