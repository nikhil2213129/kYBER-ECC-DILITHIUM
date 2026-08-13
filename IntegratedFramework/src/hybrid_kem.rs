//! Hybrid key encapsulation: X25519 (ECDH) combined with Kyber768 (ML-KEM predecessor).
//!
//! Security rationale: the two shared secrets are mixed through HKDF together with a
//! transcript binding. This is a "concatenation combiner", which is proven IND-CCA secure
//! as long as *at least one* of the two component KEMs remains secure and the KDF is a
//! secure PRF (Giacon, Heuer, Poettering 2018; Bindel et al. 2019) — the same approach
//! IETF/TLS use for X25519Kyber768 hybrid key exchange.

use hkdf::Hkdf;
use pqcrypto_kyber::kyber768;
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as _, SharedSecret as _};
use sha2::Sha384;
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey, StaticSecret};

pub const SESSION_KEY_LEN: usize = 32;

/// Domain separation label baked into the KDF `info` field so this key material can never
/// be confused with output from a different protocol/version.
const HYBRID_KEM_LABEL: &[u8] = b"hybrid-kem/x25519+kyber768/v1";

/// The receiver's long-term (or per-session) hybrid public key, published to initiators.
pub struct HybridKemPublicKey {
    pub x25519: X25519PublicKey,
    pub kyber: kyber768::PublicKey,
}

/// The receiver's hybrid keypair. Keep `x25519_secret`/`kyber_secret` private to this struct.
pub struct HybridKemKeypair {
    x25519_secret: StaticSecret,
    kyber_secret: kyber768::SecretKey,
    pub public: HybridKemPublicKey,
}

/// What the initiator sends to the receiver: the initiator's ephemeral X25519 public key
/// plus the Kyber ciphertext. Both are needed for the receiver to reconstruct the session key.
pub struct HybridKemCiphertext {
    pub initiator_x25519_public: X25519PublicKey,
    pub kyber_ciphertext: kyber768::Ciphertext,
}

impl HybridKemKeypair {
    pub fn generate() -> Self {
        let x25519_secret = StaticSecret::random();
        let x25519_public = X25519PublicKey::from(&x25519_secret);
        let (kyber_public, kyber_secret) = kyber768::keypair();

        Self {
            x25519_secret,
            kyber_secret,
            public: HybridKemPublicKey {
                x25519: x25519_public,
                kyber: kyber_public,
            },
        }
    }

    /// Receiver side: reconstruct the session key from an initiator's `HybridKemCiphertext`.
    pub fn decapsulate(&self, ct: &HybridKemCiphertext) -> [u8; SESSION_KEY_LEN] {
        let ecdh_ss = self
            .x25519_secret
            .diffie_hellman(&ct.initiator_x25519_public);
        let kyber_ss = kyber768::decapsulate(&ct.kyber_ciphertext, &self.kyber_secret);

        derive_session_key(
            ecdh_ss.as_bytes(),
            kyber_ss.as_bytes(),
            &ct.initiator_x25519_public,
            &self.public,
            &ct.kyber_ciphertext,
        )
    }
}

/// Initiator side: given the receiver's hybrid public key, produce a `HybridKemCiphertext`
/// to send back plus the session key derived on this side.
pub fn encapsulate(receiver_public: &HybridKemPublicKey) -> (HybridKemCiphertext, [u8; SESSION_KEY_LEN]) {
    let initiator_secret = EphemeralSecret::random();
    let initiator_public = X25519PublicKey::from(&initiator_secret);
    let ecdh_ss = initiator_secret.diffie_hellman(&receiver_public.x25519);

    let (kyber_ss, kyber_ciphertext) = kyber768::encapsulate(&receiver_public.kyber);

    let ct = HybridKemCiphertext {
        initiator_x25519_public: initiator_public,
        kyber_ciphertext,
    };

    let session_key = derive_session_key(
        ecdh_ss.as_bytes(),
        kyber_ss.as_bytes(),
        &ct.initiator_x25519_public,
        receiver_public,
        &ct.kyber_ciphertext,
    );

    (ct, session_key)
}

/// Concatenation combiner: HKDF-Extract-and-Expand over (Kyber_ss || ECDH_ss), salted by a
/// transcript hash so both parties must agree on every public value exchanged.
fn derive_session_key(
    ecdh_ss: &[u8],
    kyber_ss: &[u8],
    initiator_x25519_public: &X25519PublicKey,
    receiver_public: &HybridKemPublicKey,
    kyber_ciphertext: &kyber768::Ciphertext,
) -> [u8; SESSION_KEY_LEN] {
    let mut ikm = Vec::with_capacity(kyber_ss.len() + ecdh_ss.len());
    ikm.extend_from_slice(kyber_ss);
    ikm.extend_from_slice(ecdh_ss);

    let mut transcript = Vec::new();
    transcript.extend_from_slice(initiator_x25519_public.as_bytes());
    transcript.extend_from_slice(receiver_public.x25519.as_bytes());
    transcript.extend_from_slice(receiver_public.kyber.as_bytes());
    transcript.extend_from_slice(kyber_ciphertext.as_bytes());

    let hk = Hkdf::<Sha384>::new(Some(&transcript), &ikm);
    let mut okm = [0u8; SESSION_KEY_LEN];
    hk.expand(HYBRID_KEM_LABEL, &mut okm)
        .expect("SESSION_KEY_LEN is a valid HKDF-SHA384 output length");
    okm
}
