use hybrid_pqc::hybrid_kem::{self, HybridKemKeypair};
use hybrid_pqc::hybrid_sig::{self, HybridSigKeypair};
use pqcrypto_traits::kem::{Ciphertext as _, PublicKey as KemPublicKey};
use pqcrypto_traits::sign::{DetachedSignature as _, PublicKey as SignPublicKey};

fn main() {
    println!("=== Hybrid ECC + Post-Quantum Cryptography Demo ===\n");

    // ---------------------------------------------------------------
    // 1. Hybrid key exchange: X25519 (classical) + Kyber768 (PQ KEM)
    // ---------------------------------------------------------------
    println!("--- Hybrid Key Exchange (X25519 + Kyber768) ---");

    // Bob generates a long-term hybrid KEM keypair and publishes `bob.public`.
    let bob = HybridKemKeypair::generate();
    println!(
        "Bob's public key sizes: X25519 = {} bytes, Kyber768 = {} bytes",
        bob.public.x25519.as_bytes().len(),
        bob.public.kyber.as_bytes().len()
    );

    // Alice encapsulates against Bob's public key.
    let (ciphertext, alice_session_key) = hybrid_kem::encapsulate(&bob.public);
    println!(
        "Alice -> Bob ciphertext sizes: X25519 = {} bytes, Kyber768 ct = {} bytes",
        ciphertext.initiator_x25519_public.as_bytes().len(),
        ciphertext.kyber_ciphertext.as_bytes().len()
    );

    // Bob decapsulates using his private keys.
    let bob_session_key = bob.decapsulate(&ciphertext);

    println!("Alice's derived session key: {}", hex::encode(alice_session_key));
    println!("Bob's derived session key:   {}", hex::encode(bob_session_key));
    assert_eq!(alice_session_key, bob_session_key);
    println!("Session keys MATCH — secure even if X25519 OR Kyber768 alone were broken.\n");

    // ---------------------------------------------------------------
    // 2. Hybrid signatures: Ed25519 (classical) + Dilithium3 (PQ sig)
    // ---------------------------------------------------------------
    println!("--- Hybrid Signatures (Ed25519 + Dilithium3) ---");

    let signer = HybridSigKeypair::generate();
    println!(
        "Signer's public key sizes: Ed25519 = {} bytes, Dilithium3 = {} bytes",
        signer.public.ed25519.as_bytes().len(),
        signer.public.dilithium.as_bytes().len()
    );

    // Sign the session key derived above, binding the two building blocks together
    // the way a real handshake would authenticate its key-exchange transcript.
    let message = alice_session_key;
    let signature = signer.sign(&message);
    println!(
        "Signature sizes: Ed25519 = {} bytes, Dilithium3 = {} bytes",
        signature.ed25519.to_bytes().len(),
        signature.dilithium.as_bytes().len()
    );

    let valid = hybrid_sig::verify(&signer.public, &message, &signature);
    println!("Verification of authentic signature: {}", valid);
    assert!(valid);

    // Tamper with the message and confirm verification now fails.
    let mut tampered = message;
    tampered[0] ^= 0x01;
    let tampered_valid = hybrid_sig::verify(&signer.public, &tampered, &signature);
    println!("Verification after tampering with message: {}", tampered_valid);
    assert!(!tampered_valid);

    println!("\nBoth hybrid primitives behaved as expected.");
}
