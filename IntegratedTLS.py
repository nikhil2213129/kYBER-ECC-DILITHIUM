#!/usr/bin/env python3
import os
import hashlib
import oqs
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec


class HybridKeyPair:
    def __init__(self):
        self.ecc_private = ec.generate_private_key(ec.SECP256R1())
        self.ecc_public = self.ecc_private.public_key()

        self.kyber = oqs.KeyEncapsulation("Kyber768")
        self.kyber_public = self.kyber.generate_keypair()
        self.kyber_private = self.kyber.export_secret_key()

        self.dilithium = oqs.Signature("Dilithium3")
        self.dilithium_public = self.dilithium.generate_keypair()
        self.dilithium_private = self.dilithium.export_secret_key()


def ecc_encrypt(sender_priv, receiver_pub, data: bytes):
    shared = sender_priv.exchange(ec.ECDH(), receiver_pub)
    mask = hashlib.sha256(shared).digest()
    c2 = bytes(a ^ b for a, b in zip(data, mask[:len(data)]))
    return mask, c2


def ecc_decrypt(receiver_priv, sender_pub, c1: bytes, c2: bytes):
    shared = receiver_priv.exchange(ec.ECDH(), sender_pub)
    mask = hashlib.sha256(shared).digest()
    recovered = bytes(a ^ b for a, b in zip(c2, mask[:len(c2)]))
    return recovered


def hybrid_encrypt(sender: HybridKeyPair, receiver: HybridKeyPair, message: bytes):
    with oqs.KeyEncapsulation("Kyber768") as kem:
        kem.import_public_key(receiver.kyber_public)
        C_k, ss = kem.encap_secret()

    aes_key = hashlib.sha256(ss).digest()
    aes = AESGCM(aes_key)
    nonce = os.urandom(12)
    C_sym = nonce + aes.encrypt(nonce, message, None)

    C1, C2 = ecc_encrypt(sender.ecc_private, receiver.ecc_public, C_sym)

    package = C_k + C_sym + C1 + C2
    digest = hashlib.sha3_256(package).digest()
    with oqs.Signature("Dilithium3") as sig:
        sig.import_secret_key(sender.dilithium_private)
        sigma = sig.sign(digest)

    return {
        "C_k": C_k,
        "C_sym": C_sym,
        "C1": C1,
        "C2": C2,
        "sigma": sigma,
    }


def hybrid_decrypt(receiver: HybridKeyPair, sender: HybridKeyPair, package):
    C_k = package["C_k"]
    C_sym = package["C_sym"]
    C1 = package["C1"]
    C2 = package["C2"]
    sigma = package["sigma"]

    digest = hashlib.sha3_256(C_k + C_sym + C1 + C2).digest()
    with oqs.Signature("Dilithium3") as sig:
        sig.import_public_key(sender.dilithium_public)
        if not sig.verify(digest, sigma):
            raise ValueError("Dilithium signature invalid")

    recovered_sym = ecc_decrypt(receiver.ecc_private, sender.ecc_public, C1, C2)
    if recovered_sym != C_sym:
        raise ValueError("ECC integrity check failed")

    with oqs.KeyEncapsulation("Kyber768") as kem:
        kem.import_secret_key(receiver.kyber_private)
        ss = kem.decap_secret(C_k)

    aes_key = hashlib.sha256(ss).digest()
    aes = AESGCM(aes_key)
    nonce = recovered_sym[:12]
    ciphertext_and_tag = recovered_sym[12:]
    plaintext = aes.decrypt(nonce, ciphertext_and_tag, None)

    return plaintext


if __name__ == "__main__":
    alice = HybridKeyPair()
    bob = HybridKeyPair()

    message = b"Quantum-resistant hybrid ECC + PQC encryption"
    encrypted = hybrid_encrypt(sender=alice, receiver=bob, message=message)
    decrypted = hybrid_decrypt(receiver=bob, sender=alice, package=encrypted)

    print("Original :", message)
    print("Decrypted:", decrypted)
    print("Match    :", message == decrypted)
