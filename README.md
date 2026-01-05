```markdown
# Hybrid PQC–ECC CIA Cryptosystem

This repository contains a **research-grade demonstrative implementation** of a hybrid cryptosystem that integrates **Post-Quantum Cryptography (PQC)** with **Elliptic Curve Cryptography (ECC)** to achieve **Confidentiality, Integrity, and Authentication (CIA)** in a single pipeline.

The system combines:
- **Kyber768 (KEM)** – Post-quantum key encapsulation for confidentiality
- **AES-GCM** – Symmetric encryption for message confidentiality
- **ECC (ECDH over SECP256R1)** – Authentication and binding of ciphertext
- **Dilithium3 (Signature)** – Post-quantum digital signatures for authenticity and integrity

---

## Features

- 🔒 Confidentiality: Kyber768 + AES-GCM  
- ✅ Integrity: AES-GCM + ECC binding  
- 🧾 Authentication: ECC + Dilithium3 signatures  
- 🛡️ Quantum Resistance: Kyber + Dilithium secure against Shor’s and Grover’s algorithms  
- ⚡ Hybrid Agility: Combines classical ECC with PQC for defense-in-depth  

---

## Installation

Clone the repository and install dependencies:

```bash
git clone https://github.com/your-username/hybrid-pqc-ecc-cia.git
cd hybrid-pqc-ecc-cia
pip install liboqs-python cryptography
```

---

## Usage

Run the demonstration script:

```bash
python hybrid_crypto.py
```

Expected output:

```
Original : b'Quantum-resistant hybrid ECC + PQC encryption'
Decrypted: b'Quantum-resistant hybrid ECC + PQC encryption'
Match    : True
```

---

## File Structure

```
├── hybrid_crypto.py   # Full implementation (single file)
├── README.md          # Project documentation
```

---

## Security Properties

| Property        | Mechanism              |
|-----------------|------------------------|
| Confidentiality | Kyber768 + AES-GCM     |
| Integrity       | AES-GCM + ECC binding  |
| Authentication  | ECC + Dilithium3       |
| Quantum Safety  | Kyber + Dilithium3     |
| Hybrid Defense  | ECC + PQC integration  |

---

## Academic Value

This project demonstrates:
- Post-quantum confidentiality and authentication
- Hybrid cryptographic agility
- Backward compatibility with ECC systems
- Modular integration without redesigning ECC core
- Resistance to quantum attacks

---

## Disclaimer

This code is for **academic and research demonstration purposes only**.  
It is **not production-ready** and should not be used in real-world secure communication systems without rigorous review and testing.

---

## License

MIT License – free to use, modify, and distribute with attribution.
```
