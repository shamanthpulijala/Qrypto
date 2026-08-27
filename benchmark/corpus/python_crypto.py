# Benchmark corpus: Python cryptographic patterns
# Expected detections marked with comments

from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import hashlib
import ssl

# EXPECTED: RSA-2048, vulnerable, public-key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

# EXPECTED: ECDSA, vulnerable, signature
signing_key = ec.generate_private_key(ec.SECP256R1())

# EXPECTED: AES-256-GCM, adequate, symmetric
cipher = Cipher(algorithms.AES(key), modes.GCM(iv))

# EXPECTED: SHA-256, adequate, hash
digest = hashlib.sha256(b"data")

# EXPECTED: SHA-1, classical-weak, hash
digest_weak = hashlib.sha1(b"data")

# EXPECTED: MD5, classical-weak, hash (should be critical severity)
digest_broken = hashlib.md5(b"data")

# EXPECTED: TLS 1.2, adequate, tls
context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)

# EXPECTED: ML-KEM-768, quantum-resistant, pqc (should be info severity)
# from oqs import KeyEncapsulation
# kem = KeyEncapsulation("ML-KEM-768")

# EXPECTED: DES, classical-weak, symmetric (should be critical severity)
# from pyDes import des
# k = des(b"SecretKey")
