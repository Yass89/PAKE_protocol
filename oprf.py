# oprf.py
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import os

class OPRF:
    def __init__(self, backend=None):
        self._backend = default_backend() if backend is None else backend

    def H(self, P):
        # Hash the password P with SHA-256
        digest = hashes.Hash(hashes.SHA256(), backend=self._backend)
        digest.update(P.encode('utf-8'))
        return digest.finalize()

    def generate_oprf_key(self):
        # Generate RSA private key as OPRF key
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=self._backend
        )

    def perform_oprf(self, private_key, data):
        # Sign the data using the private_key
        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256()
        )
        
        # Derive a 256-bit key for AESGCM
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 32 bytes = 256 bits
            salt=None,
            info=b'oprf derived key',
            backend=self._backend
        )
        return hkdf.derive(signature)

# Example Usage
# This would not be used directly but demonstrates basic usage of the class
oprf = OPRF()
password = "password123"
hashed_password = oprf.H(password)
oprf_key = oprf.generate_oprf_key()
oprf_result = oprf.perform_oprf(oprf_key, hashed_password)
