# oprf.py: Extending with group operation and storing/loading user data.
from cryptography.hazmat.primitives.asymmetric.dsa import generate_private_key
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature, decode_dss_signature
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import hashlib
import secrets
import os
import json

class OPRF:
    def __init__(self):
        self.G = 2
        self.q = 2**2048 - 2**1984 + 1 + 2**64 * ((2**1918 - 1) // 2**64)

    def H(self, P):
        hash_instance = hashlib.sha256()
        hash_instance.update(P.encode())
        hash_int = int(hash_instance.hexdigest(), 16)
        return pow(self.G, hash_int % self.q, self.q)

    def generate_oprf_key(self):
        return secrets.randbelow(self.q)

    def client_oprf_step(self, P, r):
        C = self.H(P) ** r % self.q
        return C

    def server_oprf_step(self, C, s):
        R = C ** s % self.q
        return R

    def inverse(self, r):
        return pow(r, -1, self.q)

    def generate_salt(self):
        return secrets.randbelow(self.q)

    def create_signature_keypair(self):
        private_key = generate_private_key(key_size=2048, backend=default_backend())
        return private_key, private_key.public_key()

    def sign_data(self, private_key, data):
        signature = private_key.sign(data, hashes.SHA256())
        return encode_dss_signature(*decode_dss_signature(signature))

    def verify_signature(self, public_key, signature, data):
        r, s = decode_dss_signature(signature)
        encoded_signature = encode_dss_signature(r, s)
        try:
            public_key.verify(encoded_signature, data, hashes.SHA256())
            return True
        except:
            return False

    def encrypt(self, key, plaintext):
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        return nonce + aesgcm.encrypt(nonce, plaintext, None)

    def decrypt(self, key, ciphertext):
        aesgcm = AESGCM(key)
        nonce = ciphertext[:12]
        return aesgcm.decrypt(nonce, ciphertext[12:], None)

    def key_exchange(self, private_key, public_key):
        shared_key_material = private_key.exchange(public_key)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(shared_key_material)
        return derived_key

    def serialize_public_key(self, public_key):
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def deserialize_public_key(self, pem):
        return serialization.load_pem_public_key(pem, backend=default_backend())