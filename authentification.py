from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from traitlets import HasDescriptors
from oprf import OPRF
import os
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend

class AuthenticationProcess(OPRF):
    def __init__(self):
        super().__init__()
        self.aes_key_size = 32

    def encrypt(self, key, plaintext):
        # Key must be 256 bits (32 bytes)
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)  # IV
        # Encrypt and return ciphertext with nonce
        return nonce + aesgcm.encrypt(nonce, plaintext, None)

    def decrypt(self, key, ciphertext):
        aesgcm = AESGCM(key)
        nonce = ciphertext[:12]
        return aesgcm.decrypt(nonce, ciphertext[12:], None)

    def key_exchange(self, private_key, public_key):
        # Perform Diffie-Hellman key exchange
        shared_key_material = private_key.exchange(public_key)
        # Use HKDF to derive a symmetric key from the shared key material
        derived_key = HKDF(
            algorithm=HasDescriptors.SHA256(),
            length=self.aes_key_size,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(shared_key_material)
        return derived_key