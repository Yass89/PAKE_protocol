import os
import csv
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa, utils
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes

def int_to_element_g(s, q):
    """Convert integer s to an element in G."""
    return pow(s, 2, 2*q+1)

def convert_string_to_int(s, q):
    """Convert a string to an integer in the range [2, q]."""
    digest = hashes.Hash(hashes.SHA256())
    digest.update(s.encode())
    hash_val = int.from_bytes(digest.finalize(), byteorder='big')
    return 2 + (hash_val % (q - 2))

def create_dsa_key_pair():
    """Generate a DSA key pair."""
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)

def sign_message(private_key, message):
    """Sign a message using the private key."""
    return private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256() 
    )

def verify_signature(public_key, message, signature):
    """Verify a digital signature."""
    try:
        public_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            utils.Prehashed(hashes.SHA256())
        )
        return True
    except Exception as e:
        return False

def encrypt_message(key, nonce, message):
    """Encrypt a message using AESGCM."""
    aesgcm = AESGCM(key)
    return aesgcm.encrypt(nonce, message, None)

def decrypt_message(key, nonce, encrypted_message):
    """Decrypt a message using AESGCM."""
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, encrypted_message, None)

def create_rsa_key_pair():
    """Generate an RSA key pair for digital signatures."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return private_key, private_key.public_key()

def serialize_public_key(public_key):
    """Serialize public key to bytes."""
    return public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

def main():
    # CSV file for database
    csv_filename = 'users.csv'

    # Generate key pairs for Alice and Bob
    alice_private_key, alice_public_key = create_rsa_key_pair()
    bob_private_key, bob_public_key = create_rsa_key_pair()  # Bob's key pair can be reused for all users.

    # Alice and Bob sign a message (for simplicity, let's assume the message is their public key)
    alice_message = serialize_public_key(alice_public_key)
    bob_message = serialize_public_key(bob_public_key)
    alice_signature = sign_message(alice_private_key, alice_message)
    bob_signature = sign_message(bob_private_key, bob_message)

    # Encrypt M = Alice’s secret key || Bob’s public key
    alice_secret_key_bytes = alice_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    bob_public_key_bytes = serialize_public_key(bob_public_key)
    M = alice_secret_key_bytes + bob_public_key_bytes

    # Generate a unique salt for AESGCM encryption
    salt = os.urandom(16)
    aesgcm = AESGCM(salt)
    nonce = os.urandom(12)  # AESGCM nonce
    encrypted_M = aesgcm.encrypt(nonce, M, None)

    # Bob stores Alice's username, encrypted_M, and salt into the database
    with open(csv_filename, 'a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(['Alice', encrypted_M.hex(), salt.hex()])
    print("Alice's secret key and Bob's public key have been stored in the database.")

if __name__ == "__main__":
    main()
