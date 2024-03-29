import os
import csv
from oprf import OPRF
from cryptography.hazmat.primitives.asymmetric import dsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

class Registration:
    def __init__(self, oprf):
        self.oprf = oprf

    def register(self, username, password):
        # Generate the OPRF key (salt) for the user
        oprf_key = self.oprf.generate_oprf_key()

        # Serialize the private key to PEM or DER format
        oprf_key_serialized = oprf_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,  # or PKCS8
            encryption_algorithm=serialization.NoEncryption()  # consider BestAvailableEncryption for real applications
        )

        oprf_key_hex = oprf_key_serialized.hex()
        
        # Hash the password
        hashed_password = self.oprf.H(password)

        # Simulate OPRF and derive a symmetric key for AES-GCM
        oprf_key = self.oprf.generate_oprf_key()
        hashed_password = self.oprf.H(password)  # Hash the password
        oprf_result = self.oprf.perform_oprf(oprf_key, hashed_password)  # Perform OPRF

        # Generate DSA key pair for Alice
        alice_private_key = dsa.generate_private_key(key_size=2048)
        alice_public_key = alice_private_key.public_key()

        # Serialize Alice's public key
        alice_public_key_serialized = alice_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        # Generate DSA key pair for Bob (server)
        bob_private_key = dsa.generate_private_key(key_size=2048)
        bob_public_key = bob_private_key.public_key()

        # Serialize Bob's public key
        bob_public_key_serialized = bob_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Encrypt the message M using AES-GCM
        aesgcm = AESGCM(oprf_result)
        nonce = os.urandom(12)  # AES-GCM nonce
        encrypted_message = aesgcm.encrypt(
            nonce, 
            alice_private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ) + bob_public_key_serialized, 
            None
        )
        encrypted_envelope = nonce + encrypted_message

        # Store the user's registration data
        self.store_user_data(username, encrypted_envelope, oprf_key_hex)

        print(f"User {username} registered successfully.")

    def store_user_data(self, username, encrypted_envelope, oprf_key):
        # Check if CSV file exists; create with header if not
        users_file = 'users.csv'
        file_exists = os.path.isfile(users_file)
        
        with open(users_file, mode='a', newline='') as file:
            writer = csv.writer(file)
            if not file_exists:
                writer.writerow(["username", "encrypted_envelope", "oprf_key"])
            writer.writerow([username, encrypted_envelope.hex(), oprf_key])

# Example usage
oprf_instance = OPRF()
registration = Registration(oprf_instance)
registration.register("Alice", "password123")
