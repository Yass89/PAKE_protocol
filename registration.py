import os
import csv
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh, dsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

# Initialize DH parameters for the 2048-bit group from RFC 3526
parameters = dh.generate_parameters(generator=2, key_size=2048, backend=default_backend())

# Hash function H that maps an integer to an element of G
def hash_to_group(element, q):
    hash_obj = hashes.Hash(hashes.SHA256(), backend=default_backend())
    hash_obj.update(element.to_bytes((element.bit_length() + 7) // 8, byteorder='big'))
    hashed = int.from_bytes(hash_obj.finalize(), byteorder='big')
    return pow(hashed, 2, 2*q + 1)

# Function to generate DSA key pair
def generate_dsa_keys():
    private_key = dsa.generate_private_key(key_size=2048, backend=default_backend())
    public_key = private_key.public_key()
    return private_key, public_key

# Function for authenticated encryption
def encrypt_data(key, plaintext):
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    return nonce, aesgcm.encrypt(nonce, plaintext, None)

# Function to save data into a CSV file
def save_data(username, encrypted_message, salt):
    with open('users.csv', mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([username, encrypted_message.hex(), salt.hex()])

def main(client_password, alice_secret_key, bob_public_key, username):
    q = parameters.parameter_numbers().q

    # Client Side
    password_int = int.from_bytes(client_password.encode(), 'big')
    H_p = hash_to_group(password_int, q)
    r = parameters.parameter_numbers().p  # Random scalar r
    C = pow(H_p, r, parameters.parameter_numbers().p)

    # Server Side
    salt = os.urandom(16)  # Ensure unique salt for each user
    s = int.from_bytes(salt, 'big') % q
    R = pow(C, s, parameters.parameter_numbers().p)

    # Client Side Continued
    z = pow(r, -1, q)
    K = pow(R, z, parameters.parameter_numbers().p)

    # Alice and Bob generate their DSA key pairs
    alice_private_key, alice_public_key = generate_dsa_keys()
    bob_private_key, bob_public_key = generate_dsa_keys()  # Assuming Bob's keys are pre-generated

    # Alice encrypts the message with the derived key K
    nonce, encrypted_message = encrypt_data(K.to_bytes((K.bit_length() + 7) // 8, 'big'), alice_secret_key + bob_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo))

    # Save Alice's username, encrypted message, and salt into the database
    save_data(username, encrypted_message, salt)

    print(f"Registration complete for {username}.")

if __name__ == "__main__":
    # Example usage
    client_password = "secure_password"
    alice_secret_key = b"Alice's secret key"
    bob_public_key_material = b"Bob's public key"  # Placeholder, should be replaced with actual public key bytes
    username = "Alice"
    main(client_password, alice_secret_key, bob_public_key_material, username)
