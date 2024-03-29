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
        utils.Prehashed(hashes.SHA256())
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

def main():
    # Load or initialize database (CSV file)
    csv_filename = 'users.csv'

    # INITIALIZATION (User registration)
    q = 2**2048  # This should ideally come from an RFC 3526 group, simplified here for brevity
    alice_password = "AliceStrongPassword"
    alice_salt = os.urandom(16)  # Generate a unique salt for each user
    s = convert_string_to_int(alice_password, q)
    H_P = int_to_element_g(s, q)

    # Simulate client side operation
    alice_private_key = create_dsa_key_pair()
    alice_public_key = alice_private_key.public_key()
    r = os.urandom(32)  # Random scalar r
    C = H_P**int.from_bytes(r, 'big') % q

    # Simulate server side operation
    server_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    server_public_key = server_private_key.public_key()
    s_random_scalar = os.urandom(32)  # Server's salt as a random scalar
    R = C**int.from_bytes(s_random_scalar, 'big') % q

    # Back to client to compute shared key K
    z = pow(int.from_bytes(r, 'big'), -1, q)
    K = R**z % q

    # Alice encrypts a message with shared key K (simplified for brevity)
    shared_secret = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'handshake data',
    ).derive(R.to_bytes(256, 'big'))

    encrypted_message = encrypt_message(shared_secret, alice_salt, b"Alice secret key || Bob public key")
    print("Encrypted message:", encrypted_message)

    # Assuming Alice sends her username, encrypted message and salt to Bob (server), server stores this information
    with open(csv_filename, 'a', newline='') as csvfile:
        csvwriter = csv.writer(csvfile)
        csvwriter.writerow(["Alice", encrypted_message, alice_salt])

    # Bob (server) loads Alice's record from the CSV, could use it later for authentication or other purposes

if __name__ == "__main__":
    main()