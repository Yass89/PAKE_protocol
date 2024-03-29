import csv
from oprf import OPRF
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.serialization import load_pem_public_key

DATABASE_FILE = 'users.csv'
FIELDNAMES = ['username', 'encrypted_message', 'salt']

# Initialize the OPRF instance
oprf = OPRF()

class Server:
    def __init__(self, database_file):
        self.database_file = database_file
        self.user_secrets = self.load_user_secrets()

    def load_user_secrets(self):
        """Load user secrets from the database."""
        secrets = {}
        with open(self.database_file, mode='r', newline='') as csvfile:
            reader = csv.DictReader(csvfile, fieldnames=FIELDNAMES)
            for row in reader:
                username = row['username']
                if username:
                    secrets[username] = {
                        'encrypted_message': bytes.fromhex(row['encrypted_message']),
                        'salt': bytes.fromhex(row['salt'])
                    }
        return secrets

    def perform_dh_key_exchange(self, client_public_bytes):
        """Perform a DH key exchange and return server's public key and shared key."""
        parameters = dh.generate_parameters(generator=2, key_size=2048)
        server_private_key = parameters.generate_private_key()
        client_public_key = load_pem_public_key(client_public_bytes)

        shared_key = server_private_key.exchange(client_public_key)

        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data'
        ).derive(shared_key)

        server_public_key = server_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return derived_key, server_public_key

class Client:
    def __init__(self):
        self.server = Server(DATABASE_FILE)  # In real application, this would be server's address

    def initiate_dh_key_exchange(self):
        """Initiate DH key exchange and return client's public key and private key."""
        parameters = dh.generate_parameters(generator=2, key_size=2048)
        client_private_key = parameters.generate_private_key()
        client_public_key = client_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        return client_private_key, client_public_key

    def login(self, username, password):
        """Perform the login process."""
        if username not in self.server.user_secrets:
            print("User not found.")
            return False

        user_data = self.server.user_secrets[username]
        encrypted_message = user_data['encrypted_message']
        salt = user_data['salt']

        # DH key exchange
        client_private_key, client_public_key = self.initiate_dh_key_exchange()
        derived_key, server_public_key = self.server.perform_dh_key_exchange(client_public_key)

        # Assuming the encrypted_message is encrypted using AESGCM with the derived key
        aesgcm = AESGCM(derived_key)
        decrypted_message = aesgcm.decrypt(salt, encrypted_message, None)

        print(f"Decrypted message: {decrypted_message.decode()}")
        print("Login successful.")
        return True

# Example usage:
client = Client()
login_success = client.login("Alice", "password123")
print(f"Login was {'successful' if login_success else 'unsuccessful'}")
