import csv
import os
from oprf import OPRF
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

DATABASE_FILE = 'users.csv'
FIELDNAMES = ['username', 'encrypted_message', 'salt', 'server_secret']

# Initialize the OPRF instance
oprf = OPRF()

# The server part would typically run on the server
class Server:
    def __init__(self, database_file):
        self.database_file = database_file
        self.user_secrets = self.load_user_secrets()

    def load_user_secrets(self):
        """Load user secrets (s values) from the database."""
        secrets = {}
        with open(self.database_file, mode='r', newline='') as csvfile:
            reader = csv.DictReader(csvfile, fieldnames=FIELDNAMES)
            for row in reader:
                if row['username'] and row['server_secret']:
                    secrets[row['username']] = int(row['server_secret'])
        return secrets

    def identify_user(self, username):
        """Identify user by username."""
        return username in self.user_secrets

    def retrieve_s_for_user(self, username):
        """Retrieve s value for user."""
        return self.user_secrets.get(username)

    def compute_R(self, C, s):
        """Compute R as C^s."""
        return oprf.server_oprf_step(C, s)

    def perform_dh_key_exchange(self, client_public_key):
        """Perform a DH key exchange."""
        parameters = dh.generate_parameters(generator=2, key_size=2048)
        server_private_key = parameters.generate_private_key()
        server_public_key = server_private_key.public_key()

        shared_key = server_private_key.exchange(client_public_key)

        # Derive a shared secret key
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data'
        ).derive(shared_key)

        # In a real application, the server's public key would be sent to the client securely
        return derived_key, server_public_key

# The client part would typically run on the client
class Client:
    def __init__(self):
        self.server = Server(DATABASE_FILE)  # In a real application, this would be the server's address

    def initiate_oprf(self, P):
        """Initiate OPRF: generate r, compute C."""
        r = oprf.generate_oprf_key()  # Client's secret
        C = oprf.client_oprf_step(P, r)  # Client computes C
        return r, C

    def finalize_oprf(self, R, r):
        """Finalize OPRF to compute K."""
        r_inv = oprf.inverse(r)
        K = oprf.server_oprf_step(R, r_inv)  # Finalize OPRF to obtain K
        return K

    def login(self, username, password):
        """Perform the login process."""
        # Step 1: Identify user by username
        if not self.server.identify_user(username):
            print("User not found.")
            return False

        # Step 2: Prepare P as H(P)
        P = oprf.H(password)

        # Step 3: Initiate OPRF
        r, C = self.initiate_oprf(P)

        # Send C to the server and receive R (would be done over the network)
        s = self.server.retrieve_s_for_user(username)  # This would typically be stored securely on the server
        R = self.server.compute_R(C, s)

        # Step 4: Finalize OPRF to obtain K
        K = self.finalize_oprf(R, r)

        # Step 5: Perform DH key exchange to obtain shared secret key
        client_dh_private_key = oprf.create_signature_keypair()[0]  # Client generates DH key pair
        client_dh_public_key = client_dh_private_key.public_key()

        # In a real application, the client would send their public key to the server
        shared_secret, server_dh_public_key = self.server.perform_dh_key_exchange(client_dh_public_key)

        # The client now has the shared secret key `sk`
        print("Login successful.")
        return True

# Example usage:
client = Client()
login_success = client.login("alice", "alice_password")
print(f"Login was {'successful' if login_success else 'unsuccessful'}")