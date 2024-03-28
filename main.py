import csv
import os
from oprf import OPRF, store_user, retrieve_user
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

CSV_FILE_PATH = 'users.csv'

def store_user_csv(username, public_key, secret_data, salt):
    # Check if CSV file exists; create with header if not
    if not os.path.exists(CSV_FILE_PATH):
        with open(CSV_FILE_PATH, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(["username", "public_key", "secret_data", "salt"])
            
    # Append user data to CSV
    with open(CSV_FILE_PATH, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow([username, public_key.decode('utf-8'), secret_data.hex(), salt])

def retrieve_user_csv(username):
    if not os.path.exists(CSV_FILE_PATH):
        return None  # File doesn't exist

    with open(CSV_FILE_PATH, mode='r', newline='') as file:
        reader = csv.DictReader(file)
        for row in reader:
            if row["username"] == username:
                # Convert back from stored formats
                return {
                    "public_key": row["public_key"].encode('utf-8'),
                    "secret_data": bytes.fromhex(row["secret_data"]),
                    "salt": int(row["salt"])
                }
    return None

# Modify the registration and login code to use these new CSV functions

def registration_csv(username, password):
    oprf = OPRF()
    user_private_key, user_public_key = oprf.create_signature_keypair()
    salt = oprf.generate_salt()
    r = secrets.randbelow(oprf.q)
    C = oprf.client_oprf_step(password, r)
    oprf_key = oprf.generate_oprf_key()
    R = oprf.server_oprf_step(C, oprf_key)
    z = oprf.inverse(r)
    final_oprf_result = pow(R, z, oprf.q)
    shared_secret_key = hashlib.sha256(str(final_oprf_result).encode()).digest()
    encrypted_envelope = oprf.encrypt(shared_secret_key, user_private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ) + oprf.serialize_public_key(user_public_key))
    store_user_csv(username, oprf.serialize_public_key(user_public_key), encrypted_envelope, salt)

def login_csv(username, password):
    oprf = OPRF()
    user_data = retrieve_user_csv(username)
    if not user_data:
        return False, "User not found"
    r = secrets.randbelow(oprf.q)
    C = oprf.client_oprf_step(password, r)
    R = oprf.server_oprf_step(C, user_data['salt'])
    z = oprf.inverse(r)
    final_oprf_result = pow(R, z, oprf.q)
    shared_secret_key = hashlib.sha256(str(final_oprf_result).encode()).digest()
    try:
        decrypted_data = oprf.decrypt(shared_secret_key, user_data['secret_data'])
        return True, "Login successful"
    except Exception as e:
        return False, f"Decryption failed: {str(e)}"

# Test with CSV database
username = "Alice"
password = "password"
registration_csv(username, password)
login_status, message = login_csv(username, password)
print(login_status, message)