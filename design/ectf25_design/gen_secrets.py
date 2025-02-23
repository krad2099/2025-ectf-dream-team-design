import json
import base64
import os
from cryptography.fernet import Fernet

def generate_secret_key():
    return base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8')

def encrypt_data(data, encryption_key):
    fernet = Fernet(encryption_key)
    return fernet.encrypt(data.encode())

def main():
    encryption_key = Fernet.generate_key()
    secrets = {
        "some_secrets": generate_secret_key(),
        "encryption_key": encryption_key.decode('utf-8')
    }
    secrets_json = json.dumps(secrets, indent=4)
    encrypted_secrets = encrypt_data(secrets_json, encryption_key)

    with open("secrets.json", "wb") as f:
        f.write(encrypted_secrets)
    
    with open("encryption_key.key", "wb") as f:
        f.write(encryption_key)

if __name__ == "__main__":
    main()
