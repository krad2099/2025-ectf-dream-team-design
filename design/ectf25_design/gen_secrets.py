"""
Author: Ben Janis
Date: 2025

This source file is part of an example system for MITRE's 2025 Embedded System CTF
(eCTF). This code is being provided only for educational purposes for the 2025 MITRE
eCTF competition, and may not meet MITRE standards for quality. Use this code at your
own risk!

Copyright: Copyright (c) 2025 The MITRE Corporation
"""

import json
import base64
import os
from cryptography.fernet import Fernet

def generate_secret_key():
    return Fernet.generate_key().decode('utf-8')  # Ensures a valid key for Fernet

def encrypt_data(data, encryption_key):
    fernet = Fernet(encryption_key.encode())  # Ensure the key is in bytes
    encrypted_data = fernet.encrypt(data.encode())
    return encrypted_data

def main():
    encryption_key = Fernet.generate_key()  # Correctly generate a valid encryption key

    secrets = {
        "secret_key": generate_secret_key(),
        "encryption_key": Fernet.generate_key().decode('utf-8')  # Generates another valid key
    }

    secrets_json = json.dumps(secrets, indent=4)
    encrypted_secrets = encrypt_data(secrets_json, encryption_key)

    with open("secrets.enc", "wb") as f:  # Changed extension for clarity
        f.write(encrypted_secrets)

    # Store the encryption key securely, not in the same location as the secrets file
    with open("encryption_key.key", "wb") as f:
        f.write(encryption_key)  # Key is already in bytes

if __name__ == "__main__":
    main()
