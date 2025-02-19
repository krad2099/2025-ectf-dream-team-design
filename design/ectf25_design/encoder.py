"""
Author: Ben Janis
Date: 2025

This source file is part of an example system for MITRE's 2025 Embedded System CTF
(eCTF). This code is being provided only for educational purposes for the 2025 MITRE
eCTF competition, and may not meet MITRE standards for quality. Use this code at your
own risk!

Copyright: Copyright (c) 2025 The MITRE Corporation
"""

import argparse
import struct
import json
import os
import base64
import time
import hmac
import hashlib
from cryptography.fernet import Fernet

class Encoder:
    def __init__(self, secrets: bytes):
        secrets = json.loads(secrets)
        self.secret_key = secrets["secret_key"]
        self.encryption_key = secrets["encryption_key"]

    def generate_timestamp_nonce(self):
        timestamp = str(int(time.time() * 1000))
        nonce = base64.urlsafe_b64encode(os.urandom(16)).decode('utf-8')
        return timestamp, nonce

    def generate_2fa_code(self, secret, timestamp, nonce):
        message = f"{timestamp}{nonce}".encode()
        secret = secret.encode()
        hash = hmac.new(secret, message, hashlib.sha256).digest()
        return base64.b32encode(hash).decode('utf-8')

    def create_hash(self, frame, secret, encryption_key, timestamp, nonce, two_fa_code):
        fernet = Fernet(encryption_key)
        encrypted_message = fernet.encrypt(frame)
        combined_message = f"{encrypted_message.decode()}{two_fa_code}{timestamp}{nonce}".encode()
        return hashlib.sha256(combined_message).hexdigest(), encrypted_message

    def encode(self, channel: int, frame: bytes, timestamp: int) -> bytes:
        timestamp_str, nonce = self.generate_timestamp_nonce()
        two_fa_code = self.generate_2fa_code(self.secret_key, timestamp_str, nonce)
        hash_value, encrypted_message = self.create_hash(frame, self.secret_key, self.encryption_key, timestamp_str, nonce, two_fa_code)
        encoded_frame = struct.pack("<IQQ64s", channel, timestamp, timestamp_str.encode(), encrypted_message)
        return encoded_frame

def main():
    parser = argparse.ArgumentParser(prog="ectf25_design.encoder")
    parser.add_argument("secrets", type=argparse.FileType("rb"), help="Path to the secrets file")
    parser.add_argument("channel", type=int, help="Channel to encode for")
    parser.add_argument("frame", help="Contents of the frame")
    parser.add_argument("timestamp", type=int, help="64b timestamp to use")
    args = parser.parse_args()

    encoder = Encoder(args.secrets.read())
    encoded_frame = encoder.encode(args.channel, args.frame.encode(), args.timestamp)
    print(repr(encoded_frame))

if __name__ == "__main__":
    main()
