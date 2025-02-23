import argparse
import struct
import json
from cryptography.fernet import Fernet

class Encoder:
    def __init__(self, secrets: bytes):
        secrets = json.loads(secrets)
        encryption_key = secrets["encryption_key"].encode('utf-8')
        self.cipher = Fernet(encryption_key)
        self.some_secrets = secrets["some_secrets"]

    def encode(self, channel: int, frame: bytes, timestamp: int) -> bytes:
        data = struct.pack("<IQ", channel, timestamp) + frame
        encrypted_frame = self.cipher.encrypt(data)
        return encrypted_frame

def main():
    parser = argparse.ArgumentParser(prog="ectf25_design.encoder")
    parser.add_argument("secrets_file", type=argparse.FileType("rb"), help="Path to the secrets file")
    parser.add_argument("channel", type=int, help="Channel to encode for")
    parser.add_argument("frame", help="Contents of the frame")
    parser.add_argument("timestamp", type=int, help="64b timestamp to use")
    args = parser.parse_args()

    encoder = Encoder(args.secrets_file.read())
    print(repr(encoder.encode(args.channel, args.frame.encode(), args.timestamp)))

if __name__ == "__main__":
    main()

