import json
import argparse

def generate_subscription(secrets_file, subscription_file, decoder_id, start_time, end_time, channel):
    with open(secrets_file, "r") as f:
        secrets = json.load(f)
    
    subscription = {
        "decoder_id": decoder_id,
        "start_timestamp": start_time,
        "end_timestamp": end_time,
        "channel": channel
    }
    
    with open(subscription_file, "w") as f:
        json.dump(subscription, f, indent=4)

def main():
    parser = argparse.ArgumentParser(description="Generate subscription update")
    parser.add_argument("secrets", type=str, help="Path to the secrets file")
    parser.add_argument("output", type=str, help="Output subscription file")
    parser.add_argument("decoder_id", type=int, help="Decoder ID")
    parser.add_argument("start_time", type=int, help="Start timestamp")
    parser.add_argument("end_time", type=int, help="End timestamp")
    parser.add_argument("channel", type=int, help="Channel ID")
    args = parser.parse_args()

    generate_subscription(args.secrets, args.output, args.decoder_id, args.start_time, args.end_time, args.channel)

if __name__ == "__main__":
    main()
