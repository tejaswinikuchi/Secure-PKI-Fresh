#!/usr/bin/env python3

import os
import base64
import binascii
import pyotp
from datetime import datetime, timezone

def generate_totp_from_hex(hex_seed: str) -> str:
    """Convert hex → base32 → TOTP code"""
    seed_bytes = binascii.unhexlify(hex_seed)
    base32_seed = base64.b32encode(seed_bytes).decode("utf-8").replace("=", "")
    totp = pyotp.TOTP(base32_seed)
    return totp.now()

def main():
    seed_path = "/data/seed.txt"

    # 1. Read seed
    if not os.path.exists(seed_path):
        print("Seed not found. Run /decrypt-seed first.")
        return

    with open(seed_path, "r") as f:
        hex_seed = f.read().strip()

    # 2. Generate TOTP
    try:
        code = generate_totp_from_hex(hex_seed)
    except Exception as e:
        print(f"Error generating TOTP: {e}")
        return

    # 3. Current UTC timestamp
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:MM:%S")

    # 4. Output for cron
    print(f"{timestamp} - 2FA Code: {code}")

if __name__ == "__main__":
    main()
