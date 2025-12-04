import base64
import binascii
import pyotp
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


# ----------------------------------------------------------
# STEP 1 — Load RSA Private Key
# ----------------------------------------------------------
def load_private_key():
    with open("student_private.pem", "rb") as f:
        key_data = f.read()

    private_key = serialization.load_pem_private_key(
        key_data,
        password=None
    )
    return private_key


# ----------------------------------------------------------
# STEP 2 — Decrypt seed using RSA/OAEP SHA-256
# ----------------------------------------------------------
def decrypt_seed(encrypted_seed_b64: str, private_key) -> str:
    """
    Decrypt base64-encoded encrypted seed using RSA/OAEP with SHA-256
    and return a validated 64-character hex string.
    """

    # 1. Base64 decode
    ciphertext = base64.b64decode(encrypted_seed_b64)

    # 2. RSA/OAEP decrypt (SHA-256)
    decrypted_bytes = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # 3. Convert bytes to UTF-8
    seed = decrypted_bytes.decode("utf-8").strip()

    # 4. Validate 64-char lowercase hex
    if len(seed) != 64:
        raise ValueError(f"Seed length invalid: expected 64, got {len(seed)}")

    allowed = "0123456789abcdef"
    for c in seed.lower():
        if c not in allowed:
            raise ValueError("Seed contains non-hex characters")

    return seed.lower()


# ----------------------------------------------------------
# STEP 3 — Save seed to data/seed.txt
# ----------------------------------------------------------
def save_seed(seed: str):
    os.makedirs("data", exist_ok=True)
    path = os.path.join("data", "seed.txt")

    with open(path, "w") as f:
        f.write(seed)

    print(f"Seed stored successfully at {path}")


# ----------------------------------------------------------
# STEP 6 — TOTP Helper: Validate hex seed
# ----------------------------------------------------------
def _validate_hex_seed(hex_seed: str) -> bytes:
    """Validate 64-char hex seed and return bytes."""
    if not isinstance(hex_seed, str):
        raise ValueError("hex_seed must be a string")

    s = hex_seed.strip().lower()

    if len(s) != 64:
        raise ValueError(f"hex_seed must be 64 hex characters (got {len(s)})")

    allowed = "0123456789abcdef"
    for c in s:
        if c not in allowed:
            raise ValueError("hex_seed contains non-hex characters")

    return binascii.unhexlify(s)


# ----------------------------------------------------------
# STEP 6 — Generate TOTP Code
# ----------------------------------------------------------
def generate_totp_code(hex_seed: str) -> str:
    """
    Generate current 6-digit TOTP code.
    Algorithm: SHA1 (default), interval: 30 sec, digits: 6.
    """
    seed_bytes = _validate_hex_seed(hex_seed)

    # Convert bytes → Base32 (uppercase, no padding)
    base32_seed = base64.b32encode(seed_bytes).decode("utf-8").replace("=", "").upper()

    totp = pyotp.TOTP(base32_seed, digits=6, interval=30)
    return totp.now()


# ----------------------------------------------------------
# STEP 6 — Verify TOTP Code
# ----------------------------------------------------------
def verify_totp_code(hex_seed: str, code: str, valid_window: int = 1) -> bool:
    """
    Verify TOTP code with ± valid_window intervals (default ±30 seconds)
    """
    seed_bytes = _validate_hex_seed(hex_seed)
    base32_seed = base64.b32encode(seed_bytes).decode("utf-8").replace("=", "").upper()

    totp = pyotp.TOTP(base32_seed, digits=6, interval=30)

    try:
        return totp.verify(code, valid_window=valid_window)
    except Exception:
        return False


# ----------------------------------------------------------
# STEP 4 — Main Flow (Decrypt + Save)
# ----------------------------------------------------------
def main():
    # Read encrypted seed from file
    with open("encrypted_seed.txt", "r") as f:
        encrypted_seed_b64 = f.read().strip()

    private_key = load_private_key()
    seed = decrypt_seed(encrypted_seed_b64, private_key)

    save_seed(seed)

    print("Decryption completed successfully!")
    print("Decrypted seed:", seed)

    # Also show current TOTP code (optional)
    print("Current TOTP Code:", generate_totp_code(seed))


if __name__ == "__main__":
    main()
