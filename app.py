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
    # IMPORTANT: Use absolute path inside container
    with open("/app/student_private.pem", "rb") as f:
        key_data = f.read()

    private_key = serialization.load_pem_private_key(
        key_data,
        password=None
    )
    return private_key


# ----------------------------------------------------------
# STEP 2 — Decrypt seed with RSA/OAEP-SHA256
# ----------------------------------------------------------
def decrypt_seed(encrypted_seed_b64: str, private_key) -> str:
    ciphertext = base64.b64decode(encrypted_seed_b64)

    decrypted_bytes = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    seed = decrypted_bytes.decode("utf-8").strip()

    # Validate 64-char hex
    if len(seed) != 64:
        raise ValueError(f"Invalid seed length: expected 64, got {len(seed)}")

    if not all(c in "0123456789abcdef" for c in seed.lower()):
        raise ValueError("Seed contains invalid hex characters")

    return seed.lower()


# ----------------------------------------------------------
# STEP 3 — Save seed to /data/seed.txt (Docker volume)
# ----------------------------------------------------------
def save_seed(seed: str):
    # /data is the Docker volume mount
    os.makedirs("/data", exist_ok=True)
    path = "/data/seed.txt"

    with open(path, "w") as f:
        f.write(seed)

    print(f"Seed stored successfully at {path}")


# ----------------------------------------------------------
# Helper: Validate hex seed
# ----------------------------------------------------------
def _validate_hex_seed(hex_seed: str) -> bytes:
    s = hex_seed.strip().lower()

    if len(s) != 64:
        raise ValueError(f"hex_seed must be 64 characters (got {len(s)})")

    if not all(c in "0123456789abcdef" for c in s):
        raise ValueError("hex_seed contains invalid characters")

    return binascii.unhexlify(s)


# ----------------------------------------------------------
# Generate TOTP Code
# ----------------------------------------------------------
def generate_totp_code(hex_seed: str) -> str:
    seed_bytes = _validate_hex_seed(hex_seed)
    base32_seed = base64.b32encode(seed_bytes).decode("utf-8").replace("=", "").upper()

    totp = pyotp.TOTP(base32_seed, digits=6, interval=30)
    return totp.now()


# ----------------------------------------------------------
# Verify TOTP Code
# ----------------------------------------------------------
def verify_totp_code(hex_seed: str, code: str, valid_window: int = 1) -> bool:
    seed_bytes = _validate_hex_seed(hex_seed)
    base32_seed = base64.b32encode(seed_bytes).decode("utf-8").replace("=", "").upper()

    totp = pyotp.TOTP(base32_seed, digits=6, interval=30)

    try:
        return totp.verify(code, valid_window=valid_window)
    except Exception:
        return False


# ----------------------------------------------------------
# MAIN — Used only when running locally, not in Docker
# ----------------------------------------------------------
def main():
    print("Running local decrypt...")

    with open("encrypted_seed.txt", "r") as f:
        encrypted_seed_b64 = f.read().strip()

    private_key = load_private_key()
    seed = decrypt_seed(encrypted_seed_b64, private_key)

    save_seed(seed)

    print("Decryption successful!")
    print("Seed:", seed)
    print("Current TOTP:", generate_totp_code(seed))


if __name__ == "__main__":
    main()
