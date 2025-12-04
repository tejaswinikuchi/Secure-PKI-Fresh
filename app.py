import base64
import binascii
import pyotp
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


# -----------------------------
# Load RSA Private Key
# -----------------------------
def load_private_key():
    with open("student_private.pem", "rb") as f:
        key_data = f.read()

    private_key = serialization.load_pem_private_key(
        key_data,
        password=None
    )
    return private_key


# -----------------------------
# Decrypt seed using RSA/OAEP
# -----------------------------
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
        raise ValueError("Invalid seed length")

    allowed = "0123456789abcdef"
    for c in seed.lower():
        if c not in allowed:
            raise ValueError("Seed contains non-hex characters")

    return seed.lower()


# -----------------------------
# Save seed to /data/seed.txt
# -----------------------------
def save_seed(seed: str):
    os.makedirs("/data", exist_ok=True)      # critical fix
    path = "/data/seed.txt"                  # critical fix

    with open(path, "w") as f:
        f.write(seed)

    print(f"Seed stored successfully at {path}")


# -----------------------------
# Internal seed validator
# -----------------------------
def _validate_hex_seed(hex_seed: str) -> bytes:
    s = hex_seed.strip().lower()

    if len(s) != 64:
        raise ValueError("Seed must be 64 hex chars")

    allowed = "0123456789abcdef"
    for c in s:
        if c not in allowed:
            raise ValueError("Seed contains non-hex characters")

    return binascii.unhexlify(s)


# -----------------------------
# Generate TOTP
# -----------------------------
def generate_totp_code(hex_seed: str) -> str:
    seed_bytes = _validate_hex_seed(hex_seed)
    base32_seed = base64.b32encode(seed_bytes).decode().replace("=", "").upper()
    totp = pyotp.TOTP(base32_seed, digits=6, interval=30)
    return totp.now()


# -----------------------------
# Verify TOTP
# -----------------------------
def verify_totp_code(hex_seed: str, code: str, valid_window: int = 1) -> bool:
    seed_bytes = _validate_hex_seed(hex_seed)
    base32_seed = base64.b32encode(seed_bytes).decode().replace("=", "").upper()
    totp = pyotp.TOTP(base32_seed, digits=6, interval=30)
    return totp.verify(code, valid_window=valid_window)


# -----------------------------
# Local test only
# -----------------------------
def main():
    print("Running local decrypt...")

    with open("encrypted_seed.txt", "r") as f:
        encrypted_seed_b64 = f.read().strip()

    private_key = load_private_key()
    seed = decrypt_seed(encrypted_seed_b64, private_key)

    save_seed(seed)
    print("Decrypted seed:", seed)
    print("Current TOTP:", generate_totp_code(seed))


if __name__ == "__main__":
    main()
