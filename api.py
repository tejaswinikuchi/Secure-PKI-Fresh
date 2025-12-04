# api.py
import os
import time
import base64
import binascii
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from pydantic import BaseModel
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
import pyotp

# Config
PRIVATE_KEY_PATH = Path("student_private.pem")  # must exist
SEED_PATH = Path("data") / "seed.txt"
TOTP_INTERVAL = 30
TOTP_DIGITS = 6
TOTP_VALID_WINDOW = 1  # ±1 interval for verification

app = FastAPI(title="Secure-PKI Microservice - API")


# -------------------------
# Models
# -------------------------
class DecryptRequest(BaseModel):
    encrypted_seed: str


class VerifyRequest(BaseModel):
    code: Optional[str] = None


# -------------------------
# Helpers
# -------------------------
def load_private_key(path: Path):
    if not path.exists():
        raise FileNotFoundError(f"Private key not found: {path}")
    data = path.read_bytes()
    key = serialization.load_pem_private_key(data, password=None)
    return key


def save_seed_to_file(hex_seed: str):
    SEED_PATH.parent.mkdir(parents=True, exist_ok=True)
    # ensure one-line hex
    SEED_PATH.write_text(hex_seed.strip())
    # Optionally set permissions on unix-like systems; on Windows this no-ops gracefully
    try:
        SEED_PATH.chmod(0o600)
    except Exception:
        pass


def read_seed_from_file() -> str:
    if not SEED_PATH.exists():
        raise FileNotFoundError("Seed not decrypted yet")
    s = SEED_PATH.read_text().strip()
    if len(s) != 64:
        raise ValueError("Saved seed invalid")
    return s.lower()


def decrypt_seed_b64_with_private(encrypted_seed_b64: str, private_key) -> str:
    # 1. base64 decode
    try:
        ciphertext = base64.b64decode(encrypted_seed_b64)
    except Exception as e:
        raise ValueError("Base64 decode failed") from e

    # 2. RSA/OAEP decrypt with SHA-256
    try:
        plaintext_bytes = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            )
        )
    except Exception as e:
        raise ValueError("Decryption failed") from e

    # 3. decode to UTF-8
    try:
        plaintext = plaintext_bytes.decode("utf-8").strip()
    except Exception as e:
        raise ValueError("Decrypted bytes not valid UTF-8") from e

    # 4. validate hex seed
    if len(plaintext) != 64:
        raise ValueError("Decrypted seed length invalid")
    allowed = set("0123456789abcdef")
    if any(ch not in allowed for ch in plaintext.lower()):
        raise ValueError("Decrypted seed contains non-hex characters")

    return plaintext.lower()


def hex_to_base32_no_padding(hex_seed: str) -> str:
    # hex -> bytes -> base32 string with no padding uppercase (pyotp expects this)
    b = binascii.unhexlify(hex_seed)
    b32 = base64.b32encode(b).decode("utf-8").replace("=", "").upper()
    return b32


def generate_totp(hex_seed: str) -> str:
    b32 = hex_to_base32_no_padding(hex_seed)
    totp = pyotp.TOTP(b32, digits=TOTP_DIGITS, interval=TOTP_INTERVAL)
    return totp.now()


def verify_totp(hex_seed: str, code: str, valid_window: int = TOTP_VALID_WINDOW) -> bool:
    b32 = hex_to_base32_no_padding(hex_seed)
    totp = pyotp.TOTP(b32, digits=TOTP_DIGITS, interval=TOTP_INTERVAL)
    try:
        return totp.verify(code, valid_window=valid_window)
    except Exception:
        return False


# -------------------------
# Endpoints
# -------------------------
@app.post("/decrypt-seed")
async def post_decrypt_seed(req: DecryptRequest):
    """
    Expects JSON: { "encrypted_seed": "BASE64..." }
    Will decrypt using student_private.pem and save to data/seed.txt
    """
    # Load private key
    try:
        private_key = load_private_key(PRIVATE_KEY_PATH)
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail={"error": "Private key not found"})
    except Exception:
        raise HTTPException(status_code=500, detail={"error": "Failed to load private key"})

    # Decrypt and validate
    try:
        hex_seed = decrypt_seed_b64_with_private(req.encrypted_seed, private_key)
    except ValueError as e:
        # Return 500 per spec when decryption fails
        raise HTTPException(status_code=500, detail={"error": "Decryption failed"})
    except Exception:
        raise HTTPException(status_code=500, detail={"error": "Decryption failed"})

    # Save to /data/seed.txt
    try:
        save_seed_to_file(hex_seed)
    except Exception:
        raise HTTPException(status_code=500, detail={"error": "Failed to save seed"})

    return {"status": "ok"}


@app.get("/generate-2fa")
async def get_generate_2fa():
    """
    Returns current TOTP code and remaining seconds in period.
    Response: { "code": "123456", "valid_for": 30 }
    """
    # Check seed exists
    try:
        hex_seed = read_seed_from_file()
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail={"error": "Seed not decrypted yet"})
    except Exception:
        raise HTTPException(status_code=500, detail={"error": "Seed not decrypted yet"})

    # Generate code
    try:
        code = generate_totp(hex_seed)
    except Exception:
        raise HTTPException(status_code=500, detail={"error": "Failed to generate code"})

    # remaining seconds in current period (0-29)
    now = time.time()
    elapsed = int(now) % TOTP_INTERVAL
    remaining = TOTP_INTERVAL - elapsed
    if remaining == TOTP_INTERVAL:
        remaining = 0

    return {"code": code, "valid_for": remaining}


@app.post("/verify-2fa")
async def post_verify_2fa(req: VerifyRequest):
    """
    Verify posted TOTP code.
    Request: { "code": "123456" }
    """
    if not req.code:
        raise HTTPException(status_code=400, detail={"error": "Missing code"})

    try:
        hex_seed = read_seed_from_file()
    except FileNotFoundError:
        raise HTTPException(status_code=500, detail={"error": "Seed not decrypted yet"})
    except Exception:
        raise HTTPException(status_code=500, detail={"error": "Seed not decrypted yet"})

    try:
        valid = verify_totp(hex_seed, req.code, valid_window=TOTP_VALID_WINDOW)
    except Exception:
        raise HTTPException(status_code=500, detail={"error": "Verification failed"})

    return {"valid": bool(valid)}
