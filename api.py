from fastapi import FastAPI, HTTPException
import time
import os

from app import (
    load_private_key,
    decrypt_seed,
    save_seed,
    generate_totp_code,
    verify_totp_code,
)

app = FastAPI()


# -----------------------------
# POST /decrypt-seed
# -----------------------------
@app.post("/decrypt-seed")
def decrypt_seed_api(request: dict):
    if "encrypted_seed" not in request:
        raise HTTPException(status_code=400, detail="Missing encrypted_seed")

    encrypted_seed = request["encrypted_seed"]

    try:
        private_key = load_private_key()
        seed = decrypt_seed(encrypted_seed, private_key)

        save_seed(seed)   # <--- CRITICAL: writes to /data/seed.txt

        return {"status": "ok"}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Decryption failed: {str(e)}")


# -----------------------------
# GET /generate-2fa
# -----------------------------
@app.get("/generate-2fa")
def generate_2fa_api():
    seed_path = "/data/seed.txt"

    if not os.path.exists(seed_path):
        raise HTTPException(status_code=500, detail="Seed not decrypted yet")

    with open(seed_path, "r") as f:
        seed = f.read().strip()

    code = generate_totp_code(seed)

    # seconds remaining in current 30–second window
    valid_for = 30 - (int(time.time()) % 30)

    return {"code": code, "valid_for": valid_for}


# -----------------------------
# POST /verify-2fa
# -----------------------------
@app.post("/verify-2fa")
def verify_2fa_api(request: dict):
    if "code" not in request:
        raise HTTPException(status_code=400, detail="Missing code")

    seed_path = "/data/seed.txt"
    if not os.path.exists(seed_path):
        raise HTTPException(status_code=500, detail="Seed not decrypted yet")

    with open(seed_path, "r") as f:
        seed = f.read().strip()

    is_valid = verify_totp_code(seed, request["code"], valid_window=1)

    return {"valid": is_valid}
