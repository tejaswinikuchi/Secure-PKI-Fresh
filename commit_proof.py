import base64
import subprocess
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding


# --------------------------------------------------------
# Load Student Private Key
# --------------------------------------------------------
def load_private_key():
    with open("student_private.pem", "rb") as f:
        key_data = f.read()

    private_key = serialization.load_pem_private_key(
        key_data,
        password=None
    )
    return private_key


# --------------------------------------------------------
# Load Instructor Public Key
# --------------------------------------------------------
def load_instructor_public_key():
    with open("instructor_public.pem", "rb") as f:
        key_data = f.read()

    public_key = serialization.load_pem_public_key(key_data)
    return public_key


# --------------------------------------------------------
# STEP 1 — Sign Commit Hash (RSA-PSS SHA-256)
# --------------------------------------------------------
def sign_message(message: str, private_key) -> bytes:
    """
    Sign commit hash using RSA-PSS with SHA256.
    - message MUST be ASCII string (40-char commit hash)
    """

    message_bytes = message.encode("utf-8")

    signature = private_key.sign(
        message_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return signature


# --------------------------------------------------------
# STEP 2 — Encrypt Signature with Instructor Public Key
# --------------------------------------------------------
def encrypt_with_public_key(data: bytes, public_key) -> bytes:
    ciphertext = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return ciphertext


# --------------------------------------------------------
# STEP 3 — Get Latest Commit Hash
# --------------------------------------------------------
def get_latest_commit_hash() -> str:
    commit_hash = subprocess.check_output(
        ["git", "log", "-1", "--format=%H"]
    ).decode("utf-8").strip()

    if len(commit_hash) != 40:
        raise ValueError("Commit hash must be a 40-character hex string")

    return commit_hash


# --------------------------------------------------------
# MAIN PROGRAM — Generate Commit Proof
# --------------------------------------------------------
def main():
    print("Generating commit proof...")

    # 1. Get commit hash
    commit_hash = get_latest_commit_hash()
    print("Commit Hash:", commit_hash)

    # 2. Load keys
    private_key = load_private_key()
    instructor_pub = load_instructor_public_key()

    # 3. Sign commit hash
    signature = sign_message(commit_hash, private_key)

    # 4. Encrypt signature
    encrypted_signature = encrypt_with_public_key(signature, instructor_pub)

    # 5. Base64 encode
    proof_b64 = base64.b64encode(encrypted_signature).decode("utf-8")

    print("\n===== SUBMIT THIS AS YOUR PROOF =====")
    print("Commit Hash:", commit_hash)
    print("Encrypted Signature:", proof_b64)
    print("=====================================\n")


if __name__ == "__main__":
    main()
