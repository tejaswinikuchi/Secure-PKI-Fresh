import requests
import json

API_URL = "https://eajeyq4r3zljoq4rpovy2nthda0vtjqf.lambda-url.ap-south-1.on.aws"

def request_seed():
    student_id = input("Enter your student ID: ").strip()
    github_repo_url = input("Enter your GitHub repo URL: ").strip()

    print("\nRequesting encrypted seed from instructor API...\n")

    # IMPORTANT: Read PEM EXACTLY AS IS
    with open("student_public.pem", "r") as f:
        public_key = f.read()

    payload = {
        "student_id": student_id,
        "github_repo_url": github_repo_url,
        "public_key": public_key
    }

    headers = {"Content-Type": "application/json"}

    try:
        response = requests.post(API_URL, json=payload, headers=headers)
        data = response.json()

        if "encrypted_seed" in data:
            print("Success! Encrypted seed received.")
            with open("encrypted_seed.txt", "w") as seed_file:
                seed_file.write(data["encrypted_seed"])
            print("Saved to encrypted_seed.txt")
        else:
            print("Error:", json.dumps(data))

    except Exception as e:
        print("Exception occurred:", str(e))

if __name__ == "__main__":
    request_seed()
