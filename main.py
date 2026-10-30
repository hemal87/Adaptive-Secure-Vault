import os
import hashlib
from datetime import datetime

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64

DATA_FILE = "data.enc"
CONFIG_FILE = "config.txt"
LOG_FILE = "access_log.txt"
FAKE_DATA = "Confidential_Report_2023"
RISK_FILE = "risk_state.txt"
# ---------------- HELPERS ----------------

def get_hash(text):
    return hashlib.sha256(text.encode()).hexdigest()

def log_event(msg):
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.now()} : {msg}\n")

def self_destruct():
    log_event("SELF-DESTRUCT triggered")
    if os.path.exists(DATA_FILE):
        os.remove(DATA_FILE)
    if os.path.exists(CONFIG_FILE):
        os.remove(CONFIG_FILE)
    print("\nSECURITY ALERT: Data destroyed")
    exit()

#  PASSWORD → AES KEY
def derive_key(password: str, salt: bytes):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,          # AES-256
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password.encode())

#  AES-GCM ENCRYPT (STEP-4.1)
def aes_encrypt(plain_text: str, password: str):
    salt = os.urandom(16)
    key = derive_key(password, salt)

    aesgcm = AESGCM(key)
    nonce = os.urandom(12)

    ciphertext = aesgcm.encrypt(
        nonce,
        plain_text.encode(),
        None
    )

    return base64.b64encode(salt + nonce + ciphertext).decode()

def aes_decrypt(enc_text: str, password: str):
    # Decode base64 stored data
    raw = base64.b64decode(enc_text.encode())

    # Extract salt, nonce, and ciphertext
    salt = raw[:16]
    nonce = raw[16:28]
    ciphertext = raw[28:]

    # Derive same AES key using password + salt
    key = derive_key(password, salt)

    aesgcm = AESGCM(key)

    # Decrypt (fails automatically if password or data is wrong)
    return aesgcm.decrypt(
        nonce,
        ciphertext,
        None
    ).decode()

def save_risk(risk):
    with open(RISK_FILE, "w") as f:
        f.write(str(risk))

def load_risk():
    if not os.path.exists(RISK_FILE):
        return 0
    with open(RISK_FILE, "r") as f:
        return int(f.read())
# ---------------- AGENTIC AI SECURITY AGENT ----------------
def get_past_risk():
    if not os.path.exists(LOG_FILE):
        return 0

    risk = 0
    with open(LOG_FILE, "r") as f:
        logs = f.readlines()

    for line in logs[-10:]:   # last 10 events check
        if "Wrong password" in line:
            risk += 1
        if "SELF-DESTRUCT" in line:
            risk += 5

    return risk

class SecurityAgent:
    def __init__(self):
        self.risk_score = load_risk()  # history se start karega

    def observe(self, event):
        if event == "wrong_password":
            self.risk_score += 3
            save_risk(self.risk_score)
        elif event == "rapid_retry":
            self.risk_score += 2
        elif event == "date_mismatch":
            self.risk_score += 5
        elif event == "tampering":
            self.risk_score += 8

        save_risk(self.risk_score)

    def decide(self):
        # Dynamic threshold based on history
        if self.risk_score > 15:
            return "SELF_DESTRUCT"
        elif self.risk_score > 8:
            return "LIMIT_VIEW"
        elif self.risk_score > 3:
            return "FAKE_DATA"
        else:
            return "ALLOW"


# ---------------- SETUP ----------------
def setup():
    print("\n=== SETUP MODE ===")
    data = input("Enter secret data: ")
    password = input("Set password: ")
    max_attempts = int(input("Set maximum allowed attempts: "))
    allowed_date = input("Set allowed date (YYYY-MM-DD): ")

    encrypted_data = aes_encrypt(data, password)
    password_hash = get_hash(password)
    file_hash = get_hash(encrypted_data)

    with open(DATA_FILE, "w") as f:
        f.write(encrypted_data)

    with open(CONFIG_FILE, "w") as f:
        f.write(password_hash + "\n")
        f.write("0\n")
        f.write(str(max_attempts) + "\n")
        f.write(allowed_date + "\n")
        f.write(file_hash)

    print("Setup completed successfully")

# ---------------- ACCESS ----------------
def access():
    agent = SecurityAgent()

    if not os.path.exists(CONFIG_FILE) or not os.path.exists(DATA_FILE):
        print("No secure data found")
        return

    with open(CONFIG_FILE, "r") as f:
        lines = [line.strip() for line in f.readlines()]

    password_hash = lines[0]
    attempts = int(lines[1])
    max_attempts = int(lines[2])
    allowed_date = lines[3]
    original_file_hash = lines[4]

    today = datetime.now().strftime("%Y-%m-%d")
    if today != allowed_date:
        self_destruct()

    password = input("Enter password: ")
    import time

    current_time = time.time()

    if hasattr(access, "attempt_times"):
        access.attempt_times.append(current_time)
    else:
        access.attempt_times = [current_time]

    # last 5 seconds ke attempts
    access.attempt_times = [t for t in access.attempt_times if current_time - t < 5]

    if len(access.attempt_times) >= 3:
        agent.observe("rapid_retry")
   
    if get_hash(password) != password_hash:
        attempts += 1
        log_event("Wrong password")
        agent.observe("wrong_password")
        decision = agent.decide()
        print(f"[Security Agent Risk Score:{agent.risk_score}]")

        with open(CONFIG_FILE, "w") as f:
            f.write(password_hash + "\n")
            f.write(str(attempts) + "\n")
            f.write(str(max_attempts) + "\n")
            f.write(allowed_date + "\n")
            f.write(original_file_hash)
        if decision == "SELF_DESTRUCT":
            self_destruct()

        elif decision == "FAKE_DATA":
            print("\nACCESS DENIED")
            print("Decrypted Data:", FAKE_DATA)
            return

        if attempts >= max_attempts:
            self_destruct()
        print("\nACCESS DENIED")
        print("Decrypted Data:", FAKE_DATA)
        log_event("Fake data shown to unauthorized user")
        return

    with open(DATA_FILE, "r") as f:
        encrypted_data = f.read().strip()

    if get_hash(encrypted_data) != original_file_hash:
        agent.observe("tampering")

        decision = agent.decide()
        print(f"[Security Agent Risk Score: {agent.risk_score}]")
 
        if decision == "SELF_DESTRUCT":
            self_destruct()
        else:
            print("Tampering detected but access denied")
            return

    try:
        decrypted = aes_decrypt(encrypted_data, password)
    except Exception as e:
        print("Decryption failed:", e)
        print("\nACCESS DENIED")
        return

    print(f"[Security Agent Risk Score: {agent.risk_score}]")

    print("\nACCESS GRANTED")
    print("Decrypted Data:", decrypted)
    log_event("Access granted")
    save_risk(0)

# ---------------- MAIN ----------------
print("\n1. Setup Secure Data")
print("2. Access Secure Data")
choice = input("Choose option (1/2): ").strip()

if choice == "1":
    setup()
elif choice == "2":
    access()
else:
    print("Invalid option")

