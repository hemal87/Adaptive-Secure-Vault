import tkinter as tk
from tkinter import filedialog, messagebox
import os
import json
import time
import hashlib
import socket
import threading
import requests
import zipfile
import io
from datetime import datetime
from tkinter import simpledialog

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes


# ================= CONFIGURATION =================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
RISK_FILE = os.path.join(BASE_DIR, "risk_state.json")
AUDIT_FILE = os.path.join(BASE_DIR, "access_log.txt")

RISK_THRESHOLD = 100
RAPID_RETRY_SECONDS = 10
ANOMALY_FILE = os.path.join(BASE_DIR, "anomaly_model.json")
LOCK_FILE = os.path.join(BASE_DIR, "emergency_lock.json")

TRANSFER_PORT = 5055
RELAY_URL = "https://adaptive-secure-vault-relay.onrender.com"
MAX_TRANSFER_SIZE = 50 * 1024 * 1024

selected_file = ""
recent_attempt_times = []


# ================= UTILITY FUNCTIONS =================

def now_text():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def sha256_file(path):
    digest = hashlib.sha256()

    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)

    return digest.hexdigest()


def log_event(event, details=""):
    details = str(details).replace("\n", " ")

    with open(AUDIT_FILE, "a", encoding="utf-8") as f:
        f.write(f"{now_text()} | {event} | {details}\n")


def save_json(path, data):
    temp_path = path + ".tmp"

    with open(temp_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

    os.replace(temp_path, path)


def load_risk_state():
    default = {
        "risk_score": 0,
        "events": 0,
        "last_event": ""
    }

    if not os.path.exists(RISK_FILE):
        return default

    try:
        with open(RISK_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)

        return {
            "risk_score": max(
                0, min(100, int(data.get("risk_score", 0)))
            ),
            "events": max(0, int(data.get("events", 0))),
            "last_event": str(data.get("last_event", ""))
        }

    except (OSError, ValueError, TypeError, json.JSONDecodeError):
        return default


# ================= SECURITY AGENT =================

class SecurityAgent:

    def evaluate(
        self,
        event,
        rapid=False,
        integrity_failure=False
    ):
        state = load_risk_state()
        score = state["risk_score"]

        if event == "wrong_password":
            score += 25

        elif event == "successful_access":
            score = max(0, score - 10)

        elif event == "access_denied_date":
            score += 5

        if rapid:
            score += 20

        if integrity_failure:
            score = 100

        score = max(0, min(100, score))

        state["risk_score"] = score
        state["events"] += 1
        state["last_event"] = now_text()

        save_json(RISK_FILE, state)

        return score


security_agent = SecurityAgent()


# ================= PBKDF2 KEY DERIVATION =================

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000
    )

    return kdf.derive(password.encode("utf-8"))


# ================= SELECT FILE =================

def select_file():
    global selected_file

    if mode.get() == "setup":
        path = filedialog.askopenfilename(
            title="Select File to Encrypt"
        )
    else:
        path = filedialog.askopenfilename(
            title="Select Encrypted File",
            filetypes=[("Encrypted Files", "*.enc")]
        )

    if path:
        selected_file = path

        file_label.config(
            text="Selected: " + os.path.basename(path)
        )

        status.config(text="File selected", fg="lightgreen")

        log_event("file_selected", os.path.basename(path))


# ================= ENCRYPT FILE =================

def encrypt_file():
    if not selected_file or not os.path.isfile(selected_file):
        messagebox.showerror("Error", "Select a file first!")
        return

    password = password_entry.get()

    if not password:
        messagebox.showerror("Error", "Enter a password!")
        return

    access_date = date_entry.get().strip()

    try:
        datetime.strptime(access_date, "%Y-%m-%d")

        max_attempts = int(attempt_entry.get())

        if max_attempts < 1:
            raise ValueError

    except ValueError:
        messagebox.showerror(
            "Invalid Settings",
            "Enter date as YYYY-MM-DD and attempts as a positive integer."
        )
        return

    try:
        with open(selected_file, "rb") as f:
            data = f.read()

        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = derive_key(password, salt)

        ciphertext = AESGCM(key).encrypt(nonce, data, None)

        output_file = selected_file + ".enc"
        config_path = output_file + ".asv.json"

        with open(output_file, "wb") as f:
            f.write(salt + nonce + ciphertext)

        settings = {
            "allowed_date": access_date,
            "max_attempts": max_attempts,
            "attempts_used": 0,
            "locked": False,
            "encrypted_sha256": sha256_file(output_file),
            "original_filename": os.path.basename(selected_file)
        }

        save_json(config_path, settings)

        password_entry.delete(0, tk.END)

        status.config(
            text="Encryption successful!",
            fg="lightgreen"
        )

        log_event("encryption_success", os.path.basename(output_file))

        messagebox.showinfo(
            "Success",
            f"Encrypted file:\n{output_file}\n\n"
            f"Settings file:\n{config_path}"
        )

    except Exception as e:
        log_event("encryption_error", e)
        messagebox.showerror("Encryption Error", str(e))

# ================= CLOUD UPLOAD =================

def upload_to_cloud():
    if not selected_file or not selected_file.endswith(".enc"):
        messagebox.showerror("Error", "Select an encrypted .enc file first!")
        return

    config_path = selected_file + ".asv.json"

    if not os.path.isfile(config_path):
        messagebox.showerror(
            "Missing Settings",
            "Associated .asv.json file not found!"
        )
        return

    try:
        with open(selected_file, "rb") as enc_file, \
             open(config_path, "rb") as settings_file:

            files = {
                "file": (
                    os.path.basename(selected_file),
                    enc_file,
                    "application/octet-stream"
                ),
                "settings": (
                    os.path.basename(config_path),
                    settings_file,
                    "application/json"
                )
            }

            response = requests.post(
                RELAY_URL + "/upload",
                files=files,
                timeout=120
            )

        if response.status_code != 201:
            raise ValueError(response.text)

        result = response.json()

        transfer_id = result["transfer_id"]
        download_token = result["download_token"]

        log_event("cloud_upload_success", transfer_id)

        popup = tk.Toplevel(root)
        popup.title("Upload Successful")
        popup.geometry("500x300")
        popup.resizable(False, False)
        popup.grab_set()

        tk.Label(
            popup,
            text="Upload Successful!",
            font=("Arial", 14, "bold")
        ).pack(pady=10)

        tk.Label(popup, text="Transfer ID:").pack()

        id_entry = tk.Entry(popup, width=65)
        id_entry.pack(pady=5)
        id_entry.insert(0, transfer_id)
        id_entry.config(state="readonly")

        def copy_id():
            popup.clipboard_clear()
            popup.clipboard_append(transfer_id)
            messagebox.showinfo("Copied", "Transfer ID copied!")

        tk.Button(
            popup,
            text="Copy Transfer ID",
            command=copy_id
        ).pack(pady=5)

        tk.Label(popup, text="Download Token:").pack()

        token_entry = tk.Entry(popup, width=65)
        token_entry.pack(pady=5)
        token_entry.insert(0, download_token)
        token_entry.config(state="readonly")

        def copy_token():
            popup.clipboard_clear()
            popup.clipboard_append(download_token)
            messagebox.showinfo("Copied", "Download Token copied!")

        tk.Button(
            popup,
            text="Copy Download Token",
            command=copy_token
        ).pack(pady=5)

        tk.Label(
            popup,
            text="Expires in 30 minutes.",
            fg="red"
        ).pack(pady=8)

    except Exception as e:
        log_event("cloud_upload_error", str(e))
        messagebox.showerror("Cloud Upload Error", str(e))

        
# ================= CLOUD DOWNLOAD =================

def download_from_cloud():

    transfer_id = simpledialog.askstring(
        "Cloud Download",
        "Enter Transfer ID:"
    )

    if not transfer_id:
        return

    token = simpledialog.askstring(
        "Download Authentication",
        "Enter Download Token:",
        show="*"
    )

    if not token:
        return

    try:
        response = requests.get(
            f"{RELAY_URL}/download/{transfer_id.strip()}",
            headers={"X-Transfer-Token": token.strip()},
            timeout=120
        )

        if response.status_code != 200:
            raise ValueError(response.text)

        buffer = io.BytesIO(response.content)

        with zipfile.ZipFile(buffer, "r") as archive:

            names = archive.namelist()

            enc_files = [
                n for n in names
                if n.endswith(".enc") and "/" not in n and "\\" not in n
            ]

            if len(names) != 2 or len(enc_files) != 1:
                raise ValueError("Invalid transfer package!")

            enc_name = enc_files[0]
            settings_name = enc_name + ".asv.json"

            if settings_name not in names:
                raise ValueError("Settings file missing!")

            output_dir = filedialog.askdirectory(
                title="Select Download Location"
            )

            if not output_dir:
                return

            enc_path = os.path.join(output_dir, enc_name)
            settings_path = enc_path + ".asv.json"

            if os.path.exists(enc_path) or os.path.exists(settings_path):
                raise ValueError("Files already exist in this folder!")

            with open(enc_path, "wb") as f:
                f.write(archive.read(enc_name))

            with open(settings_path, "wb") as f:
                f.write(archive.read(settings_name))

        log_event("cloud_download_success", transfer_id)

        messagebox.showinfo(
            "Download Successful",
            f"Encrypted file received:\n{enc_path}\n\n"
            "You can now select this .enc file and decrypt it."
        )

    except Exception as e:
        log_event("cloud_download_error", str(e))
        messagebox.showerror("Download Error", str(e))
        
# ================= RAPID RETRY DETECTION =================

def note_failed_attempt(settings, config_path):
    global recent_attempt_times

    current_time = time.time()

    recent_attempt_times = [
        t for t in recent_attempt_times
        if current_time - t <= RAPID_RETRY_SECONDS
    ]

    recent_attempt_times.append(current_time)

    rapid = len(recent_attempt_times) >= 3

    score = security_agent.evaluate(
        "wrong_password",
        rapid=rapid
    )

    settings["attempts_used"] += 1

    if (
        settings["attempts_used"] >= settings["max_attempts"]
        or score >= RISK_THRESHOLD
    ):
        settings["locked"] = True

    save_json(config_path, settings)

    remaining = max(
        0,
        settings["max_attempts"] - settings["attempts_used"]
    )

    log_event(
        "wrong_password",
        f"remaining={remaining}; risk={score}; rapid_retry={rapid}"
    )

    return remaining, score, rapid


# ================= FILE INTEGRITY VERIFICATION =================

def verify_file_integrity(path, settings):
    expected_hash = settings.get("encrypted_sha256")

    if not expected_hash:
        return False

    return sha256_file(path) == expected_hash


# ================= DECRYPT FILE =================

def decrypt_file():
    if is_vault_locked():
        messagebox.showerror(
            "Emergency Lockdown",
            "Vault is locked after a security event."
        )
        log_event("decryption_blocked_emergency_lock")
        return

    path = selected_file

    if (
        not path
        or not os.path.isfile(path)
        or not path.endswith(".enc")
    ):
        messagebox.showerror("Error", "Select a valid .enc file!")
        return

    config_path = path + ".asv.json"

    if not os.path.isfile(config_path):
        messagebox.showerror(
            "Settings Not Found",
            "Settings file missing. Encrypt the original file again."
        )
        log_event("settings_missing", os.path.basename(path))
        return

    try:
        with open(config_path, "r", encoding="utf-8") as f:
            settings = json.load(f)

        required = [
            "allowed_date",
            "max_attempts",
            "attempts_used",
            "encrypted_sha256"
        ]

        if any(key not in settings for key in required):
            messagebox.showerror(
                "Invalid Settings",
                "Settings incomplete. Encrypt the original file again."
            )
            return

        if (
            settings.get("locked", False)
            or settings["attempts_used"] >= settings["max_attempts"]
        ):
            settings["locked"] = True
            save_json(config_path, settings)

            log_event("access_blocked_locked", os.path.basename(path))

            messagebox.showerror(
                "Access Locked",
                "Maximum password attempts exceeded!"
            )
            return

        today = datetime.now().strftime("%Y-%m-%d")

        if today != settings["allowed_date"]:
            score = security_agent.evaluate("access_denied_date")

            log_event("access_denied_date", f"risk={score}")

            status.config(
                text="Access denied: Date mismatch",
                fg="red"
            )

            messagebox.showerror(
                "Access Denied",
                f"Allowed date: {settings['allowed_date']}\n"
                f"Today's date: {today}"
            )
            return

        if not verify_file_integrity(path, settings):
            score = security_agent.evaluate(
                "wrong_password",
                integrity_failure=True
            )

            log_event("integrity_failure", f"risk={score}")

            status.config(text="Integrity check failed!", fg="red")

            messagebox.showerror(
                "Integrity Failure",
                "Encrypted file has been modified. Decryption blocked."
            )
            return

        password = password_entry.get()

        if not password:
            messagebox.showerror("Error", "Enter the password!")
            return

        with open(path, "rb") as f:
            raw = f.read()

        if len(raw) < 29:
            messagebox.showerror(
                "Error", "Encrypted file is invalid or damaged."
            )
            return

        salt = raw[:16]
        nonce = raw[16:28]
        ciphertext = raw[28:]

        key = derive_key(password, salt)

        try:
            decrypted_data = AESGCM(key).decrypt(
                nonce, ciphertext, None
            )

        except Exception:
            remaining, score, rapid = note_failed_attempt(
                settings, config_path
            )

            anomaly_score = detect_anomaly(
                len(recent_attempt_times),
                (
                    time.time() - recent_attempt_times[-2]
                    if len(recent_attempt_times) > 1
                    else 10
                )
            )

            response = adaptive_security_response(
                score, anomaly_score
            )

            if response == "EMERGENCY_LOCKDOWN":
                emergency_lockdown(
                    f"Adaptive response after failed access; "
                    f"risk={score}; anomaly={anomaly_score}"
                )

            password_entry.delete(0, tk.END)
            status.config(text="Access denied!", fg="red")

            messagebox.showerror(
                "Access Denied",
                f"Wrong password.\nAttempts remaining: {remaining}\n"
                f"Risk score: {score}/100\n"
                f"Anomaly score: {anomaly_score}/100\n"
                f"Response: {response}"
            )
            return

        output_file = path[:-4]

        if os.path.exists(output_file):
            output_file += ".recovered"

        with open(output_file, "wb") as f:
            f.write(decrypted_data)

        score = security_agent.evaluate("successful_access")

        settings["last_successful_access"] = now_text()
        save_json(config_path, settings)

        log_event("successful_access", f"risk={score}")

        password_entry.delete(0, tk.END)

        status.config(
            text=f"Access granted! Risk: {score}/100",
            fg="lightgreen"
        )

        messagebox.showinfo(
            "Success",
            f"File decrypted successfully!\n{output_file}"
        )

    except Exception as e:
        log_event("decryption_error", e)
        messagebox.showerror("Error", str(e))


# ================= SECURITY STATUS =================

def show_security_status():
    state = load_risk_state()

    messagebox.showinfo(
        "Security Status",
        f"Risk score: {state['risk_score']}/100\n"
        f"Recorded events: {state['events']}\n"
        f"Last event: {state['last_event'] or 'None'}"
    )
    
# ================= ANOMALY DETECTION =================

def detect_anomaly(failed_attempts, seconds_since_previous):
    """Rule-based anomaly score between 0 and 100."""

    failed_attempts = max(0, int(failed_attempts))
    seconds_since_previous = max(
        0.0, float(seconds_since_previous)
    )

    score = min(60, failed_attempts * 20)

    if seconds_since_previous < 2:
        score += 40
    elif seconds_since_previous < 5:
        score += 20

    score = min(100, score)

    try:
        samples = []

        if os.path.exists(ANOMALY_FILE):
            with open(ANOMALY_FILE, "r", encoding="utf-8") as f:
                samples = json.load(f).get("samples", [])

        samples.append(score)
        samples = samples[-100:]

        save_json(
            ANOMALY_FILE,
            {
                "samples": samples,
                "last_score": score
            }
        )

    except (OSError, ValueError, TypeError):
        pass

    log_event(
        "anomaly_detected",
        f"score={score}; failures={failed_attempts}; "
        f"interval={seconds_since_previous}"
    )

    return score


# ================= ADAPTIVE SECURITY RESPONSE =================

def adaptive_security_response(risk_score, anomaly_score):

    risk_score = max(0, min(100, int(risk_score)))
    anomaly_score = max(0, min(100, int(anomaly_score)))

    if risk_score >= 90 or anomaly_score >= 90:
        response = "EMERGENCY_LOCKDOWN"

    elif risk_score >= 60 or anomaly_score >= 60:
        response = "RESTRICT_ACCESS"

    elif risk_score >= 30 or anomaly_score >= 30:
        response = "EXTRA_VERIFICATION"

    else:
        response = "ALLOW"

    log_event(
        "adaptive_response",
        f"risk={risk_score}; anomaly={anomaly_score}; "
        f"response={response}"
    )

    return response


# ================= EMERGENCY LOCKDOWN =================

def emergency_lockdown(reason):

    save_json(
        LOCK_FILE,
        {
            "locked": True,
            "reason": str(reason),
            "time": now_text()
        }
    )

    log_event("SELF_DESTRUCTION_LOCKDOWN", reason)


def is_vault_locked():

    if not os.path.exists(LOCK_FILE):
        return False

    try:
        with open(LOCK_FILE, "r", encoding="utf-8") as f:
            return json.load(f).get("locked", True) is True

    except (OSError, ValueError, TypeError):
        return True


def reset_emergency_lock():

    if os.path.exists(LOCK_FILE):
        os.remove(LOCK_FILE)

    default_state = {
        "risk_score": 0,
        "events": 0,
        "last_event": ""
    }

    save_json(RISK_FILE, default_state)

    log_event(
        "EMERGENCY_LOCK_RESET",
        "Manual reset from GUI"
    )


# ================= TRANSFER KEY =================

def transfer_key_from_text(text):

    if len(text) < 12:
        raise ValueError(
            "Use a transfer passphrase of at least 12 characters."
        )

    salt = b"AdaptiveSecureVaultTransferV1"

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600000
    )

    return kdf.derive(text.encode("utf-8"))


# ================= CLOUD FILE RECEIVING =================

def receive_from_cloud(shared_key, transfer_id, download_token):

    if not transfer_id or not download_token:
        raise ValueError(
            "Transfer ID and Download Token are required."
        )

    response = requests.get(
        f"{RELAY_URL}/download/{transfer_id.strip()}",
        headers={
            "X-Transfer-Token": download_token.strip()
        },
        timeout=180
    )

    response.raise_for_status()

    packet = response.content

    if len(packet) > MAX_TRANSFER_SIZE + 4096:
        raise ValueError("File too large.")

    if len(packet) < 30:
        raise ValueError("Invalid transfer packet.")

    name_len = int.from_bytes(packet[:2], "big")

    if name_len < 1 or 2 + name_len + 28 > len(packet):
        raise ValueError("Invalid filename or packet.")

    filename = packet[2:2 + name_len].decode("utf-8")

    if (
        os.path.basename(filename) != filename
        or not filename.lower().endswith(".enc")
    ):
        raise ValueError("Invalid file name.")

    nonce_start = 2 + name_len

    nonce = packet[nonce_start:nonce_start + 12]

    encrypted_data = packet[nonce_start + 12:]

    decrypted_data = AESGCM(shared_key).decrypt(
        nonce,
        encrypted_data,
        None
    )

    if len(decrypted_data) > MAX_TRANSFER_SIZE:
        raise ValueError("Received file exceeds size limit.")

    destination = os.path.join(BASE_DIR, filename)

    if os.path.exists(destination):
        destination = os.path.join(
            BASE_DIR,
            datetime.now().strftime(
                "received_%Y%m%d_%H%M%S_"
            ) + filename
        )

    with open(destination, "xb") as f:
        f.write(decrypted_data)

    log_event(
        "cloud_transfer_received",
        os.path.basename(destination)
    )

    return destination


# ================= RECEIVE BUTTON FUNCTION =================

def start_receive_transfer():

    passphrase = transfer_password_entry.get().strip()
    transfer_id = transfer_id_entry.get().strip()
    download_token = download_token_entry.get().strip()

    try:
        key = transfer_key_from_text(passphrase)

        if not transfer_id or not download_token:
            raise ValueError(
                "Enter both Transfer ID and Download Token."
            )

    except ValueError as e:
        messagebox.showerror("Transfer Error", str(e))
        return

    receive_button.config(
        state="disabled",
        text="Receiving..."
    )

    status.config(
        text="Downloading encrypted file...",
        fg=COLORS["blue"]
    )

    def worker():

        try:
            received_path = receive_from_cloud(
                key,
                transfer_id,
                download_token
            )

            def success():
                receive_button.config(
                    state="normal",
                    text="Receive Encrypted File"
                )

                status.config(
                    text="File received successfully!",
                    fg=COLORS["success"]
                )

                messagebox.showinfo(
                    "Transfer Received",
                    f"File received successfully!\n\n{received_path}"
                )

            root.after(0, success)

        except Exception as e:

            error_message = str(e)

            def failure():
                receive_button.config(
                    state="normal",
                    text="Receive Encrypted File"
                )

                status.config(
                    text="File transfer failed.",
                    fg=COLORS["danger"]
                )

                messagebox.showerror(
                    "Receive Error",
                    error_message
                )

            root.after(0, failure)

    threading.Thread(
        target=worker,
        daemon=True
    ).start()


# ================= SEND BUTTON FUNCTION =================

def start_send_transfer():

    if (
        not selected_file
        or not os.path.isfile(selected_file)
        or not selected_file.lower().endswith(".enc")
    ):
        messagebox.showerror(
            "Transfer Error",
            "Select an existing .enc file first."
        )
        return

    try:

        passphrase = transfer_password_entry.get().strip()

        key = transfer_key_from_text(passphrase)

        file_size = os.path.getsize(selected_file)

        if file_size > MAX_TRANSFER_SIZE:
            raise ValueError(
                "File exceeds the 50 MB transfer limit."
            )

        with open(selected_file, "rb") as f:
            data = f.read()

        nonce = os.urandom(12)

        encrypted = AESGCM(key).encrypt(
            nonce,
            data,
            None
        )

        filename = os.path.basename(selected_file).encode("utf-8")

        packet = (
            len(filename).to_bytes(2, "big")
            + filename
            + nonce
            + encrypted
        )

        if len(packet) > MAX_TRANSFER_SIZE + 4096:
            raise ValueError(
                "Encrypted transfer packet is too large."
            )

        send_button.config(
            state="disabled",
            text="Uploading..."
        )

        status.config(
            text="Uploading file to secure cloud relay...",
            fg=COLORS["blue"]
        )

        def worker():

            try:

                response = requests.post(
                    f"{RELAY_URL}/upload",
                    files={
                        "file": (
                            "transfer.enc",
                            packet,
                            "application/octet-stream"
                        )
                    },
                    timeout=180
                )

                response.raise_for_status()

                result = response.json()

                transfer_id = result.get("transfer_id")
                download_token = result.get("download_token")

                if not transfer_id or not download_token:
                    raise ValueError(
                        "Server response is missing Transfer ID "
                        "or Download Token."
                    )

                def success():

                    send_button.config(
                        state="normal",
                        text="Send Selected .enc"
                    )

                    status.config(
                        text="File uploaded successfully!",
                        fg=COLORS["success"]
                    )

                    transfer_id_entry.delete(0, tk.END)
                    download_token_entry.delete(0, tk.END)

                    messagebox.showinfo(
                        "Transfer Successful",
                        f"File uploaded successfully!\n\n"
                        f"Transfer ID:\n{transfer_id}\n\n"
                        f"Download Token:\n{download_token}\n\n"
                        "Share both values and the transfer "
                        "passphrase securely with the receiver.\n\n"
                        "Transfer expires in 30 minutes and "
                        "can be downloaded only once."
                    )

                    log_event(
                        "cloud_transfer_sent",
                        f"ID={transfer_id}"
                    )

                root.after(0, success)

            except Exception as e:

                error_message = str(e)

                def failure():

                    send_button.config(
                        state="normal",
                        text="Send Selected .enc"
                    )

                    status.config(
                        text="Upload failed.",
                        fg=COLORS["danger"]
                    )

                    messagebox.showerror(
                        "Transfer Error",
                        error_message
                    )

                root.after(0, failure)

        threading.Thread(
            target=worker,
            daemon=True
        ).start()

    except Exception as e:

        messagebox.showerror(
            "Transfer Error",
            str(e)
        )


# ================= BATCH 3 STATUS =================

def show_batch3_status():

    state = load_risk_state()
    locked = is_vault_locked()

    model = {"samples": []}

    if os.path.exists(ANOMALY_FILE):

        try:
            with open(ANOMALY_FILE, "r", encoding="utf-8") as f:
                model = json.load(f)

        except (OSError, ValueError):
            pass

    messagebox.showinfo(
        "Batch 3 Security Status",
        f"Risk score: {state['risk_score']}/100\n"
        f"Vault lockdown: {'ACTIVE' if locked else 'Inactive'}\n"
        f"Anomaly samples: {len(model.get('samples', []))}\n\n"
        "Anomaly detection is a lightweight "
        "rule-based prototype, not a trained ML model."
    )


# ================= ANOMALY TEST =================

def run_anomaly_test():

    state = load_risk_state()

    score = detect_anomaly(
        len(recent_attempt_times),
        1.0
    )

    response = adaptive_security_response(
        state["risk_score"],
        score
    )

    if response == "EMERGENCY_LOCKDOWN":

        emergency_lockdown(
            f"High risk/anomaly: risk={state['risk_score']}, "
            f"anomaly={score}"
        )

        messagebox.showwarning(
            "Emergency Lockdown",
            "High-risk behaviour detected. Vault is now locked."
        )

    else:

        messagebox.showinfo(
            "Anomaly Check",
            f"Anomaly score: {score}/100\n"
            f"Response: {response}"
        )
        
# ================= GUI CONFIGURATION =================

COLORS = {
    "window": "#eef5ff",
    "card": "#ffffff",
    "blue": "#1769e0",
    "blue_dark": "#104eb0",
    "blue_light": "#e7f0ff",
    "text": "#17345c",
    "muted": "#607795",
    "border": "#c9dcf7",
    "success": "#13845b",
    "danger": "#c62828",
    "warning": "#a85b00"
}


# ================= MAIN WINDOW =================

root = tk.Tk()

root.title("Adaptive Secure Vault")
root.geometry("1000x900")
root.minsize(760, 700)

root.configure(bg=COLORS["window"])

canvas = tk.Canvas(
    root,
    bg=COLORS["window"],
    highlightthickness=0
)

scrollbar = tk.Scrollbar(
    root,
    orient="vertical",
    command=canvas.yview
)

canvas.configure(yscrollcommand=scrollbar.set)

scrollbar.pack(side="right", fill="y")
canvas.pack(side="left", fill="both", expand=True)

main_frame = tk.Frame(
    canvas,
    bg=COLORS["window"],
    padx=22,
    pady=18
)

frame_window = canvas.create_window(
    (0, 0),
    window=main_frame,
    anchor="nw"
)


def update_scroll_region(event=None):

    canvas.configure(
        scrollregion=canvas.bbox("all")
    )

    canvas.itemconfigure(
        frame_window,
        width=canvas.winfo_width()
    )


main_frame.bind("<Configure>", update_scroll_region)
canvas.bind("<Configure>", update_scroll_region)


def on_mousewheel(event):

    canvas.yview_scroll(
        int(-1 * (event.delta / 120)),
        "units"
    )


canvas.bind_all("<MouseWheel>", on_mousewheel)


# ================= GUI DESIGN FUNCTIONS =================

def make_card(parent, title, subtitle=None):

    card = tk.Frame(
        parent,
        bg=COLORS["card"],
        highlightbackground=COLORS["border"],
        highlightthickness=1,
        padx=16,
        pady=14
    )

    tk.Label(
        card,
        text=title,
        font=("Segoe UI", 13, "bold"),
        bg=COLORS["card"],
        fg=COLORS["text"]
    ).pack(anchor="w")

    if subtitle:

        tk.Label(
            card,
            text=subtitle,
            font=("Segoe UI", 9),
            bg=COLORS["card"],
            fg=COLORS["muted"],
            wraplength=760,
            justify="left"
        ).pack(anchor="w", pady=(3, 10))

    return card


def style_button(button, primary=False, danger=False):

    if danger:
        bg, active = "#fff0f0", "#ffe0e0"
        fg = COLORS["danger"]

    elif primary:
        bg, active = COLORS["blue"], COLORS["blue_dark"]
        fg = "#ffffff"

    else:
        bg, active = COLORS["blue_light"], "#d5e6ff"
        fg = COLORS["blue_dark"]

    button.configure(
        bg=bg,
        fg=fg,
        activebackground=active,
        activeforeground=fg,
        relief="flat",
        bd=0,
        cursor="hand2",
        font=("Segoe UI", 10, "bold"),
        padx=12,
        pady=8
    )

    return button


def style_entry(entry, width=None):

    entry.configure(
        bg="#fbfdff",
        fg=COLORS["text"],
        insertbackground=COLORS["blue"],
        relief="solid",
        bd=1,
        highlightthickness=1,
        highlightbackground=COLORS["border"],
        highlightcolor=COLORS["blue"],
        font=("Segoe UI", 10)
    )

    if width:
        entry.configure(width=width)

    return entry


# ================= HEADER =================

header = tk.Frame(
    main_frame,
    bg=COLORS["window"]
)

header.pack(fill="x", pady=(0, 16))

tk.Label(
    header,
    text="🔐  Adaptive Secure Vault",
    font=("Segoe UI", 24, "bold"),
    bg=COLORS["window"],
    fg=COLORS["blue_dark"]
).pack(anchor="w")

tk.Label(
    header,
    text="Secure File Storage  •  Encryption  •  Risk Monitoring  •  File Transfer",
    font=("Segoe UI", 11),
    bg=COLORS["window"],
    fg=COLORS["muted"]
).pack(anchor="w", pady=(3, 0))


# ================= ENCRYPTION / DECRYPTION CARD =================

operation_card = make_card(
    main_frame,
    "File Encryption / Decryption",
    "Select a file and choose the required operation."
)

operation_card.pack(fill="x", pady=(0, 12))


mode = tk.StringVar(value="setup")

mode_frame = tk.Frame(
    operation_card,
    bg=COLORS["card"]
)

mode_frame.pack(fill="x", pady=(0, 10))


tk.Radiobutton(
    mode_frame,
    text="Setup / Encrypt",
    variable=mode,
    value="setup",
    bg=COLORS["card"],
    fg=COLORS["text"],
    selectcolor=COLORS["blue_light"],
    activebackground=COLORS["card"],
    font=("Segoe UI", 10, "bold"),
    command=lambda: update_mode()
).pack(side="left", padx=(0, 18))


tk.Radiobutton(
    mode_frame,
    text="Access / Decrypt",
    variable=mode,
    value="access",
    bg=COLORS["card"],
    fg=COLORS["text"],
    selectcolor=COLORS["blue_light"],
    activebackground=COLORS["card"],
    font=("Segoe UI", 10, "bold"),
    command=lambda: update_mode()
).pack(side="left")


# ================= FILE SELECTION =================

file_row = tk.Frame(
    operation_card,
    bg=COLORS["card"]
)

file_row.pack(fill="x", pady=4)

file_label = tk.Label(
    file_row,
    text="No file selected",
    bg=COLORS["card"],
    fg=COLORS["muted"],
    font=("Segoe UI", 10),
    anchor="w",
    wraplength=600
)

file_label.pack(
    side="left",
    fill="x",
    expand=True,
    padx=(0, 10)
)

style_button(
    tk.Button(
        file_row,
        text="📁  Select File",
        command=select_file
    ),
    primary=True
).pack(side="right")


# ================= PASSWORD =================

password_label = tk.Label(
    operation_card,
    text="Set Password",
    bg=COLORS["card"],
    fg=COLORS["text"],
    font=("Segoe UI", 10, "bold")
)

password_label.pack(
    anchor="w",
    pady=(12, 4)
)

password_entry = style_entry(
    tk.Entry(
        operation_card,
        show="*",
        width=42
    )
)

password_entry.pack(
    anchor="w",
    fill="x",
    ipady=5
)


# ================= DATE AND ATTEMPT SETTINGS =================

settings_row = tk.Frame(
    operation_card,
    bg=COLORS["card"]
)

settings_row.pack(
    fill="x",
    pady=(8, 0)
)


date_box = tk.Frame(
    settings_row,
    bg=COLORS["card"]
)

date_box.pack(
    side="left",
    fill="x",
    expand=True,
    padx=(0, 12)
)

date_label = tk.Label(
    date_box,
    text="Allowed Access Date (YYYY-MM-DD)",
    bg=COLORS["card"],
    fg=COLORS["text"],
    font=("Segoe UI", 10, "bold")
)

date_label.pack(anchor="w")

date_entry = style_entry(
    tk.Entry(date_box, width=24)
)

date_entry.pack(
    fill="x",
    ipady=5,
    pady=(4, 0)
)


attempt_box = tk.Frame(
    settings_row,
    bg=COLORS["card"]
)

attempt_box.pack(
    side="left",
    fill="x",
    expand=True
)

attempt_label = tk.Label(
    attempt_box,
    text="Maximum Password Attempts",
    bg=COLORS["card"],
    fg=COLORS["text"],
    font=("Segoe UI", 10, "bold")
)

attempt_label.pack(anchor="w")

attempt_entry = style_entry(
    tk.Entry(attempt_box, width=12)
)

attempt_entry.insert(0, "3")

attempt_entry.pack(
    anchor="w",
    ipady=5,
    pady=(4, 0)
)


# ================= ENCRYPT / DECRYPT BUTTON =================

action_btn = style_button(
    tk.Button(
        operation_card,
        text="Encrypt File",
        width=24,
        command=encrypt_file
    ),
    primary=True
)

action_btn.pack(
    anchor="w",
    pady=(14, 0)
)

# ================= CLOUD UPLOAD BUTTON =================

upload_btn = style_button(
    tk.Button(
        operation_card,
        text="Upload to Cloud",
        width=24,
        command=upload_to_cloud
    ),
    primary=True
)
upload_btn.pack(anchor="w", pady=5)

# ================= CLOUD DOWNLOAD BUTTON =================

download_btn = style_button(
    tk.Button(
        operation_card,
        text="Download from Cloud",
        width=24,
        command=download_from_cloud
    ),
    primary=False
)
download_btn.pack(anchor="w", pady=5)

# ================= SECURITY STATUS CARD =================

security_card = make_card(
    main_frame,
    "Security Status & Risk Score",
    "Review the current risk level and recorded security events."
)

security_card.pack(fill="x", pady=(0, 12))


style_button(
    tk.Button(
        security_card,
        text="View Security Status / Risk Score",
        command=show_security_status
    )
).pack(anchor="w")


# ================= ANOMALY DETECTION CARD =================

batch_card = make_card(
    main_frame,
    "Security & Anomaly Detection",
    "Anomaly detection, adaptive response and emergency-lock controls."
)

batch_card.pack(fill="x", pady=(0, 12))


batch_buttons = tk.Frame(
    batch_card,
    bg=COLORS["card"]
)

batch_buttons.pack(fill="x")


style_button(
    tk.Button(
        batch_buttons,
        text="Run Anomaly Check",
        command=run_anomaly_test
    ),
    primary=True
).pack(side="left", padx=(0, 8), pady=3)


style_button(
    tk.Button(
        batch_buttons,
        text="View Security Details",
        command=show_batch3_status
    )
).pack(side="left", padx=(0, 8), pady=3)


style_button(
    tk.Button(
        batch_card,
        text="Emergency Lockdown (Manual Test)",
        command=lambda: (
            emergency_lockdown("Manual emergency lockdown test"),
            messagebox.showwarning(
                "Locked",
                "Vault locked. Files were not deleted."
            )
        )
    ),
    danger=True
).pack(anchor="w", pady=(8, 4))


style_button(
    tk.Button(
        batch_card,
        text="Reset Emergency Lock",
        command=lambda: (
            reset_emergency_lock(),
            messagebox.showinfo(
                "Lock Reset",
                "Emergency lock reset successfully."
            )
        )
    )
).pack(anchor="w")


# ================= CLOUD TRANSFER CARD =================

transfer_card = make_card(
    main_frame,
    "Secure Cloud File Transfer",
    "Transfer encrypted .enc files between different devices and networks."
)

transfer_card.pack(fill="x", pady=(0, 12))


tk.Label(
    transfer_card,
    text="Transfer Passphrase (12+ characters)",
    bg=COLORS["card"],
    fg=COLORS["text"],
    font=("Segoe UI", 10, "bold")
).pack(anchor="w")


transfer_password_entry = style_entry(
    tk.Entry(
        transfer_card,
        show="*"
    )
)

transfer_password_entry.pack(
    fill="x",
    ipady=5,
    pady=(4, 10)
)


tk.Label(
    transfer_card,
    text="Transfer ID (Receiver)",
    bg=COLORS["card"],
    fg=COLORS["text"],
    font=("Segoe UI", 10, "bold")
).pack(anchor="w")


transfer_id_entry = style_entry(
    tk.Entry(transfer_card)
)

transfer_id_entry.pack(
    fill="x",
    ipady=5,
    pady=(4, 10)
)


tk.Label(
    transfer_card,
    text="Download Token (Receiver)",
    bg=COLORS["card"],
    fg=COLORS["text"],
    font=("Segoe UI", 10, "bold")
).pack(anchor="w")


download_token_entry = style_entry(
    tk.Entry(
        transfer_card,
        show="*"
    )
)

download_token_entry.pack(
    fill="x",
    ipady=5,
    pady=(4, 10)
)


transfer_frame = tk.Frame(
    transfer_card,
    bg=COLORS["card"]
)

transfer_frame.pack(fill="x")


receive_button = style_button(
    tk.Button(
        transfer_frame,
        text="Receive Encrypted File",
        command=start_receive_transfer
    )
)

receive_button.pack(
    side="left",
    padx=(0, 8)
)


send_button = style_button(
    tk.Button(
        transfer_frame,
        text="Send Selected .enc",
        command=start_send_transfer
    ),
    primary=True
)

send_button.pack(side="left")


# ================= FOOTER STATUS =================

status = tk.Label(
    main_frame,
    text="Ready",
    bg=COLORS["window"],
    fg=COLORS["success"],
    font=("Segoe UI", 10, "bold"),
    anchor="w"
)

status.pack(
    fill="x",
    pady=(4, 0)
)


# ================= MODE SWITCHING =================

def update_mode():

    if mode.get() == "setup":

        password_label.config(
            text="Set Password"
        )

        date_box.pack(
            side="left",
            fill="x",
            expand=True,
            padx=(0, 12)
        )

        attempt_box.pack(
            side="left",
            fill="x",
            expand=True
        )

        action_btn.config(
            text="🔒  Encrypt File",
            command=encrypt_file
        )

    else:

        password_label.config(
            text="Enter Password"
        )

        date_box.pack_forget()
        attempt_box.pack_forget()

        action_btn.config(
            text="🔓  Decrypt File",
            command=decrypt_file
        )


# ================= START APPLICATION =================

update_mode()

canvas.configure(
    scrollregion=canvas.bbox("all")
)

root.mainloop()