import os
import base64
import sqlite3
import pyotp
import qrcode
from io import BytesIO
from flask import Flask, request, jsonify, send_file, render_template
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend

# ---------------- CONFIG ----------------
app = Flask(__name__)
UPLOAD_DIR = "uploads"
DB_FILE = "users.db"

os.makedirs(UPLOAD_DIR, exist_ok=True)

# ---------------- DATABASE ----------------
def init_db():
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password TEXT,
        secret TEXT,
        public_key TEXT,
        private_key BLOB
    )""")
    conn.commit()
    conn.close()

init_db()

# ---------------- HELPERS ----------------
def generate_keys(password: str):
    """Generate RSA keypair and encrypt private key with password."""
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # Serialize
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(password.encode())
    )

    return public_pem, private_pem

def aes_encrypt(data: bytes, key: bytes):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return iv + encryptor.update(data) + encryptor.finalize()

def aes_decrypt(data: bytes, key: bytes):
    iv = data[:16]
    ciphertext = data[16:]
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# ---------------- ROUTES ----------------
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/login")
def login_page():
    return render_template("login.html")

@app.route("/register")
def register_page():
    return render_template("register.html")

@app.route("/upload")
def upload_page():
    return render_template("upload.html")

@app.route("/download")
def download_page():
    return render_template("download.html")

@app.route("/share")
def share_page():
    return render_template("share.html")

# ---------------- API ----------------
@app.route("/api/register", methods=["POST"])
def api_register():
    data = request.get_json()
    username, password = data.get("username"), data.get("password")

    # Check duplicate
    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=?", (username,))
    if c.fetchone():
        conn.close()
        return jsonify({"success": False, "error": "User already exists"}), 400

    # Generate RSA keys
    public_key, private_key = generate_keys(password)

    # Generate TOTP secret
    secret = pyotp.random_base32()
    uri = pyotp.totp.TOTP(secret).provisioning_uri(username, issuer_name="SecureStore")

    # Generate QR
    qr = qrcode.make(uri)
    buf = BytesIO()
    qr.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    # Save to DB
    c.execute("INSERT INTO users (username, password, secret, public_key, private_key) VALUES (?,?,?,?,?)",
              (username, password, secret, public_key, private_key))
    conn.commit()
    conn.close()

    return jsonify({"success": True, "qr_code": qr_b64})

@app.route("/api/login", methods=["POST"])
def api_login():
    data = request.get_json()
    username, password, otp = data.get("username"), data.get("password"), data.get("otp")

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT password, secret FROM users WHERE username=?", (username,))
    row = c.fetchone()
    conn.close()

    if not row:
        return jsonify({"success": False, "error": "User not found"}), 400
    db_password, secret = row
    if password != db_password:
        return jsonify({"success": False, "error": "Invalid password"}), 400
    if not pyotp.TOTP(secret).verify(otp):
        return jsonify({"success": False, "error": "Invalid OTP"}), 400

    return jsonify({"success": True})

@app.route("/api/upload", methods=["POST"])
def api_upload():
    username = request.form.get("username")
    file = request.files.get("file")

    if not username or not file:
        return jsonify({"success": False, "error": "Missing username or file"}), 400

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT public_key FROM users WHERE username=?", (username,))
    row = c.fetchone()
    conn.close()
    if not row:
        return jsonify({"success": False, "error": "User not found"}), 400

    public_key_pem = row[0].encode()
    public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())

    # Generate AES key and encrypt file
    aes_key = os.urandom(32)
    data = file.read()
    encrypted_data = aes_encrypt(data, aes_key)

    # Encrypt AES key with RSA
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    # Save encrypted file
    filename = secure_filename(file.filename) + ".enc"
    with open(os.path.join(UPLOAD_DIR, filename), "wb") as f:
        f.write(encrypted_key + b"::" + encrypted_data)

    return jsonify({"success": True, "message": "File uploaded & encrypted successfully!"})

@app.route("/api/download", methods=["POST"])
def api_download():
    username = request.form.get("username")
    password = request.form.get("password")
    filename = request.form.get("filename")

    conn = sqlite3.connect(DB_FILE)
    c = conn.cursor()
    c.execute("SELECT private_key FROM users WHERE username=?", (username,))
    row = c.fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "User not found"}), 400

    private_key_pem = row[0]
    try:
        private_key = serialization.load_pem_private_key(
            private_key_pem,
            password=password.encode(),
            backend=default_backend()
        )
    except Exception:
        return jsonify({"error": "Invalid password for private key"}), 400

    path = os.path.join(UPLOAD_DIR, filename)
    if not os.path.exists(path):
        return jsonify({"error": "File not found"}), 400

    with open(path, "rb") as f:
        content = f.read()

    encrypted_key, encrypted_data = content.split(b"::", 1)

    # Decrypt AES key
    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

    # Decrypt file
    decrypted_data = aes_decrypt(encrypted_data, aes_key)

    return send_file(BytesIO(decrypted_data), as_attachment=True, download_name=filename.replace(".enc", ""))

@app.route("/api/share", methods=["POST"])
def api_share():
    data = request.get_json()
    filename = data.get("filename")
    link = f"http://localhost:5000/api/download_shared/{filename}"

    qr = qrcode.make(link)
    buf = BytesIO()
    qr.save(buf, format="PNG")
    qr_b64 = base64.b64encode(buf.getvalue()).decode()

    return jsonify({"success": True, "link": link, "qr_code": qr_b64})

if __name__ == "__main__":
    app.run(debug=True)
