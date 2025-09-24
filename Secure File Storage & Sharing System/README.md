# 🔐 Secure File Storage (with Encryption + OTP Authentication)

This project is a **secure file storage system** built with **Flask**.  
It allows users to **upload files, encrypt them, and later download them securely** using OTP authentication and cryptographic encryption.

---

## 🚀 Features
- Upload files securely  
- AES encryption for file security  
- OTP-based authentication  
- QR code for 2FA setup  
- Download files with decryption  
- Simple Flask-based web interface  

---

### 📂 Project Structure
SecureFileStorage/
│── app.py                     # Main Flask app
│── requirements.txt           # Python dependencies
│── README.md                  # Documentation
│
│
├── database/                  # SQLite database storage
│   └── users.db
│
├── uploads/                   # Encrypted uploaded files
├── decrypted/                 # Temporary decrypted files
├── keys/                      # RSA key storage
│   ├── private_key.pem
│   ├── public_key.pem
│
├── templates/                 # HTML templates
│   ├── index.html
│   ├── register.html
│   ├── login.html
│   ├── upload.html
│   ├── download.html
│   ├── notes.html
│
├── static/                    
│   ├── css/                   # CSS files
│   │   └── style.css
│   │
│   ├── js/                    # JavaScript files
│   │   └── app.js
│   │
│   ├── qr_codes/              # Generated QR images for OTP
│       └── user_qr.png

  ---

#### Create a virtual environment

On Linux / MacOS:

python3 -m venv venv
source venv/bin/activate


On Windows (PowerShell):

python -m venv venv
venv\Scripts\activate

  ---

##### Install dependencies
pip install -r requirements.txt

  ---

###### Run the Flask server
python app.py

  ---

###### Open in your browser
http://127.0.0.1:5000

  ---

🔑 Usage

Register → Enter username + password, scan QR code with Google Authenticator

Login → Enter username + password + OTP

Upload a file → File is encrypted & stored securely

Download file → Enter filename + OTP to decrypt & download

  ---

🤝 Contributing

Pull requests are welcome! For major changes, please open an issue first.

  ---