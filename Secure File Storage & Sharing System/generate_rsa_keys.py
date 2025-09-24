from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

#Generate Private Key
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048 #can use 4096 for stronger security
)

#Serialize private key
with open("private_key.pem", "wb") as f:
    f.write(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()  #To add password here
        )
    )

#Generate public key
public_key = private_key.public_key()

#Serialize public key
with open("public_key.pem", "wb") as f:
    f.write(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

print("✅ RSA key Pair Generated: private_key.pem & public_key.pem")