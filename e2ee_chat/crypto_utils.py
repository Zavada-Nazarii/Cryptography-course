from cryptography.hazmat.primitives.asymmetric import x25519, ed25519
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, PrivateFormat, NoEncryption
import os

def generate_dh_keypair():
    priv = x25519.X25519PrivateKey.generate()
    return priv, priv.public_key()

def derive_shared_key(priv, peer_pub):
    shared = priv.exchange(peer_pub)
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'e2ee-chat')
    return hkdf.derive(shared)

def encrypt_aes_gcm(key, plaintext):
    nonce = os.urandom(12)
    cipher = AESGCM(key)
    ct = cipher.encrypt(nonce, plaintext, None)
    return ct, nonce

def decrypt_aes_gcm(key, ciphertext, nonce):
    cipher = AESGCM(key)
    return cipher.decrypt(nonce, ciphertext, None)

def sign_data(private_key, data):
    return private_key.sign(data)

def verify_signature(public_key, signature, data):
    public_key.verify(signature, data)

def load_or_generate_ed25519(name):
    priv_file = f"{name}.pem"
    pub_file = f"{name}.pub"
    if os.path.exists(priv_file):
        with open(priv_file, "rb") as f:
            priv = serialization.load_pem_private_key(f.read(), password=None)
    else:
        priv = ed25519.Ed25519PrivateKey.generate()
        with open(priv_file, "wb") as f:
            f.write(priv.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()))
        with open(pub_file, "wb") as f:
            f.write(priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw))
    return priv, priv.public_key()


def load_ed25519_public_key(file):
    if not os.path.exists(file):
        # Виводимо попередження і генеруємо ключ
        print(f"[i] Ключ '{file}' не знайдено — створюється новий...")
        name = file.replace(".pub", "")
        _, pub = load_or_generate_ed25519(name)
        return pub
    with open(file, "rb") as f:
        return ed25519.Ed25519PublicKey.from_public_bytes(f.read())

