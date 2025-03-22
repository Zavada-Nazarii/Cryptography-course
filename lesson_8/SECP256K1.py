from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.exceptions import InvalidSignature
from binascii import unhexlify, hexlify

# ========================== Дані від Alice ==========================
alice_pub_sign_key_raw = b"""
-----BEGIN PUBLIC KEY-----
MFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAES/35y89DRx2XEh6pJvCckadQ9Awuys84
HORPVVaDksVxWfSkngYrz/c+HwVS9tV5ivnVwCHxyJ8gTQob/0LDDg==
-----END PUBLIC KEY-----
"""
alice_x_pub_key_hex = b'92ce3bc6d941238da92639c72a7d3bb483d3c18fdca9f42164459a3751638433'
alice_signature_hex = b'3045022034b7944bf92bfaa2791b5fe929d915add4ee59dbd9e776c1520568fbf2503048022100f09c9113f38fadb33b05332eab9a4982f7dda35fb1f503bb46da806c8e8dbaa2'

# ========================== Крок 1: Генерація довгострокової пари ECDSA SECP256K1 ==========================
bob_sign_priv_key = ec.generate_private_key(ec.SECP256K1())
bob_sign_pub_key = bob_sign_priv_key.public_key()

# ========================== Крок 2: Генерація ECDH (X25519) пари для Bob ==========================
bob_x_priv_key = x25519.X25519PrivateKey.generate()
bob_x_pub_key = bob_x_priv_key.public_key()

# ========================== Крок 3: Перевірка підпису Alice ==========================
# Завантажуємо підписний публічний ключ Alice
alice_pub_sign_key = load_pem_public_key(alice_pub_sign_key_raw)

# Підготовка даних для перевірки
data_for_verification = unhexlify(alice_x_pub_key_hex)

try:
    alice_pub_sign_key.verify(
        unhexlify(alice_signature_hex),
        data_for_verification,
        ec.ECDSA(hashes.SHA256())
    )
    print("[✔] Підпис Alice валідний.")
except InvalidSignature:
    print("[✘] Підпис Alice НЕвалідний!")
    exit()

# ========================== Крок 4: Підготовка відкритого X25519 Bob (Y) ==========================
bob_x_pub_key_bytes = bob_x_pub_key.public_bytes(
    serialization.Encoding.Raw,
    serialization.PublicFormat.Raw
)
bob_x_pub_key_hex = hexlify(bob_x_pub_key_bytes).decode()

# ========================== Крок 5: Підпис відкритого ECDH ключа Bob ==========================
signature_bob = bob_sign_priv_key.sign(
    bob_x_pub_key_bytes,
    ec.ECDSA(hashes.SHA256())
)
bob_signature_hex = hexlify(signature_bob).decode()

# ========================== Крок 6: Збереження публічного ключа Bob для підпису у PEM ==========================
bob_pub_sign_pem = bob_sign_pub_key.public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo
).decode()

# ========================== Крок 7: Запис результатів у файл ==========================
with open("bob_output.txt", "w") as f:
    f.write("===== Bob Long-term Signing Public Key (PEM) =====\n")
    f.write(bob_pub_sign_pem + "\n")
    f.write("===== Bob ECDH Public Key (Y) Hex =====\n")
    f.write(bob_x_pub_key_hex + "\n")
    f.write("===== Signature of Bob ECDH Public Key (Hex) =====\n")
    f.write(bob_signature_hex + "\n")

print("[✔] Завдання виконано. Результати збережено у 'bob_output.txt'")

