from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key

# Завантаження повідомлення
with open("task_message.txt", "r") as msg_file:
    message = bytes.fromhex(msg_file.read().strip())

# Завантаження підпису
with open("task_signature.txt", "r") as sig_file:
    signature = bytes.fromhex(sig_file.read().strip())

# Завантаження відкритого ключа
with open("task_pub.pem", "rb") as key_file:
    public_key = load_pem_public_key(key_file.read())

# Перевірка підпису
try:
    public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Підпис дійсний: повідомлення не було змінено.")
except Exception as e:
    print("Підпис недійсний: повідомлення могло бути змінено або підпис некоректний.")

