from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import load_pem_public_key

# Завантаження повідомлення для шифрування
with open("task_message.txt", "r") as msg_file:
    message = msg_file.read().encode()  # Читаємо текст і конвертуємо у байти

# Завантаження відкритого ключа
with open("task_pub.pem", "rb") as key_file:
    public_key = load_pem_public_key(key_file.read())

# Шифрування повідомлення
encrypted_message = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Збереження зашифрованого повідомлення у hex-форматі
with open("task-2-message.txt", "w") as enc_file:
    enc_file.write(encrypted_message.hex())

print("Повідомлення успішно зашифровано та збережено у task-2-message.txt")

