import socket
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization

# Генеруємо DH-ключі
parameters = dh.generate_parameters(generator=2, key_size=512)
bob_private_key = parameters.generate_private_key()
bob_public_key = bob_private_key.public_key()

# Підключаємося до "Аліси" (насправді до Єви)
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(("localhost", 8083))  # Єва слухає на 8083

# Відправляємо відкритий ключ
client.send(
    bob_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
)

# Отримуємо відкритий ключ від "Аліси" (насправді від Єви)
alice_public_key_data = client.recv(1024)
alice_public_key = serialization.load_pem_public_key(alice_public_key_data)

# Обчислюємо секретний ключ
shared_key = bob_private_key.exchange(alice_public_key)
print(f"[Боб] Спільний секретний ключ: {shared_key.hex()}")

# Введення тексту вручну
message = input("[Боб] Введіть повідомлення для Аліси: ")

# Відправка повідомлення
client.send(message.encode())

client.close()

