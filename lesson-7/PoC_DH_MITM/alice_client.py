import socket
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization

# Генеруємо DH-ключі
parameters = dh.generate_parameters(generator=2, key_size=512)
alice_private_key = parameters.generate_private_key()
alice_public_key = alice_private_key.public_key()

# Запускаємо сервер (Аліса чекає підключення)
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind(("0.0.0.0", 8082))  # Аліса слухає на 8082
server.listen(1)
print("[Аліса] Чекає на підключення...")

conn, addr = server.accept()
print(f"[Аліса] Підключено до {addr}")

# Відправляємо відкритий ключ Єві
conn.send(
    alice_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
)

# Отримуємо відкритий ключ Єви
eve_public_key_data = conn.recv(1024)
eve_public_key = serialization.load_pem_public_key(eve_public_key_data)
print("[Аліса] Отримала відкритий ключ від Єви.")

# Обчислюємо спільний секретний ключ
shared_key = alice_private_key.exchange(eve_public_key)
print(f"[Аліса] Спільний секретний ключ: {shared_key.hex()}")

# Отримуємо повідомлення
message = conn.recv(1024).decode()
print(f"[Аліса] Отримано повідомлення: {message}")

conn.close()

