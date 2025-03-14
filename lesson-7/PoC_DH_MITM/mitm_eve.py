import socket
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import serialization

# --- 1. Очікуємо підключення від Боба ---
mitm_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
mitm_server.bind(("0.0.0.0", 8083))  # Єва слухає замість Аліси
mitm_server.listen(1)
print("[Eve] Чекає підключення від Боба...")

conn_bob, addr = mitm_server.accept()
print(f"[Eve] Боб підключився з {addr}")

# Отримуємо відкритий ключ від Боба
bob_public_key_data = conn_bob.recv(1024)
bob_public_key = serialization.load_pem_public_key(bob_public_key_data)
print("[Eve] Отримала відкритий ключ від Боба.")

# Отримуємо параметри DH від Боба
bob_parameters = bob_public_key.public_numbers().parameter_numbers
bob_dh_parameters = dh.DHParameterNumbers(bob_parameters.p, bob_parameters.g).parameters()

# Генеруємо приватний ключ Єви для Боба
eve_private_key_bob = bob_dh_parameters.generate_private_key()
eve_public_key_bob = eve_private_key_bob.public_key()

# Надсилаємо Бобу відкритий ключ Єви
conn_bob.send(
    eve_public_key_bob.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
)

# Обчислюємо спільний ключ із Бобом
shared_key_bob = eve_private_key_bob.exchange(bob_public_key)
print(f"[Eve] Спільний секретний ключ з Бобом: {shared_key_bob.hex()}")

# --- 2. Отримуємо повідомлення від Боба ---
message_from_bob = conn_bob.recv(1024).decode()
print(f"[Eve] Отримано повідомлення від Боба: {message_from_bob}")

# --- 3. Авторизація з Алісою ---
print("[Eve] Підключаємось до Аліси...")
client_alice = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    client_alice.connect(("localhost", 8082))  # Підключаємося до Аліси
except ConnectionRefusedError:
    print("[Eve] ❌ Помилка: Аліса ще не запущена! Запустіть alice_server.py перед bob_server.py.")
    exit(1)

print("[Eve] ✅ Підключена до Аліси.")

# Отримуємо відкритий ключ Аліси
alice_public_key_data = client_alice.recv(1024)
alice_public_key = serialization.load_pem_public_key(alice_public_key_data)
print("[Eve] Отримала відкритий ключ від Аліси.")

# Використовуємо параметри Аліси для генерації свого ключа
alice_parameters = alice_public_key.public_numbers().parameter_numbers
alice_dh_parameters = dh.DHParameterNumbers(alice_parameters.p, alice_parameters.g).parameters()

# Генеруємо приватний ключ Єви для Аліси
eve_private_key_alice = alice_dh_parameters.generate_private_key()
eve_public_key_alice = eve_private_key_alice.public_key()

# Відправляємо Алісі відкритий ключ Єви
client_alice.send(
    eve_public_key_alice.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
)

# Обчислюємо спільний ключ із Алісою
shared_key_alice = eve_private_key_alice.exchange(alice_public_key)
print(f"[Eve] Спільний секретний ключ з Алісою: {shared_key_alice.hex()}")

# --- 4. Єва змінює повідомлення вручну ---
modified_message = input(f"[Eve] Введіть підроблене повідомлення (або натисніть Enter, щоб залишити оригінал): ")
if not modified_message:
    modified_message = message_from_bob  # Якщо не вводити, залишаємо оригінал

print(f"[Eve] Надсилаємо Алісі повідомлення: {modified_message}")

# Відправляємо змінене повідомлення Алісі
client_alice.send(modified_message.encode())

# Закриваємо з'єднання
conn_bob.close()
client_alice.close()
mitm_server.close()

