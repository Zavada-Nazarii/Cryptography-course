import socket
import threading
from crypto_utils import *
from utils import *

# Завантаження ключів
bob_sign_priv, bob_sign_pub = load_or_generate_ed25519("bob_ed25519")
bob_dh_priv, bob_dh_pub = generate_dh_keypair()
alice_sign_pub = load_ed25519_public_key("alice_ed25519.pub")

# Створення сокета та прийом з'єднання від Alice
s = socket.socket()
s.bind(("localhost", SERVER_PORT))
s.listen(1)
conn, addr = s.accept()

# Отримуємо DH ключ і підпис від Alice
data = conn.recv(1024)
alice_dh_pub_bytes = data[:32]
alice_signature = data[32:]
verify_signature(alice_sign_pub, alice_signature, alice_dh_pub_bytes)
alice_dh_pub = x25519.X25519PublicKey.from_public_bytes(alice_dh_pub_bytes)

# Генеруємо свій сесійний DH ключ
session_dh_priv, session_dh_pub = generate_dh_keypair()
session_dh_pub_bytes = session_dh_pub.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
shared_key = derive_shared_key(session_dh_priv, alice_dh_pub)

# Ввід першого повідомлення Bob'а
msg = input(">>> ").encode()
ciphertext, nonce = encrypt_aes_gcm(shared_key, msg)
signature = sign_data(bob_sign_priv, session_dh_pub_bytes)
conn.sendall(pack_message(session_dh_pub_bytes, nonce, ciphertext, signature))

# Потік прийому повідомлень
def receive_messages():
    while True:
        try:
            data = conn.recv(1024)
            if not data:
                break
            peer_dh_pub_bytes, nonce, ciphertext, peer_signature = unpack_message(data)
            verify_signature(alice_sign_pub, peer_signature, peer_dh_pub_bytes)
            peer_dh_pub = x25519.X25519PublicKey.from_public_bytes(peer_dh_pub_bytes)
            shared_key = derive_shared_key(session_dh_priv, peer_dh_pub)
            plaintext = decrypt_aes_gcm(shared_key, ciphertext, nonce)
            print("\n<<<", plaintext.decode(), "\n>>> ", end="")
        except Exception as e:
            print(f"[!] Error: {e}")
            break

# Потік надсилання повідомлень
def send_messages():
    while True:
        msg = input(">>> ").encode()
        ciphertext, nonce = encrypt_aes_gcm(shared_key, msg)
        conn.sendall(pack_message(session_dh_pub_bytes, nonce, ciphertext, signature))

# Запуск потоків
recv_thread = threading.Thread(target=receive_messages, daemon=True)
send_thread = threading.Thread(target=send_messages, daemon=True)

recv_thread.start()
send_thread.start()

recv_thread.join()
send_thread.join()

