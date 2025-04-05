import socket
import threading
from crypto_utils import *
from utils import *

# Завантаження ключів
alice_sign_priv, alice_sign_pub = load_or_generate_ed25519("alice_ed25519")
alice_dh_priv, alice_dh_pub = generate_dh_keypair()
bob_sign_pub = load_ed25519_public_key("bob_ed25519.pub")

# З'єднання з Bob
s = socket.socket()
s.connect(("localhost", SERVER_PORT))

# Генерація сесійного DH ключа
session_dh_priv, session_dh_pub = generate_dh_keypair()
session_dh_pub_bytes = session_dh_pub.public_bytes(encoding=Encoding.Raw, format=PublicFormat.Raw)
signature = sign_data(alice_sign_priv, session_dh_pub_bytes)

# Надсилаємо DH публічний ключ + підпис
s.sendall(session_dh_pub_bytes + signature)

# Отримуємо відповідь Bob
data = s.recv(1024)
peer_dh_pub_bytes, nonce, ciphertext, peer_signature = unpack_message(data)
verify_signature(bob_sign_pub, peer_signature, peer_dh_pub_bytes)
peer_dh_pub = x25519.X25519PublicKey.from_public_bytes(peer_dh_pub_bytes)

# Узгоджуємо спільний ключ
shared_key = derive_shared_key(session_dh_priv, peer_dh_pub)
plaintext = decrypt_aes_gcm(shared_key, ciphertext, nonce)
print("<<<", plaintext.decode())

# Потік прийому повідомлень
def receive_messages():
    while True:
        try:
            data = s.recv(1024)
            if not data:
                break
            peer_dh_pub_bytes, nonce, ciphertext, peer_signature = unpack_message(data)
            verify_signature(bob_sign_pub, peer_signature, peer_dh_pub_bytes)
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
        s.sendall(pack_message(session_dh_pub_bytes, nonce, ciphertext, signature))

# Запуск потоків
recv_thread = threading.Thread(target=receive_messages, daemon=True)
send_thread = threading.Thread(target=send_messages, daemon=True)

recv_thread.start()
send_thread.start()

recv_thread.join()
send_thread.join()

