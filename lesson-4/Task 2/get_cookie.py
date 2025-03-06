import requests
from binascii import unhexlify, hexlify
from datetime import datetime, timedelta

BASE_URL = "https://aes.cryptohack.org/flipping_cookie/"
GET_COOKIE_URL = f"{BASE_URL}get_cookie/"
CHECK_ADMIN_URL = f"{BASE_URL}check_admin/{{}}/{{}}/"

def xor_bytes(a, b):
    """Побітовий XOR двох байтових рядків."""
    return bytes(x ^ y for x, y in zip(a, b))

def xor(cookie, plain):
    start = plain.find(b'admin=False')
    cookie = bytes.fromhex(cookie)
    iv = [0xff] * 16
    cipher_fake = list(cookie)
    fake = b';admin=True;'
    for i in range(len(fake)):
        cipher_fake[16 + i] = plain[16 + i] ^ cookie[16 + i] ^ fake[i]
        iv[start + i] = plain[start + i] ^ cookie[start + i] ^ fake[i]

    cipher_fake = bytes(cipher_fake).hex()
    iv = bytes(iv).hex()
    return cipher_fake, iv

# Отримуємо cookie
response = requests.get(GET_COOKIE_URL)
cookie_hex = response.json()["cookie"]

# Створюємо правильний expires_at
expires_at = (datetime.today() + timedelta(days=1)).strftime("%s")

# Оригінальний plaintext (перед шифруванням) з правильним expires_at
plain = f"admin=False;expiry={expires_at}".encode()

# Підміна cookie
new_cookie, new_iv = xor(cookie_hex, plain)

# Перевірка адміна
check_url = CHECK_ADMIN_URL.format(new_cookie, new_iv)
result = requests.get(check_url)

print("=================================")
print(check_url)
print("=================================")
print(result.text)

