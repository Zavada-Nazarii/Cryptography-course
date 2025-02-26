import random
import secrets
import os
import struct
from Crypto.Random import get_random_bytes

# Розмір файлу в байтах (1 ГБ)
file_size = 1 * 1024 * 1024 * 1024

# Файл для random.Random.randint()
with open("random_mt19937.bin", "wb") as f:
    for _ in range(file_size // 4):  # 4 байти на число
        f.write(struct.pack("I", random.randint(0, 2**32 - 1)))

# Файл для secrets.randbits()
with open("random_secrets.bin", "wb") as f:
    for _ in range(file_size // 4):  # 4 байти на число
        f.write(struct.pack("I", secrets.randbits(32)))

# Файл для OpenSSL (Crypto.Random)
with open("random_openssl.bin", "wb") as f:
    f.write(get_random_bytes(file_size))

# Повідомлення про завершення
"Файли успішно згенеровані: random_mt19937.bin, random_secrets.bin, random_openssl.bin"

