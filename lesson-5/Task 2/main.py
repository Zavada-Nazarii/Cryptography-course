import hmac
import hashlib

# 🔹 Файли
MASTER_KEY_FILE = "master_key.txt"
IV_FILE = "iv.txt"
CIPHERTEXT_FILE = "ciphertext.txt"
MAC_KEY_FILE = "mac_key.txt"
MAC_OUTPUT_FILE = "mac.txt"

# 🔹 Функція HKDF для витягнення MAC-ключа
def hkdf_extract_expand(master_key, context, length=32):
    return hmac.new(master_key, context, hashlib.sha256).digest()[:length]

# 🔹 Функція генерації HMAC-SHA256
def generate_mac(mac_key, iv, ciphertext):
    return hmac.new(mac_key, iv + ciphertext, hashlib.sha256).hexdigest()

# 🔹 Читання файлу у байтовому форматі
def read_file(filename):
    try:
        with open(filename, "rb") as file:  # ВАЖЛИВО: читаємо як байти!
            return file.read().strip()
    except FileNotFoundError:
        print(f"❌ Файл {filename} не знайдено.")
        return None

# 🔹 Запис у файл
def write_file(filename, data):
    with open(filename, "w") as file:
        file.write(data)

# 🔹 Основна логіка генерації MAC
def generate_and_store_mac():
    # Зчитуємо вхідні дані у байтовому форматі
    master_key = read_file(MASTER_KEY_FILE)
    iv = read_file(IV_FILE)
    ciphertext = read_file(CIPHERTEXT_FILE)

    if not master_key or not iv or not ciphertext:
        print("❌ Помилка читання файлів.")
        return

    # Генеруємо MAC-ключ та переводимо у HEX
    mac_key = hkdf_extract_expand(master_key, b"mac_key")
    mac_key_hex = mac_key.hex()

    # Генеруємо імітовставку (MAC)
    mac_tag = generate_mac(mac_key, iv, ciphertext)

    # Записуємо MAC-ключ у HEX-форматі (щоб уникнути проблем із бінарними даними)
    write_file(MAC_KEY_FILE, mac_key_hex)

    # Записуємо MAC-значення у файл
    write_file(MAC_OUTPUT_FILE, mac_tag)

    print(f"✅ MAC-ключ збережено у {MAC_KEY_FILE}")
    print(f"✅ Імітовставку (MAC) збережено у {MAC_OUTPUT_FILE}")

# 🔹 Виконання скрипта
if __name__ == "__main__":
    generate_and_store_mac()

