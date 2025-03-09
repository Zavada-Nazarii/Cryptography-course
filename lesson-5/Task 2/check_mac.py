import hmac
import hashlib

# 🔹 Файли
MAC_KEY_FILE = "mac_key.txt"
IV_FILE = "iv.txt"
CIPHERTEXT_FILE = "ciphertext.txt"
MAC_FILE = "mac.txt"

# 🔹 Функція генерації HMAC-SHA256
def generate_mac(mac_key, iv, ciphertext):
    return hmac.new(mac_key, iv + ciphertext, hashlib.sha256).hexdigest()

# 🔹 Читання файлів (тепер правильне!)
def read_file(filename, binary=False):
    try:
        mode = "rb" if binary else "r"
        with open(filename, mode) as file:
            return file.read().strip()
    except FileNotFoundError:
        print(f"❌ Файл {filename} не знайдено.")
        return None

# 🔹 Основна логіка перевірки MAC
def verify_mac():
    mac_key_hex = read_file(MAC_KEY_FILE)  # MAC-ключ у HEX
    iv = read_file(IV_FILE, binary=True)  # IV у байтовому форматі
    ciphertext = read_file(CIPHERTEXT_FILE, binary=True)  # Шифротекст у байтовому форматі
    stored_mac = read_file(MAC_FILE)  # MAC у HEX

    if not mac_key_hex or not iv or not ciphertext or not stored_mac:
        print("❌ Помилка читання файлів.")
        return

    # Перетворюємо MAC-ключ із HEX у байти
    mac_key = bytes.fromhex(mac_key_hex)

    # Обчислюємо новий MAC
    computed_mac = generate_mac(mac_key, iv, ciphertext)

    # Порівнюємо MAC-и
    if hmac.compare_digest(computed_mac, stored_mac):
        print("✅ Дані автентичні! Шифротекст не змінювався.")
    else:
        print("❌ Попередження! Дані були змінені або підроблені.")

# 🔹 Виконання скрипта
if __name__ == "__main__":
    verify_mac()

