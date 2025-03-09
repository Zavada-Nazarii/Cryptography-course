import hashlib
import json

HASHED_OUTPUT_FILE = "hashed_passwords.json"
MAX_ZXCVBN_LENGTH = 72  # Обмеження для zxcvbn

# 🔹 Функція перевірки паролю
def verify_password(input_password, stored_data):
    salt = bytes.fromhex(stored_data["salt"])  # Перетворюємо salt назад у байти
    stored_hash = stored_data["hash"]  # Отримуємо збережений хеш
    iterations = stored_data["iterations"]  # Отримуємо кількість ітерацій

    # Якщо пароль > 72 символів, попередньо хешуємо його SHA-512
    if len(input_password) > MAX_ZXCVBN_LENGTH:
        input_password = hashlib.sha512(input_password.encode()).hexdigest()

    # Генеруємо хеш введеного паролю
    new_hash = hashlib.pbkdf2_hmac('sha256', input_password.encode(), salt, iterations).hex()

    # Порівнюємо збережений хеш із обчисленим
    return new_hash == stored_hash

# 🔹 Функція завантаження збережених паролів
def load_hashed_passwords(filename):
    try:
        with open(filename, "r", encoding="utf-8") as file:
            return json.load(file)
    except FileNotFoundError:
        print(f"❌ Помилка: файл {filename} не знайдено.")
        return {}

# 🔹 Основна логіка перевірки паролю
def check_password():
    stored_passwords = load_hashed_passwords(HASHED_OUTPUT_FILE)
    
    if not stored_passwords:
        print("❌ Немає збережених паролів для перевірки.")
        return

    input_password = input("🔑 Введіть пароль для перевірки: ")

    # Перевіряємо введений пароль з усіма збереженими хешами
    for stored_pass, stored_data in stored_passwords.items():
        if verify_password(input_password, stored_data):
            print(f"✅ Пароль правильний! Він відповідає збереженому хешу для \"{stored_pass}\"")
            return

    print("❌ Невірний пароль.")

# 🔹 Виконання перевірки
if __name__ == "__main__":
    check_password()

