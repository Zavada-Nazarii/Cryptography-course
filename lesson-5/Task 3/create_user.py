import hashlib
import os
import json
from zxcvbn import zxcvbn
from base64 import b64encode

# 🔹 Файл для збереження користувачів
USER_DATA_FILE = "users.json"
MAX_ZXCVBN_LENGTH = 72  # Обмеження для zxcvbn
AES_KEY_LENGTH = 16  # 128-бітний ключ (16 байтів)

# 🔹 Функція для визначення унікальності символів у довгому паролі
def calculate_entropy(password):
    unique_chars = len(set(password))  # Кількість унікальних символів
    length_factor = len(password) // 10  # Додатковий коефіцієнт за довжину
    return unique_chars + length_factor  # Чим більше унікальних символів, тим складніше

# 🔹 Функція визначення кількості ітерацій для PBKDF2
def get_pbkdf2_params(password):
    if len(password) <= MAX_ZXCVBN_LENGTH:  # Якщо пароль короткий, використовуємо zxcvbn
        score = zxcvbn(password)['score']
    else:  # Якщо пароль довгий, розраховуємо складність вручну
        entropy = calculate_entropy(password)
        if entropy < 15:
            score = 1  # Дуже слабкий пароль
        elif entropy < 25:
            score = 2  # Середній пароль
        elif entropy < 35:
            score = 3  # Сильний пароль
        else:
            score = 4  # Дуже складний пароль

    # Визначаємо кількість ітерацій залежно від складності паролю
    if score == 0 or score == 1:
        iterations = 500_000  # Дуже слабкий пароль → максимальна складність
    elif score == 2:
        iterations = 300_000  # Середній пароль → висока складність
    elif score == 3:
        iterations = 200_000  # Сильний пароль → помірна складність
    else:
        iterations = 100_000  # Дуже складний пароль → швидке хешування

    return iterations

# 🔹 Функція хешування паролю через PBKDF2 + Генерація AES-128 ключа
def generate_user_data(username, password):
    if len(password) > MAX_ZXCVBN_LENGTH:
        password = hashlib.sha512(password.encode()).hexdigest()  # Попереднє хешування SHA-512

    iterations = get_pbkdf2_params(password)
    salt = os.urandom(16)  # Генеруємо випадковий salt
    
    # Генеруємо хеш паролю
    hashed_pw = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations)
    
    # Генеруємо AES-128 ключ із пароля (PBKDF2)
    aes_key = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations, dklen=AES_KEY_LENGTH)

    return {
        'username': username,
        'iterations': iterations,
        'salt': salt.hex(),
        'hash': hashed_pw.hex(),
        'aes_key': b64encode(aes_key).decode()  # Ключ у base64 для читабельності
    }

# 🔹 Зчитування існуючих користувачів
def load_users():
    try:
        with open(USER_DATA_FILE, "r", encoding="utf-8") as file:
            return json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}

# 🔹 Збереження користувачів у JSON
def save_users(users):
    with open(USER_DATA_FILE, "w", encoding="utf-8") as file:
        json.dump(users, file, indent=4)

# 🔹 Основна логіка
def main():
    users = load_users()

    username = input("📝 Введіть логін: ").strip()
    if username in users:
        print("❌ Логін вже існує! Оберіть інший.")
        return

    password = input("🔑 Введіть пароль: ").strip()
    user_data = generate_user_data(username, password)

    users[username] = user_data  # Додаємо нового користувача
    save_users(users)  # Зберігаємо у файл

    print(f"✅ Користувач {username} доданий! Дані збережено у {USER_DATA_FILE}")

# 🔹 Виконання скрипта
if __name__ == "__main__":
    main()

