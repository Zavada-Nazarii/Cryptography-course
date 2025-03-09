import hashlib
import os
import json
from zxcvbn import zxcvbn

PASSWORDS_FILE = "passwords.txt"
HASHED_OUTPUT_FILE = "hashed_passwords.json"
MAX_ZXCVBN_LENGTH = 72  # Обмеження для zxcvbn

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

# 🔹 Функція хешування паролю через PBKDF2
def hash_password_pbkdf2(password):
    if len(password) > MAX_ZXCVBN_LENGTH:
        password = hashlib.sha512(password.encode()).hexdigest()  # Попереднє хешування SHA-512

    iterations = get_pbkdf2_params(password)
    salt = os.urandom(16)  # Генеруємо випадковий salt
    hashed_pw = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, iterations)
    
    return {
        'iterations': iterations,
        'salt': salt.hex(),
        'hash': hashed_pw.hex()
    }

# 🔹 Зчитування паролів із файлу
def read_passwords_from_file(filename):
    try:
        with open(filename, "r", encoding="utf-8") as file:
            passwords = [line.strip() for line in file if line.strip()]
        return passwords
    except FileNotFoundError:
        print(f"❌ Помилка: файл {filename} не знайдено.")
        return []

# 🔹 Основна логіка хешування
passwords = read_passwords_from_file(PASSWORDS_FILE)
hashed_passwords = {pw: hash_password_pbkdf2(pw) for pw in passwords}

# 🔹 Збереження у файл JSON
with open(HASHED_OUTPUT_FILE, "w", encoding="utf-8") as file:
    json.dump(hashed_passwords, file, indent=4)

print(f"✅ Паролі успішно захешовані та збережені у {HASHED_OUTPUT_FILE}.")

