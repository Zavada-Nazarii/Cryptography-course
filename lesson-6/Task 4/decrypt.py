import gmpy2
from Crypto.Util.number import long_to_bytes

# Читаємо `n` і `ct` з output.txt
with open("output.txt", "r") as f:
    data = f.readlines()

# Отримуємо значення `n` і `ct`
n = int(data[0].split(" = ")[1].strip())
ct = int(data[2].split(" = ")[1].strip())

# Знаходимо цілий корінь третього степеня
pt, is_exact = gmpy2.iroot(ct, 3)  # is_exact показує, чи це точний куб

if is_exact:
    flag = long_to_bytes(int(pt))
    print(f"✅ Розшифрований флаг: {flag.decode()}")
else:
    print("❌ Не вдалося знайти точний кубічний корінь. Можливо, використано padding.")

