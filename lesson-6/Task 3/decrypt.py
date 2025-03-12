from Crypto.Util.number import long_to_bytes

# Читаємо `n` і `ct` з файлу output.txt
with open("output.txt", "r") as f:
    data = f.readlines()

# Отримуємо значення `n` і `ct`
n = int(data[0].split(" = ")[1].strip())
ct = int(data[2].split(" = ")[1].strip())

# Оскільки e = 1, то ct = pt, тому просто перетворюємо в байти
flag = long_to_bytes(ct)

print(f"✅ Розшифрований флаг: {flag.decode()}")

