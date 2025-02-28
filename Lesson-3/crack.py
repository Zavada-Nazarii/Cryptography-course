import string
import time
import requests

def encrypt(pt_hex):
    """Отримати зашифрований текст через Oracle"""
    url = f"http://aes.cryptohack.org/ecb_oracle/encrypt/{pt_hex}/"
    
    r = requests.get(url)
    if r.status_code != 200:
        print(f"HTTP Error {r.status_code}: {r.text}")
        return None
    
    return r.json().get("ciphertext", "")

def print_blk(text, size=32):
    """Вивести текст у вигляді блоків"""
    parts = [text[i:i+size] for i in range(0, len(text), size)]
    print(" | ".join(parts))

def crack():
    flag = ''
    total = 32 - 1
    alphabet = '_@}{' + string.digits + string.ascii_lowercase + string.ascii_uppercase

    while True:
        payload = 'A' * (total - len(flag))
        expected = encrypt(payload.encode().hex())
        print(f"Еталонний {expected}")
        if expected is None:
            print("Помилка при отриманні відповіді від сервера, спробую ще раз...")
            time.sleep(3)
            continue

        print('E', '', end='')
        print_blk(expected, 32)
        
        for c in alphabet: 
            res = encrypt((payload + flag + c).encode().hex())

            if res is None:
                print(f"Помилка при перевірці символу {c}, пропускаємо...")
                time.sleep(3)
                continue

            print(c, '', end='')
            print_blk(res, 32)

            if res[32:64] == expected[32:64]:
                flag += c
                print(f"🔓 Поточний фрагмент прапора: {flag}")
                break
            
            time.sleep(0.5)  # Зменшуємо навантаження на сервер

        if flag.endswith('}'): 
            print(f"✅ Прапор знайдено: {flag}")
            break

    return flag

crack()

