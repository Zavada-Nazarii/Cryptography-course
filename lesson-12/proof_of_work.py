import hashlib
import time

# Складність PoW – кількість нулів на початку хешу
DIFFICULTY = 5

# Хеш-функція SHA-256 для блоку
def calculate_hash(data, prev_hash, nonce):
    block_content = f"{data}{prev_hash}{nonce}".encode()
    return hashlib.sha256(block_content).hexdigest()

# Клас Блоку
class Block:
    def __init__(self, data, prev_hash=""):
        self.data = data
        self.prev_hash = prev_hash
        self.nonce = 0
        self.hash = ""

# Процес майнінгу блоку – Proof-of-Work
def mine_block(block, difficulty):
    prefix = '0' * difficulty
    nonce = 0
    while True:
        hash_attempt = calculate_hash(block.data, block.prev_hash, nonce)
        if hash_attempt.startswith(prefix):
            block.nonce = nonce
            block.hash = hash_attempt
            break
        nonce += 1

# Додавання нового блоку до блокчейну
def add_block(blockchain, data):
    prev_block = blockchain[-1]
    new_block = Block(data=data, prev_hash=prev_block.hash)
    print(f"Майнінг нового блоку з даними: {data} ...")
    start_time = time.time()
    mine_block(new_block, DIFFICULTY)
    end_time = time.time()
    blockchain.append(new_block)
    print(f"✅ Блок додано: Hash={new_block.hash}, Nonce={new_block.nonce}, Час майнінгу={end_time - start_time:.2f} сек\n")

# Ініціалізація блокчейну
def create_blockchain(values):
    blockchain = []
    print("Генерація Genesis Block...")
    genesis_block = Block(data="Genesis", prev_hash="")
    mine_block(genesis_block, DIFFICULTY)
    blockchain.append(genesis_block)
    print(f"✅ Genesis Block додано: Hash={genesis_block.hash}, Nonce={genesis_block.nonce}\n")
    
    for value in values:
        add_block(blockchain, value)
    
    return blockchain

# Тестові дані
values = [91911, 90954, 95590, 97390, 96578, 97211, 95090]

# Створення блокчейну
blockchain = create_blockchain(values)

# Вивід всієї інформації
print("\n📦 Вміст Blockchain:")
for i, block in enumerate(blockchain):
    print(f"Блок {i}:")
    print(f"  Data       : {block.data}")
    print(f"  Prev Hash  : {block.prev_hash}")
    print(f"  Nonce      : {block.nonce}")
    print(f"  Hash       : {block.hash}")
    print()

