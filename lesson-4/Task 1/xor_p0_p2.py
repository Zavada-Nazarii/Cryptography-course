from Crypto.Cipher import AES

fake_plain = bytes.fromhex('cf6afc6cf0166f52e699b6493905f55644eb299b18231bd831f86f9c1738caa763ac8cc619ab6083839198bbaeb6bd14')

P0 = fake_plain[:16]
P2 = fake_plain[32:48]

key = bytes([P0[i] ^ P2[i] for i in range(16)])
print(f"Recovered key: {key.hex()}")


