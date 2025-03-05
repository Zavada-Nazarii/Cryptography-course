from Crypto.Cipher import AES

fake_plain = bytes.fromhex('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa461cb3c94e389b30efcff80a633f33da066cda004317a57bcfa284583d19e2e8')

P0 = fake_plain[:16]
P2 = fake_plain[32:48]

key = bytes([P0[i] ^ P2[i] for i in range(16)])
print(f"Recovered key: {key.hex()}")


