from binascii import hexlify
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh, rsa, padding
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    NoEncryption,
    PublicFormat,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Генерація параметрів DH (спільних для всіх)
print("Generating DH parameters...")
parameters = dh.generate_parameters(generator=2, key_size=2048)
print("\nModule:\n", parameters.parameter_numbers().p)
print("\nGen:", parameters.parameter_numbers().g)

# Генерація RSA-ключів для цифрового підпису
alice_rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
alice_rsa_public_key = alice_rsa_private_key.public_key()

bob_rsa_private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
bob_rsa_public_key = bob_rsa_private_key.public_key()

# Alice: створення DH-ключів
alice_private_key = parameters.generate_private_key()  # a
alice_public_key = alice_private_key.public_key()  # g^a

# Підпис відкритого ключа Alice
alice_signature = alice_rsa_private_key.sign(
    alice_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo),
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
    hashes.SHA256(),
)

# Bob: створення DH-ключів
bob_private_key = parameters.generate_private_key()  # b
bob_public_key = bob_private_key.public_key()  # g^b

# Підпис відкритого ключа Bob
bob_signature = bob_rsa_private_key.sign(
    bob_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo),
    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
    hashes.SHA256(),
)

# Alice --> Bob: alice_public_key, alice_signature
# Bob --> Alice: bob_public_key, bob_signature

# Bob: перевірка підпису Alice
try:
    alice_rsa_public_key.verify(
        alice_signature,
        alice_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    print("\n✅ Підпис Alice вірний!")
except Exception as e:
    print("\n❌ Помилка перевірки підпису Alice:", e)

# Alice: перевірка підпису Bob
try:
    bob_rsa_public_key.verify(
        bob_signature,
        bob_public_key.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    print("✅ Підпис Bob вірний!")
except Exception as e:
    print("❌ Помилка перевірки підпису Bob:", e)

# Alice: обчислення спільного ключа
alice_shared_value = alice_private_key.exchange(bob_public_key)
print("\nShared secret value:\n", hexlify(alice_shared_value))
alice_derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,  # Важливо не додавати рандомізацію для отримання однакового ключа з обох сторін.
    info=b"handshake data",
).derive(alice_shared_value)
print("\nDerived secret key:\n", hexlify(alice_derived_key))

# Bob: обчислення спільного ключа
bob_shared_value = bob_private_key.exchange(alice_public_key)
print("\nShared secret value:\n", hexlify(bob_shared_value))
bob_derived_key = HKDF(
    algorithm=hashes.SHA256(),
    length=32,
    salt=None,  # Важливо не додавати рандомізацію для отримання однакового ключа з обох сторін.
    info=b"handshake data",
).derive(bob_shared_value)

print("\nDerived secret key:\n", hexlify(bob_derived_key))
print("\nShared values equal?\t", alice_shared_value == bob_shared_value)
print("Shared keys equal?\t", alice_derived_key == bob_derived_key)

