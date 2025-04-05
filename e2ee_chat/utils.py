from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

SERVER_PORT = 8888

def pack_message(dh_pub, nonce, ciphertext, signature):
    return dh_pub + nonce + ciphertext + signature

def unpack_message(data):
    return data[:32], data[32:44], data[44:-64], data[-64:]