#!/usr/bin/env python3

import base64
from cbor2 import dumps
from cwt import COSE, COSEMessage, COSEKey

expected_plaintext_payload = b'This is a real firmware image.'

# See Section 7.1.2 Example (AES-KW + AES-GCM)
# https://datatracker.ietf.org/doc/html/draft-ietf-suit-firmware-encryption#section-7.1.2
print("Example 1: AES-KW")
secret_key_jwk = {
    "kty": "Symmetric",
    "k": "61" * 16, # 0x61 = 'a'
    "alg": "A128KW",
    "kid": "kid-1",
}
print(f"Secret COSE_Key: {secret_key_jwk}")
for key in ["k"]:
    secret_key_jwk[key] = base64.b64encode(bytes.fromhex(secret_key_jwk[key])).decode()
secret_key = COSEKey.from_jwk(secret_key_jwk)

# 1. Load SUIT_Encryption_Info and the detached encrypted payload
with open("./encryption_info_aes.cose", "rb") as f:
    suit_encryption_info_bytes = f.read()
print(f"SUIT_Encryption_Info: {suit_encryption_info_bytes.hex()}")
with open("./encrypted_image_aes.bin", "rb") as f:
    encrypted_payload_bytes = f.read()
print(f"Encrypted Payload: {encrypted_payload_bytes.hex()}")

# 2. Decrypt the Encrypted Payload using SUIT_Encryption_Info
ctx = COSE.new()
result = ctx.decode(suit_encryption_info_bytes, keys=[secret_key], detached_payload=encrypted_payload_bytes)
print(f"\nDecrypted Payload: {result}")
assert result == expected_plaintext_payload
print("Successfully decrypted")


# See Section 7.1.3 Example (ECDH-ES+AES-KW + AES-GCM)
# https://datatracker.ietf.org/doc/html/draft-ietf-suit-firmware-encryption#section-7.1.3
print("Example 2: ECDH-ES+AES-KW + AES-GCM")
receiver_private_key_jwk = {
    "kty": "EC2",
    "crv": "P-256",
    "x": '5886CD61DD875862E5AAA820E7A15274C968A9BC96048DDCACE32F50C3651BA3',
    "y": '9EED8125E932CD60C0EAD3650D0A485CF726D378D1B016ED4298B2961E258F1B',
    "d": '60FE6DD6D85D5740A5349B6F91267EEAC5BA81B8CB53EE249E4B4EB102C476B3',
    "key_ops": ["deriveKey"],
    "alg": "ECDH-ES+A128KW",
    "kid": "kid-2",
}
kdf_context = {
    "alg": "A128KW",
    "supp_pub": {
        "key_data_length": 128,
        "protected": {"alg": "ECDH-ES+A128KW"},
        "other": "SUIT Payload Encryption",
    },
}
print(f"Private COSE_Key: {receiver_private_key_jwk}")
for key in ["x", "y", "d"]:
    receiver_private_key_jwk[key] = base64.b64encode(bytes.fromhex(receiver_private_key_jwk[key])).decode()
receiver_private_key = COSEKey.from_jwk(receiver_private_key_jwk)

# 1. Load SUIT_Encryption_Info and the detached encrypted payload
with open("./encryption_info_esdh.cose", "rb") as f:
    suit_encryption_info_bytes = f.read()
print(f"SUIT_Encryption_Info: {suit_encryption_info_bytes.hex()}")
with open("./encrypted_image_esdh.bin", "rb") as f:
    encrypted_payload_bytes = f.read()
print(f"Encrypted Payload: {encrypted_payload_bytes.hex()}")

# 2. Decrypt the Encrypted Payload using SUIT_Encryption_Info
ctx = COSE.new()
result = ctx.decode(suit_encryption_info_bytes, keys=[receiver_private_key], context=kdf_context, detached_payload=encrypted_payload_bytes)
print(f"\nDecrypted Payload: {result}")
assert result == expected_plaintext_payload
print("Successfully decrypted")

