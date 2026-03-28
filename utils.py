# utils.py
import hashlib
import time
# Use the explicit Cryptodome namespace to avoid conflicts with any legacy 'crypto' package on Windows.
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import pad, unpad

def sha256_hex(data_bytes: bytes) -> str:
    
    return hashlib.sha256(data_bytes).hexdigest()

def derive_key_from_password(password: str) -> bytes:

   
    return hashlib.sha256(password.encode()).digest()

def aes_encrypt(plaintext: str, key_bytes: bytes) -> bytes:
    
    key = key_bytes[:16] 
    # Using time as simple IV source (as per original concept)
    iv = hashlib.sha256(key_bytes + str(time.time()).encode()).digest()[:16]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pad(plaintext.encode(), AES.block_size))
    return iv + ct  

def aes_decrypt(iv_and_ct: bytes, key_bytes: bytes) -> str:
    
    key = key_bytes[:16]
    iv = iv_and_ct[:16]
    ct = iv_and_ct[16:]

    cipher = AES.new(key, AES.MODE_CBC, iv)
    pt = unpad(cipher.decrypt(ct), AES.block_size)
    return pt.decode()

def mask_student_id(student_id: str) -> str:
    #Hides the middle of the ID (e.g., 12345 -> 12*45).
    if len(student_id) <= 4:
        return "****"
    return student_id[:2] + "*"*(len(student_id)-4) + student_id[-2:]
