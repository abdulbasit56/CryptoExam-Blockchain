# protocols.py
# Custom cryptographic protocols built on math primitives from crypto_math.
#
# NOTE ON OPPOSITES:
# This file demonstrates the two "mirror" functions of cryptography:
# 1. ENCRYPTION (ElGamal): Uses Bob's Public Key to LOCK. 
#    Only Bob's Private Key can UNLOCK.
#    Goal: Secrecy (Only Bob can read it).
#
# 2. SIGNATURE (RSA): Uses Alice's Private Key to SIGN. 
#    Alice's Public Key is used to VERIFY.
#    Goal: Authenticity (Proves Alice wrote it).

import os
import json
import random
import hashlib
from typing import List, Tuple, Dict

from crypto_math import fast_pow, mod_inverse, is_prime


def _random_bigint(bits: int = 256) -> int:
    return random.getrandbits(bits)


class DiffieHellman:
    def __init__(self, p: int, g: int):
        self.p = p
        self.g = g
        self.private = random.randint(2, p - 2)
        self.public = fast_pow(self.g, self.private, self.p)

    def compute_shared(self, other_public: int) -> int:
        return fast_pow(other_public, self.private, self.p)


class CustomElGamal:
    """
    ENCRYPTION PROTOCOL (Confidentiality)
    -------------------------------------
    This is the "Forward" direction:
    1. Use Receiver's Public Key (B) to ENCRYPT.
    2. Use Receiver's Private Key (b) to DECRYPT.
    
    Educational ElGamal implementation on Z_p*.
    Roles: 
    - Bob (Receiver) chooses secret 'b' and publishes B = g^b mod p.
    - Alice (Sender) chooses fresh random 'a', computes shared secret s = B^a mod p.
    - Alice sends (A, X) where A = g^a mod p and X = m * s mod p.
    """
    def __init__(self, p: int, g: int, b: int = None, B: int = None):
        self.p = p
        self.g = g
        # If private key b is provided, compute B. If only B is provided, use it (public-only instance).
        if b is not None:
            self.b = b
            self.B = fast_pow(self.g, self.b, self.p)
        elif B is not None:
            self.b = None
            self.B = B
        else:
            # Generate full keypair if nothing supplied.
            self.b = random.randint(2, p - 2)
            self.B = fast_pow(self.g, self.b, self.p)

    def public_key(self) -> Dict[str, int]:
        return {"p": self.p, "g": self.g, "B": self.B}

    def private_key(self) -> Dict[str, int]:
        return {"p": self.p, "g": self.g, "b": self.b}

    @classmethod
    def from_keys(cls, public: Dict[str, int], private: Dict[str, int] = None):
        private = private or {}
        b = private.get("b")
        B = public.get("B")
        return cls(public["p"], public["g"], b=b, B=B)

    def encrypt_int(self, m: int) -> Tuple[int, int]:
        if m >= self.p:
            raise ValueError("Plaintext too large for modulus")
        # Alice’s fresh secret a for this encryption
        a = random.randint(2, self.p - 2)
        
        # A = g^a mod p (Alice's half of the DH handshake)
        A = fast_pow(self.g, a, self.p)
        
        # Shared secret s = B^a mod p
        s = fast_pow(self.B, a, self.p) 
        
        # Ciphertext component X = m * s mod p
        X = (m * s) % self.p             
        return A, X

    def decrypt_int(self, A: int, X: int) -> int:
        # Recompute shared secret s = A^b mod p
        s = fast_pow(A, self.b, self.p)
        
        # Calculate inverse of s to remove it from X
        s_inv = mod_inverse(s, self.p)
        return (X * s_inv) % self.p

    def encrypt_text(self, text: str) -> Tuple[int, int]:
        m_int = int.from_bytes(text.encode("utf-8"), "big")
        return self.encrypt_int(m_int)

    def decrypt_text(self, A: int, X: int) -> str:
        m_int = self.decrypt_int(A, X)
        length = (m_int.bit_length() + 7) // 8
        return m_int.to_bytes(length, "big").decode("utf-8")


class CustomRSA:
    """
    SIGNATURE PROTOCOL (Authenticity)
    ---------------------------------
    This is the "Reverse" direction:
    1. Use Signer's Private Key (a) to SIGN.
    2. Use Signer's Public Key (A) to VERIFY.
    
    Variable Legend (Standard Exam Notation):
    n   : Public Modulus (The "Clock" of the public world).
    phi : Euler's Totient (The "Clock" of the secret world).
    A   : Public Key (Alice's Public Component).
    a   : Private Key (Alice's Private Component).
    """
    def __init__(self, n: int, A: int, a: int):
        self.n = n
        self.A = A
        self.a = a

    @staticmethod
    def _generate_prime(bits: int) -> int:
        while True:
            candidate = random.getrandbits(bits) | 1
            if is_prime(candidate):
                return candidate

    @classmethod
    def generate_keys(cls, bits: int = 512, A: int = 65537):
        # 1. Generate two secret primes
        prime1 = cls._generate_prime(bits // 2)
        prime2 = cls._generate_prime(bits // 2)
        
        # 2. Calculate n (Public Modulus)
        n = prime1 * prime2
        
        # 3. Calculate phi (Euler's Totient)
        # This acts as the secret "gear ratio" for the keys.
        phi = (prime1 - 1) * (prime2 - 1)
        
        # 4. Calculate Private Key 'a'
        # We find the inverse of Public Key 'A' using the SECRET clock (phi).
        # This works because: a * A = 1 (mod phi)
        a = mod_inverse(A, phi)
        
        return cls(n, A, a)

    def _hash(self, message: str) -> int:
        """Converts message to an integer < n"""
        digest = hashlib.sha256(message.encode("utf-8")).digest()
        return int.from_bytes(digest, "big") % self.n

    def sign(self, message: str) -> int:
        msgHash = self._hash(message)
        
        # Logic: encryptedMsgHash = msgHash^a mod n
        # "Sign with my Private Key (a)"
        encryptedMsgHash = fast_pow(msgHash, self.a, self.n)
        return encryptedMsgHash

    def verify(self, message: str, encryptedMsgHash: int) -> bool:
        msgHash = self._hash(message)
        
        # Logic: check if encryptedMsgHash^A mod n == msgHash
        # "Verify with Alice's Public Key (A)"
        check = fast_pow(encryptedMsgHash, self.A, self.n)
        return check == msgHash

    def export_public(self) -> Dict[str, int]:
        return {"n": self.n, "A": self.A}

    def export_private(self) -> Dict[str, int]:
        return {"n": self.n, "A": self.A, "a": self.a}


class LamportSignature:
    def __init__(self):
        # We process the message as a 256-bit hash (SHA-256).
        # We need a key pair (0 and 1) for every single bit.
        self.num_bits = 256
        self.is_used = False

    def generate_keys(self) -> Tuple[List[int], List[str]]:
        # The Private Key is just a massive list of 512 random numbers.
        # (2 numbers for each of the 256 bits).
        full_private_key = []
        # The Public Key is the list of hashes of those numbers.
        full_public_key = []
        for _ in range(self.num_bits * 2):
            # 1. Create a random number (A piece of the Private Key)
            private_part = _random_bigint(256)
            full_private_key.append(private_part)
            # 2. Hash it to create the Public Key part
            # Everyone sees this hash, but they can't reverse it to find the private number.
            public_part = hashlib.sha256(private_part.to_bytes(32, "big")).hexdigest()
            full_public_key.append(public_part)
        return full_private_key, full_public_key

    def sign(self, message: bytes, full_private_key: List[int]) -> List[str]:
        if self.is_used:
            raise ValueError("SECURITY ALERT: keys cannot be reused!")
        # 1. Hash the message to get the "instructions" (0s and 1s)
        msg_hash_bytes = hashlib.sha256(message).digest()
        # The Signature will be a collection of revealed private keys.
        revealed_private_keys = []
        for i in range(self.num_bits):
            # 2. Check the bit value of the message at this position (0 or 1)
            byte_idx = i // 8
            bit_in_byte = 7 - (i % 8)
            bit_value = (msg_hash_bytes[byte_idx] >> bit_in_byte) & 1
            # 3. SELECT: The message bit tells us WHICH Private Key to broadcast.
            # If bit is 0, we grab the first key of the pair.
            # If bit is 1, we grab the second key of the pair.
            key_index = (i * 2) + bit_value
            # 4. BROADCAST: We take that specific secret number...
            specific_private_key = full_private_key[key_index]
            # ...and add it to our broadcast package (the signature).
            revealed_private_keys.append(specific_private_key.to_bytes(32, "big").hex())
        self.is_used = True
        return revealed_private_keys

    def verify(self, message: bytes, revealed_private_keys: List[str], full_public_key: List[str]) -> bool:
        # 1. The Verifier calculates the bits of the message again.
        msg_hash_bytes = hashlib.sha256(message).digest()
        if len(revealed_private_keys) != self.num_bits:
            return False
        for i in range(self.num_bits):
            # Get the message bit (0 or 1)
            byte_idx = i // 8
            bit_in_byte = 7 - (i % 8)
            bit_value = (msg_hash_bytes[byte_idx] >> bit_in_byte) & 1
            # 2. The Verifier checks the Public Key list.
            # "Since the message bit is X, the signer SHOULD have used the key at index Y."
            expected_index = (i * 2) + bit_value
            expected_public_hash = full_public_key[expected_index]
            # 3. Hash the Private Key the signer broadcasted.
            received_private_key_bytes = bytes.fromhex(revealed_private_keys[i])
            hash_of_received_key = hashlib.sha256(received_private_key_bytes).hexdigest()
            # 4. Compare:
            # Does the hash of what they sent match the Public Key on record?
            if hash_of_received_key != expected_public_hash:
                return False # Fraud! The key they sent doesn't match the lock for this message bit.
        return True


def save_json(path: str, data: dict):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)


def load_json(path: str):
    if not os.path.exists(path):
        return None
    with open(path, "r") as f:
        return json.load(f)
