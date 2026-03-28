
import random

def fast_pow(base: int, power: int, mod: int) -> int:
  
    result = 1
    while power > 0:

        if power % 2 == 1:
            result = (result * base) % mod

        base = (base * base) % mod
        power = power // 2
    return result

def find_gcd(a: int, b: int) -> int:

    #Euclidean Algorithm.
    while b:
        a, b = b, a % b
    return a

def extended_gcd(a: int, b: int):
    """
    Iterative Extended Euclidean Algorithm.
    Returns (g, x, y) such that a*x + b*y = g = gcd(a, b).
    Matches the original recursive semantics but avoids recursion depth limits.
    """
    old_r, r = a, b
    old_s, s = 1, 0
    old_t, t = 0, 1
    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t
    return old_r, old_s, old_t


def mod_inverse(a: int, m: int) -> int:
    """Modular inverse using iterative EEA (keeps recursion depth low)."""
    g, x, _ = extended_gcd(a % m, m)
    if g != 1:
        raise Exception('Modular inverse does not exist')
    return x % m

def is_prime(n: int, k: int = 5):

    #Miller-Rabin Primality Test.

    if n <= 1: return False
    if n <= 3: return True
    if n % 2 == 0: return False

    r, d = 0, n - 1
    while d % 2 == 0:

        r += 1
        d //= 2

    for _ in range(k):

        a = random.randint(2, n - 2)
        x = fast_pow(a, d, n)
    
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = fast_pow(x, 2, n)
            if x == n - 1:
                break
        else:

            return False
    return True
