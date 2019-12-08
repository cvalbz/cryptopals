import sys
sys.path.insert(0, '../set_1_basics')
sys.path.insert(0, '../set_5_diffie_hellman_friends')
from diffie_hellman import HonestCryptographer
from utils import random_integer
import sympy
from sha1_keyed_mac import sha1
from hashed_mac import hmac
from implement_rsa import modinv

p = 7199773997391911030609999317773941274322764333428698921736339643928346453700085358802973900485592910475480089726140708102474957429903531369589969318716771
g = 4565356397095740655436854503483826832136106141639563487732438195343690437606117828318042418238184896212352329118608100083187535033402010599512641674644143

q = 236234353446506858198510045061214171961
j = 30477252323177606811760882179058908038824640750610513771646768011063128035873508507547741559514324673960576895059570

def trick_bob_to_communicate(bob, r):
    h = 1

    while h == 1:
        r_int = random_integer(1, p)
        h = pow(r_int, (p-1)/r, p)

    bob.compute_shared_secret(h)

    m = "crazy flamboyant for the rap enjoyment" + "\x10" * 10
    _, iv = bob.send_encrypted_message(m)
    t = bob.send_mac(m)

    return h, m, t

def find_factors_of_j():
    small_primes = sympy.primerange(1, 2**16)

    factors = []
    for sp in small_primes:
        if j % sp == 0:
            factors.append(sp)
    
    return factors

def find_x_mod_r(h, r, m, tag):
    for i in range(0, r):
        k = pow(h, i, p)
        key = bytearray(sha1(str(k)).decode('hex'))[:16]
        if hmac(key, m) == tag:
            return i

    raise Exception('x mod r not found!!!')

def solve_crt(equations):
    ai = [a for (a, m) in equations]
    mi = [m for (a, m) in equations]
    M = reduce(lambda x, y: x*y, mi)

    bi = [M/m for m in mi]

    bi_prime = [modinv(i, j) for (i,j) in zip(bi, mi)]

    x = 0
    for (i,j,k) in zip(ai, bi, bi_prime):
        x = (x + (i * j * k)) % M

    return x

def find_bob_secret_key(bob):
    rs = find_factors_of_j()

    crt_equations = []
    for r in rs:
        h, m, t = trick_bob_to_communicate(bob, r)
        x_mod_r = find_x_mod_r(h, r, m, t)

        crt_equations.append( (x_mod_r, r) )

    secret_key = solve_crt(crt_equations)
    return secret_key

def main():
    alice = HonestCryptographer(p, g, q = q)
    bob   = HonestCryptographer(p, g, q = q)

    alice.generate_keys(subgroup=True)
    bob.generate_keys(subgroup=True)

    secret_key = find_bob_secret_key(bob)

    if secret_key == bob.secret_key:
        print("challenge 7.57 completed.")
    else:
        print("challenge 7.57 failed.")

if __name__ == '__main__':
    main()