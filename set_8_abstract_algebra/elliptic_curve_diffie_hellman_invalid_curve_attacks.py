import sys
sys.path.insert(0, '../set_1_basics')
sys.path.insert(0, '../set_5_diffie_hellman_friends')
from diffie_hellman import HonestCryptographer
from utils import random_integer
from sympy.ntheory import factorint
from diffie_hellman_small_group_confinement import solve_crt
from sha1_keyed_mac import sha1
from hashed_mac import hmac

O = object()

class Point():
    def __init__(self, x, y):
        self.x = x
        self.y = y

    def __str__(self):
        return "(%s, %s)" % (self.x, self.y)

    def __eq__(self, other):
        """Override the default Equals behavior"""
        if isinstance(other, self.__class__):
            return self.__dict__ == other.__dict__
        return NotImplemented

    def __ne__(self, other):
        """Define a non-equality test"""
        if isinstance(other, self.__class__):
            return not self.__eq__(other)
        return NotImplemented

    def __hash__(self):
        """Override the default hash behavior (that returns the id or the object)"""
        return hash(tuple(sorted(self.__dict__.items())))

base_point = Point(182, 85518893674295321206118380980485522083)

def valid(P, a, b, p):
    """
    Determine whether we have a valid representation of a point
    on our curve.  We assume that the x and y coordinates
    are always reduced modulo p, so that we can compare
    two points for equality with a simple ==.
    """
    if P == O:
        return True
    else:
        return (
            (P.y**2 - (P.x**3 + a*P.x + b)) % p == 0 and
            0 <= P.x < p and 0 <= P.y < p)

def inv_mod_p(x, p):
    """
    Compute an inverse for x modulo p, assuming that x
    is not divisible by p.
    """
    if x % p == 0:
        raise ZeroDivisionError("Impossible inverse")
    return pow(x, p-2, p)

def ec_inv(P, a, b, p):
    """
    Inverse of the point P on the elliptic curve y^2 = x^3 + ax + b.
    """
    if P == O:
        return P
    return Point(P.x, (-P.y)%p)

def ec_add(P, Q, a, b, p):
    """
    Sum of the points P and Q on the elliptic curve y^2 = x^3 + ax + b.
    """
    if not (valid(P, a, b, p) and valid(Q, a, b, p)):
        raise ValueError("Invalid inputs")

    # Deal with the special cases where either P, Q, or P + Q is
    # the origin.
    if P == O:
        result = Q
    elif Q == O:
        result = P
    elif Q == ec_inv(P, a, b, p):
        result = O
    else:
        # Cases not involving the origin.
        if P == Q:
            dydx = (3 * P.x**2 + a) * inv_mod_p(2 * P.y, p)
        else:
            dydx = (Q.y - P.y) * inv_mod_p(Q.x - P.x, p)
        x = (dydx**2 - P.x - Q.x) % p
        y = (dydx * (P.x - x) - P.y) % p
        result = Point(x, y)

    # The above computations *should* have given us another point
    # on the curve.
    assert valid(result, a, b, p)
    return result

def ec_scale_point(x, k, a, b, p):
    result = O
    while k > 0:
        if k % 2 == 1:
            result = ec_add(result, x, a, b, p)
        x = ec_add(x, x, a, b, p)
        k = k >> 1
    return result

def generate_keypair(baseorder, a, b, p):
    secret = random_integer(1, baseorder)
    public = ec_scale_point(base_point, secret, a, b, p)
    return (secret, public)

def compute_secret(peer_public, self_secret, a, b, p):
    return ec_scale_point(peer_public, self_secret, a, b, p)

def ec_trick_bob_to_communicate(P, bob_sk, a, b, p):
    bob_shared_secret = compute_secret(P, bob_sk, a, b, p)

    m = "crazy flamboyant for the rap enjoyment" + "\x10" * 10

    fake_bob = HonestCryptographer(1, 1)
    fake_bob.shared_secret = bob_shared_secret
    _, iv = fake_bob.send_encrypted_message(m)
    t = fake_bob.send_mac(m)

    return m, t

def ec_find_x_mod_r(curve, P, r, m, tag):
    a, b, p, order = curve
    for i in range(0, r):
        # print "%s / %s" % (i, r)
        k = ec_scale_point(P, i, a, b, p)
        key = bytearray(sha1(str(k)).decode('hex'))[:16]
        if hmac(key, m) == tag:
            return i

    raise Exception('x mod r not found!!!')

def legendre(a, p):
    return pow(a, (p - 1) // 2, p)
 
def tonelli(n, p):
    assert legendre(n, p) == 1, "not a square (mod p)"
    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1
    if s == 1:
        return pow(n, (p + 1) // 4, p)

    z = 2
    while z < p:
        if p - 1 == legendre(z, p):
            break
        z += 1

    c = pow(z, q, p)
    r = pow(n, (q + 1) // 2, p)
    t = pow(n, q, p)
    m = s
    t2 = 0
    while (t - 1) % p != 0:
        t2 = (t * t) % p
        for i in range(1, m):
            if (t2 - 1) % p == 0:
                break
            t2 = (t2 * t2) % p
        b = pow(c, 1 << (m - i - 1), p)
        r = (r * b) % p
        c = (b * b) % p
        t = (t * c) % p
        m = i
    return r

def generate_points_small_order(curve, r):
    a, b, p, order = curve
    m = order / r

    found = False

    while not found:
        x = random_integer(1, order-1)

        right_side = (pow(x, 3, p) + a * x + b) % p
        if not (legendre(right_side, p) == 1):
            continue
        y = tonelli(right_side, p)
        P_candidate = Point(x, y)
        assert valid(P_candidate, a, b, p)

        # print "trying: %s" % P_candidate
        result = ec_scale_point(P_candidate, m, a, b, p)
        if result != O:
            found = True

    assert ec_scale_point(result, r, a, b, p) == O
    return result


def ec_find_bob_secret_key(bob_sk):
    curve_1 = (233970423115425145524320034830161922882, 210, 233970423115425145524320034830162017933, 233970423115425145550826547352470124412)
    curve_2 = (233970423115425145524320034830161922882, 504, 233970423115425145524320034830162017933, 233970423115425145544350131142039591210)
    curve_3 = (233970423115425145524320034830161922882, 727, 233970423115425145524320034830162017933, 233970423115425145545378039958152057148)

    curve_1_good_small_subgroups = [i for i in factorint(curve_1[3]).keys() if i < 10**6 and i not in [2]]
    curve_2_good_small_subgroups = [i for i in factorint(curve_2[3]).keys() if i < 10**6 and i not in [2, 11]]
    curve_3_good_small_subgroups = [i for i in factorint(curve_3[3]).keys() if i < 10**6 and i not in [2, 7, 23]]

    crt_equations = []

    for curve, subgroups in [(curve_1, curve_1_good_small_subgroups),\
                                  (curve_2, curve_2_good_small_subgroups),\
                                  (curve_3, curve_3_good_small_subgroups)]:
        
        a, b, p, order = curve
        for r in subgroups:
            assert order % r == 0

            P = generate_points_small_order(curve, r)

            m, t = ec_trick_bob_to_communicate(P, bob_sk, a, b, p)
            x_mod_r = ec_find_x_mod_r(curve, P, r, m, t)
            print "found bob_sk modulo %s" % r

            crt_equations.append( (x_mod_r, r) )


    secret_key = solve_crt(crt_equations)
    return secret_key

def main():
    a = 233970423115425145524320034830161922882 # -95051 mod p
    b = 11279326
    p = 233970423115425145524320034830162017933  
    order = 29246302889428143187362802287225875743

    assert valid(base_point, a, b, p)
    assert ec_scale_point(base_point, order, a, b, p) == O

    alice_sk, alice_pk = generate_keypair(order, a, b, p)
    bob_sk, bob_pk = generate_keypair(order, a, b, p)

    alice_shared_secret = compute_secret(bob_pk, alice_sk, a, b, p)
    bob_shared_secret = compute_secret(alice_pk, bob_sk, a, b, p)
    assert bob_shared_secret == alice_shared_secret

    bob_secret_key = ec_find_bob_secret_key(bob_sk)

    if bob_secret_key == bob_sk:
        print("challenge 7.59 completed.")
    else:
        print("challenge 7.59 failed.")

if __name__ == '__main__':
    main()