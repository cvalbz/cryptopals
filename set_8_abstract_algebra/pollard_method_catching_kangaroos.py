import sys
sys.path.insert(0, '../set_1_basics')
sys.path.insert(0, '../set_5_diffie_hellman_friends')
from diffie_hellman import HonestCryptographer
from utils import random_integer
from implement_rsa import modinv

p = 11470374874925275658116663507232161402086650258453896274534991676898999262641581519101074740642369848233294239851519212341844337347119899874391456329785623
q = 335062023296420808191071248367701059461
j = 34233586850807404623475048381328686211071196701374230492615844865929237417097514638999377942356150481334217896204702
g = 622952335333961296978159266084741085889881358738459939978290179936063635566740258555167783009058567397963466103140082647486611657350811560630587013183357

k = 20

def brute_force_dlp(y):
    for i in xrange(1, 2**20):
        if pow(g, i, p) == y:
            return i
    raise Exception('brute force failed!!!')

def f(y):
    return pow(2, y % k)

def define_N(f):
    c = 2

    s = sum([f(i) for i in xrange(k)])
    m = (s / k) * c

    return m

def tame_kangaroo(b, y, g):
    N = define_N(f)

    xT = 0
    yT = pow(g, b, p)

    i = 1
    while i < N:
        xT = xT + f(yT)
        yT = (yT * pow(g, f(yT), p)) % p
        i += 1

    return (xT, yT)

def wild_kangaroo(a, b, y, g):
    N = define_N(f)

    (xT, yT) = tame_kangaroo(b, y, g)

    xW = 0
    yW = y

    while xW < b - a + xT:
        xW = xW + f(yW)
        yW = (yW * pow(g, f(yW), p)) % p

        if yW == yT:
            return b + xT - xW


def transform(y, r, n):
    g_ = pow(g, r, p)
    y_ = y * modinv(pow(g, n, p), p)

    return y_, g_


def main():
    alice = HonestCryptographer(p, g, q = q)
    bob   = HonestCryptographer(p, g, q = q)

    alice.generate_keys(subgroup=True)
    bob.generate_keys(subgroup=True)

    #### subchallenge 1 ####
    y = 7760073848032689505395005705677365876654629189298052775754597607446617558600394076764814236081991643094239886772481052254010323780165093955236429914607119

    x = brute_force_dlp(y)
    print "Brute forced DLP: %s" % x

    a, b = 0, 2**20
    x = wild_kangaroo(a, b, y, g)
    print "Pollard kangaroo method DLP (subchallenge 1): %s" % x

    #### subchallenge 2 ####
    y = 9388897478013399550694114614498790691034187453089355259602614074132918843899833277397448144245883225611726912025846772975325932794909655215329941809013733

    a, b = 0, 2**40
    x = wild_kangaroo(a, b, y, g)
    print "Pollard kangaroo method DLP (subchallenge 2): %s" % x
    assert pow(g, 359579674340, p) == y

    #### subchallenge 3 - extra info ####

    r = random_integer(2, q-1)
    n = bob.secret_key % r
    y_, g_ = transform(bob.public_key, r, n)

    m = wild_kangaroo(0, (q-1)/r, y_, g_)
    x = n + r * m

    if x == bob.secret_key:
        print("challenge 7.58 completed.")
    else:
        print("challenge 7.58 failed.")

if __name__ == '__main__':
    main()