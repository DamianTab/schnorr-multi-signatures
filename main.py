import hashlib
import random
import sys
from random import SystemRandom  # cryptographic random byte generator

import sympy

rand = SystemRandom()  # create strong random number generator

# variables
message = "Hello W0rld";
lower_bound = 100
upper_bound = 200


# cyclic prime order subgroup (Fq,*) based on generating two prime numbers as p = 2q+1 where p and q are primes
def gen_cyclic_prime_subgroup():
    # prime numbers
    q = sympy.randprime(lower_bound, upper_bound)
    p = 2 * q + 1
    while not sympy.isprime(p):
        q = sympy.randprime(lower_bound, upper_bound)
        p = 2 * q + 1
    print("Cyclic group generation - q: ", q, " p: ", p)

    # Zp group of integers Z_p*
    zp = [x for x in range(p)]
    # group without 0
    zp = zp[1:]

    # find all elements in cyclic Zq with prime order q group:
    group = []
    for integer in zp:
        potential_element = pow(integer, 2, p)
        group.append(potential_element)
    return list(set(group)), p


if __name__ == "__main__":

    if len(sys.argv) > 1:
        # reading message
        message = str(sys.argv[1])

    # creating cyclic group
    cyclic_group, p = gen_cyclic_prime_subgroup()
    # Every element from prime order cyclic group exclusiv 1 is generator
    generator = 1
    while generator == 1:
        generator = random.choice(cyclic_group)

    print(f"generator: {generator}\t group: {cyclic_group}\t p: {p}\t")

    # private key
    x = random.choice(cyclic_group)
    print(f"x: {x}")
    # public key
    X = pow(generator, x, p)
    print(f"X: {X}")

    ### Sending message
    # random number from cyclic group
    r = random.choice(cyclic_group)
    print(f"random number: {r}\t")
    R = pow(generator, r, p)
    print(f"R: {R}\t")

    hash = hashlib.sha256()
    hash.update(X.to_bytes(4, byteorder='big'))
    hash.update(R.to_bytes(4, byteorder='big'))
    hash.update(message.encode('utf-8'))
    # For hexadecimal use hexdigest
    c_hash = hash.digest()
    # The signature is R and s -> (R,s)
    c = int.from_bytes(c_hash, 'big')
    print(f"c= {c}")
    s = r + c * x
    print(f"s: {s}")

    ### Verification
    left_side = pow(generator, s, p)
    print(f"leftside= {left_side}")
    print(f"pow(X, c, p)= {pow(X, c, p)}")
    right_side = (R * pow(X, c, p)) % p
    # leftside pow(generator, s, p); rightside R * pow(X, c, p)
    print(f"leftside  = {left_side} and rightside = {right_side} is equals?: {left_side == right_side}")
