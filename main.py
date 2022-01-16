import random
import sys
from random import SystemRandom  # cryptographic random byte generator

import sympy

rand = SystemRandom()  # create strong random number generator

# variables
message = "Hello W0rld";
lower_bound = 2
upper_bound = 20


# cyclic group (Fq,*) based on generating two prime numbers as p = 2q+1 where p and 1 are primes
def gen_cyclic_group():
    # prime numbers
    q = sympy.randprime(lower_bound, upper_bound)
    p = 2 * q + 1
    print("q: ", q, " p: ", p)

    # Zp group of integers Z_p*
    zp = [x for x in range(p)]
    # group without 0
    zp = zp[1:]

    # find all elements in cyclic Zq with prime order q group:
    group = []
    for integer in zp:
        potential_element = integer ** 2 % p
        group.append(potential_element)
    return list(set(group))


if __name__ == "__main__":
    if len(sys.argv) > 1:
        # reading message
        message = str(sys.argv[1])

    # creating cyclic group
    cyclic_group = gen_cyclic_group()
    # prime number p
    p = len(cyclic_group)
    # random number from cyclic group
    r = random.choice(cyclic_group)
    generator = 0
    print("p: ", p, "generator: ", generator, " random number: ", r, "group: ", cyclic_group)
