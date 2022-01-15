import random
import sys
from random import SystemRandom  # cryptographic random byte generator
import sympy

rand = SystemRandom()  # create strong random number generator

# variables
message = "Hello W0rld";
lower_bound = 2
upper_bound = 10


# cyclic group (Fq,*)
def gen_cyclic_group():
    result = []
    power = 1
    for _ in range(upper_bound):
        result.append(generator ** power)
        power += 1
    print("cyclic group: ", result)
    # print([x/13 for x in result])
    return result


if __name__ == "__main__":
    if len(sys.argv) > 1:
        # reading message
        message = str(sys.argv[1])
    # prime number
    q = sympy.randprime(lower_bound, upper_bound)
    # generator for cyclic group
    generator = rand.randint(lower_bound, upper_bound)
    # creating cyclic group
    cyclic_group = gen_cyclic_group()
    # random from cyclic group
    r = random.choice(cyclic_group)


