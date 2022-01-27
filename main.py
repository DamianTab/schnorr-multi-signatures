import hashlib
import logging
import random
import sys
from abc import ABC, abstractmethod
from random import SystemRandom  # cryptographic random byte generator

import sympy

rand = SystemRandom()  # create strong random number generator

# variables
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s | %(levelname)s | %(message)s')
message_content = "Hello W0rld";
lower_bound = 100
upper_bound = 200

#todo we should know the real parameter size like p, q, message size, signature time, verification time, overall runtime
# todo how bitcoin works with multisignature, generally examples
# todo maybe security

class CyclicGroup:
    def __init__(self):
        self.p = 0
        self.elements = []
        self.generator = 0
    #     todo move hash function


    # cyclic prime order subgroup (Fq,*) based on generating two prime numbers as p = 2q+1 where p and q are primes
    def generate_prime_order_subgroup(self):
        # prime numbers
        q = sympy.randprime(lower_bound, upper_bound)
        self.p = 2 * q + 1
        while not sympy.isprime(self.p):
            q = sympy.randprime(lower_bound, upper_bound)
            self.p = 2 * q + 1
        logging.debug("Cyclic group generation - q: %i, p: %i", q, self.p)

        # Zp group of integers Z_p*
        zp = [x for x in range(self.p)]
        # group without 0
        zp = zp[1:]

        # find all elements in cyclic Zq with prime order q group:
        group = []
        for integer in zp:
            potential_element = pow(integer, 2, self.p)
            group.append(potential_element)
        self.elements = list(set(group))

    def select_generator(self):
        generator = 1
        while generator == 1:
            generator = random.choice(self.elements)
        self.generator = generator
        logging.debug(f"generator: {generator}\t p: {self.p}\t group: {self.elements}\t")


class Signature(ABC):
    def __init__(self, cyclic_group):
        self.cyclic_group = cyclic_group
        self.private_key = 0
        self.public_key = 0
        self.hash_name = "sha256"

    def generate_keys(self):
        self.private_key = random.choice(cyclic_group.elements)
        logging.debug(f"private key: {self.private_key}")
        self.public_key = pow(cyclic_group.generator, self.private_key, cyclic_group.p)
        logging.debug(f"public key: {self.public_key}")
        return self.public_key

    def compute_challenge(self, message, X, R):
        hash = hashlib.new(self.hash_name)
        hash.update(X.to_bytes(4, byteorder='big'))
        hash.update(R.to_bytes(4, byteorder='big'))
        hash.update(message.encode('utf-8'))
        c_hash = hash.digest()
        c = int.from_bytes(c_hash, 'big')
        logging.debug(f"c= {c}")
        return c

    @abstractmethod
    def sign_message(self, message):
        pass

    @abstractmethod
    def verify_message(self, message, signers, R, s):
        pass


class SchnorrSignature(Signature):

    def __init__(self, cyclic_group):
        super().__init__(cyclic_group)

    def sign_message(self, message):
        # random number from cyclic group
        r = random.choice(cyclic_group.elements)
        R = pow(cyclic_group.generator, r, cyclic_group.p)
        logging.debug(f"random number: {r}\t R: {R}\t")

        c = self.compute_challenge(message, self.public_key, R)
        s = r + c * self.private_key
        logging.debug(f"s: {s}")
        # The signature is R and s -> (X,R,s)
        return self.public_key, R, s

    def verify_message(self, message, signers, R, s):
        # signer's public key
        X = signers[0]

        left_side = pow(cyclic_group.generator, s, cyclic_group.p)
        logging.debug(f"leftside= {left_side}")
        c = self.compute_challenge(message, X, R)
        logging.debug(f"pow(X, c, p)= {pow(X, c, cyclic_group.p)}")
        right_side = (R * pow(X, c, cyclic_group.p)) % cyclic_group.p
        # leftside pow(generator, s, p); rightside (R * pow(X, c, p) )   mod p
        logging.debug(f"leftside  = {left_side} and rightside = {right_side} is equals?: {left_side == right_side}")
        return left_side == right_side


if __name__ == "__main__":
    if len(sys.argv) > 1:
        # reading message
        message_content = str(sys.argv[1])

    # Setup
    cyclic_group = CyclicGroup()
    cyclic_group.generate_prime_order_subgroup()
    cyclic_group.select_generator()

    # Key generation
    sig1 = SchnorrSignature(cyclic_group)
    sig1.generate_keys()

    sig2 = SchnorrSignature(cyclic_group)
    sig2.generate_keys()

    sig3 = SchnorrSignature(cyclic_group)
    sig3.generate_keys()

    # Signature
    signers = []
    X, R, s = sig1.sign_message(message_content)
    signers.append(X)

    # Verification
    result = sig2.verify_message(message_content, signers, R, s)

    # todo add maxwell signature
