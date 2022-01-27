import hashlib
import logging
import random
import sys
from abc import ABC, abstractmethod
from random import SystemRandom  # cryptographic random byte generator

import sympy

rand = SystemRandom()  # create strong random number generator
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s | %(levelname)s | %(message)s')

# variables
message_content = "Hello W0rld";
prime_number_lower_bound = 100
prime_number_upper_bound = 200


def log(phase, subject, message, *args):
    logging.debug(" OBJECT: %-22s |\t PHASE: %-23s | \t" + message, subject, phase, *args)


# todo we should know the real parameter size like p, q, message size, signature time, verification time, overall runtime
# todo how bitcoin works with multisignature, generally examples
# todo maybe security

class CyclicGroup:
    def __init__(self):
        self.object_name = "Schnorr cyclic group"
        self.p = 0
        self.elements = []
        self.generator = 0
        self.hash_name = "sha256"

    # cyclic prime order subgroup (Fq,*) based on generating two prime numbers as p = 2q+1 where p and q are primes
    def generate_prime_order_subgroup(self):
        # prime numbers
        q = sympy.randprime(prime_number_lower_bound, prime_number_upper_bound)
        self.p = 2 * q + 1
        while not sympy.isprime(self.p):
            q = sympy.randprime(prime_number_lower_bound, prime_number_upper_bound)
            self.p = 2 * q + 1
        log("Setup", self.object_name, "Cyclic group generation - q: %i, p: %i", q, self.p)

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
        log("Setup", self.object_name, "generator: %s\t p: %s\t\t group: %s\t", self.generator, self.p, self.elements)


class Signer(ABC):
    signers_number = 0

    def __init__(self, cyclic_group):
        Signer.signers_number += 1
        self.object_name = "Signer-" + str(self.signers_number)
        self.cyclic_group = cyclic_group
        self.private_key = 0
        self.public_key = 0

    def generate_keys(self):
        self.private_key = random.choice(cyclic_group.elements)
        self.public_key = pow(cyclic_group.generator, self.private_key, cyclic_group.p)
        log("Key generation", self.object_name, "private key: %s, public key: %s", self.private_key, self.public_key)
        return self.public_key

    def compute_challenge(self, message, X, R):
        hash = hashlib.new(cyclic_group.hash_name)
        hash.update(X.to_bytes(4, byteorder='big'))
        hash.update(R.to_bytes(4, byteorder='big'))
        hash.update(message.encode('utf-8'))
        c_hash = hash.digest()
        c = int.from_bytes(c_hash, 'big')
        log("---", self.object_name, "c= %i", c)
        return c

    @abstractmethod
    def sign_message(self, message):
        pass

    @abstractmethod
    def verify_message(self, message, signers, R, s):
        pass


class SchnorrSigner(Signer):

    def __init__(self, cyclic_group):
        super().__init__(cyclic_group)

    # The signature is R and s -> (R,s)
    def sign_message(self, message):
        # random number from cyclic group
        r = random.choice(cyclic_group.elements)
        R = pow(cyclic_group.generator, r, cyclic_group.p)
        c = self.compute_challenge(message, self.public_key, R)
        s = r + c * self.private_key
        log("Signature", self.object_name, "r: %i\t R: %i\t s: %i", r, R, s)
        # todo wywalic X
        return self.public_key, R, s

    def verify_message(self, message, signers, R, s):
        # signer's public key
        X = signers[0]

        left_side = pow(cyclic_group.generator, s, cyclic_group.p)
        c = self.compute_challenge(message, X, R)
        right_side = (R * pow(X, c, cyclic_group.p)) % cyclic_group.p

        # leftside pow(generator, s, p); rightside (R * pow(X, c, p) )  mod p
        log("Verification", self.object_name, "g^s mod p  = %i \t|\t R*X^c mod p = %i \t|\t is equals?: %s", left_side,
            right_side, left_side == right_side)
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
    signer1 = SchnorrSigner(cyclic_group)
    signer1.generate_keys()

    signer2 = SchnorrSigner(cyclic_group)
    signer2.generate_keys()

    signer3 = SchnorrSigner(cyclic_group)
    signer3.generate_keys()

    # Signature
    signers = []
    X, R, s = signer1.sign_message(message_content)
    signers.append(X)

    # Verification
    result = signer2.verify_message(message_content, signers, R, s)

    # todo add maxwell signature
