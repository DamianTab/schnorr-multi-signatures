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
prime_number_lower_bound = 10
prime_number_upper_bound = 20


def log(phase, subject, message, *args):
    logging.debug(" OBJECT: %-22s |\t PHASE: %-23s | \t" + message, subject, phase, *args)


def hash_data(hash_name, *args):
    hash = hashlib.new(hash_name)
    for arg in args:
        if isinstance(arg, int):
            hash.update(arg.to_bytes(4, byteorder='big'))
        else:
            hash.update(arg.encode('utf-8'))
    return int.from_bytes(hash.digest(), 'big')


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

    def compute_challenge(self, X, R, message):
        c = hash_data(self.cyclic_group.hash_name, X, R, message)
        log("---", self.object_name, "c= %i", c)
        return c

    @abstractmethod
    def sign_message(self, R, si_list):
        pass

    @abstractmethod
    def verify_message(self, message, signers, R, s):
        pass


# class SchnorrSigner(Signer):
#
#     def __init__(self, cyclic_group):
#         super().__init__(cyclic_group)
#
#     # The signature is R and s -> (R,s)
#     def sign_message(self, message):
#         # random number from cyclic group
#         r = random.choice(cyclic_group.elements)
#         R = pow(cyclic_group.generator, r, cyclic_group.p)
#         c = self.compute_challenge(message, self.public_key, R)
#         s = r + c * self.private_key
#         log("Signature", self.object_name, "r: %i\t R: %i\t s: %i", r, R, s)
#         # todo wywalic X
#         return self.public_key, R, s
#
#     def verify_message(self, message, signers, R, s):
#         # signer's public key
#         X = signers[0]
#
#         left_side = pow(cyclic_group.generator, s, cyclic_group.p)
#         c = self.compute_challenge(message, X, R)
#         right_side = (R * pow(X, c, cyclic_group.p)) % cyclic_group.p
#
#         # leftside pow(generator, s, p); rightside (R * pow(X, c, p) )  mod p
#         log("Verification", self.object_name, "g^s mod p  = %i \t|\t R*X^c mod p = %i \t|\t is equals?: %s", left_side,
#             right_side, left_side == right_side)
#         return left_side == right_side

class SignerData:
    def __init__(self):
        # hash of L and Xi
        self.ai = 0
        # random number from cyclic group
        self.ri = 0
        self.Ri = 0
        # aggregated public keys
        self.X_aggregated = 0


class MaxwellSigner(Signer):

    def __init__(self, cyclic_group):
        super().__init__(cyclic_group)

    # Round 1
    def calculate_aggregated_public_key(self, data, L):
        data.ai = hash_data(self.cyclic_group.hash_name, str(L), self.public_key)
        data.X_aggregated = 1
        for key in L:
            ai = hash_data(self.cyclic_group.hash_name, str(L), key)
            data.X_aggregated *= pow(key, ai, self.cyclic_group.p)
    #         todo byc moze modulo

    # Round 2
    def send_hashed_random_value(self, data):
        ri = random.choice(cyclic_group.elements)
        Ri = pow(cyclic_group.generator, ri, cyclic_group.p)
        hash_R = hash_data(cyclic_group.hash_name, Ri)

        data.ri = ri
        data.Ri = Ri
        return hash_R

    # Round 2
    def send_random_value(self, data):
        return data.Ri

    # Round 2
    def verify_committed_values(self, ti_list, Ri_list):
        for ti, Ri in zip(ti_list, Ri_list):
            hash_Ri = hash_data(cyclic_group.hash_name, Ri)
            if ti != hash_Ri:
                raise ValueError("Received hash ti: %i is diffrent from calculated: %i for number Ri: %i", ti, hash_Ri, Ri)
        log("Signature", self.object_name, "Committed values are correct.")


    # Round 3
    def calculate_individual_signature(self, data, Ri_list, message):
        aggregated_R = 1
        for Ri in Ri_list:
            aggregated_R *= Ri
        c = self.compute_challenge(data.X_aggregated, aggregated_R, message)
        # si = (data.ri + c * data.ai * self.private_key) % self.cyclic_group.p
        si = data.ri + c * data.ai * self.private_key
        return aggregated_R, si


    # Round 3
    # The signature is R and s -> (R,s)
    def sign_message(self, R, si_list):
        # todo ask why here I cannot do modulo p
        # s = sum(si_list) % self.cyclic_group.p
        s = sum(si_list)
        return R, s

    def verify_message(self, message, L, R, s):
        X_aggregated = 1
        for key in L:
            ai = hash_data(self.cyclic_group.hash_name, str(L), key)
            X_aggregated *= pow(key, ai, self.cyclic_group.p)
        c = self.compute_challenge(X_aggregated, R, message)
        left_side = pow(cyclic_group.generator, s, cyclic_group.p)
        right_side = (R * pow(X_aggregated, c, cyclic_group.p)) % cyclic_group.p
        # right_side = (R * pow(X_aggregated, c% cyclic_group.p, cyclic_group.p)) % cyclic_group.p

        # leftside pow(generator, s, p); rightside (R * pow(X, c, p) )  mod p
        log("Verification", self.object_name, "g^s mod p  = %i \t|\t R*X^c mod p = %i \t|\t is equals?: %s", left_side,
            right_side, left_side == right_side)
        return left_side == right_side


if __name__ == "__main__":
    if len(sys.argv) > 1:
        # reading message
        message_content = str(sys.argv[1])

    ### Setup
    cyclic_group = CyclicGroup()
    cyclic_group.generate_prime_order_subgroup()
    cyclic_group.select_generator()

    ### Key generation
    users = []
    # List of signers' public keys
    L = []
    for i in range(3):
        signer = MaxwellSigner(cyclic_group)
        X = signer.generate_keys()
        users.append(signer)
        # Each user except first one will be signer
        if i != 0:
            L.append(X)

    ### Signature
    signers_data = []

    # Round 1
    for signer in users[1:]:
        data = SignerData()
        signers_data.append(data)
        signer.calculate_aggregated_public_key(data, L)
    log("Signature", "All signers", "Round 1 finished - calculated aggregated public key.")

    # Round 2
    ti_list = []
    for data, signer in zip(signers_data, users[1:]):
        ti = signer.send_hashed_random_value(data)
        ti_list.append(ti)
    log("Signature", "All signers", "All signers received comitted hash values ti: %s", str(ti_list))

    Ri_list = []
    for data, signer in zip(signers_data, users[1:]):
        Ri = signer.send_random_value(data)
        Ri_list.append(Ri)
    log("Signature", "All signers", "All signers received random values Ri: %s", str(Ri_list))

    for signer in users[1:]:
        signer.verify_committed_values(ti_list, Ri_list)

    # Round 3
    si_list = []
    R, s = 0, 0
    for data, signer in zip(signers_data, users[1:]):
        R, si = signer.calculate_individual_signature(data, Ri_list, message_content)
        si_list.append(si)

    # We can take signature from any signer (R, s)
    for signer in users[1:]:
        R, s = signer.sign_message(R, si_list)
    # R, s = users[1].sign_message(R, si_list)

    ### Verification
    result = users[0].verify_message(message_content, L, R, s)