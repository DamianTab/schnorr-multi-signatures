import hashlib
import logging
import random
import sys
import time
from abc import ABC, abstractmethod
from random import SystemRandom  # cryptographic random byte generator

import sympy

rand = SystemRandom()  # create strong random number generator
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s | %(levelname)s | %(message)s')

# variables
message_content = "Hello W0rld"
number_of_bits = 256
prime_number_upper_bound = pow(2, number_of_bits - 1)
number_of_signers = 300


def log(phase, subject, message, *args):
    logging.debug(" OBJECT: %-22s |\t PHASE: %-23s | \t" + message, subject, phase, *args)


def log_time(phase, t1, t2):
    log(phase, "TIME-MEASUREMENT", "------------------------   This phase took: %.3f ms    -    in other words: %f s",
        (t2 - t1) / 1_000_000,
        (t2 - t1) / 1_000_000_000)


def hash_data(hash_name, *args):
    hash = hashlib.new(hash_name)
    for arg in args:
        if isinstance(arg, int):
            hash.update(arg.to_bytes(int(number_of_bits / 8), byteorder='big'))
        else:
            hash.update(arg.encode('utf-8'))
    return int.from_bytes(hash.digest(), 'big')


# todo we should know the real parameter size like p, q, message size, signature time, verification time, overall runtime
# todo try to run for different bit number and different and different number of signer
# todo BLS multisignature is better if there is more than 300 signers but in more practical case 300< better is schnorr multisig, check slides from last year student with number of signer that 300 signers is too much


class CyclicGroup:
    def __init__(self):
        self.object_name = "Schnorr cyclic group"
        self.p = 0
        self.q = 0
        self.elements = []
        self.generator = 0
        self.hash_name = "sha256"
        self.k = 0

    # subgroup of prime order q (Zq,*) from cyclic group (Zp,*) based on generating two prime numbers as p = kq+1 where p and q are primes
    def generate_prime_order_subgroup(self):
        self.p = -1
        while not sympy.isprime(self.p):
            self.q = sympy.randprime(int(prime_number_upper_bound / 2**129), prime_number_upper_bound / 2**128)
            self.k = random.randrange(2, 2**128)
            self.p = self.k * self.q + 1
        log("Setup", self.object_name, "Cyclic group generation k: %i q: %i, p: %i", self.k, self.q, self.p)

    # generator is g = h^r mod p only when g != 1
    def select_generator(self, generate_elements=False):
        self.generator = pow(random.randrange(0, self.p), self.k, self.p)
        while self.generator <= 1:
            self.generator = pow(random.randrange(0, self.p), self.k, self.p)
        log("Setup", self.object_name, "generator: %s\t p: %s", self.generator, self.p)

        if generate_elements:
            self.elements = sorted([pow(self.generator, i, self.p) for i in range(0, self.q)])
            log("Setup", self.object_name, "group: %s", self.elements[:25])


# in schnorr paper they suggest to use schnorr group thats why we implement both in group p and schnorr group

class Signer(ABC):
    signers_number = 0

    def __init__(self, cyclic_group):
        Signer.signers_number += 1
        self.object_name = "Signer-" + str(self.signers_number)
        self.cyclic_group = cyclic_group
        self.private_key = 0
        self.public_key = 0

    def generate_keys(self):
        self.private_key = random.randrange(0, self.cyclic_group.q)
        self.public_key = pow(cyclic_group.generator, self.private_key, cyclic_group.p)
        log("Key generation", self.object_name, "private key: %s, public key: %s", self.private_key, self.public_key)
        return self.public_key

    def compute_challenge(self, X, R, message):
        c = hash_data(self.cyclic_group.hash_name, X, R, message)
        # log("---", self.object_name, "c= %i", c)
        return c

    @abstractmethod
    def create_aggregated_multisig(self, R, si_list):
        pass

    @abstractmethod
    def verify_message(self, message, signers, R, s):
        pass


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
        data.X_aggregated = data.X_aggregated % self.cyclic_group.p

    # Round 2
    def send_hashed_random_value(self, data):
        ri = random.randrange(0, self.cyclic_group.q)
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
                raise ValueError("Received hash ti: %i is diffrent from calculated: %i for number Ri: %i", ti, hash_Ri,
                                 Ri)
        log("Signature", self.object_name, "Committed values are correct.")

    # Round 3
    def sign_message(self, data, Ri_list, message):
        aggregated_R = 1
        for Ri in Ri_list:
            aggregated_R *= Ri
        aggregated_R = aggregated_R % self.cyclic_group.p

        c = self.compute_challenge(data.X_aggregated, aggregated_R, message)
        si = (data.ri + c * data.ai * self.private_key) % self.cyclic_group.q
        return aggregated_R, si

    # Round 3
    def create_aggregated_multisig(self, R, si_list):
        s = sum(si_list) % self.cyclic_group.q
        return R, s

    # Verification
    def verify_message(self, message, L, R, s):
        log("Verification", self.object_name, "Starting verification --------")
        X_aggregated = 1
        for key in L:
            ai = hash_data(self.cyclic_group.hash_name, str(L), key)
            X_aggregated *= pow(key, ai, self.cyclic_group.p)

        X_aggregated = X_aggregated % self.cyclic_group.p
        c = self.compute_challenge(X_aggregated, R, message)

        log("Verification", self.object_name, "This is value of final s: %i", s)
        left_side = pow(cyclic_group.generator, s, cyclic_group.p)
        right_side = (R * pow(X_aggregated, c, cyclic_group.p)) % cyclic_group.p
        # leftside pow(generator, s, p); rightside (R * pow(X, c, p) )  mod p
        log("Verification", self.object_name, "IS EQUALS?: %s \t |\t g^s mod p  = %i \t|\t R*X^c mod p = %i ", left_side == right_side, left_side,
            right_side)
        return left_side == right_side


if __name__ == "__main__":
    if len(sys.argv) > 1:
        message_content = str(sys.argv[1])
        number_of_signers = str(sys.argv[2])

    ### Setup
    t1 = time.time_ns()
    cyclic_group = CyclicGroup()
    cyclic_group.generate_prime_order_subgroup()
    cyclic_group.select_generator()
    log_time("Setup", t1, time.time_ns())

    ### Key generation
    t1 = time.time_ns()
    users = []
    # List of signers' public keys
    L = []
    for i in range(number_of_signers):
        signer = MaxwellSigner(cyclic_group)
        X = signer.generate_keys()
        users.append(signer)
        # Each user except first one will be signer
        if i != 0:
            L.append(X)
    log_time("Key generation", t1, time.time_ns())

    ### Signature
    t1 = time.time_ns()
    signers_data = []

    # Round 1
    log("Signature", "All signers", "Round 1 started ...")
    for signer in users[1:]:
        data = SignerData()
        signers_data.append(data)
        signer.calculate_aggregated_public_key(data, L)
    log("Signature", "All signers", "Round 1 finished - calculated aggregated public key.")

    # Round 2
    log("Signature", "All signers", "Round 2 started ...")
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
    log("Signature", "All signers", "Round 2 finished - All committed values are correct")

    # Round 3
    log("Signature", "All signers", "Round 3 started ...")
    si_list = []
    R, s = 0, 0
    for data, signer in zip(signers_data, users[1:]):
        R, si = signer.sign_message(data, Ri_list, message_content)
        si_list.append(si)

    R, s = users[1].create_aggregated_multisig(R, si_list)
    log_time("Signature", t1, time.time_ns())
    log("Signature", "All signers", "Round 3 finished - Signature generated correctly")

    ### Verification
    t1 = time.time_ns()
    result = users[0].verify_message(message_content, L, R, s)
    log_time("Verification", t1, time.time_ns())
