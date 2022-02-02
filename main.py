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
prime_number_upper_bound = 1000000
number_of_signers = 10


def log(phase, subject, message, *args):
    logging.debug(" OBJECT: %-22s |\t PHASE: %-23s | \t" + message, subject, phase, *args)


def log_time(phase, t1, t2):
    log(phase, "TIME-MEASUREMENT", "------------------------   This phase took: %f μs    -    in other words: %f s", (t2 - t1) / 1000,
        (t2 - t1) / 1000_000_000)


def hash_data(hash_name, *args):
    hash = hashlib.new(hash_name)
    for arg in args:
        if isinstance(arg, int):
            hash.update(arg.to_bytes(1024, byteorder='big'))
        else:
            hash.update(arg.encode('utf-8'))
    return int.from_bytes(hash.digest(), 'big')


# todo we should know the real parameter size like p, q, message size, signature time, verification time, overall runtime
# todo try to do everything with mod p in group p
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

    # cyclic prime order q subgroup (Zq,*) from group (Zp,*) based on generating two prime numbers as p = rq+1 where r=2, p and q are primes
    def generate_prime_order_subgroup(self):
        # prime numbers
        self.q = sympy.randprime(int(prime_number_upper_bound / 2), prime_number_upper_bound)
        self.p = 2 * self.q + 1
        while not sympy.isprime(self.p):
            self.q = sympy.randprime(int(prime_number_upper_bound / 2), prime_number_upper_bound)
            self.p = 2 * self.q + 1
        log("Setup", self.object_name, "Cyclic group generation - q: %i, p: %i", self.q, self.p)

    def select_generator(self, generate_elements=False, is_schnorr_group=True):
        self.generator = 1

        if is_schnorr_group:
            while self.generator <= 1 or pow(self.generator, self.q, self.p) != 1:
                self.generator = random.randrange(0, self.p)
            if generate_elements:
                self.elements = sorted([pow(self.generator, i, self.p) for i in range(0, self.q)])
                log("Setup", self.object_name, "group: %s", self.elements[:25])
        else:
            s = set(range(1, self.p))
            results = []
            for a in s:
                g = set()
                for x in s:
                    g.add((a ** x) % self.p)
                if g == s:
                    self.generator = a
                    results.append(a)
                    break
            log("Setup", self.object_name, "generator: %s\t p: %s", self.generator, self.p)
            return results


# in schnorr paper they suggest to use schnorr group thats why we implement both in group p and schnorr group

class Signer(ABC):
    signers_number = 0

    def __init__(self, cyclic_group):
        Signer.signers_number += 1
        self.object_name = "Signer-" + str(self.signers_number)
        self.cyclic_group = cyclic_group
        self.private_key = 0
        self.public_key = 0

    def generate_keys(self, is_schnorr_group=True):
        group_size = self.cyclic_group.q if is_schnorr_group else self.cyclic_group.p
        print(group_size)
        self.private_key = random.randrange(0, group_size)
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

    # Round 2
    def send_hashed_random_value(self, data, is_schnorr_group=True):
        group_size = self.cyclic_group.q if is_schnorr_group else self.cyclic_group.p
        print(group_size)

        ri = random.randrange(0, group_size)
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
    # The signature is R and s -> (R,s)
    def sign_message(self, data, Ri_list, message, is_schnorr_group=True):
        aggregated_R = 1
        for Ri in Ri_list:
            aggregated_R *= Ri
        # todo here should be 256bit c number
        c = self.compute_challenge(data.X_aggregated, aggregated_R, message)
        group_size = self.cyclic_group.q if is_schnorr_group else self.cyclic_group.p
        print(group_size)

        si = (data.ri + c * data.ai * self.private_key) % group_size
        return aggregated_R, si

    # Round 3
    def create_aggregated_multisig(self, R, si_list, is_schnorr_group=True):
        group_size = self.cyclic_group.q if is_schnorr_group else self.cyclic_group.p
        print(group_size)

        s = sum(si_list) % group_size
        return R, s

    # Verification
    def verify_message(self, message, L, R, s):
        log("Verification", self.object_name, "Starting verification --------")
        X_aggregated = 1
        for key in L:
            ai = hash_data(self.cyclic_group.hash_name, str(L), key)
            X_aggregated *= pow(key, ai, self.cyclic_group.p)
        c = self.compute_challenge(X_aggregated, R, message)

        log("Verification", self.object_name, "This is value of final s: %i", s)
        left_side = pow(cyclic_group.generator, s, cyclic_group.p)
        right_side = (R * pow(X_aggregated, c, cyclic_group.p)) % cyclic_group.p
        # leftside pow(generator, s, p); rightside (R * pow(X, c, p) )  mod p
        log("Verification", self.object_name, "g^s mod p  = %i \t|\t R*X^c mod p = %i \t|\t is equals?: %s", left_side,
            right_side, left_side == right_side)
        return left_side == right_side


if __name__ == "__main__":
    if len(sys.argv) > 1:
        message_content = str(sys.argv[1])
        number_of_signers = str(sys.argv[2])

    ### Setup
    t1 = time.time_ns()
    cyclic_group = CyclicGroup()
    cyclic_group.generate_prime_order_subgroup()
    cyclic_group.select_generator(is_schnorr_group=False)
    log_time("Setup", t1, time.time_ns())

    ### Key generation
    t1 = time.time_ns()
    users = []
    # List of signers' public keys
    L = []
    for i in range(number_of_signers):
        signer = MaxwellSigner(cyclic_group)
        X = signer.generate_keys(is_schnorr_group=False)
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
        ti = signer.send_hashed_random_value(data, is_schnorr_group=False)
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
        R, si = signer.sign_message(data, Ri_list, message_content, is_schnorr_group=False)
        si_list.append(si)

    R, s = users[1].create_aggregated_multisig(R, si_list, is_schnorr_group=False)
    log_time("Signature", t1, time.time_ns())
    log("Signature", "All signers", "Round 3 finished - Signature generated correctly")

    ### Verification
    t1 = time.time_ns()
    result = users[0].verify_message(message_content, L, R, s)
    log_time("Verification", t1, time.time_ns())
