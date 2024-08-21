from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import pickle
import os
import logging
from datetime import datetime, timedelta
from sympy import isprime, nextprime
import random

# Set up logging
logging.basicConfig(filename='key_management.log', level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class RabinKeyManager:
    def __init__(self, key_size=1024):
        self.key_size = key_size
        self.keys = {}
        self.key_expiration = {}
    
    def generate_rabin_key_pair(self):
        # Generate two large primes
        p = self.generate_large_prime()
        q = self.generate_large_prime()
        n = p * q
        return (n, p, q)
    
    def generate_large_prime(self):
        while True:
            num = random.getrandbits(self.key_size // 2)
            if isprime(num):
                return num

    def encrypt(self, plaintext, n):
        return pow(plaintext, 2, n)
    
    def decrypt(self, ciphertext, p, q):
        n = p * q
        r = pow(ciphertext, (p + 1) // 4, p)
        s = pow(ciphertext, (q + 1) // 4, q)
        return (r * q * pow(q, -1, p) + s * p * pow(p, -1, q)) % n

    def generate_keys(self, name):
        n, p, q = self.generate_rabin_key_pair()
        self.keys[name] = {
            'public': n,
            'private': (p, q)
        }
        self.key_expiration[name] = datetime.now() + timedelta(days=365)
        logging.info(f"Keys generated for {name}")
    
    def distribute_keys(self, name):
        if name in self.keys:
            return self.keys[name]
        else:
            raise ValueError(f"Keys for {name} not found")
    
    def revoke_keys(self, name):
        if name in self.keys:
            del self.keys[name]
            del self.key_expiration[name]
            logging.info(f"Keys revoked for {name}")
        else:
            raise ValueError(f"Keys for {name} not found")

    def renew_keys(self):
        for name in list(self.keys.keys()):
            if datetime.now() > self.key_expiration[name]:
                self.generate_keys(name)
                logging.info(f"Keys renewed for {name}")
    
    def save_keys(self, filename):
        with open(filename, 'wb') as f:
            pickle.dump(self.keys, f)
        logging.info("Keys saved to file")

    def load_keys(self, filename):
        if os.path.exists(filename):
            with open(filename, 'rb') as f:
                self.keys = pickle.load(f)
                logging.info("Keys loaded from file")
    
    def is_key_expired(self, name):
        if name in self.key_expiration:
            return datetime.now() > self.key_expiration[name]
        return False

def main():
    manager = RabinKeyManager()

    # Generate and distribute keys
    hospitals = ['Hospital_A', 'Hospital_B', 'Clinic_X']
    for hospital in hospitals:
        manager.generate_keys(hospital)
        keys = manager.distribute_keys(hospital)
        print(f"{hospital} Keys: {keys}")

    # Simulate key renewal
    manager.renew_keys()

    # Save and load keys
    manager.save_keys('keys.pkl')
    manager.load_keys('keys.pkl')

    # Revoke keys for a hospital
    manager.revoke_keys('Hospital_A')

if __name__ == '__main__':
    main()
