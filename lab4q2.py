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


//pip install sympy
/*
Hospital_A Keys: {'public': 40369356168200866795699187884307185184132997005625680372222183047735000421759273177838709716251314332263845742360364608089821353316496790062063746201198843953260244432540393466213917494484214067443322789182214570715840471904013327709417215922756659066672088918613766069212376990032423006107386296360218557873, 'private': (10325047906061319351415494739991928134362521004766631646209067100764109434955765173105660866127947633595067567845583522569420209550227502052185884020154589, 3909846863228792995966569196413728135537278976666859362096023623142928855428707844498660256142408540151140477386706043985839687918551191894694526506006757)}
Hospital_B Keys: {'public': 16746606566873907207290687790254508829017688966137490125718027489689810727435246059400662543467879200470421222051530395708341219575133032302800239516324494682912467860013516572383199736853696681562873983783846993704274049840930940673086232665755222470842728803861818270106800444266859546729429603716022284099, 'private': (2729966195929348369433550233026449837182767026796749305106087157402761015823934170287122399843588553639918641598149833824511020924922863355494573677536943, 6134364078150405797882000751204736512360222465106244680677309922237483441913096095454738802571585255743085402870395748369651936290736891276178537053758893)}
Clinic_X Keys: {'public': 8470608107052716875532090815776548437527416806895301398872351005697506667324307971614897025317163503287081535414325548056424916359321853088653495002260683748897070392733798401938709170828189137987231190589991307774883307670633624511645990808514120208893430357836360846059390786048737476958278781816767466029, 'private': (4912470511151233901282128647135057291141337139227593663336025999459109111444824089766031158824849260765669704630614379818154902563667998048935353753215473, 1724307166389002100973700785732917446082619640615635721380422688792383008780454546575248539830599340281597408376958566588499889592538766249769110975000573)}
Keys saved to file
Keys loaded from file
Keys revoked for Hospital_A
*/
