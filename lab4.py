from cryptography.hazmat.primitives.asymmetric import rsa, dh
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import pickle
import os
import os

class KeyManager:
    def __init__(self):
        self.keys = {}
        self.dh_parameters = dh.generate_parameters(generator=2, key_size=2048)

    def generate_rsa_key_pair(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        return private_key, public_key

    def generate_dh_key_pair(self):
        private_key = self.dh_parameters.generate_private_key()
        public_key = private_key.public_key()
        return private_key, public_key

    def serialize_key(self, key):
        if isinstance(key, rsa.RSAPublicKey):
            return key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
        elif isinstance(key, rsa.RSAPrivateKey):
            return key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
        elif isinstance(key, dh.DHPublicKey):
            return key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
        elif isinstance(key, dh.DHPrivateKey):
            return key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
        else:
            raise TypeError("Unsupported key type")

    def deserialize_key(self, key_bytes, key_type):
        key_bytes = key_bytes.encode('utf-8')
        if key_type == 'rsa_public':
            return serialization.load_pem_public_key(key_bytes)
        elif key_type == 'rsa_private':
            return serialization.load_pem_private_key(key_bytes, password=None)
        elif key_type == 'dh_public':
            return serialization.load_pem_public_key(key_bytes)
        elif key_type == 'dh_private':
            return serialization.load_pem_private_key(key_bytes, password=None)
        else:
            raise ValueError("Unsupported key type")

    def save_keys(self, filename):
        with open(filename, 'wb') as f:
            pickle.dump(self.keys, f)

    def load_keys(self, filename):
        if os.path.exists(filename):
            with open(filename, 'rb') as f:
                self.keys = pickle.load(f)

    def add_key(self, name, key, key_type):
        self.keys[name] = (self.serialize_key(key), key_type)

    def get_key(self, name):
        return self.deserialize_key(self.keys[name][0], self.keys[name][1])


class SecureCommunication:
    def __init__(self, key_manager):
        self.key_manager = key_manager

    def encrypt(self, plaintext, key):
        nonce = os.urandom(12)  # Generate a random nonce for AES-GCM
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return nonce, ciphertext, encryptor.tag

    def decrypt(self, nonce, ciphertext, tag, key):
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
        decryptor = cipher.decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()


def main():
    key_manager = KeyManager()
    comms = SecureCommunication(key_manager)

    # Generate and manage RSA keys for subsystems
    for name in ['Finance', 'HR', 'SupplyChain']:
        private_key, public_key = key_manager.generate_rsa_key_pair()
        key_manager.add_key(name + '_private', private_key, 'rsa_private')
        key_manager.add_key(name + '_public', public_key, 'rsa_public')

    # Save and load keys
    key_manager.save_keys('keys.pkl')
    key_manager.load_keys('keys.pkl')

    # Generate and exchange DH keys
    finance_dh_private_key, finance_dh_public_key = key_manager.generate_dh_key_pair()
    hr_dh_private_key, hr_dh_public_key = key_manager.generate_dh_key_pair()

    shared_key = finance_dh_private_key.exchange(hr_dh_public_key)

    # Derive AES key
    derived_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'secure_communication'
    ).derive(shared_key)

    # Encrypt and decrypt message
    message = b'Secure message'
    nonce, ciphertext, tag = comms.encrypt(message, derived_key)
    decrypted_message = comms.decrypt(nonce, ciphertext, tag, derived_key)

    print(f'Original message: {message.decode()}')
    print(f'Decrypted message: {decrypted_message.decode()}')


if __name__ == '__main__':
    main()
//pip install cryptography
//Output
//Original message: Secure message
//Decrypted message: Secure message
