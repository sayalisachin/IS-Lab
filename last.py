import hashlib
import time
import random
import string
import numpy as np

# Constants
NUM_STRINGS = 100  # Number of random strings
STRING_LENGTH = 10  # Length of each random string

# Helper function to generate random strings
def generate_random_strings(num_strings, length):
    return [''.join(random.choices(string.ascii_letters + string.digits, k=length)) for _ in range(num_strings)]

# Hash computation functions
def compute_md5_hash(data):
    return hashlib.md5(data.encode()).hexdigest()

def compute_sha1_hash(data):
    return hashlib.sha1(data.encode()).hexdigest()

def compute_sha256_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()

# Function to measure hash computation time
def measure_hash_time(hash_function, data_list):
    start_time = time.time()
    hash_values = [hash_function(data) for data in data_list]
    end_time = time.time()
    return hash_values, end_time - start_time

# Function to detect collisions
def detect_collisions(hash_values):
    seen = set()
    collisions = set()
    for value in hash_values:
        if value in seen:
            collisions.add(value)
        seen.add(value)
    return collisions

def main():
    # Generate dataset
    data_list = generate_random_strings(NUM_STRINGS, STRING_LENGTH)
    
    # MD5 Hash Computation
    md5_hashes, md5_time = measure_hash_time(compute_md5_hash, data_list)
    md5_collisions = detect_collisions(md5_hashes)
    
    # SHA-1 Hash Computation
    sha1_hashes, sha1_time = measure_hash_time(compute_sha1_hash, data_list)
    sha1_collisions = detect_collisions(sha1_hashes)
    
    # SHA-256 Hash Computation
    sha256_hashes, sha256_time = measure_hash_time(compute_sha256_hash, data_list)
    sha256_collisions = detect_collisions(sha256_hashes)
    
    # Print Results
    print(f"MD5 Computation Time: {md5_time:.4f} seconds")
    print(f"MD5 Collisions: {len(md5_collisions)}")
    
    print(f"SHA-1 Computation Time: {sha1_time:.4f} seconds")
    print(f"SHA-1 Collisions: {len(sha1_collisions)}")
    
    print(f"SHA-256 Computation Time: {sha256_time:.4f} seconds")
    print(f"SHA-256 Collisions: {len(sha256_collisions)}")

if __name__ == "__main__":
    main()
