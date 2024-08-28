def hash_function(s: str) -> int:
    # Initial hash value
    hash_value = 5381
    
    # Iterate over each character in the input string
    for char in s:
        # Update the hash value using bitwise operations
        hash_value = (hash_value * 33) ^ ord(char)
        
        # Ensure the hash value stays within a 32-bit range
        hash_value &= 0xFFFFFFFF
    
    return hash_value

# Example usage
input_string = "example"
print(f"Hash value for '{input_string}': {hash_function(input_string)}")
