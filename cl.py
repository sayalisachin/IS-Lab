import socket

def hash_function(s: str) -> int:
    hash_value = 5381
    for char in s:
        hash_value = (hash_value * 33) ^ ord(char)
        hash_value &= 0xFFFFFFFF
    return hash_value

def start_client(data: str):
    host = '127.0.0.1'
    port = 12345

    # Create a socket object
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))
    
    try:
        # Send data to the server
        client_socket.sendall(data.encode('utf-8'))
        
        # Receive the hash from the server
        data_hash_from_server = client_socket.recv(1024).decode('utf-8')
        print("Received hash from server:", data_hash_from_server)
        
        # Compute the hash of the data locally
        local_hash = hash_function(data)
        print("Local hash computed:", local_hash)
        
        # Verify the integrity by comparing hashes
        if int(data_hash_from_server) == local_hash:
            print("Data integrity verified.")
        else:
            print("Data integrity verification failed.")
    finally:
        # Close the connection
        client_socket.close()

if __name__ == '__main__':
    test_data = "Hello, World!"
    start_client(test_data)
