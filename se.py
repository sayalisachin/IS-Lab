import socket

def hash_function(s: str) -> int:
    hash_value = 5381
    for char in s:
        hash_value = (hash_value * 33) ^ ord(char)
        hash_value &= 0xFFFFFFFF
    return hash_value

def start_server():
    host = '127.0.0.1'
    port = 12345
    buffer_size = 1024

    # Create a socket object
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    
    print("Server listening on port", port)
    
    # Accept a connection from a client
    conn, addr = server_socket.accept()
    print("Connected to", addr)
    
    try:
        # Receive data from the client
        data = conn.recv(buffer_size).decode('utf-8')
        print("Received data:", data)
        
        # Compute the hash of the received data
        data_hash = hash_function(data)
        
        # Send the hash back to the client
        conn.sendall(str(data_hash).encode('utf-8'))
    finally:
        # Close the connection
        conn.close()
        server_socket.close()

if __name__ == '__main__':
    start_server()
