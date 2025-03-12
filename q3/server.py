import socket
import argparse

def start_server( nagle, delayed_ack):
    port = 12345
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    if not nagle:
        server_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)  
    if not delayed_ack:
        server_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 1)
    
    server_socket.bind(("127.0.0.1", port))
    server_socket.listen(1)
    
    print(f"Server listening on port {port}...")
    conn, addr = server_socket.accept()
    print(f"Connection from {addr}")

    with open("received_file.txt", "wb") as f:
        while True:
        	data = conn.recv(40)  # Receive 40 bytes
        	if not data:
        		break  
        	f.write(data)  
        	if not delayed_ack:
        		conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 1)  # Reapply Quick ACK


    
    print("File received successfully.")
    conn.close()
    server_socket.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--nagle", type=int, choices=[0, 1], default=1) #Enable(1) or Disable(0) Nagle
    parser.add_argument("--delayed_ack", type=int, choices=[0, 1], default=1)#Enable(1) or Disable(0) Delayed ACK
    args = parser.parse_args()

    start_server(args.nagle, args.delayed_ack)
