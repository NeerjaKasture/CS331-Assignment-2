import socket
import time
import argparse

def send_file(nagle, delayed_ack):
    server_ip = "127.0.0.1"
    port = 12345
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    
    if not nagle:
        client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)  # Disable Nagle
    if not delayed_ack:
        client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_QUICKACK, 1) # enable quick ack

    client_socket.connect((server_ip, port))
    print("Connected to server.")

    FILESIZE = 4096 # 4 KB
    CHUNK_SIZE = 40
    data = b'A' * FILESIZE
    sent_bytes = 0

    for i in range(0, FILESIZE, CHUNK_SIZE):
        client_socket.send(data[i : i + CHUNK_SIZE])
        sent_bytes += CHUNK_SIZE
        time.sleep(1)  

    
    print("File sent successfully.")
    client_socket.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--nagle", type=int, choices=[0, 1], default=1) #Enable(1) or Disable(0) Nagle
    parser.add_argument("--delayed_ack", type=int, choices=[0, 1], default=1)#Enable(1) or Disable(0) Delayed ACK
    args = parser.parse_args()

    send_file(args.nagle, args.delayed_ack)
