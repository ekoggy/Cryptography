#this is a server
import socket
from asn import ASN

def start_server() -> socket.socket:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((socket.gethostbyname(socket.gethostname()), 8000))
    listener.listen(0)
    connection, address = listener.accept()
    print(f'Connect clent {address}\n')
    return connection

def init_keys(connection:socket.socket) -> int:
    asn = connection.recv(1024)
    _, a, c = ASN.decrypt_diffie_hellman(asn)
    y = get_parameter()
    connection.send(a**y)
    a = connection.recv(1024)
    key = c**y
    return key

def get_parameter():
    pass

def send():
    pass

def main():
    connection = start_server()
    init_keys(connection)
    pass

if __name__ == '__main__':
    main()