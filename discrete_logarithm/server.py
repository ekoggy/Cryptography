#this is a server
import socket
from asn import ASN
import random as rnd

def start_server() -> socket.socket:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(('127.0.0.1', 8000))
    listener.listen(0)
    connection, address = listener.accept()
    print(f'Connect clent {address}\n')
    return connection

def get_parameter(p) -> int:
    return rnd.randint(1, p)

def exchange_keys(connection:socket.socket) -> int:
    asn = connection.recv(4096)
    p, a, c = ASN.decrypt_diffie_hellman(asn, "client")
    print(f'Recived parameters:\na = {a}\na^x = {c}')
    y = get_parameter(p)
    print(f'Generated y = {y}')
    asn = ASN.encrypt_diffie_hellman(a**y)
    connection.send(asn)
    key = c**y
    print(f'Kb = {key}')
    return key

def main():
    connection = start_server()
    key = exchange_keys(connection)
    AESkey = key % (2**256)
    print(f'AES key = {AESkey}')
    while(True):
        asn = connection.recv(4096)
        message_bytes, len = ASN.decrypt_aes_diffie_hellman(asn)
        message_bytes = message_bytes[:len]
        message = bytes.decode(message_bytes)
        print(message)
        if message == 'exit':
           break
    connection.close()

if __name__ == '__main__':
    main()