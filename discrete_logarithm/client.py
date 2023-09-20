#this is a client
from config import address, port, a
import socket
from asn import ASN
import random as rnd
from Crypto.Util.number import getPrime
from Crypto.Random import get_random_bytes

def connect_server() ->socket.socket:
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    connection.connect((address, port))
    return connection

def get_parameter(p) -> int:
    return rnd.randint(1, p)

def exchange_keys(connection:socket.socket) -> int:
    p = getPrime(1024, randfunc=get_random_bytes)
    x = get_parameter(p)
    asn = ASN.encrypt_diffie_hellman(a**x, "client", p, a)
    connection.send(asn)
    asn = connection.recv(4096)
    c = int(ASN.decrypt_diffie_hellman(asn))
    print(f'Generated parameters:\na = {a}\nx = {x}')
    print(f'Recived a^y = {c}')
    key = c**x
    print(f'Ka = {key}')
    return key



def main():
    connection = connect_server()
    key = exchange_keys(connection)
    AESkey = key % (2**256)
    print(f'AES key = {AESkey}')
    while(True):
        message = input("Enter the message: ")
        message_bytes = bytes(message, 'utf-8')
        message_len = len(message_bytes)
        extension_length = 16 - message_len
        for i in range (extension_length):
            message_bytes += b'\x03'
        asn = ASN.encrypt_aes_diffie_hellman(message_len, message_bytes)
        connection.send(asn)
        if message == 'exit':
            break
    connection.close()
    

if __name__ == '__main__':
    main()