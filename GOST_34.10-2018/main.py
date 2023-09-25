# -*- coding: windows-1251 -*-

#pip install pycryptodome
from Crypto.Random import get_random_bytes
from Crypto.Util.number import getPrime, inverse, GCD
import random
from random import randint
from sympy import isprime
import numpy as np
import gostcrypto
from asn1 import Decoder, Encoder, Numbers
import os
import hashlib

p = 57896044623332830704464930175758866532580959320654190378215212919875855638347
q = 28948022311666415352232465087879433266289459622068172692541485718987902249339
A = 1
B = 3580094891504076339485469867608308463096783610651696491327180352870738800622 
xP =  34716160583222611645030789937385729759908872067425542316787922148347820731789 
yP = 5898821206414759138201363717802568499793444816690169368839685124167835466530

def PointSum(x1, y1, x2, y2):

    L = 0

    if x1 == 0 and y1 == 0:
        return x2, y2
    elif x2 == 0 and y2 == 0:
        return x1, y1
    elif x1 == x2 and y1 == -y2:
        return 0, 0 
    elif x1 == x2 and y1 == y2:
        L = ((3 * (x1**2) + A) * inverse(2 * y1, p)) % p
    else:
        L = ((y2 - y1) * inverse((x2 - x1), p)) % p

    x3 = (L**2 - x1 - x2) % p
    y3 = (L * (x1 - x3) - y1) % p

    return x3, y3


def BinMulti(P_x, P_y, k):

    if(k == 0):
        return 0, 0 
    elif(k == 1):
        return P_x, P_y

    a = CreateVctr(k)

    Q_x, Q_y = 0, 0

    for i in a:
        Q_x, Q_y = PointSum(Q_x, Q_y, Q_x, Q_y)

        if(i == 1):
            Q_x, Q_y = PointSum(Q_x, Q_y, P_x, P_y)

    return Q_x, Q_y


def CreateVctr(x):

    lst = []

    while(x != 0):
        lst.append(x % 2)
        x //= 2

    vctr = np.array(lst[::-1])

    return vctr


def generate_parameters(q, P_x, P_y):

    d = randint(1, q - 1)
    Q_x, Q_y = BinMulti(P_x, P_y, d)

    print("Parameters were successfully generated!\n")
    print("xQ:", Q_x, "\nyQ:", Q_y, "\nd:", d, "\n")
    return Q_x, Q_y, d


def generate_sign(q, P_x, P_y, d):

    text_file = open('text.txt', 'rb')
    text = text_file.read()
    text_file.close()

    hash = gostcrypto.gosthash.new('streebog256', data=text)
    hash = hash.hexdigest()
    hash = hash.encode('utf-8')
    hash = int.from_bytes(hash, "big")

    e = hash % q
    if(e == 0):
        e = 1

    while True:
        k = randint(1, q - 1)
        C_x, C_y = BinMulti(P_x, P_y, k)

        r = C_x % q
        if(r == 0):
            continue

        s = (r * d + k * e) % q
        if(s != 0):
            break

    sign_asn.append(r)
    sign_asn.append(s)

    sign.append(CreateVctr(r))
    sign.append(CreateVctr(s))

    print("Sign was successfully generated!\n")

def BinVctrToDec(lst):

    size = len(lst)

    x = 0
    for i in range(0, size):
        x += int(lst[i]) * (2**(size - i - 1))

    return x


def verify_signature():

    Q_x_dec, Q_y_dec, P_x_dec, P_y_dec, A_dec, B_dec, p_dec, q_dec, r_dec, s_dec = read_asn()

    if((r_dec <= 0 or r_dec >= q_dec) and (s_dec <= 0 or s_dec >= q)):
        print("The signature is invalid, cause 1")
        return

    fin = open('text.txt', 'rb')
    text = fin.read()
    fin.close()

    hash = gostcrypto.gosthash.new('streebog256', data=text)
    hash = hash.hexdigest()
    hash = hash.encode('utf-8')
    a = int.from_bytes(hash, "big")

    e = a % q_dec
    if(e == 0):
        e = 1

    v = inverse(e, q)
    z_1 = (s_dec * v) % q_dec
    z_2 = ((-1) * r_dec * v) % q_dec

    P_x_dec, P_y_dec = BinMulti(P_x_dec, P_y_dec, z_1)
    Q_x_dec, Q_y_dec = BinMulti(Q_x_dec, Q_y_dec, z_2)
    C_x, C_y = PointSum(P_x_dec, P_y_dec, Q_x_dec, Q_y_dec)

    R = C_x % q_dec

    print("R:", R, "\nr:", r_dec, "\n")

    if(R == r_dec):
        print("The signature is valid")
    else:
        print("The signature is invalid, cause 2")


def write_asn(Q_x, Q_y, P_x, P_y, q, B):

    asn1 = Encoder()
    asn1.start()
    asn1.enter(Numbers.Sequence)  
    asn1.enter(Numbers.Set) 
    asn1.enter(Numbers.Sequence) 
    asn1.write(b'\x80\x06\07\00', Numbers.OctetString) 
    asn1.enter(Numbers.Sequence)  
    asn1.write(Q_x, Numbers.Integer) 
    asn1.write(Q_y, Numbers.Integer)  
    asn1.leave()
    asn1.enter(Numbers.Sequence)  
    asn1.enter(Numbers.Sequence)  
    asn1.write(p, Numbers.Integer) 
    asn1.leave()
    asn1.enter(Numbers.Sequence)  
    asn1.write(A, Numbers.Integer)  
    asn1.write(B, Numbers.Integer)  
    asn1.leave()
    asn1.enter(Numbers.Sequence)
    asn1.write(P_x, Numbers.Integer)  
    asn1.write(P_y, Numbers.Integer) 
    asn1.leave()
    asn1.write(q, Numbers.Integer)
    asn1.leave()
    asn1.enter(Numbers.Sequence)  
    asn1.write(sign_asn[0], Numbers.Integer) 
    asn1.write(sign_asn[1], Numbers.Integer)
    asn1.leave()
    asn1.leave()
    asn1.leave()
    asn1.enter(Numbers.Sequence)
    asn1.leave()
    asn1.leave()

    os.makedirs('sign', exist_ok=True)

    filename = "sign.txt"

    with open("sign/" + filename, "wb") as eFile:
        eFile.write(asn1.output())


def read_asn():
    filename = "sign.txt"
    asn1 = Decoder()
    with open("sign/" + filename, "rb") as eFile:
        encoded_bytes = eFile.read()
    asn1.start(encoded_bytes)
    asn1.enter()  
    asn1.enter() 
    asn1.enter() 
    asn1.read() 
    asn1.enter()  
    Q_x = asn1.read()[1] 
    Q_y = asn1.read()[1] 
    asn1.leave()
    asn1.enter()  
    asn1.enter() 
    p = asn1.read()[1] 
    asn1.leave()
    asn1.enter() 
    A = asn1.read()[1]  
    B = asn1.read()[1]  
    asn1.leave()
    asn1.enter()  
    P_x = asn1.read()[1]  
    P_y = asn1.read()[1]  
    asn1.leave()
    q = asn1.read()[1]  
    asn1.leave()
    asn1.enter()  
    r = asn1.read()[1] 
    s = asn1.read()[1] 
    asn1.leave()
    asn1.leave()
    asn1.leave()
    asn1.enter()
    asn1.leave()
    asn1.leave()
    return Q_x, Q_y, P_x, P_y, A, B, p, q, r,s



sign = [] 
sign_asn = [] 

def main():
    #global public_key, private_key
    #public_key, private_key = init_keys()

    while True:
        print('''
Warning: You will not be able to decrypt the file or verify 
the signature if the action was  not performed at the current start of the program.
              
Available fighters:
1. Bugs Bunny (create signature)
2. Tor Odinson (verify signature)
''' )
        command = input("Choose your fighter: ")

        if command == '1' or command == 'Bugs Bunny':
            Q_x, Q_y, d = generate_parameters(q, xP, yP)
            generate_sign(q, xP, yP, d)
            write_asn(Q_x, Q_y, xP, yP, q, B)
            #create_signature()
        elif command == '2' or command == 'Tor Odinson':
            verify_signature()
        else:
            print("incorrect input, try again")
    

if __name__ == '__main__':
    main()