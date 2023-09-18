# -*- coding: windows-1251 -*-

#pip install pycryptodome
from Crypto.Random import get_random_bytes
from Crypto.Util.number import getPrime, inverse, GCD

import random
from random import randint

from sympy import isprime

# pip install numpy
import numpy as np

#pip install gostcrypto
import gostcrypto

# pip install asn1
from asn1 import Decoder, Encoder, Numbers

import os

import hashlib


# Сложение точек на ЭК
def PointSum(x1, y1, x2, y2):

    L = 0

    # Если складываем с бесконечно удаленной точкой
    if x1 == 0 and y1 == 0:
        return x2, y2
    elif x2 == 0 and y2 == 0:
        return x1, y1
    # Если складываем P = (a , b) и P = (a, -b)
    elif x1 == x2 and y1 == -y2:
        return 0, 0 # бесконечно удаленная точка
    # Если P = Q
    elif x1 == x2 and y1 == y2:
        L = ((3 * (x1**2) + A) * inverse(2 * y1, p)) % p
    # Если P != Q
    else:
        L = ((y2 - y1) * inverse((x2 - x1), p)) % p

    x3 = (L**2 - x1 - x2) % p
    y3 = (L * (x1 - x3) - y1) % p

    return x3, y3


# Бинарное умножение точки на число
def BinMulti(P_x, P_y, k):

    if(k == 0):
        return 0, 0 # бесконечно удаленная точка
    elif(k == 1):
        return P_x, P_y

    a = CreateVctr(k)

    Q_x, Q_y = 0, 0

    for i in a:
        Q_x, Q_y = PointSum(Q_x, Q_y, Q_x, Q_y)

        if(i == 1):
            Q_x, Q_y = PointSum(Q_x, Q_y, P_x, P_y)

    return Q_x, Q_y


# Создание двоичного вектора
def CreateVctr(x):

    lst = []

    while(x != 0):
        lst.append(x % 2)
        x //= 2

    vctr = np.array(lst[::-1])

    return vctr


# Генерация параметров криптосистемы
def generate_parameters(q, P_x, P_y):

    d = randint(1, q - 1)
    Q_x, Q_y = BinMulti(P_x, P_y, d)

    print("Parameters were successfully generated!\n")
    print("xQ:", Q_x, "\nyQ:", Q_y, "\nd:", d, "\n")
    return Q_x, Q_y, d


# Формирование подписи
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

# Переводит двоичные векторы в числа
def BinVctrToDec(lst):

    size = len(lst)

    x = 0
    for i in range(0, size):
        x += int(lst[i]) * (2**(size - i - 1))

    return x


# Проверка подписи
def check_sign():

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


# Генерируем asn-файл
def write_asn(Q_x, Q_y, P_x, P_y, q, B):

    asn1 = Encoder()
    asn1.start()
    asn1.enter(Numbers.Sequence)  # Заголовок
    asn1.enter(Numbers.Set) # Множество ключей, 1 задействован
    asn1.enter(Numbers.Sequence) # Первый "ключ"
    asn1.write(b'\x80\x06\07\00', Numbers.OctetString) # Идентификатор алгоритма
    asn1.enter(Numbers.Sequence)  # Значение открытого ключа
    asn1.write(Q_x, Numbers.Integer)  # Q_x
    asn1.write(Q_y, Numbers.Integer)  # Q_y
    asn1.leave()
    asn1.enter(Numbers.Sequence)  # Параметры криптосистемы
    asn1.enter(Numbers.Sequence)  # Параметры поля
    asn1.write(p, Numbers.Integer)  # p
    asn1.leave()
    asn1.enter(Numbers.Sequence)  # Параметры кривой
    asn1.write(A, Numbers.Integer)  # Коэффициент A
    asn1.write(B, Numbers.Integer)  # Коэффициент B
    asn1.leave()
    asn1.enter(Numbers.Sequence)  # Образующая группы точек кривой
    asn1.write(P_x, Numbers.Integer)  # P_x
    asn1.write(P_y, Numbers.Integer)  # P_y
    asn1.leave()
    asn1.write(q, Numbers.Integer)  # Порядок группы q
    asn1.leave()
    asn1.enter(Numbers.Sequence)  # Подпись сообщения
    asn1.write(sign_asn[0], Numbers.Integer)  # r
    asn1.write(sign_asn[1], Numbers.Integer)  # s
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

# Чтение asn-файла
def read_asn():
    filename = "sign.txt"
    asn1 = Decoder()
    with open("sign/" + filename, "rb") as eFile:
        encoded_bytes = eFile.read()
    asn1.start(encoded_bytes)
    asn1.enter()  # Заголовок
    asn1.enter() # Множество ключей, 1 задействован
    asn1.enter() # Первый "ключ"
    asn1.read() # Идентификатор алгоритма
    asn1.enter()  # Значение открытого ключа
    Q_x = asn1.read()[1]  # Q_x
    Q_y = asn1.read()[1]  # Q_y
    asn1.leave()
    asn1.enter()  # Параметры криптосистемы
    asn1.enter()  # Параметры поля
    p = asn1.read()[1]  # p
    asn1.leave()
    asn1.enter()  # Параметры кривой
    A = asn1.read()[1]  # Коэффициент A
    B = asn1.read()[1]  # Коэффициент B
    asn1.leave()
    asn1.enter()  # Образующая группы точек кривой
    P_x = asn1.read()[1]  # P_x
    P_y = asn1.read()[1]  # P_y
    asn1.leave()
    q = asn1.read()[1]  # Порядок группы q
    asn1.leave()
    asn1.enter()  # Подпись сообщения
    r = asn1.read()[1]  # r
    s = asn1.read()[1]  # s
    asn1.leave()
    asn1.leave()
    asn1.leave()
    asn1.enter()
    asn1.leave()
    asn1.leave()
    return Q_x, Q_y, P_x, P_y, A, B, p, q, r,s

# Параметры криптосистемы
p = 57896044623332830704464930175758866532580959320654190378215212919875855638347 # модуль эллиптической кривой
q = 28948022311666415352232465087879433266289459622068172692541485718987902249339 # порядок подгруппы группы точек эллиптической кривой
A = 1
B = 3580094891504076339485469867608308463096783610651696491327180352870738800622 # коэффициенты ЭК
xP =  34716160583222611645030789937385729759908872067425542316787922148347820731789 # координата точки
yP = 5898821206414759138201363717802568499793444816690169368839685124167835466530 # координата точки

sign = [] # r, s - двоичные векторы
sign_asn = [] # r,

while(1): 
    print("1 - Sign a message\n2 - Check the sign\n0 - Exit")
    c = input("Enter action: ")
    if(c == "1"):
        Q_x, Q_y, d = generate_parameters(q, xP, yP)
        generate_sign(q, xP, yP, d)
        write_asn(Q_x, Q_y, xP, yP, q, B)
    elif(c == "2"):
        check_sign()
    elif(c == "0"):
        exit()
    else:
        print("Incorrect input! Try again!")
