from asn import ASN
from Crypto.Util.number import inverse
from random import randint
import numpy as np
import gostcrypto

def get_points_sum(x1, y1, x2, y2, A = 1, 
                   p = 57896044623332830704464930175758866532580959320654190378215212919875855638347):

    lamda = 0

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
        lamda = ((3 * (x1**2) + A) * inverse(2 * y1, p)) % p
    # Если P != Q
    else:
        lamda = ((y2 - y1) * inverse((x2 - x1), p)) % p

    x3 = (lamda**2 - x1 - x2) % p
    y3 = (lamda * (x1 - x3) - y1) % p

    return x3, y3

def get_binary_vector(x):

    lst = []

    while(x != 0):
        lst.append(x % 2)
        x //= 2

    vctr = np.array(lst[::-1])

    return vctr

def multiply_binary(P_x, P_y, k):

    if(k == 0):
        return 0, 0 # бесконечно удаленная точка
    elif(k == 1):
        return P_x, P_y

    a = get_binary_vector(k)

    Q_x, Q_y = 0, 0

    for i in a:
        Q_x, Q_y = get_points_sum(Q_x, Q_y, Q_x, Q_y)

        if(i == 1):
            Q_x, Q_y = get_points_sum(Q_x, Q_y, P_x, P_y)

    return Q_x, Q_y

def generate_parameters(q, P_x, P_y):

    d = randint(1, q - 1)
    Q_x, Q_y = multiply_binary(P_x, P_y, d)

    print("Parameters were successfully generated!\n")
    print("xQ:", Q_x, "\nyQ:", Q_y, "\nd:", d, "\n")
    return Q_x, Q_y, d

def get_text(filename = None):

    if filename == None:
        filename = input("Enter the path to the file: ")
    text = b''
    with open(filename, "rb") as file:
        for line in file:
            text += line

    return text, filename

#------------------CREATING BLOCK------------------#
def form_sign(Q_x, Q_y, A, B, p, q, P_x, P_y, d, text):
    hash = gostcrypto.gosthash.new('streebog256', data=text)
    hash = hash.hexdigest()
    hash = hash.encode('utf-8')
    hash = int.from_bytes(hash, "big")
    print(hash)

    e = hash % q
    if(e == 0):
        e = 1

    while True:
        k = randint(1, q - 1)
        C_x, C_y = multiply_binary(P_x, P_y, k)

        r = C_x % q
        if(r == 0):
            continue

        s = (r * d + k * e) % q
        if(s != 0):
            break

    sign = []
    sign.append(Q_x)
    sign.append(Q_y)
    sign.append(p)
    sign.append(A)
    sign.append(B)
    sign.append(P_x)
    sign.append(P_y)
    sign.append(q)
    sign.append(r)
    sign.append(s)
    
    print("Sign was successfully generated!\n")
    return sign

def generate_signature(Q_x, Q_y, A, B, p, q, P_x, P_y, d):

    text, filename = get_text()
    sign = form_sign(Q_x, Q_y, A, B, p, q, P_x, P_y, d, text)
    asn_text = ASN.encrypt_gost_eds(sign)
    with open("^" + filename, "wb") as enc:
        enc.write(asn_text)


#------------------VERIFYING BLOCK------------------#
def check_sign(q, Q_x_dec, Q_y_dec, P_x_dec, P_y_dec, q_dec, r_dec, s_dec, text):
    hash = gostcrypto.gosthash.new('streebog256', data=text)
    hash = hash.hexdigest()
    hash = hash.encode('utf-8')
    a = int.from_bytes(hash, "big")
    
    e = a % q
    if(e == 0):
        e = 1

    v = inverse(e, q)
    z_1 = (s_dec * v) % q
    z_2 = ((-1) * r_dec * v) % q

    P_x_dec, P_y_dec = multiply_binary(P_x_dec, P_y_dec, z_1)
    Q_x_dec, Q_y_dec = multiply_binary(Q_x_dec, Q_y_dec, z_2)
    C_x, C_y = get_points_sum(P_x_dec, P_y_dec, Q_x_dec, Q_y_dec)
    
    R = C_x % q

    print("R:", R, "\nr:", r_dec, "\n")

    if(R == r_dec):
        print("The signature is valid")
    else:
        print("The signature is invalid")

def verify_signature(q):

    text, filename = get_text()
    sign_asn, _ = get_text('^' + filename)
    Q_x_dec, Q_y_dec, P_x_dec, P_y_dec, A_dec, B_dec, p_dec, q_dec, r_dec, s_dec = ASN.decrypt_gost_eds(sign_asn)
    check_sign(q, Q_x_dec, Q_y_dec, P_x_dec, P_y_dec, q_dec, r_dec, s_dec, text)   

def main():

    p = 57896044623332830704464930175758866532580959320654190378215212919875855638347 
    q = 28948022311666415352232465087879433266289459622068172692541485718987902249339 
    A = 1
    B = 3580094891504076339485469867608308463096783610651696491327180352870738800622 
    xP = 34716160583222611645030789937385729759908872067425542316787922148347820731789 
    yP = 5898821206414759138201363717802568499793444816690169368839685124167835466530 

    while True:
        print('''
Warning: You will not be able to decrypt the file or verify 
the signature if the action was  not performed at the current start of the program.
              
Available fighters:
1. Willy Wonka (create signature)
2. Frodo Baggins (verify signature)
''' )
        command = input("Choose your fighter: ")

        if command == '1' or command == 'Willy Wonka':
            Q_x, Q_y, d = generate_parameters(q, xP, yP)
            generate_signature(Q_x, Q_y, A, B, p, q, xP, yP, d)
        elif command == '2' or command == 'Frodo Baggins':
            verify_signature(q)       
        else:
            print("incorrect input, try again")

if __name__ == '__main__':
    main()
