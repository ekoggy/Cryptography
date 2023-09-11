import random as rnd
from math import log2
from Crypto.Util.number import getPrime, inverse, GCD
from Crypto.Random import get_random_bytes

# init keys
public_key = (0, 0)
private_key = (0, 0)
aes_key = get_random_bytes(32) 
init_vector = get_random_bytes(16)
rsa_pq = (0, 0)
        

def get_fraction(e, n, l):
	a, q = divmod(e, n)
	t = n
	res = [a]

	while q != 0:
		next_t = q
		a, q = divmod(t, q)
		t = next_t
		res.append(a)

	return res



def factorization_attack(e_a, e_b, d_b, n):
    
    s = e_b * d_b - 1
    k = 0
    
    while (s % 2 == 0):
        k += 1
        s = s // 2

    while True:
        a = rnd.randrange(1, n)
        t = n
        b = pow(a, s, n)

        for i in range(n):
            x, y = pow(b, 2^i, n), pow(b, 2^(i-1), n)
            if x == 1:
                if y != -1:
                    t = y
                break
        if t != n:
            break
    
    p, q = GCD(t + 1, n), GCD(t - 1, n)

    phi = (p-1)(q-1)

    d_a = inverse(e_a, phi)

    return d_a


def wiener_attack(e, n):
    l = log2(n)
    a = get_fraction(e, n, l)
    q = [0, 1, 0]
    m = pow(rnd.randrange(1, n), e, n)
    d = -1
    for i in range (2, l):
        q[2] = a[i-1] * q[1] + q[0]
        if pow(m, q[1], n) == m:
            d = q[i]
        q[0], q[1] = q[1], q[2]
    return d


def keyless_decryption_attack(c, e, n):
    c_vector = [c, 0]
    for i in range(n):
        c_vector[1] = pow(c_vector[0], e, n)
        if c_vector[1] % n == c:
            m = c_vector[0]
        c_vector[0] = c_vector[1]
    return m



def init_keys():
    global rsa_pq
    # choosing p and q
    p = getPrime(1024, randfunc=get_random_bytes)
    q = getPrime(1024, randfunc=get_random_bytes)
    rsa_pq = (p, q)
    e = 0
    #init base parameters
    n = p * q
    v = (p-1)*(q-1)
    while GCD(e, v) > 1:
        e = getPrime(1024, randfunc=get_random_bytes)
    d = inverse(e, v)

    return (n, e), (n, d)

def main():
    global public_key, private_key
    public_key, private_key = init_keys()

    while True:
        print('''
Warning: You will not be able to decrypt the file or verify 
the signature if the action was  not performed at the current start of the program.
              
Available fighters:
1. Harry Potter ()
2. Tom Sawyer ()
3. Optimus Prime ()
4. Captain Nemo (verify signature)
5. Albert Einstein (view parameters)
''' )
        command = input("Choose your fighter: ")

        if command == '1' or command == 'Robin Hood':
            encrypt_file()
        elif command == '2' or command == 'James Bond':
            decrypt_file()
        elif command == '3' or command == 'Spider-man':
            create_signature()
        elif command == '4' or command == 'Captain Nemo':
            verify_signature()
        elif command == '5' or command == 'Albert Einstein':
            view_parameters()
        else:
            print("incorrect input, try again")
    

if __name__ == '__main__':
    main()