import random as rnd
import math
import time
from sympy import isprime, sqrt
from Crypto.Util.number import getPrime, inverse, GCD
from Crypto.Random import get_random_bytes

#--------FACTORIZATION BLOCK--------#

def factorization_attack(e_a, e_b, d_b, n):
    
    s = e_b * d_b - 1
    while (s % 2 == 0):
        s = s // 2
    
    while True: 
        t = n-1
        a = rnd.randrange(1, n)
        b = pow(a, s, n)
        x = b
        y = 0
        while True:
            y = x #b^2^(l-1)
            x = pow(x, 2, n)#b^2^l
            if x == 1:
                if y != -1:
                    t = y
                break
        if t != n-1 and t != 1:
            break
    
    p, q = GCD(t + 1, n), GCD(t - 1, n)
    phi = (p-1)*(q-1)

    d_a = inverse(e_a, phi)

    return p, q, d_a

def get_e_and_d(phi):
    e = 0
    while GCD(e, phi) > 1:
        e = getPrime(1024, randfunc=get_random_bytes)
    d = inverse(e, phi)
    return e, d

def get_first_program_param():
    p = getPrime(1024, randfunc=get_random_bytes)
    q = getPrime(1024, randfunc=get_random_bytes)
    e_a = 0
    e_b = 0
    n = p * q
    phi = (p-1)*(q-1)
    e_a, d_a = get_e_and_d(phi)

    while True:
        e_b, d_b = get_e_and_d(phi)
        if e_a != e_b and d_a != d_b:
            break
    return e_a, e_b, d_a, d_b, n

def first_program():
    e_a, e_b, d_a, d_b, n = get_first_program_param()

    print(f' n = {n}\n\
          e_a = {e_a}\n\
          d_a = {d_a}\n\
          e_b = {e_b}\n\
          d_b = {d_b}')

    p_predicted, q_predicted, d_a_predicted = factorization_attack(e_a, e_b, d_b, n)
    print(f'\
          Predicted:\n\
          p by factorisation {p_predicted}\n\
          q by factorisation {q_predicted}\n\
          d_a by factorisation {d_a_predicted}')

    if d_a_predicted == d_a:
        print(f'Success')
    else:
        print(f'Failure')

#--------WIENER BLOCK--------#

def get_fraction(e, n):
	a, q = divmod(e, n)
	t = n
	x = [a]

	while q != 0:
		next_t = q
		a, q = divmod(t, q)
		t = next_t
		x.append(a)

	return x

def wiener_attack(e, n):
    a = get_fraction(e, n)
    l = len(a)
    q = [0, 1, 0]
    m = rnd.randint(1, n-1) 
    d = -1
    for i in range (1, l):
        q[2] = a[i] * q[1] + q[0]
        if pow(m, e*q[2], n) == m:
            d = q[2]
        q[0], q[1] = q[1], q[2]
    return d

def second_program():

    n = 159120802052440427821561598797245794196486762007282213614899538625298940765077913123669326518443057755809732511261424922103777938173006527628957265784605473595141601914607205620259694486382859683903964193688529214708416973894744745552398481940927574916829347154100077369737008945802414290266124801056303429283
    e = 11344248856885807164295503665454231487754375121089537309789856526927258776275114297414196034298992736180410481299229993278201451840436370855751788204922795778488609359900203381710724197371026038017982542547796382021400514829497189707464973191055639707115355334522474997824622403851742433216683635618563112299
    d = 23404895650626450554473888487065756508057288839850568254229721811842778880539

    print(f'\
        n = {n}\n\
        e = {e}\n\
        d = {d}')

    d_predicted = wiener_attack(e, n)
    print(f'Predicted d by wiener {d_predicted}')

    if d == d_predicted:
        print(f'Success')
    else:
        print(f'Failure')

#--------KEYLESS DECRYPTION BLOCK--------#

def keyless_decryption_attack(c, e, n):
    c_vector = [c, 0]
    for i in range(n):
        c_vector[1] = pow(c_vector[0], e, n)
        print(c_vector[0])
        if c_vector[1] % n == c:
            m = c_vector[0]
            break
        c_vector[0] = c_vector[1]
    return m

def third_program():
    m = 156
    p = getPrime(32, randfunc=get_random_bytes)
    q = getPrime(32, randfunc=get_random_bytes)
    e = 0
    #init base parameters
    n = p * q
    v = (p-1)*(q-1)
    while GCD(e, v) > 1:
        e = getPrime(32, randfunc=get_random_bytes)
    d = inverse(e, v)

    c = pow(m, e, n)

    print(f'\
        n = {n}\n\
        e = {e}\n\
        d = {d}\n\
        m = {m}\n\
        c = {c}')
    start = time.time()
    m_predicted = keyless_decryption_attack(c, e, n)
    end = time.time() - start
    print(f'Predicted d by wiener {m_predicted}')
    print(f'spended time = {end} seconds')
    if m == m_predicted:
        print(f'Success')
    else:
        print(f'Failure')

#--------PARAMETERS GENERATOR-------#

def gen_security_parameters():
	# p и q - безопасные простые числа, z = 2*z1 + 1
	while True:
		p = getPrime(512, randfunc=get_random_bytes)
		p_1 = (p - 1) // 2
		if(isprime(p_1) == True):
			break
	while True:
		q = getPrime(512 + 12, randfunc=get_random_bytes) # разница в 12 байт между p и q
		q_1 = (q - 1) // 2
		
		if(isprime(q_1) == True):
			break

	n = p * q
	v = (p - 1) * (q - 1)

	while True:
		e = 2
		while (GCD(e, v) > 1):
			e = getPrime(16, randfunc=get_random_bytes) # 16 байт, не слишком большое и не слишком маленькое
		d = inverse(e, v)
		if(d >= sqrt(sqrt(n))):
			break

	return n, e, d, p, q


def main():

    while True:
        print('''
Warning: You will not be able to decrypt the file or verify 
the signature if the action was  not performed at the current start of the program.
              
Available fighters:
1. Harry Potter (factorization)
2. Tom Sawyer (wiener)
3. Optimus Prime (keyless decryption)
4. John Snow (generate parameters)
''' )
        command = input("Choose your fighter: ")

        if command == '1' or command == 'Harry Potter':
            first_program()
        elif command == '2' or command == 'Tom Sawyer':
            second_program()
        elif command == '3' or command == 'Optimus Prime':
           third_program()
        elif command == '4' or command == 'John Snow':
            n, e, d, p, q = gen_security_parameters()
            print(f'Generated parameters:\n\
{"*"*50}\nn = {n}\n\
{"*"*50}\ne = {e}\n\
{"*"*50}\nd = {d}\n\
{"*"*50}\np = {p}\n\
{"*"*50}\nq = {q}')
        else:
            print("incorrect input, try again")

if __name__ == '__main__':
    main()