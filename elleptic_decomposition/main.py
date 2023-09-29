from Crypto.Random import get_random_bytes
from Crypto.Util.number import getPrime, inverse, GCD
import random
from random import randint
import time
from math import log
from sympy import isprime
import numpy as np

iterations = 0

# Сложение точек на ЭК
def get_points_sum(x1, y1, x2, y2, A, p, n):

    L = 0

    # Если складываем с бесконечно удаленной точкой
    if x1 == 0 and y1 == 0:
        return x2, y2, 0
    elif x2 == 0 and y2 == 0:
        return x1, y1, 0
    # Если складываем P = (a , b) и P = (a, -b)
    elif x1 == x2 and y1 == -y2:
        return 0, 0, 0 # бесконечно удаленная точка
    # Если P = Q
    elif x1 == x2 and y1 == y2:
        d = GCD(p, 2 * y1)
        if(d > 1 and d < n):
            return x2, y2, d
        L = ((3 * (x1**2) + A) * inverse(2 * y1, p)) % p
    # Если P != Q
    else:
        d = GCD(p, x2 - x1)
        if(d > 1 and d < n):
            return x2, y2, d
        L = ((y2 - y1) * inverse((x2 - x1), p)) % p

    x3 = (L**2 - x1 - x2) % p
    y3 = (L * (x1 - x3) - y1) % p

    return x3, y3, d

# Создание двоичного вектора
def get_binary_vector(x):

    lst = []

    while(x != 0):
        lst.append(x % 2)
        x //= 2

    vctr = np.array(lst[::-1])

    return vctr

# Бинарное умножение точки на число
def multiply_binary(P_x, P_y, k, A, n):

    if(k == 0):
        return 0, 0 # бесконечно удаленная точка
    elif(k == 1):
        return P_x, P_y

    a = get_binary_vector(k)

    Q_x, Q_y = 0, 0
    global iterations

    for i in a:
        Q_x, Q_y, d = get_points_sum(Q_x, Q_y, Q_x, Q_y, A, n)
        iterations += 1

        if d > 1 and d < n:
            return Q_x, Q_y, d

        if(i == 1):
            Q_x, Q_y, d = get_points_sum(Q_x, Q_y, P_x, P_y, A, n)
            iterations += 1

        if d > 1 and d < n:
            return Q_x, Q_y, d

    return Q_x, Q_y, d

# Создание базы разложения
def get_base(m):

    a = []
    a.append(2)
    count = 1
    num = 3

    while True:
        if(isprime(num)):
            a.append(num)
            count += 1
        num += 2

        if(count == m):
            break

    return a

# Факторизация
def get_prime_divisors(n, m):
       
    D = get_base(m)

    while True:

        # Генерируем координаты точки
        Q_x = randint(1, n)
        Q_y = randint(1, n)

        # Генерируем коэффициенты
        while True:
            A = randint(-2, 3)
            B = randint(1, n)

            k = (4 * pow(A, 3, n) + 27 * pow(B, 2, n)) % n
            if(k != 0 and pow(Q_y, 2, n) == (pow(Q_x, 3, n) + A * Q_x + B) % n):
                break

        i = 0
        Q_xi, Q_yi = Q_x, Q_y

        while i < m:
            ai = int(0.5 * (log(n)/log(D[i]))) # натуральный логарифм
            j = 0

            while j <= ai:
                Q_xi, Q_yi, d = multiply_binary(Q_xi, Q_yi, D[i], A, n)
                j += 1

                if d > 1 and d < n:
                    if(isprime(d) != True):
                        d = get_prime_divisors(d, m)
                    return d
            i += 1

def get_multipliers(number, base):
    divisors = []
    while(isprime(number) == False):
       d = get_prime_divisors(number, base)
       number //= d
       divisors.append(d)
    divisors.append(number)

def main():
    while(True):
        n = int(input('Enter your fighter\'s number (number):'))
        m = int(input('Enter the arena number (base):'))
        
        start = time.perf_counter()
        divisors, iterations = get_multipliers(n, m)
        stop = time.perf_counter()
        
        print(f'Achievements received (prime divisors): {divisors}\n\
Fight time: {stop - start} second\n\
Number of rounds: {iterations}')

if __name__ == '__main__':
    main()