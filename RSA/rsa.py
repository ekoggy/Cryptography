from Crypto.Util.number import getPrime, inverse, GCD
from Crypto.Random import get_random_bytes

class RSA:
    def __init__(self, filename = None) -> None:
        # base parameters
        self.n = 0
        self.e = 0
        self.d = 0

        #keys
        self.public_key = (1, 0)
        self.private_key = (1, 0)

        # choosing p and q
        if not filename:
            p = getPrime(1024, randfunc=get_random_bytes)
            q = getPrime(1024, randfunc=get_random_bytes)
        else:
            with open(filename, "r", encoding="utf-8") as file:
                p = int(file.readline())
                q = int(file.readline())
        
        #init base parameters
        v = (p-1)*(q-1)
        while GCD(self.e, v) > 1:
            self.e = getPrime(1024, randfunc=get_random_bytes)
        self.d = inverse(self.e, v)

        # init keys
        self.public_key = tuple(self.n, self.e)
        self.private_key = tuple(self.n, self.e)


    
    def encrypt():
        pass

    def decrypt():
        pass

    def form_sign():
        pass

    def check_sign():
        pass