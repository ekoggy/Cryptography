from Crypto.Util.number import getPrime, inverse, GCD
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256

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
        self.n = p * q
        v = (p-1)*(q-1)
        while GCD(self.e, v) > 1:
            self.e = getPrime(1024, randfunc=get_random_bytes)
        self.d = inverse(self.e, v)

        # init keys
        self.public_key = tuple[self.n, self.e]
        self.private_key = tuple[self.n, self.e]

    def encrypt(self, open_text):
        open_text_bytes = int.from_bytes(open_text, byteorder="big")
        encrypted_text = pow(open_text_bytes, self.e, self.n)
        return encrypted_text

    def decrypt(self, encrypted_text):
        encrypted_text = pow(encrypted_text, self.d, self.n)
        open_text = encrypted_text.to_bytes(32, byteorder="big")
        return open_text

    def form_sign(self, text):
        hash = SHA256.new(text)
        int_hash = int(hash.hexdigest(),16)
        sign = pow(int_hash, self.d, self.n)
        return sign

    def check_sign(self, sign, text):
        hash = SHA256.new(text)
        checking_hash = pow(sign, self.e, self.n)
        if hash == checking_hash:
            print('Подпись принимается')
        else:
            print('Подпись неверна')