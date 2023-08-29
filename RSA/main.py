from rsa import RSA
from asn import ASN
from Crypto.Cipher import AES
from Crypto.Util.number import getPrime, inverse, GCD
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Util.Padding import pad, unpad

# init keys
public_key = (0, 0)
private_key = (0, 0)
aes_key = get_random_bytes(32) 
init_vector = get_random_bytes(16)


def get_text():

    filename = input("Enter the path to the file: ")
    text = b''
    with open(filename, "rb") as file:
        for line in file:
            text += line

    return text, filename


#------------------ENCRYPTION BLOCK(#)------------------#
def encrypt_text(text):
    aes_cipher = AES.new(key=aes_key, 
                         mode=AES.MODE_CBC, 
                         iv=init_vector)
    
    encrypted_text = aes_cipher.encrypt(pad(text, 16))

    return encrypted_text, aes_key

def encrypt_key(open_key):
    open_key_bytes = int.from_bytes(open_key, byteorder="big")
    encrypted_key = pow(open_key_bytes, public_key[1], public_key[0])
    return encrypted_key

def encrypt_file(): # #
    text, filename = get_text()
    encrypted_text, open_key = encrypt_text(text)
    encrypted_key = encrypt_key(open_key)
    asn_text = ASN.encrypt(b'\x00\x01',
                b'Encoded file with RSA',
                public_key[0],
                public_key[1],
                encrypted_key,
                b'\x10\x82',
                len(encrypted_text),
                encrypted_text)
    with open("#" + filename, "wb") as enc:
        enc.write(asn_text)


#------------------DECRYPTION BLOCK(~)------------------#
def decrypt_key(encrypted_key):
    open_key_bytes = pow(encrypted_key, private_key[1], private_key[0])
    open_key = open_key_bytes.to_bytes(32, byteorder="big")
    return open_key

def decrypt_text(text, key):
    aes_cipher = AES.new(key=key, 
                         mode=AES.MODE_CBC, 
                         iv=init_vector)
    
    decrypted_text = aes_cipher.decrypt(text)
    decrypted_text = unpad(decrypted_text, 16)

    return decrypted_text

def decrypt_file():
    text, filename = get_text()
    _, _, encrypted_key, encrypted_text = ASN.decrypt(text)
    open_key = decrypt_key(encrypted_key)
    open_text = decrypt_text(encrypted_text, open_key)

    with open("~" + filename, "wb") as dec:
        dec.write(open_text)
   

#------------------CREATING BLOCK(^)------------------#
def form_sign(text):
    hash = SHA256.new(text)
    int_hash = int(hash.hexdigest(),16)
    sign = pow(int_hash, private_key[1], private_key[0])
    return sign

def create_signature():# ^
    text, filename = get_text()
    sign = form_sign(text)
    asn_text = ASN.encrypt(b'\x00\x40',
                b'EDS with RSA',
                public_key[0],
                public_key[1],
                encrypted_key,
                b'\x10\x82',
                len(encrypted_text),
                encrypted_text)
    with open("#" + filename, "wb") as enc:
        enc.write(asn_text)


#------------------VERIFYING BLOCK($)------------------#
def check_sign( sign, text):
    hash = SHA256.new(text)
    checking_hash = pow(sign, public_key[1], public_key[0])
    if hash == checking_hash:
        print('Подпись принимается')
    else:
        print('Подпись неверна')

def verify_signature():#
    pass


#------------------VIEWING BLOCK------------------#
def view_parameters():
    pass


def init_keys():
    # choosing p and q
    p = getPrime(1024, randfunc=get_random_bytes)
    q = getPrime(1024, randfunc=get_random_bytes)
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
1. Robin Hood (encrypt file)
2. James Bond (decrypt file)
3. Spider-man (create signature)
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