from rsa import RSA

if __name__ == '__main__':
    text = input('Введите текст: ')
    coder = RSA()
    encrypted_text = coder.encrypt(text.encode('utf-8'))
    print(encrypted_text)
    decrypted_text = coder.decrypt(encrypted_text)
    x = decrypted_text.decode('utf-8')
    print(x)