from asn1 import Decoder, Encoder, Numbers

class ASN:
    @staticmethod
    def encrypt_rsa_cipher(id_key_algorithm,
                string_key_id, 
                n, 
                e, 
                key, 
                id_text_algorithm, 
                text_len, 
                text):
        # работа с asn1
        asn1 = Encoder()
        asn1.start()
        asn1.enter(Numbers.Sequence)
        asn1.enter(Numbers.Set)
        asn1.enter(Numbers.Sequence)
        asn1.write(id_key_algorithm, Numbers.OctetString)  # Идентификатор алгоритма шифрования - 0x0001 – RSA
        asn1.write(string_key_id, Numbers.UTF8String)  # Строковый идентификатор ключа, псевдоним
        asn1.enter(Numbers.Sequence)  # Последовательность для открытого ключа
        asn1.write(n, Numbers.Integer)  # n
        asn1.write(e, Numbers.Integer)  # e
        asn1.leave()
        asn1.enter(Numbers.Sequence)  # Параметры алгоритма - Для RSA не используется
        asn1.leave()
        asn1.enter(Numbers.Sequence)  # Шифртекст алгоритма с открытым ключом - зашифрованный промежуточный ключ симметричного алгоритма
        asn1.write(key, Numbers.Integer)
        asn1.leave()
        asn1.leave()
        asn1.leave()
        asn1.enter(Numbers.Sequence)  # Открытые данные о файле - Дополнительные данные
        asn1.write(id_text_algorithm, Numbers.OctetString)  # Идентификатор алгоритма шифрования
        asn1.write(text_len, Numbers.Integer)  # Длина сообщения
        asn1.leave()
        asn1.leave()
        asn1.write(text)  # шифртекст
        return asn1.output()
    
    @staticmethod
    def decrypt_rsa_cipher(asn):
        asn1 = Decoder()
        asn1.start(asn)
        asn1.enter()  # Sequence
        asn1.enter()  # Set
        asn1.enter()  # Sequence
        _, _ = asn1.read()  # Идентификатор алгоритма шифрования
        _, _ = asn1.read()  # Строковый идентификатор ключа, псевдоним
        asn1.enter()  # Последовательность для открытого ключа
        _, n = asn1.read()  # n
        _, e = asn1.read()  # e
        asn1.leave()
        asn1.enter()  # Параметры алгоритма - Для RSA не используется
        asn1.leave()
        asn1.enter()  # Шифртекст алгоритма с открытым ключом - зашифрованный промежуточный ключ симметричного алгоритма
        _, key = asn1.read()
        asn1.leave()
        asn1.leave()
        asn1.leave()
        asn1.enter()  # Открытые данные о файле - Дополнительные данные
        _, _ = asn1.read()  # Идентификатор алгоритма шифрования
        _, _ = asn1.read()  # Длина сообщения
        asn1.leave()
        asn1.leave()
        _, text = asn1.read()  # шифртекст

        return n,e,key,text
    
    @staticmethod
    def encrypt_rsa_eds(id_key_algorithm,
                string_key_id, 
                n, 
                e, 
                sign):
        asn1 = Encoder()
        asn1.start()
        asn1.enter(Numbers.Sequence)
        asn1.enter(Numbers.Set)
        asn1.enter(Numbers.Sequence)
        asn1.write(id_key_algorithm, Numbers.OctetString)  # Идентификатор алгоритма - SHA256
        asn1.write(string_key_id, Numbers.UTF8String)  # Строковый идентификатор ключа, псевдоним
        asn1.enter(Numbers.Sequence)  # Последовательность для открытого ключа
        asn1.write(n, Numbers.Integer)  # n
        asn1.write(e, Numbers.Integer)  # e
        asn1.leave()
        asn1.enter(Numbers.Sequence)  # Параметры алгоритма - Для RSA не используется
        asn1.leave()
        asn1.enter(Numbers.Sequence)  # подпись сообщения
        asn1.write(sign, Numbers.Integer)
        asn1.leave()
        asn1.leave()
        asn1.leave()
        asn1.enter(Numbers.Sequence)  # дополнительных данных нет
        asn1.leave()
        asn1.leave()

        return asn1.output()

    @staticmethod
    def decrypt_rsa_eds(asn):
        asn1 = Decoder()
        asn1.start(asn)
        asn1.enter()  # Sequence
        asn1.enter()  # Set
        asn1.enter()  # Sequence
        _, _ = asn1.read()  # Идентификатор алгоритма шифрования
        _, _ = asn1.read()  # Строковый идентификатор ключа, псевдоним
        asn1.enter()  # Последовательность для открытого ключа
        _, n = asn1.read()  # n
        _, e = asn1.read()  # e
        asn1.leave()
        asn1.enter()
        asn1.leave()
        asn1.enter()
        _, sign = asn1.read()

        return n, e, sign
    
    @staticmethod
    def encrypt_diffie_hellman(id_key_algorithm,
                string_key_id,
                c,
                mode = "server", 
                p = 0, 
                a = 0):
        asn1 = Encoder()
        asn1.start()
        asn1.enter(Numbers.Sequence) # Заголовок
        asn1.enter(Numbers.Set) # Множество ключей,1 задействован
        asn1.enter(Numbers.Sequence) # Первый ключ 
        asn1.write(id_key_algorithm, Numbers.OctetString)  # Идентификатор алгоритма - Диффи-Хеллманн 0х0021
        asn1.write(string_key_id, Numbers.UTF8String)  # Строковый идентификатор ключа, псевдоним  - 'dh'
        asn1.enter(Numbers.Sequence)  # значение открытого ключа, не используется
        asn1.leave()
        asn1.enter(Numbers.Sequence)  # параметры криптосистемы
        if mode == "client":
            asn1.write(p, Numbers.Integer)  # простое число p
            asn1.write(a, Numbers.Integer)  # образующая a
        asn1.leave()
        asn1.enter(Numbers.Sequence)  # шифртекст, показатель a^x
        asn1.write(c, Numbers.Integer)
        asn1.leave()
        asn1.leave()
        asn1.leave()
        asn1.enter(Numbers.Sequence)  # дополнительных данных нет
        asn1.leave()
        asn1.leave()

        return asn1.output()

    @staticmethod
    def decrypt_diffie_hellman(asn, mode = "server"):
        asn1 = Decoder()
        asn1.start(asn)
        asn1.enter(Numbers.Sequence) # Заголовок
        asn1.enter(Numbers.Set) # Множество ключей,1 задействован
        asn1.enter(Numbers.Sequence) # Первый ключ 
        _, _ = asn1.read()  # Идентификатор алгоритма - Диффи-Хеллманн 0х0021
        _, _ = asn1.read()  # Строковый идентификатор ключа, псевдоним  - 'dh'
        asn1.enter()  # значение открытого ключа, не используется
        asn1.leave()
        asn1.enter(Numbers.Sequence)  # параметры криптосистемы
        if mode == "client":
            _, p = asn1.read()  # простое число p
            _, a = asn1.read()  # образующая a 
        asn1.leave()
        asn1.enter(Numbers.Sequence)  # шифртекст, показатель a^x
        _, c = asn1.read()  # простое число p
        asn1.leave()
        asn1.leave()
        asn1.leave()
        asn1.enter(Numbers.Sequence)  # дополнительных данных нет
        asn1.leave()
        asn1.leave()

        if mode == "client":
            return p, a, c
        else:
            return c