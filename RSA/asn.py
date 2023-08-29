from asn1 import Decoder, Encoder, Numbers

class ASN:
    @staticmethod
    def encrypt(id_key_algorithm,
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
    def decrypt(asn):
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