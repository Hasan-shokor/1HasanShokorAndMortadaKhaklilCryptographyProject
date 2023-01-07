from cryptography import AESClass



while True:
    data = input("add text here: ")
    if data == '0':
        break
    else:
        AESClass.encryptAES(data.encode('utf-8'))
        AESClass.decryptAES()





