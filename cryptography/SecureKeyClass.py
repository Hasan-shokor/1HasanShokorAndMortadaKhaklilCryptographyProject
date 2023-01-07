from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP,AES

aeskey = open('keys/aesKey.pem', 'rb').read()


def generatKeys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    file_out = open('keys/privateKey.pem', 'wb')
    file_out.write(private_key)
    file_out.close()

    public_key = key.publickey().export_key()
    file_out = open('keys/publicKey.pem', 'wb')
    file_out.write(public_key)
    print(private_key,'\n\n\n\n', public_key)
    file_out.close()
    return public_key


def encryptRSA():

    #encrypting aes key with rsa private key
    fileData = open('encrypted.pem', "wb")

    pubKey = RSA.import_key(open('keys/publicKey.pem').read())
    cipherRSA = PKCS1_OAEP.new(pubKey)
    encyptedData = cipherRSA.encrypt(aeskey)
    [ fileData.write(encyptedData)]
    print('\ndata:', encyptedData)
    return encyptedData


def decryptRSA():

    inputFile = open('encrypted.pem', 'rb')
    privateKey = RSA.import_key(open('keys/privateKey.pem').read())
    encryptedKey= inputFile.read()
    cipherRSA = PKCS1_OAEP.new(privateKey)
    decryptedKey = cipherRSA.decrypt(encryptedKey)
    file1 = open('decrypted.pem', 'wb')
    file1.write(decryptedKey)
    return decryptedKey


