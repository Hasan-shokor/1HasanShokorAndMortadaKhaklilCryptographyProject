from Crypto.Cipher import AES

key = open('decrypted.pem', 'rb').read()

def encryptAES(data):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
   # print(f'AES key: {key} \n\n cipher text: {ciphertext} \n tag: {tag}')
    print(f'encrypted: {ciphertext}')
    file_out = open("encrypted_data.bin", "wb")
    [ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
    file_out.close

def decryptAES():
    file_in = open("encrypted_data.bin", "rb")
    nonce, tag, cypherTxt = [file_in.read(x) for x in (16, 16, -1)]
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    data2 = cipher.decrypt_and_verify(cypherTxt, tag)
    print(f'decrypted text: {data2}')

