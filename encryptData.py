from cryptography.fernet import Fernet
import rsa


def Encryption(message):
    # open the symmetric key file
    with open('messageKey.key', 'rb') as skey:
        key = skey.read()

    # create the cipher
    cipher = Fernet(key)

    # encrypt the data
    encrypted_data = cipher.encrypt(bytes(message, 'utf-8'))

    with open('EncryptedFile', 'wb') as edata:
        edata.write(encrypted_data)

    # open the public key file
    with open('publicKey.key', 'rb') as pkey:
        pkdata = pkey.read()

    # load the file
    pubkey = rsa.PublicKey.load_pkcs1(pkdata)

    # encrypt the symmetric key file with the public key
    encrypted_key = rsa.encrypt(key, pubkey)

    with open('encryptedMessageKey', 'wb') as ekey:
        ekey.write(encrypted_key)
