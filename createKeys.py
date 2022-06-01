import rsa
from cryptography.fernet import Fernet


def KeyGeneration():
    # create the symmetric key
    key = Fernet.generate_key()

    # write the symmetric key to a file
    with open('symmetricKey.key', 'wb') as sk:
        sk.write(key)

    # create the pub & private keys
    (pubkey, privkey) = rsa.newkeys(2048)

    # write the public key to a file
    with open('publicKey.key', 'wb') as pukey:
        pukey.write(pubkey.save_pkcs1('PEM'))

    # write the private key to a file
    with open('privateKey.key', 'wb') as prkey:
        prkey.write(privkey.save_pkcs1('PEM'))
