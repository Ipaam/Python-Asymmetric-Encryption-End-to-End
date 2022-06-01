import base64
import json
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding as cipher_padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


def aes_encryption(pub_key, data={}):
    data = json.dumps(data)
    key = os.urandom(16)
    iv = os.urandom(16)
    cipher = Cipher(
        algorithm=algorithms.AES(key),
        mode=modes.CBC(iv),
        backend=default_backend()
    )
    padder = cipher_padding.PKCS7(128).padder()
    encryptor = cipher.encryptor()
    pad_data = padder.update(data.encode())
    pad_data += padder.finalize()
    encrypt_data = encryptor.update(pad_data)
    encrypt_data += encryptor.finalize()
    public_key = serialization.load_pem_public_key(
        pub_key.encode(),
        backend=default_backend()
    )
    enc_key = public_key.encrypt(key, padding.PKCS1v15())
    result = {
        'encData': base64.b64encode(encrypt_data).decode(),
        'iv': base64.b64encode(iv).decode(),
        'encKey': base64.b64encode(enc_key).decode()
    }
    return result


def aes_decryption(priv, encData, iv, encKey):
    private_key = priv
    enc_key = base64.b64decode(encKey)
    my_iv = base64.b64decode(iv)

    private_key = serialization.load_pem_private_key(
        private_key.encode(),
        password=None,
        backend=default_backend()
    )
    key = private_key.decrypt(
        enc_key,
        padding=padding.PKCS1v15()
    )
    enc_data = encData
    enc_data = base64.b64decode(enc_data)
    cipher = Cipher(
        algorithm=algorithms.AES(key),
        mode=modes.CBC(my_iv),
        backend=default_backend()
    )
    decryptor = cipher.decryptor()
    data = decryptor.update(enc_data)
    data += decryptor.finalize()
    padder = cipher_padding.PKCS7(128).unpadder()
    data = padder.update(data)
    data += padder.finalize()
    return json.loads(data.decode('utf8'))
