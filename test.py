from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from aes_encryption import aes_encryption, aes_decryption

with open("private_key.pem", "rb") as key_file:
    # private_key = serialization.load_pem_private_key(
    #     key_file.read(),
    #     password=None,
    #     backend=default_backend()
    # )
    private_key = key_file.read().decode()

with open("public_key.pem", "rb") as key_file:
    # public_key = serialization.load_pem_public_key(
    #     key_file.read(),
    #     backend=default_backend()
    # )
    public_key = key_file.read().decode()

aes_encryptedData = aes_encryption(public_key, {"message": "salam"})

decryptedData = aes_decryption(private_key, aes_encryptedData['encData'], aes_encryptedData['iv'], aes_encryptedData['encKey'])

print(decryptedData)
