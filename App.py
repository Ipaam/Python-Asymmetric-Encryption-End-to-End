import createKeys
import encryptData
import decryptData


class App:
    @staticmethod
    def KeysCreation():
        createKeys.KeyGeneration()

    @staticmethod
    def DataEncryption(message):
        encryptData.Encryption(message)

    @staticmethod
    def DataDecryption():
        decryptData.Decryption()


        
# Create Keys using this
App.KeysCreation()

# Once Keys Created, Encrypt Data using this
App.DataEncryption("Hi danial!!!")

# The Encrypted data can be Decrypted using this
App.DataDecryption()
