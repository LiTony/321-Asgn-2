from Crypto.Cipher import AES

key = b"0123456789012345"
aesCipher = AES.new(key, AES.MODE_ECB)
blockToEncrypt = b"ABCDEFGHIJKLMNOP"

blockToDecrypt = aesCipher.encrypt(blockToEncrypt)

aesCipher.decrypt(blockToDecrypt)