from Crypto.Cipher import AES

# 128 bits = 16B
def pad_128_bits(message):
    offset = 16 - len(message) % 16
    for i in range(offset):
        message = message + chr(offset)
    return message

key = b"0123456789012345"
aesCipher = AES.new(key, AES.MODE_ECB)
blockToEncrypt = b"ABCDEFGHIJKLMNOP"

blockToDecrypt = aesCipher.encrypt(blockToEncrypt)

aesCipher.decrypt(blockToDecrypt)