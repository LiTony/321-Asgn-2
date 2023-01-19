from Crypto.Cipher import AES
import random, string

# gives you a random key of size bytes
def get_rand_key(size):
    return ''.join(random.choice(string.ascii_letters) for i in range(size))

# 128 bits = 16B
def pad_128_bits(message):
    offset = 16 - len(message) % 16
    for i in range(offset):
        message = message + chr(offset)
    return message

# initialize cipher
key = get_rand_key(16)
cipher = AES.new(key, AES.MODE_ECB)
print(key)

print(pad_128_bits("hello wolrd"))
# msg = cipher.encrypt('this is the plaintext')
# print (type(msg))