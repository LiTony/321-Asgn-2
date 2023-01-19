from Crypto.Cipher import AES

# 128 bits = 16B
def pad_128_bits(message):
    offset = 16 - len(message) % 16
    for i in range(offset):
        message = message + chr(offset)
    return message

# returns a list of 16B chunks, padded
def ecb(message, aes):
    pad_m = pad_128_bits(message)
    count = len(pad_m)//16 
    
    # create a list of 16B chunks
    chunks = []  
    for i in range(count):
        start = i * 16
        chunk = pad_m[start:start+16]
        chunks.append(bytes(chunk, encoding="ascii"))
    
    # encrypt the message, chunk by chunk
    encrypted = b""
    for chunk in chunks:
        encrypted = encrypted + aes.encrypt(chunk)
    return encrypted


key = b"0123456789012345"
aesCipher = AES.new(key, AES.MODE_ECB)
plaintext = "hello! my message is longer than 128 bytes :)"
print(plaintext)
ciphertext = ecb(plaintext, aesCipher)
print(ciphertext)
print(aesCipher.decrypt(ciphertext))