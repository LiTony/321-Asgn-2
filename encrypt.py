from Crypto.Cipher import AES
from PIL import Image
from io import BytesIO

# 128 bits = 16B
def pad_128_bits(message):
    offset = 16 - len(message) % 16
    if offset == 16:
        offset = 0
    for i in range(offset):
        message = message + bytes(offset)
    return message

# pads the message and returns a 
# list of 16B chunks
def pad_and_chunk(message):
    pad_m = pad_128_bits(message)
    count = len(pad_m)//16 

    # create a list of 16B chunks
    chunks = []  
    for i in range(count):
        start = i * 16
        chunk = pad_m[start:start+16]
        chunks.append(chunk)
    return chunks

# returns an encrypted, padded set of bytes
# message is in byte form
def ecb(message, aes):
    chunks = pad_and_chunk(message)
    
    # encrypt the message, chunk by chunk
    encrypted = b""
    for chunk in chunks:
        encrypted = encrypted + aes.encrypt(chunk)
    return encrypted

# returns encrypted message by cbc
# iv is the same size as a 16B chunk
def cbc(message, iv, aes):
    chunks = pad_and_chunk(message)

    encrypted = b""
    prev_cipher = iv
    for chunk in chunks:
        xor_chunk = xor(prev_cipher, chunk)
        curr_cipher = aes.encrypt(xor_chunk)
        encrypted = encrypted + curr_cipher
        prev_cipher = curr_cipher
    return encrypted

# workaround for xor-ing bytes
def xor(b1, b2):
    res = b""
    for b1, b2 in zip(b1, b2):
        res = res + bytes([b1^b2])
    return res


# returns the byte form of a given image
def get_image_bytearray(path):
    with open(path, "rb") as image:
        f = image.read()
        b = bytearray(f)
        return bytes(b)

# displays the bytes using PIL.Image
def showimage(bytes):
    img = Image.open(BytesIO(bytes))
    img.show()

def main():
    # 16B key and initialization vector
    key = b"0123456789012345"
    iv = b"0123456789012345"
    aesCipher = AES.new(key, AES.MODE_ECB)
    plaintext = get_image_bytearray("mustang.bmp")

    # the header is preserved so we can actually view the image
    header, image = plaintext[0:54], plaintext[54:]
    ecb_cipher = ecb(image, aesCipher)
    showimage(header + ecb_cipher)

    cbc_cipher = cbc(image, iv, aesCipher)
    showimage(header + cbc_cipher)
    return

if __name__ == "__main__":
    main()
