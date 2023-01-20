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

# returns a list of 16B chunks, padded
# message is in byte form
def ecb(message, aes):
    pad_m = pad_128_bits(message)
    count = len(pad_m)//16 

    # create a list of 16B chunks
    chunks = []  
    for i in range(count):
        start = i * 16
        chunk = pad_m[start:start+16]
        chunks.append(chunk)
    
    # encrypt the message, chunk by chunk
    encrypted = b""
    for chunk in chunks:
        encrypted = encrypted + aes.encrypt(chunk)
    return encrypted

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

key = b"0123456789012345"
aesCipher = AES.new(key, AES.MODE_ECB)
plaintext = get_image_bytearray("mustang.bmp")

# the header is preserved so we can actually view the image
header, image = plaintext[0:54], plaintext[54:]
ciphertext = ecb(image, aesCipher)
showimage(header + ciphertext)
aesCipher.decrypt(ciphertext)
