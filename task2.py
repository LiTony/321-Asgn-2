from Crypto.Cipher import AES
from PIL import Image
from io import BytesIO
import urllib.parse

from encrypt import pad_and_chunk, cbc, decrypt_cbc, xor;

def testCode():
    def submitTest():
        userAnswer = input("Type an arbitrary string: ")
        userEncode = urllib.parse.quote(userAnswer, safe='~()*!.\'')
        result = b"userid=456; userdata=" + userEncode.encode('ascii') + b";session-id=31337"
        chunks = pad_and_chunk(result)
        return chunks

    chunks = submitTest()
    for chunk in chunks:
        print(chunk, f"\t len = %d" %(len(chunk)))
    return

def submit(iv, aes):
    userAnswer = input("Type an arbitrary string: ")
    userEncode = urllib.parse.quote(userAnswer, safe='~()*!.\'')
    result = b"userid=456; userdata=" + userEncode.encode('ascii') + b";session-id=31337"
    print("result:\n\t", result)
    encrypted = cbc(result, iv, aes)
    print("encrypted:\n\t", encrypted)
    return encrypted

def verify(ciphertext, iv, aesCipher):
    plaintext = decrypt_cbc(ciphertext, iv, aesCipher)
    print("plaintext: \n", plaintext)
    if b";admin=true;" in plaintext:
        return True, plaintext
    return False, plaintext

def printBy16(text):
    length = (len(text) // 16) % 16
    for i in range(length+1):
        print(text[(i-1)*16: i*16])

def modify(ciphertext):
    #given input: 12345678;admin=true;
    # b'userid=456; user'   [0:16]
    # b'data=12345678%3B'   [16:32] <--- Modified   [B]
    # b'admin%3Dtrue%3B;'[c]   [32:48] affected        [A] (post-decryption)
    # b'session-id=31337'   [48:64]
        
    middle_chunk = ciphertext[16:32]
    desired_message = b';admin=true;;;;;'
    modified_middle = xor(middle_chunk, b'admin%3Dtrue%3B;') # produce 0s
    finished_middle = xor(modified_middle, desired_message)
    print("middle_chunk: \n\t", middle_chunk)
    print("modified_middle: \n\t", modified_middle)
    new_ct = ciphertext[0:16] + finished_middle + ciphertext[32:]
    print("net_ct: \n", new_ct)
    return new_ct

def main():
    # 16B key and initialization vector
    key = b"0123456789012345"
    iv = b"0123456789012345"
    aesCipher = AES.new(key, AES.MODE_ECB)
    
    ciphertext = submit(iv, aesCipher)

    ciphertext = modify(ciphertext)

    result, plaintext = verify(ciphertext, iv, aesCipher)

    print("result:\n\t", result)
    print("by 16:\n")
    printBy16(plaintext)

    return

if __name__ == "__main__":
    main()