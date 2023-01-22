from Crypto.Cipher import AES
from PIL import Image
from io import BytesIO
import urllib.parse

from encrypt import pad_and_chunk, cbc;

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

def main():
    # 16B key and initialization vector
    key = b"0123456789012345"
    iv = b"0123456789012345"
    aesCipher = AES.new(key, AES.MODE_ECB)
    
    encrypted = submit(iv, aesCipher)

    decrypted = b""

    # CONSTRUCTION IN PROGRESS
    len16 = len(encrypted) // 16
    for i in range(len16):
        decrypted += aesCipher.decrypt(encrypted[(i-1)*16:i*16])
    # CONSTRUCTION IN PROGRESS

    print("decrypted:\n\t", decrypted)

    return

if __name__ == "__main__":
    main()