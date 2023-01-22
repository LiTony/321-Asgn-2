from Crypto.Cipher import AES
from PIL import Image
from io import BytesIO
import urllib.parse

def submit():
    userAnswer = input("Type an arbitrary string: ")
    userEncode = urllib.parse.quote(userAnswer, safe='~()*!.\'')
    result = "userid=456; userdata=" + userEncode + ";session-id=31337"
    return result

answer = submit()
print(answer)