from fishbowlofb import FishBowlOFB, FishBowlKDF
import sys, select, getpass, os, time, getopt, re

ivlen = 20
keylen = 26

def geniv(ivlen):
    iv = []
    while True:
        byte = os.urandom(1)
        if ord(byte) >= 0 and ord(byte) <= 25:
            iv.append(chr(ord(byte) + 65))
        if len(iv) == ivlen:
            break
    return "".join(iv)

def sterilize(text):
    text =  "".join(re.findall("[a-zA-Z]+", text)).upper()
    return text

try:
    mode = sys.argv[1]
except IndexError as ier:
    print("Error: Did you forget encrypt/decrypt?")
    sys.exit(1)

input_filename = sys.argv[2]
output_filename = sys.argv[3]

try:
    infile = open(input_filename, "r")
except IOError as ier:
    print("Input file not found.")
    sys.exit(1)

try:
    outfile = open(output_filename, "w")
except IOError as ier:
    print("Output file not found.")
    sys.exit(1)

try:
    key = sys.argv[4]
except IndexError as ier:
    key = getpass.getpass("Enter key: ")

fb = FishBowlOFB()
#key = FishBowlKDF().kdf(key, keylen)

start = time.time()
data = infile.read()
infile.close()

if mode == "encrypt":
    iv = geniv(ivlen)
    c = fb.encrypt(sterilize(data), key, iv)
    outfile.write(iv+c)
elif mode == "decrypt":
    iv = data[:ivlen]
    data = data[ivlen:]
    plain_text = fb.decrypt(sterilize(data), key, iv)
    outfile.write(plain_text)
outfile.close()

end = time.time() - start
bps = len(data) / end
sys.stdout.write("Completed in "+str(end)+" seconds\n")
sys.stdout.write(str(bps)+" bytes per second.\n")
