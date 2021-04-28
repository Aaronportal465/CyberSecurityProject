import sys
import math
import time

x = 53
y = 59

#TO RUN ANY INPUT FILE
# For encrpytion uncomment all 4
# For decryption comment out the second line (it will overwrite the code and decode an empty file)

#Takes in the test text files
#inFile = open("tiny.txt", "r")
#outFile = open("tinyEnc.txt", "w")
#otherInFile = open("tinyEnc.txt", "r")
#otherOutFile = open("tinyDec.txt", "w")


#Takes in the input Alice.txt file
#inFile = open("alice.txt", "r")
#outFile = open("aliceEnc.txt", "w")
#otherInFile = open("aliceEnc.txt", "r")
#otherOutFile = open("aliceDec.txt", "w")

#Takes in the input Sample1.txt file
#inFile = open("Sample1.txt", "r")
#outFile = open("Sample1Enc.txt", "w")
#otherInFile = open("Sample1Enc.txt", "r")
#otherOutFile = open("Sample1Dec.txt", "w")

#Takes in the input Sample2.txt file
#inFile = open("Sample2.txt", "r")
#outFile = open("Sample2Enc.txt", "w")
#otherInFile = open("Sample2Enc.txt", "r")
#otherOutFile = open("Sample2Dec.txt", "w")


#Takes in the input Sample3.txt file
inFile = open("Sample3.txt", "r")
#outFile = open("Sample3Enc.txt", "w")
otherInFile = open("Sample3Enc.txt", "r")
otherOutFile = open("Sample3Dec.txt", "w")


# Variables
# x = firstPrime
# y = secondPrime
# r = Eulers Toitent
# e = ????


# Functions Needed
# GCD(e, r)
# Euclid(e, r)
# extendedEuclid(x, y)
# mulInverse(e, r)
#


# checks if number is prime
def checkPrime(num):
    if num == 2:
        return True
    elif ((num < 2) or (num % 2) == 0):
        return False
    elif (num > 2):
        for i in range(2, num):
            if not (num % i):
                return False
    return True


if (checkPrime(x) == False and checkPrime(y) == False):
    exit("Please make both numbers Prime numbers")
else:
    print("Prime numbers are %d and %d" % (x, y))

n = x * y
# n = 3233
print("RSA n: " + str(n))

# Eulers Toitent= r
r = (x - 1) * (y - 1)
print("Eulers Torient r: " + str(r))


# GCD
def eGCD(e, r):
    while (r != 0):
        e, r = r, e % r
    return e


# Euclid's Algorithm
def euclid(e, r):
    for i in range(1, r):
        while (e != 0):
            a, b = r // e, r % e
            if (y != 0):
                # print("%d = %d * (%d) + %d"%(r, a, e, b))
                l = 0
            r = e
            e = b


# Extended Euclid's Algorithm
def extendedEuclid(a, b):
    if (a % b == 0):
        return (b, 0, 1)
    else:
        gcd, s, t = extendedEuclid(b, a % b)
        s = s - ((a // b) * t)
        # print("%d = %d*(%d) + (%d)*(%d)"%(gcd,a,t,s,b))
        return (gcd, t, s)


# Multiplicative Inverse
def mulInverse(e, r):
    gcd, s, _ = extendedEuclid(e, r)
    if (gcd != 1):
        return None
    else:

        return s % r


for i in range(1, 1000):
    if (eGCD(i, r) == 1):
        e = i

print("The value of e is: ", e)

# Private and Public sorted
euclid(e, r)

d = mulInverse(e, r)

public = (e, n)
private = (d, n)

print()
print("Private key: ", private)
print("Public key: ", public)

def listToString(string):

    string = str(string)
    string1 = ""

    for c in string:
        string1 += c

    return string1

def encrypt(publicKey, text):
    e, n = public
    arr = []
    m = 0

    for i in text:
        if (i.isupper()):
            m = ord(i) - 65
            c = pow(m, e)
            c = c%n
            #c = (m ** e) % n
            arr.append(c)

        elif (i.islower()):
            m = ord(i) - 97
            c = pow(m, e)
            c = c % n
            #c = (m ** e) % n
            arr.append(c)

        elif (i.isspace()):
            arr.append(400)

    #converts the list to a string and reformats it
    output = listToString(arr)
    output = output[1:-1]
    #output = output.replace(',', '')

    outFile.write(output)
    outFile.write("\n")

    return output


def decrypt(private, ciphertext):
    d, n = private
    text = ciphertext.split(',')
    buff = ''
    m = 0

    #print("DID I MAKE IT THIS FAR?")
    for i in text:

        j = int(i)
        if (j == 400):
            buff += ' '


        else:

            m = pow(int(i), d)
            m = m%n
            m = int(m) + 65
            #print(m)
            c = chr(m)
            #print(buff)
            buff += c
    return buff

#        else:
#            m = (int(i) ** d) % n
#            m += 65
#            m = int(m)
#            c = chr(m)
#            buff += c




# Choose Encrypt or Decrypt and Print
choose = input("Type '1' for encryption or '2' for decrytion.")
if (choose == '1'):
    print("I'm working give me a second to finish")
    start = time.time()


    for line in inFile:
        enc_msg = encrypt(public, line)
        #print("The encrypted message is:", enc_msg)
    end = time.time()
    print("The runtime for encryption was: ", (end-start))

elif (choose == '2'):
    start = time.time()
    #print(otherInFile.read())
    for line in otherInFile:

        dec_msg = decrypt(private, line)
        otherOutFile.write(dec_msg)
        otherOutFile.write("\n")
    otherOutFile.close()
    dec = open("aliceDec.txt", "r")

    #print("The decrypted message is: ")
    #THIS DOESN'T SEND THE ACTUAL MESSAGE
    #print(dec.read())

    end = time.time()
    print("The runtime for decrpytion was: ", (end-start))

else:
    exit("Incorrect Option.")
