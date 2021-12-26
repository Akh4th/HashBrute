import binascii
from termcolor import colored as c
import hashlib as h
import os.path
import time


def sha512(file, hsh):
    try:
        i = 0
        tim = time.time()
        print(c("STARTED DECRYPTING ", "red") + c("SHA512", 'blue') + c(" - ", "red") + c(hsh, "green") + c(" FROM ","red") + c(file, 'green'))
        time.sleep(1)
        with open(file, 'r') as filename:
            for line in filename.readlines():
                for passwd in line.split():
                    i += 1
                    pre = (i * 100) / counts
                    dur = time.time() - tim
                    print(c(f"\rTRIES : {i}/{counts}\t\t", "yellow") + c(f"PROGRESS : {round(pre, 2)}%\t\t", "blue") + c(f"DURATION : {round(dur, 2)}s", "green"), end=" ")
                    x = h.sha512(passwd.encode())
                    if x.hexdigest() == hsh:
                        print(c("\nDecryption is over !\n", 'red') + c("Decrypted string : ", 'yellow') + c(passwd, 'green'))
                        return True
                    else:
                        continue
        return False
    except Exception as e:
        print(f"Error while decrypting !\nError code : {e}")


def sha256(file, hsh):
    try:
        i = 0
        tim = time.time()
        print(c("STARTED DECRYPTING ", "red") + c("SHA256", 'blue') + c(" - ", "red") + c(hsh, "green") + c(" FROM ","red") + c(file, 'green'))
        time.sleep(1)
        with open(file, 'r') as filename:
            for line in filename.readlines():
                for passwd in line.split():
                    i += 1
                    pre = (i * 100) / counts
                    dur = time.time() - tim
                    print(c(f"\rTRIES : {i}/{counts}\t\t", "yellow") + c(f"PROGRESS : {round(pre, 2)}%\t\t", "blue") + c(f"DURATION : {round(dur, 2)}s", "green"), end=" ")
                    x = h.sha256(passwd.encode())
                    if x.hexdigest() == hsh:
                        print(c("\nDecryption is over !\n", 'red') + c("Decrypted string : ", 'yellow') + c(passwd, 'green'))
                        return True
                    else:
                        continue
        return False
    except Exception as e:
        print(f"Error while decrypting !\nError code : {e}")


def sha1(file, hsh):
    try:
        i = 0
        tim = time.time()
        print(c("STARTED DECRYPTING ", "red") + c("SHA1", 'blue') + c(" - ", "red") + c(hsh, "green") + c(" FROM ","red") + c(file, 'green'))
        time.sleep(1)
        with open(file, 'r') as filename:
            for line in filename.readlines():
                for passwd in line.split():
                    i += 1
                    pre = (i * 100) / counts
                    dur = time.time() - tim
                    print(c(f"\rTRIES : {i}/{counts}\t\t", "yellow") + c(f"PROGRESS : {round(pre, 2)}%\t\t", "blue") + c(f"DURATION : {round(dur, 2)}s", "green"), end=" ")
                    x = h.sha1(passwd.encode())
                    if x.hexdigest() == hsh:
                        print(c("\nDecryption is over !\n", 'red') + c("Decrypted string : ", 'yellow') + c(passwd, 'green'))
                        return True
                    else:
                        continue
        return False
    except Exception as e:
        print(f"Error while decrypting !\nError code : {e}")


def md5(file, hsh):
    try:
        i = 0
        tim = time.time()
        print(c("STARTED DECRYPTING ", "red") + c("MD5", 'blue') + c(" - ", "red") + c(hsh, "green") + c(" FROM ", "red") + c(file, 'green'))
        time.sleep(3)
        with open(file, 'r') as filename:
            for line in filename.readlines():
                for passwd in line.split():
                    i += 1
                    pre = (i * 100) / counts
                    dur = time.time() - tim
                    print(c(f"\rTRIES : {i}/{counts}\t\t", "yellow") + c(f"PROGRESS : {round(pre, 2)}%\t\t", "blue") + c(f"DURATION : {round(dur, 2)}s", "green"), end=" ")
                    x = h.md5(passwd.encode())
                    if x.hexdigest() == hsh:
                        print(c("\nDecryption is over !\n", 'red') + c("Decrypted string : ", 'yellow') + c(passwd, 'green'))
                        return True
                    else:
                        continue
        return False
    except Exception as e:
        print(f"Error while decrypting !\nError code : {e}")


def ntlm(file, hsh):
    try:
        i = 0
        tim = time.time()
        print(c("STARTED DECRYPTING ", "red") + c("NTLM", 'blue') + c(" - ", "red") + c(hsh, "green") + c(" FROM ", "red") + c(file, 'green'))
        time.sleep(3)
        with open(file, 'r') as filename:
            for line in filename.readlines():
                for passwd in line.split():
                    i += 1
                    pre = (i * 100) / counts
                    dur = time.time() - tim
                    print(c(f"\rTRIES : {i}/{counts}\t\t", "yellow") + c(f"PROGRESS : {round(pre, 2)}%\t\t", "blue") + c(f"DURATION : {round(dur, 2)}s", "green"), end=" ")
                    y = h.new('md4', passwd.encode('utf-16le')).digest()
                    x = binascii.hexlify(y).decode()
                    if x == hsh:
                        print(c("\nDecryption is over !\n", 'red') + c("Decrypted string : ", 'yellow') + c(passwd, 'green'))
                        return True
                    else:
                        continue
        return False
    except Exception as e:
        print(f"Error while decrypting !\nError code : {e}")


def detect(hsh):
    # 64 bits hash
    if len(hsh) == 64:
        print(c("SHA256 DETECTED !!!\n", 'blue'))
        time.sleep(1)
        if not sha256(wordlist, hsh):
            print(c("\nNO MATCH FOUND !\n", "red") + c("PLEASE USE ANOTHER WORDLIST !", 'yellow'))
            quit()
    # 40 bits hash
    elif len(hsh) == 40:
        print(c("SHA1 DETECTED !!!\n", 'blue'))
        time.sleep(1)
        if not sha1(wordlist, hsh):
            print(c("\nNO MATCH FOUND !\n", "red") + c("PLEASE USE ANOTHER WORDLIST !", 'yellow'))
            quit()
    # 32 bits hash
    elif len(hsh) == 32:
        choice = input(c("32 bits hash was found, please choose hash algorithm :\n", 'red') + c("[NTLM/MD5 or * for both] : ", 'yellow'))
        choices = ['ntlm', 'md5', '*']
        while choice.lower() not in choices:
            choice = input(c("WRONG INPUT !!!\n", 'red') + c("[NTLM/MD5/*] : ", 'yellow'))
        if choice.lower() == choices[0]:
            print(c("\nNTLM DETECTED !!!\n", 'blue'))
            time.sleep(1)
            if not ntlm(wordlist, hsh):
                print(c("\nNO MATCH FOUND !\n", "red") + c("PLEASE USE ANOTHER WORDLIST !", 'yellow'))
                quit()
        elif choice.lower() == choices[1]:
            print(c("\nMD5 DETECTED !!!\n", 'blue'))
            time.sleep(1)
            if not md5(wordlist, hsh):
                print(c("\nNO MATCH FOUND !\n", "red") + c("PLEASE USE ANOTHER WORDLIST !", 'yellow'))
                quit()
        else:
            print(c("\nTRYING BOTH ", 'red') + c("NTLM ", 'blue') + c("& ", "red") + c("MD5", 'blue'))
            time.sleep(1)
            if not ntlm(wordlist, hsh):
                print(c("\n\nNOT NTLM !!!\n", "red") + c("TRYING MD5 !\n", 'yellow'))
                time.sleep(2)
                if not md5(wordlist, hsh):
                    print(c("\nNO MATCH FOUND !\n", "red") + c("PLEASE USE ANOTHER WORDLIST !", 'yellow'))
                    quit()
    # 128 bits hash
    elif len(hsh) == 128:
        print(c("SHA512 DETECTED !!!\n", 'blue'))
        time.sleep(1)
        if not sha512(wordlist, hsh):
            print(c("\nNO MATCH FOUND !\n", "red") + c("PLEASE USE ANOTHER WORDLIST !", 'yellow'))
            quit()
    else:
        print(c("\nUNRECOGNIZED HASH FORMAT !\n", 'red') + c("Maybe hash has salt ?", 'yellow'))
        quit()


if __name__ == "__main__":
    print(c("Welcome to python ", "red") + c("HASH DECRYPTER ", "green") + c("by", "red") + c(" Akh4th", 'blue') + c(" !", 'red'))
    time.sleep(3)
    # Getting and validating hash file
    hashed = input(c("Hash file name : ", 'yellow'))
    while not os.path.isfile(hashed):
        hashed = input(c("File doesn't exist, make sure you use full path !\n", 'red') + c("Hash file name : ", 'yellow'))
    time.sleep(1)
    # Getting and validating wordlist file
    wordlist = input(c("Wordlist file name : ", 'yellow'))
    while not os.path.isfile(wordlist):
        wordlist = input(c("File doesn't exist, make sure you use full path !\n", 'red') + c("Hash file name : ", 'yellow'))
    time.sleep(1)
    # Storing the hash on a variable
    with open(hashed, 'r') as hush:
        hashed = hush.read()
        print(c("\nHASH SUCCESSFULLY LOADED !", "green"))
    time.sleep(1)
    # counting tries on wordlist
    counts = len(open(wordlist, "r").readlines())
    print(c("WORDLIST SUCCESSFULLY LOADED !\n", "green") + c("TOTAL OF ", "red") + c(counts, "yellow") + c(" tries ahead !\n", "red"))
    time.sleep(1)
    # Starting brute force according to hash's length
    detect(hashed)
