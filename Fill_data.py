import binascii
from termcolor import colored as c
import hashlib as h
import os.path

choices = ['MD5', 'SHA1', 'SHA512', 'SHA256', 'NTLM']


def check(kind1, hsh):
    try:
        with open(kind1.upper() + "_table.txt", 'r') as file2:
            for word2 in file2.readlines():
                if word2.split(" ")[0] == hsh:
                    return True
        return False
    except:
        return False


def matching(z):
    match z:
        case "md5":
            print(c("\nConverting from ", "red") + c(wordlist, "blue"), c("to ", "red") + c("MD5", 'blue'))
            with open(wordlist, "r") as words:
                for line in words.readlines():
                    with open(kind.upper() + "_table.txt", "a") as file:
                        x = h.md5(line.encode()).hexdigest()
                        if not check(kind, x):
                            file.write(x + " = " + line + "\n")

        case "sha1":
            print(c("\nConverting from ", "red") + c(wordlist, "blue"), c("to ", "red") + c("SHA1", 'blue'))
            with open(wordlist, "r") as words:
                for line in words.readlines():
                    with open(kind.upper() + "_table.txt", "a") as file:
                        x = h.sha1(line.encode()).hexdigest()
                        if not check(kind, x):
                            file.write(x + " = " + line + "\n")

        case "sha256":
            print(c("\nConverting from ", "red") + c(wordlist, "blue"), c("to ", "red") + c("SHA256", 'blue'))
            with open(wordlist, "r") as words:
                for line in words.readlines():
                    with open(kind.upper() + "_table.txt", "a") as file:
                        x = h.sha256(line.encode()).hexdigest()
                        if not check(kind, x):
                            file.write(x + " = " + line + "\n")

        case "sha512":
            print(c("\nConverting from ", "red") + c(wordlist, "blue"), c("to ", "red") + c("SHA512", 'blue'))
            with open(wordlist, "r") as words:
                for line in words.readlines():
                    with open(kind.upper() + "_table.txt", "a") as file:
                        x = h.sha512(line.encode()).hexdigest()
                        if not check(kind, x):
                            file.write(x + " = " + line + "\n")

        case "ntlm":
            print(c("\nConverting from ", "red") + c(wordlist, "blue"), c("to ", "red") + c("NTLM", 'blue'))
            with open(wordlist, "r") as words:
                for line in words.readlines():
                    with open(kind.upper() + "_table.txt", "a") as file:
                        y = h.new('md4', line.encode('utf-16le')).digest()
                        x = binascii.hexlify(y).decode()
                        if not check(kind, x):
                            file.write(x + " = " + line + "\n")
    print(c("\nDONE !\n", "green") + c(z.upper() + "_table.txt", "yellow") + c(" Has been updated.", "green"))


# Getting hash type
kind = input(c("Hash Type : ", "blue"))
while kind.upper() not in choices:
    kind = input(c("Wrong hash type, try again ", "red"))
# Importing wordlist
wordlist = input(c("Wordlist name : ", "blue"))
while not os.path.isfile(wordlist):
    wordlist = input(c("File doesn't exist, try again ", "red"))
try:
    matching(kind.lower())
except Exception as e:
    print(c("Error while running.\n", "red") + c("Error Code : ", 'yellow') + c(e, "blue"))
