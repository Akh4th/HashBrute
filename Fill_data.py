import binascii
from termcolor import colored as c
import hashlib as h
import os.path

choices = ['MD5', 'SHA1', 'SHA512', 'SHA256', 'NTLM']
# Getting hash type
kind = input(c("Hash Type : ", "blue"))
while kind.upper() not in choices:
    kind = input(c("Wrong hash type, try again ", "red"))
# Importing wordlist
wordlist = input(c("Wordlist name : ", "blue"))
while not os.path.isfile(wordlist):
    wordlist = input(c("File doesn't exist, try again ", "red"))


# Checking if hash is already on database
def check(kind1, word1):
    with open(kind1.upper() + "_table.txt", 'r') as file2:
        for word2 in file2.readlines():
            if word2.split(" ")[2] == word1:
                return True
    return False


if kind.lower() == "md5":
    with open(wordlist, "r") as words:
        for line in words.readlines():
            with open(kind.upper() + "_table.txt", "a") as file:
                x = h.md5(line.encode()).hexdigest()
                if not check(kind, line):
                    file.write(x + " = " + line)


elif kind.lower() == "sha1":
    with open(wordlist, "r") as words:
        for line in words.readlines():
            with open(kind.upper() + "_table.txt", "a") as file:
                x = h.md5(line.encode()).hexdigest()
                if not check(kind, line):
                    file.write(x + " = " + line)


elif kind.lower() == "sha256":
    with open(wordlist, "r") as words:
        for line in words.readlines():
            with open(kind.upper() + "_table.txt", "a") as file:
                x = h.md5(line.encode()).hexdigest()
                if not check(kind, line):
                    file.write(x + " = " + line)


elif kind.lower() == "sha512":
    with open(wordlist, "r") as words:
        for line in words.readlines():
            with open(kind.upper() + "_table.txt", "a") as file:
                x = h.md5(line.encode()).hexdigest()
                if not check(kind, line):
                    file.write(x + " = " + line)


else:
    with open(wordlist, "r") as words:
        for line in words.readlines():
            with open(kind.upper() + "_table.txt", "a") as file:
                y = h.new('md4', line.encode('utf-16le')).digest()
                x = binascii.hexlify(y).decode()
                if not check(kind, line):
                    file.write(x + " = " + line)
