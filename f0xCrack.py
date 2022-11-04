# SHA256 Password cracker
# Created by slyf0x
# 9/28/2022

from pwntools import *
import sys

if len(sys.argv != 2):
    print("Invalid Argument")
    print(">> {} <sha256sum".format(sys.argv[0]))
    exit()

userHash = sys.argv[1]
pwFile = "rockyou.txt"
attempts = 0

with log.process("Attempting to crack: {}\n".format(userHash)) as p:
    with open(pwFile, "r", encoding='latin-l') as pwList:
        for password in pwList:
            password = password.strip("\n").encode('latin-l')
            pwHash = sha256sumhex(password)
            p.status("[]{}] {} == {}".format(attempts, password.decode('latin-l'), pwHash))
            if pwHash == userHash:
                p.success("Password hash found after {} attempts. {} hashes to {}.".format(attempts, pwHash)
                exit()
            attempts += 1
        p.failure("Hash not found")

#test with echo -ne python | sha256sum
