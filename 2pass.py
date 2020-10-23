#!/usr/bin/env python3
import sys
import os
import getopt
import json
import hashlib
import random
from string import ascii_lowercase, ascii_uppercase, digits
from getpass import getpass
from Crypto.Cipher import AES

COMMANDS = ["ls","create","rm","add"]

#Generate random password
def generate_password():
    return ''.join(random.choices(ascii_lowercase+ascii_uppercase+digits
        +"?"+"."+"'"+"+"+")"+"("+"&"+"["+"]"+"!"+"#"+"_"
        +"%"+"$"+"@"+"|"+"*"+":"+"="+"~",k=12))

#Add padding and returns a 32 bytes padded string
def pad(s):
    return s.encode() + b"\0" * (AES.block_size - len(s) % AES.block_size)

#Encrypt a string and returns a random generated iv + encrypted message with AES_CBC
def encrypt(message, key):
    message = pad(message)
    iv = hashlib.md5(key.encode()).digest()
    cipher = AES.new(key.encode("utf-8"), AES.MODE_CBC, iv)
    return iv+cipher.encrypt(message)

#Decrypt a message encrypted with AES_CBC and removes padding
def decrypt(ciphertext, key):
    iv = hashlib.md5(key.encode()).digest()
    cipher = AES.new(key.encode("utf-8"), AES.MODE_CBC, iv)
    try:
        plaintext = cipher.decrypt(ciphertext[AES.block_size:])
    except ValueError:
        print("coffre compromis")
        sys.exit()
    return plaintext.rstrip(b"\0")

#Compute integrity of data, concats hash with data, calls encrypt and save the result in a file
def encrypt_file(data, filename, key):
    h = hashlib.sha256(data.encode()).hexdigest()
    cipher = encrypt(h+data,key)
    with open(filename,"wb") as f:
        f.write(cipher)

#Open a vault file, call decrypt, check integrity and returns data if integrity is checked
def decrypt_file(filename, key):
    try:
        with open(filename,"rb") as f:
            ciphertext = f.read()
            dec = decrypt(ciphertext,key)
    except EnvironmentError:
        print("No such file or directory",file=sys.stderr)
        sys.exit()
    try:
        h = dec.decode()[:64]
        data = dec.decode()[64:]
    except UnicodeDecodeError:
        print("Can't decode file, check your key",file=sys.stderr)
        sys.exit()
    if hashlib.sha256(data.encode()).hexdigest() == h:
        return data
    else:
        print("File's integrity compromised",file=sys.stderr)
        sys.exit()

#Print help menu
def print_help():
    print("2pass v1 (23-10-2020). Usage :")
    print("2pass [-f inputFile] [-o inputFile] [-i passwordID] [-h] command")
    print("    -f Vault file containing passwords")
    print("    -o Output vault inputFile name")
    print("    -i Password ID")
    print("    -h Display help")
    print("Commands")
    print("ls    add     rm    create")
    sys.exit()

#Check if the vault's format is correct
def check_vault(filename,key):
    if len(key) != 16:
        print("Wrong key size !",file=sys.stderr)
        sys.exit()
    vault = json.loads(decrypt_file(filename,key))
    if "data" not in vault:
        print(vault)
        print("Vault format error !")
        sys.exit()
    return vault

#Read vault and print it
def read_vault(filename):
    key = getpass("Please enter your 16 chars key: ")
    vault = check_vault(filename,key)
    if len(vault["data"]) == 0:
        print("Vault empty !")
        sys.exit()
    try:
        print("id" + "\t" + "title" + "\t" + "login" + "\t" + "URL")
        print("-"*42)
        for passw in vault["data"]:
            print(str(passw["id"]) + "\t" + passw["title"]
             + "\t" + passw["login"] + "\t" + passw["URL"])
    except KeyError:
        print("Vault format error !",file=sys.stderr)
    sys.exit()

#Read password from vault by it's id
def read_password(filename,id):
    key = getpass("Please enter key: ")
    vault = check_vault(filename,key)
    if len(vault["data"]) == 0:
        print("Vault empty !")
        sys.exit()
    try:
        print("le password est " + vault['data'][id]["password"])
        sys.exit()
    except KeyError:
        sys.exit()
    except IndexError:
        print("Unknown ID",file=sys.stderr)
        sys.exit()

#Creates a vault from a given file
def create_vault(outputfile):
    data = json.dumps({
        "data":[]
    })
    key = getpass("Please choose your 16 chars key, it'll be your vault password: ")
    if len(key) != 16:
        print("Wrong key size !",file=sys.stderr)
        sys.exit()
    encrypt_file(data,outputfile,key)
    print("Vault successfully created !")
    sys.exit()

#Add password to the vault
def add_password(filename):
    key = getpass("Please enter your 16 chars key: ")
    vault = check_vault(filename,key)
    title = input("Title: ")
    print("just enter if you want a randomly created password")
    password = getpass("Password: ")
    login = input("Login: ")
    url = input("URL: ")
    if len(password) == 0:
        password = generate_password()
    if len(password) > 100:
        print("Password too long",file=sys.stderr)
        sys.exit()
    if len(title) < 1 or len(password) < 1 or len(login) < 1 or len(url) < 1:
        print("Some arguments are wrong",file=sys.stderr)
        sys.exit()
    id = len(vault["data"])
    entry = {
        "id":id,
        "title":title,
        "password":password,
        "login":login,
        "URL":url
    }
    vault["data"].append(entry)
    vault = json.dumps(vault)
    encrypt_file(vault,filename,key)
    print("Entry successfully added !")
    sys.exit()

#Removes password from a vault
def remove_password(filename,id):
    key = getpass("Please enter key: ")
    vault = check_vault(filename,key)
    try:
        del vault["data"][id]
        for i in vault["data"]:
            if i["id"]>=id:
                i["id"] = i["id"]-1




    except IndexError:
        print("Unknown ID",file=sys.stderr)
        sys.exit()
    vault = json.dumps(vault)
    encrypt_file(vault,filename,key)
    print("Entry successfully removed !")
    sys.exit()

#Main function
def main(argv,argc):
    try:
        opts, args = getopt.getopt(argv[1:],'hf:o:i:',[])
    except getopt.GetoptError:
        print("Bad usage see help -h",file=sys.stderr)
        sys.exit()
    for opt,arg in opts:
        if opt in '-h':
            print_help()
            sys.exit()
        if opt in '-f':
            if not os.path.isfile(arg):
                print("File not found",file=sys.stderr)
                sys.exit()
            f=arg
        if opt in '-i':
            try:
                i=int(arg)
            except ValueError:
                print("-i not an integer",file=sys.stderr)
                sys.exit()
        if opt in '-o':
            if os.path.isfile(arg):
                while 1:
                    c = input("File already exists do you want to overwrite it ? (y/n)")
                    if c == "y":
                        o=arg
                        break
                    elif c == "n":
                        sys.exit()
                    else:
                        print("Please choose y or n")
            else:
                o=arg
    print("2pass v0.1 (17-10-2020)")
    if len(args) < 1:
        print("Please enter a command, see -h",file=sys.stderr)
        sys.exit()
    if len(args) > 1:
        print("Too much commands, see -h",file=sys.stderr)
        sys.exit()
    if args[0] in COMMANDS:
        if args[0] == "ls" and ('f' in locals()):
            if 'i' not in locals():
                read_vault(f)
                sys.exit()
            else:
                read_password(f,i)
                sys.exit()
        if args[0] == "add" and ('f' in locals()):
            add_password(f)
            sys.exit()
        if args[0] == "rm" and ('f' in locals()) and ('i' in locals()):
            remove_password(f,i)
            sys.exit()
        if args[0] == "create" and ('o' in locals()):
            create_vault(o)
            sys.exit()
    print("Not a command or wrong arguments, see help -h",file=sys.stderr)
    sys.exit()

if __name__ == "__main__" :
    main(sys.argv, len(sys.argv))
