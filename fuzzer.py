import random
import string
from subprocess import run, PIPE
import time
import sys
import os

def fuzzer(length=-1, max_length=100, char_start=32, char_range=32):
    if length == -1:
        string_length = random.randrange(0, max_length + 1)
    else:
        string_length = length
    out = ""
    for _ in range(0, string_length):
        out += random.choice(string.printable.replace('"',"").replace('/',""))
    return out.strip("\r\n")

print("===========Fuzzer 3000==============")
a,b,c,d,e=0,0,0,0,0
steps = 100
print("Testing...")
for _ in range(steps):
    devnull = open(os.devnull,"w")
    
    filename = "test_vaults/"+fuzzer(max_length=100, char_start=1, char_range=254)
    key = fuzzer(length=16, char_start=1, char_range=254)
    title = fuzzer(max_length=500, char_start=1, char_range=254)
    password = fuzzer(max_length=500, char_start=1, char_range=254)
    login = fuzzer(max_length=500, char_start=1, char_range=254)
    url = fuzzer(max_length=500, char_start=1, char_range=254)
    i = fuzzer(max_length=500, char_start=1, char_range=254)
    
    #Check create
    p = run(['python3', '2pass.py','-o',filename,'create'], stdout=devnull,input=key+'\n', encoding='ascii')
    if p.stderr != None:
        a+=1
        print(filename)
        print("create - "+p.stderr)
    time.sleep(0.5)
    
    #Check ls
    p = run(['python3', '2pass.py','-f',filename,'ls'], stdout=devnull,input=key+'\n', encoding='ascii')
    if p.stderr != None:
        b+=1
        print(filename)
        print("ls - "+p.stderr)
    time.sleep(0.5)
    
    #Check add
    p = run(['python3', '2pass.py','-f',filename,'add'], stdout=devnull,input=key+'\n'+title+'\n'+password+'\n'+login+'\n'+url+'\n', encoding='ascii')
    if p.stderr != None:
        c+=1
        print(filename)
        print("add - "+p.stderr)
    time.sleep(0.5)
    
    #Check add empty password
    p = run(['python3', '2pass.py','-f',filename,'add'], stdout=devnull,input=key+'\n'+title+'\n'+""+'\n'+login+'\n'+url+'\n', encoding='ascii')
    if p.stderr != None:
        d+=1
        print(filename)
        print("add empty pass- "+p.stderr)
    time.sleep(0.5)
    
    #Check ls -i
    p = run(['python3', '2pass.py','-f',filename,'-i',str(i),'ls'], stdout=devnull,input=key+'\n', encoding='ascii')
    if p.stderr != None:
        e+=1
        print(filename)
        print("ls i - "+p.stderr)
    time.sleep(0.5)
    
    #cleanup
    os.system("rm -f test_vaults/* 2> /dev/null")
    os.system("rm -f test_vaults/.* 2> /dev/null")
    
print("======Rapport========")
print("create : "+ str(a) + "/" + str(steps))
print("ls : "+ str(b) + "/" + str(steps))
print("add : "+ str(c) + "/" + str(steps))
print("add empty pass : "+ str(d) + "/" + str(steps))
print("ls -i : "+ str(e) + "/" + str(steps))