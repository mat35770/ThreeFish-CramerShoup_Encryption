#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import os
import hashlib
import random
import os
import re
import base64
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.number import inverse
from random import randint
from datetime import datetime
from time import time
from custom_md5 import md5

P = Q = A1 = A2 = X = Y = W = 0
HOME = r"C:\Users\Mathieu\OneDrive\Documents\UTT\GS15\Projet\ThreeFish-CramerShoup_Encryption_Delalande_Griech" #Répertoire où les clés seront stockées
DIR = ".cs_keys"
PUBKEY = "cs_pub"
PRIVKEY = "cs_priv"

def concat_bytes(tab_bytes):
    result = b''
    for word in tab_bytes:
        result = result + word
    return result

def byteFromHex(str):
    return bytearray.fromhex(str)

def H(b1, b2, c):
    return md5("".join([hex(i).replace("0x", "") for i in [b1, b2, c]]).encode('utf-8'))

def padRight(s, char, n):
    return ('{:' + char + '>' + str(n) + '}').format(s)

def base64Encode(str):
    b = base64.b64encode(bytes(str, encoding="utf8"))
    return "".join([chr(i) for i in b])

def base64Decode(str):
    b = base64.b64decode(bytes(str, encoding="utf8"))
    return "".join([chr(i) for i in b])

def rand(min,max):
    return randint(min,max)

def random_binaire(n):
    arr = ["1"]
    for i in range(1,n):
        arr.append(str(rand(0,1)))
    return int("".join(arr),2)

def strong_prime(bits):

    n = random_binaire(bits)
    while MillerRabinPrimalityTest(n) != True:
        n = random_binaire(bits)
    return n


def generate_two_prime(bits):
    
    q = strong_prime(bits)
    p = 2*q+1
    while MillerRabinPrimalityTest(p) != True:
        q = strong_prime(bits)
        p = 2*q+1
    return q, p

def find_generators(p, q):
    
    g = []
    start = time()
    while len(g) < 2:
        a = rand(2, p-2)
        if pow(a, 2, p) != 1 and pow(a, q, p) != 1 and (a not in g):
            g.append(a)
        if time()-start>3:
            break 
    return g

def MillerRabinPrimalityTest(number):
    

    #L'algorithme prend un nombre impair en entrée, donc on test d'abord l'exception pour le nombre 2

    if number == 2:
        return True
    elif number == 1 or number % 2 == 0:
        return False
    
    #On veut exprimer n comme : 2^s * r (r impair)
    
    # partie impaire du nombre
    oddPartOfNumber = number - 1
    
    # Le nombre de fois que le nombre est divisé par deux
    timesTwoDividNumber = 0
    
    # Tant que r est pair, diviser par deux pour trouver la partie impaire
    
    while oddPartOfNumber % 2 == 0:
        oddPartOfNumber = oddPartOfNumber // 2
        timesTwoDividNumber = timesTwoDividNumber + 1 
     
    
    # On en vérifie plusieurs afin d'éviter les cas de "strong liars"
  

    #Le terme "strong liar" désigne le cas où n est composite mais l'équation donne le même resultat que si il était premier.
    for time in range(3):
        
        #choix d'un "bon" nombre aléatoire
        while True:
            
            randomNumber = random.randint(2, number)-1
            if randomNumber != 0 and randomNumber != 1:
                break

        randomNumberWithPower = pow(randomNumber, oddPartOfNumber, number)
        
        #Si le nombre aléatoire n'est pas ni -1 (mod n)
        if (randomNumberWithPower != 1) and (randomNumberWithPower != number - 1):
            # nombre d'itérations
            iterationNumber = 1
         
            #Tant qu'on peut mettre le nombre au carré et que le résultat n'est pas -1 mod n
            while (iterationNumber <= timesTwoDividNumber - 1) and (randomNumberWithPower != number - 1):
                randomNumberWithPower = pow(randomNumberWithPower, 2, number)
                iterationNumber = iterationNumber + 1
           
            #Si x != -1 mod n, c'est parce qu'on n'a pas trouvé de témoins. ==> n est composite

            if (randomNumberWithPower != number - 1):
                return False
            
    # Le nombre a passé le test 
    return True


def generate_key(n):
    global P, Q, A1, A2, X, Y, W

    P, Q = generate_two_prime(n)
    g = find_generators(P, Q)
    A1, A2 = g

    x1, x2, y1, y2, w = [rand(0, P-1) for i in range(5)]

    X = (pow(A1, x1, P) * pow(A2, x2, P)) % P
    Y = (pow(A1, y1, P) * pow(A2, y2, P)) % P
    W = pow(A1, w, P)

    pubkey = (X, Y, W, A1, A2, P)
    privkey = (x1, x2, y1, y2, w, P)

    strPub = "{{}}".join([hex(i).replace("0x", "") for i in pubkey])
    strSct = "{{}}".join([hex(i).replace("0x", "") for i in privkey])

    os.chdir(HOME)
    if not os.path.isdir(DIR):
        os.mkdir(DIR)
    os.chdir(DIR)

    with open(PUBKEY, "w+") as f:
        f.write(base64Encode(strPub))

    with open(PRIVKEY, "w+") as f:
        f.write(base64Encode(strSct))



def encrypt_block(block):
    os.chdir(HOME)

    if os.path.isdir(DIR):
        os.chdir(DIR)
        if not os.path.exists(PRIVKEY):
            generate_key(256)
    else:
        generate_key(256)
    
    with open(PUBKEY, "r") as f:
        pubkey = re.split("{{}}", base64Decode(f.read()))
    

    X, Y, W, A1, A2, P = [int(i, 16) for i in pubkey]

    b = rand(0, P-1)
    B1 = pow(A1, b, P)
    B2 = pow(A2, b, P)
   
    bit_size = 256
    m = int.from_bytes(block, sys.byteorder)
    if m > P or len(block) * 8 >= bit_size:
        raise OverflowError('Le bloc est trop long')

    padded_block = pad(block, bit_size, 'iso7816')


    c = (pow(W, b, P) * int.from_bytes(padded_block, sys.byteorder)) % P 
    beta = int(H(B1, B2, c), 16)
    v = (pow(X, b, P)  * pow(Y, b * beta, P) ) % P
    
    # return everything to bytes
    b_B1 = B1.to_bytes(bit_size//8, sys.byteorder)
    b_B2 = B2.to_bytes(bit_size//8, sys.byteorder)
    b_c = c.to_bytes(bit_size//8, sys.byteorder)
    b_v = v.to_bytes(bit_size//8, sys.byteorder)

    return b_B1 + b_B2 + b_c + b_v

def decrypt_block(block):
    os.chdir(HOME)
    if os.path.isdir(DIR):
        os.chdir(DIR)
        if os.path.exists(PRIVKEY):
            with open(PRIVKEY, 'r') as f:
                privkey = re.split("{{}}", base64Decode(f.read()))
                x1, x2, y1, y2, w, P = [int(i, 16) for i in privkey]

                bit_size = 256
                byte_size = bit_size // 8

                if len(block) == 4*byte_size:
                    b_B1 = block[0:byte_size]
                    b_B2 = block[byte_size:2*byte_size]
                    b_c = block[2*byte_size:3*byte_size]
                    b_v = block[3*byte_size:4*byte_size]

                    B1 = int.from_bytes(b_B1, sys.byteorder)
                    B2 = int.from_bytes(b_B2, sys.byteorder)
                    c = int.from_bytes(b_c, sys.byteorder)
                    v = int.from_bytes(b_v, sys.byteorder)

                    beta = int(H(B1, B2, c), 16)
                    V = pow(B1, x1, P) * pow(B2, x2, P) * pow((pow(B1, y1, P) * pow(B2, y2, P)), beta, P) % P
                    if v == V :
                        m = (inverse(pow(B1, w, P), P) * c) % P
                        m = m.to_bytes(byte_size, sys.byteorder)
                        return unpad(m, byte_size, 'iso7816')
                    else:
                        print("La vérification a échoué")
        else:
            return ""
    else:
        return ""

def encrypt_file(fic, out):

    file_in = open(fic, 'rb')
    file_out = open(out, 'wb')
    file = bytes(file_in.read())
    block_size = 8
    padded_file = pad(file, block_size, style='iso7816')
    blocks = [padded_file[i*block_size:(i+1)*block_size] for i in range(len(padded_file)//block_size)]
    for block in blocks:
        crypted_block = encrypt_block(block)
        file_out.write(crypted_block)
    file_in.close()
    file_out.close()

def decrypt_file(fic, out):

    file_in = open(fic, 'rb')
    file_out = open(out, 'wb')
    file = bytes(file_in.read())
    block_size = 128
    blocks = [file[i*block_size:(i+1)*block_size] for i in range(len(file)//block_size)]
    for i in range(len(file)//block_size):
        blocks[i] = decrypt_block(blocks[i])
    out = concat_bytes(blocks)
    file_out.write(out)
    file_in.close()
    file_out.close()
