import time
from bitstring import BitArray, BitStream
from SDES import *
import pickle

#a brute force attack on DES requires a single plaintext/ciphertext pair

def brute_force(plaintext_ciphertext):
    start_time = time.time()
    possible_keys = []

    plaintext = plaintext_ciphertext[0][0]
    ciphertext = plaintext_ciphertext[0][1]


    for i in range(2 ** 10):
        #print(i)
        test_key1 = BitArray(uint=i,length=10)
        for j in range(2 ** 10):

            test_key2 = BitArray(uint=j, length=10)

            output1 = S_DES(plaintext,test_key1,decrpyt=False)
            output2 = S_DES(output1,test_key2,decrpyt=False)
            if output2 == ciphertext:
                possible_keys.append((test_key1.bin,test_key2.bin))

    half_time = time.time() - start_time
    #pickle.dump(possible_keys, open( "possible_keys_brute.p", "wb"))
    #pickle.dump(half_time, open( "half_time_brute.p", "wb"))

    #Iterating over all PT-CT pairs to find pair used to encrypt all PT-CT pairs
    true_keys = {}
    for PC_pair in plaintext_ciphertext:
        plaintext = PC_pair[0]
        ciphertext = PC_pair[1]
        for pair in possible_keys:
            if S_DES(plaintext,BitArray(bin=pair[0],length=10),decrpyt=False) == S_DES(ciphertext,BitArray(bin=pair[1],length=10),decrpyt=True):
                if pair in true_keys:
                    true_keys[pair] += 1
                else:
                    true_keys[pair] = 1

    #Sorting true keys -- pair with value of 5 will be key that works for all PT-CT pairs -- true key
    true_keys = dict(sorted(true_keys.items(), key=lambda item: item[1]))

    true_key = max(true_keys, key = true_keys.get)

    total_time = time.time() - start_time
    #pickle.dump(true_keys, open( "true_keys_brute.p", "wb"))
    #pickle.dump(total_time, open( "total_time_brute.p", "wb"))


    return true_key, total_time