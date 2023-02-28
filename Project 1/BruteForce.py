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
        print(i)
        test_key1 = BitArray(uint=i,length=10)
        for j in range(2 ** 10):

            test_key2 = BitArray(uint=j, length=10)

            output1 = S_DES(plaintext,test_key1,decrpyt=False)
            output2 = S_DES(output1,test_key2,decrpyt=False)
            if output2 == ciphertext:
                possible_keys.append((test_key1.bin,test_key2.bin))

    half_time = time.time() - start_time
    pickle.dump(possible_keys, open( "possible_keys.p", "wb"))
    pickle.dump(half_time, open( "half_time.p", "wb"))

    true_keys = []
    plaintext = plaintext_ciphertext[2][0]
    ciphertext = plaintext_ciphertext[2][1]
    for key_pair in possible_keys:
        output1 = S_DES(plaintext,BitArray(bin=key_pair[0],length=10),decrpyt=False)
        output2 = S_DES(output1,BitArray(bin=key_pair[1],length=10),decrpyt=False)
        if output2 == ciphertext:
            true_keys.append((key_pair[0],key_pair[1]))


    total_time = time.time() - start_time
    pickle.dump(true_keys, open( "true_keys.p", "wb"))
    pickle.dump(total_time, open( "total_time.p", "wb"))


    return total_time,possible_keys

plaintext_ciphertext = [[BitArray("0x42"),BitArray("0x11")], [BitArray("0x72"),BitArray("0x6d")], 
                        [BitArray("0x75"),BitArray("0xfa")], [BitArray("0x74"),BitArray("0xa9")], 
                        [BitArray("0x65"),BitArray("0x34")]]

total_time, possible_keys = brute_force(plaintext_ciphertext)
print(total_time)
print(possible_keys)