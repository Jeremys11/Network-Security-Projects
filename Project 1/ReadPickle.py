import pickle
import time
from bitstring import BitArray, BitStream
from SDES import *

#(746, 513) True Keys

def addOne(num):
    return num,num+1

numlist = [1,2,3,4,5,6,7]

table = dict([addOne(num) for num in numlist])

#print(table)


true_keys_middle = pickle.load( open( "true_keys_middle.p", "rb" ) )

print(true_keys_middle)

#testing_pairs = dict(set.intersection(*(set(d.items()) for d in true_keys_middle)))

plaintext_ciphertext = [[BitArray("0x42"),BitArray("0x11")], [BitArray("0x72"),BitArray("0x6d")], 
                        [BitArray("0x75"),BitArray("0xfa")], [BitArray("0x74"),BitArray("0xa9")], 
                        [BitArray("0x65"),BitArray("0x34")]]

"""plaintext_1 = plaintext_ciphertext[0][0]
ciphertext_1 = plaintext_ciphertext[0][1]

plaintext_2 = plaintext_ciphertext[1][0]
ciphertext_2 = plaintext_ciphertext[1][1]

plaintext_3 = plaintext_ciphertext[2][0]
ciphertext_3 = plaintext_ciphertext[2][1]

plaintext_4 = plaintext_ciphertext[3][0]
ciphertext_4 = plaintext_ciphertext[3][1]

plaintext_5 = plaintext_ciphertext[4][0]
ciphertext_5 = plaintext_ciphertext[4][1]

for testing_pairs in true_keys_middle:
    for pair in testing_pairs:
        output1a = S_DES(plaintext_1,BitArray(bin=pair,length=10),decrpyt=False)
        output1b = S_DES(output1a,BitArray(bin=testing_pairs[pair],length=10),decrpyt=False)

        output2a = S_DES(plaintext_2,BitArray(bin=pair,length=10),decrpyt=False)
        output2b = S_DES(output2a,BitArray(bin=testing_pairs[pair],length=10),decrpyt=False)

        output3a = S_DES(plaintext_3,BitArray(bin=pair,length=10),decrpyt=False)
        output3b = S_DES(output3a,BitArray(bin=testing_pairs[pair],length=10),decrpyt=False)

        output4a = S_DES(plaintext_4,BitArray(bin=pair,length=10),decrpyt=False)
        output4b = S_DES(output4a,BitArray(bin=testing_pairs[pair],length=10),decrpyt=False)

        output5a = S_DES(plaintext_5,BitArray(bin=pair,length=10),decrpyt=False)
        output5b = S_DES(output5a,BitArray(bin=testing_pairs[pair],length=10),decrpyt=False)


        if ((output1b == ciphertext_1) and (output2b == ciphertext_2) and (output3b == ciphertext_3) and (output4b == ciphertext_4) and (output5b == ciphertext_5)):
            print(pair)
            print(testing_pairs[pair])"""