import time
from SDES import *
from bitstring import BitArray, BitStream
import pickle

"""
    Notes from StackExchange
    https://security.stackexchange.com/questions/122624/how-does-the-meet-in-the-middle-attack-work-on-double-des


    Encrypt the plaintext with all 2**10 possible keys and write down the results
    Decrypt the ciphertext with all 2*10 possible keys and write down the results
    Check where the results are the same. That is your key.

    Assume that you are a cryptanalyst who has access to the plain text and encrypted text. Your aim 
    is to recover the secret key. Assume AAA (plaintext) -> XXX (After 1st encryption) -> ZZZ 
    (after 2nd encryption).

    You start with AAA and try all the 2**10 combinations for secret key by encrypting AAA. 
    This will give you a big list of possible values for XXX. Next you take ZZZ and try all the 
    2*10 combinations for secret key by decrypting ZZZ. This will give you a big list of possible 
    values for XXX.

"""


def meet_in_the_middle_attack(plaintext_ciphertext):
    start_time = time.time()

    #Arrays will hold enc and dec values for plaintext="0x42" ciphertext="0x11"
    encrypting_values = []
    decrypting_values = []

    possible_keys = [] #Will hold all key pairs where value of partial cipher is the same

    #plaintext="0x42" ciphertext="0x11"
    plaintext = plaintext_ciphertext[0][0]
    ciphertext = plaintext_ciphertext[0][1]

    #Iterating over all possible Keys
    for i in range(2**10):
        test_key1 = BitArray(uint=i,length=10)

        #DES encrpyt for plaintext, decrypt for ciphertext
        output1 = S_DES(plaintext,test_key1,decrpyt=False)
        output2 = S_DES(ciphertext,test_key1,decrpyt=True)

        encrypting_values.append(output1.bin)
        decrypting_values.append(output2.bin)


    #Finding all key pairs that result in the same partial cipher
    for i in range(len(encrypting_values)):
        print(i)
        for j in range(len(decrypting_values)):
            if encrypting_values[i] == decrypting_values[j]:
                possible_keys.append((i,j))

    #pickling incase of crash
    pickle.dump(possible_keys, open( "possible_keys_middle.p", "wb"))

    #Iterating over all PT-CT pairs to find pair used to encrypt all PT-CT pairs
    true_keys = {}
    for PC_pair in plaintext_ciphertext:
        plaintext = PC_pair[0]
        ciphertext = PC_pair[1]
        for pair in possible_keys:
            if S_DES(plaintext,BitArray(uint=pair[0],length=10),decrpyt=False) == S_DES(ciphertext,BitArray(uint=pair[1],length=10),decrpyt=True):
                if pair in true_keys:
                    true_keys[pair] += 1
                else:
                    true_keys[pair] = 1


    #Sorting true keys -- pair with value of 5 will be key that works for all PT-CT pairs -- true key
    true_keys = dict(sorted(true_keys.items(), key=lambda item: item[1]))


    pickle.dump(true_keys, open( "true_keys_middle.p", "wb"))


    total_time = time.time() - start_time
    pickle.dump(total_time, open( "total_time_middle.p", "wb"))
    
    return total_time


## MAIN
## Code outside of meet_in_the_middle_attack function
plaintext_ciphertext = [[BitArray("0x42"),BitArray("0x11")], [BitArray("0x72"),BitArray("0x6d")], 
                        [BitArray("0x75"),BitArray("0xfa")], [BitArray("0x74"),BitArray("0xa9")], 
                        [BitArray("0x65"),BitArray("0x34")]]

total_time = meet_in_the_middle_attack(plaintext_ciphertext)

print(total_time)