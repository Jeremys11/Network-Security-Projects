import time
from SDES import *
from bitstring import BitArray, BitStream
import pickle

"""

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

start_time = time.time()
def meet_in_the_middle_attack(plaintext_ciphertext):
    encrypting_keys = []
    decrypting_keys = []

    true_keys = []

    for pair in plaintext_ciphertext:
        plaintext = pair[0]
        ciphertext = pair[1]
        for i in range(2**10):
            test_key1 = BitArray(uint=i,length=10)
            output1 = S_DES(plaintext,test_key1,decrpyt=False)
            output2 = S_DES(ciphertext,test_key1,decrpyt=True)
            encrypting_keys.append(output1.bin)
            decrypting_keys.append(output2.bin)

        both = set(encrypting_keys).intersection(decrypting_keys)

        indices_A = [encrypting_keys.index(x) for x in both]
        indices_B = [decrypting_keys.index(x) for x in both]

        both2 = {}
        for i in range(len(indices_A)):
            both2[indices_A[i]] = indices_B[i]

        true_keys.append(both2)
    pickle.dump(true_keys, open( "true_keys_middle.p", "wb"))


    total_time = time.time() - start_time
    pickle.dump(total_time, open( "total_time_middle.p", "wb"))
    
    return total_time


plaintext_ciphertext = [[BitArray("0x42"),BitArray("0x11")], [BitArray("0x72"),BitArray("0x6d")], 
                        [BitArray("0x75"),BitArray("0xfa")], [BitArray("0x74"),BitArray("0xa9")], 
                        [BitArray("0x65"),BitArray("0x34")]]

total_time = meet_in_the_middle_attack(plaintext_ciphertext)

print(total_time)