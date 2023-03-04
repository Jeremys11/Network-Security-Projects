from SDES import *
from MiddleAttack import meet_in_the_middle_attack
from BruteForce import brute_force
from BlockChaining import block_chaining
from WeakKeys import weak_keys

##  Testing SDES
##
def testing_sdes():

    #(746, 513) True Keys
    plaintext_ciphertext = [[BitArray("0x42"),BitArray("0x11")], [BitArray("0x72"),BitArray("0x6d")], 
                        [BitArray("0x75"),BitArray("0xfa")], [BitArray("0x74"),BitArray("0xa9")], 
                        [BitArray("0x65"),BitArray("0x34")]]

    for pair in plaintext_ciphertext:
        plaintext = pair[0]
        output = S_DES(plaintext,BitArray(uint=746,length=10),decrpyt=False)
        output2 = S_DES(output,BitArray(uint=513,length=10),decrpyt=False)
        print("plaintext: ",plaintext,"ciphertext: ", output2)


##  Testing MiddleAttack
##
def testing_middleattack():

    #(746, 513) True Keys
    plaintext_ciphertext = [[BitArray("0x42"),BitArray("0x11")], [BitArray("0x72"),BitArray("0x6d")], 
                        [BitArray("0x75"),BitArray("0xfa")], [BitArray("0x74"),BitArray("0xa9")], 
                        [BitArray("0x65"),BitArray("0x34")]]

    true_key, total_time = meet_in_the_middle_attack(plaintext_ciphertext)

    print("Meet-in-the-middle - Found Key Pair: ", true_key)
    print("Meet-in-the-middle - Total Time (seconds): ", total_time)

##  Testing Brute Force
##
def testing_bruteforce():


    #(746, 513) True Keys
    plaintext_ciphertext = [[BitArray("0x42"),BitArray("0x11")], [BitArray("0x72"),BitArray("0x6d")], 
                        [BitArray("0x75"),BitArray("0xfa")], [BitArray("0x74"),BitArray("0xa9")], 
                        [BitArray("0x65"),BitArray("0x34")]]

    true_key, total_time = brute_force(plaintext_ciphertext)

    print("Brute Force - Found Key Pair: ", true_key)
    print("Brute Force - Total Time (seconds): ", total_time)

##  Testing Blockchaining
##
def testing_blockchaining():

    decoded_message = block_chaining()
    print(decoded_message)

##  Testing WeakKeys
##
def testing_weakkeys():

    weak_keys = weak_keys()
    print(weak_keys)

##  MAIN
##  
if __name__ == "__main__":

    testing_sdes()
    print()
    testing_middleattack()
    print()
    testing_blockchaining()
    print()
    testing_bruteforce()
    print()
    testing_weakkeys