from SDES import *

##  block_chaining
##
def block_chaining():
    #len = 632 -- 79 Blocks
    #0 - 631

    #(746, 513) True Keys -- Found from previous meet-in-the-middle attack
    true_key1 = BitArray(uint=746,length=10)
    true_key2 = BitArray(uint=513,length=10)
    
    #Supplied Bitstring in hex
    BigString = BitArray("0x7327313cf64670395a16ba52fca025a7e787f23277d1cbd70879359bcce1b08a269bf29d7b8fe109c81ec8ef9cf8a025a7e787f232bcda51b4888e8eceb7b27bd67f99cee11406638f744ea1cf4a12")
   
    IV = BitArray("0x6a") #Supplied IV

    decoded_message = [] #List will hold character of decoded chars

    next_cipher = BitArray(BigString[0:8])
    #Using range(79) since len(Bigstring) = 632, which subdivies into 79 8-bit parts
    for i in range(79):

        #Get 8-bit chunks from BigSting
        current_cipher = BitArray(BigString[i*8:(i+1)*8])

        #First pass uses IV, all other passes use previous ciphertext
        if(i == 0):
            output1 = S_DES(current_cipher,true_key2,decrpyt=True)
            output2 = S_DES(output1,true_key1,decrpyt=True)
            plaintext = output2 ^ IV
        else:
            output1 = S_DES(current_cipher,true_key2,decrpyt=True)
            output2 = S_DES(output1,true_key1,decrpyt=True)
            plaintext = output2 ^ next_cipher

        #Decoding message into ascii and setting next cipher to current cipher
        decoded_message.append(bytes.fromhex(plaintext.h).decode('ascii'))
        next_cipher = current_cipher

    #Merging list of characters into one string
    decoded_message = ''.join(decoded_message)

    return decoded_message
