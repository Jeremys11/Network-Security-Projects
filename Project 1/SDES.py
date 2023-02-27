from bitstring import BitArray, BitStream

SHIFT_COUNTER = [1,2,2,2,2]

##  Takes in 4bit input
##  Outputs 4 bit value by joining 2 2bit values
def s_boxes(text):

    #First and last bit = i ; Middle two bits = j
    S1_table = [[1,0,3,2], [3,2,1,0], [0,2,1,3], [3,1,3,2]]

    S2_table = [[0,1,2,3], [2,0,1,3], [3,0,1,0], [2,1,0,3]]

    # Getting the indexing values i and j to read S1 and S2 tables
    temp1 = BitArray(length=2)
    temp2 = BitArray(length=2)

    # Getting index i
    temp1[0] = text[0]
    temp1[1] = text[3]

    # Getting index j
    temp2[0] = text[1]
    temp2[1] = text[2]

    # S1 Table Read
    output1 = BitArray(length=2)
    output1 = BitArray(bin(S1_table[temp1.uint][temp2.uint]))

    # S2 Table Read
    output2 = BitArray(length=2)
    output2 = BitArray(bin(S2_table[temp1.uint][temp2.uint]))

    # Permuting the value after the SBoxes
    output = post_sbox_permutation(output1,output2)

    return output

##  Joins S1 and S2 and permutes the resulting bitstring
##  Returns 4bit value
def post_sbox_permutation(S1,S2):
    
    S_join = BitArray(S1+S2,length=4) #join S1 and S2 - len(4) specified to force 0x0 and 0x1 2 bits

    permutation_rule = {0:1, 1:3, 2:2, 3:0}

    permuted_text = BitArray(length=4)
    for i in range(len(permuted_text)):
        permuted_text[i] = S_join[permutation_rule[i]]

    return permuted_text

##  Input 4bit value R
##  Returns 8bit value
def expansion_function(R):
    permutation_rule= {0:3, 1:0, 2:1, 3:2, 4:1, 5:2, 6:3, 7:1}

    permuted_text = BitArray(length=8)
    for i in range(len(permuted_text)):
        permuted_text[i] = R[permutation_rule[i]]

    return permuted_text

##  Takes 4bit value R and 8bit value K
##  Returns 4bit value
def cipher_function(R,K):

    expandedR = expansion_function(R)

    preSBox = expandedR.__ixor__(
        K
    )

    output = s_boxes(preSBox)

    return output

##  Function for first permuted choice
##  Takes 10bit key and breaks it into 2 5-bit values C0 and D0
def permuted_choice1(key):
    permutation_rule_C = {0:8, 1:6, 2:1, 3:4, 4:5}
    permutation_rule_D = {0:0, 1:3, 2:9, 3:7, 4:2}

    permuted_textC = BitArray(length=5)
    for i in range(len(permuted_textC)):
        permuted_textC[i] = key[permutation_rule_C[i]]

    permuted_textD = BitArray(length=5)
    for i in range(len(permuted_textD)):
        permuted_textD[i] = key[permutation_rule_D[i]]

    return permuted_textC,permuted_textD

##  Function for permuted choices 2 - 4
##  Takes 10bit key and returns 8-bit value
def permuted_choice2(key):
    permutation_rule = {0:1,1:6,2:7,3:9,4:0,5:8,6:2,7:3}

    permuted_text = BitArray(length=8)
    for i in range(len(permuted_text)):
        permuted_text[i] = key[permutation_rule[i]]

    return permuted_text


##  Function for initial,inverse, and expansion permutations
##  Takes 8bit plaintext and returns 8bit value
##  As these all work on the plaintext and have the same bit size, I grouped them together
def permutation(text,permute):
    if permute == "initial":
        permutation_rule = {0:3, 1:0, 2:2, 3:4, 4:6, 5:1, 6:7, 7:5}
    elif permute == "inverse":
        permutation_rule = {0:1, 1:5, 2:2, 3:0, 4:3, 5:7, 6:3, 7:6}
    elif permute == "expansion":
        permutation_rule = {0:3, 1:0, 2:1, 3:2, 4:1, 5:2, 6:3, 7:0}
    else:
        permutation_rule = {0:3, 1:0, 2:1, 3:2, 4:1, 5:2, 6:3, 7:0} #Defaults to expansion rule

    permuted_text = BitArray(length=8)
    for i in range(len(text)):
        permuted_text[i] = text[permutation_rule[i]]
    
    return permuted_text
        
##  Takes in 2 4bit values L and R and 8bit value K
##  Returns 2 4bit values L and R
def plaintext_flowchart(L,R,K):

    R1 = L.__ixor__(
        cipher_function(R,K)
    )

    L1 = R
    return L1,R1

##  Takes in 2 5bit values C and D
##  Returns 2 5bit values C and D and 8bit value K
def key_flowchart(C,D,round_counter):

    K = permuted_choice2(C+D)

    #All left shifts after the first are by 2
    C.rol(2)
    D.rol(2)

    return C,D,K

##  Looping function
##  Takes in 8bit plaintext and 10bit key
##  Outputs 8bit ciphertext
def S_DES(plaintext,key,decrpyt):
    
    C,D = permuted_choice1(key)
    
    initial_permutation = permutation(plaintext,permute="initial")

    if decrpyt == True:
        L = initial_permutation[4:]
        R = initial_permutation[:4]        
    else:
        #Swap L and R for decryption
        L = initial_permutation[:4]
        R = initial_permutation[4:]  

    #Left shift 1 with wrap around
    #Only first left shift is by 1, the rest are by 2
    L.rol(1) 
    R.rol(1) 

    #Looping for both plaintext and key flowcharts
    #C,D,L,R Defined outside loop so they are not lost between loops
    for i in range(4):
        C,D,K = key_flowchart(C,D,round_counter)
        L,R = plaintext_flowchart(L,R,K)

    final_text = BitArray(L+R,length=8)
    inverse_permutation = permutation(final_text,permute="inverse")

    return inverse_permutation

##  MAIN
##  
if __name__ == "__main__":
    #plaintext_ciphertext = {"0x42":"0x11", "0x72":"0x6d", "0x75":"0xfa", "0x74":"0xa9", "0x65":"0x34"}
    #plaintext_key = {"0x42":"0x256"}
    plaintext_key = {"0x94":"0x256"}
    for plaintext in plaintext_key:
        output = S_DES(plaintext=BitStream(plaintext),key=BitStream(plaintext_key[plaintext]),decrpyt=True)
        print("output: ", output)

    #Double DES - Electronic Code Book Mode (ECB Mode)
    #plaintext = "0x42"
    #Keys = ["0x256","0x257"]
    #output1 = S_DES(BitStream(plaintext),BitStream(Keys[1]))
    #output2 = S_DES(BitStream(output1),BitStream(Keys[1]))
    #print(output)

    #