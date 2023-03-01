from bitstring import BitArray, BitStream
from SDES import *
import pickle


#E(E(x)) = x -- weak key
def weak_keys():
    true_weak_keys = []
    weak_keys = {}
    for i in range(2 ** 8):
        print(i)
        plaintext = BitArray(uint=i,length=8)
        for j in range(2 ** 10):
            key = BitArray(uint=j,length=10)

            if(plaintext == S_DES(S_DES(plaintext,key,decrpyt=False),key,decrpyt=False)):
                if key.bin not in weak_keys:
                    weak_keys[key.bin] = 1
                else:
                    weak_keys[key.bin] += 1

    #pickle.dump(weak_keys, open( "weak_keys.p", "wb"))

    weak_keys = dict(sorted(weak_keys.items(), key=lambda item: item[1]))
    for keys in weak_keys:
        if weak_keys[keys] == 256:
            true_weak_keys.append(keys)
    
    return true_weak_keys