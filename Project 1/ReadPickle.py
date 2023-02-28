import pickle
import time
from bitstring import BitArray, BitStream
from SDES import *

true_keys = pickle.load( open( "true_keys.p", "rb" ) )

print(true_keys)

#true_keys_middle = pickle.load( open( "true_keys_middle.p", "rb" ) )


#test = dict(set.intersection(*(set(d.items()) for d in true_keys_middle)))

#print(test[0])
