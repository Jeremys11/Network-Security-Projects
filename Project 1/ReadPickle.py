import pickle
import time
from bitstring import BitArray, BitStream

true_keys = pickle.load( open( "true_keys.p", "rb" ) )

print(true_keys)

possible_keys = pickle.load( open( "possible_keys.p", "rb" ) )

#print(possible_keys)