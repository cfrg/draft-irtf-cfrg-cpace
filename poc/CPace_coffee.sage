import sys
sys.path.append("sagelib")

from sagelib.CPace_string_utils import *

from sagelib.CPace_hashing import *

from sagelib.ristretto_decaf import *

# Definitions for Ristretto and Decaf

class G_CoffeeEcosystem():
    def __init__(self, coffee_point_class):
        self.point_class = coffee_point_class
        self.field = coffee_point_class.F
        self.q = coffee_point_class.P
        self.field_size_bytes = ceil(log(self.q,2) / 8)
        self.p = coffee_point_class.order
        self.name = coffee_point_class.name
        
        self.I = (coffee_point_class.map(H_SHAKE256().hash(b"1234",self.field_size_bytes * 2)) * 0).encode()
        self.DSI = b"CPace" + (self.name.title()).encode("ascii") # use .title() for capitalizing first letter.
        self.DSI_ISK = self.DSI + b"_ISK"
        self.encoding_of_scalar = "little endian"

    def sample_scalar(self, deterministic_scalar_for_test_vectors = "False"):
        if deterministic_scalar_for_test_vectors == "False":
            value = random_bytes(self.field_size_bytes)
        else:
            value = H_SHAKE256().hash(deterministic_scalar_for_test_vectors)
        
        value_int = ByteArrayToInteger(value, self.field_size_bytes)
        reduced_value = value_int % self.p
        result = IntegerToByteArray(reduced_value,self.field_size_bytes)        
        return result

    def scalar_mult(self,scalar,encoded_point):
        point = self.point_class.decode(encoded_point)
        scalar_as_int = ByteArrayToInteger(scalar, self.field_size_bytes);
        return (point * scalar_as_int).encode()

    def scalar_mult_vfy(self,scalar,encoded_point):
        scalar_as_int = ByteArrayToInteger(scalar, self.field_size_bytes);
        try:
            point = self.point_class.decode(encoded_point);
        except:
            # Decoding of point failed.
            return self.I
        return (point * scalar_as_int).encode()

    def calculate_generator(self, H, PRS, CI, sid, print_test_vector_info = False, file = sys.stdout):
        (gen_string, len_zpad) = generator_string(PRS, self.DSI,CI,sid,H.s_in_bytes)
        string_hash = H.hash(gen_string, self.field_size_bytes * 2)
        result = self.point_class.map(string_hash)
        if print_test_vector_info:
            print ("\n###  Test vectors for calculate_generator with group "+self.name+"\n", file = file)
            print ("~~~", file = file)
            print ("  Inputs", file = file)
            print ("    H   =", H.name, "with input block size", H.s_in_bytes, "bytes.", file = file)
            print ("    PRS =", PRS, "; ZPAD length:", len_zpad,";\n" +
                   "    DSI =", self.DSI, file = file)
            print ("    CI =", CI, file = file)
            print ("    CI =", ByteArrayToLEPrintString(CI), file = file)
            print ("    sid =", ByteArrayToLEPrintString(sid), file = file)
            print ("  Outputs", file = file)
            tv_output_byte_array(gen_string, test_vector_name = "hash generator string", 
                                 line_prefix = "    ", max_len = 60, file = file)
            tv_output_byte_array(string_hash, test_vector_name = "hash result", 
                                 line_prefix = "    ", max_len = 60, file = file)
            tv_output_byte_array(result.encode(), test_vector_name = "encoded generator g", 
                                 line_prefix = "    ", max_len = 60, file = file)
            print ("~~~\n", file = file)
        return result.encode()

def output_coffee_invalid_point_test_cases(G, file = sys.stdout):
    X = G.calculate_generator( H_SHAKE256(), b"Password", b"CI", b"sid")
    y = G.sample_scalar(deterministic_scalar_for_test_vectors= b"yes we want it")
    K = G.scalar_mult_vfy(y,X)
    Z = G.scalar_mult(y,X)
    print ("\n### Test case for scalar_mult with valid inputs\n", file = file)
    print ("~~~", file = file)
    tv_output_byte_array(y, test_vector_name = "s", 
                         line_prefix = "    ", max_len = 60, file = file)
    tv_output_byte_array(X, test_vector_name = "X", 
                         line_prefix = "    ", max_len = 60, file = file)
    tv_output_byte_array(Z, test_vector_name = "G.scalar_mult(s,decode(X))", 
                         line_prefix = "    ", max_len = 60, file = file)
    tv_output_byte_array(K, test_vector_name = "G.scalar_mult_vfy(s,X)", 
                         line_prefix = "    ", max_len = 60, file = file)
    print ("~~~\n", file = file)
    
    Y_inv1 = bytearray(X)
    for m in range(16*256):
        Y_inv1[m%16] = (Y_inv1[m%16] - 1) % 256 # choose an incorrect value    
        K_inv1 = G.scalar_mult_vfy(y,Y_inv1)
        if K_inv1 == G.I:
            break
                   
    print ("\n### Invalid inputs for scalar_mult_vfy which MUST result in aborts\n", file = file)
    print ("For these test cases scalar_mult_vfy(y,.) MUST return the representation"+
           " of the neutral element G.I. A G.I result from scalar_mult_vfy MUST make" +
           " the protocol abort!.", file = file)
    print ("~~~", file = file)
    tv_output_byte_array(y, test_vector_name = "s", 
                         line_prefix = "    ", max_len = 60, file = file)
    tv_output_byte_array(Y_inv1, test_vector_name = "Y_i1", 
                         line_prefix = "    ", max_len = 60, file = file)   
    tv_output_byte_array(G.I, test_vector_name = "G.I", 
                         line_prefix = "    ", max_len = 60, file = file)
    print ("    G.scalar_mult_vfy(s,Y_i1) = G.scalar_mult_vfy(s,G.I) = G.I", file = file)
    print ("~~~\n", file = file)    

if __name__ == "__main__":
    G = G_CoffeeEcosystem(Ed25519Point)
    output_coffee_invalid_point_test_cases(G)
