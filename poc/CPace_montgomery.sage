import sys

########## Definitions from RFC 7748 ##################
from sagelib.RFC7748_X448_X25519 import *

from sagelib.CPace_string_utils import *

from sagelib.CPace_hashing import *

class G_Montgomery:
    """Here we have common definitions for the X448 and X25519"""
    def sample_scalar(self, deterministic_scalar_for_test_vectors = "False"):
        if deterministic_scalar_for_test_vectors == "False":
            return random_bytes(self.field_size_bytes)
        else:
            H = H_SHA512()
            value = H.hash(deterministic_scalar_for_test_vectors)
            return value[0:self.field_size_bytes]

    def decodeLittleEndian(self, b):
        bits = self.field_size_bits
        num_bytes = floor((bits+7)/8)
        return sum([b[i] << 8*i for i in range(num_bytes)])

    def decodeUCoordinate(self, u):        
        u_list = [b for b in u]
        # Ignore any unused bits.
        if self.field_size_bits % 8:
            u_list[-1] &= (1<<(self.field_size_bits%8))-1
        return self.decodeLittleEndian(u_list)

    def encodeUCoordinate(self,u):
        u = u % self.q
        return IntegerToByteArray(u,self.field_size_bytes)
    
    def find_z_ell2(self,F):
        """ Argument: F, a field object, e.g., F = GF(2^255 - 19) """
        ctr = F.gen()
        while True:
            for Z_cand in (F(ctr), F(-ctr)):
                # Z must be a non-square in F.
                if is_square(Z_cand):
                    continue
                return Z_cand
            ctr += 1
        
    def elligator2(self,r):
        q = self.q
        Fq = GF(q)
        A = Fq(self.A)
        B = Fq(1)
    
        # calculate the appropriate non-square as specified in the hash2curve draft.
        u = Fq(self.find_z_ell2(Fq))
        powerForChi = floor((q-1)/2)
    
        v = - A / (1 + u * r^2)
        epsilon = (v^3 + A * v^2 + B * v)^powerForChi
        x = epsilon * v - (1 - epsilon) * A/2
        return self.encodeUCoordinate(Integer(x))

    def calculate_generator(self, H, PRS, CI, sid, print_test_vector_info = False, file = sys.stdout):
        (gen_string, len_zpad) = generator_string(PRS, self.DSI,CI,sid,H.s_in_bytes)
        string_hash = H.hash(gen_string, self.field_size_bytes)
        u = self.decodeUCoordinate(string_hash)
        result = self.elligator2(u)
        if print_test_vector_info:
            print ("\n###  Test vectors for calculate_generator with group "+self.name+"\n",file=file)
            print ("~~~", file=file)

            print ("  Inputs", file=file)
            print ("    H   =", H.name, "with input block size", H.s_in_bytes, "bytes.", file=file)
            print ("    PRS =", PRS, "; ZPAD length:", len_zpad,"; DSI =", self.DSI, file=file)
            print ("    CI =", CI, file=file)
            print ("    CI =", ByteArrayToLEPrintString(CI), file=file)
            print ("    sid =", ByteArrayToLEPrintString(sid), file=file)
            print ("  Outputs",file=file)
            tv_output_byte_array(string_hash, test_vector_name = "hash generator string", 
                                 line_prefix = "    ", max_len = 60, file=file)
            tv_output_byte_array(IntegerToByteArray(u), test_vector_name = "decoded field element of %i bits" % self.field_size_bits, 
                                 line_prefix = "    ", max_len = 60, file=file)
            tv_output_byte_array(result, test_vector_name = "generator g", 
                                 line_prefix = "    ", max_len = 60, file=file)
            print ("~~~", file=file)
        return result

    
class G_X25519(G_Montgomery):
    def __init__(self):
        self.I = zero_bytes(32)
        self.field_size_bytes = 32
        self.field_size_bits = 255
        self.DSI = b"CPace255"
        self.DSI_ISK = b"CPace255_ISK"
        self.name = "X25519" # group name
        self.encoding_of_scalar = "little endian"
        
        # curve definitions
        self.q = 2^255 - 19
        self.A = 486662
        
    def scalar_mult(self,scalar,point):
        return X25519(scalar,point)

    def scalar_mult_vfy(self,scalar,point):
        return X25519(scalar,point)


class G_X448(G_Montgomery):
    def __init__(self):
        self.I = zero_bytes(56)
        self.field_size_bytes = 56
        self.field_size_bits = 448
        self.DSI = b"CPace448"
        self.DSI_ISK = b"CPace448_ISK"
        self.name = "X448" # group name
        self.encoding_of_scalar = "little endian"
        
        # curve definitions
        self.q = 2^448 - 2^224 - 1
        self.A = 156326
        
    def scalar_mult(self,scalar,point):
        return X448(scalar,point) # yet no definition for X448 in this script file

    def scalar_mult_vfy(self,scalar,point):
        return X448(scalar,point) # yet no definition for X448 in this script file

