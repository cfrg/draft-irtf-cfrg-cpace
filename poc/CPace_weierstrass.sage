import sys

from sagelib.CPace_string_utils import *

from sagelib.CPace_hashing import *

import binascii
import random
import hashlib
import sys

sys.path.append("sagelib")
from sagelib.hash_to_field import I2OSP, OS2IP
from sagelib.suite_p256 import *
from sagelib.suite_p384 import *
from sagelib.suite_p521 import *

# Definitions for Short-Weierstrass-Curves

class G_ShortWeierstrass():
    def __init__(self, mapping_primitive_generator): 

        # we first generate a dummy map object for deriving the curve and the
        # suite name strings.
        #     
        map_with_dummy_dst = mapping_primitive_generator(b"dummy")
        
        self.curve = map_with_dummy_dst("some arbitrary string").curve();
        
        self.field = self.curve.base_field();
        self.q = self.field.order()
        self.field_size_bytes = ceil(log(float(self.q),2) / 8)
        self.p = self.curve.order();
        self.name = map_with_dummy_dst.curve_name
        
        if not (self.p.is_prime()):
            raise ValueError ("Group order for Short-Weierstrass must be prime")

        self.I = b"" # Represent the neutral element as the empty string.

        self.DSI = b"CPace" + map_with_dummy_dst.suite_name.encode("ascii")
        self.DSI_ISK = self.DSI + b"_ISK"
        self.encoding_of_scalar = "big endian"
        self.DST = self.DSI + b"_DST"
        
        self.map = mapping_primitive_generator(self.DST)

      
    def sample_scalar(self, deterministic_scalar_for_test_vectors = "False"):
        random_bytes_len =  self.field_size_bytes * 2
        if deterministic_scalar_for_test_vectors == "False":
            string = random_bytes(random_bytes_len)
        else:
            H = H_SHAKE256()
            string = H.hash(deterministic_scalar_for_test_vectors, random_bytes_len)
        scalar = ByteArrayToInteger(string, random_bytes_len)
        scalar = scalar % self.p
        return I2OSP(scalar,self.field_size_bytes)
    
    def point_to_octets(self,point):
        if point == (point * 0):
            return b"\00" # Neutral element.
    
        x,y = point.xy()
        return b"\04" + I2OSP(x,self.field_size_bytes) + I2OSP(y,self.field_size_bytes)

    def octets_to_point(self,octets):
        if (octets[0] == 0) and (len(octets) == 1):
            point = self.curve.gens()[0]
            return point * 0 # neutral element.
        
        if not octets[0] == 4:
            raise ValueError("Only uncompressed format supported.")
           
        if not (len(octets) == 1 + self.field_size_bytes * 2):
            raise ValueError("Wrong length of field")
        
        xstr = octets[1:(self.field_size_bytes+1)]
        ystr = octets[(self.field_size_bytes+1):]
        return self.curve(OS2IP(xstr),OS2IP(ystr))
        
    def scalar_pow(self,scalar_octets,point_octets):
        point = self.octets_to_point(point_octets)        
        scalar = OS2IP(scalar_octets)
        return self.point_to_octets(point * scalar)

    def scalar_pow_negated_result(self,scalar_octets,point_octets):
        point = self.octets_to_point(point_octets)        
        scalar = OS2IP(scalar_octets)
        return self.point_to_octets(-point * scalar)

    def scalar_pow_vfy(self,scalar_octets,point_octets):
        scalar = OS2IP(scalar_octets)
        try:
            point = self.octets_to_point(point_octets)
        except:
            # Incorrect format or point is not on curve
            return self.I
        
        result_point = point * scalar
               
        if result_point == point * 0:
            return self.I
        else:
            x,y = result_point.xy()
            return I2OSP(x,self.field_size_bytes)
        
    def calculate_generator(self, H, PRS, CI, sid, print_test_vector_info = False, file = sys.stdout ):
        (gen_string, len_zpad) = generator_string(self.DSI, PRS, CI, sid, H.s_in_bytes)
        result = self.map(gen_string)
        if print_test_vector_info:
            print ("\n###  Test vectors for calculate\\_generator with group "+self.name+"\n", file =file)
            print ("~~~", file = file)
            print ("  Inputs", file = file)
            print ("    H   =", H.name, "with input block size", H.s_in_bytes, "bytes.", file = file)
            print ("    PRS =", PRS, "; ZPAD length:", len_zpad,";",file = file);
            print ("    DSI =", self.DSI, file = file)
            print ("    DST =", self.DST, file = file)
            print ("    CI =", CI, file = file)
            print ("    CI =", ByteArrayToLEPrintString(CI), file = file)
            print ("    sid =", ByteArrayToLEPrintString(sid), file = file)
            print ("  Outputs", file = file)
            tv_output_byte_array(gen_string, test_vector_name = "generator_string(PRS,G.DSI,CI,sid,H.s_in_bytes)", 
                                 line_prefix = "    ", max_len = 60, file = file)
            tv_output_byte_array(self.point_to_octets(result), test_vector_name = "generator g", 
                                 line_prefix = "    ", max_len = 60,file = file)
            print ("~~~", file = file)
        return self.point_to_octets(result)

def output_weierstrass_invalid_point_test_cases(G, file = sys.stdout):
    X = G.calculate_generator( H_SHA256(), b"Password", b"CI", b"sid")
    y = G.sample_scalar(deterministic_scalar_for_test_vectors= b"yes we want it")
    K = G.scalar_pow_vfy(y,X)
    Z = G.scalar_pow(y,X)
    print ("\n### Test case for scalar\\_mult\\_vfy with correct inputs\n", file = file)
    print ("\n~~~", file = file)
    tv_output_byte_array(y, test_vector_name = "s", 
                         line_prefix = "    ", max_len = 60, file = file)
    tv_output_byte_array(X, test_vector_name = "X", 
                         line_prefix = "    ", max_len = 60, file = file)
    tv_output_byte_array(Z, test_vector_name = "G.scalar_pow(s,X) (full coordinates)", 
                         line_prefix = "    ", max_len = 60, file = file)
    tv_output_byte_array(K, test_vector_name = "G.scalar_pow_vfy(s,X) (only X-coordinate)", 
                         line_prefix = "    ", max_len = 60, file = file)
    print ("~~~\n", file = file)
    
    Y_inv1 = bytearray(X)
    Y_inv1[-1] = (Y_inv1[-2] - 1) % 256 # choose an incorrect y-coordinate
    K_inv1 = G.scalar_pow_vfy(y,Y_inv1)
    Y_inv2 = b"\0"
    K_inv2 = G.scalar_pow_vfy(y,Y_inv2)
       
    print ("\n### Invalid inputs for scalar\\_mult\\_vfy\n", file = file)
    print ("For these test cases scalar\\_mult\\_vfy(y,.) MUST return the representation"+
           " of the neutral element G.I. When including Y\\_i1 or Y\\_i2 in MSGa or MSGb the protocol MUST abort.\n", file = file)
    print ("\n~~~", file = file)
    tv_output_byte_array(y, test_vector_name = "s", 
                         line_prefix = "    ", max_len = 60, file = file)
    tv_output_byte_array(Y_inv1, test_vector_name = "Y_i1", 
                         line_prefix = "    ", max_len = 60, file = file)   
    tv_output_byte_array(Y_inv2, test_vector_name = "Y_i2", 
                         line_prefix = "    ", max_len = 60, file = file)
    print ("    G.scalar_pow_vfy(s,Y_i1) = G.scalar_pow_vfy(s,Y_i2) = G.I", file = file)
    print ("~~~\n", file = file)    
    
    	    	
def cpace_map_for_nist_p256(dst):
    suite_name = "P256_XMD:SHA-256_SSWU_NU_"
    is_ro = False
    
    p = 2^256 - 2^224 + 2^192 + 2^96 - 1
    F = GF(p)
    A = F(-3)
    B = F(0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b)

    k = 128
    expander = XMDExpander(dst, hashlib.sha256, k)
    suite_def = BasicH2CSuiteDef("NIST P-256", F, A, B, expander, hashlib.sha256, 48, GenericSSWU, 1, k, is_ro, dst)

    return BasicH2CSuite(suite_name,suite_def)

def cpace_map_for_nist_p384(dst):
    suite_name = "P384_XMD:SHA-384_SSWU_NU_"
    is_ro = False
    
    p = 2^384 - 2^128 - 2^96 + 2^32 - 1
    F = GF(p)
    A = F(-3)
    B = F(0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef)

    k = 192
    expander = XMDExpander(dst, hashlib.sha384, k)
    suite_def = BasicH2CSuiteDef("NIST P-384", F, A, B, expander, hashlib.sha384, 72, GenericSSWU, 1, k, is_ro, dst)

    return BasicH2CSuite(suite_name,suite_def)

def cpace_map_for_nist_p521(dst):
    suite_name = "P521_XMD:SHA-512_SSWU_NU_"
    is_ro = False
    
    p = 2^521 - 1
    F = GF(p)
    A = F(-3)
    B =  F(0x51953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00)

    k = 256
    expander = XMDExpander(dst, hashlib.sha512, k)
    suite_def = BasicH2CSuiteDef("NIST P-521", F, A, B, expander, hashlib.sha512, 98, GenericSSWU, 1, k, is_ro, dst)

    return BasicH2CSuite(suite_name,suite_def)

    
if __name__ == "__main__":
    print ("Checking correct implementation of the encode_to_curve map for P256:\n");

    dst_p256_for_hash2curve_testvectors = b"QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_NU_"

    print ("Results for P256 from the hash2curve sample code:");
    point = p256_sswu_nu(b"");
    x,y = point.xy()
    tv_output_byte_array(I2OSP(x,32), test_vector_name = "X_b''", max_len = 60) 
    tv_output_byte_array(I2OSP(y,32), test_vector_name = "Y_b''", max_len = 60)

    print ("Our results for P256 when using the hash to curve dummy dst\n'%s':" % dst_p256_for_hash2curve_testvectors)
    test_p256_map = cpace_map_for_nist_p256(dst_p256_for_hash2curve_testvectors)
    print ("Checking correct implementation of the encode_to_curve map for P256\nif we use the DST from the hash2curve test vectors:");
    point2 = test_p256_map(b"");
    x2,y2 = point2.xy()
    tv_output_byte_array(I2OSP(x2,32), test_vector_name = "X2_b''", max_len = 60) 
    tv_output_byte_array(I2OSP(y2,32), test_vector_name = "Y2_b''", max_len = 60)

    print ("Our results for P256 when using the hash to curve dst 'dummy'")
    test_p256_map = cpace_map_for_nist_p256(b"dummy")
    print ("Checking correct implementation of the encode_to_curve map for P256\nif we use DST == 'dummy':");
    point3 = test_p256_map(b"");
    x3,y3 = point3.xy()
    tv_output_byte_array(I2OSP(x3,32), test_vector_name = "X3_b''", max_len = 60) 
    tv_output_byte_array(I2OSP(y3,32), test_vector_name = "Y3_b''", max_len = 60)

    assert x2 == x
    assert y2 == y

    assert x3 != x
    assert y3 != y



    print ("####\n" * 3)
    print ("Checking correct implementation of the encode_to_curve map for P384:\n");

    dst_p384_for_hash2curve_testvectors = b"QUUX-V01-CS02-with-P384_XMD:SHA-384_SSWU_NU_"

    print ("Results for P384 from the hash2curve sample code:");
    point = p384_sswu_nu(b"");
    x,y = point.xy()
    tv_output_byte_array(I2OSP(x,48), test_vector_name = "X_b''", max_len = 60) 
    tv_output_byte_array(I2OSP(y,48), test_vector_name = "Y_b''", max_len = 60)

    print ("Our results for P384 when using the hash to curve dummy dst\n'%s':" % dst_p384_for_hash2curve_testvectors)
    test_p384_map = cpace_map_for_nist_p384(dst_p384_for_hash2curve_testvectors)
    print ("Checking correct implementation of the encode_to_curve map for P384\nif we use the DST from the hash2curve test vectors:");
    point2 = test_p384_map(b"");
    x2,y2 = point2.xy()
    tv_output_byte_array(I2OSP(x2,48), test_vector_name = "X2_b''", max_len = 60) 
    tv_output_byte_array(I2OSP(y2,48), test_vector_name = "Y2_b''", max_len = 60)

    print ("Our results for P384 when using the hash to curve dst 'dummy'")
    test_p384_map = cpace_map_for_nist_p384(b"dummy")
    print ("Checking correct implementation of the encode_to_curve map for P256\nif we use DST == 'dummy':");
    point3 = test_p384_map(b"");
    x3,y3 = point3.xy()
    tv_output_byte_array(I2OSP(x3,48), test_vector_name = "X3_b''", max_len = 60) 
    tv_output_byte_array(I2OSP(y3,48), test_vector_name = "Y3_b''", max_len = 60)

    assert x2 == x
    assert y2 == y

    assert x3 != x
    assert y3 != y


    print ("####\n" * 3)
    print ("Checking correct implementation of the encode_to_curve map for P521:\n");

    dst_p521_for_hash2curve_testvectors = b"QUUX-V01-CS02-with-P521_XMD:SHA-512_SSWU_NU_"

    print ("Results for P521 from the hash2curve sample code:");
    point = p521_sswu_nu(b"");
    x,y = point.xy()
    tv_output_byte_array(I2OSP(x,66), test_vector_name = "X_b''", max_len = 60) 
    tv_output_byte_array(I2OSP(y,66), test_vector_name = "Y_b''", max_len = 60)

    print ("Our results for P5212 when using the hash to curve dummy dst\n'%s':" % dst_p521_for_hash2curve_testvectors)
    test_p521_map = cpace_map_for_nist_p521(dst_p521_for_hash2curve_testvectors)
    print ("Checking correct implementation of the encode_to_curve map for P521\nif we use the DST from the hash2curve test vectors:");
    point2 = test_p521_map(b"");
    x2,y2 = point2.xy()
    tv_output_byte_array(I2OSP(x2,66), test_vector_name = "X2_b''", max_len = 60) 
    tv_output_byte_array(I2OSP(y2,66), test_vector_name = "Y2_b''", max_len = 60)

    print ("Our results for P521 when using the hash to curve dst 'dummy'")
    test_p521_map = cpace_map_for_nist_p521(b"dummy")
    print ("Checking correct implementation of the encode_to_curve map for P256\nif we use DST == 'dummy':");
    point3 = test_p521_map(b"");
    x3,y3 = point3.xy()
    tv_output_byte_array(I2OSP(x3,66), test_vector_name = "X3_b''", max_len = 60) 
    tv_output_byte_array(I2OSP(y3,66), test_vector_name = "Y3_b''", max_len = 60)

    assert x2 == x
    assert y2 == y

    assert x3 != x
    assert y3 != y


    G_P256 = G_ShortWeierstrass(cpace_map_for_nist_p256)
    output_weierstrass_invalid_point_test_cases(G_P256)

