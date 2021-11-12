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
    def __init__(self, mapping_primitive):        
        self.map = mapping_primitive
        self.curve = self.map("some arbitrary string").curve();
        
        self.field = self.curve.base_field();
        self.q = self.field.order()
        self.field_size_bytes = ceil(log(float(self.q),2) / 8)
        self.p = self.curve.order();
        self.name = mapping_primitive.curve_name
        
        if not (self.p.is_prime()):
            raise ValueError ("Group order for Short-Weierstrass must be prime")

        self.I = I2OSP(0,1) # Represent the neutral element as a single byte string "\00"

        self.DSI = b"CPace" + mapping_primitive.suite_name.encode("ascii")
        self.DSI_ISK = self.DSI + b"_ISK"
        self.encoding_of_scalar = "big endian"
      
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
        
    def scalar_mult(self,scalar_octets,point_octets):
        point = self.octets_to_point(point_octets)        
        scalar = OS2IP(scalar_octets)
        return self.point_to_octets(point * scalar)

    def scalar_mult_vfy(self,scalar_octets,point_octets):
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
        (gen_string, len_zpad) = generator_string(PRS, self.DSI,CI,sid,H.s_in_bytes)
        result = self.map(gen_string)
        if print_test_vector_info:
            print ("\n###  Test vectors for calculate_generator with group "+self.name+"\n", file =file)
            print ("~~~", file = file)
            print ("  Inputs", file = file)
            print ("    H   =", H.name, "with input block size", H.s_in_bytes, "bytes.", file = file)
            print ("    PRS =", PRS, "; ZPAD length:", len_zpad,";",file = file);
            print ("    DSI =", self.DSI, file = file)
            print ("    CI =", CI, file = file)
            print ("    CI =", ByteArrayToLEPrintString(CI), file = file)
            print ("    sid =", ByteArrayToLEPrintString(sid), file = file)
            print ("  Outputs", file = file)
            tv_output_byte_array(gen_string, test_vector_name = "string passed to map", 
                                 line_prefix = "    ", max_len = 60, file = file)
            tv_output_byte_array(self.point_to_octets(result), test_vector_name = "generator g", 
                                 line_prefix = "    ", max_len = 60,file = file)
            print ("~~~", file = file)
        return self.point_to_octets(result)