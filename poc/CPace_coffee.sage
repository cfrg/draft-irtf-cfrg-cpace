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
        self.DSI = b"CPace" + self.name.encode("ascii")
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
            print ("    PRS =", PRS, "; ZPAD length:", len_zpad,"; DSI =", self.DSI, file = file)
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

