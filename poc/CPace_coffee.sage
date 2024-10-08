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

    def _derive_element(self, string_hash):
        P1 = self.point_class.map(string_hash[:self.field_size_bytes])
        P2 = self.point_class.map(string_hash[self.field_size_bytes:])
        result = P1 + P2
        return result
    	
    def calculate_generator(self, H, PRS, CI, sid, print_test_vector_info = False, file = sys.stdout):
        (gen_string, len_zpad) = generator_string(self.DSI, PRS, CI, sid, H.s_in_bytes)
        string_hash = H.hash(gen_string, self.field_size_bytes * 2)
        
        result = self._derive_element(string_hash)
        
        if print_test_vector_info:
            print ("\n###  Test vectors for calculate\\_generator with group "+self.name+"\n", file = file)
            print ("~~~", file = file)
            print ("  Inputs", file = file)
            print ("    H   =", H.name, "with input block size", H.s_in_bytes, "bytes.", file = file)
            print ("    PRS =", PRS, "; ZPAD length:", len_zpad,";\n" +
                   "    DSI =", self.DSI, file = file)
            print ("    CI =", CI, file = file)
            print ("    CI =", ByteArrayToLEPrintString(CI), file = file)
            print ("    sid =", ByteArrayToLEPrintString(sid), file = file)
            print ("  Outputs", file = file)
            tv_output_byte_array(gen_string, test_vector_name = "generator_string(G.DSI,PRS,CI,sid,H.s_in_bytes)", 
                                 line_prefix = "    ", max_len = 60, file = file)
            tv_output_byte_array(string_hash, test_vector_name = "hash result", 
                                 line_prefix = "    ", max_len = 60, file = file)
            tv_output_byte_array(result.encode(), test_vector_name = "encoded generator g", 
                                 line_prefix = "    ", max_len = 60, file = file)
            print ("~~~\n", file = file)

            result_dict = {}
            result_dict["H"] = H.name
            result_dict["H.s_in_bytes"] = int(H.s_in_bytes)
            result_dict["PRS"] = byte_string_to_json (PRS)
            result_dict["ZPAD length"] = int(len_zpad)
            result_dict["DSI"] = byte_string_to_json(self.DSI)
            result_dict["CI"] = byte_string_to_json(CI)
            result_dict["sid"] = byte_string_to_json(sid)
            result_dict["generator_string(G.DSI,PRS,CI,sid,H.s_in_bytes)"] = byte_string_to_json(gen_string)
            result_dict["hash result"] = byte_string_to_json(string_hash)
            result_dict["encoded generator g"] = byte_string_to_json(result.encode())
            
            print ("\n####  Testvectors as JSON file encoded as BASE64\n", file=file)
            tv_output_python_dictionary_as_json_base64(result_dict,file=file)

            
            
        return result.encode()

def output_coffee_invalid_point_test_cases(G, file = sys.stdout):
    result_dict = {}
    X = G.calculate_generator( H_SHAKE256(), b"Password", b"CI", b"sid")
    y = G.sample_scalar(deterministic_scalar_for_test_vectors= b"yes we want it")
    K = G.scalar_mult_vfy(y,X)
    Z = G.scalar_mult(y,X)
    print ("\n### Test case for scalar\\_mult with valid inputs\n", file = file)
    print ("\n~~~", file = file)
    tv_output_byte_array(y, test_vector_name = "s", 
                         line_prefix = "    ", max_len = 60, file = file)
    tv_output_byte_array(X, test_vector_name = "X", 
                         line_prefix = "    ", max_len = 60, file = file)
    tv_output_byte_array(Z, test_vector_name = "G.scalar_mult(s,decode(X))", 
                         line_prefix = "    ", max_len = 60, file = file)
    tv_output_byte_array(K, test_vector_name = "G.scalar_mult_vfy(s,X)", 
                         line_prefix = "    ", max_len = 60, file = file)
    print ("~~~\n", file = file)
    
    dict_valid = {}
    dict_valid["s"] = byte_string_to_json(y)
    dict_valid["X"] = byte_string_to_json(X)
    dict_valid["G.scalar_mult(s,decode(X))"] = byte_string_to_json(Z)
    dict_valid["G.scalar_mult_vfy(s,X)"] = byte_string_to_json(K)
    
    result_dict["Valid"] = dict_valid
    
    Y_inv1 = bytearray(X)
    for m in range(16*256):
        Y_inv1[m%16] = (Y_inv1[m%16] - 1) % 256 # choose an incorrect value    
        K_inv1 = G.scalar_mult_vfy(y,Y_inv1)
        if K_inv1 == G.I:
            break
                   
    print ("\n### Invalid inputs for scalar\\_mult\\_vfy\n", file = file)
    print ("For these test cases scalar\\_mult\\_vfy(y,.) MUST return the representation"+
           " of the neutral element G.I. When points Y\\_i1 or Y\\_i2 are included in message of A or B the protocol MUST abort.", file = file)
    print ("\n~~~", file = file)
    tv_output_byte_array(y, test_vector_name = "s", 
                         line_prefix = "    ", max_len = 60, file = file)
    tv_output_byte_array(Y_inv1, test_vector_name = "Y_i1", 
                         line_prefix = "    ", max_len = 60, file = file)   
    tv_output_byte_array(G.I, test_vector_name = "Y_i2 == G.I", 
                         line_prefix = "    ", max_len = 60, file = file)
    print ("    G.scalar_mult_vfy(s,Y_i1) = G.scalar_mult_vfy(s,Y_i2) = G.I", file = file)
    print ("~~~\n", file = file)    

    result_dict["Invalid Y1"] = byte_string_to_json(Y_inv1)
    result_dict["Invalid Y2"] = byte_string_to_json(G.I)
    
    print ("\n####  Testvectors as JSON file encoded as BASE64\n", file=file)
    tv_output_python_dictionary_as_json_base64(result_dict,file=file)


    return result_dict
       
if __name__ == "__main__":


    # Check implementation here against Ristretto255 draft.
    
    G = G_CoffeeEcosystem(Ed25519Point)
    
    testvector_in = bytearray.fromhex("5d1be09e3d0c82fc538112490e35701979d99e06ca3e2b5b54bffe8b4dc772c1" 
                                      + "4d98b696a1bbfb5ca32c436cc61c16563790306c79eaca7705668b47dffe5bb6")
    
    correct_result = bytearray.fromhex("3066f82a 1a747d45 120d1740 f1435853 1a8f04bb ffe6a819 f86dfe50 f44a0a46")
    
    out = G._derive_element(testvector_in)

    tv_output_byte_array(out.encode(), test_vector_name = "encoded result of ristretto255 test vector.", 
                         line_prefix = "    ", max_len = 60)

    tv_output_byte_array(correct_result, test_vector_name = "testvector from ristretto255 draft", 
                         line_prefix = "    ", max_len = 60)

    assert out.encode() == correct_result;
    


    # Check implementation here against Decaf448 draft.

    G = G_CoffeeEcosystem(Ed448GoldilocksPoint)
    
    testvector_in = bytearray.fromhex("cbb8c991fd2f0b7e1913462d6463e4fd2ce4ccdd28274dc2ca1f4165"
                                      + "d5ee6cdccea57be3416e166fd06718a31af45a2f8e987e301be59ae6"
                                      + "673e963001dbbda80df47014a21a26d6c7eb4ebe0312aa6fffb8d1b2"
                                      + "6bc62ca40ed51f8057a635a02c2b8c83f48fa6a2d70f58a1185902c0")
   
    correct_result = bytearray.fromhex("0c709c96 07dbb01c 94513358 745b7c23 953d03b3 3e39c723 4e268d1d"
                                       + "6e24f340 14ccbc22 16b965dd 231d5327 e591dc3c 0e8844cc fd568848")
                                       
    out = G._derive_element(testvector_in)

    tv_output_byte_array(out.encode(), test_vector_name = "encoded result of decaf448 test vector.", 
                         line_prefix = "    ", max_len = 60)

    tv_output_byte_array(correct_result, test_vector_name = "testvector from decaf448 draft", 
                         line_prefix = "    ", max_len = 60)

    assert out.encode() == correct_result;

    
    
    output_coffee_invalid_point_test_cases(G)
