import sys

########## Definitions from RFC 7748 ##################
from sagelib.RFC7748_X448_X25519 import *
from sagelib.CPace_string_utils import *
from sagelib.CPace_hashing import *
from sagelib.CPace_coffee import *
from sagelib.CPace_weierstrass import *
from sagelib.CPace_montgomery import *
from sagelib.test_vectors_X448_X25519 import *

def CPace_ISK(H, DSI,sid,K,MSGa,MSGb,doPrint = 1, symmetric_execution = False, file = sys.stdout):
    if symmetric_execution:
        concatenated_msg_transcript = oCAT(MSGa,MSGb)
        if doPrint:
            print ("\n###  Test vector for ISK calculation parallel execution\n", file=file)
            print ("~~~", file=file)
            tv_output_byte_array(concatenated_msg_transcript, test_vector_name = "ordered cat of transcript ", 
                         line_prefix = "    ", max_len = 60, file=file)
            cat_string = "oCAT(MSGa,MSGb)"
    else:
        concatenated_msg_transcript = MSGa + MSGb
        if doPrint:
            print ("\n###  Test vector for ISK calculation initiator/responder\n", file=file)
            print ("~~~", file=file)
            tv_output_byte_array(concatenated_msg_transcript, test_vector_name = "unordered cat of transcript ", 
                         line_prefix = "    ", max_len = 60, file=file)
            cat_string = "MSGa||MSGb"

    string = prefix_free_cat(DSI,sid,K) + concatenated_msg_transcript
    ISK = H.hash(string)
    if doPrint:
        tv_output_byte_array(DSI, test_vector_name = "DSI = G.DSI_ISK, " + str(DSI), 
                         line_prefix = "    ", max_len = 60, file=file)
        tv_output_byte_array(string, test_vector_name = "prefix_free_cat(DSI,sid,K)||" + cat_string, 
                         line_prefix = "    ", max_len = 60, file=file)
        tv_output_byte_array(ISK, test_vector_name = "ISK result", 
                         line_prefix = "    ", max_len = 60, file=file)
        print ("~~~", file=file)

    return ISK

def generate_test_vector(H,G, with_ANSI_C_initializers = True,file=sys.stdout, print_negated_Y = False):
    print ("##  Test vector for CPace using group " + G.name + " and hash "+H.name +"\n", file=file)

    #
    prefix_for_json_file_variables = G.name + "-" + H.name

    sid = H.hash(b"sid")
    sid = sid [:16]

    PRS = b"Password"
    CI = (prepend_len(b"Ainitiator") 
          + prepend_len(b"Bresponder"))

    ADa = b"ADa"
    ADb = b"ADb"

    g = G.calculate_generator(H,PRS,CI,sid, True, file = file)
    
    seed = b""
    while True:
        ya = G.sample_scalar(b"A"+seed)
        Ya = G.scalar_mult(ya, g)
        yb = G.sample_scalar(b"B"+seed)
        Yb = G.scalar_mult(yb, g)
        if not (oCAT(Ya,Yb) == Ya + Yb):
            break;
        seed += b" "
               
    MSGa = prefix_free_cat(Ya,ADa)
    MSGb = prefix_free_cat(Yb,ADb)
   
    print ("\n###  Test vector for MSGa\n", file=file)
    print ("~~~", file=file)
    print ("  Inputs", file=file)
    print ("    ADa =",ADa, file=file)
    tv_output_byte_array(ya, test_vector_name = "ya (" + G.encoding_of_scalar +")", 
                         line_prefix = "    ", max_len = 60, file=file)
    
    print ("  Outputs",file=file)
    tv_output_byte_array(Ya, test_vector_name = "Ya", 
                         line_prefix = "    ", max_len = 60, file=file)
                         
    if (print_negated_Y):
        tv_output_byte_array(G.scalar_mult_negated_result(ya, g), test_vector_name = "Alternative correct value for Ya: g^(-ya)", 
                             line_prefix = "    ", max_len = 60, file=file)
    
    tv_output_byte_array(MSGa, test_vector_name = "MSGa", 
                         line_prefix = "    ", max_len = 60, file=file)
    print ("~~~", file=file)
    print ("\n###  Test vector for MSGb\n", file=file)
    print ("~~~", file=file)
    print ("  Inputs", file=file)
    print ("    ADb =", ADb, file=file)
    tv_output_byte_array(yb, test_vector_name = "yb (" + G.encoding_of_scalar +")", 
                         line_prefix = "    ", max_len = 60, file=file)
    print ("  Outputs", file=file)
    tv_output_byte_array(Yb, test_vector_name = "Yb", 
                         line_prefix = "    ", max_len = 60, file=file)
    if (print_negated_Y):
        tv_output_byte_array(G.scalar_mult_negated_result(yb, g), test_vector_name = "Alternative correct value for Yb: g^(-yb)", 
                             line_prefix = "    ", max_len = 60, file=file)
    tv_output_byte_array(MSGb, test_vector_name = "MSGb", 
                         line_prefix = "    ", max_len = 60, file=file)
    
    print ("~~~", file=file)
    print ("\n###  Test vector for secret points K\n", file=file)
    print ("~~~", file=file)
    K1 = G.scalar_mult_vfy(ya,Yb)
    K2 = G.scalar_mult_vfy(yb,Ya)
    tv_output_byte_array(K1, test_vector_name = "scalar_mult_vfy(ya,Yb)", 
                         line_prefix = "    ", max_len = 60, file=file)
    tv_output_byte_array(K2, test_vector_name = "scalar_mult_vfy(yb,Ya)", 
                         line_prefix = "    ", max_len = 60, file=file)
    print ("~~~\n", file=file)
    if (K1 != K2):
        print ("Diffie-Hellman did fail!")
    K = K1
    
    ISK_IR = CPace_ISK(H,G.DSI_ISK,sid,K,MSGa,MSGb,doPrint = 1, symmetric_execution = False, file=file)
    ISK_SY = CPace_ISK(H,G.DSI_ISK,sid,K,MSGa,MSGb,doPrint = 1, symmetric_execution = True, file=file)
    
    if with_ANSI_C_initializers:
        print ("\n###  Corresponding ANSI-C initializers\n", file=file)
        print ("~~~", file=file)
        print (ByteArrayToCInitializer(PRS, "tc_PRS"), file=file)
        print (ByteArrayToCInitializer(CI, "tc_CI"), file=file)
        print (ByteArrayToCInitializer(sid, "tc_sid"), file=file)
        print (ByteArrayToCInitializer(g, "tc_g"), file=file)
        print (ByteArrayToCInitializer(ya, "tc_ya"), file=file)
        print (ByteArrayToCInitializer(ADa, "tc_ADa"), file=file)
        print (ByteArrayToCInitializer(Ya, "tc_Ya"), file=file)
        print (ByteArrayToCInitializer(yb, "tc_yb"), file=file)
        print (ByteArrayToCInitializer(ADb, "tc_ADb"), file=file)
        print (ByteArrayToCInitializer(Yb, "tc_Yb"), file=file)
        print (ByteArrayToCInitializer(K1, "tc_K"), file=file)
        print (ByteArrayToCInitializer(ISK_IR, "tc_ISK_IR"), file=file)
        print (ByteArrayToCInitializer(ISK_SY, "tc_ISK_SY"), file=file)
        print ("~~~\n", file=file)

if __name__ == "__main__":
    print ("Markdown for test vectors is generated.");
    print ("Be patient. This may take some time, as in the course of the process");
    print ("the group orders of the curves will be verified and checked for primality.");
    
    with open('../testvectors.md', 'w') as f:

        print("\n# CPace function definitions\n", file = f)
        
        generate_testvectors_string_functions(file = f)
    
        G = G_X25519()
        G.output_markdown_description_for_decodeUCoordinate(file = f);
        G.output_markdown_description_for_elligator2(file = f);
        
        print ("Z for Curve25519: ", G.find_z_ell2(GF(G.q)))
        
        print("\n# Test vectors\n", file = f)
    
        H = H_SHA512()
        G = G_X25519()
        generate_test_vector(H,G, file=f)
        output_test_vectors_for_weak_points_255(file = f)
 
        H = H_SHAKE256()
        G = G_X448()
        
        print ("Z for Ed448 : -", -G.find_z_ell2(GF(G.q)))

        generate_test_vector(H,G, file=f)
        output_test_vectors_for_weak_points_448(file = f)
   
        H = H_SHA512()
        G = G_CoffeeEcosystem(Ed25519Point)
        generate_test_vector(H,G, file=f)
        output_coffee_invalid_point_test_cases(G, file=f)

        H = H_SHAKE256()
        G = G_CoffeeEcosystem(Ed448GoldilocksPoint)
        generate_test_vector(H,G, file=f)
        output_coffee_invalid_point_test_cases(G, file=f)
    
        H = H_SHA256()
        G = G_ShortWeierstrass(p256_sswu_nu)
        generate_test_vector(H,G, file=f,print_negated_Y = True)
        output_weierstrass_invalid_point_test_cases(G, file=f)

        H = H_SHA384()
        G = G_ShortWeierstrass(p384_sswu_nu)
        generate_test_vector(H,G, file=f,print_negated_Y = True)
        output_weierstrass_invalid_point_test_cases(G, file=f)

        H = H_SHA512()
        G = G_ShortWeierstrass(p521_sswu_nu)
        generate_test_vector(H,G, file=f,print_negated_Y = True)
        output_weierstrass_invalid_point_test_cases(G, file=f)

