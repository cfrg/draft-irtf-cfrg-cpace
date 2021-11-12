from sagelib.CPace_string_utils import *

########## Definitions from RFC 7748 ##################

def decodeLittleEndian(b, bits):
    b_list = string_or_bytes_to_list(b)
    return sum([b_list[i] << 8*i for i in range(floor((bits+7)/8))])

def string_or_bytes_to_list(u):
    try:
        u_list = [ord(b) for b in u]
    except:
        u_list = [b for b in u]
    return u_list

def decodeUCoordinate(u, bits):
    u_list = string_or_bytes_to_list(u)    
    # Ignore any unused bits.
    if bits % 8:
        u_list[-1] &= (1<<(bits%8))-1
    return decodeLittleEndian(u_list, bits)

def encodeUCoordinate(u, bits):
    num_bytes = floor((bits+7)/8)
    result = bytearray(num_bytes)
    for i in range(num_bytes):
    	result[i] = (Integer(u) >> 8*i) & 0xff
    return bytes(result)

def decodeScalar25519(k):
    k_list = string_or_bytes_to_list(k)    
    k_list[0] &= 248
    k_list[31] &= 127
    k_list[31] |= 64
    return decodeLittleEndian(k_list, 255)

def decodeScalar448(k):
    k_list = string_or_bytes_to_list(k)    
    k_list[0] &= 252
    k_list[55] |= 128
    return decodeLittleEndian(k_list, 448)

def encodeScalar(u, bits):
    num_bytes = floor((bits+7)/8)
    result = bytearray(num_bytes)
    for i in range(num_bytes):
    	result[i] = (Integer(u) >> 8*i) & 0xff
    return bytes(result)

########## Additions ##################

def decodeScalarForInverse25519(k):
    k_list = string_or_bytes_to_list(k)    
    k_list[0] &= 248
    return decodeLittleEndian(k_list, 255)

def decodeScalarForInverse448(k):
    k_list = string_or_bytes_to_list(k)    
    k_list[0] &= 252
    return decodeLittleEndian(k_list, 448)

def decodeUnclampedScalar(k):
    k_list = string_or_bytes_to_list(k)    
    return decodeLittleEndian(k_list, len(k_list) * 8)

########## X25519 ##################

A_Curve25519 = 486662
q_Curve25519 = 2^255-19

# all inputs to be given as byte array.
def Inverse_X25519(scalar,basepoint):
    OrderPrimeSubgroup = 2^252 + 27742317777372353535851937790883648493
    num_bytes_for_field = ceil(log(q_Curve25519,2) / 8)
    SF = GF(OrderPrimeSubgroup)
    coFactor = 8
    scalar_clamped = decodeScalar25519(scalar)
    inverse_scalar = 1 /  (SF(scalarClamped) * coFactor)
    inverse_scalar_int = Integer(inverse_scalar) * coFactor
    inverse_scalar = encodeScalar(inverse_scalar_int,num_bytes_for_field * 8)
    return X__(basepoint,inverse_scalar,
               scalar_decoder=decodeScalarForInverse25519,
               warnForPointOnTwist = warnForPointOnTwist,
               A = 486662, field_prime = 2^255-19)

def X25519(scalar, basepoint, warnForPointOnTwist = True, unclamped_basepoint = False):
    return X__(scalar, basepoint, 
               scalar_decoder = decodeScalar25519, 
               warnForPointOnTwist = warnForPointOnTwist, 
               A = 486662, field_prime = 2^255-19, unclamped_basepoint = unclamped_basepoint)


########## X448 ##################

A_Curve448 = 156326
q_Curve448 = 2^448 - 2^224 - 1

# all inputs to be given as byte array.
def Inverse_X448(scalar,basepoint):
    OrderPrimeSubgroup = 2^446 - 0x8335dc163bb124b65129c96fde933d8d723a70aadc873d6d54a7bb0d
    num_bytes_for_field = ceil(log(q_Curve448,2) / 8)

    SF = GF(OrderPrimeSubgroup)
    coFactor = 4
    scalar_clamped = decodeScalar448(scalar)
    inverse_scalar = 1 /  (SF(scalarClamped) * coFactor)
    inverse_scalar_int = Integer(inverse_scalar) * coFactor
    inverse_scalar = encodeScalar(inverse_scalar_int,num_bytes_for_field * 8)
    return X__(basepoint,inverse_scalar,
               scalar_decoder=decodeScalarForInverse448,
               warnForPointOnTwist = warnForPointOnTwist,
               A = 156326, field_prime = 2^448 - 2^224 - 1)

def X448(scalar, basepoint, warnForPointOnTwist = True):
    return X__(scalar, basepoint, 
               scalar_decoder = decodeScalar448, 
               warnForPointOnTwist = warnForPointOnTwist, 
               A = 156326, field_prime = 2^448 - 2^224 - 1)

########## Common for X448 and X25519 ##################

def is_on_curve(basepoint, A = 486662, field_prime = 2^255-19):
    F = GF(field_prime)
    A = F(A)
    num_bits_for_field = ceil(log(float(field_prime),2))
    u = F(decodeUCoordinate(basepoint, num_bits_for_field))
    v2 = u^3 + A*u^2 + u
    if not v2.is_square():
        return  False
    else:
        return True # on twist

def get_nonsquare(F):
    """ Argument: F, a field object, e.g., F = GF(2^255 - 19) """
    ctr = F.gen()
    while True:
        for Z_cand in (F(ctr), F(-ctr)):
            # Z must be a non-square in F.
            if is_square(Z_cand):
                continue
            return Z_cand
        ctr += 1

def X__(encoded_scalar, basepoint, scalar_decoder=decodeScalar25519, 
        warnForPointOnTwist = True, 
        A = 486662, field_prime = 2^255-19, unclamped_basepoint = False):
    """Implements scalar multiplication for both, X448 and X25519."""
    num_bytes_for_field = ceil(log(field_prime,2) / 8)
    num_bits_for_field = ceil(log(float(field_prime),2))
    F = GF(Integer(field_prime))
    A = F(A)
    nonsquare = get_nonsquare(F)
    E = EllipticCurve(F, [0, A , 0, 1 , 0])
    Twist = EllipticCurve(F, [0, A * nonsquare, 0, 1 * nonsquare^2, 0])

    if unclamped_basepoint:
        u = F(decodeUCoordinate(basepoint, num_bits_for_field + 1))
    else:
        u = F(decodeUCoordinate(basepoint, num_bits_for_field))
    scalar = scalar_decoder(encoded_scalar)

    d = 1
    v2 = u^3 + A*u^2 + u
    if not v2.is_square():
        if (warnForPointOnTwist):
            print("Input point is on the twist! "),
        E = Twist
        d = nonsquare
        u = d * u
        v2 = u^3 + A*u^2 * nonsquare + u * nonsquare^2
    v = v2.sqrt()
    
    point = E(u, v)
    (resultPoint_u, resultPoint_v, result_Point_z) = point * scalar
    resultCoordinate = resultPoint_u / d

    return encodeUCoordinate(Integer(resultCoordinate),num_bits_for_field)
    
class X25519_testCase:
    def __init__(self,u_in, s_in, u_out):
        self.u_in = u_in
        self.s_in = s_in
        self.u_out = u_out

    def runTest(self):
        us = IntegerToByteArray(self.u_in)
        ss = IntegerToByteArray(self.s_in)
        r  = encodeUCoordinate(self.u_out,256)
        u = X25519(ss,us, unclamped_basepoint = True)
        if (u != r):
            print ("Fail")
            print ("Input u :\n0x%032x\n" % self.u_in)
            print ("Input s :\n0x%032x\n" % self.s_in)
            print ("Correct Result :\n0x%032x\n" % self.u_out)
            print ("Actual Result :\n0x%032x\n" % decodeLittleEndian(u,256))
            return False
        print ("Pass")
        return True
    
    def docOutput(self):
        print ("Test case for X25519:")
        print ("u:"),
        print (IntegerToLEPrintString(self.u_in))
        print ("s:"),
        print (IntegerToLEPrintString(self.s_in))
        print ("r:"),
        print (IntegerToLEPrintString(self.u_out))
            
if __name__ == "__main__":
    testCases = []

    tv = \
        X25519_testCase(0x4c1cabd0a603a9103b35b326ec2466727c5fb124a4c19435db3030586768dbe6,\
                        0xc49a44ba44226a50185afcc10a4c1462dd5e46824b15163b9d7c52f06be346a5,\
                        0x5285a2775507b454f7711c4903cfec324f088df24dea948e90c6e99d3755dac3)
    testCases.append(tv)

    tv = X25519_testCase(0x13a415c749d54cfc3e3cc06f10e7db312cae38059d95b7f4d3116878120f21e5,\
                         0xdba18799e16a42cd401eae021641bc1f56a7d959126d25a3c67b4d1d4e9664b,\
                         0x5779ac7a64f7f8e652a19f79685a598bf873b8b45ce4ad7a7d90e87694decb95)
    testCases.append(tv)

    tv = X25519_testCase(0,\
                         0xc49a44ba44226a50185afcc10a4c1462dd5e46824b15163b9d7c52f06be346a5,\
                     0)
    testCases.append(tv)
    
    weakp = []
    weakp.append(0)
    weakp.append(1)
    weakp.append(325606250916557431795983626356110631294008115727848805560023387167927233504) #(which has order 8)
    weakp.append(39382357235489614581723060781553021112529911719440698176882885853963445705823) #(which also has order 8)
    weakp.append(2^255 - 19 - 1)
    weakp.append(2^255 - 19)
    weakp.append(2^255 - 19 + 1)
    weakp.append(2^255 - 19 + 325606250916557431795983626356110631294008115727848805560023387167927233504)
    weakp.append(2^255 - 19 + 39382357235489614581723060781553021112529911719440698176882885853963445705823)
    weakp.append(2 * (2^255 - 19) - 1)
    weakp.append(2 * (2^255 - 19))
    weakp.append(2 * (2^255 - 19) + 1)

    s_in = 0xff9a44ba44226a50185afcc10a4c1462dd5e46824b15163b9d7c52f06be346af;
    for x in weakp:
        tv = X25519_testCase (x,s_in,0)
        testCases.append(tv)

    for x in testCases:
        x.runTest()

    for x in testCases:
        x.docOutput()
        
    input_scalar = 599189175373896402783756016145213256157230856085026129926891459468622403380588640249457727683869421921443004045221642549886377526240828
    input_coor = 382239910814107330116229961234899377031416365240571325148346555922438025162094455820962429142971339584360034337310079791515452463053830
    correct_output =  0xce3e4ff95a60dc6697da1db1d85e6afbdf79b50a2412d7546d5f239fe14fbaadeb445fc66a01b0779d98223961111e21766282f73dd96b6f

    own_result = X448(IntegerToByteArray(input_scalar,57),IntegerToByteArray(input_coor,57))
    own_result = bytes(reversed(own_result))

    if correct_output == ByteArrayToInteger(own_result, 56):
        print ("X448 result matches test vector.\n", ByteArrayToLEPrintString(own_result))
    else:
        print ("X448 result does not match:\n", 
               ByteArrayToLEPrintString(own_result),"\n",
               IntegerToLEPrintString(correct_output))
    

    input_scalar = 31029842492115040904895560451863089656472772604678260265531221036453811406496
    input_coor =   34426434033919594451155107781188821651316167215306631574996226621102155684838
    correct_output = 0xc3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552

    own_result = X25519(IntegerToByteArray(input_scalar),IntegerToByteArray(input_coor))
    own_result = bytes(reversed(own_result))
    if correct_output == ByteArrayToInteger(own_result, 32):
        print ("X25519 result matches test vector.\n", ByteArrayToLEPrintString(own_result))
    else:
        print ("X25519 result does not match:\n", 
               ByteArrayToLEPrintString(own_result),"\n",
               IntegerToLEPrintString(correct_output))
