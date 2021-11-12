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
    u = Integer(u)
    return ''.join([chr((u >> 8*i) & 0xff)
                    for i in range(floor((bits+7)/8))])

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
    return ''.join([chr((Integer(u) >> 8*i) & 0xff)
                    for i in range(floor((bits+7)/8))])

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
