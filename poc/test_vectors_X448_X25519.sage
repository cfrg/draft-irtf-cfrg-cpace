import sys

########## Definitions from RFC 7748 ##################
from sagelib.RFC7748_X448_X25519 import *
from sagelib.CPace_string_utils import *
from sagelib.CPace_hashing import *


def output_test_vectors_for_weak_points_255(file = sys.stdout):
    print ("\n## Test vectors for X25519 low order points\n",file = file)
    print ("Points that need to return neutral element when input to", file = file)
    print ("plain X25519 that also accept un-normalized inputs with", file = file)
    print ("bit #255 set in the input point encoding.", file = file)
    print ("\n~~~", file = file)

    s_in = 0xff9a44ba44226a50185afcc10a4c1462dd5e46824b15163b9d7c52f06be346af;

    weak_pts255 = [(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'), 
                   (b'\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'), 
                   (b'\xec\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x7f'), 
                   (b'\xe0\xebz|;A\xb8\xae\x16V\xe3\xfa\xf1\x9f\xc4j\xda\t\x8d\xeb\x9c2\xb1\xfd\x86b\x05\x16_I\xb8\x00'), 
                   (b'_\x9c\x95\xbc\xa3P\x8c$\xb1\xd0\xb1U\x9c\x83\xef[\x04D\\\xc4X\x1c\x8e\x86\xd8"N\xdd\xd0\x9f\x11W')]
    nc_weak_pts255 = [(b'\xed\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x7f'), 
                      (b'\xda\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'),
                      (b'\xee\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x7f'),
                      (b'\xdb\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'),
                      (b'\xd9\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'),
                      (b'\xcd\xebz|;A\xb8\xae\x16V\xe3\xfa\xf1\x9f\xc4j\xda\t\x8d\xeb\x9c2\xb1\xfd\x86b\x05\x16_I\xb8\x80'), 
                      (b'L\x9c\x95\xbc\xa3P\x8c$\xb1\xd0\xb1U\x9c\x83\xef[\x04D\\\xc4X\x1c\x8e\x86\xd8"N\xdd\xd0\x9f\x11\xd7')]

    weakp = []
    for wp in weak_pts255:
        weakp.append(decodeUCoordinate(wp,255))
    for wp in nc_weak_pts255:
        weakp.append(decodeUCoordinate(wp,256))

    ctr=0;
    for x in weakp:
        print ("u"+'{:01x}'.format(ctr)+":",IntegerToLEPrintString(x), file = file);
        ctr += 1;
    
    print ("\nResults for X25519 implementations not clearing bit #255:", file = file)
    print ("(i.e. with X25519 not implemented according to RFC7748!):", file = file)
    print ("s =", IntegerToLEPrintString(s_in), file = file);
    print ("rN = X25519(s,uX);", file = file)
    ctr=0;
    for x in weakp:
        r = X25519(encodeScalar(s_in,256), encodeUCoordinate(x,256),warnForPointOnTwist=0,unclamped_basepoint = True);
        r = decodeLittleEndian(r,256)
        print ("r"+'{:01x}'.format(ctr)+":",IntegerToLEPrintString(r), file = file);
        ctr += 1;

    print ("\nResults for X25519 implementations that clear bit #255:", file = file)
    print ("(i.e. implemented according to RFC7748!):", file = file)
    print ("s =", IntegerToLEPrintString(s_in), file = file);
    print ("qN = X25519(s, uX & ((1 << 255) - 1));", file = file)
    ctr=0;
    for x in weakp:
        q = X25519(encodeScalar(s_in,256), encodeUCoordinate(x,256),warnForPointOnTwist=0);
        q = decodeLittleEndian(q,256)
        print ("q"+'{:01x}'.format(ctr)+":",IntegerToLEPrintString(q), file = file);
        ctr += 1;
        
    print ("~~~\n", file = file)


def output_test_vectors_for_weak_points_448(file = sys.stdout):
    print ("\n## Test vectors for X448 low order points\n",file = file)
    print ("Points that need to return neutral element when input to", file = file)
    print ("plain X448 that also accept non-canonical inputs larger", file = file)
    print ("than the field prime.", file = file)

    s = b""
    while True:
        s = H_SHAKE256().hash(s,56)
        if (s[0] & 3 == 3):
            break;
    
    weak_pts448 = [bytearray(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'), bytearray(b'\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'), bytearray(b'\xfe\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff')]
    nc_weak_pts448= [bytearray(b'\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff'), bytearray(b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff')]
           
    weakp = []
    for wp in weak_pts448:
        weakp.append(wp)
    for wp in nc_weak_pts448:
        weakp.append(wp)

    ctr=0;
    print ("\n### Weak points for X448 smaller than the field prime (canonical)\n",file = file)
    print ("~~~", file = file)
    for x in weak_pts448:
        tv_output_byte_array(x, 
                         test_vector_name = 'u%i' % ctr, 
                         line_prefix = "  ", max_len = 60, file = file);
        ctr += 1;
    print ("~~~", file = file)
    print ("\n### Weak points for X448 larger or equal to the field prime (non-canonical)\n",file = file)
    print ("~~~", file = file)
    for x in nc_weak_pts448:
        tv_output_byte_array(x, 
                         test_vector_name = 'u%i' % ctr, 
                         line_prefix = "  ", max_len = 60, file = file);
        ctr += 1;
    print ("~~~", file = file)
    
    print ("\n### Expected results for X448\n",file = file)
    ctr=0;
    print ("~~~", file = file)
    tv_output_byte_array(s, 
                         test_vector_name = 'scalar s', 
                         line_prefix = "  ", max_len = 60, file = file);
    for x in weak_pts448:
        res = X448(s,x,warnForPointOnTwist = False)
        res = decodeUCoordinate(res,448)
        res = IntegerToByteArray(res,56)
        tv_output_byte_array(res, 
                         test_vector_name = 'X448(s,u%i)' % ctr, 
                         line_prefix = "  ", max_len = 60, file = file);
        ctr += 1;

    for x in nc_weak_pts448:
        res = X448(s,x,warnForPointOnTwist = False)
        res = decodeUCoordinate(res,448)
        res = IntegerToByteArray(res,56)
        tv_output_byte_array(res, 
                         test_vector_name = 'X448(s,u%i)' % ctr, 
                         line_prefix = "  ", max_len = 60, file = file);
        ctr += 1;
    print ("~~~\n", file = file)


if __name__ == "__main__":
    output_test_vectors_for_weak_points_255()
    output_test_vectors_for_weak_points_448()
