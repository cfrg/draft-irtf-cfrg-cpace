import sys

########## Definitions from RFC 7748 ##################
from sagelib.RFC7748_X448_X25519 import *
from sagelib.CPace_string_utils import *
from sagelib.CPace_hashing import *


def output_test_vectors_for_weak_points_255(file = sys.stdout):
    print ("\n### Test vectors for G_X25519.scalar_mult_vfy: low order points\n",file = file)
    print ("Test vectors for which G_X25519.scalar_mult_vfy(s_in,ux) must return the neutral", file = file)
    print("element or would return the neutral element if bit #255 of field element", file = file)
    print ("representation was not correctly cleared. (The decodeUCoordinate function from RFC7748 mandates clearing bit #255 for field element representations for use in the X25519 function.).", file = file)
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
    
#    print ("\nResults for X25519 implementations not clearing bit #255:", file = file)
#    print ("(i.e. with X25519 not implemented according to RFC7748!):", file = file)
#    print ("s =", IntegerToLEPrintString(s_in), file = file);
#    print ("rN = X25519(s,uX);", file = file)
#    ctr=0;
#    for x in weakp:
#        r = X25519(encodeScalar(s_in,256), encodeUCoordinate(x,256),warnForPointOnTwist=0,unclamped_basepoint = True);
#        r = decodeLittleEndian(r,256)
#        print ("r"+'{:01x}'.format(ctr)+":",IntegerToLEPrintString(r), file = file);
#        ctr += 1;
#
#    print ("\nResults for X25519 implementations that clear bit #255:", file = file)
#    print ("(i.e. implemented according to RFC7748!):", file = file)
    print ("s =", IntegerToLEPrintString(s_in), file = file);
    print ("qN = G_X25519.scalar_mult_vfy(s, uX)", file = file)
    ctr=0;
    for x in weakp:
        q = X25519(encodeScalar(s_in,256), encodeUCoordinate(x,256),warnForPointOnTwist=0);
        q = decodeLittleEndian(q,256)
        print ("q"+'{:01x}'.format(ctr)+":",IntegerToLEPrintString(q), file = file);
        ctr += 1;
        
    print ("~~~\n", file = file)


def output_test_vectors_for_weak_points_448(file = sys.stdout):
    print ("\n### Test vectors for G_X448.scalar_mult_vfy: low order points\n",file = file)
    print ("Test vectors for which G_X448.scalar_mult_vfy(s_in,ux) must return the neutral", file = file)
    print("element", file = file)
    print ("This includes points that are non-canonicaly encoded, i.e. have coordinate values", file = file)
    print ("larger", file = file)
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
    print ("\nWeak points for X448 smaller than the field prime (canonical)\n",file = file)
    print ("~~~", file = file)
    for x in weak_pts448:
        tv_output_byte_array(x, 
                         test_vector_name = 'u%i' % ctr, 
                         line_prefix = "  ", max_len = 60, file = file);
        ctr += 1;
    print ("~~~", file = file)
    print ("\nWeak points for X448 larger or equal to the field prime (non-canonical)\n",file = file)
    print ("~~~", file = file)
    for x in nc_weak_pts448:
        tv_output_byte_array(x, 
                         test_vector_name = 'u%i' % ctr, 
                         line_prefix = "  ", max_len = 60, file = file);
        ctr += 1;
    print ("~~~", file = file)
    
    print ("\nExpected results for X448 resp. G_X448.scalar_mult_vfy\n",file = file)
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
                         test_vector_name = 'G_X448.scalar_mult_vfy(s,u%i)' % ctr, 
                         line_prefix = "  ", max_len = 60, file = file);
        ctr += 1;

    for x in nc_weak_pts448:
        res = X448(s,x,warnForPointOnTwist = False)
        res = decodeUCoordinate(res,448)
        res = IntegerToByteArray(res,56)
        tv_output_byte_array(res, 
                         test_vector_name = 'G_X448.scalar_mult_vfy(s,u%i)' % ctr, 
                         line_prefix = "  ", max_len = 60, file = file);
        ctr += 1;
    print ("~~~\n", file = file)
    print ("\nTest vectors for scalar_mult with nonzero outputs\n",file = file)
 
    print ("~~~", file = file)
    u_curve = H_SHAKE256().hash(b"valid_",56)
    res_curve = X448(s,u_curve,warnForPointOnTwist = True)
    res_curve = decodeUCoordinate(res_curve,448)
    res_curve = IntegerToByteArray(res_curve,56)
    
    tv_output_byte_array(s, 
                         test_vector_name = 'scalar s', 
                         line_prefix = "  ", max_len = 60, file = file);
    tv_output_byte_array(u_curve, 
                         test_vector_name = 'point coordinate u_curve on the curve', 
                         line_prefix = "  ", max_len = 60, file = file);
    tv_output_byte_array(res_curve, 
                         test_vector_name = 'G_X448.scalar_mult_vfy(s,u_curve)', 
                         line_prefix = "  ", max_len = 60, file = file);
                         
    print ("", file = file)
    u_twist = H_SHAKE256().hash(b" point on twist ",56)
    res_twist = X448(s,u_twist,warnForPointOnTwist = False)
    res_twist = decodeUCoordinate(res_twist,448)
    res_twist = IntegerToByteArray(res_twist,56)
                         
    tv_output_byte_array(u_twist, 
                         test_vector_name = 'point coordinate u_twist on the twist', 
                         line_prefix = "  ", max_len = 60, file = file);
    tv_output_byte_array(res_twist, 
                         test_vector_name = 'G_X448.scalar_mult_vfy(s,u_twist)', 
                         line_prefix = "  ", max_len = 60, file = file);
                         
                     
    print ("~~~\n", file = file)



if __name__ == "__main__":
    output_test_vectors_for_weak_points_448()
    output_test_vectors_for_weak_points_255()

