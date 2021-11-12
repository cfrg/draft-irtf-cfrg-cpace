import sys

########## Definitions from RFC 7748 ##################
from sagelib.RFC7748_X448_X25519 import *

def montgomery_get_weak_points(A,field_prime):
    F = GF(field_prime)
    A = F(A)
    num_bits_for_field = ceil(log(float(field_prime),2))
    num_bytes_for_field = floor((num_bits_for_field + 7) / 8)

    nonsquare = get_nonsquare(F)   
    curve = EllipticCurve(F, [0, A , 0, 1 , 0])
    twist = EllipticCurve(F, [0, A * nonsquare, 0, 1 * nonsquare^2, 0])
    
    order_curve = curve.order()
    order_twist = twist.order()
       
    def get_cofactor(order_curve):
        cofactor_candidate = 1;
        while True:
            if order_curve % cofactor_candidate == 0:
                rest = Integer(order_curve / cofactor_candidate)
                if rest.is_prime():
                    return Integer(cofactor_candidate), Integer(order_curve / cofactor_candidate);
            cofactor_candidate += 1

    c,p = get_cofactor(order_curve)
    c_prime,p_prime = get_cofactor(order_twist)
    
    print ("Number of bytes for field: %i" % num_bytes_for_field)
    print ("Number of bits for field: %i" % num_bits_for_field)
    print ("Cofactor curve: %i" % c)
    print ("Cofactor twist: %i" % c_prime)
    print ("Order curve: %i" % (p))
    print ("Order twist: %i" % (p_prime))
    
    weak_points = [];

    for m in range(50):
        u = encodeUCoordinate(m,num_bytes_for_field * 8)

        if is_on_curve(u,A,field_prime):
            u1 = X__(encodeScalar(p,8 * num_bytes_for_field),u,
                     scalar_decoder = decodeUnclampedScalar, A = A, field_prime = field_prime,
                     warnForPointOnTwist = False)
            if not u1 in weak_points:
                weak_points.append(u1)
                print ("Found weak point on curve")
        else:
            u1 = X__(encodeScalar(p_prime,8 * num_bytes_for_field),u,
                     scalar_decoder = decodeUnclampedScalar, A = A, field_prime = field_prime,
                     warnForPointOnTwist = False)
            if not u1 in weak_points:
                weak_points.append(u1)
                print ("Found weak point on twist.")
        if len(weak_points) == (c + c_prime) / 2 - 1: break

    print (weak_points)

    non_canonical_weak_points = []
    for m in weak_points:
        u = decodeUCoordinate(m,num_bits_for_field)
        while True:
            u += field_prime
            if u < 2^(8 * num_bytes_for_field):
                non_canonical_weak_points.append(encodeUCoordinate(u,num_bytes_for_field * 8))
            else:
                break;

    return weak_points,non_canonical_weak_points
        
if __name__ == "__main__":
    weak_pts255, nc_weak_pts255 = montgomery_get_weak_points(A_Curve25519,q_Curve25519)
    print (len(weak_pts255))
    print (len(nc_weak_pts255))

    print ("Weak points Curve25519:\n", weak_pts255)
    print ("Weak non-canonical points Curve25519:\n", nc_weak_pts255)

    import sys

    sys.stdout.flush()

    weak_pts448, nc_weak_pts448 = montgomery_get_weak_points(A_Curve448,q_Curve448)

    print ("Weak points Curve448:\n", weak_pts448)
    print ("Weak non-canonical points Curve448:\n", nc_weak_pts448)

