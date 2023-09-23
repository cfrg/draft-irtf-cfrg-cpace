#!/usr/local/bin/sage
# vim: syntax=python

########## Little-Endian octet string to integer conversion

def ByteArrayToInteger(k,numBytes=32):
    return sum((k[i] << (8 * i)) for i in range(len(k)))

def IntegerToByteArray(k,numBytes = 32):
    result = bytearray(numBytes);
    for i in range(numBytes):
        result[i] = (k >> (8 * i)) & 0xff;
    return result


def IntegerToLEPrintString(u,numBytes=32):
    u = Integer(u)
    res = ""
    ctr = 0
    while ((u != 0) | (numBytes > 0)):
        byte =  u % 256
        res += ("%02x" % byte)
        u = (u - byte) >> 8
        numBytes = numBytes - 1
        ctr = ctr + 1
    return res

def ByteArrayToCInitializer(k, name, values_per_line = 16):
    values = [b for b in k]
    result = "const uint8_t " + name +"[] = {"
    n = 0
    for x in values:
        if n == 0:
            result += "\n "
        n = (n + 1) % values_per_line;
        
        result += ("0x%02x" %x) +","
    result += "\n};"
    return result

def ByteArrayToLEPrintString(k):
    bytes = [(b) for b in k]
    res = ""
    ctr = 0
    for x in bytes:
        res += ("%02x" %x)
        ctr = ctr + 1
    return res

########## X25519

def clampScalar25519(k):
    r = bytearray(k)
    r[0] &= 248
    r[31] &= 127
    r[31] |= 64
    return r

def clampScalarForInversion25519(k):
    r = bytearray(k)
    r[0] &= 248
    return r

# all inputs to be given as byte array.
def Inverse_X25519(scalar,basepoint):
    OrderPrimeSubgroup = 2^252 + 27742317777372353535851937790883648493
    SF = GF(OrderPrimeSubgroup)
    coFactor = SF(8)
    scalarClamped = clampScalar25519(scalar)
    inverse_scalar = 1 /  (SF(ByteArrayToInteger(scalarClamped)) * coFactor)
    inverse_scalar_int = Integer(inverse_scalar) * 8
    inverse_scalar = IntegerToByteArray(inverse_scalar_int)
    return X25519(basepoint,inverse_scalar,withClamping=0)

def X25519(scalar, basepoint, withClamping=1,warnForPointOnTwist = 1, A = 486662, prime = 2^255-19, nonsquare = 2):
    prime = 2^255 - 19
    F = GF(prime)
    A = F(A)
    nonsquare = F(nonsquare)   
    E = EllipticCurve(F, [0, A , 0, 1 , 0])
    Twist = EllipticCurve(F, [0, A * nonsquare, 0, 1 * nonsquare^2, 0])

    u = F(ByteArrayToInteger(basepoint))
    if (withClamping == 1):
        clampedScalar = ByteArrayToInteger(clampScalar25519(scalar))
    else:    
        clampedScalar = ByteArrayToInteger(clampScalarForInversion25519(scalar))

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
    (resultPoint_u, resultPoint_v, result_Point_z) = point * clampedScalar
    resultCoordinate = resultPoint_u / d
    
    return IntegerToByteArray(Integer(resultCoordinate))
    
def test_X25519():
    print ("Tests for X25519:");

    class X25519_testCase:
        def __init__(self,u_in, s_in, u_out):
            self.u_in = u_in
            self.s_in = s_in
            self.u_out = u_out

        def runTest(self):
            us = IntegerToByteArray(self.u_in)
            ss = IntegerToByteArray(self.s_in)
            r  = IntegerToByteArray(self.u_out)
            u = X25519(ss,us)
            if (u != r):
                print ("Fail")
                print ("Input u :\n0x%032x\n" % self.u_in)
                print ("Input s :\n0x%032x\n" % self.s_in)
                print ("Correct Result :\n0x%032x\n" % self.u_out)
                print ("Actual Result :\n0x%032x\n" % ByteArrayToInteger(u))
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
        

    testCases = []

    tv = \
        X25519_testCase(0x4c1cabd0a603a9103b35b326ec2466727c5fb124a4c19435db3030586768dbe6,
                        0xc49a44ba44226a50185afcc10a4c1462dd5e46824b15163b9d7c52f06be346a5,
                        0x5285a2775507b454f7711c4903cfec324f088df24dea948e90c6e99d3755dac3)
    testCases.append(tv)


    tv = X25519_testCase(0x13a415c749d54cfc3e3cc06f10e7db312cae38059d95b7f4d3116878120f21e5,
                         0xdba18799e16a42cd401eae021641bc1f56a7d959126d25a3c67b4d1d4e9664b,
                         0x5779ac7a64f7f8e652a19f79685a598bf873b8b45ce4ad7a7d90e87694decb95)
    testCases.append(tv)

    tv = X25519_testCase(0,
                         0xc49a44ba44226a50185afcc10a4c1462dd5e46824b15163b9d7c52f06be346a5,
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

if __name__ == "__main__":
    test_X25519()
