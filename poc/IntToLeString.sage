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
    result = "const unsigned char " + name +"[] = {"
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

