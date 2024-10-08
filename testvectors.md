
# CPace function definitions


## Definition and test vectors for string utility functions


### prepend\_len function


~~~ python
def prepend_len(data):
    "prepend LEB128 encoding of length"
    length = len(data)
    length_encoded = b""
    while True:
        if length < 128:
            length_encoded += bytes([length])
        else:
            length_encoded += bytes([(length & 0x7f) + 0x80])
        length = int(length >> 7)
        if length == 0:
            break;
    return length_encoded + data
~~~


### prepend\_len test vectors

~~~
  prepend_len(b""): (length: 1 bytes)
    00
  prepend_len(b"1234"): (length: 5 bytes)
    0431323334
  prepend_len(bytes(range(127))): (length: 128 bytes)
    7f000102030405060708090a0b0c0d0e0f101112131415161718191a1b
    1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738
    393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455
    565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172
    737475767778797a7b7c7d7e
  prepend_len(bytes(range(128))): (length: 130 bytes)
    8001000102030405060708090a0b0c0d0e0f101112131415161718191a
    1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637
    38393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f5051525354
    55565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f7071
    72737475767778797a7b7c7d7e7f
~~~

####  Testvectors as JSON file encoded as BASE64


~~~ test-vectors
 #eyJwcmVwZW5kX2xlbihiKSI6ICJBQT09IiwgImJcIjEyMzRcIiI6ICJNVEl6TkE9PS
 #IsICJwcmVwZW5kX2xlbihiXCIxMjM0XCIpIjogIkJERXlNelE9IiwgInByZXBlbmRf
 #bGVuKGJ5dGVzKHJhbmdlKDEyNykpKSI6ICJmd0FCQWdNRUJRWUhDQWtLQ3d3TkRnOF
 #FFUklURkJVV0Z4Z1pHaHNjSFI0ZklDRWlJeVFsSmljb0tTb3JMQzB1THpBeE1qTTBO
 #VFkzT0RrNk96dzlQajlBUVVKRFJFVkdSMGhKU2t0TVRVNVBVRkZTVTFSVlZsZFlXVn
 #BiWEYxZVgyQmhZbU5rWldabmFHbHFhMnh0Ym05d2NYSnpkSFYyZDNoNWVudDhmWDQ9
 #IiwgInByZXBlbmRfbGVuKGJ5dGVzKHJhbmdlKDEyOCkpKSI6ICJnQUVBQVFJREJBVU
 #dCd2dKQ2dzTURRNFBFQkVTRXhRVkZoY1lHUm9iSEIwZUh5QWhJaU1rSlNZbktDa3FL
 #eXd0TGk4d01USXpORFUyTnpnNU9qczhQVDQvUUVGQ1EwUkZSa2RJU1VwTFRFMU9UMU
 #JSVWxOVVZWWlhXRmxhVzF4ZFhsOWdZV0pqWkdWbVoyaHBhbXRzYlc1dmNIRnljM1Ix
 #ZG5kNGVYcDdmSDErZnc9PSJ9
~~~



### lv\_cat function


~~~ python
  def lv_cat(*args):
      result = b""
      for arg in args:
          result += prepend_len(arg)
      return result
~~~


### Testvector for lv\_cat()

~~~
  lv_cat(b"1234",b"5",b"",b"678"): (length: 12 bytes)
    043132333401350003363738
~~~

####  Testvectors as JSON file encoded as BASE64


~~~ test-vectors
 #eyJiXCIxMjM0XCIiOiAiTVRJek5BPT0iLCAiYlwiNVwiIjogIk5RPT0iLCAiYlwiNj
 #c4XCIiOiAiTmpjNCIsICJsdl9jYXQoYlwiMTIzNFwiLGJcIjVcIixiXCJcIixiXCI2
 #NzhcIikiOiAiQkRFeU16UUJOUUFETmpjNCJ9
~~~


## Definition of generator\_string function.


~~~ python
def generator_string(DSI,PRS,CI,sid,s_in_bytes):
    # Concat all input fields with prepended length information.
    # Add zero padding in the first hash block after DSI and PRS.
    len_zpad = max(0,s_in_bytes - 1 - len(prepend_len(PRS))
                     - len(prepend_len(DSI)))
    return lv_cat(DSI, PRS, zero_bytes(len_zpad),
                           CI, sid)
~~~


## Definitions and test vector ordered concatenation


### Definitions for lexiographical ordering


For ordered concatenation lexiographical ordering of byte sequences is used:


~~~ python
   def lexiographically_larger(bytes1,bytes2):
      "Returns True if bytes1>bytes2 using lexiographical ordering."
      min_len = min (len(bytes1), len(bytes2))
      for m in range(min_len):
          if bytes1[m] > bytes2[m]:
              return True;
          elif bytes1[m] < bytes2[m]:
              return False;
      return len(bytes1) > len(bytes2)
~~~

### Definitions for ordered concatenation

With the above definition of lexiographical ordering ordered concatenation is specified as follows.




~~~ python
  def o_cat(bytes1,bytes2):
      if lexiographically_larger(bytes1,bytes2):
          return b"oc" + bytes1 + bytes2
      else:
          return b"oc" + bytes2 + bytes1
~~~

### Test vectors ordered concatenation

~~~
  string comparison for o_cat:
    lexiographically_larger(b"\0", b"\0\0") == False
    lexiographically_larger(b"\1", b"\0\0") == True
    lexiographically_larger(b"\0\0", b"\0") == True
    lexiographically_larger(b"\0\0", b"\1") == False
    lexiographically_larger(b"\0\1", b"\1") == False
    lexiographically_larger(b"ABCD", b"BCD") == False

  o_cat(b"ABCD",b"BCD"): (length: 9 bytes)
    6f6342434441424344
  o_cat(b"BCD",b"ABCDE"): (length: 10 bytes)
    6f634243444142434445
~~~

####  Testvectors as JSON file encoded as BASE64


~~~ test-vectors
 #eyJiXCJBQkNEXCIiOiAiUVVKRFJBPT0iLCAiYlwiQkNEXCIiOiAiUWtORSIsICJiXC
 #JBQkNERVwiIjogIlFVSkRSRVU9IiwgIm9fY2F0KGJcIkFCQ0RcIixiXCJCQ0RcIiki
 #OiAiYjJOQ1EwUkJRa05FIiwgIm9fY2F0KGJcIkJDRFwiLGJcIkFCQ0RFXCIpIjogIm
 #IyTkNRMFJCUWtORVJRPT0ifQ==
~~~



### Definitions for transcript\_ir function

~~~ python
def transcript_ir(Ya,ADa,Yb,ADb):
    result = lv_cat(Ya,ADa) + lv_cat(Yb,ADb)
    return result
~~~

### Test vectors transcript\_ir function

~~~
  transcript_ir(b"123", b"PartyA", b"234",b"PartyB"):
  (length: 22 bytes)
    03313233065061727479410332333406506172747942
  transcript_ir(b"3456",b"PartyA",b"2345",b"PartyB"):
  (length: 24 bytes)
    043334353606506172747941043233343506506172747942
~~~

####  Testvectors as JSON file encoded as BASE64


~~~ test-vectors
 #eyJiXCIxMjNcIiI6ICJNVEl6IiwgImJcIjIzNFwiIjogIk1qTTAiLCAiYlwiUGFydH
 #lBXCIiOiAiVUdGeWRIbEIiLCAiYlwiUGFydHlCXCIiOiAiVUdGeWRIbEMiLCAiYlwi
 #MzQ1NlwiIjogIk16UTFOZz09IiwgImJcIjIzNDVcIiI6ICJNak0wTlE9PSIsICJ0cm
 #Fuc2NyaXB0X2lyKGJcIjEyM1wiLGJcIlBhcnR5QVwiLGJcIjIzNFwiLGJcIlBhcnR5
 #QlwiKSI6ICJBekV5TXdaUVlYSjBlVUVETWpNMEJsQmhjblI1UWc9PSIsICJ0cmFuc2
 #NyaXB0X2lyKGJcIjM0NTZcIixiXCJQYXJ0eUFcIixiXCIyMzQ1XCIsYlwiUGFydHlC
 #XCIpIjogIkJETTBOVFlHVUdGeWRIbEJCREl6TkRVR1VHRnlkSGxDIn0=
~~~



### Definitions for transcript\_oc function

~~~ python
def transcript_oc(Ya,ADa,Yb,ADb):
    result = o_cat(lv_cat(Ya,ADa),lv_cat(Yb,ADb))
    return result
~~~

### Test vectors for transcript\_oc function

~~~
  transcript_oc(b"123", b"PartyA", b"234",b"PartyB"):
  (length: 24 bytes)
    6f6303323334065061727479420331323306506172747941
  transcript_oc(b"3456",b"PartyA",b"2345",b"PartyB"):
  (length: 26 bytes)
    6f63043334353606506172747941043233343506506172747942
~~~

####  Testvectors as JSON file encoded as BASE64


~~~ test-vectors
 #eyJiXCIxMjNcIiI6ICJNVEl6IiwgImJcIjIzNFwiIjogIk1qTTAiLCAiYlwiUGFydH
 #lBXCIiOiAiVUdGeWRIbEIiLCAiYlwiUGFydHlCXCIiOiAiVUdGeWRIbEMiLCAiYlwi
 #MzQ1NlwiIjogIk16UTFOZz09IiwgImJcIjIzNDVcIiI6ICJNak0wTlE9PSIsICJ0cm
 #Fuc2NyaXB0X29jKGJcIjEyM1wiLGJcIlBhcnR5QVwiLGJcIjIzNFwiLGJcIlBhcnR5
 #QlwiKSI6ICJiMk1ETWpNMEJsQmhjblI1UWdNeE1qTUdVR0Z5ZEhsQiIsICJ0cmFuc2
 #NyaXB0X29jKGJcIjM0NTZcIixiXCJQYXJ0eUFcIixiXCIyMzQ1XCIsYlwiUGFydHlC
 #XCIpIjogImIyTUVNelExTmdaUVlYSjBlVUVFTWpNME5RWlFZWEowZVVJPSJ9
~~~



## Decoding and Encoding functions according to RFC7748

~~~ python
   def decodeLittleEndian(b, bits):
       return sum([b[i] << 8*i for i in range((bits+7)/8)])

   def decodeUCoordinate(u, bits):
       u_list = [ord(b) for b in u]
       # Ignore any unused bits.
       if bits % 8:
           u_list[-1] &= (1<<(bits%8))-1
       return decodeLittleEndian(u_list, bits)

   def encodeUCoordinate(u, bits):
       return ''.join([chr((u >> 8*i) & 0xff)
                       for i in range((bits+7)/8)])
~~~



## Elligator 2 reference implementation
The Elligator 2 map requires a non-square field element Z which shall be calculated
as follows.

~~~ python
    def find_z_ell2(F):
        # Find nonsquare for Elligator2
        # Argument: F, a field object, e.g., F = GF(2^255 - 19)
        ctr = F.gen()
        while True:
            for Z_cand in (F(ctr), F(-ctr)):
                # Z must be a non-square in F.
                if is_square(Z_cand):
                    continue
                return Z_cand
            ctr += 1
~~~

The values of the non-square Z only depend on the curve. The algorithm above
results in a value of Z = 2 for Curve25519 and Z=-1 for Ed448.

The following code maps a field element r to an encoded field element which
is a valid u-coordinate of a Montgomery curve with curve parameter A.

~~~ python
    def elligator2(r, q, A, field_size_bits):
        # Inputs: field element r, field order q,
        #         curve parameter A and field size in bits
        Fq = GF(q); A = Fq(A); B = Fq(1);

        # get non-square z as specified in the hash2curve draft.
        z = Fq(find_z_ell2(Fq))
        powerForLegendreSymbol = floor((q-1)/2)

        v = - A / (1 + z * r^2)
        epsilon = (v^3 + A * v^2 + B * v)^powerForLegendreSymbol
        x = epsilon * v - (1 - epsilon) * A/2
        return encodeUCoordinate(Integer(x), field_size_bits)
~~~



# Test vectors

##  Test vector for CPace using group X25519 and hash SHA-512


###  Test vectors for calculate\_generator with group X25519

~~~
  Inputs
    H   = SHA-512 with input block size 128 bytes.
    PRS = b'Password' ; ZPAD length: 109 ; DSI = b'CPace255'
    CI = b'oc\x0bB_responder\x0bA_initiator'
    CI = 6f630b425f726573706f6e6465720b415f696e69746961746f72
    sid = 7e4b4791d6a8ef019b936c79fb7f2c57
  Outputs
    generator_string(G.DSI,PRS,CI,sid,H.s_in_bytes):
    (length: 172 bytes)
      0843506163653235350850617373776f72646d000000000000000000
      00000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      000000000000000000000000000000001a6f630b425f726573706f6e
      6465720b415f696e69746961746f72107e4b4791d6a8ef019b936c79
      fb7f2c57
    hash generator string: (length: 32 bytes)
      92806dc608984dbf4e4aae478c6ec453ae979cc01ecc1a2a7cf49f5c
      ee56551b
    decoded field element of 255 bits: (length: 32 bytes)
      92806dc608984dbf4e4aae478c6ec453ae979cc01ecc1a2a7cf49f5c
      ee56551b
    generator g: (length: 32 bytes)
      64e8099e3ea682cfdc5cb665c057ebb514d06bf23ebc9f743b51b822
      42327074
~~~

####  Testvectors as JSON file encoded as BASE64


~~~ test-vectors
 #eyJIIjogIlNIQS01MTIiLCAiSC5zX2luX2J5dGVzIjogMTI4LCAiUFJTIjogIlVHRn
 #pjM2R2Y21RPSIsICJaUEFEIGxlbmd0aCI6IDEwOSwgIkRTSSI6ICJRMUJoWTJVeU5U
 #VT0iLCAiQ0kiOiAiYjJNTFFsOXlaWE53YjI1a1pYSUxRVjlwYm1sMGFXRjBiM0k9Ii
 #wgInNpZCI6ICJma3RIa2Rhbzd3R2JrMng1KzM4c1Z3PT0iLCAiZ2VuZXJhdG9yX3N0
 #cmluZyhHLkRTSSxQUlMsQ0ksc2lkLEguc19pbl9ieXRlcykiOiAiQ0VOUVlXTmxNal
 #UxQ0ZCaGMzTjNiM0prYlFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB
 #QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU
 #FBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB
 #QUFBQUFBQUFBQUFBYWIyTUxRbDl5WlhOd2IyNWtaWElMUVY5cGJtbDBhV0YwYjNJUW
 #ZrdEhrZGFvN3dHYmsyeDUrMzhzVnc9PSIsICJoYXNoIGdlbmVyYXRvciBzdHJpbmci
 #OiAia29CdHhnaVlUYjlPU3E1SGpHN0VVNjZYbk1BZXpCb3FmUFNmWE81V1ZScz0iLC
 #AiZGVjb2RlZCBmaWVsZCBlbGVtZW50IG9mIDI1NSBiaXRzIjogImtvQnR4Z2lZVGI5
 #T1NxNUhqRzdFVTY2WG5NQWV6Qm9xZlBTZlhPNVdWUnM9IiwgImdlbmVyYXRvciBnIj
 #ogIlpPZ0puajZtZ3MvY1hMWmx3RmZydFJUUWEvSSt2SjkwTzFHNElrSXljSFE9In0=
~~~


###  Test vector for message from A

~~~
  Inputs
    ADa = b'ADa'
    ya (little endian): (length: 32 bytes)
      21b4f4bd9e64ed355c3eb676a28ebedaf6d8f17bdc365995b3190971
      53044080
  Outputs
    Ya: (length: 32 bytes)
      1b02dad6dbd29a07b6d28c9e04cb2f184f0734350e32bb7e62ff9dbc
      fdb63d15
~~~

###  Test vector for message from B

~~~
  Inputs
    ADb = b'ADb'
    yb (little endian): (length: 32 bytes)
      848b0779ff415f0af4ea14df9dd1d3c29ac41d836c7808896c4eba19
      c51ac40a
  Outputs
    Yb: (length: 32 bytes)
      20cda5955f82c4931545bcbf40758ce1010d7db4db2a907013d79c7a
      8fcf957f
~~~

###  Test vector for secret points K

~~~
    scalar_mult_vfy(ya,Yb): (length: 32 bytes)
      f97fdfcfff1c983ed6283856a401de3191ca919902b323c5f950c970
      3df7297a
    scalar_mult_vfy(yb,Ya): (length: 32 bytes)
      f97fdfcfff1c983ed6283856a401de3191ca919902b323c5f950c970
      3df7297a
~~~


###  Test vector for ISK calculation initiator/responder

~~~
    transcript_ir(Ya,ADa,Yb,ADb): (length: 74 bytes)
      201b02dad6dbd29a07b6d28c9e04cb2f184f0734350e32bb7e62ff9d
      bcfdb63d15034144612020cda5955f82c4931545bcbf40758ce1010d
      7db4db2a907013d79c7a8fcf957f03414462
    DSI = G.DSI_ISK, b'CPace255_ISK': (length: 12 bytes)
      43506163653235355f49534b
    lv_cat(DSI,sid,K)||transcript_ir(Ya,ADa,Yb,ADb):
    (length: 137 bytes)
      0c43506163653235355f49534b107e4b4791d6a8ef019b936c79fb7f
      2c5720f97fdfcfff1c983ed6283856a401de3191ca919902b323c5f9
      50c9703df7297a201b02dad6dbd29a07b6d28c9e04cb2f184f073435
      0e32bb7e62ff9dbcfdb63d15034144612020cda5955f82c4931545bc
      bf40758ce1010d7db4db2a907013d79c7a8fcf957f03414462
    ISK result: (length: 64 bytes)
      a051ee5ee2499d16da3f69f430218b8ea94a18a45b67f9e86495b382
      c33d14a5c38cecc0cc834f960e39e0d1bf7d76b9ef5d54eecc5e0f38
      6c97ad12da8c3d5f
~~~

###  Test vector for ISK calculation parallel execution

~~~
    transcript_oc(Ya,ADa,Yb,ADb): (length: 76 bytes)
      6f632020cda5955f82c4931545bcbf40758ce1010d7db4db2a907013
      d79c7a8fcf957f03414462201b02dad6dbd29a07b6d28c9e04cb2f18
      4f0734350e32bb7e62ff9dbcfdb63d1503414461
    DSI = G.DSI_ISK, b'CPace255_ISK': (length: 12 bytes)
      43506163653235355f49534b
    lv_cat(DSI,sid,K)||transcript_oc(Ya,ADa,Yb,ADb):
    (length: 139 bytes)
      0c43506163653235355f49534b107e4b4791d6a8ef019b936c79fb7f
      2c5720f97fdfcfff1c983ed6283856a401de3191ca919902b323c5f9
      50c9703df7297a6f632020cda5955f82c4931545bcbf40758ce1010d
      7db4db2a907013d79c7a8fcf957f03414462201b02dad6dbd29a07b6
      d28c9e04cb2f184f0734350e32bb7e62ff9dbcfdb63d1503414461
    ISK result: (length: 64 bytes)
      5cc27e49679423f81a37d7521d9fb1327c840d2ea4a1543652e7de5c
      abb89ebad27d24761b3288a3fd5764b441ecb78d30abc26161ff45ea
      297bb311dde04727
~~~

###  Test vector for optional output of session id

~~~
    H.hash(b"CPaceSidOut" + transcript_ir(Ya,ADa, Yb,ADb)):
    (length: 64 bytes)
      f7ae11ac3ee85c3c42d8bd51ba823fbe17158f43d34a1296f1cb2567
      bcc71dc8b201a134b566b468aad8fd04f02f96e3caf9d5601f7ed760
      a0a951a5a861b5e7
    H.hash(b"CPaceSidOut" + transcript_oc(Ya,ADa, Yb,ADb)):
    (length: 64 bytes)
      a38389e34fa492788c1df43b06b427710491174e53c33b01362a490d
      116fe1b7e870aa6e2a7fc018725e3b7f969f7508042e44cd3863f39a
      a75026a190d1902b
~~~

###  Corresponding C programming language initializers

~~~ c
const unsigned char tc_PRS[] = {
 0x50,0x61,0x73,0x73,0x77,0x6f,0x72,0x64,
};
const unsigned char tc_CI[] = {
 0x6f,0x63,0x0b,0x42,0x5f,0x72,0x65,0x73,0x70,0x6f,0x6e,0x64,
 0x65,0x72,0x0b,0x41,0x5f,0x69,0x6e,0x69,0x74,0x69,0x61,0x74,
 0x6f,0x72,
};
const unsigned char tc_sid[] = {
 0x7e,0x4b,0x47,0x91,0xd6,0xa8,0xef,0x01,0x9b,0x93,0x6c,0x79,
 0xfb,0x7f,0x2c,0x57,
};
const unsigned char tc_g[] = {
 0x64,0xe8,0x09,0x9e,0x3e,0xa6,0x82,0xcf,0xdc,0x5c,0xb6,0x65,
 0xc0,0x57,0xeb,0xb5,0x14,0xd0,0x6b,0xf2,0x3e,0xbc,0x9f,0x74,
 0x3b,0x51,0xb8,0x22,0x42,0x32,0x70,0x74,
};
const unsigned char tc_ya[] = {
 0x21,0xb4,0xf4,0xbd,0x9e,0x64,0xed,0x35,0x5c,0x3e,0xb6,0x76,
 0xa2,0x8e,0xbe,0xda,0xf6,0xd8,0xf1,0x7b,0xdc,0x36,0x59,0x95,
 0xb3,0x19,0x09,0x71,0x53,0x04,0x40,0x80,
};
const unsigned char tc_ADa[] = {
 0x41,0x44,0x61,
};
const unsigned char tc_Ya[] = {
 0x1b,0x02,0xda,0xd6,0xdb,0xd2,0x9a,0x07,0xb6,0xd2,0x8c,0x9e,
 0x04,0xcb,0x2f,0x18,0x4f,0x07,0x34,0x35,0x0e,0x32,0xbb,0x7e,
 0x62,0xff,0x9d,0xbc,0xfd,0xb6,0x3d,0x15,
};
const unsigned char tc_yb[] = {
 0x84,0x8b,0x07,0x79,0xff,0x41,0x5f,0x0a,0xf4,0xea,0x14,0xdf,
 0x9d,0xd1,0xd3,0xc2,0x9a,0xc4,0x1d,0x83,0x6c,0x78,0x08,0x89,
 0x6c,0x4e,0xba,0x19,0xc5,0x1a,0xc4,0x0a,
};
const unsigned char tc_ADb[] = {
 0x41,0x44,0x62,
};
const unsigned char tc_Yb[] = {
 0x20,0xcd,0xa5,0x95,0x5f,0x82,0xc4,0x93,0x15,0x45,0xbc,0xbf,
 0x40,0x75,0x8c,0xe1,0x01,0x0d,0x7d,0xb4,0xdb,0x2a,0x90,0x70,
 0x13,0xd7,0x9c,0x7a,0x8f,0xcf,0x95,0x7f,
};
const unsigned char tc_K[] = {
 0xf9,0x7f,0xdf,0xcf,0xff,0x1c,0x98,0x3e,0xd6,0x28,0x38,0x56,
 0xa4,0x01,0xde,0x31,0x91,0xca,0x91,0x99,0x02,0xb3,0x23,0xc5,
 0xf9,0x50,0xc9,0x70,0x3d,0xf7,0x29,0x7a,
};
const unsigned char tc_ISK_IR[] = {
 0xa0,0x51,0xee,0x5e,0xe2,0x49,0x9d,0x16,0xda,0x3f,0x69,0xf4,
 0x30,0x21,0x8b,0x8e,0xa9,0x4a,0x18,0xa4,0x5b,0x67,0xf9,0xe8,
 0x64,0x95,0xb3,0x82,0xc3,0x3d,0x14,0xa5,0xc3,0x8c,0xec,0xc0,
 0xcc,0x83,0x4f,0x96,0x0e,0x39,0xe0,0xd1,0xbf,0x7d,0x76,0xb9,
 0xef,0x5d,0x54,0xee,0xcc,0x5e,0x0f,0x38,0x6c,0x97,0xad,0x12,
 0xda,0x8c,0x3d,0x5f,
};
const unsigned char tc_ISK_SY[] = {
 0x5c,0xc2,0x7e,0x49,0x67,0x94,0x23,0xf8,0x1a,0x37,0xd7,0x52,
 0x1d,0x9f,0xb1,0x32,0x7c,0x84,0x0d,0x2e,0xa4,0xa1,0x54,0x36,
 0x52,0xe7,0xde,0x5c,0xab,0xb8,0x9e,0xba,0xd2,0x7d,0x24,0x76,
 0x1b,0x32,0x88,0xa3,0xfd,0x57,0x64,0xb4,0x41,0xec,0xb7,0x8d,
 0x30,0xab,0xc2,0x61,0x61,0xff,0x45,0xea,0x29,0x7b,0xb3,0x11,
 0xdd,0xe0,0x47,0x27,
};
const unsigned char tc_ISK_SY[] = {
 0x5c,0xc2,0x7e,0x49,0x67,0x94,0x23,0xf8,0x1a,0x37,0xd7,0x52,
 0x1d,0x9f,0xb1,0x32,0x7c,0x84,0x0d,0x2e,0xa4,0xa1,0x54,0x36,
 0x52,0xe7,0xde,0x5c,0xab,0xb8,0x9e,0xba,0xd2,0x7d,0x24,0x76,
 0x1b,0x32,0x88,0xa3,0xfd,0x57,0x64,0xb4,0x41,0xec,0xb7,0x8d,
 0x30,0xab,0xc2,0x61,0x61,0xff,0x45,0xea,0x29,0x7b,0xb3,0x11,
 0xdd,0xe0,0x47,0x27,
};
const unsigned char tc_sid_out_ir[] = {
 0xf7,0xae,0x11,0xac,0x3e,0xe8,0x5c,0x3c,0x42,0xd8,0xbd,0x51,
 0xba,0x82,0x3f,0xbe,0x17,0x15,0x8f,0x43,0xd3,0x4a,0x12,0x96,
 0xf1,0xcb,0x25,0x67,0xbc,0xc7,0x1d,0xc8,0xb2,0x01,0xa1,0x34,
 0xb5,0x66,0xb4,0x68,0xaa,0xd8,0xfd,0x04,0xf0,0x2f,0x96,0xe3,
 0xca,0xf9,0xd5,0x60,0x1f,0x7e,0xd7,0x60,0xa0,0xa9,0x51,0xa5,
 0xa8,0x61,0xb5,0xe7,
};
const unsigned char tc_sid_out_oc[] = {
 0xa3,0x83,0x89,0xe3,0x4f,0xa4,0x92,0x78,0x8c,0x1d,0xf4,0x3b,
 0x06,0xb4,0x27,0x71,0x04,0x91,0x17,0x4e,0x53,0xc3,0x3b,0x01,
 0x36,0x2a,0x49,0x0d,0x11,0x6f,0xe1,0xb7,0xe8,0x70,0xaa,0x6e,
 0x2a,0x7f,0xc0,0x18,0x72,0x5e,0x3b,0x7f,0x96,0x9f,0x75,0x08,
 0x04,0x2e,0x44,0xcd,0x38,0x63,0xf3,0x9a,0xa7,0x50,0x26,0xa1,
 0x90,0xd1,0x90,0x2b,
};
~~~


###  Testvectors as JSON file encoded as BASE64


~~~ test-vectors
 #eyJQUlMiOiAiVUdGemMzZHZjbVE9IiwgIkNJIjogImIyTUxRbDl5WlhOd2IyNWtaWE
 #lMUVY5cGJtbDBhV0YwYjNJPSIsICJzaWQiOiAiZmt0SGtkYW83d0diazJ4NSszOHNW
 #dz09IiwgImciOiAiWk9nSm5qNm1ncy9jWExabHdGZnJ0UlRRYS9JK3ZKOTBPMUc0SW
 #tJeWNIUT0iLCAieWEiOiAiSWJUMHZaNWs3VFZjUHJaMm9vNisydmJZOFh2Y05sbVZz
 #eGtKY1ZNRVFJQT0iLCAiQURhIjogIlFVUmgiLCAiWWEiOiAiR3dMYTF0dlNtZ2UyMG
 #95ZUJNc3ZHRThITkRVT01ydCtZditkdlAyMlBSVT0iLCAieWIiOiAiaElzSGVmOUJY
 #d3IwNmhUZm5kSFR3cHJFSFlOc2VBaUpiRTY2R2NVYXhBbz0iLCAiQURiIjogIlFVUm
 #kiLCAiWWIiOiAiSU0ybGxWK0N4Sk1WUmJ5L1FIV000UUVOZmJUYktwQndFOWVjZW8v
 #UGxYOD0iLCAiSyI6ICIrWC9mei84Y21EN1dLRGhXcEFIZU1aSEtrWmtDc3lQRitWRE
 #pjRDMzS1hvPSIsICJJU0tfSVIiOiAib0ZIdVh1SkpuUmJhUDJuME1DR0xqcWxLR0tS
 #Ylovbm9aSld6Z3NNOUZLWERqT3pBeklOUGxnNDU0TkcvZlhhNTcxMVU3c3hlRHpoc2
 #w2MFMyb3c5WHc9PSIsICJJU0tfU1kiOiAiWE1KK1NXZVVJL2dhTjlkU0haK3hNbnlF
 #RFM2a29WUTJVdWZlWEt1NG5yclNmU1IyR3pLSW8vMVhaTFJCN0xlTk1LdkNZV0gvUm
 #VvcGU3TVIzZUJISnc9PSIsICJzaWRfb3V0cHV0X2lyIjogIjk2NFJyRDdvWER4QzJM
 #MVJ1b0kvdmhjVmowUFRTaEtXOGNzbFo3ekhIY2l5QWFFMHRXYTBhS3JZL1FUd0w1Ym
 #p5dm5WWUI5KzEyQ2dxVkdscUdHMTV3PT0iLCAic2lkX291dHB1dF9vYyI6ICJvNE9K
 #NDAra2tuaU1IZlE3QnJRbmNRU1JGMDVUd3pzQk5pcEpEUkZ2NGJmb2NLcHVLbi9BR0
 #hKZU8zK1duM1VJQkM1RXpUaGo4NXFuVUNhaGtOR1FLdz09In0=
~~~


### Test vectors for G\_X25519.scalar\_mult\_vfy: low order points

Test vectors for which G\_X25519.scalar\_mult\_vfy(s\_in,ux) must return the neutral
element or would return the neutral element if bit #255 of field element
representation was not correctly cleared. (The decodeUCoordinate function from RFC7748 mandates clearing bit #255 for field element representations for use in the X25519 function.).

~~~
u0: 0000000000000000000000000000000000000000000000000000000000000000
u1: 0100000000000000000000000000000000000000000000000000000000000000
u2: ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f
u3: e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800
u4: 5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157
u5: edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f
u6: daffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
u7: eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f
u8: dbffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
u9: d9ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
ua: cdeb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b880
ub: 4c9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f11d7

u0 ... ub MUST be verified to produce the correct results q0 ... qb:

Additionally, u0,u1,u2,u3,u4,u5 and u7 MUST trigger the abort case
when included in message from A or B.

s = af46e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449aff
qN = G_X25519.scalar_mult_vfy(s, uX)
q0: 0000000000000000000000000000000000000000000000000000000000000000
q1: 0000000000000000000000000000000000000000000000000000000000000000
q2: 0000000000000000000000000000000000000000000000000000000000000000
q3: 0000000000000000000000000000000000000000000000000000000000000000
q4: 0000000000000000000000000000000000000000000000000000000000000000
q5: 0000000000000000000000000000000000000000000000000000000000000000
q6: d8e2c776bbacd510d09fd9278b7edcd25fc5ae9adfba3b6e040e8d3b71b21806
q7: 0000000000000000000000000000000000000000000000000000000000000000
q8: c85c655ebe8be44ba9c0ffde69f2fe10194458d137f09bbff725ce58803cdb38
q9: db64dafa9b8fdd136914e61461935fe92aa372cb056314e1231bc4ec12417456
qa: e062dcd5376d58297be2618c7498f55baa07d7e03184e8aada20bca28888bf7a
qb: 993c6ad11c4c29da9a56f7691fd0ff8d732e49de6250b6c2e80003ff4629a175
~~~


####  Testvectors as JSON file encoded as BASE64


~~~ test-vectors
 #eyJJbnZhbGlkIFkwIjogIkFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU
 #FBQUFBQUFBQUE9IiwgIkludmFsaWQgWTEiOiAiQVFBQUFBQUFBQUFBQUFBQUFBQUFB
 #QUFBQUFBQUFBQUFBQUFBQUFBQUFBQT0iLCAiSW52YWxpZCBZMiI6ICI3UC8vLy8vLy
 #8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLzM4PSIsICJJbnZhbGlkIFkz
 #IjogIjRPdDZmRHRCdUs0V1Z1UDY4Wi9FYXRvSmpldWNNckg5aG1JRkZsOUp1QUE9Ii
 #wgIkludmFsaWQgWTQiOiAiWDV5VnZLTlFqQ1N4MExGVm5JUHZXd1JFWE1SWUhJNkcy
 #Q0pPM2RDZkVWYz0iLCAiSW52YWxpZCBZNSI6ICI3Zi8vLy8vLy8vLy8vLy8vLy8vLy
 #8vLy8vLy8vLy8vLy8vLy8vLy8vLzM4PSIsICJJbnZhbGlkIFk2IjogIjJ2Ly8vLy8v
 #Ly8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLzg9IiwgIkludmFsaWQgWT
 #ciOiAiN3YvLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8zOD0i
 #LCAiSW52YWxpZCBZOCI6ICIyLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy
 #8vLy8vLy8vLy84PSIsICJJbnZhbGlkIFk5IjogIjJmLy8vLy8vLy8vLy8vLy8vLy8v
 #Ly8vLy8vLy8vLy8vLy8vLy8vLy8vLzg9IiwgIkludmFsaWQgWTEwIjogInpldDZmRH
 #RCdUs0V1Z1UDY4Wi9FYXRvSmpldWNNckg5aG1JRkZsOUp1SUE9IiwgIkludmFsaWQg
 #WTExIjogIlRKeVZ2S05RakNTeDBMRlZuSVB2V3dSRVhNUllISTZHMkNKTzNkQ2ZFZG
 #M9In0=
~~~

##  Test vector for CPace using group X448 and hash SHAKE-256


###  Test vectors for calculate\_generator with group X448

~~~
  Inputs
    H   = SHAKE-256 with input block size 136 bytes.
    PRS = b'Password' ; ZPAD length: 117 ; DSI = b'CPace448'
    CI = b'oc\x0bB_responder\x0bA_initiator'
    CI = 6f630b425f726573706f6e6465720b415f696e69746961746f72
    sid = 5223e0cdc45d6575668d64c552004124
  Outputs
    generator_string(G.DSI,PRS,CI,sid,H.s_in_bytes):
    (length: 180 bytes)
      0843506163653434380850617373776f726475000000000000000000
      00000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000001a6f630b
      425f726573706f6e6465720b415f696e69746961746f72105223e0cd
      c45d6575668d64c552004124
    hash generator string: (length: 56 bytes)
      98b713f84529194d719a7d86cb0f504b8afeb05354d68747e18b2e7c
      c8b6da526085e4263bd8bea7d69e479ebad09e30ae062e5d089da7f3
    decoded field element of 448 bits: (length: 56 bytes)
      98b713f84529194d719a7d86cb0f504b8afeb05354d68747e18b2e7c
      c8b6da526085e4263bd8bea7d69e479ebad09e30ae062e5d089da7f3
    generator g: (length: 56 bytes)
      e293b7ccf61ca7eb928a26391cf38b660f874a001fdf0bf3a91fd182
      f2b6d83e61a9377ede127eba7e0d4c08592eaff33d4aa705d6ce54bb
~~~

####  Testvectors as JSON file encoded as BASE64


~~~ test-vectors
 #eyJIIjogIlNIQUtFLTI1NiIsICJILnNfaW5fYnl0ZXMiOiAxMzYsICJQUlMiOiAiVU
 #dGemMzZHZjbVE9IiwgIlpQQUQgbGVuZ3RoIjogMTE3LCAiRFNJIjogIlExQmhZMlUw
 #TkRnPSIsICJDSSI6ICJiMk1MUWw5eVpYTndiMjVrWlhJTFFWOXBibWwwYVdGMGIzST
 #0iLCAic2lkIjogIlVpUGd6Y1JkWlhWbWpXVEZVZ0JCSkE9PSIsICJnZW5lcmF0b3Jf
 #c3RyaW5nKEcuRFNJLFBSUyxDSSxzaWQsSC5zX2luX2J5dGVzKSI6ICJDRU5RWVdObE
 #5EUTRDRkJoYzNOM2IzSmtkUUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB
 #QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU
 #FBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB
 #QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQnB2WXd0Q1gzSmxjM0J2Ym1SbGNndEJYMm
 #x1YVhScFlYUnZjaEJTSStETnhGMWxkV2FOWk1WU0FFRWsiLCAiaGFzaCBnZW5lcmF0
 #b3Igc3RyaW5nIjogIm1MY1QrRVVwR1UxeG1uMkd5dzlRUzRyK3NGTlUxb2RINFlzdW
 #ZNaTIybEpnaGVRbU85aStwOWFlUjU2NjBKNHdyZ1l1WFFpZHAvTT0iLCAiZGVjb2Rl
 #ZCBmaWVsZCBlbGVtZW50IG9mIDQ0OCBiaXRzIjogIm1MY1QrRVVwR1UxeG1uMkd5dz
 #lRUzRyK3NGTlUxb2RINFlzdWZNaTIybEpnaGVRbU85aStwOWFlUjU2NjBKNHdyZ1l1
 #WFFpZHAvTT0iLCAiZ2VuZXJhdG9yIGciOiAiNHBPM3pQWWNwK3VTaWlZNUhQT0xaZy
 #tIU2dBZjN3dnpxUi9SZ3ZLMjJENWhxVGQrM2hKK3VuNE5UQWhaTHEvelBVcW5CZGJP
 #VkxzPSJ9
~~~


###  Test vector for message from A

~~~
  Inputs
    ADa = b'ADa'
    ya (little endian): (length: 56 bytes)
      21b4f4bd9e64ed355c3eb676a28ebedaf6d8f17bdc365995b3190971
      53044080516bd083bfcce66121a3072646994c8430cc382b8dc543e8
  Outputs
    Ya: (length: 56 bytes)
      7f645772cc209bf9fd9d76dbb10283bea71b12235e3bb21878d5e56a
      70506e165743a632de98eca9932c5d2efe36500a59b2fdaed0d8a148
~~~

###  Test vector for message from B

~~~
  Inputs
    ADb = b'ADb'
    yb (little endian): (length: 56 bytes)
      848b0779ff415f0af4ea14df9dd1d3c29ac41d836c7808896c4eba19
      c51ac40a439caf5e61ec88c307c7d619195229412eaa73fb2a5ea20d
  Outputs
    Yb: (length: 56 bytes)
      a4690a0750c42b288ddd0ba08e3f4902dfe70bae5c9e2c6ee95844de
      f2692be77646b20d3b429f8da00d21433ee0891c667658d8d0c48e38
~~~

###  Test vector for secret points K

~~~
    scalar_mult_vfy(ya,Yb): (length: 56 bytes)
      db3fff9da59576715b04d4df8dc8d18db2430e57bbed337dbeee5bb2
      d6ab6ceddc9c75c5c0b17fad7eb724daa12f8f1903dd6c2cede6135a
    scalar_mult_vfy(yb,Ya): (length: 56 bytes)
      db3fff9da59576715b04d4df8dc8d18db2430e57bbed337dbeee5bb2
      d6ab6ceddc9c75c5c0b17fad7eb724daa12f8f1903dd6c2cede6135a
~~~


###  Test vector for ISK calculation initiator/responder

~~~
    transcript_ir(Ya,ADa,Yb,ADb): (length: 122 bytes)
      387f645772cc209bf9fd9d76dbb10283bea71b12235e3bb21878d5e5
      6a70506e165743a632de98eca9932c5d2efe36500a59b2fdaed0d8a1
      480341446138a4690a0750c42b288ddd0ba08e3f4902dfe70bae5c9e
      2c6ee95844def2692be77646b20d3b429f8da00d21433ee0891c6676
      58d8d0c48e3803414462
    DSI = G.DSI_ISK, b'CPace448_ISK': (length: 12 bytes)
      43506163653434385f49534b
    lv_cat(DSI,sid,K)||transcript_ir(Ya,ADa,Yb,ADb):
    (length: 209 bytes)
      0c43506163653434385f49534b105223e0cdc45d6575668d64c55200
      412438db3fff9da59576715b04d4df8dc8d18db2430e57bbed337dbe
      ee5bb2d6ab6ceddc9c75c5c0b17fad7eb724daa12f8f1903dd6c2ced
      e6135a387f645772cc209bf9fd9d76dbb10283bea71b12235e3bb218
      78d5e56a70506e165743a632de98eca9932c5d2efe36500a59b2fdae
      d0d8a1480341446138a4690a0750c42b288ddd0ba08e3f4902dfe70b
      ae5c9e2c6ee95844def2692be77646b20d3b429f8da00d21433ee089
      1c667658d8d0c48e3803414462
    ISK result: (length: 64 bytes)
      599892a2078a8c988181625e1e5e5f7a6163f7d72f21b93ebefba0f1
      7ff7ea3aa0594bd569cf74264157b3c0087bdccf2f59c77156628487
      f5ca1645b8e9d05b
~~~

###  Test vector for ISK calculation parallel execution

~~~
    transcript_oc(Ya,ADa,Yb,ADb): (length: 124 bytes)
      6f6338a4690a0750c42b288ddd0ba08e3f4902dfe70bae5c9e2c6ee9
      5844def2692be77646b20d3b429f8da00d21433ee0891c667658d8d0
      c48e3803414462387f645772cc209bf9fd9d76dbb10283bea71b1223
      5e3bb21878d5e56a70506e165743a632de98eca9932c5d2efe36500a
      59b2fdaed0d8a14803414461
    DSI = G.DSI_ISK, b'CPace448_ISK': (length: 12 bytes)
      43506163653434385f49534b
    lv_cat(DSI,sid,K)||transcript_oc(Ya,ADa,Yb,ADb):
    (length: 211 bytes)
      0c43506163653434385f49534b105223e0cdc45d6575668d64c55200
      412438db3fff9da59576715b04d4df8dc8d18db2430e57bbed337dbe
      ee5bb2d6ab6ceddc9c75c5c0b17fad7eb724daa12f8f1903dd6c2ced
      e6135a6f6338a4690a0750c42b288ddd0ba08e3f4902dfe70bae5c9e
      2c6ee95844def2692be77646b20d3b429f8da00d21433ee0891c6676
      58d8d0c48e3803414462387f645772cc209bf9fd9d76dbb10283bea7
      1b12235e3bb21878d5e56a70506e165743a632de98eca9932c5d2efe
      36500a59b2fdaed0d8a14803414461
    ISK result: (length: 64 bytes)
      3ac73f03030296aa591f01326b18afa47e1189129cd06ae8dfb05e6e
      b1310cde948b59eef0755365c06a339266afe594948c56a538d98a65
      767113938a9a78d8
~~~

###  Test vector for optional output of session id

~~~
    H.hash(b"CPaceSidOut" + transcript_ir(Ya,ADa, Yb,ADb)):
    (length: 64 bytes)
      00a2333a79481abe71efd6594d7bbaac55c808482e869c9b65c4b53d
      7100d3da8f3cabd59fa0c1f22d6d2f9ac0c093962292798fca2c0b93
      268974cad75d575a
    H.hash(b"CPaceSidOut" + transcript_oc(Ya,ADa, Yb,ADb)):
    (length: 64 bytes)
      a1ce90537a8d53b06d77e79fe719461cc5ed8300d21d1866a59f9638
      601833f57a8b5e88db9a52abfa1b4e8a651a400bc9205082aad81eb3
      11c44373b9a19eff
~~~

###  Corresponding C programming language initializers

~~~ c
const unsigned char tc_PRS[] = {
 0x50,0x61,0x73,0x73,0x77,0x6f,0x72,0x64,
};
const unsigned char tc_CI[] = {
 0x6f,0x63,0x0b,0x42,0x5f,0x72,0x65,0x73,0x70,0x6f,0x6e,0x64,
 0x65,0x72,0x0b,0x41,0x5f,0x69,0x6e,0x69,0x74,0x69,0x61,0x74,
 0x6f,0x72,
};
const unsigned char tc_sid[] = {
 0x52,0x23,0xe0,0xcd,0xc4,0x5d,0x65,0x75,0x66,0x8d,0x64,0xc5,
 0x52,0x00,0x41,0x24,
};
const unsigned char tc_g[] = {
 0xe2,0x93,0xb7,0xcc,0xf6,0x1c,0xa7,0xeb,0x92,0x8a,0x26,0x39,
 0x1c,0xf3,0x8b,0x66,0x0f,0x87,0x4a,0x00,0x1f,0xdf,0x0b,0xf3,
 0xa9,0x1f,0xd1,0x82,0xf2,0xb6,0xd8,0x3e,0x61,0xa9,0x37,0x7e,
 0xde,0x12,0x7e,0xba,0x7e,0x0d,0x4c,0x08,0x59,0x2e,0xaf,0xf3,
 0x3d,0x4a,0xa7,0x05,0xd6,0xce,0x54,0xbb,
};
const unsigned char tc_ya[] = {
 0x21,0xb4,0xf4,0xbd,0x9e,0x64,0xed,0x35,0x5c,0x3e,0xb6,0x76,
 0xa2,0x8e,0xbe,0xda,0xf6,0xd8,0xf1,0x7b,0xdc,0x36,0x59,0x95,
 0xb3,0x19,0x09,0x71,0x53,0x04,0x40,0x80,0x51,0x6b,0xd0,0x83,
 0xbf,0xcc,0xe6,0x61,0x21,0xa3,0x07,0x26,0x46,0x99,0x4c,0x84,
 0x30,0xcc,0x38,0x2b,0x8d,0xc5,0x43,0xe8,
};
const unsigned char tc_ADa[] = {
 0x41,0x44,0x61,
};
const unsigned char tc_Ya[] = {
 0x7f,0x64,0x57,0x72,0xcc,0x20,0x9b,0xf9,0xfd,0x9d,0x76,0xdb,
 0xb1,0x02,0x83,0xbe,0xa7,0x1b,0x12,0x23,0x5e,0x3b,0xb2,0x18,
 0x78,0xd5,0xe5,0x6a,0x70,0x50,0x6e,0x16,0x57,0x43,0xa6,0x32,
 0xde,0x98,0xec,0xa9,0x93,0x2c,0x5d,0x2e,0xfe,0x36,0x50,0x0a,
 0x59,0xb2,0xfd,0xae,0xd0,0xd8,0xa1,0x48,
};
const unsigned char tc_yb[] = {
 0x84,0x8b,0x07,0x79,0xff,0x41,0x5f,0x0a,0xf4,0xea,0x14,0xdf,
 0x9d,0xd1,0xd3,0xc2,0x9a,0xc4,0x1d,0x83,0x6c,0x78,0x08,0x89,
 0x6c,0x4e,0xba,0x19,0xc5,0x1a,0xc4,0x0a,0x43,0x9c,0xaf,0x5e,
 0x61,0xec,0x88,0xc3,0x07,0xc7,0xd6,0x19,0x19,0x52,0x29,0x41,
 0x2e,0xaa,0x73,0xfb,0x2a,0x5e,0xa2,0x0d,
};
const unsigned char tc_ADb[] = {
 0x41,0x44,0x62,
};
const unsigned char tc_Yb[] = {
 0xa4,0x69,0x0a,0x07,0x50,0xc4,0x2b,0x28,0x8d,0xdd,0x0b,0xa0,
 0x8e,0x3f,0x49,0x02,0xdf,0xe7,0x0b,0xae,0x5c,0x9e,0x2c,0x6e,
 0xe9,0x58,0x44,0xde,0xf2,0x69,0x2b,0xe7,0x76,0x46,0xb2,0x0d,
 0x3b,0x42,0x9f,0x8d,0xa0,0x0d,0x21,0x43,0x3e,0xe0,0x89,0x1c,
 0x66,0x76,0x58,0xd8,0xd0,0xc4,0x8e,0x38,
};
const unsigned char tc_K[] = {
 0xdb,0x3f,0xff,0x9d,0xa5,0x95,0x76,0x71,0x5b,0x04,0xd4,0xdf,
 0x8d,0xc8,0xd1,0x8d,0xb2,0x43,0x0e,0x57,0xbb,0xed,0x33,0x7d,
 0xbe,0xee,0x5b,0xb2,0xd6,0xab,0x6c,0xed,0xdc,0x9c,0x75,0xc5,
 0xc0,0xb1,0x7f,0xad,0x7e,0xb7,0x24,0xda,0xa1,0x2f,0x8f,0x19,
 0x03,0xdd,0x6c,0x2c,0xed,0xe6,0x13,0x5a,
};
const unsigned char tc_ISK_IR[] = {
 0x59,0x98,0x92,0xa2,0x07,0x8a,0x8c,0x98,0x81,0x81,0x62,0x5e,
 0x1e,0x5e,0x5f,0x7a,0x61,0x63,0xf7,0xd7,0x2f,0x21,0xb9,0x3e,
 0xbe,0xfb,0xa0,0xf1,0x7f,0xf7,0xea,0x3a,0xa0,0x59,0x4b,0xd5,
 0x69,0xcf,0x74,0x26,0x41,0x57,0xb3,0xc0,0x08,0x7b,0xdc,0xcf,
 0x2f,0x59,0xc7,0x71,0x56,0x62,0x84,0x87,0xf5,0xca,0x16,0x45,
 0xb8,0xe9,0xd0,0x5b,
};
const unsigned char tc_ISK_SY[] = {
 0x3a,0xc7,0x3f,0x03,0x03,0x02,0x96,0xaa,0x59,0x1f,0x01,0x32,
 0x6b,0x18,0xaf,0xa4,0x7e,0x11,0x89,0x12,0x9c,0xd0,0x6a,0xe8,
 0xdf,0xb0,0x5e,0x6e,0xb1,0x31,0x0c,0xde,0x94,0x8b,0x59,0xee,
 0xf0,0x75,0x53,0x65,0xc0,0x6a,0x33,0x92,0x66,0xaf,0xe5,0x94,
 0x94,0x8c,0x56,0xa5,0x38,0xd9,0x8a,0x65,0x76,0x71,0x13,0x93,
 0x8a,0x9a,0x78,0xd8,
};
const unsigned char tc_ISK_SY[] = {
 0x3a,0xc7,0x3f,0x03,0x03,0x02,0x96,0xaa,0x59,0x1f,0x01,0x32,
 0x6b,0x18,0xaf,0xa4,0x7e,0x11,0x89,0x12,0x9c,0xd0,0x6a,0xe8,
 0xdf,0xb0,0x5e,0x6e,0xb1,0x31,0x0c,0xde,0x94,0x8b,0x59,0xee,
 0xf0,0x75,0x53,0x65,0xc0,0x6a,0x33,0x92,0x66,0xaf,0xe5,0x94,
 0x94,0x8c,0x56,0xa5,0x38,0xd9,0x8a,0x65,0x76,0x71,0x13,0x93,
 0x8a,0x9a,0x78,0xd8,
};
const unsigned char tc_sid_out_ir[] = {
 0x00,0xa2,0x33,0x3a,0x79,0x48,0x1a,0xbe,0x71,0xef,0xd6,0x59,
 0x4d,0x7b,0xba,0xac,0x55,0xc8,0x08,0x48,0x2e,0x86,0x9c,0x9b,
 0x65,0xc4,0xb5,0x3d,0x71,0x00,0xd3,0xda,0x8f,0x3c,0xab,0xd5,
 0x9f,0xa0,0xc1,0xf2,0x2d,0x6d,0x2f,0x9a,0xc0,0xc0,0x93,0x96,
 0x22,0x92,0x79,0x8f,0xca,0x2c,0x0b,0x93,0x26,0x89,0x74,0xca,
 0xd7,0x5d,0x57,0x5a,
};
const unsigned char tc_sid_out_oc[] = {
 0xa1,0xce,0x90,0x53,0x7a,0x8d,0x53,0xb0,0x6d,0x77,0xe7,0x9f,
 0xe7,0x19,0x46,0x1c,0xc5,0xed,0x83,0x00,0xd2,0x1d,0x18,0x66,
 0xa5,0x9f,0x96,0x38,0x60,0x18,0x33,0xf5,0x7a,0x8b,0x5e,0x88,
 0xdb,0x9a,0x52,0xab,0xfa,0x1b,0x4e,0x8a,0x65,0x1a,0x40,0x0b,
 0xc9,0x20,0x50,0x82,0xaa,0xd8,0x1e,0xb3,0x11,0xc4,0x43,0x73,
 0xb9,0xa1,0x9e,0xff,
};
~~~


###  Testvectors as JSON file encoded as BASE64


~~~ test-vectors
 #eyJQUlMiOiAiVUdGemMzZHZjbVE9IiwgIkNJIjogImIyTUxRbDl5WlhOd2IyNWtaWE
 #lMUVY5cGJtbDBhV0YwYjNJPSIsICJzaWQiOiAiVWlQZ3pjUmRaWFZtaldURlVnQkJK
 #QT09IiwgImciOiAiNHBPM3pQWWNwK3VTaWlZNUhQT0xaZytIU2dBZjN3dnpxUi9SZ3
 #ZLMjJENWhxVGQrM2hKK3VuNE5UQWhaTHEvelBVcW5CZGJPVkxzPSIsICJ5YSI6ICJJ
 #YlQwdlo1azdUVmNQcloyb282KzJ2Ylk4WHZjTmxtVnN4a0pjVk1FUUlCUmE5Q0R2OH
 #ptWVNHakJ5WkdtVXlFTU13NEs0M0ZRK2c9IiwgIkFEYSI6ICJRVVJoIiwgIllhIjog
 #ImYyUlhjc3dnbS9uOW5YYmJzUUtEdnFjYkVpTmVPN0lZZU5YbGFuQlFiaFpYUTZZeT
 #NwanNxWk1zWFM3K05sQUtXYkw5cnREWW9VZz0iLCAieWIiOiAiaElzSGVmOUJYd3Iw
 #NmhUZm5kSFR3cHJFSFlOc2VBaUpiRTY2R2NVYXhBcERuSzllWWV5SXd3ZkgxaGtaVW
 #lsQkxxcHoreXBlb2cwPSIsICJBRGIiOiAiUVVSaSIsICJZYiI6ICJwR2tLQjFERUt5
 #aU4zUXVnamo5SkF0L25DNjVjbml4dTZWaEUzdkpwSytkMlJySU5PMEtmamFBTklVTS
 #s0SWtjWm5aWTJOREVqamc9IiwgIksiOiAiMnovL25hV1ZkbkZiQk5UZmpjalJqYkpE
 #RGxlNzdUTjl2dTVic3RhcmJPM2NuSFhGd0xGL3JYNjNKTnFoTDQ4WkE5MXNMTzNtRT
 #FvPSIsICJJU0tfSVIiOiAiV1ppU29nZUtqSmlCZ1dKZUhsNWZlbUZqOTljdkliayt2
 #dnVnOFgvMzZqcWdXVXZWYWM5MEprRlhzOEFJZTl6UEwxbkhjVlppaElmMXloWkZ1T2
 #5RV3c9PSIsICJJU0tfU1kiOiAiT3NjL0F3TUNscXBaSHdFeWF4aXZwSDRSaVJLYzBH
 #cm8zN0JlYnJFeERONlVpMW51OEhWVFpjQnFNNUptcitXVWxJeFdwVGpaaW1WMmNST1
 #RpcHA0MkE9PSIsICJzaWRfb3V0cHV0X2lyIjogIkFLSXpPbmxJR3I1eDc5WlpUWHU2
 #ckZYSUNFZ3VocHliWmNTMVBYRUEwOXFQUEt2Vm42REI4aTF0TDVyQXdKT1dJcEo1aj
 #hvc0M1TW1pWFRLMTExWFdnPT0iLCAic2lkX291dHB1dF9vYyI6ICJvYzZRVTNxTlU3
 #QnRkK2VmNXhsR0hNWHRnd0RTSFJobXBaK1dPR0FZTS9WNmkxNkkyNXBTcS9vYlRvcG
 #xHa0FMeVNCUWdxcllIck1SeEVOenVhR2Uvdz09In0=
~~~


### Test vectors for G\_X448.scalar\_mult\_vfy: low order points

Test vectors for which G\_X448.scalar\_mult\_vfy(s\_in,ux) must return the neutral
element.
This includes points that are non-canonicaly encoded, i.e. have coordinate values
larger
than the field prime.

Weak points for X448 smaller than the field prime (canonical)

~~~
  u0: (length: 56 bytes)
    0000000000000000000000000000000000000000000000000000000000
    000000000000000000000000000000000000000000000000000000
  u1: (length: 56 bytes)
    0100000000000000000000000000000000000000000000000000000000
    000000000000000000000000000000000000000000000000000000
  u2: (length: 56 bytes)
    fefffffffffffffffffffffffffffffffffffffffffffffffffffffffe
    ffffffffffffffffffffffffffffffffffffffffffffffffffffff
~~~

Weak points for X448 larger or equal to the field prime (non-canonical)

~~~
  u3: (length: 56 bytes)
    fffffffffffffffffffffffffffffffffffffffffffffffffffffffffe
    ffffffffffffffffffffffffffffffffffffffffffffffffffffff
  u4: (length: 56 bytes)
    00000000000000000000000000000000000000000000000000000000ff
    ffffffffffffffffffffffffffffffffffffffffffffffffffffff

All of the above points u0 ... u4 MUST trigger the abort case
when included in the protocol messages from A or B.
~~~

Expected results for X448 resp. G\_X448.scalar\_mult\_vfy

~~~
  scalar s: (length: 56 bytes)
    af8a14218bf2a2062926d2ea9b8fe4e8b6817349b6ed2feb1e5d64d7a4
    523f15fceec70fb111e870dc58d191e66a14d3e9d482d04432cadd
  G_X448.scalar_mult_vfy(s,u0): (length: 56 bytes)
    0000000000000000000000000000000000000000000000000000000000
    000000000000000000000000000000000000000000000000000000
  G_X448.scalar_mult_vfy(s,u1): (length: 56 bytes)
    0000000000000000000000000000000000000000000000000000000000
    000000000000000000000000000000000000000000000000000000
  G_X448.scalar_mult_vfy(s,u2): (length: 56 bytes)
    0000000000000000000000000000000000000000000000000000000000
    000000000000000000000000000000000000000000000000000000
  G_X448.scalar_mult_vfy(s,u3): (length: 56 bytes)
    0000000000000000000000000000000000000000000000000000000000
    000000000000000000000000000000000000000000000000000000
  G_X448.scalar_mult_vfy(s,u4): (length: 56 bytes)
    0000000000000000000000000000000000000000000000000000000000
    000000000000000000000000000000000000000000000000000000
~~~


Test vectors for scalar_mult with nonzero outputs

~~~
  scalar s: (length: 56 bytes)
    af8a14218bf2a2062926d2ea9b8fe4e8b6817349b6ed2feb1e5d64d7a4
    523f15fceec70fb111e870dc58d191e66a14d3e9d482d04432cadd
  point coordinate u_curve on the curve: (length: 56 bytes)
    ab0c68d772ec2eb9de25c49700e46d6325e66d6aa39d7b65eb84a68c55
    69d47bd71b41f3e0d210f44e146dec8926b174acb3f940a0b82cab
  G_X448.scalar_mult_vfy(s,u_curve): (length: 56 bytes)
    3b0fa9bc40a6fdc78c9e06ff7a54c143c5d52f365607053bf0656f5142
    0496295f910a101b38edc1acd3bd240fd55dcb7a360553b8a7627e

  point coordinate u_twist on the twist: (length: 56 bytes)
    c981cd1e1f72d9c35c7d7cf6be426757c0dc8206a2fcfa564a8e7618c0
    3c0e61f9a2eb1c3e0dd97d6e9b1010f5edd03397a83f5a914cb3ff
  G_X448.scalar_mult_vfy(s,u_twist): (length: 56 bytes)
    d0a2bb7e9c5c2c627793d8342f23b759fe7d9e3320a85ca4fd61376331
    50ffd9a9148a9b75c349fac43d64bec49a6e126cc92cbfbf353961
~~~


####  Testvectors as JSON file encoded as BASE64


~~~ test-vectors
 #eyJJbnZhbGlkIFkxIjogIkFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU
 #FBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQT0iLCAiSW52
 #YWxpZCBZMiI6ICJBUUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU
 #FBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUE9IiwgIkludmFsaWQg
 #WTMiOiAiL3YvLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy83Ly8vLy
 #8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy84PSIsICJJbnZhbGlkIFk0Ijog
 #Ii8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vNy8vLy8vLy8vLy
 #8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vLy8vOD0iLCAiSW52YWxpZCBZNSI6ICJBQUFB
 #QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBUC8vLy8vLy8vLy8vLy8vLy
 #8vLy8vLy8vLy8vLy8vLy8vLy8vLzg9IiwgIlZhbGlkIChvbiBjdXJ2ZSkiOiB7InMi
 #OiAicjRvVUlZdnlvZ1lwSnRMcW00L2s2TGFCYzBtMjdTL3JIbDFrMTZSU1B4WDg3c2
 #NQc1JIb2NOeFkwWkhtYWhUVDZkU0MwRVF5eXQwPSIsICJ1X2N1cnZlIjogInF3eG8x
 #M0xzTHJuZUpjU1hBT1J0WXlYbWJXcWpuWHRsNjRTbWpGVnAxSHZYRzBIejROSVE5RT
 #RVYmV5SkpyRjByTFA1UUtDNExLcz0iLCAicmVzX2N1cnZlIjogIk93K3B2RUNtL2Nl
 #TW5nYi9lbFRCUThYVkx6WldCd1U3OEdWdlVVSUVsaWxma1FvUUd6anR3YXpUdlNRUD
 #FWM0xlallGVTdpblluND0ifSwgIlZhbGlkIChvbiB0d2lzdCkiOiB7InMiOiAicjRv
 #VUlZdnlvZ1lwSnRMcW00L2s2TGFCYzBtMjdTL3JIbDFrMTZSU1B4WDg3c2NQc1JIb2
 #NOeFkwWkhtYWhUVDZkU0MwRVF5eXQwPSIsICJ1X3R3aXN0IjogInlZSE5IaDl5MmNO
 #Y2ZYejJ2a0puVjhEY2dnYWkvUHBXU281MkdNQThEbUg1b3VzY1BnM1pmVzZiRUJEMT
 #dkQXpsNmcvV3BGTXMvOD0iLCAicmVzX3R3aXN0IjogIjBLSzdmcHhjTEdKM2s5ZzBM
 #eU8zV2Y1OW5qTWdxRnlrL1dFM1l6RlEvOW1wRklxYmRjTkorc1E5Wkw3RW1tNFNiTW
 #tzdjc4MU9XRT0ifX0=
~~~

##  Test vector for CPace using group ristretto255 and hash SHA-512


###  Test vectors for calculate\_generator with group ristretto255

~~~
  Inputs
    H   = SHA-512 with input block size 128 bytes.
    PRS = b'Password' ; ZPAD length: 100 ;
    DSI = b'CPaceRistretto255'
    CI = b'oc\x0bB_responder\x0bA_initiator'
    CI = 6f630b425f726573706f6e6465720b415f696e69746961746f72
    sid = 7e4b4791d6a8ef019b936c79fb7f2c57
  Outputs
    generator_string(G.DSI,PRS,CI,sid,H.s_in_bytes):
    (length: 172 bytes)
      11435061636552697374726574746f3235350850617373776f726464
      00000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      000000000000000000000000000000001a6f630b425f726573706f6e
      6465720b415f696e69746961746f72107e4b4791d6a8ef019b936c79
      fb7f2c57
    hash result: (length: 64 bytes)
      c63a5750e2439c17ccd8213be14fde2f87e1bc637001a97f5929c77b
      30ea0e08afbc75ace5d3d73b2842a79d01488c5fd7ea30d475ee6095
      45af1bfd1ff77c8e
    encoded generator g: (length: 32 bytes)
      a6fc82c3b8968fbb2e06fee81ca858586dea50d248f0c7ca6a18b090
      2a30b36b
~~~


####  Testvectors as JSON file encoded as BASE64


~~~ test-vectors
 #eyJIIjogIlNIQS01MTIiLCAiSC5zX2luX2J5dGVzIjogMTI4LCAiUFJTIjogIlVHRn
 #pjM2R2Y21RPSIsICJaUEFEIGxlbmd0aCI6IDEwMCwgIkRTSSI6ICJRMUJoWTJWU2FY
 #TjBjbVYwZEc4eU5UVT0iLCAiQ0kiOiAiYjJNTFFsOXlaWE53YjI1a1pYSUxRVjlwYm
 #1sMGFXRjBiM0k9IiwgInNpZCI6ICJma3RIa2Rhbzd3R2JrMng1KzM4c1Z3PT0iLCAi
 #Z2VuZXJhdG9yX3N0cmluZyhHLkRTSSxQUlMsQ0ksc2lkLEguc19pbl9ieXRlcykiOi
 #AiRVVOUVlXTmxVbWx6ZEhKbGRIUnZNalUxQ0ZCaGMzTjNiM0prWkFBQUFBQUFBQUFB
 #QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU
 #FBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB
 #QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBYWIyTUxRbDl5WlhOd2IyNWtaWElMUVY5cG
 #JtbDBhV0YwYjNJUWZrdEhrZGFvN3dHYmsyeDUrMzhzVnc9PSIsICJoYXNoIHJlc3Vs
 #dCI6ICJ4anBYVU9KRG5CZk0yQ0U3NFUvZUw0Zmh2R053QWFsL1dTbkhlekRxRGdpdn
 #ZIV3M1ZFBYT3loQ3A1MEJTSXhmMStvdzFIWHVZSlZGcnh2OUgvZDhqZz09IiwgImVu
 #Y29kZWQgZ2VuZXJhdG9yIGciOiAicHZ5Q3c3aVdqN3N1QnY3b0hLaFlXRzNxVU5KST
 #hNZkthaGl3a0Nvd3Mycz0ifQ==
~~~


###  Test vector for message from A

~~~
  Inputs
    ADa = b'ADa'
    ya (little endian): (length: 32 bytes)
      da3d23700a9e5699258aef94dc060dfda5ebb61f02a5ea77fad53f4f
      f0976d08
  Outputs
    Ya: (length: 32 bytes)
      d40fb265a7abeaee7939d91a585fe59f7053f982c296ec413c624c66
      9308f87a
~~~

###  Test vector for message from B

~~~
  Inputs
    ADb = b'ADb'
    yb (little endian): (length: 32 bytes)
      d2316b454718c35362d83d69df6320f38578ed5984651435e2949762
      d900b80d
  Outputs
    Yb: (length: 32 bytes)
      08bcf6e9777a9c313a3db6daa510f2d398403319c2341bd506a92e67
      2eb7e307
~~~

###  Test vector for secret points K

~~~
    scalar_mult_vfy(ya,Yb): (length: 32 bytes)
      e22b1ef7788f661478f3cddd4c600774fc0f41e6b711569190ff88fa
      0e607e09
    scalar_mult_vfy(yb,Ya): (length: 32 bytes)
      e22b1ef7788f661478f3cddd4c600774fc0f41e6b711569190ff88fa
      0e607e09
~~~


###  Test vector for ISK calculation initiator/responder

~~~
    transcript_ir(Ya,ADa,Yb,ADb): (length: 74 bytes)
      20d40fb265a7abeaee7939d91a585fe59f7053f982c296ec413c624c
      669308f87a034144612008bcf6e9777a9c313a3db6daa510f2d39840
      3319c2341bd506a92e672eb7e30703414462
    DSI = G.DSI_ISK, b'CPaceRistretto255_ISK':
    (length: 21 bytes)
      435061636552697374726574746f3235355f49534b
    lv_cat(DSI,sid,K)||transcript_ir(Ya,ADa,Yb,ADb):
    (length: 146 bytes)
      15435061636552697374726574746f3235355f49534b107e4b4791d6
      a8ef019b936c79fb7f2c5720e22b1ef7788f661478f3cddd4c600774
      fc0f41e6b711569190ff88fa0e607e0920d40fb265a7abeaee7939d9
      1a585fe59f7053f982c296ec413c624c669308f87a034144612008bc
      f6e9777a9c313a3db6daa510f2d398403319c2341bd506a92e672eb7
      e30703414462
    ISK result: (length: 64 bytes)
      4c5469a16b2364c4b944ebc1a79e51d1674ad47db26e8718154f59fa
      ebfaa52d8346f30aa58377117eb20d527f2cbc5c76381f7fd372e89d
      f8239f87f2e02ed1
~~~

###  Test vector for ISK calculation parallel execution

~~~
    transcript_oc(Ya,ADa,Yb,ADb): (length: 76 bytes)
      6f6320d40fb265a7abeaee7939d91a585fe59f7053f982c296ec413c
      624c669308f87a034144612008bcf6e9777a9c313a3db6daa510f2d3
      98403319c2341bd506a92e672eb7e30703414462
    DSI = G.DSI_ISK, b'CPaceRistretto255_ISK':
    (length: 21 bytes)
      435061636552697374726574746f3235355f49534b
    lv_cat(DSI,sid,K)||transcript_oc(Ya,ADa,Yb,ADb):
    (length: 148 bytes)
      15435061636552697374726574746f3235355f49534b107e4b4791d6
      a8ef019b936c79fb7f2c5720e22b1ef7788f661478f3cddd4c600774
      fc0f41e6b711569190ff88fa0e607e096f6320d40fb265a7abeaee79
      39d91a585fe59f7053f982c296ec413c624c669308f87a0341446120
      08bcf6e9777a9c313a3db6daa510f2d398403319c2341bd506a92e67
      2eb7e30703414462
    ISK result: (length: 64 bytes)
      980dcc5a1c52ceea031e75f38ed266586616488c5c5780285fcbcf79
      087c7bcdbd993502eee606b718ba31e840a000a7b7befe15ea427c5c
      fe88344fa1237f35
~~~

###  Test vector for optional output of session id

~~~
    H.hash(b"CPaceSidOut" + transcript_ir(Ya,ADa, Yb,ADb)):
    (length: 64 bytes)
      2a76d3bbc499dfdc4dcacc9ff042f4e1a54e3843258e100ccd7c60f0
      a541f9d3ebf025e68a460dde218bd39f0711bc6fa11409c9d7b69d8c
      cf6b32fc51ddb699
    H.hash(b"CPaceSidOut" + transcript_oc(Ya,ADa, Yb,ADb)):
    (length: 64 bytes)
      ca4b50700c46203ccd10bc0e9f31095e508189cb59857537be561048
      d34b9ed9a9697af11c998f484c3d783b0b531434caa6835d4c32344f
      cd17160c9c348fc7
~~~

###  Corresponding C programming language initializers

~~~ c
const unsigned char tc_PRS[] = {
 0x50,0x61,0x73,0x73,0x77,0x6f,0x72,0x64,
};
const unsigned char tc_CI[] = {
 0x6f,0x63,0x0b,0x42,0x5f,0x72,0x65,0x73,0x70,0x6f,0x6e,0x64,
 0x65,0x72,0x0b,0x41,0x5f,0x69,0x6e,0x69,0x74,0x69,0x61,0x74,
 0x6f,0x72,
};
const unsigned char tc_sid[] = {
 0x7e,0x4b,0x47,0x91,0xd6,0xa8,0xef,0x01,0x9b,0x93,0x6c,0x79,
 0xfb,0x7f,0x2c,0x57,
};
const unsigned char tc_g[] = {
 0xa6,0xfc,0x82,0xc3,0xb8,0x96,0x8f,0xbb,0x2e,0x06,0xfe,0xe8,
 0x1c,0xa8,0x58,0x58,0x6d,0xea,0x50,0xd2,0x48,0xf0,0xc7,0xca,
 0x6a,0x18,0xb0,0x90,0x2a,0x30,0xb3,0x6b,
};
const unsigned char tc_ya[] = {
 0xda,0x3d,0x23,0x70,0x0a,0x9e,0x56,0x99,0x25,0x8a,0xef,0x94,
 0xdc,0x06,0x0d,0xfd,0xa5,0xeb,0xb6,0x1f,0x02,0xa5,0xea,0x77,
 0xfa,0xd5,0x3f,0x4f,0xf0,0x97,0x6d,0x08,
};
const unsigned char tc_ADa[] = {
 0x41,0x44,0x61,
};
const unsigned char tc_Ya[] = {
 0xd4,0x0f,0xb2,0x65,0xa7,0xab,0xea,0xee,0x79,0x39,0xd9,0x1a,
 0x58,0x5f,0xe5,0x9f,0x70,0x53,0xf9,0x82,0xc2,0x96,0xec,0x41,
 0x3c,0x62,0x4c,0x66,0x93,0x08,0xf8,0x7a,
};
const unsigned char tc_yb[] = {
 0xd2,0x31,0x6b,0x45,0x47,0x18,0xc3,0x53,0x62,0xd8,0x3d,0x69,
 0xdf,0x63,0x20,0xf3,0x85,0x78,0xed,0x59,0x84,0x65,0x14,0x35,
 0xe2,0x94,0x97,0x62,0xd9,0x00,0xb8,0x0d,
};
const unsigned char tc_ADb[] = {
 0x41,0x44,0x62,
};
const unsigned char tc_Yb[] = {
 0x08,0xbc,0xf6,0xe9,0x77,0x7a,0x9c,0x31,0x3a,0x3d,0xb6,0xda,
 0xa5,0x10,0xf2,0xd3,0x98,0x40,0x33,0x19,0xc2,0x34,0x1b,0xd5,
 0x06,0xa9,0x2e,0x67,0x2e,0xb7,0xe3,0x07,
};
const unsigned char tc_K[] = {
 0xe2,0x2b,0x1e,0xf7,0x78,0x8f,0x66,0x14,0x78,0xf3,0xcd,0xdd,
 0x4c,0x60,0x07,0x74,0xfc,0x0f,0x41,0xe6,0xb7,0x11,0x56,0x91,
 0x90,0xff,0x88,0xfa,0x0e,0x60,0x7e,0x09,
};
const unsigned char tc_ISK_IR[] = {
 0x4c,0x54,0x69,0xa1,0x6b,0x23,0x64,0xc4,0xb9,0x44,0xeb,0xc1,
 0xa7,0x9e,0x51,0xd1,0x67,0x4a,0xd4,0x7d,0xb2,0x6e,0x87,0x18,
 0x15,0x4f,0x59,0xfa,0xeb,0xfa,0xa5,0x2d,0x83,0x46,0xf3,0x0a,
 0xa5,0x83,0x77,0x11,0x7e,0xb2,0x0d,0x52,0x7f,0x2c,0xbc,0x5c,
 0x76,0x38,0x1f,0x7f,0xd3,0x72,0xe8,0x9d,0xf8,0x23,0x9f,0x87,
 0xf2,0xe0,0x2e,0xd1,
};
const unsigned char tc_ISK_SY[] = {
 0x98,0x0d,0xcc,0x5a,0x1c,0x52,0xce,0xea,0x03,0x1e,0x75,0xf3,
 0x8e,0xd2,0x66,0x58,0x66,0x16,0x48,0x8c,0x5c,0x57,0x80,0x28,
 0x5f,0xcb,0xcf,0x79,0x08,0x7c,0x7b,0xcd,0xbd,0x99,0x35,0x02,
 0xee,0xe6,0x06,0xb7,0x18,0xba,0x31,0xe8,0x40,0xa0,0x00,0xa7,
 0xb7,0xbe,0xfe,0x15,0xea,0x42,0x7c,0x5c,0xfe,0x88,0x34,0x4f,
 0xa1,0x23,0x7f,0x35,
};
const unsigned char tc_ISK_SY[] = {
 0x98,0x0d,0xcc,0x5a,0x1c,0x52,0xce,0xea,0x03,0x1e,0x75,0xf3,
 0x8e,0xd2,0x66,0x58,0x66,0x16,0x48,0x8c,0x5c,0x57,0x80,0x28,
 0x5f,0xcb,0xcf,0x79,0x08,0x7c,0x7b,0xcd,0xbd,0x99,0x35,0x02,
 0xee,0xe6,0x06,0xb7,0x18,0xba,0x31,0xe8,0x40,0xa0,0x00,0xa7,
 0xb7,0xbe,0xfe,0x15,0xea,0x42,0x7c,0x5c,0xfe,0x88,0x34,0x4f,
 0xa1,0x23,0x7f,0x35,
};
const unsigned char tc_sid_out_ir[] = {
 0x2a,0x76,0xd3,0xbb,0xc4,0x99,0xdf,0xdc,0x4d,0xca,0xcc,0x9f,
 0xf0,0x42,0xf4,0xe1,0xa5,0x4e,0x38,0x43,0x25,0x8e,0x10,0x0c,
 0xcd,0x7c,0x60,0xf0,0xa5,0x41,0xf9,0xd3,0xeb,0xf0,0x25,0xe6,
 0x8a,0x46,0x0d,0xde,0x21,0x8b,0xd3,0x9f,0x07,0x11,0xbc,0x6f,
 0xa1,0x14,0x09,0xc9,0xd7,0xb6,0x9d,0x8c,0xcf,0x6b,0x32,0xfc,
 0x51,0xdd,0xb6,0x99,
};
const unsigned char tc_sid_out_oc[] = {
 0xca,0x4b,0x50,0x70,0x0c,0x46,0x20,0x3c,0xcd,0x10,0xbc,0x0e,
 0x9f,0x31,0x09,0x5e,0x50,0x81,0x89,0xcb,0x59,0x85,0x75,0x37,
 0xbe,0x56,0x10,0x48,0xd3,0x4b,0x9e,0xd9,0xa9,0x69,0x7a,0xf1,
 0x1c,0x99,0x8f,0x48,0x4c,0x3d,0x78,0x3b,0x0b,0x53,0x14,0x34,
 0xca,0xa6,0x83,0x5d,0x4c,0x32,0x34,0x4f,0xcd,0x17,0x16,0x0c,
 0x9c,0x34,0x8f,0xc7,
};
~~~


###  Testvectors as JSON file encoded as BASE64


~~~ test-vectors
 #eyJQUlMiOiAiVUdGemMzZHZjbVE9IiwgIkNJIjogImIyTUxRbDl5WlhOd2IyNWtaWE
 #lMUVY5cGJtbDBhV0YwYjNJPSIsICJzaWQiOiAiZmt0SGtkYW83d0diazJ4NSszOHNW
 #dz09IiwgImciOiAicHZ5Q3c3aVdqN3N1QnY3b0hLaFlXRzNxVU5KSThNZkthaGl3a0
 #Nvd3Mycz0iLCAieWEiOiAiMmowamNBcWVWcGtsaXUrVTNBWU4vYVhydGg4Q3BlcDMr
 #dFUvVC9DWGJRZz0iLCAiQURhIjogIlFVUmgiLCAiWWEiOiAiMUEreVphZXI2dTU1T2
 #RrYVdGL2xuM0JUK1lMQ2x1eEJQR0pNWnBNSStIbz0iLCAieWIiOiAiMGpGclJVY1l3
 #MU5pMkQxcDMyTWc4NFY0N1ZtRVpSUTE0cFNYWXRrQXVBMD0iLCAiQURiIjogIlFVUm
 #kiLCAiWWIiOiAiQ0x6MjZYZDZuREU2UGJiYXBSRHkwNWhBTXhuQ05CdlZCcWt1Wnk2
 #MzR3Yz0iLCAiSyI6ICI0aXNlOTNpUFpoUjQ4ODNkVEdBSGRQd1BRZWEzRVZhUmtQK0
 #krZzVnZmdrPSIsICJJU0tfSVIiOiAiVEZScG9Xc2paTVM1Uk92QnA1NVIwV2RLMUgy
 #eWJvY1lGVTlaK3V2NnBTMkRSdk1LcFlOM0VYNnlEVkovTEx4Y2RqZ2ZmOU55NkozNE
 #k1K0g4dUF1MFE9PSIsICJJU0tfU1kiOiAibUEzTVdoeFN6dW9ESG5Yemp0Sm1XR1lX
 #U0l4Y1Y0QW9YOHZQZVFoOGU4MjltVFVDN3VZR3R4aTZNZWhBb0FDbnQ3NytGZXBDZk
 #Z6K2lEUlBvU04vTlE9PSIsICJzaWRfb3V0cHV0X2lyIjogIktuYlR1OFNaMzl4Tnlz
 #eWY4RUwwNGFWT09FTWxqaEFNelh4ZzhLVkIrZFByOENYbWlrWU4zaUdMMDU4SEVieH
 #ZvUlFKeWRlMm5ZelBhekw4VWQyMm1RPT0iLCAic2lkX291dHB1dF9vYyI6ICJ5a3RR
 #Y0F4R0lEek5FTHdPbnpFSlhsQ0JpY3RaaFhVM3ZsWVFTTk5MbnRtcGFYcnhISm1QU0
 #V3OWVEc0xVeFEweXFhRFhVd3lORS9ORnhZTW5EU1B4dz09In0=
~~~


### Test case for scalar\_mult with valid inputs


~~~
    s: (length: 32 bytes)
      7cd0e075fa7955ba52c02759a6c90dbbfc10e6d40aea8d283e407d88
      cf538a05
    X: (length: 32 bytes)
      2c3c6b8c4f3800e7aef6864025b4ed79bd599117e427c41bd47d93d6
      54b4a51c
    G.scalar_mult(s,decode(X)): (length: 32 bytes)
      7c13645fe790a468f62c39beb7388e541d8405d1ade69d1778c5fe3e
      7f6b600e
    G.scalar_mult_vfy(s,X): (length: 32 bytes)
      7c13645fe790a468f62c39beb7388e541d8405d1ade69d1778c5fe3e
      7f6b600e
~~~


### Invalid inputs for scalar\_mult\_vfy

For these test cases scalar\_mult\_vfy(y,.) MUST return the representation of the neutral element G.I. When points Y\_i1 or Y\_i2 are included in message of A or B the protocol MUST abort.

~~~
    s: (length: 32 bytes)
      7cd0e075fa7955ba52c02759a6c90dbbfc10e6d40aea8d283e407d88
      cf538a05
    Y_i1: (length: 32 bytes)
      2b3c6b8c4f3800e7aef6864025b4ed79bd599117e427c41bd47d93d6
      54b4a51c
    Y_i2 == G.I: (length: 32 bytes)
      00000000000000000000000000000000000000000000000000000000
      00000000
    G.scalar_mult_vfy(s,Y_i1) = G.scalar_mult_vfy(s,Y_i2) = G.I
~~~


####  Testvectors as JSON file encoded as BASE64


~~~ test-vectors
 #eyJWYWxpZCI6IHsicyI6ICJmTkRnZGZwNVZicFN3Q2RacHNrTnUvd1E1dFFLNm8wb1
 #BrQjlpTTlUaWdVPSIsICJYIjogIkxEeHJqRTg0QU9ldTlvWkFKYlR0ZWIxWmtSZmtK
 #OFFiMUgyVDFsUzBwUnc9IiwgIkcuc2NhbGFyX211bHQocyxkZWNvZGUoWCkpIjogIm
 #ZCTmtYK2VRcEdqMkxEbSt0emlPVkIyRUJkR3Q1cDBYZU1YK1BuOXJZQTQ9IiwgIkcu
 #c2NhbGFyX211bHRfdmZ5KHMsWCkiOiAiZkJOa1grZVFwR2oyTERtK3R6aU9WQjJFQm
 #RHdDVwMFhlTVgrUG45cllBND0ifSwgIkludmFsaWQgWTEiOiAiS3p4cmpFODRBT2V1
 #OW9aQUpiVHRlYjFaa1Jma0o4UWIxSDJUMWxTMHBSdz0iLCAiSW52YWxpZCBZMiI6IC
 #JBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBPSJ9
~~~

##  Test vector for CPace using group decaf448 and hash SHAKE-256


###  Test vectors for calculate\_generator with group decaf448

~~~
  Inputs
    H   = SHAKE-256 with input block size 136 bytes.
    PRS = b'Password' ; ZPAD length: 112 ;
    DSI = b'CPaceDecaf448'
    CI = b'oc\x0bB_responder\x0bA_initiator'
    CI = 6f630b425f726573706f6e6465720b415f696e69746961746f72
    sid = 5223e0cdc45d6575668d64c552004124
  Outputs
    generator_string(G.DSI,PRS,CI,sid,H.s_in_bytes):
    (length: 180 bytes)
      0d435061636544656361663434380850617373776f72647000000000
      00000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000001a6f630b
      425f726573706f6e6465720b415f696e69746961746f72105223e0cd
      c45d6575668d64c552004124
    hash result: (length: 112 bytes)
      7148f4d60587aaafa64d2fd6bcfe45ee71e8b971d1d5ff3bbf8c1451
      797c62a1af22ab25638749f97f9b15fedcf4aeee87282cf667594ab0
      92b6023c8f8d3a61c38b0af791c9271137df01b57d63b79734bbce69
      91e3e2e10fdc805abc9e6e6f3daeff6fd34093d26de240b326764252
    encoded generator g: (length: 56 bytes)
      9a700ecc378eb98e57387df456d5b4b4f1dceebbb1371527eeb7e1bf
      bab64ecc9c9303396145ba04f5b5aea5baedfa61f31f00fbc5fd5606
~~~


####  Testvectors as JSON file encoded as BASE64


~~~ test-vectors
 #eyJIIjogIlNIQUtFLTI1NiIsICJILnNfaW5fYnl0ZXMiOiAxMzYsICJQUlMiOiAiVU
 #dGemMzZHZjbVE9IiwgIlpQQUQgbGVuZ3RoIjogMTEyLCAiRFNJIjogIlExQmhZMlZF
 #WldOaFpqUTBPQT09IiwgIkNJIjogImIyTUxRbDl5WlhOd2IyNWtaWElMUVY5cGJtbD
 #BhV0YwYjNJPSIsICJzaWQiOiAiVWlQZ3pjUmRaWFZtaldURlVnQkJKQT09IiwgImdl
 #bmVyYXRvcl9zdHJpbmcoRy5EU0ksUFJTLENJLHNpZCxILnNfaW5fYnl0ZXMpIjogIk
 #RVTlFZV05sUkdWallXWTBORGdJVUdGemMzZHZjbVJ3QUFBQUFBQUFBQUFBQUFBQUFB
 #QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU
 #FBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB
 #QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFCcHZZd3RDWDNKbGMzQnZibV
 #JsY2d0QlgybHVhWFJwWVhSdmNoQlNJK0ROeEYxbGRXYU5aTVZTQUVFayIsICJoYXNo
 #IHJlc3VsdCI6ICJjVWowMWdXSHFxK21UUy9XdlA1RjduSG91WEhSMWY4N3Y0d1VVWG
 #w4WXFHdklxc2xZNGRKK1grYkZmN2M5Szd1aHlnczltZFpTckNTdGdJOGo0MDZZY09M
 #Q3ZlUnlTY1JOOThCdFgxanQ1YzB1ODVwa2VQaTRRL2NnRnE4bm01dlBhNy9iOU5Baz
 #lKdDRrQ3pKblpDVWc9PSIsICJlbmNvZGVkIGdlbmVyYXRvciBnIjogIm1uQU96RGVP
 #dVk1WE9IMzBWdFcwdFBIYzdydXhOeFVuN3JmaHY3cTJUc3lja3dNNVlVVzZCUFcxcn
 #FXNjdmcGg4eDhBKzhYOVZnWT0ifQ==
~~~


###  Test vector for message from A

~~~
  Inputs
    ADa = b'ADa'
    ya (little endian): (length: 56 bytes)
      33d561f13cfc0dca279c30e8cde895175dc25483892819eba132d58c
      13c0462a8eb0d73fda941950594bef5191d8394691f86edffcad6c1e
  Outputs
    Ya: (length: 56 bytes)
      627f8bb2ae945e2a518967df9b00aff19253d3086398f2ec18be846c
      c0d1f286c2ce3caf1da639859ccd2a6a01a9372a17e66bb7006e571b
~~~

###  Test vector for message from B

~~~
  Inputs
    ADb = b'ADb'
    yb (little endian): (length: 56 bytes)
      2523c969f68fa2b2aea294c2539ef36eb1e0558abd14712a7828f16a
      85ed2c7e77e2bdd418994405fb1b57b6bbaadd66849892aac9d81402
  Outputs
    Yb: (length: 56 bytes)
      8e9811e4402fac098743ca7b2b509b91b38c8cf1360cc6cab3011871
      7019782b7f58a591c63d9c9247b774e6b0e0b826ff4f8399f94772db
~~~

###  Test vector for secret points K

~~~
    scalar_mult_vfy(ya,Yb): (length: 56 bytes)
      94f4ae494f4e8b07ade3354726eee49c5518b363cda544f5b4541b97
      32830be37ea0e63fc83f54be280dea0747a043c76d473e01689af77f
    scalar_mult_vfy(yb,Ya): (length: 56 bytes)
      94f4ae494f4e8b07ade3354726eee49c5518b363cda544f5b4541b97
      32830be37ea0e63fc83f54be280dea0747a043c76d473e01689af77f
~~~


###  Test vector for ISK calculation initiator/responder

~~~
    transcript_ir(Ya,ADa,Yb,ADb): (length: 122 bytes)
      38627f8bb2ae945e2a518967df9b00aff19253d3086398f2ec18be84
      6cc0d1f286c2ce3caf1da639859ccd2a6a01a9372a17e66bb7006e57
      1b03414461388e9811e4402fac098743ca7b2b509b91b38c8cf1360c
      c6cab30118717019782b7f58a591c63d9c9247b774e6b0e0b826ff4f
      8399f94772db03414462
    DSI = G.DSI_ISK, b'CPaceDecaf448_ISK': (length: 17 bytes)
      435061636544656361663434385f49534b
    lv_cat(DSI,sid,K)||transcript_ir(Ya,ADa,Yb,ADb):
    (length: 214 bytes)
      11435061636544656361663434385f49534b105223e0cdc45d657566
      8d64c5520041243894f4ae494f4e8b07ade3354726eee49c5518b363
      cda544f5b4541b9732830be37ea0e63fc83f54be280dea0747a043c7
      6d473e01689af77f38627f8bb2ae945e2a518967df9b00aff19253d3
      086398f2ec18be846cc0d1f286c2ce3caf1da639859ccd2a6a01a937
      2a17e66bb7006e571b03414461388e9811e4402fac098743ca7b2b50
      9b91b38c8cf1360cc6cab30118717019782b7f58a591c63d9c9247b7
      74e6b0e0b826ff4f8399f94772db03414462
    ISK result: (length: 64 bytes)
      9c2726a6cda1179349cbc38f31765eab646a2a5f176f3019fab4a0aa
      bd9d17c2ba895998cff698d801761a003512c1cf67d144b21e1cb6d6
      b82da71d0da76cad
~~~

###  Test vector for ISK calculation parallel execution

~~~
    transcript_oc(Ya,ADa,Yb,ADb): (length: 124 bytes)
      6f63388e9811e4402fac098743ca7b2b509b91b38c8cf1360cc6cab3
      0118717019782b7f58a591c63d9c9247b774e6b0e0b826ff4f8399f9
      4772db0341446238627f8bb2ae945e2a518967df9b00aff19253d308
      6398f2ec18be846cc0d1f286c2ce3caf1da639859ccd2a6a01a9372a
      17e66bb7006e571b03414461
    DSI = G.DSI_ISK, b'CPaceDecaf448_ISK': (length: 17 bytes)
      435061636544656361663434385f49534b
    lv_cat(DSI,sid,K)||transcript_oc(Ya,ADa,Yb,ADb):
    (length: 216 bytes)
      11435061636544656361663434385f49534b105223e0cdc45d657566
      8d64c5520041243894f4ae494f4e8b07ade3354726eee49c5518b363
      cda544f5b4541b9732830be37ea0e63fc83f54be280dea0747a043c7
      6d473e01689af77f6f63388e9811e4402fac098743ca7b2b509b91b3
      8c8cf1360cc6cab30118717019782b7f58a591c63d9c9247b774e6b0
      e0b826ff4f8399f94772db0341446238627f8bb2ae945e2a518967df
      9b00aff19253d3086398f2ec18be846cc0d1f286c2ce3caf1da63985
      9ccd2a6a01a9372a17e66bb7006e571b03414461
    ISK result: (length: 64 bytes)
      6d2178ed3048703025b9007ec84c4d969e8d8135df455e608c16aa15
      2e1219c86cea563254428a9d969903ae3649d1050da1e6e0c1c060e1
      ebf7316a7e993389
~~~

###  Test vector for optional output of session id

~~~
    H.hash(b"CPaceSidOut" + transcript_ir(Ya,ADa, Yb,ADb)):
    (length: 64 bytes)
      65bffde17b7acf07cfd437bdb973a8f7340bf911d393a61498c0a50e
      f0d68bca103fbdb0f5b799505562e59811df1bc5d9b4f5f0f7c57c22
      cd7ed6db4d153e3a
    H.hash(b"CPaceSidOut" + transcript_oc(Ya,ADa, Yb,ADb)):
    (length: 64 bytes)
      7ce27043d1b1d0d0e02e16979637e2a00547ed6e15ea988f7d3c9b3c
      2159b26ab3834bff7ff86240323e25216ba2ee6ea6e1582502017f8e
      6d65f8c4a5e65543
~~~

###  Corresponding C programming language initializers

~~~ c
const unsigned char tc_PRS[] = {
 0x50,0x61,0x73,0x73,0x77,0x6f,0x72,0x64,
};
const unsigned char tc_CI[] = {
 0x6f,0x63,0x0b,0x42,0x5f,0x72,0x65,0x73,0x70,0x6f,0x6e,0x64,
 0x65,0x72,0x0b,0x41,0x5f,0x69,0x6e,0x69,0x74,0x69,0x61,0x74,
 0x6f,0x72,
};
const unsigned char tc_sid[] = {
 0x52,0x23,0xe0,0xcd,0xc4,0x5d,0x65,0x75,0x66,0x8d,0x64,0xc5,
 0x52,0x00,0x41,0x24,
};
const unsigned char tc_g[] = {
 0x9a,0x70,0x0e,0xcc,0x37,0x8e,0xb9,0x8e,0x57,0x38,0x7d,0xf4,
 0x56,0xd5,0xb4,0xb4,0xf1,0xdc,0xee,0xbb,0xb1,0x37,0x15,0x27,
 0xee,0xb7,0xe1,0xbf,0xba,0xb6,0x4e,0xcc,0x9c,0x93,0x03,0x39,
 0x61,0x45,0xba,0x04,0xf5,0xb5,0xae,0xa5,0xba,0xed,0xfa,0x61,
 0xf3,0x1f,0x00,0xfb,0xc5,0xfd,0x56,0x06,
};
const unsigned char tc_ya[] = {
 0x33,0xd5,0x61,0xf1,0x3c,0xfc,0x0d,0xca,0x27,0x9c,0x30,0xe8,
 0xcd,0xe8,0x95,0x17,0x5d,0xc2,0x54,0x83,0x89,0x28,0x19,0xeb,
 0xa1,0x32,0xd5,0x8c,0x13,0xc0,0x46,0x2a,0x8e,0xb0,0xd7,0x3f,
 0xda,0x94,0x19,0x50,0x59,0x4b,0xef,0x51,0x91,0xd8,0x39,0x46,
 0x91,0xf8,0x6e,0xdf,0xfc,0xad,0x6c,0x1e,
};
const unsigned char tc_ADa[] = {
 0x41,0x44,0x61,
};
const unsigned char tc_Ya[] = {
 0x62,0x7f,0x8b,0xb2,0xae,0x94,0x5e,0x2a,0x51,0x89,0x67,0xdf,
 0x9b,0x00,0xaf,0xf1,0x92,0x53,0xd3,0x08,0x63,0x98,0xf2,0xec,
 0x18,0xbe,0x84,0x6c,0xc0,0xd1,0xf2,0x86,0xc2,0xce,0x3c,0xaf,
 0x1d,0xa6,0x39,0x85,0x9c,0xcd,0x2a,0x6a,0x01,0xa9,0x37,0x2a,
 0x17,0xe6,0x6b,0xb7,0x00,0x6e,0x57,0x1b,
};
const unsigned char tc_yb[] = {
 0x25,0x23,0xc9,0x69,0xf6,0x8f,0xa2,0xb2,0xae,0xa2,0x94,0xc2,
 0x53,0x9e,0xf3,0x6e,0xb1,0xe0,0x55,0x8a,0xbd,0x14,0x71,0x2a,
 0x78,0x28,0xf1,0x6a,0x85,0xed,0x2c,0x7e,0x77,0xe2,0xbd,0xd4,
 0x18,0x99,0x44,0x05,0xfb,0x1b,0x57,0xb6,0xbb,0xaa,0xdd,0x66,
 0x84,0x98,0x92,0xaa,0xc9,0xd8,0x14,0x02,
};
const unsigned char tc_ADb[] = {
 0x41,0x44,0x62,
};
const unsigned char tc_Yb[] = {
 0x8e,0x98,0x11,0xe4,0x40,0x2f,0xac,0x09,0x87,0x43,0xca,0x7b,
 0x2b,0x50,0x9b,0x91,0xb3,0x8c,0x8c,0xf1,0x36,0x0c,0xc6,0xca,
 0xb3,0x01,0x18,0x71,0x70,0x19,0x78,0x2b,0x7f,0x58,0xa5,0x91,
 0xc6,0x3d,0x9c,0x92,0x47,0xb7,0x74,0xe6,0xb0,0xe0,0xb8,0x26,
 0xff,0x4f,0x83,0x99,0xf9,0x47,0x72,0xdb,
};
const unsigned char tc_K[] = {
 0x94,0xf4,0xae,0x49,0x4f,0x4e,0x8b,0x07,0xad,0xe3,0x35,0x47,
 0x26,0xee,0xe4,0x9c,0x55,0x18,0xb3,0x63,0xcd,0xa5,0x44,0xf5,
 0xb4,0x54,0x1b,0x97,0x32,0x83,0x0b,0xe3,0x7e,0xa0,0xe6,0x3f,
 0xc8,0x3f,0x54,0xbe,0x28,0x0d,0xea,0x07,0x47,0xa0,0x43,0xc7,
 0x6d,0x47,0x3e,0x01,0x68,0x9a,0xf7,0x7f,
};
const unsigned char tc_ISK_IR[] = {
 0x9c,0x27,0x26,0xa6,0xcd,0xa1,0x17,0x93,0x49,0xcb,0xc3,0x8f,
 0x31,0x76,0x5e,0xab,0x64,0x6a,0x2a,0x5f,0x17,0x6f,0x30,0x19,
 0xfa,0xb4,0xa0,0xaa,0xbd,0x9d,0x17,0xc2,0xba,0x89,0x59,0x98,
 0xcf,0xf6,0x98,0xd8,0x01,0x76,0x1a,0x00,0x35,0x12,0xc1,0xcf,
 0x67,0xd1,0x44,0xb2,0x1e,0x1c,0xb6,0xd6,0xb8,0x2d,0xa7,0x1d,
 0x0d,0xa7,0x6c,0xad,
};
const unsigned char tc_ISK_SY[] = {
 0x6d,0x21,0x78,0xed,0x30,0x48,0x70,0x30,0x25,0xb9,0x00,0x7e,
 0xc8,0x4c,0x4d,0x96,0x9e,0x8d,0x81,0x35,0xdf,0x45,0x5e,0x60,
 0x8c,0x16,0xaa,0x15,0x2e,0x12,0x19,0xc8,0x6c,0xea,0x56,0x32,
 0x54,0x42,0x8a,0x9d,0x96,0x99,0x03,0xae,0x36,0x49,0xd1,0x05,
 0x0d,0xa1,0xe6,0xe0,0xc1,0xc0,0x60,0xe1,0xeb,0xf7,0x31,0x6a,
 0x7e,0x99,0x33,0x89,
};
const unsigned char tc_ISK_SY[] = {
 0x6d,0x21,0x78,0xed,0x30,0x48,0x70,0x30,0x25,0xb9,0x00,0x7e,
 0xc8,0x4c,0x4d,0x96,0x9e,0x8d,0x81,0x35,0xdf,0x45,0x5e,0x60,
 0x8c,0x16,0xaa,0x15,0x2e,0x12,0x19,0xc8,0x6c,0xea,0x56,0x32,
 0x54,0x42,0x8a,0x9d,0x96,0x99,0x03,0xae,0x36,0x49,0xd1,0x05,
 0x0d,0xa1,0xe6,0xe0,0xc1,0xc0,0x60,0xe1,0xeb,0xf7,0x31,0x6a,
 0x7e,0x99,0x33,0x89,
};
const unsigned char tc_sid_out_ir[] = {
 0x65,0xbf,0xfd,0xe1,0x7b,0x7a,0xcf,0x07,0xcf,0xd4,0x37,0xbd,
 0xb9,0x73,0xa8,0xf7,0x34,0x0b,0xf9,0x11,0xd3,0x93,0xa6,0x14,
 0x98,0xc0,0xa5,0x0e,0xf0,0xd6,0x8b,0xca,0x10,0x3f,0xbd,0xb0,
 0xf5,0xb7,0x99,0x50,0x55,0x62,0xe5,0x98,0x11,0xdf,0x1b,0xc5,
 0xd9,0xb4,0xf5,0xf0,0xf7,0xc5,0x7c,0x22,0xcd,0x7e,0xd6,0xdb,
 0x4d,0x15,0x3e,0x3a,
};
const unsigned char tc_sid_out_oc[] = {
 0x7c,0xe2,0x70,0x43,0xd1,0xb1,0xd0,0xd0,0xe0,0x2e,0x16,0x97,
 0x96,0x37,0xe2,0xa0,0x05,0x47,0xed,0x6e,0x15,0xea,0x98,0x8f,
 0x7d,0x3c,0x9b,0x3c,0x21,0x59,0xb2,0x6a,0xb3,0x83,0x4b,0xff,
 0x7f,0xf8,0x62,0x40,0x32,0x3e,0x25,0x21,0x6b,0xa2,0xee,0x6e,
 0xa6,0xe1,0x58,0x25,0x02,0x01,0x7f,0x8e,0x6d,0x65,0xf8,0xc4,
 0xa5,0xe6,0x55,0x43,
};
~~~


###  Testvectors as JSON file encoded as BASE64


~~~ test-vectors
 #eyJQUlMiOiAiVUdGemMzZHZjbVE9IiwgIkNJIjogImIyTUxRbDl5WlhOd2IyNWtaWE
 #lMUVY5cGJtbDBhV0YwYjNJPSIsICJzaWQiOiAiVWlQZ3pjUmRaWFZtaldURlVnQkJK
 #QT09IiwgImciOiAibW5BT3pEZU91WTVYT0gzMFZ0VzB0UEhjN3J1eE54VW43cmZodj
 #dxMlRzeWNrd001WVVXNkJQVzFycVc2N2ZwaDh4OEErOFg5VmdZPSIsICJ5YSI6ICJN
 #OVZoOFR6OERjb25uRERvemVpVkYxM0NWSU9KS0Jucm9UTFZqQlBBUmlxT3NOYy8ycF
 #FaVUZsTDcxR1IyRGxHa2ZodTMveXRiQjQ9IiwgIkFEYSI6ICJRVVJoIiwgIllhIjog
 #IlluK0xzcTZVWGlwUmlXZmZtd0N2OFpKVDB3aGptUExzR0w2RWJNRFI4b2JDemp5dk
 #hhWTVoWnpOS21vQnFUY3FGK1pydHdCdVZ4cz0iLCAieWIiOiAiSlNQSmFmYVBvckt1
 #b3BUQ1U1N3pickhnVllxOUZIRXFlQ2p4YW9YdExINTM0cjNVR0psRUJmc2JWN2E3cX
 #QxbWhKaVNxc25ZRkFJPSIsICJBRGIiOiAiUVVSaSIsICJZYiI6ICJqcGdSNUVBdnJB
 #bUhROHA3SzFDYmtiT01qUEUyRE1iS3N3RVljWEFaZUN0L1dLV1J4ajJja2tlM2RPYX
 #c0TGdtLzArRG1mbEhjdHM9IiwgIksiOiAibFBTdVNVOU9pd2V0NHpWSEp1N2tuRlVZ
 #czJQTnBVVDF0RlFibHpLREMrTitvT1kveUQ5VXZpZ042Z2RIb0VQSGJVYytBV2lhOT
 #M4PSIsICJJU0tfSVIiOiAibkNjbXBzMmhGNU5KeThPUE1YWmVxMlJxS2w4WGJ6QVor
 #clNncXIyZEY4SzZpVm1Zei9hWTJBRjJHZ0ExRXNIUFo5RkVzaDRjdHRhNExhY2REYW
 #RzclE9PSIsICJJU0tfU1kiOiAiYlNGNDdUQkljREFsdVFCK3lFeE5scDZOZ1RYZlJW
 #NWdqQmFxRlM0U0djaHM2bFl5VkVLS25aYVpBNjQyU2RFRkRhSG00TUhBWU9Icjl6Rn
 #FmcGt6aVE9PSIsICJzaWRfb3V0cHV0X2lyIjogIlpiLzk0WHQ2endmUDFEZTl1WE9v
 #OXpRTCtSSFRrNllVbU1DbER2RFdpOG9RUDcydzliZVpVRlZpNVpnUjN4dkYyYlQxOF
 #BmRmZDTE5mdGJiVFJVK09nPT0iLCAic2lkX291dHB1dF9vYyI6ICJmT0p3UTlHeDBO
 #RGdMaGFYbGpmaW9BVkg3VzRWNnBpUGZUeWJQQ0Zac21xemcwdi9mL2hpUURJK0pTRn
 #JvdTV1cHVGWUpRSUJmNDV0WmZqRXBlWlZRdz09In0=
~~~


### Test case for scalar\_mult with valid inputs


~~~
    s: (length: 56 bytes)
      dd1bc7015daabb7672129cc35a3ba815486b139deff9bdeca7a4fc61
      34323d34658761e90ff079972a7ca8aa5606498f4f4f0ebc0933a819
    X: (length: 56 bytes)
      601431d5e51f43d422a92d3fb2373bde28217aab42524c341aa404ea
      ba5aa5541f7042dbb3253ce4c90f772b038a413dcb3a0f6bf3ae9e21
    G.scalar_mult(s,decode(X)): (length: 56 bytes)
      388b35c60eb41b66085a2118316218681d78979d667702de105fdc1f
      21ffe884a577d795f45691781390a229a3bd7b527e831380f2f585a4
    G.scalar_mult_vfy(s,X): (length: 56 bytes)
      388b35c60eb41b66085a2118316218681d78979d667702de105fdc1f
      21ffe884a577d795f45691781390a229a3bd7b527e831380f2f585a4
~~~


### Invalid inputs for scalar\_mult\_vfy

For these test cases scalar\_mult\_vfy(y,.) MUST return the representation of the neutral element G.I. When points Y\_i1 or Y\_i2 are included in message of A or B the protocol MUST abort.

~~~
    s: (length: 56 bytes)
      dd1bc7015daabb7672129cc35a3ba815486b139deff9bdeca7a4fc61
      34323d34658761e90ff079972a7ca8aa5606498f4f4f0ebc0933a819
    Y_i1: (length: 56 bytes)
      5f1431d5e51f43d422a92d3fb2373bde28217aab42524c341aa404ea
      ba5aa5541f7042dbb3253ce4c90f772b038a413dcb3a0f6bf3ae9e21
    Y_i2 == G.I: (length: 56 bytes)
      00000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
    G.scalar_mult_vfy(s,Y_i1) = G.scalar_mult_vfy(s,Y_i2) = G.I
~~~


####  Testvectors as JSON file encoded as BASE64


~~~ test-vectors
 #eyJWYWxpZCI6IHsicyI6ICIzUnZIQVYycXUzWnlFcHpEV2p1b0ZVaHJFNTN2K2Izc3
 #A2VDhZVFF5UFRSbGgySHBEL0I1bHlwOHFLcFdCa21QVDA4T3ZBa3pxQms9IiwgIlgi
 #OiAiWUJReDFlVWZROVFpcVMwL3NqYzczaWdoZXF0Q1VrdzBHcVFFNnJwYXBWUWZjRU
 #xic3lVODVNa1BkeXNEaWtFOXl6b1BhL091bmlFPSIsICJHLnNjYWxhcl9tdWx0KHMs
 #ZGVjb2RlKFgpKSI6ICJPSXMxeGc2MEcyWUlXaUVZTVdJWWFCMTRsNTFtZHdMZUVGL2
 #NIeUgvNklTbGQ5ZVY5RmFSZUJPUW9pbWp2WHRTZm9NVGdQTDFoYVE9IiwgIkcuc2Nh
 #bGFyX211bHRfdmZ5KHMsWCkiOiAiT0lzMXhnNjBHMllJV2lFWU1XSVlhQjE0bDUxbW
 #R3TGVFRi9jSHlILzZJU2xkOWVWOUZhUmVCT1FvaW1qdlh0U2ZvTVRnUEwxaGFRPSJ9
 #LCAiSW52YWxpZCBZMSI6ICJYeFF4MWVVZlE5UWlxUzAvc2pjNzNpZ2hlcXRDVWt3ME
 #dxUUU2cnBhcFZRZmNFTGJzeVU4NU1rUGR5c0Rpa0U5eXpvUGEvT3VuaUU9IiwgIklu
 #dmFsaWQgWTIiOiAiQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU
 #FBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBPSJ9
~~~

##  Test vector for CPace using group NIST P-256 and hash SHA-256


###  Test vectors for calculate\_generator with group NIST P-256

~~~
  Inputs
    H   = SHA-256 with input block size 64 bytes.
    PRS = b'Password' ; ZPAD length: 23 ;
    DSI = b'CPaceP256_XMD:SHA-256_SSWU_NU_'
    DST = b'CPaceP256_XMD:SHA-256_SSWU_NU__DST'
    CI = b'oc\x0bB_responder\x0bA_initiator'
    CI = 6f630b425f726573706f6e6465720b415f696e69746961746f72
    sid = 34b36454cab2e7842c389f7d88ecb7df
  Outputs
    generator_string(PRS,G.DSI,CI,sid,H.s_in_bytes):
    (length: 108 bytes)
      1e4350616365503235365f584d443a5348412d3235365f535357555f
      4e555f0850617373776f726417000000000000000000000000000000
      00000000000000001a6f630b425f726573706f6e6465720b415f696e
      69746961746f721034b36454cab2e7842c389f7d88ecb7df
    generator g: (length: 65 bytes)
      04eee577320b1c241a79419fcde5718c2b63f81ef8717d56a57d2fb2
      6b65a8beb63573b52605efb32ff4cf31aaef9a92df84e4e8408cc6c7
      cf27a535aad2b38a56
~~~

####  Testvectors as JSON file encoded as BASE64


~~~ test-vectors
 #eyJIIjogIlNIQS0yNTYiLCAiSC5zX2luX2J5dGVzIjogNjQsICJQUlMiOiAiVUdGem
 #MzZHZjbVE9IiwgIlpQQUQgbGVuZ3RoIjogMjMsICJEU0kiOiAiUTFCaFkyVlFNalUy
 #WDFoTlJEcFRTRUV0TWpVMlgxTlRWMVZmVGxWZiIsICJDSSI6ICJiMk1MUWw5eVpYTn
 #diMjVrWlhJTFFWOXBibWwwYVdGMGIzST0iLCAic2lkIjogIk5MTmtWTXF5NTRRc09K
 #OTlpT3kzM3c9PSIsICJnZW5lcmF0b3Jfc3RyaW5nKEcuRFNJLFBSUyxDSSxzaWQsSC
 #5zX2luX2J5dGVzKSI6ICJIa05RWVdObFVESTFObDlZVFVRNlUwaEJMVEkxTmw5VFUx
 #ZFZYMDVWWHdoUVlYTnpkMjl5WkJjQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU
 #FBQnB2WXd0Q1gzSmxjM0J2Ym1SbGNndEJYMmx1YVhScFlYUnZjaEEwczJSVXlyTG5o
 #Q3c0bjMySTdMZmYiLCAiZ2VuZXJhdG9yIGciOiAiQk83bGR6SUxIQ1FhZVVHZnplVn
 #hqQ3RqK0I3NGNYMVdwWDB2c210bHFMNjJOWE8xSmdYdnN5LzB6ekdxNzVxUzM0VGs2
 #RUNNeHNmUEo2VTFxdEt6aWxZPSJ9
~~~


###  Test vector for message from A

~~~
  Inputs
    ADa = b'ADa'
    ya (big endian): (length: 32 bytes)
      37574cfbf1b95ff6a8e2d7be462d4d01e6dde2618f34f4de9df869b2
      4f532c5d
  Outputs
    Ya: (length: 65 bytes)
      041f12ad5fc65010a24fc04c86197109a36df0e9ce85a7479e1e1364
      692fdace17ea5a634e19c207a5d52ead6c6817a163cf2f2fe3406c5d
      fdfc2ecdf8e42c5e16
    Alternative correct value for Ya: (-ya)*g:
    (length: 65 bytes)
      041f12ad5fc65010a24fc04c86197109a36df0e9ce85a7479e1e1364
      692fdace1715a59cb0e63df85b2ad1529397e85e9c30d0d01dbf93a2
      0203d132071bd3a1e9
~~~

###  Test vector for message from B

~~~
  Inputs
    ADb = b'ADb'
    yb (big endian): (length: 32 bytes)
      e5672fc9eb4e721f41d80181ec4c9fd9886668acc48024d33c82bb10
      2aecba52
  Outputs
    Yb: (length: 65 bytes)
      046a51180b6ebabaf5ed0af8cd786886d93342bcae4c158ce1617a0a
      cc8ec354486f9ed2e9210913206d1e3f5e463d2d320c4f1f5ce8b677
      a7e38a26f752bf8f84
    Alternative correct value for Yb: (-yb)*g:
    (length: 65 bytes)
      046a51180b6ebabaf5ed0af8cd786886d93342bcae4c158ce1617a0a
      cc8ec3544890612d15def6ece092e1c0a1b9c2d2cdf3b0e0a4174988
      581c75d908ad40707b
~~~

###  Test vector for secret points K

~~~
    scalar_mult_vfy(ya,Yb): (length: 32 bytes)
      3e0e2f8976fb8d0deee30aef4b5cd3631eed249af32f53d0dd009b5d
      7b8f6b6c
    scalar_mult_vfy(yb,Ya): (length: 32 bytes)
      3e0e2f8976fb8d0deee30aef4b5cd3631eed249af32f53d0dd009b5d
      7b8f6b6c
~~~


###  Test vector for ISK calculation initiator/responder

~~~
    transcript_ir(Ya,ADa,Yb,ADb): (length: 140 bytes)
      41041f12ad5fc65010a24fc04c86197109a36df0e9ce85a7479e1e13
      64692fdace17ea5a634e19c207a5d52ead6c6817a163cf2f2fe3406c
      5dfdfc2ecdf8e42c5e160341446141046a51180b6ebabaf5ed0af8cd
      786886d93342bcae4c158ce1617a0acc8ec354486f9ed2e921091320
      6d1e3f5e463d2d320c4f1f5ce8b677a7e38a26f752bf8f8403414462
    DSI = G.DSI_ISK, b'CPaceP256_XMD:SHA-256_SSWU_NU__ISK':
    (length: 34 bytes)
      4350616365503235365f584d443a5348412d3235365f535357555f4e
      555f5f49534b
    lv_cat(DSI,sid,K)||transcript_ir(Ya,ADa,Yb,ADb):
    (length: 225 bytes)
      224350616365503235365f584d443a5348412d3235365f535357555f
      4e555f5f49534b1034b36454cab2e7842c389f7d88ecb7df203e0e2f
      8976fb8d0deee30aef4b5cd3631eed249af32f53d0dd009b5d7b8f6b
      6c41041f12ad5fc65010a24fc04c86197109a36df0e9ce85a7479e1e
      1364692fdace17ea5a634e19c207a5d52ead6c6817a163cf2f2fe340
      6c5dfdfc2ecdf8e42c5e160341446141046a51180b6ebabaf5ed0af8
      cd786886d93342bcae4c158ce1617a0acc8ec354486f9ed2e9210913
      206d1e3f5e463d2d320c4f1f5ce8b677a7e38a26f752bf8f84034144
      62
    ISK result: (length: 32 bytes)
      9565ed286b6e3cf1f943fd31746f9a22935537025a1328d4980005ba
      984f0c39
~~~

###  Test vector for ISK calculation parallel execution

~~~
    transcript_oc(Ya,ADa,Yb,ADb): (length: 142 bytes)
      6f6341046a51180b6ebabaf5ed0af8cd786886d93342bcae4c158ce1
      617a0acc8ec354486f9ed2e9210913206d1e3f5e463d2d320c4f1f5c
      e8b677a7e38a26f752bf8f840341446241041f12ad5fc65010a24fc0
      4c86197109a36df0e9ce85a7479e1e1364692fdace17ea5a634e19c2
      07a5d52ead6c6817a163cf2f2fe3406c5dfdfc2ecdf8e42c5e160341
      4461
    DSI = G.DSI_ISK, b'CPaceP256_XMD:SHA-256_SSWU_NU__ISK':
    (length: 34 bytes)
      4350616365503235365f584d443a5348412d3235365f535357555f4e
      555f5f49534b
    lv_cat(DSI,sid,K)||transcript_oc(Ya,ADa,Yb,ADb):
    (length: 227 bytes)
      224350616365503235365f584d443a5348412d3235365f535357555f
      4e555f5f49534b1034b36454cab2e7842c389f7d88ecb7df203e0e2f
      8976fb8d0deee30aef4b5cd3631eed249af32f53d0dd009b5d7b8f6b
      6c6f6341046a51180b6ebabaf5ed0af8cd786886d93342bcae4c158c
      e1617a0acc8ec354486f9ed2e9210913206d1e3f5e463d2d320c4f1f
      5ce8b677a7e38a26f752bf8f840341446241041f12ad5fc65010a24f
      c04c86197109a36df0e9ce85a7479e1e1364692fdace17ea5a634e19
      c207a5d52ead6c6817a163cf2f2fe3406c5dfdfc2ecdf8e42c5e1603
      414461
    ISK result: (length: 32 bytes)
      62a445a4daa3546dd031c66ead2e4e015abbcc83bde31c90f841149f
      d441c58a
~~~

###  Test vector for optional output of session id

~~~
    H.hash(b"CPaceSidOut" + transcript_ir(Ya,ADa, Yb,ADb)):
    (length: 32 bytes)
      a7386d1c2eb06e8056d7fecbcf691e08d189d96236020ef31b414069
      8a4b99f9
    H.hash(b"CPaceSidOut" + transcript_oc(Ya,ADa, Yb,ADb)):
    (length: 32 bytes)
      d337dbc0dd797b4e6f2f14ea4925c58e5d5523871e8cb43a3c1b0f2b
      1a1ffde3
~~~

###  Corresponding C programming language initializers

~~~ c
const unsigned char tc_PRS[] = {
 0x50,0x61,0x73,0x73,0x77,0x6f,0x72,0x64,
};
const unsigned char tc_CI[] = {
 0x6f,0x63,0x0b,0x42,0x5f,0x72,0x65,0x73,0x70,0x6f,0x6e,0x64,
 0x65,0x72,0x0b,0x41,0x5f,0x69,0x6e,0x69,0x74,0x69,0x61,0x74,
 0x6f,0x72,
};
const unsigned char tc_sid[] = {
 0x34,0xb3,0x64,0x54,0xca,0xb2,0xe7,0x84,0x2c,0x38,0x9f,0x7d,
 0x88,0xec,0xb7,0xdf,
};
const unsigned char tc_g[] = {
 0x04,0xee,0xe5,0x77,0x32,0x0b,0x1c,0x24,0x1a,0x79,0x41,0x9f,
 0xcd,0xe5,0x71,0x8c,0x2b,0x63,0xf8,0x1e,0xf8,0x71,0x7d,0x56,
 0xa5,0x7d,0x2f,0xb2,0x6b,0x65,0xa8,0xbe,0xb6,0x35,0x73,0xb5,
 0x26,0x05,0xef,0xb3,0x2f,0xf4,0xcf,0x31,0xaa,0xef,0x9a,0x92,
 0xdf,0x84,0xe4,0xe8,0x40,0x8c,0xc6,0xc7,0xcf,0x27,0xa5,0x35,
 0xaa,0xd2,0xb3,0x8a,0x56,
};
const unsigned char tc_ya[] = {
 0x37,0x57,0x4c,0xfb,0xf1,0xb9,0x5f,0xf6,0xa8,0xe2,0xd7,0xbe,
 0x46,0x2d,0x4d,0x01,0xe6,0xdd,0xe2,0x61,0x8f,0x34,0xf4,0xde,
 0x9d,0xf8,0x69,0xb2,0x4f,0x53,0x2c,0x5d,
};
const unsigned char tc_ADa[] = {
 0x41,0x44,0x61,
};
const unsigned char tc_Ya[] = {
 0x04,0x1f,0x12,0xad,0x5f,0xc6,0x50,0x10,0xa2,0x4f,0xc0,0x4c,
 0x86,0x19,0x71,0x09,0xa3,0x6d,0xf0,0xe9,0xce,0x85,0xa7,0x47,
 0x9e,0x1e,0x13,0x64,0x69,0x2f,0xda,0xce,0x17,0xea,0x5a,0x63,
 0x4e,0x19,0xc2,0x07,0xa5,0xd5,0x2e,0xad,0x6c,0x68,0x17,0xa1,
 0x63,0xcf,0x2f,0x2f,0xe3,0x40,0x6c,0x5d,0xfd,0xfc,0x2e,0xcd,
 0xf8,0xe4,0x2c,0x5e,0x16,
};
const unsigned char tc_yb[] = {
 0xe5,0x67,0x2f,0xc9,0xeb,0x4e,0x72,0x1f,0x41,0xd8,0x01,0x81,
 0xec,0x4c,0x9f,0xd9,0x88,0x66,0x68,0xac,0xc4,0x80,0x24,0xd3,
 0x3c,0x82,0xbb,0x10,0x2a,0xec,0xba,0x52,
};
const unsigned char tc_ADb[] = {
 0x41,0x44,0x62,
};
const unsigned char tc_Yb[] = {
 0x04,0x6a,0x51,0x18,0x0b,0x6e,0xba,0xba,0xf5,0xed,0x0a,0xf8,
 0xcd,0x78,0x68,0x86,0xd9,0x33,0x42,0xbc,0xae,0x4c,0x15,0x8c,
 0xe1,0x61,0x7a,0x0a,0xcc,0x8e,0xc3,0x54,0x48,0x6f,0x9e,0xd2,
 0xe9,0x21,0x09,0x13,0x20,0x6d,0x1e,0x3f,0x5e,0x46,0x3d,0x2d,
 0x32,0x0c,0x4f,0x1f,0x5c,0xe8,0xb6,0x77,0xa7,0xe3,0x8a,0x26,
 0xf7,0x52,0xbf,0x8f,0x84,
};
const unsigned char tc_K[] = {
 0x3e,0x0e,0x2f,0x89,0x76,0xfb,0x8d,0x0d,0xee,0xe3,0x0a,0xef,
 0x4b,0x5c,0xd3,0x63,0x1e,0xed,0x24,0x9a,0xf3,0x2f,0x53,0xd0,
 0xdd,0x00,0x9b,0x5d,0x7b,0x8f,0x6b,0x6c,
};
const unsigned char tc_ISK_IR[] = {
 0x95,0x65,0xed,0x28,0x6b,0x6e,0x3c,0xf1,0xf9,0x43,0xfd,0x31,
 0x74,0x6f,0x9a,0x22,0x93,0x55,0x37,0x02,0x5a,0x13,0x28,0xd4,
 0x98,0x00,0x05,0xba,0x98,0x4f,0x0c,0x39,
};
const unsigned char tc_ISK_SY[] = {
 0x62,0xa4,0x45,0xa4,0xda,0xa3,0x54,0x6d,0xd0,0x31,0xc6,0x6e,
 0xad,0x2e,0x4e,0x01,0x5a,0xbb,0xcc,0x83,0xbd,0xe3,0x1c,0x90,
 0xf8,0x41,0x14,0x9f,0xd4,0x41,0xc5,0x8a,
};
const unsigned char tc_ISK_SY[] = {
 0x62,0xa4,0x45,0xa4,0xda,0xa3,0x54,0x6d,0xd0,0x31,0xc6,0x6e,
 0xad,0x2e,0x4e,0x01,0x5a,0xbb,0xcc,0x83,0xbd,0xe3,0x1c,0x90,
 0xf8,0x41,0x14,0x9f,0xd4,0x41,0xc5,0x8a,
};
const unsigned char tc_sid_out_ir[] = {
 0xa7,0x38,0x6d,0x1c,0x2e,0xb0,0x6e,0x80,0x56,0xd7,0xfe,0xcb,
 0xcf,0x69,0x1e,0x08,0xd1,0x89,0xd9,0x62,0x36,0x02,0x0e,0xf3,
 0x1b,0x41,0x40,0x69,0x8a,0x4b,0x99,0xf9,
};
const unsigned char tc_sid_out_oc[] = {
 0xd3,0x37,0xdb,0xc0,0xdd,0x79,0x7b,0x4e,0x6f,0x2f,0x14,0xea,
 0x49,0x25,0xc5,0x8e,0x5d,0x55,0x23,0x87,0x1e,0x8c,0xb4,0x3a,
 0x3c,0x1b,0x0f,0x2b,0x1a,0x1f,0xfd,0xe3,
};
~~~


###  Testvectors as JSON file encoded as BASE64


~~~ test-vectors
 #eyJQUlMiOiAiVUdGemMzZHZjbVE9IiwgIkNJIjogImIyTUxRbDl5WlhOd2IyNWtaWE
 #lMUVY5cGJtbDBhV0YwYjNJPSIsICJzaWQiOiAiTkxOa1ZNcXk1NFFzT0o5OWlPeTMz
 #dz09IiwgImciOiAiQk83bGR6SUxIQ1FhZVVHZnplVnhqQ3RqK0I3NGNYMVdwWDB2c2
 #10bHFMNjJOWE8xSmdYdnN5LzB6ekdxNzVxUzM0VGs2RUNNeHNmUEo2VTFxdEt6aWxZ
 #PSIsICJ5YSI6ICJOMWRNKy9HNVgvYW80dGUrUmkxTkFlYmQ0bUdQTlBUZW5maHBzaz
 #lUTEYwPSIsICJBRGEiOiAiUVVSaCIsICJZYSI6ICJCQjhTclYvR1VCQ2lUOEJNaGhs
 #eENhTnQ4T25PaGFkSG5oNFRaR2t2MnM0WDZscGpUaG5DQjZYVkxxMXNhQmVoWTg4dk
 #wrTkFiRjM5L0M3TitPUXNYaFk9IiwgInliIjogIjVXY3Z5ZXRPY2g5QjJBR0I3RXlm
 #MllobWFLekVnQ1RUUElLN0VDcnN1bEk9IiwgIkFEYiI6ICJRVVJpIiwgIlliIjogIk
 #JHcFJHQXR1dXJyMTdRcjR6WGhvaHRrelFyeXVUQldNNFdGNkNzeU93MVJJYjU3UzZT
 #RUpFeUJ0SGo5ZVJqMHRNZ3hQSDF6b3RuZW40NG9tOTFLL2o0UT0iLCAiSyI6ICJQZz
 #R2aVhiN2pRM3U0d3J2UzF6VFl4N3RKSnJ6TDFQUTNRQ2JYWHVQYTJ3PSIsICJJU0tf
 #SVIiOiAibFdYdEtHdHVQUEg1US8weGRHK2FJcE5WTndKYUV5alVtQUFGdXBoUEREaz
 #0iLCAiSVNLX1NZIjogIllxUkZwTnFqVkczUU1jWnVyUzVPQVZxN3pJTzk0eHlRK0VF
 #VW45UkJ4WW89IiwgInNpZF9vdXRwdXRfaXIiOiAicHpodEhDNndib0JXMS83THoya2
 #VDTkdKMldJMkFnN3pHMEZBYVlwTG1maz0iLCAic2lkX291dHB1dF9vYyI6ICIwemZi
 #d04xNWUwNXZMeFRxU1NYRmpsMVZJNGNlakxRNlBCc1BLeG9mL2VNPSJ9
~~~


### Test case for scalar\_mult\_vfy with correct inputs


~~~
    s: (length: 32 bytes)
      f012501c091ff9b99a123fffe571d8bc01e8077ee581362e1bd21399
      0835643b
    X: (length: 65 bytes)
      0424648eb986c2be0af636455cef0550671d6bcd8aa26e0d72ffa1b1
      fd12ba4e0f78da2b6d2184f31af39e566aef127014b6936c9a37346d
      10a4ab2514faef5831
    G.scalar_mult(s,X) (full coordinates): (length: 65 bytes)
      04f5a191f078c87c36633b78c701751159d56c59f3fe9105b5720673
      470f303ab925b6a7fd1cdd8f649a21cf36b68d9e9c4a11919a951892
      519786104b27033757
    G.scalar_mult_vfy(s,X) (only X-coordinate):
    (length: 32 bytes)
      f5a191f078c87c36633b78c701751159d56c59f3fe9105b572067347
      0f303ab9
~~~


### Invalid inputs for scalar\_mult\_vfy

For these test cases scalar\_mult\_vfy(y,.) MUST return the representation of the neutral element G.I. When including Y\_i1 or Y\_i2 in messages of A or B the protocol MUST abort.


~~~
    s: (length: 32 bytes)
      f012501c091ff9b99a123fffe571d8bc01e8077ee581362e1bd21399
      0835643b
    Y_i1: (length: 65 bytes)
      0424648eb986c2be0af636455cef0550671d6bcd8aa26e0d72ffa1b1
      fd12ba4e0f78da2b6d2184f31af39e566aef127014b6936c9a37346d
      10a4ab2514faef5857
    Y_i2: (length: 1 bytes)
      00
    G.scalar_mult_vfy(s,Y_i1) = G.scalar_mult_vfy(s,Y_i2) = G.I
~~~


####  Testvectors as JSON file encoded as BASE64


~~~ test-vectors
 #eyJWYWxpZCI6IHsicyI6ICI4QkpRSEFrZitibWFFai8vNVhIWXZBSG9CMzdsZ1RZdU
 #c5SVRtUWcxWkRzPSIsICJYIjogIkJDUmtqcm1Hd3I0SzlqWkZYTzhGVUdjZGE4Mktv
 #bTROY3YraHNmMFN1azRQZU5vcmJTR0U4eHJ6bmxacTd4SndGTGFUYkpvM05HMFFwS3
 #NsRlBydldERT0iLCAiRy5zY2FsYXJfbXVsdChzLFgpIChmdWxsIGNvb3JkaW5hdGVz
 #KSI6ICJCUFdoa2ZCNHlIdzJZenQ0eHdGMUVWblZiRm56L3BFRnRYSUdjMGNQTURxNU
 #piYW4vUnpkajJTYUljODJ0bzJlbkVvUmtacVZHSkpSbDRZUVN5Y0ROMWM9IiwgIkcu
 #c2NhbGFyX211bHRfdmZ5KHMsWCkgKG9ubHkgWC1jb29yZGluYXRlKSI6ICI5YUdSOE
 #hqSWZEWmpPM2pIQVhVUldkVnNXZlAra1FXMWNnWnpSdzh3T3JrPSJ9LCAiSW52YWxp
 #ZCBZMSI6ICJCQ1JranJtR3dyNEs5alpGWE84RlVHY2RhODJLb200TmN2K2hzZjBTdW
 #s0UGVOb3JiU0dFOHhyem5sWnE3eEp3RkxhVGJKbzNORzBRcEtzbEZQcnZXRmM9Iiwg
 #IkludmFsaWQgWTIiOiAiQUE9PSJ9
~~~

##  Test vector for CPace using group NIST P-384 and hash SHA-384


###  Test vectors for calculate\_generator with group NIST P-384

~~~
  Inputs
    H   = SHA-384 with input block size 128 bytes.
    PRS = b'Password' ; ZPAD length: 87 ;
    DSI = b'CPaceP384_XMD:SHA-384_SSWU_NU_'
    DST = b'CPaceP384_XMD:SHA-384_SSWU_NU__DST'
    CI = b'oc\x0bB_responder\x0bA_initiator'
    CI = 6f630b425f726573706f6e6465720b415f696e69746961746f72
    sid = 5b3773aa90e8f23c61563a4b645b276c
  Outputs
    generator_string(PRS,G.DSI,CI,sid,H.s_in_bytes):
    (length: 172 bytes)
      1e4350616365503338345f584d443a5348412d3338345f535357555f
      4e555f0850617373776f726457000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      000000000000000000000000000000001a6f630b425f726573706f6e
      6465720b415f696e69746961746f72105b3773aa90e8f23c61563a4b
      645b276c
    generator g: (length: 97 bytes)
      04ffe1bdc3293fdbe31b2959916e52c018e923eac99836bd9a1cbeec
      794a8d4d78baa32cdafc9685bc1067a780f4ad9c8a6c6e164aa42906
      d1e27f782581adc8e0109219626a2b8fbdc34602e4084554bdd6c0c6
      98dd657ac8e31b2bcce1c7b0d8
~~~

####  Testvectors as JSON file encoded as BASE64


~~~ test-vectors
 #eyJIIjogIlNIQS0zODQiLCAiSC5zX2luX2J5dGVzIjogMTI4LCAiUFJTIjogIlVHRn
 #pjM2R2Y21RPSIsICJaUEFEIGxlbmd0aCI6IDg3LCAiRFNJIjogIlExQmhZMlZRTXpn
 #MFgxaE5SRHBUU0VFdE16ZzBYMU5UVjFWZlRsVmYiLCAiQ0kiOiAiYjJNTFFsOXlaWE
 #53YjI1a1pYSUxRVjlwYm1sMGFXRjBiM0k9IiwgInNpZCI6ICJXemR6cXBEbzhqeGhW
 #anBMWkZzbmJBPT0iLCAiZ2VuZXJhdG9yX3N0cmluZyhHLkRTSSxQUlMsQ0ksc2lkLE
 #guc19pbl9ieXRlcykiOiAiSGtOUVlXTmxVRE00TkY5WVRVUTZVMGhCTFRNNE5GOVRV
 #MWRWWDA1Vlh3aFFZWE56ZDI5eVpGY0FBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU
 #FBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB
 #QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBYWIyTUxRbDl5Wl
 #hOd2IyNWtaWElMUVY5cGJtbDBhV0YwYjNJUVd6ZHpxcERvOGp4aFZqcExaRnNuYkE9
 #PSIsICJnZW5lcmF0b3IgZyI6ICJCUC9odmNNcFA5dmpHeWxaa1c1U3dCanBJK3JKbU
 #RhOW1oeSs3SGxLalUxNHVxTXMydnlXaGJ3UVo2ZUE5SzJjaW14dUZrcWtLUWJSNG45
 #NEpZR3R5T0FRa2hsaWFpdVB2Y05HQXVRSVJWUzkxc0RHbU4xbGVzampHeXZNNGNldz
 #JBPT0ifQ==
~~~


###  Test vector for message from A

~~~
  Inputs
    ADa = b'ADa'
    ya (big endian): (length: 48 bytes)
      ef433dd5ad142c860e7cb6400dd315d388d5ec5420c550e9d6f0907f
      375d988bc4d704837e43561c497e7dd93edcdb9d
  Outputs
    Ya: (length: 97 bytes)
      0434a04da121995d81d7c5ded02cf2e70954dca49059485ea38310b7
      3b96fa1ec78619c5a1e524472778331fbe009fa1564a3203e42993a3
      6285fa54e6c24184fd227458c87781be16fff46dbc970cc1b1770050
      a94d6826d52f211b234792e66d
    Alternative correct value for Ya: (-ya)*g:
    (length: 97 bytes)
      0434a04da121995d81d7c5ded02cf2e70954dca49059485ea38310b7
      3b96fa1ec78619c5a1e524472778331fbe009fa156b5cdfc1bd66c5c
      9d7a05ab193dbe7b02dd8ba737887e41e9000b924368f33e4d88ffaf
      55b297d92ad0dee4ddb86d1992
~~~

###  Test vector for message from B

~~~
  Inputs
    ADb = b'ADb'
    yb (big endian): (length: 48 bytes)
      50b0e36b95a2edfaa8342b843dddc90b175330f2399c1b36586dedda
      3c255975f30be6a750f9404fccc62a6323b5e471
  Outputs
    Yb: (length: 97 bytes)
      040a6559147fd492ad74ab1f4def6196fd6399540e84706227a1f90d
      104cdaeb630b7c5c18748deb25653ad2a4cb5e6274841cad328bb031
      2628b9b1f51bea72b8c610999a6730f752649205ae85c452ef83f98b
      e715cd0103186874b07cf02074
    Alternative correct value for Yb: (-yb)*g:
    (length: 97 bytes)
      040a6559147fd492ad74ab1f4def6196fd6399540e84706227a1f90d
      104cdaeb630b7c5c18748deb25653ad2a4cb5e62747be352cd744fce
      d9d7464e0ae4158d4739ef666598cf08ad9b6dfa517a3bad0f7c0674
      17ea32fefce7978b50830fdf8b
~~~

###  Test vector for secret points K

~~~
    scalar_mult_vfy(ya,Yb): (length: 48 bytes)
      a9acaea95692a64462067fe8e4321f2fca9793a8a0420f0e253ed0d6
      db858fe161de7576206a8a35bd4a60e00724fd3e
    scalar_mult_vfy(yb,Ya): (length: 48 bytes)
      a9acaea95692a64462067fe8e4321f2fca9793a8a0420f0e253ed0d6
      db858fe161de7576206a8a35bd4a60e00724fd3e
~~~


###  Test vector for ISK calculation initiator/responder

~~~
    transcript_ir(Ya,ADa,Yb,ADb): (length: 204 bytes)
      610434a04da121995d81d7c5ded02cf2e70954dca49059485ea38310
      b73b96fa1ec78619c5a1e524472778331fbe009fa1564a3203e42993
      a36285fa54e6c24184fd227458c87781be16fff46dbc970cc1b17700
      50a94d6826d52f211b234792e66d0341446161040a6559147fd492ad
      74ab1f4def6196fd6399540e84706227a1f90d104cdaeb630b7c5c18
      748deb25653ad2a4cb5e6274841cad328bb0312628b9b1f51bea72b8
      c610999a6730f752649205ae85c452ef83f98be715cd0103186874b0
      7cf0207403414462
    DSI = G.DSI_ISK, b'CPaceP384_XMD:SHA-384_SSWU_NU__ISK':
    (length: 34 bytes)
      4350616365503338345f584d443a5348412d3338345f535357555f4e
      555f5f49534b
    lv_cat(DSI,sid,K)||transcript_ir(Ya,ADa,Yb,ADb):
    (length: 305 bytes)
      224350616365503338345f584d443a5348412d3338345f535357555f
      4e555f5f49534b105b3773aa90e8f23c61563a4b645b276c30a9acae
      a95692a64462067fe8e4321f2fca9793a8a0420f0e253ed0d6db858f
      e161de7576206a8a35bd4a60e00724fd3e610434a04da121995d81d7
      c5ded02cf2e70954dca49059485ea38310b73b96fa1ec78619c5a1e5
      24472778331fbe009fa1564a3203e42993a36285fa54e6c24184fd22
      7458c87781be16fff46dbc970cc1b1770050a94d6826d52f211b2347
      92e66d0341446161040a6559147fd492ad74ab1f4def6196fd639954
      0e84706227a1f90d104cdaeb630b7c5c18748deb25653ad2a4cb5e62
      74841cad328bb0312628b9b1f51bea72b8c610999a6730f752649205
      ae85c452ef83f98be715cd0103186874b07cf0207403414462
    ISK result: (length: 48 bytes)
      d1b74375c7d63d7de246cbf3fc2b3092645c73a0aa816989c0de6048
      ed4ece6a54df82d05d2be3498cb9288be7bdbdb9
~~~

###  Test vector for ISK calculation parallel execution

~~~
    transcript_oc(Ya,ADa,Yb,ADb): (length: 206 bytes)
      6f63610434a04da121995d81d7c5ded02cf2e70954dca49059485ea3
      8310b73b96fa1ec78619c5a1e524472778331fbe009fa1564a3203e4
      2993a36285fa54e6c24184fd227458c87781be16fff46dbc970cc1b1
      770050a94d6826d52f211b234792e66d0341446161040a6559147fd4
      92ad74ab1f4def6196fd6399540e84706227a1f90d104cdaeb630b7c
      5c18748deb25653ad2a4cb5e6274841cad328bb0312628b9b1f51bea
      72b8c610999a6730f752649205ae85c452ef83f98be715cd01031868
      74b07cf0207403414462
    DSI = G.DSI_ISK, b'CPaceP384_XMD:SHA-384_SSWU_NU__ISK':
    (length: 34 bytes)
      4350616365503338345f584d443a5348412d3338345f535357555f4e
      555f5f49534b
    lv_cat(DSI,sid,K)||transcript_oc(Ya,ADa,Yb,ADb):
    (length: 307 bytes)
      224350616365503338345f584d443a5348412d3338345f535357555f
      4e555f5f49534b105b3773aa90e8f23c61563a4b645b276c30a9acae
      a95692a64462067fe8e4321f2fca9793a8a0420f0e253ed0d6db858f
      e161de7576206a8a35bd4a60e00724fd3e6f63610434a04da121995d
      81d7c5ded02cf2e70954dca49059485ea38310b73b96fa1ec78619c5
      a1e524472778331fbe009fa1564a3203e42993a36285fa54e6c24184
      fd227458c87781be16fff46dbc970cc1b1770050a94d6826d52f211b
      234792e66d0341446161040a6559147fd492ad74ab1f4def6196fd63
      99540e84706227a1f90d104cdaeb630b7c5c18748deb25653ad2a4cb
      5e6274841cad328bb0312628b9b1f51bea72b8c610999a6730f75264
      9205ae85c452ef83f98be715cd0103186874b07cf0207403414462
    ISK result: (length: 48 bytes)
      a051d4532ca9fb6774e097ebac69c1d6a18144a15421dc155d0b1e8a
      ef9f9d8c0fe86e85d3cbee7796ff50171f42801b
~~~

###  Test vector for optional output of session id

~~~
    H.hash(b"CPaceSidOut" + transcript_ir(Ya,ADa, Yb,ADb)):
    (length: 48 bytes)
      8d5a03946a69ffa12cd6efd469fe8671bbc25fad6db2656f3963c94e
      9c940bdecc2bd555474c211817787d5cf7870ed1
    H.hash(b"CPaceSidOut" + transcript_oc(Ya,ADa, Yb,ADb)):
    (length: 48 bytes)
      c0729db25db40c48a35f787d5410b2cb9a2d9f5e9cf1cf159ed2f63c
      6b2185e597e176cc221422e9496eeda2bf123c8b
~~~

###  Corresponding C programming language initializers

~~~ c
const unsigned char tc_PRS[] = {
 0x50,0x61,0x73,0x73,0x77,0x6f,0x72,0x64,
};
const unsigned char tc_CI[] = {
 0x6f,0x63,0x0b,0x42,0x5f,0x72,0x65,0x73,0x70,0x6f,0x6e,0x64,
 0x65,0x72,0x0b,0x41,0x5f,0x69,0x6e,0x69,0x74,0x69,0x61,0x74,
 0x6f,0x72,
};
const unsigned char tc_sid[] = {
 0x5b,0x37,0x73,0xaa,0x90,0xe8,0xf2,0x3c,0x61,0x56,0x3a,0x4b,
 0x64,0x5b,0x27,0x6c,
};
const unsigned char tc_g[] = {
 0x04,0xff,0xe1,0xbd,0xc3,0x29,0x3f,0xdb,0xe3,0x1b,0x29,0x59,
 0x91,0x6e,0x52,0xc0,0x18,0xe9,0x23,0xea,0xc9,0x98,0x36,0xbd,
 0x9a,0x1c,0xbe,0xec,0x79,0x4a,0x8d,0x4d,0x78,0xba,0xa3,0x2c,
 0xda,0xfc,0x96,0x85,0xbc,0x10,0x67,0xa7,0x80,0xf4,0xad,0x9c,
 0x8a,0x6c,0x6e,0x16,0x4a,0xa4,0x29,0x06,0xd1,0xe2,0x7f,0x78,
 0x25,0x81,0xad,0xc8,0xe0,0x10,0x92,0x19,0x62,0x6a,0x2b,0x8f,
 0xbd,0xc3,0x46,0x02,0xe4,0x08,0x45,0x54,0xbd,0xd6,0xc0,0xc6,
 0x98,0xdd,0x65,0x7a,0xc8,0xe3,0x1b,0x2b,0xcc,0xe1,0xc7,0xb0,
 0xd8,
};
const unsigned char tc_ya[] = {
 0xef,0x43,0x3d,0xd5,0xad,0x14,0x2c,0x86,0x0e,0x7c,0xb6,0x40,
 0x0d,0xd3,0x15,0xd3,0x88,0xd5,0xec,0x54,0x20,0xc5,0x50,0xe9,
 0xd6,0xf0,0x90,0x7f,0x37,0x5d,0x98,0x8b,0xc4,0xd7,0x04,0x83,
 0x7e,0x43,0x56,0x1c,0x49,0x7e,0x7d,0xd9,0x3e,0xdc,0xdb,0x9d,
};
const unsigned char tc_ADa[] = {
 0x41,0x44,0x61,
};
const unsigned char tc_Ya[] = {
 0x04,0x34,0xa0,0x4d,0xa1,0x21,0x99,0x5d,0x81,0xd7,0xc5,0xde,
 0xd0,0x2c,0xf2,0xe7,0x09,0x54,0xdc,0xa4,0x90,0x59,0x48,0x5e,
 0xa3,0x83,0x10,0xb7,0x3b,0x96,0xfa,0x1e,0xc7,0x86,0x19,0xc5,
 0xa1,0xe5,0x24,0x47,0x27,0x78,0x33,0x1f,0xbe,0x00,0x9f,0xa1,
 0x56,0x4a,0x32,0x03,0xe4,0x29,0x93,0xa3,0x62,0x85,0xfa,0x54,
 0xe6,0xc2,0x41,0x84,0xfd,0x22,0x74,0x58,0xc8,0x77,0x81,0xbe,
 0x16,0xff,0xf4,0x6d,0xbc,0x97,0x0c,0xc1,0xb1,0x77,0x00,0x50,
 0xa9,0x4d,0x68,0x26,0xd5,0x2f,0x21,0x1b,0x23,0x47,0x92,0xe6,
 0x6d,
};
const unsigned char tc_yb[] = {
 0x50,0xb0,0xe3,0x6b,0x95,0xa2,0xed,0xfa,0xa8,0x34,0x2b,0x84,
 0x3d,0xdd,0xc9,0x0b,0x17,0x53,0x30,0xf2,0x39,0x9c,0x1b,0x36,
 0x58,0x6d,0xed,0xda,0x3c,0x25,0x59,0x75,0xf3,0x0b,0xe6,0xa7,
 0x50,0xf9,0x40,0x4f,0xcc,0xc6,0x2a,0x63,0x23,0xb5,0xe4,0x71,
};
const unsigned char tc_ADb[] = {
 0x41,0x44,0x62,
};
const unsigned char tc_Yb[] = {
 0x04,0x0a,0x65,0x59,0x14,0x7f,0xd4,0x92,0xad,0x74,0xab,0x1f,
 0x4d,0xef,0x61,0x96,0xfd,0x63,0x99,0x54,0x0e,0x84,0x70,0x62,
 0x27,0xa1,0xf9,0x0d,0x10,0x4c,0xda,0xeb,0x63,0x0b,0x7c,0x5c,
 0x18,0x74,0x8d,0xeb,0x25,0x65,0x3a,0xd2,0xa4,0xcb,0x5e,0x62,
 0x74,0x84,0x1c,0xad,0x32,0x8b,0xb0,0x31,0x26,0x28,0xb9,0xb1,
 0xf5,0x1b,0xea,0x72,0xb8,0xc6,0x10,0x99,0x9a,0x67,0x30,0xf7,
 0x52,0x64,0x92,0x05,0xae,0x85,0xc4,0x52,0xef,0x83,0xf9,0x8b,
 0xe7,0x15,0xcd,0x01,0x03,0x18,0x68,0x74,0xb0,0x7c,0xf0,0x20,
 0x74,
};
const unsigned char tc_K[] = {
 0xa9,0xac,0xae,0xa9,0x56,0x92,0xa6,0x44,0x62,0x06,0x7f,0xe8,
 0xe4,0x32,0x1f,0x2f,0xca,0x97,0x93,0xa8,0xa0,0x42,0x0f,0x0e,
 0x25,0x3e,0xd0,0xd6,0xdb,0x85,0x8f,0xe1,0x61,0xde,0x75,0x76,
 0x20,0x6a,0x8a,0x35,0xbd,0x4a,0x60,0xe0,0x07,0x24,0xfd,0x3e,
};
const unsigned char tc_ISK_IR[] = {
 0xd1,0xb7,0x43,0x75,0xc7,0xd6,0x3d,0x7d,0xe2,0x46,0xcb,0xf3,
 0xfc,0x2b,0x30,0x92,0x64,0x5c,0x73,0xa0,0xaa,0x81,0x69,0x89,
 0xc0,0xde,0x60,0x48,0xed,0x4e,0xce,0x6a,0x54,0xdf,0x82,0xd0,
 0x5d,0x2b,0xe3,0x49,0x8c,0xb9,0x28,0x8b,0xe7,0xbd,0xbd,0xb9,
};
const unsigned char tc_ISK_SY[] = {
 0xa0,0x51,0xd4,0x53,0x2c,0xa9,0xfb,0x67,0x74,0xe0,0x97,0xeb,
 0xac,0x69,0xc1,0xd6,0xa1,0x81,0x44,0xa1,0x54,0x21,0xdc,0x15,
 0x5d,0x0b,0x1e,0x8a,0xef,0x9f,0x9d,0x8c,0x0f,0xe8,0x6e,0x85,
 0xd3,0xcb,0xee,0x77,0x96,0xff,0x50,0x17,0x1f,0x42,0x80,0x1b,
};
const unsigned char tc_ISK_SY[] = {
 0xa0,0x51,0xd4,0x53,0x2c,0xa9,0xfb,0x67,0x74,0xe0,0x97,0xeb,
 0xac,0x69,0xc1,0xd6,0xa1,0x81,0x44,0xa1,0x54,0x21,0xdc,0x15,
 0x5d,0x0b,0x1e,0x8a,0xef,0x9f,0x9d,0x8c,0x0f,0xe8,0x6e,0x85,
 0xd3,0xcb,0xee,0x77,0x96,0xff,0x50,0x17,0x1f,0x42,0x80,0x1b,
};
const unsigned char tc_sid_out_ir[] = {
 0x8d,0x5a,0x03,0x94,0x6a,0x69,0xff,0xa1,0x2c,0xd6,0xef,0xd4,
 0x69,0xfe,0x86,0x71,0xbb,0xc2,0x5f,0xad,0x6d,0xb2,0x65,0x6f,
 0x39,0x63,0xc9,0x4e,0x9c,0x94,0x0b,0xde,0xcc,0x2b,0xd5,0x55,
 0x47,0x4c,0x21,0x18,0x17,0x78,0x7d,0x5c,0xf7,0x87,0x0e,0xd1,
};
const unsigned char tc_sid_out_oc[] = {
 0xc0,0x72,0x9d,0xb2,0x5d,0xb4,0x0c,0x48,0xa3,0x5f,0x78,0x7d,
 0x54,0x10,0xb2,0xcb,0x9a,0x2d,0x9f,0x5e,0x9c,0xf1,0xcf,0x15,
 0x9e,0xd2,0xf6,0x3c,0x6b,0x21,0x85,0xe5,0x97,0xe1,0x76,0xcc,
 0x22,0x14,0x22,0xe9,0x49,0x6e,0xed,0xa2,0xbf,0x12,0x3c,0x8b,
};
~~~


###  Testvectors as JSON file encoded as BASE64


~~~ test-vectors
 #eyJQUlMiOiAiVUdGemMzZHZjbVE9IiwgIkNJIjogImIyTUxRbDl5WlhOd2IyNWtaWE
 #lMUVY5cGJtbDBhV0YwYjNJPSIsICJzaWQiOiAiV3pkenFwRG84anhoVmpwTFpGc25i
 #QT09IiwgImciOiAiQlAvaHZjTXBQOXZqR3lsWmtXNVN3QmpwSStySm1EYTltaHkrN0
 #hsS2pVMTR1cU1zMnZ5V2hid1FaNmVBOUsyY2lteHVGa3FrS1FiUjRuOTRKWUd0eU9B
 #UWtobGlhaXVQdmNOR0F1UUlSVlM5MXNER21OMWxlc2pqR3l2TTRjZXcyQT09IiwgIn
 #lhIjogIjcwTTkxYTBVTElZT2ZMWkFEZE1WMDRqVjdGUWd4VkRwMXZDUWZ6ZGRtSXZF
 #MXdTRGZrTldIRWwrZmRrKzNOdWQiLCAiQURhIjogIlFVUmgiLCAiWWEiOiAiQkRTZ1
 #RhRWhtVjJCMThYZTBDenk1d2xVM0tTUVdVaGVvNE1RdHp1VytoN0hoaG5Gb2VVa1J5
 #ZDRNeCsrQUoraFZrb3lBK1FwazZOaWhmcFU1c0pCaFAwaWRGaklkNEcrRnYvMGJieV
 #hETUd4ZHdCUXFVMW9KdFV2SVJzalI1TG1iUT09IiwgInliIjogIlVMRGphNVdpN2Zx
 #b05DdUVQZDNKQ3hkVE1QSTVuQnMyV0czdDJqd2xXWFh6QythblVQbEFUOHpHS21Nan
 #RlUngiLCAiQURiIjogIlFVUmkiLCAiWWIiOiAiQkFwbFdSUi8xSkt0ZEtzZlRlOWhs
 #djFqbVZRT2hIQmlKNkg1RFJCTTJ1dGpDM3hjR0hTTjZ5VmxPdEtreTE1aWRJUWNyVE
 #tMc0RFbUtMbXg5UnZxY3JqR0VKbWFaekQzVW1TU0JhNkZ4Rkx2Zy9tTDV4WE5BUU1Z
 #YUhTd2ZQQWdkQT09IiwgIksiOiAicWF5dXFWYVNwa1JpQm4vbzVESWZMOHFYazZpZ1
 #FnOE9KVDdRMXR1RmorRmgzblYySUdxS05iMUtZT0FISlAwKyIsICJJU0tfSVIiOiAi
 #MGJkRGRjZldQWDNpUnN2ei9Dc3drbVJjYzZDcWdXbUp3TjVnU08xT3ptcFUzNExRWF
 #N2alNZeTVLSXZudmIyNSIsICJJU0tfU1kiOiAib0ZIVVV5eXArMmQwNEpmcnJHbkIx
 #cUdCUktGVUlkd1ZYUXNlaXUrZm5Zd1A2RzZGMDh2dWQ1Yi9VQmNmUW9BYiIsICJzaW
 #Rfb3V0cHV0X2lyIjogImpWb0RsR3BwLzZFczF1L1VhZjZHY2J2Q1g2MXRzbVZ2T1dQ
 #SlRweVVDOTdNSzlWVlIwd2hHQmQ0ZlZ6M2h3N1IiLCAic2lkX291dHB1dF9vYyI6IC
 #J3SEtkc2wyMERFaWpYM2g5VkJDeXk1b3RuMTZjOGM4Vm50TDJQR3NoaGVXWDRYYk1J
 #aFFpNlVsdTdhSy9FanlMIn0=
~~~


### Test case for scalar\_mult\_vfy with correct inputs


~~~
    s: (length: 48 bytes)
      6e8a99a5cdd408eae98e1b8aed286e7b12adbbdac7f2c628d9060ce9
      2ae0d90bd57a564fd3500fbcce3425dc94ba0ade
    X: (length: 97 bytes)
      045b4cd53c4506cc04ba4c44f2762d5d32c3e55df25b8baa5571b165
      7ad9576efea8259f0684de065a470585b4be876748c7797054f3defe
      f21b77f83d53bac57c89d52aa4d6dd5872bd281989b138359698009f
      8ac1f301538badcce9d9f4036e
    G.scalar_mult(s,X) (full coordinates): (length: 97 bytes)
      0465c28db05fd9f9a93651c5cc31eae49c4e5246b46489b8f6105873
      3173a033cda76c3e3ea5352b804e67fdbe2e334be8245dad5c8c993e
      63bacf0456478f29b71b6c859f13676f84ff150d2741f028f560584a
      0bdba19a63df62c08949c2fd6d
    G.scalar_mult_vfy(s,X) (only X-coordinate):
    (length: 48 bytes)
      65c28db05fd9f9a93651c5cc31eae49c4e5246b46489b8f610587331
      73a033cda76c3e3ea5352b804e67fdbe2e334be8
~~~


### Invalid inputs for scalar\_mult\_vfy

For these test cases scalar\_mult\_vfy(y,.) MUST return the representation of the neutral element G.I. When including Y\_i1 or Y\_i2 in messages of A or B the protocol MUST abort.


~~~
    s: (length: 48 bytes)
      6e8a99a5cdd408eae98e1b8aed286e7b12adbbdac7f2c628d9060ce9
      2ae0d90bd57a564fd3500fbcce3425dc94ba0ade
    Y_i1: (length: 97 bytes)
      045b4cd53c4506cc04ba4c44f2762d5d32c3e55df25b8baa5571b165
      7ad9576efea8259f0684de065a470585b4be876748c7797054f3defe
      f21b77f83d53bac57c89d52aa4d6dd5872bd281989b138359698009f
      8ac1f301538badcce9d9f40302
    Y_i2: (length: 1 bytes)
      00
    G.scalar_mult_vfy(s,Y_i1) = G.scalar_mult_vfy(s,Y_i2) = G.I
~~~


####  Testvectors as JSON file encoded as BASE64


~~~ test-vectors
 #eyJWYWxpZCI6IHsicyI6ICJib3FacGMzVUNPcnBqaHVLN1NodWV4S3R1OXJIOHNZbz
 #JRWU02U3JnMlF2VmVsWlAwMUFQdk00MEpkeVV1Z3JlIiwgIlgiOiAiQkZ0TTFUeEZC
 #c3dFdWt4RThuWXRYVExENVYzeVc0dXFWWEd4WlhyWlYyNytxQ1dmQm9UZUJscEhCWV
 #cwdm9kblNNZDVjRlR6M3Y3eUczZjRQVk82eFh5SjFTcWsxdDFZY3Iwb0dZbXhPRFdX
 #bUFDZmlzSHpBVk9McmN6cDJmUURiZz09IiwgIkcuc2NhbGFyX211bHQocyxYKSAoZn
 #VsbCBjb29yZGluYXRlcykiOiAiQkdYQ2piQmYyZm1wTmxIRnpESHE1SnhPVWthMFpJ
 #bTQ5aEJZY3pGem9EUE5wMncrUHFVMUs0Qk9aLzIrTGpOTDZDUmRyVnlNbVQ1anVzOE
 #VWa2VQS2JjYmJJV2ZFMmR2aFA4VkRTZEI4Q2oxWUZoS0M5dWhtbVBmWXNDSlNjTDli
 #UT09IiwgIkcuc2NhbGFyX211bHRfdmZ5KHMsWCkgKG9ubHkgWC1jb29yZGluYXRlKS
 #I6ICJaY0tOc0YvWithazJVY1hNTWVya25FNVNSclJraWJqMkVGaHpNWE9nTTgybmJE
 #NCtwVFVyZ0U1bi9iNHVNMHZvIn0sICJJbnZhbGlkIFkxIjogIkJGdE0xVHhGQnN3RX
 #VreEU4bll0WFRMRDVWM3lXNHVxVlhHeFpYclpWMjcrcUNXZkJvVGVCbHBIQllXMHZv
 #ZG5TTWQ1Y0ZUejN2N3lHM2Y0UFZPNnhYeUoxU3FrMXQxWWNyMG9HWW14T0RXV21BQ2
 #Zpc0h6QVZPTHJjenAyZlFEQWc9PSIsICJJbnZhbGlkIFkyIjogIkFBPT0ifQ==
~~~

##  Test vector for CPace using group NIST P-521 and hash SHA-512


###  Test vectors for calculate\_generator with group NIST P-521

~~~
  Inputs
    H   = SHA-512 with input block size 128 bytes.
    PRS = b'Password' ; ZPAD length: 87 ;
    DSI = b'CPaceP521_XMD:SHA-512_SSWU_NU_'
    DST = b'CPaceP521_XMD:SHA-512_SSWU_NU__DST'
    CI = b'oc\x0bB_responder\x0bA_initiator'
    CI = 6f630b425f726573706f6e6465720b415f696e69746961746f72
    sid = 7e4b4791d6a8ef019b936c79fb7f2c57
  Outputs
    generator_string(PRS,G.DSI,CI,sid,H.s_in_bytes):
    (length: 172 bytes)
      1e4350616365503532315f584d443a5348412d3531325f535357555f
      4e555f0850617373776f726457000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      000000000000000000000000000000001a6f630b425f726573706f6e
      6465720b415f696e69746961746f72107e4b4791d6a8ef019b936c79
      fb7f2c57
    generator g: (length: 133 bytes)
      0400e58a8fbf08b38e34a3676f6d690bed58aa4115ff32a57ec87172
      fc2a1fb89d03258c6429c464981b3284b5fedbd1244bf27432008868
      7065b9075dd558e14ed69901d2162db1ba3a49c97dca7c902cb1b96b
      abe21a31942114c860665b35c46b8213f6de17194de54c441083dd11
      63d5907adad8824bb1307dcf6a55c11a8f01d9789b
~~~

####  Testvectors as JSON file encoded as BASE64


~~~ test-vectors
 #eyJIIjogIlNIQS01MTIiLCAiSC5zX2luX2J5dGVzIjogMTI4LCAiUFJTIjogIlVHRn
 #pjM2R2Y21RPSIsICJaUEFEIGxlbmd0aCI6IDg3LCAiRFNJIjogIlExQmhZMlZRTlRJ
 #eFgxaE5SRHBUU0VFdE5URXlYMU5UVjFWZlRsVmYiLCAiQ0kiOiAiYjJNTFFsOXlaWE
 #53YjI1a1pYSUxRVjlwYm1sMGFXRjBiM0k9IiwgInNpZCI6ICJma3RIa2Rhbzd3R2Jr
 #Mng1KzM4c1Z3PT0iLCAiZ2VuZXJhdG9yX3N0cmluZyhHLkRTSSxQUlMsQ0ksc2lkLE
 #guc19pbl9ieXRlcykiOiAiSGtOUVlXTmxVRFV5TVY5WVRVUTZVMGhCTFRVeE1sOVRV
 #MWRWWDA1Vlh3aFFZWE56ZDI5eVpGY0FBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU
 #FBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFB
 #QUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBYWIyTUxRbDl5Wl
 #hOd2IyNWtaWElMUVY5cGJtbDBhV0YwYjNJUWZrdEhrZGFvN3dHYmsyeDUrMzhzVnc9
 #PSIsICJnZW5lcmF0b3IgZyI6ICJCQURsaW8rL0NMT09OS05uYjIxcEMrMVlxa0VWL3
 #pLbGZzaHhjdndxSDdpZEF5V01aQ25FWkpnYk1vUzEvdHZSSkV2eWRESUFpR2h3WmJr
 #SFhkVlk0VTdXbVFIU0ZpMnh1anBKeVgzS2ZKQXNzYmxycStJYU1aUWhGTWhnWmxzMX
 #hHdUNFL2JlRnhsTjVVeEVFSVBkRVdQVmtIcmEySUpMc1RCOXoycFZ3UnFQQWRsNG13
 #PT0ifQ==
~~~


###  Test vector for message from A

~~~
  Inputs
    ADa = b'ADa'
    ya (big endian): (length: 66 bytes)
      006367e9c2aeff9f1db19af600cca73343d47cbe446cebbd1ccd783f
      82755a872da86fd0707eb3767c6114f1803deb62d63bdd1e613f67e6
      3e8c141ee5310e3ee819
  Outputs
    Ya: (length: 133 bytes)
      0400c2bfd794467f4438277e85a42e101fa4061e1ef6e05f81e5381f
      30e73b341dd726089cb6a6bbe5a509fad009857488db7130ff768090
      7312eb724cddb4dcce675b0098ad400fef80e1deb4bc1756c43961ef
      60b85f2d62ed458454e11616a5d1df1e5809636821a73662f9f12254
      e6f9950dd01fa8e26a8b20736fb63c63c81094f681
    Alternative correct value for Ya: (-ya)*g:
    (length: 133 bytes)
      0400c2bfd794467f4438277e85a42e101fa4061e1ef6e05f81e5381f
      30e73b341dd726089cb6a6bbe5a509fad009857488db7130ff768090
      7312eb724cddb4dcce675b016752bff0107f1e214b43e8a93bc69e10
      9f47a0d29d12ba7bab1ee9e95a2e20e1a7f69c97de58c99d060eddab
      19066af22fe0571d9574df8c9049c39c37ef6b097e
~~~

###  Test vector for message from B

~~~
  Inputs
    ADb = b'ADb'
    yb (big endian): (length: 66 bytes)
      009227bf8dc741dacc9422f8bf3c0e96fce9587bc562eaafe0dc5f6f
      82f28594e4a6f98553560c62b75fa4abb198cecbbb86ebd41b0ea025
      4cde78ac68d39a240ae7
  Outputs
    Yb: (length: 133 bytes)
      0400706ea69b2b7167773248ea6e69a574e9dd2ff8a3d04a6e07f70c
      709869ca486827d59f9290599d1cf94e1a03fc242e2b1316afe2fa21
      8bfaeb3e1ffd9f19bf062d01f6b15c9c3651be4c08baf01eec25c818
      ee12c6edc4620644b1d97cf24f868732d56fe45ce78e302c221c92f4
      03e0fa3207de8bb41b388d81046a298ed8ddac9b2a
    Alternative correct value for Yb: (-yb)*g:
    (length: 133 bytes)
      0400706ea69b2b7167773248ea6e69a574e9dd2ff8a3d04a6e07f70c
      709869ca486827d59f9290599d1cf94e1a03fc242e2b1316afe2fa21
      8bfaeb3e1ffd9f19bf062d00094ea363c9ae41b3f7450fe113da37e7
      11ed39123b9df9bb4e26830db07978cd2a901ba31871cfd3dde36d0b
      fc1f05cdf821744be4c7727efb95d67127225364d5
~~~

###  Test vector for secret points K

~~~
    scalar_mult_vfy(ya,Yb): (length: 66 bytes)
      018e0e7e9ade74917c11c0f6b52f95ed871eab235437cbee8b5c2509
      516e787a80e825ed5d539fa6a0ec32c48fa8fabe85809d000d0cfd30
      832c23d477c991bea8e5
    scalar_mult_vfy(yb,Ya): (length: 66 bytes)
      018e0e7e9ade74917c11c0f6b52f95ed871eab235437cbee8b5c2509
      516e787a80e825ed5d539fa6a0ec32c48fa8fabe85809d000d0cfd30
      832c23d477c991bea8e5
~~~


###  Test vector for ISK calculation initiator/responder

~~~
    transcript_ir(Ya,ADa,Yb,ADb): (length: 278 bytes)
      85010400c2bfd794467f4438277e85a42e101fa4061e1ef6e05f81e5
      381f30e73b341dd726089cb6a6bbe5a509fad009857488db7130ff76
      80907312eb724cddb4dcce675b0098ad400fef80e1deb4bc1756c439
      61ef60b85f2d62ed458454e11616a5d1df1e5809636821a73662f9f1
      2254e6f9950dd01fa8e26a8b20736fb63c63c81094f6810341446185
      010400706ea69b2b7167773248ea6e69a574e9dd2ff8a3d04a6e07f7
      0c709869ca486827d59f9290599d1cf94e1a03fc242e2b1316afe2fa
      218bfaeb3e1ffd9f19bf062d01f6b15c9c3651be4c08baf01eec25c8
      18ee12c6edc4620644b1d97cf24f868732d56fe45ce78e302c221c92
      f403e0fa3207de8bb41b388d81046a298ed8ddac9b2a03414462
    DSI = G.DSI_ISK, b'CPaceP521_XMD:SHA-512_SSWU_NU__ISK':
    (length: 34 bytes)
      4350616365503532315f584d443a5348412d3531325f535357555f4e
      555f5f49534b
    lv_cat(DSI,sid,K)||transcript_ir(Ya,ADa,Yb,ADb):
    (length: 397 bytes)
      224350616365503532315f584d443a5348412d3531325f535357555f
      4e555f5f49534b107e4b4791d6a8ef019b936c79fb7f2c5742018e0e
      7e9ade74917c11c0f6b52f95ed871eab235437cbee8b5c2509516e78
      7a80e825ed5d539fa6a0ec32c48fa8fabe85809d000d0cfd30832c23
      d477c991bea8e585010400c2bfd794467f4438277e85a42e101fa406
      1e1ef6e05f81e5381f30e73b341dd726089cb6a6bbe5a509fad00985
      7488db7130ff7680907312eb724cddb4dcce675b0098ad400fef80e1
      deb4bc1756c43961ef60b85f2d62ed458454e11616a5d1df1e580963
      6821a73662f9f12254e6f9950dd01fa8e26a8b20736fb63c63c81094
      f6810341446185010400706ea69b2b7167773248ea6e69a574e9dd2f
      f8a3d04a6e07f70c709869ca486827d59f9290599d1cf94e1a03fc24
      2e2b1316afe2fa218bfaeb3e1ffd9f19bf062d01f6b15c9c3651be4c
      08baf01eec25c818ee12c6edc4620644b1d97cf24f868732d56fe45c
      e78e302c221c92f403e0fa3207de8bb41b388d81046a298ed8ddac9b
      2a03414462
    ISK result: (length: 64 bytes)
      1669a0a29726adc7eea2510d6f7e004a135fa63ac3c9f9e6ce53cba5
      d5e3781aced515956041e43358409a13ef90ddc3c36fd8d7d81424c8
      e94592e21854260a
~~~

###  Test vector for ISK calculation parallel execution

~~~
    transcript_oc(Ya,ADa,Yb,ADb): (length: 280 bytes)
      6f6385010400c2bfd794467f4438277e85a42e101fa4061e1ef6e05f
      81e5381f30e73b341dd726089cb6a6bbe5a509fad009857488db7130
      ff7680907312eb724cddb4dcce675b0098ad400fef80e1deb4bc1756
      c43961ef60b85f2d62ed458454e11616a5d1df1e5809636821a73662
      f9f12254e6f9950dd01fa8e26a8b20736fb63c63c81094f681034144
      6185010400706ea69b2b7167773248ea6e69a574e9dd2ff8a3d04a6e
      07f70c709869ca486827d59f9290599d1cf94e1a03fc242e2b1316af
      e2fa218bfaeb3e1ffd9f19bf062d01f6b15c9c3651be4c08baf01eec
      25c818ee12c6edc4620644b1d97cf24f868732d56fe45ce78e302c22
      1c92f403e0fa3207de8bb41b388d81046a298ed8ddac9b2a03414462
    DSI = G.DSI_ISK, b'CPaceP521_XMD:SHA-512_SSWU_NU__ISK':
    (length: 34 bytes)
      4350616365503532315f584d443a5348412d3531325f535357555f4e
      555f5f49534b
    lv_cat(DSI,sid,K)||transcript_oc(Ya,ADa,Yb,ADb):
    (length: 399 bytes)
      224350616365503532315f584d443a5348412d3531325f535357555f
      4e555f5f49534b107e4b4791d6a8ef019b936c79fb7f2c5742018e0e
      7e9ade74917c11c0f6b52f95ed871eab235437cbee8b5c2509516e78
      7a80e825ed5d539fa6a0ec32c48fa8fabe85809d000d0cfd30832c23
      d477c991bea8e56f6385010400c2bfd794467f4438277e85a42e101f
      a4061e1ef6e05f81e5381f30e73b341dd726089cb6a6bbe5a509fad0
      09857488db7130ff7680907312eb724cddb4dcce675b0098ad400fef
      80e1deb4bc1756c43961ef60b85f2d62ed458454e11616a5d1df1e58
      09636821a73662f9f12254e6f9950dd01fa8e26a8b20736fb63c63c8
      1094f6810341446185010400706ea69b2b7167773248ea6e69a574e9
      dd2ff8a3d04a6e07f70c709869ca486827d59f9290599d1cf94e1a03
      fc242e2b1316afe2fa218bfaeb3e1ffd9f19bf062d01f6b15c9c3651
      be4c08baf01eec25c818ee12c6edc4620644b1d97cf24f868732d56f
      e45ce78e302c221c92f403e0fa3207de8bb41b388d81046a298ed8dd
      ac9b2a03414462
    ISK result: (length: 64 bytes)
      f2f3bd8cd442a4e16659b47a7b7a84f29be75893ed2e5f772d7a3c8b
      779eb0df937a4ec50a4f1ff01ebbaa97d80e090ea69b00a95200ed25
      8e48c6f7e9d8fbc2
~~~

###  Test vector for optional output of session id

~~~
    H.hash(b"CPaceSidOut" + transcript_ir(Ya,ADa, Yb,ADb)):
    (length: 64 bytes)
      56cc3cd8be77cdc84c0d1906de1ffc8ef7cbb326a3f05267b6e8c634
      4e2781eb20ef725e84cb1bb45927435051b4e0fae78e975bf15099f9
      e38d755413eee2fd
    H.hash(b"CPaceSidOut" + transcript_oc(Ya,ADa, Yb,ADb)):
    (length: 64 bytes)
      a46c7189ba6a36c4447741e057da39c885b7d59e08bd2df1852a5271
      f2a8a2e9b187ccd07325a3eede646adee0c06fe58da77f74177896b2
      1053c5d107de006d
~~~

###  Corresponding C programming language initializers

~~~ c
const unsigned char tc_PRS[] = {
 0x50,0x61,0x73,0x73,0x77,0x6f,0x72,0x64,
};
const unsigned char tc_CI[] = {
 0x6f,0x63,0x0b,0x42,0x5f,0x72,0x65,0x73,0x70,0x6f,0x6e,0x64,
 0x65,0x72,0x0b,0x41,0x5f,0x69,0x6e,0x69,0x74,0x69,0x61,0x74,
 0x6f,0x72,
};
const unsigned char tc_sid[] = {
 0x7e,0x4b,0x47,0x91,0xd6,0xa8,0xef,0x01,0x9b,0x93,0x6c,0x79,
 0xfb,0x7f,0x2c,0x57,
};
const unsigned char tc_g[] = {
 0x04,0x00,0xe5,0x8a,0x8f,0xbf,0x08,0xb3,0x8e,0x34,0xa3,0x67,
 0x6f,0x6d,0x69,0x0b,0xed,0x58,0xaa,0x41,0x15,0xff,0x32,0xa5,
 0x7e,0xc8,0x71,0x72,0xfc,0x2a,0x1f,0xb8,0x9d,0x03,0x25,0x8c,
 0x64,0x29,0xc4,0x64,0x98,0x1b,0x32,0x84,0xb5,0xfe,0xdb,0xd1,
 0x24,0x4b,0xf2,0x74,0x32,0x00,0x88,0x68,0x70,0x65,0xb9,0x07,
 0x5d,0xd5,0x58,0xe1,0x4e,0xd6,0x99,0x01,0xd2,0x16,0x2d,0xb1,
 0xba,0x3a,0x49,0xc9,0x7d,0xca,0x7c,0x90,0x2c,0xb1,0xb9,0x6b,
 0xab,0xe2,0x1a,0x31,0x94,0x21,0x14,0xc8,0x60,0x66,0x5b,0x35,
 0xc4,0x6b,0x82,0x13,0xf6,0xde,0x17,0x19,0x4d,0xe5,0x4c,0x44,
 0x10,0x83,0xdd,0x11,0x63,0xd5,0x90,0x7a,0xda,0xd8,0x82,0x4b,
 0xb1,0x30,0x7d,0xcf,0x6a,0x55,0xc1,0x1a,0x8f,0x01,0xd9,0x78,
 0x9b,
};
const unsigned char tc_ya[] = {
 0x00,0x63,0x67,0xe9,0xc2,0xae,0xff,0x9f,0x1d,0xb1,0x9a,0xf6,
 0x00,0xcc,0xa7,0x33,0x43,0xd4,0x7c,0xbe,0x44,0x6c,0xeb,0xbd,
 0x1c,0xcd,0x78,0x3f,0x82,0x75,0x5a,0x87,0x2d,0xa8,0x6f,0xd0,
 0x70,0x7e,0xb3,0x76,0x7c,0x61,0x14,0xf1,0x80,0x3d,0xeb,0x62,
 0xd6,0x3b,0xdd,0x1e,0x61,0x3f,0x67,0xe6,0x3e,0x8c,0x14,0x1e,
 0xe5,0x31,0x0e,0x3e,0xe8,0x19,
};
const unsigned char tc_ADa[] = {
 0x41,0x44,0x61,
};
const unsigned char tc_Ya[] = {
 0x04,0x00,0xc2,0xbf,0xd7,0x94,0x46,0x7f,0x44,0x38,0x27,0x7e,
 0x85,0xa4,0x2e,0x10,0x1f,0xa4,0x06,0x1e,0x1e,0xf6,0xe0,0x5f,
 0x81,0xe5,0x38,0x1f,0x30,0xe7,0x3b,0x34,0x1d,0xd7,0x26,0x08,
 0x9c,0xb6,0xa6,0xbb,0xe5,0xa5,0x09,0xfa,0xd0,0x09,0x85,0x74,
 0x88,0xdb,0x71,0x30,0xff,0x76,0x80,0x90,0x73,0x12,0xeb,0x72,
 0x4c,0xdd,0xb4,0xdc,0xce,0x67,0x5b,0x00,0x98,0xad,0x40,0x0f,
 0xef,0x80,0xe1,0xde,0xb4,0xbc,0x17,0x56,0xc4,0x39,0x61,0xef,
 0x60,0xb8,0x5f,0x2d,0x62,0xed,0x45,0x84,0x54,0xe1,0x16,0x16,
 0xa5,0xd1,0xdf,0x1e,0x58,0x09,0x63,0x68,0x21,0xa7,0x36,0x62,
 0xf9,0xf1,0x22,0x54,0xe6,0xf9,0x95,0x0d,0xd0,0x1f,0xa8,0xe2,
 0x6a,0x8b,0x20,0x73,0x6f,0xb6,0x3c,0x63,0xc8,0x10,0x94,0xf6,
 0x81,
};
const unsigned char tc_yb[] = {
 0x00,0x92,0x27,0xbf,0x8d,0xc7,0x41,0xda,0xcc,0x94,0x22,0xf8,
 0xbf,0x3c,0x0e,0x96,0xfc,0xe9,0x58,0x7b,0xc5,0x62,0xea,0xaf,
 0xe0,0xdc,0x5f,0x6f,0x82,0xf2,0x85,0x94,0xe4,0xa6,0xf9,0x85,
 0x53,0x56,0x0c,0x62,0xb7,0x5f,0xa4,0xab,0xb1,0x98,0xce,0xcb,
 0xbb,0x86,0xeb,0xd4,0x1b,0x0e,0xa0,0x25,0x4c,0xde,0x78,0xac,
 0x68,0xd3,0x9a,0x24,0x0a,0xe7,
};
const unsigned char tc_ADb[] = {
 0x41,0x44,0x62,
};
const unsigned char tc_Yb[] = {
 0x04,0x00,0x70,0x6e,0xa6,0x9b,0x2b,0x71,0x67,0x77,0x32,0x48,
 0xea,0x6e,0x69,0xa5,0x74,0xe9,0xdd,0x2f,0xf8,0xa3,0xd0,0x4a,
 0x6e,0x07,0xf7,0x0c,0x70,0x98,0x69,0xca,0x48,0x68,0x27,0xd5,
 0x9f,0x92,0x90,0x59,0x9d,0x1c,0xf9,0x4e,0x1a,0x03,0xfc,0x24,
 0x2e,0x2b,0x13,0x16,0xaf,0xe2,0xfa,0x21,0x8b,0xfa,0xeb,0x3e,
 0x1f,0xfd,0x9f,0x19,0xbf,0x06,0x2d,0x01,0xf6,0xb1,0x5c,0x9c,
 0x36,0x51,0xbe,0x4c,0x08,0xba,0xf0,0x1e,0xec,0x25,0xc8,0x18,
 0xee,0x12,0xc6,0xed,0xc4,0x62,0x06,0x44,0xb1,0xd9,0x7c,0xf2,
 0x4f,0x86,0x87,0x32,0xd5,0x6f,0xe4,0x5c,0xe7,0x8e,0x30,0x2c,
 0x22,0x1c,0x92,0xf4,0x03,0xe0,0xfa,0x32,0x07,0xde,0x8b,0xb4,
 0x1b,0x38,0x8d,0x81,0x04,0x6a,0x29,0x8e,0xd8,0xdd,0xac,0x9b,
 0x2a,
};
const unsigned char tc_K[] = {
 0x01,0x8e,0x0e,0x7e,0x9a,0xde,0x74,0x91,0x7c,0x11,0xc0,0xf6,
 0xb5,0x2f,0x95,0xed,0x87,0x1e,0xab,0x23,0x54,0x37,0xcb,0xee,
 0x8b,0x5c,0x25,0x09,0x51,0x6e,0x78,0x7a,0x80,0xe8,0x25,0xed,
 0x5d,0x53,0x9f,0xa6,0xa0,0xec,0x32,0xc4,0x8f,0xa8,0xfa,0xbe,
 0x85,0x80,0x9d,0x00,0x0d,0x0c,0xfd,0x30,0x83,0x2c,0x23,0xd4,
 0x77,0xc9,0x91,0xbe,0xa8,0xe5,
};
const unsigned char tc_ISK_IR[] = {
 0x16,0x69,0xa0,0xa2,0x97,0x26,0xad,0xc7,0xee,0xa2,0x51,0x0d,
 0x6f,0x7e,0x00,0x4a,0x13,0x5f,0xa6,0x3a,0xc3,0xc9,0xf9,0xe6,
 0xce,0x53,0xcb,0xa5,0xd5,0xe3,0x78,0x1a,0xce,0xd5,0x15,0x95,
 0x60,0x41,0xe4,0x33,0x58,0x40,0x9a,0x13,0xef,0x90,0xdd,0xc3,
 0xc3,0x6f,0xd8,0xd7,0xd8,0x14,0x24,0xc8,0xe9,0x45,0x92,0xe2,
 0x18,0x54,0x26,0x0a,
};
const unsigned char tc_ISK_SY[] = {
 0xf2,0xf3,0xbd,0x8c,0xd4,0x42,0xa4,0xe1,0x66,0x59,0xb4,0x7a,
 0x7b,0x7a,0x84,0xf2,0x9b,0xe7,0x58,0x93,0xed,0x2e,0x5f,0x77,
 0x2d,0x7a,0x3c,0x8b,0x77,0x9e,0xb0,0xdf,0x93,0x7a,0x4e,0xc5,
 0x0a,0x4f,0x1f,0xf0,0x1e,0xbb,0xaa,0x97,0xd8,0x0e,0x09,0x0e,
 0xa6,0x9b,0x00,0xa9,0x52,0x00,0xed,0x25,0x8e,0x48,0xc6,0xf7,
 0xe9,0xd8,0xfb,0xc2,
};
const unsigned char tc_ISK_SY[] = {
 0xf2,0xf3,0xbd,0x8c,0xd4,0x42,0xa4,0xe1,0x66,0x59,0xb4,0x7a,
 0x7b,0x7a,0x84,0xf2,0x9b,0xe7,0x58,0x93,0xed,0x2e,0x5f,0x77,
 0x2d,0x7a,0x3c,0x8b,0x77,0x9e,0xb0,0xdf,0x93,0x7a,0x4e,0xc5,
 0x0a,0x4f,0x1f,0xf0,0x1e,0xbb,0xaa,0x97,0xd8,0x0e,0x09,0x0e,
 0xa6,0x9b,0x00,0xa9,0x52,0x00,0xed,0x25,0x8e,0x48,0xc6,0xf7,
 0xe9,0xd8,0xfb,0xc2,
};
const unsigned char tc_sid_out_ir[] = {
 0x56,0xcc,0x3c,0xd8,0xbe,0x77,0xcd,0xc8,0x4c,0x0d,0x19,0x06,
 0xde,0x1f,0xfc,0x8e,0xf7,0xcb,0xb3,0x26,0xa3,0xf0,0x52,0x67,
 0xb6,0xe8,0xc6,0x34,0x4e,0x27,0x81,0xeb,0x20,0xef,0x72,0x5e,
 0x84,0xcb,0x1b,0xb4,0x59,0x27,0x43,0x50,0x51,0xb4,0xe0,0xfa,
 0xe7,0x8e,0x97,0x5b,0xf1,0x50,0x99,0xf9,0xe3,0x8d,0x75,0x54,
 0x13,0xee,0xe2,0xfd,
};
const unsigned char tc_sid_out_oc[] = {
 0xa4,0x6c,0x71,0x89,0xba,0x6a,0x36,0xc4,0x44,0x77,0x41,0xe0,
 0x57,0xda,0x39,0xc8,0x85,0xb7,0xd5,0x9e,0x08,0xbd,0x2d,0xf1,
 0x85,0x2a,0x52,0x71,0xf2,0xa8,0xa2,0xe9,0xb1,0x87,0xcc,0xd0,
 0x73,0x25,0xa3,0xee,0xde,0x64,0x6a,0xde,0xe0,0xc0,0x6f,0xe5,
 0x8d,0xa7,0x7f,0x74,0x17,0x78,0x96,0xb2,0x10,0x53,0xc5,0xd1,
 0x07,0xde,0x00,0x6d,
};
~~~


###  Testvectors as JSON file encoded as BASE64


~~~ test-vectors
 #eyJQUlMiOiAiVUdGemMzZHZjbVE9IiwgIkNJIjogImIyTUxRbDl5WlhOd2IyNWtaWE
 #lMUVY5cGJtbDBhV0YwYjNJPSIsICJzaWQiOiAiZmt0SGtkYW83d0diazJ4NSszOHNW
 #dz09IiwgImciOiAiQkFEbGlvKy9DTE9PTktObmIyMXBDKzFZcWtFVi96S2xmc2h4Y3
 #Z3cUg3aWRBeVdNWkNuRVpKZ2JNb1MxL3R2UkpFdnlkRElBaUdod1pia0hYZFZZNFU3
 #V21RSFNGaTJ4dWpwSnlYM0tmSkFzc2JscnErSWFNWlFoRk1oZ1psczF4R3VDRS9iZU
 #Z4bE41VXhFRUlQZEVXUFZrSHJhMklKTHNUQjl6MnBWd1JxUEFkbDRtdz09IiwgInlh
 #IjogIkFHTm42Y0t1LzU4ZHNacjJBTXluTTBQVWZMNUViT3U5SE0xNFA0SjFXb2N0cU
 #cvUWNINnpkbnhoRlBHQVBldGkxanZkSG1FL1orWStqQlFlNVRFT1B1Z1oiLCAiQURh
 #IjogIlFVUmgiLCAiWWEiOiAiQkFEQ3Y5ZVVSbjlFT0NkK2hhUXVFQitrQmg0ZTl1Qm
 #ZnZVU0SHpEbk96UWQxeVlJbkxhbXUrV2xDZnJRQ1lWMGlOdHhNUDkyZ0pCekV1dHlU
 #TjIwM001bld3Q1lyVUFQNzREaDNyUzhGMWJFT1dIdllMaGZMV0x0UllSVTRSWVdwZE
 #hmSGxnSlkyZ2hwelppK2ZFaVZPYjVsUTNRSDZqaWFvc2djMisyUEdQSUVKVDJnUT09
 #IiwgInliIjogIkFKSW52NDNIUWRyTWxDTDR2endPbHZ6cFdIdkZZdXF2NE54ZmI0TH
 #loWlRrcHZtRlUxWU1ZcmRmcEt1eG1NN0x1NGJyMUJzT29DVk0zbmlzYU5PYUpBcm4i
 #LCAiQURiIjogIlFVUmkiLCAiWWIiOiAiQkFCd2JxYWJLM0ZuZHpKSTZtNXBwWFRwM1
 #MvNG85QktiZ2YzREhDWWFjcElhQ2ZWbjVLUVdaMGMrVTRhQS93a0xpc1RGcS9pK2lH
 #TCt1cytILzJmR2I4R0xRSDJzVnljTmxHK1RBaTY4QjdzSmNnWTdoTEc3Y1JpQmtTeD
 #JYenlUNGFITXRWdjVGem5qakFzSWh5UzlBUGcraklIM291MEd6aU5nUVJxS1k3WTNh
 #eWJLZz09IiwgIksiOiAiQVk0T2ZwcmVkSkY4RWNEMnRTK1Y3WWNlcXlOVU44dnVpMX
 #dsQ1ZGdWVIcUE2Q1h0WFZPZnBxRHNNc1NQcVBxK2hZQ2RBQTBNL1RDRExDUFVkOG1S
 #dnFqbCIsICJJU0tfSVIiOiAiRm1tZ29wY21yY2Z1b2xFTmIzNEFTaE5mcGpyRHlmbm
 #16bFBMcGRYamVCck8xUldWWUVIa00xaEFtaFB2a04zRHcyL1kxOWdVSk1qcFJaTGlH
 #RlFtQ2c9PSIsICJJU0tfU1kiOiAiOHZPOWpOUkNwT0ZtV2JSNmUzcUU4cHZuV0pQdE
 #xsOTNMWG84aTNlZXNOK1RlazdGQ2s4ZjhCNjdxcGZZRGdrT3Bwc0FxVklBN1NXT1NN
 #YjM2ZGo3d2c9PSIsICJzaWRfb3V0cHV0X2lyIjogIlZzdzgyTDUzemNoTURSa0czaC
 #84anZmTHN5YWo4RkpudHVqR05FNG5nZXNnNzNKZWhNc2J0RmtuUTFCUnRPRDY1NDZY
 #Vy9GUW1mbmpqWFZVRSs3aS9RPT0iLCAic2lkX291dHB1dF9vYyI6ICJwR3h4aWJwcU
 #5zUkVkMEhnVjlvNXlJVzMxWjRJdlMzeGhTcFNjZktvb3VteGg4elFjeVdqN3Q1a2F0
 #N2d3Ry9samFkL2RCZDRscklRVThYUkI5NEFiUT09In0=
~~~


### Test case for scalar\_mult\_vfy with correct inputs


~~~
    s: (length: 66 bytes)
      0182dd7925f1753419e4bf83429763acd37d64000cd5a175edf53a15
      87dd986bc95acc1506991702b6ba1a9ee2458fee8efc00198cf0088c
      480965ef65ff2048b856
    X: (length: 133 bytes)
      0400dc5078b24c4af1620cc10fbecc6cd8cf1cab0b011efb73c782f2
      26dc21c7ca7eb406be74a69ecba5b4a87c07cfc6e687b4beca9a6eda
      c95940a3b4120573b26a80005e697833b0ba285fce7b3f1f25243008
      860b8f1de710a0dcc05b0d20341efe90eb2bcca26797c2d85ae6ca74
      c00696cb1b13e40bda15b27964d7670576647bfab9
    G.scalar_mult(s,X) (full coordinates): (length: 133 bytes)
      040122f88ce73ec5aa2d1c8c5d04148760c3d97ba87daa10d8cb8bb7
      c73cf6e951fc922721bf1437995cfb13e132a78beb86389e60d3517c
      df6d99a8a2d6db19ef27bd0055af9e8ddcf337ce0a7c22a9c8099bc4
      a44faeded1eb72effd26e4f322217b67d60b944b267b3df5046078fd
      577f1785728f49b241fd5e8c83223a994a2d219281
    G.scalar_mult_vfy(s,X) (only X-coordinate):
    (length: 66 bytes)
      0122f88ce73ec5aa2d1c8c5d04148760c3d97ba87daa10d8cb8bb7c7
      3cf6e951fc922721bf1437995cfb13e132a78beb86389e60d3517cdf
      6d99a8a2d6db19ef27bd
~~~


### Invalid inputs for scalar\_mult\_vfy

For these test cases scalar\_mult\_vfy(y,.) MUST return the representation of the neutral element G.I. When including Y\_i1 or Y\_i2 in messages of A or B the protocol MUST abort.


~~~
    s: (length: 66 bytes)
      0182dd7925f1753419e4bf83429763acd37d64000cd5a175edf53a15
      87dd986bc95acc1506991702b6ba1a9ee2458fee8efc00198cf0088c
      480965ef65ff2048b856
    Y_i1: (length: 133 bytes)
      0400dc5078b24c4af1620cc10fbecc6cd8cf1cab0b011efb73c782f2
      26dc21c7ca7eb406be74a69ecba5b4a87c07cfc6e687b4beca9a6eda
      c95940a3b4120573b26a80005e697833b0ba285fce7b3f1f25243008
      860b8f1de710a0dcc05b0d20341efe90eb2bcca26797c2d85ae6ca74
      c00696cb1b13e40bda15b27964d7670576647bfaf9
    Y_i2: (length: 1 bytes)
      00
    G.scalar_mult_vfy(s,Y_i1) = G.scalar_mult_vfy(s,Y_i2) = G.I
~~~


####  Testvectors as JSON file encoded as BASE64


~~~ test-vectors
 #eyJWYWxpZCI6IHsicyI6ICJBWUxkZVNYeGRUUVo1TCtEUXBkanJOTjlaQUFNMWFGMT
 #dmVTZGWWZkbUd2Sldzd1ZCcGtYQXJhNkdwN2lSWS91anZ3QUdZendDSXhJQ1dYdlpm
 #OGdTTGhXIiwgIlgiOiAiQkFEY1VIaXlURXJ4WWd6QkQ3N01iTmpQSEtzTEFSNzdjOG
 #VDOGliY0ljZktmclFHdm5TbW5zdWx0S2g4QjgvRzVvZTB2c3FhYnRySldVQ2p0QklG
 #YzdKcWdBQmVhWGd6c0xvb1g4NTdQeDhsSkRBSWhndVBIZWNRb056QVd3MGdOQjcra0
 #9zcnpLSm5sOExZV3ViS2RNQUdsc3NiRStRTDJoV3llV1RYWndWMlpIdjZ1UT09Iiwg
 #Ikcuc2NhbGFyX211bHQocyxYKSAoZnVsbCBjb29yZGluYXRlcykiOiAiQkFFaStJem
 #5Qc1dxTFJ5TVhRUVVoMkREMlh1b2Zhb1EyTXVMdDhjODl1bFIvSkluSWI4VU41bGMr
 #eFBoTXFlTDY0WTRubURUVVh6ZmJabW9vdGJiR2U4bnZRQlZyNTZOM1BNM3pncDhJcW
 #5JQ1p2RXBFK3UzdEhyY3UvOUp1VHpJaUY3WjlZTGxFc21lejMxQkdCNC9WZC9GNFZ5
 #ajBteVFmMWVqSU1pT3BsS0xTR1NnUT09IiwgIkcuc2NhbGFyX211bHRfdmZ5KHMsWC
 #kgKG9ubHkgWC1jb29yZGluYXRlKSI6ICJBU0w0ak9jK3hhb3RISXhkQkJTSFlNUFpl
 #Nmg5cWhEWXk0dTN4enoyNlZIOGtpY2h2eFEzbVZ6N0UrRXlwNHZyaGppZVlOTlJmTj
 #l0bWFpaTF0c1o3eWU5In0sICJJbnZhbGlkIFkxIjogIkJBRGNVSGl5VEVyeFlnekJE
 #NzdNYk5qUEhLc0xBUjc3YzhlQzhpYmNJY2ZLZnJRR3ZuU21uc3VsdEtoOEI4L0c1b2
 #UwdnNxYWJ0ckpXVUNqdEJJRmM3SnFnQUJlYVhnenNMb29YODU3UHg4bEpEQUloZ3VQ
 #SGVjUW9OekFXdzBnTkI3K2tPc3J6S0pubDhMWVd1YktkTUFHbHNzYkUrUUwyaFd5ZV
 #dUWFp3VjJaSHY2K1E9PSIsICJJbnZhbGlkIFkyIjogIkFBPT0ifQ==
~~~

