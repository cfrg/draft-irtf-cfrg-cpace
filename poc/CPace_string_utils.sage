import base64
import json
import sys

def ByteArrayToInteger(k,numBytes=32):
    try:
        k_list = [ord(b) for b in k]
    except:
        k_list = [b for b in k]
 
    if numBytes < len(k_list):
    	numBytes = len(k_list)
    	
    return sum((k_list[i] << (8 * i)) for i in range(numBytes))

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

def ByteArrayToCInitializer(k, name, values_per_line = 12):
    values = [b for b in k]
    result = "const unsigned char " + name +"[] = {"
    n = 0
    for x in values:
        if n == 0:
            result += "\n "
        n = (n + 1) % values_per_line;
        
        result += ("0x%02x" % x) +","
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

def tv_output_byte_array(data, test_vector_name = "", line_prefix = "  ", max_len = 60, file = sys.stdout):
    string = ByteArrayToLEPrintString(data)
    if len(test_vector_name) > 39:
	    print (line_prefix + test_vector_name + ":\n" + line_prefix+"(length: %i bytes)" % len(data) ,end="",file = file)
    else:
	    print (line_prefix + test_vector_name + ": (length: %i bytes)" % len(data) ,end="",file = file)
    
    chars_per_line = max_len - len(line_prefix)
    while True:
        print ("\n" + line_prefix + "  " + string[0:chars_per_line],end="", file = file)
        string = string[chars_per_line:]
        if len(string) == 0:
            print("\n",end="",file=file)
            return

def tv_output_python_dictionary_as_json_base64(dictionary, line_prefix = "  ", max_len = 60, file = sys.stdout):
    json_text = json.dumps(dictionary).encode("ASCII")
    json_string = base64.standard_b64encode(json_text).decode("ASCII")
    
    result = "\n"
    base64_header = line_prefix + "###"
    base64_trailer = "\n"

    offset = 0;
    while offset < len(json_string):
    	next_chunk_len = min(len(json_string), max_len)
    	result += base64_header + json_string[offset:(offset+next_chunk_len)] + base64_trailer
    	offset += next_chunk_len
    result += "\n"
    
    print(result,end="",file=file)
            
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

def lv_cat(*args):
    result = b""
    for arg in args:
        result += prepend_len(arg)
    return result


def lexiographically_larger(bytes1,bytes2):
    "Returns True if bytes1 > bytes2 for lexiographical ordering."
    min_len = min (len(bytes1), len(bytes2))
    for m in range(min_len):
        if bytes1[m] > bytes2[m]:
            return True;
        elif bytes1[m] < bytes2[m]:
            return False;
    return len(bytes1) > len(bytes2)

def o_cat(bytes1,bytes2):
    if lexiographically_larger(bytes1,bytes2):
        return b"oc" + bytes1 + bytes2
    else:
        return b"oc" + bytes2 + bytes1


def transcript_oc(Ya,ADa,Yb,ADb):
    result = o_cat(lv_cat(Ya,ADa),lv_cat(Yb,ADb))
    return result

def transcript_ir(Ya,ADa,Yb,ADb):
    result = lv_cat(Ya,ADa) + lv_cat(Yb,ADb)
    return result

def zero_bytes(length):
    result = b"\0" * length
    return result

def generator_string(DSI,PRS,CI,sid,s_in_bytes):
    """
    Concat all input fields with prepended length information.
    Add zero padding in the first hash block after DSI and PRS.
    """
    len_zpad = max(0,s_in_bytes - 1 - len(prepend_len(PRS))
                     - len(prepend_len(DSI)))
    return (lv_cat(DSI, PRS, zero_bytes(len_zpad), CI, sid), len_zpad)
    
def generate_testvectors_string_functions(file = sys.stdout):
    print ("\n## Definition and test vectors for string utility functions\n", file = file)
    print ("\n### prepend\\_len function\n", file = file)

    print (
"""
~~~
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
""", file = file);

    print ("\n### prepend\\_len test vectors\n", file = file)
    print ("~~~", file = file)

    tv_output_byte_array(prepend_len(b""), 
                         test_vector_name = 'prepend_len(b"")', 
                         line_prefix = "  ", max_len = 60, file = file);
    tv_output_byte_array(prepend_len(b"1234"), 
                         test_vector_name = 'prepend_len(b"1234")', 
                         line_prefix = "  ", max_len = 60, file = file);

    tv_output_byte_array(prepend_len(bytes(range(127))), 
                         test_vector_name = 'prepend_len(bytes(range(127)))', 
                         line_prefix = "  ", max_len = 60, file = file);
    tv_output_byte_array(prepend_len(bytes(range(128))), 
                         test_vector_name = 'prepend_len(bytes(range(128)))', 
                         line_prefix = "  ", max_len = 60, file = file);

    print ("~~~", file = file)


    print ("\n\n### lv\\_cat function\n", file = file)
    
    print (
"""
~~~
  def lv_cat(*args):
      result = b""
      for arg in args:
          result += prepend_len(arg)
      return result
~~~
""", file = file);


    print ("\n### Testvector for lv\\_cat()\n", file = file)
    print ("~~~", file = file)
    tv_output_byte_array(lv_cat(b"1234",b"5",b"",b"6789"), 
                         test_vector_name = 'lv_cat(b"1234",b"5",b"",b"6789")', 
                         line_prefix = "  ", max_len = 60, file = file);
    
    print ("~~~", file = file)

    print ("\n## Definition of generator\\_string function.\n\n" +
"""
~~~
def generator_string(DSI,PRS,CI,sid,s_in_bytes):
    # Concat all input fields with prepended length information.
    # Add zero padding in the first hash block after DSI and PRS.
    len_zpad = max(0,s_in_bytes - 1 - len(prepend_len(PRS))
                     - len(prepend_len(DSI)))
    return lv_cat(DSI, PRS, zero_bytes(len_zpad),
                           CI, sid)
~~~
""", file = file);
    
    print ("\n## Definitions and test vector ordered concatenation\n", file = file)

    print ("\n### Definitions for lexiographical ordering\n", file = file)
        
    print ("\nFor ordered concatenation lexiographical ordering of byte sequences is used:\n\n" +
"""
~~~
   def lexiographically_larger(bytes1,bytes2):
      "Returns True if bytes1 > bytes2 using lexiographical ordering."
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

""" + "\n\n", file = file)


    print ("~~~", file = file)
    print ("  def o_cat(bytes1,bytes2):", file = file);
    print ("      if lexiographically_larger(bytes1,bytes2):", file = file);
    print ('          return b"oc" + bytes1 + bytes2', file = file);
    print ("      else:", file = file);
    print ('          return b"oc" + bytes2 + bytes1', file = file);
    print ("~~~", file = file)

    print ("\n### Test vectors ordered concatenation\n", file = file)
    
    print ("~~~", file = file)
    print ("  string comparison for o_cat:", file = file)    
    print ('    lexiographically_larger(b"\\0", b"\\0\\0") ==', lexiographically_larger(b"\\0", b"\\0\\0"), file = file)
    print ('    lexiographically_larger(b"\\1", b"\\0\\0") ==', lexiographically_larger(b"\1", b"\0\0"), file = file)
    print ('    lexiographically_larger(b"\\0\\0", b"\\0") ==', lexiographically_larger(b"\0\0", b"\0"), file = file)
    print ('    lexiographically_larger(b"\\0\\0", b"\\1") ==', lexiographically_larger(b"\0\0", b"\1"), file = file)
    print ('    lexiographically_larger(b"\\0\\1", b"\\1") ==', lexiographically_larger(b"\0\1", b"\1"), file = file)
    print ('    lexiographically_larger(b"ABCD", b"BCD") ==', lexiographically_larger(b"ABCD", b"BCD"), file = file)
    print ('', file = file)

    tv_output_byte_array(o_cat(b"ABCD",b"BCD"), 
                         test_vector_name = 'o_cat(b"ABCD",b"BCD")', 
                         line_prefix = "  ", max_len = 60, file = file);
    tv_output_byte_array(o_cat(b"BCD",b"ABCDE"), 
                         test_vector_name = 'o_cat(b"BCD",b"ABCDE")', 
                         line_prefix = "  ", max_len = 60, file = file);
    print ("~~~", file = file)


    print ("""

### Definitions for transcript\\_ir function

~~~
def transcript_ir(Ya,ADa,Yb,ADb):
    result = lv_cat(Ya,ADa) + lv_cat(Yb,ADb)
    return result
~~~""", file = file)

    print ("\n### Test vectors transcript\\_ir function\n", file = file)

    print ("~~~", file = file)
    tv_output_byte_array(transcript_ir(b"123",b"PartyA",b"234",b"PartyB"), 
                         test_vector_name = 'transcript_ir(b"123", b"PartyA", b"234",b"PartyB")', 
                         line_prefix = "  ", max_len = 60, file = file);
    
    tv_output_byte_array(transcript_ir(b"3456",b"PartyA",b"2345",b"PartyB"), 
                         test_vector_name = 'transcript_ir(b"3456",b"PartyA",b"2345",b"PartyB")', 
                         line_prefix = "  ", max_len = 60, file = file);

    print ("~~~", file = file)

    print ("""

### Definitions for transcript\\_oc function

~~~
def transcript_oc(Ya,ADa,Yb,ADb):
    result = o_cat(lv_cat(Ya,ADa),lv_cat(Yb,ADb))
    return result
~~~""", file = file)

    print ("\n### Test vectors for transcript\\_oc function\n", file = file)

    print ("~~~", file = file)
    tv_output_byte_array(transcript_oc(b"123",b"PartyA",b"234",b"PartyB"), 
                         test_vector_name = 'transcript_oc(b"123", b"PartyA", b"234",b"PartyB")', 
                         line_prefix = "  ", max_len = 60, file = file);
    
    tv_output_byte_array(transcript_oc(b"3456",b"PartyA",b"2345",b"PartyB"), 
                         test_vector_name = 'transcript_oc(b"3456",b"PartyA",b"2345",b"PartyB")', 
                         line_prefix = "  ", max_len = 60, file = file);
    print ("~~~", file = file)



def zero_bytes(length):
    result = b"\0" * length
    return result

def random_bytes(length):
    values = [randint(0, 255) for i in range(length)]
    result = b""
    for v in values:
        result += v.to_bytes(1, 'little')
    return result

if __name__ == "__main__":
	generate_testvectors_string_functions()
		
	tv_output_python_dictionary_as_json_base64(test_dictionary)
