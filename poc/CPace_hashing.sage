#Definitions for the hash primitives

import hashlib 

class H_SHA512:
    def __init__(self):
        self.b_in_bytes = 64
        self.bmax_in_bytes = 64
        self.s_in_bytes = 128
        self.name = "SHA-512"
        
    def hash(self,input_str, l = 64):
        m = hashlib.sha512(input_str)
        digest = m.digest()
        if len(digest) < l:
            raise ValueError("Output length of Hash primitive (%i bytes) not long enough. %i bytes were requested." % (len(digest), l))
        return digest[0:l]

    
class H_SHA384:
    def __init__(self):
        self.b_in_bytes = 48
        self.bmax_in_bytes = 48
        self.s_in_bytes = 128
        self.name = "SHA-384"
        
    def hash(self,input_str, l = 48):
        m = hashlib.sha384(input_str)
        digest = m.digest()
        if len(digest) < l:
            raise ValueError("Output length of Hash primitive (%i bytes) not long enough. %i bytes were requested." % (len(digest), l))
        return digest[0:l]

    
class H_SHA256:
    def __init__(self):
        self.b_in_bytes = 32
        self.bmax_in_bytes = 32
        self.s_in_bytes = 64
        self.name = "SHA-256"
        
    def hash(self,input_str, l = 32):
        m = hashlib.sha256(input_str)
        digest = m.digest()
        if len(digest) < l:
            raise ValueError("Output length of Hash primitive (%i bytes) not long enough. %i bytes were requested." % (len(digest), l))

        return digest[0:l]

class H_SHAKE256:
    def __init__(self):
        self.b_in_bytes = 64
        self.bmax_in_bytes = 2^128
        self.s_in_bytes = 136
        self.name = "SHAKE-256"
        
    def hash(self,input_str, l = 64):
        m = hashlib.shake_256(input_str)
        digest = m.digest(l) # Note: hashlib.shake_256 seems to be buggy in some Sage environments :-(
        return digest
