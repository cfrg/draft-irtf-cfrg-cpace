---
title: CPace, a balanced composable PAKE
abbrev: CPace
docname: draft-irtf-cfrg-cpace-latest
date:
category: info

ipr: trust200902
keyword: Internet-Draft

stand_alone: yes
pi: [toc, sortrefs, symrefs]

author:
 -  ins: M. Abdalla
    name: Michel Abdalla
    org: DI, École Normale Supérieure, Paris
    email: michel.abdalla@ens.fr
 -  ins: B. Haase
    name: Bjoern Haase
    org: Endress + Hauser Liquid Analysis
    email: bjoern.m.haase@web.de
 -  ins: J. Hesse
    name: Julia Hesse
    org: IBM Research Europe - Zurich
    email: JHS@zurich.ibm.com

normative:
  SEC1:
    title: "SEC 1: Elliptic Curve Cryptography"
    target: http://www.secg.org/sec1-v2.pdf
    date: May, 2009
    author:
      -
        org: Standards for Efficient Cryptography Group (SECG)

informative:
  CPacePaper2:
    title: The 'quantum annoying' property of password-authenticated key exchange protocols.
    target: https://eprint.iacr.org/2021/696
    author:
      -
        ins: E. Eaton
      -
        ins: D. Stebila
  CPacePaper:
    title: "Security analysis of CPace"
    target: https://eprint.iacr.org/2021/114
    author:
      -
        ins: M. Abdalla
      -
        ins: B. Haase
      -
        ins: J. Hesse
  AUCPacePaper:
    title: "AuCPace. PAKE protocol tailored for the use in the internet of things"
    target: https://eprint.iacr.org/2018/286
    date: Feb, 2018
    author:
      -
        ins: B. Haase
      -
        ins: B. Labrique
  CDMP05:
    title: "Merkle-Damgaard Revisited: How to Construct a Hash Function"
    seriesinfo:
        "In": Advances in Cryptology - CRYPTO 2005
        "pages": 430-448
        DOI: 10.1007/11535218_26
    target: https://doi.org/10.1007/11535218_26
    date: 2005
    author:
      -
        ins: J-S. Coron
        name: Jean-Sebastien Coron
        org: University of Luxembourg
      -
        ins: Y. Dodis
        name: Yevgeniy Dodis
        org: New York University
      -
        ins: C. Malinaud
        name: Cecile Malinaud
        org: University of Luxembourg
      -
        ins: P. Puniya
        name: Prashant Puniya
        org: New York University

  FIPS202:
    title: "SHA-3 Standard: Permutation-Based Hash and Extendable-Output Functions"
    target: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
    date: Aug, 2015
    author:
      -
        org: National Institute of Standards and Technology (NIST)

  IEEE1363:
    title: Standard Specifications for Public Key Cryptography, IEEE 1363
    date: 2000

  SEC2:
    title: "SEC 2: Recommended Elliptic Curve Domain Parameters"
    target: http://www.secg.org/sec2-v2.pdf
    date: Jan, 2010
    author:
      -
        org: Standards for Efficient Cryptography Group (SECG)

--- abstract

This document describes CPace which is a protocol for two
parties that share a low-entropy secret (password) to derive a strong shared key without
disclosing the secret to offline dictionary attacks. This method was tailored for constrained devices,
is compatible with any group of both prime- and non-prime order,
and comes with  a security proof providing composability guarantees.

--- middle

# Introduction

This document describes CPace which is a protocol for two
parties for deriving a strong shared secret from a shared low-entropy secret (password) without
exposing the secret to offline dictionary attacks.

The CPace design was tailored for efficiency on constrained devices such as secure-element chipsets
and considers mitigations with respect to adversaries that might become
capable of breaking the discrete logarithm problem on elliptic curves by quantum computers.

CPace is designed to be suitable as both, a building block within a larger protocol construction using CPace as substep,
and as a standalone protocol.
CPace comes with both, game-based and simulation-based proofs where the latter provides
composability guarantees for settings where CPace forms a substep in a larger solution.

# Requirements Notation

{::boilerplate bcp14}

# Definition CPace

## Setup

For CPace both communication partners need to agree on a common cipher suite. Cipher suites consist of a combination of
a hash function and an elliptic curve environment G. With "environment" we denote a compilation of all of
an elliptic curve group with associated group operations and an calculate_generator() method that maps an octet
string to a group element.

Throughout this document we will be using an object-style notation such as, e.g. H.b\_in\_bytes and G.sample\_scalar(),
for refering to constants and functions asociated with with the group environment and the hash function. (For instance H.b\_in\_bytes
will be referring to the max. output size of the hash function in bytes and G.sample\_scalar() will refer to the method
used for a group environment G for sampling scalars for use as a secret key.)

### Hash functions H

With H we denote a hash function, where H.hash(m,l)
operates on an input octet string m and returns a hashing result of l octets.
Common choices for H are SHA-512 {{?RFC6234}} or SHAKE-256 {{FIPS202}}.
For considering both, variable-output-length primitives and fixed-length output primitives we use the following convention.
In case that the hash function is specified for a fixed-size output, we define H.hash(m,l) such
that it returns the first l octets of the output.

We use the following notation for referring to the specific properties of a hash function H:

- With H.b\_in\_bytes we denote the _default_ output size in bytes corresponding to the symmetric
security level of the hash primitive. E.g. H.b\_in\_bytes = 64 for SHA512 and SHAKE256 and H.b\_in_bytes = 32 for
SHA256 and SHAKE128. We use the notation H.hash(m) = H.hash(m, H.b\_in\_bytes) and let the hash primitive
output the default length if no explicit length parameter is given.

- With H.bmax\_in\_bytes we denote the _maximum_ output size in octets supported by the hash primitive. In case of fixed-size
hashes such as SHA-256, this is the same as H.b\_in\_bytes, while there is no such limit for hash functions such as SHAKE-256.

- With H.s\_in\_bytes we denote the _input block size_ used by H. For instance, for SHA512 the input block size s\_in\_bytes is 128,
while for SHAKE-256 the input block size amounts to 136 bytes.

### Group environment objects G

For a given group G this document specifies how to define the following set of group-specific
functions and constants for the protocol execution. We use the following notation for referring to the specific properties of a group environment G:

- G.calculate\_generator(H,PRS,CI,sid) denotes a function that outputs a
representation of a group element which is derived from input octet strings PRS, CI, sid by the help of
the hash function H.

- G.sample\_scalar() is a function returning a representation of a scalar value appropriate as a
private Diffie-Hellman key for the group G.

- G.scalar\_mult(y,g) is a function an encoding of a generator g on the group as second parameter and a scalar y as first.
It returns an octet string representation of a group element Y.

- With G.I we denote a unique octet string representation of the neutral element of the group G. This representation
will be used for for detecting error conditions.

- G.scalar\_mult\_vfy(y,X) is a function that returns an octet string representation of a group element K which is
calculated from a scalar y and an encoding of a group element X. Moreover scalar\_mult\_vfy implements validity verifications of the inputs
and returns the neutral element G.I in case of error conditions if the validity checks fail.

- G.DSI denotes a domain-separation identifier string which SHALL be uniquely identifying a given CPace's cipher suite group environment G.

## Inputs

- PRS denotes a password-related octet string which is a MANDATORY input for all CPace instantiations.
Typically PRS is derived from a low-entropy secret such as a user-supplied password (pw) or a personal
identification number.

- CI denotes an OPTIONAL octet string for the channel identifier. CI can be used for
binding CPace to one specific communication channel, for which CI needs to be
available to both protocol partners upon protocol start. Typically CI is obtained by a concatenating strings that
uniquely identify the protocol partner's identities, such as their networking addresses.

- sid denotes an OPTIONAL octet string input, the so-called session id. In application scenarios
where a higher-level protocol has established a unique sid value this parameter can be used to
bind the CPace protocol execution to one specific session.

- ADa and ADb denote OPTIONAL "associated data" octet strings that are publicly transmitted as part of the protocol flow. ADa and ADb can for instance include party identifiers or a protocol version information
(e.g. for avoiding downgrade attacks). In a setting with initiator and responder roles, the information ADa sent by the
initiator can be used by the responder for identifying which among possibly several different PRS are to be
used for the given user in this protocol session.

## Notation

- str1 \|\| str2 denotes concatenation of octet strings.

- oCAT(str1,str2) denotes _ordered_ concatenation of octet strings as specified in the appendix.

- CONCAT(MSGa,MSGb) defines a concatenation method that depends on the application scenario.
In applications where CPace is used without clear initiator and responder roles, i.e. where the ordering of
messages is not enforced by the protocol flow, CONCAT(MSGa,MSGb) = oCAT(MSGa,MSGb) SHALL be used. In settings
where the protocol flow enforces ordering CONCAT(MSGa,MSGb) SHOULD BE implemented such that the _later_ message
is appended to the _earlier_ message, i.e. CONCAT(MSGa,MSGb) = MSGa\|\|MSGb, if MSGa comes first.

- len(S) denotes the number of octets in a string S.

- nil represent an empty octet string, i.e., len(nil) = 0.

- prepend\_len(octet\_string) denotes the octet sequence that is obtained from prepending
the length of the octet string to the string itself. The length shall be prepended by using an UTF-8 encoding of the length.
This will result in a single-byte encoding for values below 128. (Test vectors and reference implementations are given in the appendix.)

- prefix\_free\_cat(a0,a1, ...) denotes a function that outputs the prefix-free encoding of
all input octet strings as the concatenation of the individual strings with their respective
length prepended: prepend\_len(a0) \|\| prepend\_len(a1) \|\| ... . Such prefix-free encoding
of multiple substrings allows for parsing individual subcomponents of a network message. (Test vectors and reference implmenetations are given in the appendix.)

- sample\_random\_bytes(n) denotes a function that returns n octets
uniformly distributed between 0 and 255.

- zero\_bytes(n) denotes a function that returns n octets with value 0.

### Notation for group operations

We use "multiplicative" notation for group operation, where X^y denotes scalar multiplication within the group.

# The CPace protocol

CPace is a one round protocol where two parties, A and B interact.

In the setup phase both sides agree on a common hash function H and a group
environment G and a session id value sid.

At invocation, A and B are provisioned with public (CI) and secret
information (PRS) as prerequisite for running the protocol.

A sends a message MSGa to B. MSGa contains the public share Ya
and OPTIONAL associated data ADa (i.e. an ADa field that MAY have a length of 0 bytes).

Likewise, B sends a message MSGb to A. MSGb contains the public share Yb
and OPTIONAL associated data ADb (i.e. an ADb field that MAY have a length of 0 bytes).

Both A and B use the received messages for deriving a shared intermediate session key, ISK.

Naming of this
key as "intermediate" session key highlights the fact, that it is RECOMMENDED to process ISK
by use of a suitable strong key-derivation function KDF (such as defined in {{?RFC5869}}) first,
before actually using the key in a higher-level protocol.

## Session id establishment

It is RECOMMENDED to establish sid in the course of the higher-level protocol that invokes CPace
as a unique sid value may be used for binding a CPace run to one specific instance of the higher-level
protocol. It is RECOMMENDED to obtain sid by concatenating random bytes produced by A with random bytes produced by B.

Where no such sid is available from a higher-level protocol layer, a suitable approach for defining the
session id is to let an initiator choose a fresh random sid send it to B together with the
first message. This method is shown in the setup protocol section below prior to the actual
protocol flow and works whenever the message produced by party A comes first.

The sid string SHOULD HAVE a length of at least 8 bytes.

The sid string MAY also be the emtpy string, nil. I.e. use of the sid string is OPTIONAL.

## Protocol flow

~~~
              A                  B
              | (setup protocol  |
(sample sid)  |     and sid)     |
              |----------------->|
    ---------------------------------------
              |                  |
(compute Ya)  |      Ya, ADa     | (compute Yb)
              |----------------->|
              |      Yb, ADb     |
              |<-----------------|
              |   (verify data)  |
(derive ISK)  |                  | (derive ISK)
~~~

## CPace

To begin, A calculates a generator g = G.calculate\_generator(H, PRS,CI,sid).

A samples ya = G.sample\_scalar() randomly according to the specification for the group environment G.
A then calculates Ya= G.scalar\_mult (ya,g). A then transmits MSGa = prefix\_free\_cat(Ya, ADa) with
Ya and the optional associated data ADa to B. ADa MAY have length zero.

(Note that the use of the prefix-free encoding with the prepended lengths of the substrings Ya and ADa allows B to parse MSGa and separate Ya and ADa.)

Similarly B picks yb = G.sample\_scalar() randomly. B then calculates
g = G.calculate_generator(H, PRS,CI,sid) and
Yb = G.scalar\_mult(yb,g). B sends MSGb = prefix\_free\_cat(Yb, ADb) to A.

B calculates K = G.scalar\_mult_vfy(yb,Ya). B MUST abort if K is the encoding of the neutral element G.I (error condition).
Otherwise B returns ISK = H.hash(prefix\_free\_cat(G.DSI \|\| "\_ISK", sid, K)\|\|CONCAT(MSGa, MSGb).

Likewise upon reception of Yb, A calculates K = G.scalar\_mult\_vfy(Yb,ya). A MUST abort if K is the neutral element G.I.
If K is different from G.I, A returns ISK = H.hash(prefix\_free\_cat(G.DSI \|\| "\_ISK", sid, K) \|\| CONCAT(MSGa, MSGb).

Upon completion of this protocol, the session key ISK returned by A and B will be identical by both
parties if and only if the supplied input parameters sid, PRS and CI match on both sides and the
transcripts match.

## Initiator/Responder and Parallel CPace

CPace is proven secure with and without mandated ordering of the message flow. I.e. it can be implemented in an initiator/responder
setting and also in a parallel setting. In the parallel setting the CONCAT(MSGa,MSGb) function which is needed for deriving the ISK values
SHALL be implemented by using ordered concatenation oCAT(MSGa,MSGb).

In the initiator/responder setting the responder MAY abort the protocol without sending its message if the verification check
fails. (i.e. if the call to G.scalar\_mult\_vfy produced the neutral element G.I).

# RECOMMENDED Ciphersuites

This section documents RECOMMENDED CPACE ciphersuite configurations. Any ciphersuite configuration for CPace
is REQUIRED to specify,

- a group environment object G with associated definitions for

  - the four CPace functions functions G.sample\_scalar(), G.scalar\_mult() and G.scalar\_mult\_vfy() and G.calculate\_generator()

  - a domain separation identifier string G.DSI unique for this cipher suite.

- a hash function H

Currently, test vectors are available for the following RECOMMENDED cipher suites

- CPACE-X25519-SHA512. This suite uses G\_X25519 defined in {{CPaceMontgomery}} and SHA-512.

- CPACE-X448-SHAKE256. This suite uses G\_X448 defined in {{CPaceMontgomery}} and SHAKE-256.

- CPACE-P256\_XMD:SHA-256\_SSWU_NU\_-SHA256.
This suite instantiates G as specified in {{CPaceWeierstrass}} using the encode_to_curve function P256\_XMD:SHA-256\_SSWU_NU\_
from {{!I-D.irtf-cfrg-hash-to-curve}} on curve NIST-P256 with the SHA-256 hash.

- CPACE-P384\_XMD:SHA-384\_SSWU_NU\_-SHA384.
This suite instantiates G as specified in {{CPaceWeierstrass}} using the encode_to_curve function P384\_XMD:SHA-384\_SSWU_NU\_
from {{!I-D.irtf-cfrg-hash-to-curve}} on curve NIST-P384 with the SHA-384 hash.

- CPACE-P521\_XMD:SHA-512\_SSWU_NU\_-SHA512.
This suite instantiates G as specified in {{CPaceWeierstrass}} using the encode_to_curve function P521\_XMD:SHA-384\_SSWU_NU\_
from {{!I-D.irtf-cfrg-hash-to-curve}} on curve NIST-P384 with the SHA-512 hash.

- CPACE-RISTR255-SHA512.
This suite uses G\_ristretto255 defined in {{CPaceCoffee}} and SHA-512.

- CPACE-DECAF448-SHAKE256
This suite uses G\_decaf448 defined in {{CPaceCoffee}} and SHAKE-256.

CPace can securely be implemented on further elliptic curves when following the guidance given in {{sec-considerations}}.

# Implementation of CPace cipher suites

## Common function for calculating generator strings generator\_string()

The different cipher suites for CPace defined in the upcoming sections share the same method for combining the individual strings PRS, CI, sid and the domain-separation string G.DSI to a generator string.

- generator\_string(PRS,DSI,CI,sid, s) denotes a function that returns the string
prefix\_free\_cat(PRS,zero\_bytes(len\_zpad), DSI, CI, sid) in which all input strings are concatenated.

- len\_zpad = MAX(0, H.s\_in\_bytes - len(prepend\_length(PRS)) - 1)

The zero padding of length len\_zpad is designed such that the encoding of PRS together with the zero padding field completely fills the
first input block of the hash.
As a result the number of bytes to hash becomes independent of the actual length of the password (PRS).


The following reference code implements the generator\_string function.

~~~
def generator_string(PRS,DSI,CI,sid, H.s_in_bytes):
    len_zpad = MAX(0, H.s_in_bytes - len(prepend_length(PRS)) - 1)
    return prefix_free_cat(PRS,zero_bytes(len_zpad), DSI, CI, sid)
~~~

The introduction of a zero-padding within the generator string also helps at mitigating attacks of a side-channel adversary that
analyzes correlations between publicly known variable information with the low-entropy PRS string.
Note that the hash of the first block does not depend on session-specific inputs, such as sid oder CI.

## CPace group objects G\_X25519 and G\_X448 for single-coordinate Ladders on Montgomery curves {#CPaceMontgomery}

In this section we consider the case of CPace when using the X25519 and X448 Diffie-Hellman functions
from {{?RFC7748}} operating on the Montgomery curves Curve25519 and Curve448 {{?RFC7748}}.

CPace implementations using single-coordinate ladders on further Montgomery curves SHALL use the definitions in line
with the specifications for X25519 and X448 and review the guidance given in {{sec-considerations}}.

For X25519 the following definitions apply:

- G\_X25519.field\_size\_bytes = 32

- G\_X25519.field\_size\_bits = 255

- G\_X25519.sample\_scalar() = sample\_random\_bytes(G.field\_size\_bytes)

- G\_X25519.scalar\_mult(y,g) = G.scalar\_mult\_vfy(y,g) = X25519(y,g)

- G\_X25519.I = zero\_bytes(G.field\_size\_bytes)

- G\_X25519.DSI = "CPace255"

CPace cipher suites using G\_X25519 MUST use a hash function producing at least H.b\_max\_in\_bytes >= 32 bytes of output. It is RECOMMENDED
to use G\_X25519 in combination with SHA-512.

For X448 the following definitions apply:

- G\_X448.field\_size\_bytes = 56

- G\_X448.field\_size\_bits = 448

- G\_X448.sample\_scalar() = sample\_random\_bytes(G.field\_size\_bytes)

- G\_X448.scalar\_mult(y,g) = G.scalar\_mult\_vfy(y,g) = X448(y,g)

- G\_X448.I = zero\_bytes(G.field\_size\_bytes)

- G\_X448.DSI = "CPace448"

CPace cipher suites using G\_X448 MUST use a hash function producing at least H.b\_max\_in\_bytes >= 56 bytes of output. It is RECOMMENDED
to use G\_X25519 in combination with SHAKE-256.

For both, G\_X448 and G\_X25519 The G.calculate\_generator(H, PRS,sid,CI) function shall be implemented as follows.

 - First gen\_str = generator\_string(PRS,G.DSI,CI,sid, H.s\_in\_bytes) SHALL BE calculated using the input block size of the
   chosen hash primitive.

 - This string SHALL then BE hashed to the required length
   gen\_str\_hash = H.hash(gen\_str, G.field\_size\_bytes).
   Note that this implies that the permissible output length H.maxb\_in\_bytes MUST BE larger or equal to the
   field size of the group G for making a hashing primitive suitable.

 - This result is then considered as a field coordinate using
   the u = decodeUCoordinate(gen\_str\_hash, G.field\_size\_bits) function from {{!RFC7748}} which we
   repeat in the appendix for convenience.

 - The result point g is then calculated as (g,v) = map\_to\_curve\_elligator2(u) using the function
   from {{!I-D.irtf-cfrg-hash-to-curve}}. Note that the v coordinate produced by the map\_to\_curve\_elligator2 function
   is not required for CPace and discarded. The appendix repeats the definitions from {{!I-D.irtf-cfrg-hash-to-curve}} for convenience.

In the appendix we show sage code that can be used as reference implementation and corresponding test vectors..

## CPace group objects G\_Ristretto255 and G\_Decaf448 for prime-order group abstractions {#CPaceCoffee}

In this section we consider the case of CPace using the Ristretto255 and Decaf448 group abstractions.
These abstractions define an encode and decode function, group operations using an internal encoding
and a one-way-map. With the group abstractions there is a distinction between an internal representation
of group elements and an external encoding of the same group element. In order to distinguish between these
different representations, we prepend an underscore before values using the internal representation within this
section.

For Ristretto255 the following definitions apply:

- G\_Ristretto255.DSI = "CPaceRistretto255"

- G\_Ristretto255.field\_size\_bytes = 32

- G\_Ristretto255.group\_size\_bits = 252

- G\_Ristretto255.group\_order = 2^252 + 27742317777372353535851937790883648493

CPace cipher suites using G\_Ristretto255 MUST use a hash function producing at least H.b\_max\_in\_bytes >= 64 bytes of output.
It is RECOMMENDED to use G\_Ristretto255 in combination with SHA-512.

For decaf448 the following definitions apply:

- G\_Decaf448.DSI = "CPaceDecaf448"

- G\_Decaf448.field\_size\_bytes = 56

- G\_Decaf448.group\_size\_bits = 445

- G\_Decaf448.group\_order = l = 2^446 -
    13818066809895115352007386748515426880336692474882178609894547503885

CPace cipher suites using G\_Decaf448 MUST use a hash function producing at least H.b\_max\_in\_bytes >= 112 bytes of output.
It is RECOMMENDED to use G\_Decaf448 in combination with SHAKE-256.

For both abstractions the following definitions apply:

- It is RECOMMENDED to implement G.sample\_scalar() as follows.

  - Set scalar = sample\_random\_bytes(G.group\_size\_bytes).

  - Then clear the most significant bits larger than G.group\_size\_bits.

  - Interpret the result as the little-endian encoding of an integer value and return the result.

-  Alternatively, G.sample\_scalar() MAY also implement uniform sampling between 1 and (G.group\_order - 1). (The more complex
uniform sampling process might provide a larger side-channel attack surface for embedded systems in hostile environments.)

- G.scalar\_mult(y,\_g) SHALL operate on a scalar y and a group element \_g in the internal representation of the group abstraction environment. It returns the value Y = encode((\_g)^y), i.e. it returns a value using the public encoding.

- G.I = is the public encoding representation of the identity element.

- G.scalar\_mult\_vfy(y,X) operates on a value using the public encoding and a scalar and is implemented as follows. If the decode(X) function fails, it returns G.I. Otherwise it returns encode( decode(X)^y ).

- The G.calculate\_generator(H, PRS,sid,CI) function SHALL return a decoded point and SHALL BE implemented as follows.

   - First gen\_str = generator\_string(PRS,G.DSI,CI,sid, H.s\_in\_bytes) is calculated using the input block size of the chosen hash primitive.

   - This string is then hashed to the required length gen\_str\_hash = H.hash(gen\_str, 2 * G.field\_size\_bytes).  Note that this
     implies that the permissible output length H.maxb\_in\_bytes MUST BE larger or equal to twice the field size of the group G for making a
     hashing primitive suitable. Finally the internal representation of the generator \_g is calculated as \_g = one\_way\_map(gen\_str\_hash)
     using the one-way map function from the abstraction.

Note that with these definitions the scalar\_mult function operates on a _decoded_ point \_g and returns an encoded point,
while the scalar\_mult\_vfy(y,X) function operates on an encoded point X (and also returns an encoded point).

## CPace group objects for curves in Short-Weierstrass representation {#CPaceWeierstrass}

The group environment objects G defined in this section for use with Short-Weierstrass curves,
are parametrized by the choice of an elliptic curve and by choice of a suitable encode\_to\_curve(str) function.
encode\_to\_curve(str) must map an octet string str to a point on the curve.

### Curves and associated functions

Elliptic curves in Short-Weierstrass form are considered in {{IEEE1363}}.
{{IEEE1363}} allows for both, curves of prime and non-prime order. However, for the procedures described in this section any suitable
group MUST BE of prime order.

The specification for the group environment objects specified in this section closely follow the ECKAS-DH1 method from {{IEEE1363}}.
I.e. we use the same methods and encodings and protocol substeps as employed in the TLS
 {{?RFC5246}} {{?RFC8446}} protocol family.

For CPace only the uncompressed full-coordinate encodings from {{SEC1}} (x _and_ y coordinate) SHOULD be used.
Commonly used curve groups are specified in {{SEC2}} and {{?RFC5639}}. A typical representative of such a Short-Weierstrass curve is NIST-P256.
Point verification as used in ECKAS-DH1 is described in Annex A.16.10. of {{IEEE1363}}.

For deriving Diffie-Hellman shared secrets ECKAS-DH1 from {{IEEE1363}} specifies the use of an ECSVDP-DH method. ECSVDP-DH either returns "error" or the x-coordinate of the Diffie-Hellman shared secret.

### Suitable encode\_to\_curve methods

All the encode\_to\_curve methods specified {{!I-D.irtf-cfrg-hash-to-curve}}
are suitable for CPace. For Short-Weierstrass curves it is RECOMMENDED to use the non-uniform variant of the SSWU
mapping primitive from {{!I-D.irtf-cfrg-hash-to-curve}} if a SSWU mapping is available for the chosen curve.

### Definition of the group environment G for Short-Weierstrass curves

In this paragraph we use the following notation for defining the group object G for a selected curve and encode\_to\_curve method:

- With G.group\_order we denote the order of the elliptic curve which MUST BE a prime.

- With G.is\_valid(X) we denote a method which operates on an octet stream according to {{SEC1}} of a point on the group and returns true if the point is valid or false otherwise. This G.is\_valid(X) method SHALL be implemented according to Annex A.16.10. of {{IEEE1363}}. I.e. it shall return false if X encodes either the neutral element on the group or does not form a valid encoding of a point on the group.

- With G.encode\_to\_curve(str) we denote a selected mapping function from {{!I-D.irtf-cfrg-hash-to-curve}}. I.e. a function that maps
octet string str to a point on the group. {{!I-D.irtf-cfrg-hash-to-curve}} considers both, uniform and non-uniform mappings based on several different strategies. It is RECOMMENDED to use the nonuniform variant of the SSWU mapping primitive within {{!I-D.irtf-cfrg-hash-to-curve}}.

- G.DSI denotes a domain-separation identifier string. G.DSI which SHALL BE obtained by the concatenation of "CPace" and the associated name of the cipher suite used for the encode\_to\_curve function as specified in {{!I-D.irtf-cfrg-hash-to-curve}}. E.g. when using the map with the name "P384\_XMD:SHA-384\_SSWU\_NU\_"
on curve NIST-P384 the resulting value SHALL BE G.DSI = "CPaceP384\_XMD:SHA-384\_SSWU\_NU\_".

Using the above definitions, the CPace functions required for the group object G are defined as follows.

- G.sample\_scalar() SHALL return a value between 1 and (G.group\_order - 1). The value sampling MUST BE uniformly random. It is RECOMMENDED to use rejection sampling for converting a uniform bitstring to a uniform value between 1 and (G.group\_order - 1).

- G.calculate\_generator(H, PRS,sid,CI) function SHALL be implemented as follows.

   - First gen\_str = generator\_string(PRS,G.DSI,CI,sid, H.s\_in\_bytes) is calculated.

   - Then the output of a call to G.encode\_to\_curve(gen\_str) is returned, using the selected function from {{!I-D.irtf-cfrg-hash-to-curve}}.

- G.scalar\_mult(s,X) is a function that operates on a scalar s and an input point X. The input X shall use the same encoding as produced by the G.calculate\_generator method above.
G.scalar\_mult(s,X) SHALL return an encoding of the point X^s according to {{SEC1}}. It SHOULD use the full-coordinate format without compression that encodes both, x and y coordinates of the result point.

- G.scalar\_mult\_vfy(s,X) merges verification of point X according to {{IEEE1363}} A.16.10. and the the ECSVDP-DH procedure from {{IEEE1363}}.
It SHALL BE implemented as follows:

   - If G.is\_valid(X) = False then G.scalar\_mult\_vfy(s,X) SHALL return "error".

   - Otherwise G.scalar\_mult\_vfy(s,X) SHALL return the result of the ECSVDP-DH procedure from {{IEEE1363}} (section 7.2.1). I.e. it shall
     either return "error" (in case that X^s is the neutral element) or the secret shared value "z" (otherwise). "z" SHALL be encoded by using
     the big-endian encoding of the x-coordinate of the result point X^s according to {{SEC1}}.

- We represent the neutral element G.I by using the encoding of the "error" result case from the G.scalar\_mult\_vfy method above.


# Security Considerations {#sec-considerations}

A security proof of CPace is found in {{CPacePaper}}. This proof covers all recommended cipher suites included in this document.
In the following sections we firstly describe aspects to consider when deviating from recommended cipher suites. Secondly we aim at
giving guidance for implementations.

## Party identifiers and relay-attacks

If unique strings identifying the protocol partners are included either as part of the channel identifier CI, the session id sid or the associated data fields ADa, ADb, the ISK will provide implicit authentication also regarding the party identities. Incorporating party identifier strings
is important for fending-off relay-attacks.

Such attacks may become relevant, e.g., in a setting where several servers share the same password PRS

- Here an adversary might relay messages from a honest user A which aims at interacting to server B to a server C instead.

- If no party identifier strings are used, and B and C use the same PRS value, A might be establishing a common ISK key with C while assuming to be interacting with party B.

Including and checking party identifiers for correct values can fend off such relay-attacks.

## Security considerations regarding sampling of scalars
For curves over fields F\_p where p is a prime close to a power of two 2^field\_size\_bits, we recommend sampling scalars as a uniform bit string of length field\_size\_bits. We do so in order to reduce both, complexity of the implementation and reducing the attack surface
with respect to side-channels for embedded systems in hostile environments.
The effect of non-uniform sampling was analyzed in {{CPacePaper}} for the case of Curve25519 and Curve448.

This analysis does not transfer most curves in Short-Weierstrass form. As a result, we recommend rejection sampling for the group environment
objects from {{CPaceWeierstrass}}.

## Security considerations regarding hashing and key derivation

In order to prevent analysis of length-extension attacks on hash functions, all hash input strings in CPace are designed to be prefix-free strings which have the length of individual substrings prependeded.
This choice was made in order to make CPace suitable also for hash function instantiations using
Merkle-Damgard constructions such as SHA2 or SHA512 along the lines of {{CDMP05}}.
This is guaranteed by the design of the prefix\_free\_cat() function. In case that an application whishes to use an
other form of encoding, the guidance given in {{CDMP05}} SHOULD BE considered.

Although already K is a shared value, still it MUST NOT itself be used as a shared secret key. Instead ISK MUST BE used. Leakage of K to an adversary can lead to offline-dictionary attacks.

## Security considerations for single-coordinate CPace on Montgomery curves

The definitions given for the recommended cipher suites for the Montgomery curves Curve25519 and Curve448 in {{CPaceMontgomery}} rely on the following properties  {{CPacePaper}}:

- The curve has order (p * c) with p prime and c a small cofactor. Also the curve's quadratic twist must be of order (p' * c') with p' prime and c' a cofactor.

- The cofactor c' of the twist MUST BE EQUAL to or an integer multiple of the cofactor c of the curve.

- Both field order q and group order p MUST BE close to a power of two along the lines of {{CPacePaper}}, Appendix E.

- The representation of the neutral element G.I MUST BE the same for both, the curve and its twist.

- The implementation of G.scalar\_mult\_vfy(y,X) MUST map all c low-order points on the curve and all c' low-order points on the twist  on the representation of the identity element G.I.

Alternative Montgomery curves outside of the set recommended here, can use the specifications given in {{CPaceMontgomery}} given, that the above properties hold.

## Verification of invalid point detection

Correct implementation of point verification SHALL BE verified for any actual CPace implementation. As such, it SHOULD BE checked that the abort cases in the protocol specification are indeed triggered whenever an inbound message (MSGa or MSGb) includes a point (Ya or Yb) that makes G.scalar\_mult\_vfy(y,Ya) output the error-result G.I.

The verification SHALL be carried out by including any of the invalid points in both MSGa _and_ MSGb, in order to make sure that _both_ parties have the verification checks properly implemented.

For any of the recommended cipher suites, the appendix gives a set of the invalid point representations that MUST trigger the abort case.

### Verification for Short-Weierstrass

For implementations offering Short-Weierstrass cipher suites, the verification checks MUST verify that the abort cases are triggered if
MSGa or MSGb include either of, the point at infinity and an invalid point not on the curve.

### Verification of invalid point detection for X448 and X25519
The Curve25519-based cipher suite employs the twist security feature of the curve for point validation.
As such, it is MANDATORY to check that any actual X448 and X25519 function implementation maps
all low-order points on both the curve and the twist on the neutral element and correctly clears bit #255 of field elements.
Corresponding test vectors which produce the all-zero outputs are provided in the appendix. All inputs that produce an all-zero
output of G.scalar\_mult\_vfy(s,Y) MUST trigger the abort case.

### Verification for Decaf448 and Ristretto255

Similarly for CPace on Decaf448 and Ristretto255 the verification checks of the protocol implementation
MUST verify that the abort cases are triggered if
MSGa or MSGb include either of, invalid encodings or encodings of the neutral element. The appendix gives corresponding test vectors.


## Nonce values

Secret scalars ya and yb MUST NOT be reused. Values for sid SHOULD NOT be reused as the composability
guarantees of the simulation-based proof rely on uniqueness of session ids {{CPacePaper}}.

If CPace is used as a building block of higher-level protocols, it is RECOMMENDED that sid
is generated by the higher-level protocol and passed to CPace. One suitable option is that sid
is generated by concatenating ephemeral random strings from both parties.

## Password hashing and application environments

Password databases in a client/server setting SHOULD use iterated password hashing such as specified in {{?RFC7914}} (scrypt) and {{?RFC9106}}
(Argon2). Such iterated password hashing requires the exchange of so-called "salt" nonce values.
CPace does not itself provide mechanisms for agreeing on such salt values.
(For an analysis of this aspect see, e.g., the discussion in {{AUCPacePaper}} where
CPace has been used as building block within the augmented AuCPace protocol {{AUCPacePaper}}).

As a consequence, in a setting of a server with several distinct users it is RECOMMENDED to seriously
consider the augmented PAKE protocol OPAQUE {{?I-D.draft-irtf-cfrg-opaque}} instead.

## Side channel considerations

All state-of-the art methods for realizing constant-time execution SHOULD be used.

In case that side-channel attacks are to be considered practical for a given application, it is RECOMMENDED to pay special
attention on the substeps used for of calculating
the secret generator G.calculate_generator(PRS,CI,sid).
The most critical substep to consider might be the processing of the first block of the hash that includes
the PRS string.

In case of a server unit which is considering to store the PRS string in its persistent memory,
it is RECOMMENDED not to persist the original PRS string itself. Instead it is RECOMMENDED to instead
persist the intermediate hash function's state that is obtained after processing the first input block that includes the PRS string.
Note that the first hashing block in CPace is designed to include only the PRS string (i.e. no session-specific variable inputs).
When storing the intermediate state but not PRS itself, the attacker might be able to observe at most one single power traces for this first block (with PRS included). An attacker might then be forced to mount a combined side-channel and password dictionary attack instead of a
conventional divide-and-conquer approach that attacks individual PRS bytes one-by-one.

The zero-padding introduced when hashing the sensitive PRS string can be expected to make
the task for a side-channel attack somewhat more complex. Still this feature alone is not sufficient for ruling out power analysis attacks.

## Quantum computers

CPace is proven secure under the hardness of the computational Simultaneous Diffie-Hellmann (SDH)
assumption in the group G (as defined in {{CPacePaper}}).
This assumption is not expected to hold any longer if large-scale quantum computers (LSQC) happen to  become available.
Still even in case that LSQC emerge, it is reasonable to assume that discrete-logarithm calculations will remain costly.
Here CPace whith ephemeral session id values
forces the adversary to solve one computational Diffie-Hellman problem per password guess {{CPacePaper2}}.
In this sense, using the wording suggested by Steve Thomas on the CFRG mailing list, CPace is "quantum-annoying".

# IANA Considerations

No IANA action is required.

# Acknowledgements

Thanks to the members of the CFRG for comments and advice. Any comment and advice is appreciated.

--- back




# CPace function definitions


## Definition and test vectors for string utility functions


### prepend_length function


~~~
  def prepend_length_to_bytes(data):
      length_as_utf8_string = chr(len(data)).encode('utf-8')
      return (length_as_utf8_string + data)
~~~


### prepend_length test vectors

~~~
  prepend_length_to_bytes(b""): (length: 1 bytes)
    00
  prepend_length_to_bytes(b"1234"): (length: 5 bytes)
    0431323334
  prepend_length_to_bytes(bytes(range(127))):
  (length: 128 bytes)
    7f000102030405060708090a0b0c0d0e0f101112131415161718191a1b
    1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738
    393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455
    565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172
    737475767778797a7b7c7d7e
  prepend_length_to_bytes(bytes(range(128))):
  (length: 130 bytes)
    c280000102030405060708090a0b0c0d0e0f101112131415161718191a
    1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637
    38393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f5051525354
    55565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f7071
    72737475767778797a7b7c7d7e7f
~~~

### prefix_free_cat function


~~~
  def prefix_free_cat(*args):
      result = b""
      for arg in args:
          result += prepend_length_to_bytes(arg)
      return result
~~~


### Testvector for prefix_free_cat()

~~~
  prefix_free_cat(b"1234",b"5",b"",b"6789"):
  (length: 13 bytes)
    04313233340135000436373839
~~~

## Definitions and test vector ordered concatenation


### Definitions ordered concatenation

~~~
  def oCAT(str1,str2):
      if str1 > str2:
          return str1 + str2
      else:
          return str2 + str1
~~~

### Test vectors ordered concatenation

~~~
  string comparison for oCAT:
    b"\0" > b"\0\0" == False
    b"\1" > b"\0\0" == True
    b"\0\0" > b"\0" == True
    b"\0\0" > b"\1" == False
    b"\0\1" > b"\1" == False
    b"ABCD" > b"BCD" == False

  oCAT(b"ABCD",b"BCD"): (length: 7 bytes)
    42434441424344
  oCAT(b"BCD",b"ABCDE"): (length: 8 bytes)
    4243444142434445
~~~


## Decoding and Encoding functions according to RFC7748

~~~
   def decodeLittleEndian(b, bits):
       return sum([b[i] << 8*i for i in range((bits+7)/8)])

   def decodeUCoordinate(u, bits):
       u_list = [ord(b) for b in u]
       # Ignore any unused bits.
       if bits % 8:
           u_list[-1] &= (1<<(bits%8))-1
       return decodeLittleEndian(u_list, bits)

   def encodeUCoordinate(u, bits):
       u = u % p
       return ''.join([chr((u >> 8*i) & 0xff)
                       for i in range((bits+7)/8)])
~~~



## Elligator 2 reference implementation
The Elligator 2 map requires a non-square field element Z which shall be calculated
as follows.

~~~
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

The following code maps a field element r to an encoded field element which
is a valid u-coordinate of a Montgomery curve with curve parameter A.

~~~
    def elligator2(r, q, A, field_size_bits):
        # Inputs: field element r, field order q,
        #         curve parameter A and field size in bits
        Fq = GF(q); A = Fq(A); B = Fq(1);

        # calculate non-square z as specified in the hash2curve draft.
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
    PRS = b'Password' ; ZPAD length: 118 ; DSI = b'CPace255'
    CI = b'\nAinitiator\nBresponder'
    CI = 0a41696e69746961746f720a42726573706f6e646572
    sid = 7e4b4791d6a8ef019b936c79fb7f2c57
  Outputs
    hash generator string: (length: 32 bytes)
      8094a6b3638fb04e81fd8fa41c14a12d275da121b271836435f13eac
      7f36c081
    decoded field element of 255 bits: (length: 32 bytes)
      8094a6b3638fb04e81fd8fa41c14a12d275da121b271836435f13eac
      7f36c001
    generator g: (length: 32 bytes)
      2d42aaeeafc98341112f349009438500ccbfc3a468af3ee703538736
      00266459
~~~

###  Test vector for MSGa

~~~
  Inputs
    ADa = b'ADa'
    ya (little endian): (length: 32 bytes)
      21b4f4bd9e64ed355c3eb676a28ebedaf6d8f17bdc365995b3190971
      53044080
  Outputs
    Ya: (length: 32 bytes)
      bda9c0bbda668bbfa082863b39d5611d494ea4b4f63148adaddf49c8
      7d616456
    MSGa: (length: 37 bytes)
      20bda9c0bbda668bbfa082863b39d5611d494ea4b4f63148adaddf49
      c87d61645603414461
~~~

###  Test vector for MSGb

~~~
  Inputs
    ADb = b'ADb'
    yb (little endian): (length: 32 bytes)
      848b0779ff415f0af4ea14df9dd1d3c29ac41d836c7808896c4eba19
      c51ac40a
  Outputs
    Yb: (length: 32 bytes)
      ebe179457f3bd9aad5949ba0adab307611a9d887e651183ea146bb93
      a67ee347
    MSGb: (length: 37 bytes)
      20ebe179457f3bd9aad5949ba0adab307611a9d887e651183ea146bb
      93a67ee34703414462
~~~

###  Test vector for secret points K

~~~
    scalar_mult_vfy(ya,Yb): (length: 32 bytes)
      0ef51e811a4ac0e5889f2040d005e6ac969de3320f3575294ce71eb3
      5e8a1037
    scalar_mult_vfy(yb,Ya): (length: 32 bytes)
      0ef51e811a4ac0e5889f2040d005e6ac969de3320f3575294ce71eb3
      5e8a1037
~~~


###  Test vector for ISK calculation initiator/responder

~~~
    unordered cat of transcript : (length: 74 bytes)
      20bda9c0bbda668bbfa082863b39d5611d494ea4b4f63148adaddf49
      c87d6164560341446120ebe179457f3bd9aad5949ba0adab307611a9
      d887e651183ea146bb93a67ee34703414462
    DSI = G.DSI_ISK, b'CPace255_ISK': (length: 12 bytes)
      43506163653235355f49534b
    prefix_free_cat(DSI,sid,K)||MSGa||MSGb: (length: 137 bytes)
      0c43506163653235355f49534b107e4b4791d6a8ef019b936c79fb7f
      2c57200ef51e811a4ac0e5889f2040d005e6ac969de3320f3575294c
      e71eb35e8a103720bda9c0bbda668bbfa082863b39d5611d494ea4b4
      f63148adaddf49c87d6164560341446120ebe179457f3bd9aad5949b
      a0adab307611a9d887e651183ea146bb93a67ee34703414462
    ISK result: (length: 64 bytes)
      4ac69bdda900a8d5a17c41aa1bdeec61a08f1c157f59f925a70f0d9d
      6050e2240a5f019d110711299192804bb1e6e2ecb4b3fb50f2b70220
      fe4119458df2d600
~~~

###  Test vector for ISK calculation parallel execution

~~~
    ordered cat of transcript : (length: 74 bytes)
      20ebe179457f3bd9aad5949ba0adab307611a9d887e651183ea146bb
      93a67ee3470341446220bda9c0bbda668bbfa082863b39d5611d494e
      a4b4f63148adaddf49c87d61645603414461
    DSI = G.DSI_ISK, b'CPace255_ISK': (length: 12 bytes)
      43506163653235355f49534b
    prefix_free_cat(DSI,sid,K)||oCAT(MSGa,MSGb):
    (length: 137 bytes)
      0c43506163653235355f49534b107e4b4791d6a8ef019b936c79fb7f
      2c57200ef51e811a4ac0e5889f2040d005e6ac969de3320f3575294c
      e71eb35e8a103720ebe179457f3bd9aad5949ba0adab307611a9d887
      e651183ea146bb93a67ee3470341446220bda9c0bbda668bbfa08286
      3b39d5611d494ea4b4f63148adaddf49c87d61645603414461
    ISK result: (length: 64 bytes)
      deed1cd5c1ea2c45148313962d267b8e528c3b4bb0217b7aba653432
      309aba1494ad6add2f8fb0b2f8daee47fa49a89b448fa268161bd3ed
      84a49ee046695d54
~~~

###  Corresponding ANSI-C initializers

~~~
const uint8_t tc_PRS[] = {
 0x50,0x61,0x73,0x73,0x77,0x6f,0x72,0x64,
};
const uint8_t tc_CI[] = {
 0x0a,0x41,0x69,0x6e,0x69,0x74,0x69,0x61,0x74,0x6f,0x72,0x0a,
 0x42,0x72,0x65,0x73,0x70,0x6f,0x6e,0x64,0x65,0x72,
};
const uint8_t tc_sid[] = {
 0x7e,0x4b,0x47,0x91,0xd6,0xa8,0xef,0x01,0x9b,0x93,0x6c,0x79,
 0xfb,0x7f,0x2c,0x57,
};
const uint8_t tc_g[] = {
 0x2d,0x42,0xaa,0xee,0xaf,0xc9,0x83,0x41,0x11,0x2f,0x34,0x90,
 0x09,0x43,0x85,0x00,0xcc,0xbf,0xc3,0xa4,0x68,0xaf,0x3e,0xe7,
 0x03,0x53,0x87,0x36,0x00,0x26,0x64,0x59,
};
const uint8_t tc_ya[] = {
 0x21,0xb4,0xf4,0xbd,0x9e,0x64,0xed,0x35,0x5c,0x3e,0xb6,0x76,
 0xa2,0x8e,0xbe,0xda,0xf6,0xd8,0xf1,0x7b,0xdc,0x36,0x59,0x95,
 0xb3,0x19,0x09,0x71,0x53,0x04,0x40,0x80,
};
const uint8_t tc_ADa[] = {
 0x41,0x44,0x61,
};
const uint8_t tc_Ya[] = {
 0xbd,0xa9,0xc0,0xbb,0xda,0x66,0x8b,0xbf,0xa0,0x82,0x86,0x3b,
 0x39,0xd5,0x61,0x1d,0x49,0x4e,0xa4,0xb4,0xf6,0x31,0x48,0xad,
 0xad,0xdf,0x49,0xc8,0x7d,0x61,0x64,0x56,
};
const uint8_t tc_yb[] = {
 0x84,0x8b,0x07,0x79,0xff,0x41,0x5f,0x0a,0xf4,0xea,0x14,0xdf,
 0x9d,0xd1,0xd3,0xc2,0x9a,0xc4,0x1d,0x83,0x6c,0x78,0x08,0x89,
 0x6c,0x4e,0xba,0x19,0xc5,0x1a,0xc4,0x0a,
};
const uint8_t tc_ADb[] = {
 0x41,0x44,0x62,
};
const uint8_t tc_Yb[] = {
 0xeb,0xe1,0x79,0x45,0x7f,0x3b,0xd9,0xaa,0xd5,0x94,0x9b,0xa0,
 0xad,0xab,0x30,0x76,0x11,0xa9,0xd8,0x87,0xe6,0x51,0x18,0x3e,
 0xa1,0x46,0xbb,0x93,0xa6,0x7e,0xe3,0x47,
};
const uint8_t tc_K[] = {
 0x0e,0xf5,0x1e,0x81,0x1a,0x4a,0xc0,0xe5,0x88,0x9f,0x20,0x40,
 0xd0,0x05,0xe6,0xac,0x96,0x9d,0xe3,0x32,0x0f,0x35,0x75,0x29,
 0x4c,0xe7,0x1e,0xb3,0x5e,0x8a,0x10,0x37,
};
const uint8_t tc_ISK_IR[] = {
 0x4a,0xc6,0x9b,0xdd,0xa9,0x00,0xa8,0xd5,0xa1,0x7c,0x41,0xaa,
 0x1b,0xde,0xec,0x61,0xa0,0x8f,0x1c,0x15,0x7f,0x59,0xf9,0x25,
 0xa7,0x0f,0x0d,0x9d,0x60,0x50,0xe2,0x24,0x0a,0x5f,0x01,0x9d,
 0x11,0x07,0x11,0x29,0x91,0x92,0x80,0x4b,0xb1,0xe6,0xe2,0xec,
 0xb4,0xb3,0xfb,0x50,0xf2,0xb7,0x02,0x20,0xfe,0x41,0x19,0x45,
 0x8d,0xf2,0xd6,0x00,
};
const uint8_t tc_ISK_SY[] = {
 0xde,0xed,0x1c,0xd5,0xc1,0xea,0x2c,0x45,0x14,0x83,0x13,0x96,
 0x2d,0x26,0x7b,0x8e,0x52,0x8c,0x3b,0x4b,0xb0,0x21,0x7b,0x7a,
 0xba,0x65,0x34,0x32,0x30,0x9a,0xba,0x14,0x94,0xad,0x6a,0xdd,
 0x2f,0x8f,0xb0,0xb2,0xf8,0xda,0xee,0x47,0xfa,0x49,0xa8,0x9b,
 0x44,0x8f,0xa2,0x68,0x16,0x1b,0xd3,0xed,0x84,0xa4,0x9e,0xe0,
 0x46,0x69,0x5d,0x54,
};
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

##  Test vector for CPace using group X448 and hash SHAKE-256


###  Test vectors for calculate\_generator with group X448

~~~
  Inputs
    H   = SHAKE-256 with input block size 136 bytes.
    PRS = b'Password' ; ZPAD length: 126 ; DSI = b'CPace448'
    CI = b'\nAinitiator\nBresponder'
    CI = 0a41696e69746961746f720a42726573706f6e646572
    sid = 5223e0cdc45d6575668d64c552004124
  Outputs
    hash generator string: (length: 56 bytes)
      d28572fc9ab2154752f8a74642f0ef59f006cbe15c432ea80f9f3f78
      c7ce96453fa40bb1ce05b15510c86d4529e3a73232c9438c7aeb13e5
    decoded field element of 448 bits: (length: 32 bytes)
      d28572fc9ab2154752f8a74642f0ef59f006cbe15c432ea80f9f3f78
      c7ce9645
    generator g: (length: 56 bytes)
      50135658002afcc03f8e331d3c88d6bfd186791069f76a216fb00137
      afef584672c034c70348c7721ef7f2eac26c292182626ff34fdcd95a
~~~

###  Test vector for MSGa

~~~
  Inputs
    ADa = b'ADa'
    ya (little endian): (length: 56 bytes)
      45acf93116ae5d3dae995a7c627df2924321a8e857d9a200807131e3
      8839b0c2b357bbc6b6d0bc59bf9efff940f43f1892559bf4e5182c17
  Outputs
    Ya: (length: 56 bytes)
      5cfb6fc59e76c2446c76c82899c4b3a805f8a3bb8ebab573b88f7243
      1a3e7e40f047f0bed311bad71bf9b78032655c8655df14e79a82bc8e
    MSGa: (length: 61 bytes)
      385cfb6fc59e76c2446c76c82899c4b3a805f8a3bb8ebab573b88f72
      431a3e7e40f047f0bed311bad71bf9b78032655c8655df14e79a82bc
      8e03414461
~~~

###  Test vector for MSGb

~~~
  Inputs
    ADb = b'ADb'
    yb (little endian): (length: 56 bytes)
      a145e914b347002d298ce2051394f0ed68cf3623dfe5db082c78ffa5
      a667acdc946caa301a01983e5be7b50e9d4564f813a02542efed1f91
  Outputs
    Yb: (length: 56 bytes)
      c1a9eb498b623df32dba8a299c4d2f5e01066dbef6fbd85687d84725
      141ddef072fa621afd28ece71b6a3a4a8da5f091c7101c7d51f05127
    MSGb: (length: 61 bytes)
      38c1a9eb498b623df32dba8a299c4d2f5e01066dbef6fbd85687d847
      25141ddef072fa621afd28ece71b6a3a4a8da5f091c7101c7d51f051
      2703414462
~~~

###  Test vector for secret points K

~~~
    scalar_mult_vfy(ya,Yb): (length: 56 bytes)
      e53b4f9f8dae7a92d9cf2cab18919c7ff6a33a0030bbe70c863fe282
      10b51f9c455db36edccb266c10ca19980411386cfda4c2c97e160db7
    scalar_mult_vfy(yb,Ya): (length: 56 bytes)
      e53b4f9f8dae7a92d9cf2cab18919c7ff6a33a0030bbe70c863fe282
      10b51f9c455db36edccb266c10ca19980411386cfda4c2c97e160db7
~~~


###  Test vector for ISK calculation initiator/responder

~~~
    unordered cat of transcript : (length: 122 bytes)
      385cfb6fc59e76c2446c76c82899c4b3a805f8a3bb8ebab573b88f72
      431a3e7e40f047f0bed311bad71bf9b78032655c8655df14e79a82bc
      8e0341446138c1a9eb498b623df32dba8a299c4d2f5e01066dbef6fb
      d85687d84725141ddef072fa621afd28ece71b6a3a4a8da5f091c710
      1c7d51f0512703414462
    DSI = G.DSI_ISK, b'CPace448_ISK': (length: 12 bytes)
      43506163653434385f49534b
    prefix_free_cat(DSI,sid,K)||MSGa||MSGb: (length: 209 bytes)
      0c43506163653434385f49534b105223e0cdc45d6575668d64c55200
      412438e53b4f9f8dae7a92d9cf2cab18919c7ff6a33a0030bbe70c86
      3fe28210b51f9c455db36edccb266c10ca19980411386cfda4c2c97e
      160db7385cfb6fc59e76c2446c76c82899c4b3a805f8a3bb8ebab573
      b88f72431a3e7e40f047f0bed311bad71bf9b78032655c8655df14e7
      9a82bc8e0341446138c1a9eb498b623df32dba8a299c4d2f5e01066d
      bef6fbd85687d84725141ddef072fa621afd28ece71b6a3a4a8da5f0
      91c7101c7d51f0512703414462
    ISK result: (length: 64 bytes)
      4479a287cfccbc3bbd18df61bbba5853f866710548b53f4802ed25ab
      c181dfcffa4e89e6dc68bd51baf7d757892ffba77eb3a2e0a0ee4480
      fbeb07974d8a4132
~~~

###  Test vector for ISK calculation parallel execution

~~~
    ordered cat of transcript : (length: 122 bytes)
      38c1a9eb498b623df32dba8a299c4d2f5e01066dbef6fbd85687d847
      25141ddef072fa621afd28ece71b6a3a4a8da5f091c7101c7d51f051
      2703414462385cfb6fc59e76c2446c76c82899c4b3a805f8a3bb8eba
      b573b88f72431a3e7e40f047f0bed311bad71bf9b78032655c8655df
      14e79a82bc8e03414461
    DSI = G.DSI_ISK, b'CPace448_ISK': (length: 12 bytes)
      43506163653434385f49534b
    prefix_free_cat(DSI,sid,K)||oCAT(MSGa,MSGb):
    (length: 209 bytes)
      0c43506163653434385f49534b105223e0cdc45d6575668d64c55200
      412438e53b4f9f8dae7a92d9cf2cab18919c7ff6a33a0030bbe70c86
      3fe28210b51f9c455db36edccb266c10ca19980411386cfda4c2c97e
      160db738c1a9eb498b623df32dba8a299c4d2f5e01066dbef6fbd856
      87d84725141ddef072fa621afd28ece71b6a3a4a8da5f091c7101c7d
      51f0512703414462385cfb6fc59e76c2446c76c82899c4b3a805f8a3
      bb8ebab573b88f72431a3e7e40f047f0bed311bad71bf9b78032655c
      8655df14e79a82bc8e03414461
    ISK result: (length: 64 bytes)
      16ad185633706299ef0365093f964ff483b30a5fba0d90b6f01c1e86
      80b87c9cde7c58fcb947835d1b6a31823fd1f09b8fa340762dd7d70a
      f176dff3d26a1c2a
~~~

###  Corresponding ANSI-C initializers

~~~
const uint8_t tc_PRS[] = {
 0x50,0x61,0x73,0x73,0x77,0x6f,0x72,0x64,
};
const uint8_t tc_CI[] = {
 0x0a,0x41,0x69,0x6e,0x69,0x74,0x69,0x61,0x74,0x6f,0x72,0x0a,
 0x42,0x72,0x65,0x73,0x70,0x6f,0x6e,0x64,0x65,0x72,
};
const uint8_t tc_sid[] = {
 0x52,0x23,0xe0,0xcd,0xc4,0x5d,0x65,0x75,0x66,0x8d,0x64,0xc5,
 0x52,0x00,0x41,0x24,
};
const uint8_t tc_g[] = {
 0x50,0x13,0x56,0x58,0x00,0x2a,0xfc,0xc0,0x3f,0x8e,0x33,0x1d,
 0x3c,0x88,0xd6,0xbf,0xd1,0x86,0x79,0x10,0x69,0xf7,0x6a,0x21,
 0x6f,0xb0,0x01,0x37,0xaf,0xef,0x58,0x46,0x72,0xc0,0x34,0xc7,
 0x03,0x48,0xc7,0x72,0x1e,0xf7,0xf2,0xea,0xc2,0x6c,0x29,0x21,
 0x82,0x62,0x6f,0xf3,0x4f,0xdc,0xd9,0x5a,
};
const uint8_t tc_ya[] = {
 0x45,0xac,0xf9,0x31,0x16,0xae,0x5d,0x3d,0xae,0x99,0x5a,0x7c,
 0x62,0x7d,0xf2,0x92,0x43,0x21,0xa8,0xe8,0x57,0xd9,0xa2,0x00,
 0x80,0x71,0x31,0xe3,0x88,0x39,0xb0,0xc2,0xb3,0x57,0xbb,0xc6,
 0xb6,0xd0,0xbc,0x59,0xbf,0x9e,0xff,0xf9,0x40,0xf4,0x3f,0x18,
 0x92,0x55,0x9b,0xf4,0xe5,0x18,0x2c,0x17,
};
const uint8_t tc_ADa[] = {
 0x41,0x44,0x61,
};
const uint8_t tc_Ya[] = {
 0x5c,0xfb,0x6f,0xc5,0x9e,0x76,0xc2,0x44,0x6c,0x76,0xc8,0x28,
 0x99,0xc4,0xb3,0xa8,0x05,0xf8,0xa3,0xbb,0x8e,0xba,0xb5,0x73,
 0xb8,0x8f,0x72,0x43,0x1a,0x3e,0x7e,0x40,0xf0,0x47,0xf0,0xbe,
 0xd3,0x11,0xba,0xd7,0x1b,0xf9,0xb7,0x80,0x32,0x65,0x5c,0x86,
 0x55,0xdf,0x14,0xe7,0x9a,0x82,0xbc,0x8e,
};
const uint8_t tc_yb[] = {
 0xa1,0x45,0xe9,0x14,0xb3,0x47,0x00,0x2d,0x29,0x8c,0xe2,0x05,
 0x13,0x94,0xf0,0xed,0x68,0xcf,0x36,0x23,0xdf,0xe5,0xdb,0x08,
 0x2c,0x78,0xff,0xa5,0xa6,0x67,0xac,0xdc,0x94,0x6c,0xaa,0x30,
 0x1a,0x01,0x98,0x3e,0x5b,0xe7,0xb5,0x0e,0x9d,0x45,0x64,0xf8,
 0x13,0xa0,0x25,0x42,0xef,0xed,0x1f,0x91,
};
const uint8_t tc_ADb[] = {
 0x41,0x44,0x62,
};
const uint8_t tc_Yb[] = {
 0xc1,0xa9,0xeb,0x49,0x8b,0x62,0x3d,0xf3,0x2d,0xba,0x8a,0x29,
 0x9c,0x4d,0x2f,0x5e,0x01,0x06,0x6d,0xbe,0xf6,0xfb,0xd8,0x56,
 0x87,0xd8,0x47,0x25,0x14,0x1d,0xde,0xf0,0x72,0xfa,0x62,0x1a,
 0xfd,0x28,0xec,0xe7,0x1b,0x6a,0x3a,0x4a,0x8d,0xa5,0xf0,0x91,
 0xc7,0x10,0x1c,0x7d,0x51,0xf0,0x51,0x27,
};
const uint8_t tc_K[] = {
 0xe5,0x3b,0x4f,0x9f,0x8d,0xae,0x7a,0x92,0xd9,0xcf,0x2c,0xab,
 0x18,0x91,0x9c,0x7f,0xf6,0xa3,0x3a,0x00,0x30,0xbb,0xe7,0x0c,
 0x86,0x3f,0xe2,0x82,0x10,0xb5,0x1f,0x9c,0x45,0x5d,0xb3,0x6e,
 0xdc,0xcb,0x26,0x6c,0x10,0xca,0x19,0x98,0x04,0x11,0x38,0x6c,
 0xfd,0xa4,0xc2,0xc9,0x7e,0x16,0x0d,0xb7,
};
const uint8_t tc_ISK_IR[] = {
 0x44,0x79,0xa2,0x87,0xcf,0xcc,0xbc,0x3b,0xbd,0x18,0xdf,0x61,
 0xbb,0xba,0x58,0x53,0xf8,0x66,0x71,0x05,0x48,0xb5,0x3f,0x48,
 0x02,0xed,0x25,0xab,0xc1,0x81,0xdf,0xcf,0xfa,0x4e,0x89,0xe6,
 0xdc,0x68,0xbd,0x51,0xba,0xf7,0xd7,0x57,0x89,0x2f,0xfb,0xa7,
 0x7e,0xb3,0xa2,0xe0,0xa0,0xee,0x44,0x80,0xfb,0xeb,0x07,0x97,
 0x4d,0x8a,0x41,0x32,
};
const uint8_t tc_ISK_SY[] = {
 0x16,0xad,0x18,0x56,0x33,0x70,0x62,0x99,0xef,0x03,0x65,0x09,
 0x3f,0x96,0x4f,0xf4,0x83,0xb3,0x0a,0x5f,0xba,0x0d,0x90,0xb6,
 0xf0,0x1c,0x1e,0x86,0x80,0xb8,0x7c,0x9c,0xde,0x7c,0x58,0xfc,
 0xb9,0x47,0x83,0x5d,0x1b,0x6a,0x31,0x82,0x3f,0xd1,0xf0,0x9b,
 0x8f,0xa3,0x40,0x76,0x2d,0xd7,0xd7,0x0a,0xf1,0x76,0xdf,0xf3,
 0xd2,0x6a,0x1c,0x2a,
};
~~~


### Test vectors for G\_X448.scalar\_mult\_vfy: low order points

Test vectors for which G\_X448.scalar\_mult\_vfy(s\_in,ux) must return the neutral
element
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

##  Test vector for CPace using group ristretto255 and hash SHA-512


###  Test vectors for calculate\_generator with group ristretto255

~~~
  Inputs
    H   = SHA-512 with input block size 128 bytes.
    PRS = b'Password' ; ZPAD length: 118 ;
    DSI = b'CPaceRistretto255'
    CI = b'\nAinitiator\nBresponder'
    CI = 0a41696e69746961746f720a42726573706f6e646572
    sid = 7e4b4791d6a8ef019b936c79fb7f2c57
  Outputs
    hash generator string: (length: 186 bytes)
      0850617373776f726476000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000114350616365526973747265
      74746f323535160a41696e69746961746f720a42726573706f6e6465
      72107e4b4791d6a8ef019b936c79fb7f2c57
    hash result: (length: 64 bytes)
      f3cad1569594824c1f94e13e1694e4d267052eeff202f7479e807292
      5a500b675e1ce80ca22fcbb84735f4a27a4cc7d4c2b4ffd2c14aa5ca
      1da9573b905f3161
    encoded generator g: (length: 32 bytes)
      4ca608ea0979b597df7c2ebc8ab399e1e62d4bd01eea990b8ce4e2f3
      4b942467
~~~


###  Test vector for MSGa

~~~
  Inputs
    ADa = b'ADa'
    ya (little endian): (length: 32 bytes)
      a5e49403aece4ef34b11aefc60e9a931c65548f4eef6d26e44bb4e88
      ea35e806
  Outputs
    Ya: (length: 32 bytes)
      588b7b448f3ec63bea4132f80c7b388b6f2e2a5f8205aeaee58476d5
      bf9e3135
    MSGa: (length: 37 bytes)
      20588b7b448f3ec63bea4132f80c7b388b6f2e2a5f8205aeaee58476
      d5bf9e313503414461
~~~

###  Test vector for MSGb

~~~
  Inputs
    ADb = b'ADb'
    yb (little endian): (length: 32 bytes)
      07594fdfdf6b2cef61b4a3e7843e02a809cabdbf76c3d4f8fbdfc4ed
      eb124d0f
  Outputs
    Yb: (length: 32 bytes)
      eed0b518ffd1777b2f6f18f7e15f0984aa6c4b7aae69da7f33fe0362
      3a77ab02
    MSGb: (length: 37 bytes)
      20eed0b518ffd1777b2f6f18f7e15f0984aa6c4b7aae69da7f33fe03
      623a77ab0203414462
~~~

###  Test vector for secret points K

~~~
    scalar_mult_vfy(ya,Yb): (length: 32 bytes)
      1038335b51006ed9bbdf999158a31637bc056ae023fb341c10813ef3
      0da4c52a
    scalar_mult_vfy(yb,Ya): (length: 32 bytes)
      1038335b51006ed9bbdf999158a31637bc056ae023fb341c10813ef3
      0da4c52a
~~~


###  Test vector for ISK calculation initiator/responder

~~~
    unordered cat of transcript : (length: 74 bytes)
      20588b7b448f3ec63bea4132f80c7b388b6f2e2a5f8205aeaee58476
      d5bf9e31350341446120eed0b518ffd1777b2f6f18f7e15f0984aa6c
      4b7aae69da7f33fe03623a77ab0203414462
    DSI = G.DSI_ISK, b'CPaceRistretto255_ISK':
    (length: 21 bytes)
      435061636552697374726574746f3235355f49534b
    prefix_free_cat(DSI,sid,K)||MSGa||MSGb: (length: 146 bytes)
      15435061636552697374726574746f3235355f49534b107e4b4791d6
      a8ef019b936c79fb7f2c57201038335b51006ed9bbdf999158a31637
      bc056ae023fb341c10813ef30da4c52a20588b7b448f3ec63bea4132
      f80c7b388b6f2e2a5f8205aeaee58476d5bf9e31350341446120eed0
      b518ffd1777b2f6f18f7e15f0984aa6c4b7aae69da7f33fe03623a77
      ab0203414462
    ISK result: (length: 64 bytes)
      2964fcd0711122264380b41a75b5b54953b3aa649becec76b144c6db
      6cc5eba6e02541b74212b551c7010f2fa3cecee2d6ca4d4b84856507
      d3282b85bc8b8f53
~~~

###  Test vector for ISK calculation parallel execution

~~~
    ordered cat of transcript : (length: 74 bytes)
      20eed0b518ffd1777b2f6f18f7e15f0984aa6c4b7aae69da7f33fe03
      623a77ab020341446220588b7b448f3ec63bea4132f80c7b388b6f2e
      2a5f8205aeaee58476d5bf9e313503414461
    DSI = G.DSI_ISK, b'CPaceRistretto255_ISK':
    (length: 21 bytes)
      435061636552697374726574746f3235355f49534b
    prefix_free_cat(DSI,sid,K)||oCAT(MSGa,MSGb):
    (length: 146 bytes)
      15435061636552697374726574746f3235355f49534b107e4b4791d6
      a8ef019b936c79fb7f2c57201038335b51006ed9bbdf999158a31637
      bc056ae023fb341c10813ef30da4c52a20eed0b518ffd1777b2f6f18
      f7e15f0984aa6c4b7aae69da7f33fe03623a77ab020341446220588b
      7b448f3ec63bea4132f80c7b388b6f2e2a5f8205aeaee58476d5bf9e
      313503414461
    ISK result: (length: 64 bytes)
      b608bfbb7b5508fe56cad0aa41f8d07b600035f53848f86b796eabe6
      3f816a506b678baa34f78779da601ab3b5106250701ff2a0fddb3a5b
      7845622ccb66b3f7
~~~

###  Corresponding ANSI-C initializers

~~~
const uint8_t tc_PRS[] = {
 0x50,0x61,0x73,0x73,0x77,0x6f,0x72,0x64,
};
const uint8_t tc_CI[] = {
 0x0a,0x41,0x69,0x6e,0x69,0x74,0x69,0x61,0x74,0x6f,0x72,0x0a,
 0x42,0x72,0x65,0x73,0x70,0x6f,0x6e,0x64,0x65,0x72,
};
const uint8_t tc_sid[] = {
 0x7e,0x4b,0x47,0x91,0xd6,0xa8,0xef,0x01,0x9b,0x93,0x6c,0x79,
 0xfb,0x7f,0x2c,0x57,
};
const uint8_t tc_g[] = {
 0x4c,0xa6,0x08,0xea,0x09,0x79,0xb5,0x97,0xdf,0x7c,0x2e,0xbc,
 0x8a,0xb3,0x99,0xe1,0xe6,0x2d,0x4b,0xd0,0x1e,0xea,0x99,0x0b,
 0x8c,0xe4,0xe2,0xf3,0x4b,0x94,0x24,0x67,
};
const uint8_t tc_ya[] = {
 0xa5,0xe4,0x94,0x03,0xae,0xce,0x4e,0xf3,0x4b,0x11,0xae,0xfc,
 0x60,0xe9,0xa9,0x31,0xc6,0x55,0x48,0xf4,0xee,0xf6,0xd2,0x6e,
 0x44,0xbb,0x4e,0x88,0xea,0x35,0xe8,0x06,
};
const uint8_t tc_ADa[] = {
 0x41,0x44,0x61,
};
const uint8_t tc_Ya[] = {
 0x58,0x8b,0x7b,0x44,0x8f,0x3e,0xc6,0x3b,0xea,0x41,0x32,0xf8,
 0x0c,0x7b,0x38,0x8b,0x6f,0x2e,0x2a,0x5f,0x82,0x05,0xae,0xae,
 0xe5,0x84,0x76,0xd5,0xbf,0x9e,0x31,0x35,
};
const uint8_t tc_yb[] = {
 0x07,0x59,0x4f,0xdf,0xdf,0x6b,0x2c,0xef,0x61,0xb4,0xa3,0xe7,
 0x84,0x3e,0x02,0xa8,0x09,0xca,0xbd,0xbf,0x76,0xc3,0xd4,0xf8,
 0xfb,0xdf,0xc4,0xed,0xeb,0x12,0x4d,0x0f,
};
const uint8_t tc_ADb[] = {
 0x41,0x44,0x62,
};
const uint8_t tc_Yb[] = {
 0xee,0xd0,0xb5,0x18,0xff,0xd1,0x77,0x7b,0x2f,0x6f,0x18,0xf7,
 0xe1,0x5f,0x09,0x84,0xaa,0x6c,0x4b,0x7a,0xae,0x69,0xda,0x7f,
 0x33,0xfe,0x03,0x62,0x3a,0x77,0xab,0x02,
};
const uint8_t tc_K[] = {
 0x10,0x38,0x33,0x5b,0x51,0x00,0x6e,0xd9,0xbb,0xdf,0x99,0x91,
 0x58,0xa3,0x16,0x37,0xbc,0x05,0x6a,0xe0,0x23,0xfb,0x34,0x1c,
 0x10,0x81,0x3e,0xf3,0x0d,0xa4,0xc5,0x2a,
};
const uint8_t tc_ISK_IR[] = {
 0x29,0x64,0xfc,0xd0,0x71,0x11,0x22,0x26,0x43,0x80,0xb4,0x1a,
 0x75,0xb5,0xb5,0x49,0x53,0xb3,0xaa,0x64,0x9b,0xec,0xec,0x76,
 0xb1,0x44,0xc6,0xdb,0x6c,0xc5,0xeb,0xa6,0xe0,0x25,0x41,0xb7,
 0x42,0x12,0xb5,0x51,0xc7,0x01,0x0f,0x2f,0xa3,0xce,0xce,0xe2,
 0xd6,0xca,0x4d,0x4b,0x84,0x85,0x65,0x07,0xd3,0x28,0x2b,0x85,
 0xbc,0x8b,0x8f,0x53,
};
const uint8_t tc_ISK_SY[] = {
 0xb6,0x08,0xbf,0xbb,0x7b,0x55,0x08,0xfe,0x56,0xca,0xd0,0xaa,
 0x41,0xf8,0xd0,0x7b,0x60,0x00,0x35,0xf5,0x38,0x48,0xf8,0x6b,
 0x79,0x6e,0xab,0xe6,0x3f,0x81,0x6a,0x50,0x6b,0x67,0x8b,0xaa,
 0x34,0xf7,0x87,0x79,0xda,0x60,0x1a,0xb3,0xb5,0x10,0x62,0x50,
 0x70,0x1f,0xf2,0xa0,0xfd,0xdb,0x3a,0x5b,0x78,0x45,0x62,0x2c,
 0xcb,0x66,0xb3,0xf7,
};
~~~


### Test case for scalar\_mult with valid inputs


~~~
    s: (length: 32 bytes)
      7cd0e075fa7955ba52c02759a6c90dbbfc10e6d40aea8d283e407d88
      cf538a05
    X: (length: 32 bytes)
      162b0c9287285f2b7d9406d60f0efe860a79376d4677d759e2df0349
      f09ac868
    G.scalar_mult(s,decode(X)): (length: 32 bytes)
      ae9f505c1e1bd3f7b78b93c3245b0ff91652352ccf02932a6340c995
      f87cb840
    G.scalar_mult_vfy(s,X): (length: 32 bytes)
      ae9f505c1e1bd3f7b78b93c3245b0ff91652352ccf02932a6340c995
      f87cb840
~~~


### Invalid inputs for scalar\_mult\_vfy which MUST result in aborts

For these test cases scalar\_mult\_vfy(y,.) MUST return the representation of the neutral element G.I. A G.I result from scalar\_mult\_vfy MUST make the protocol abort!

~~~
    s: (length: 32 bytes)
      7cd0e075fa7955ba52c02759a6c90dbbfc10e6d40aea8d283e407d88
      cf538a05
    Y_i1: (length: 32 bytes)
      152b0c9287285f2b7d9406d60f0efe860a79376d4677d759e2df0349
      f09ac868
    G.I: (length: 32 bytes)
      00000000000000000000000000000000000000000000000000000000
      00000000
    G.scalar_mult_vfy(s,Y_i1) = G.scalar_mult_vfy(s,G.I) = G.I
~~~

##  Test vector for CPace using group decaf448 and hash SHAKE-256


###  Test vectors for calculate\_generator with group decaf448

~~~
  Inputs
    H   = SHAKE-256 with input block size 136 bytes.
    PRS = b'Password' ; ZPAD length: 126 ;
    DSI = b'CPaceDecaf448'
    CI = b'\nAinitiator\nBresponder'
    CI = 0a41696e69746961746f720a42726573706f6e646572
    sid = 5223e0cdc45d6575668d64c552004124
  Outputs
    hash generator string: (length: 190 bytes)
      0850617373776f72647e000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000d435061
      63654465636166343438160a41696e69746961746f720a4272657370
      6f6e646572105223e0cdc45d6575668d64c552004124
    hash result: (length: 112 bytes)
      0787ad892b47bbd4ae8b5d89b2e2251cf5e9531f9ec1ffcebe64533b
      36837d8cec22573d7d3a988dd386e1153ec58e5e28cad35d0a4b3118
      22f8202e1c115ce54370ab2dfa01df5ed7a4a9747c706ece2db494db
      4dda4f61882e66da022c13f4787b6281d7a2d1817c327471b85a4c70
    encoded generator g: (length: 56 bytes)
      c296167d6eb953a41aed15a99079660979a048f2decc53cf00f22275
      d1b87e744fab5fdef91d1af002e89e78ce27fbecc45a467ca00329c1
~~~


###  Test vector for MSGa

~~~
  Inputs
    ADa = b'ADa'
    ya (little endian): (length: 56 bytes)
      02129e24bc93238e60692c147abe4274d3f01333cc3042a5789f52a6
      35e5067343e865cd1dcbc82cbb81ca0efed246711aac2db28f1d9634
  Outputs
    Ya: (length: 56 bytes)
      2a2213c21a09e2469555ee11f6c3bde91183d3e0040a7a0f9b63ba37
      c5609a7e0d596a2f1492881b502c16f4a068acedbd3546900c63803c
    MSGa: (length: 61 bytes)
      382a2213c21a09e2469555ee11f6c3bde91183d3e0040a7a0f9b63ba
      37c5609a7e0d596a2f1492881b502c16f4a068acedbd3546900c6380
      3c03414461
~~~

###  Test vector for MSGb

~~~
  Inputs
    ADb = b'ADb'
    yb (little endian): (length: 56 bytes)
      415172a6797b4680acdfee0acdc187b854a8ff873048e094ecdc2baf
      fc27eb040e1eb8e76d13b0b74ac9771603f642e6df98be702a37e90a
  Outputs
    Yb: (length: 56 bytes)
      805d70591bf8fdf7870e8fed7d57c397e8970429b081e98a6d110ea2
      c31a536f3f6ecfc771f3fcef90096c6229ab6dac7c6a41bf0028823b
    MSGb: (length: 61 bytes)
      38805d70591bf8fdf7870e8fed7d57c397e8970429b081e98a6d110e
      a2c31a536f3f6ecfc771f3fcef90096c6229ab6dac7c6a41bf002882
      3b03414462
~~~

###  Test vector for secret points K

~~~
    scalar_mult_vfy(ya,Yb): (length: 56 bytes)
      c655dc74dd0f67d22bf4508d3c0be27b035b60b20a455564dbf54844
      99d2286ce96cf37d885a5d58fc511c5284658d3fcd4bc95be454d7ec
    scalar_mult_vfy(yb,Ya): (length: 56 bytes)
      c655dc74dd0f67d22bf4508d3c0be27b035b60b20a455564dbf54844
      99d2286ce96cf37d885a5d58fc511c5284658d3fcd4bc95be454d7ec
~~~


###  Test vector for ISK calculation initiator/responder

~~~
    unordered cat of transcript : (length: 122 bytes)
      382a2213c21a09e2469555ee11f6c3bde91183d3e0040a7a0f9b63ba
      37c5609a7e0d596a2f1492881b502c16f4a068acedbd3546900c6380
      3c0341446138805d70591bf8fdf7870e8fed7d57c397e8970429b081
      e98a6d110ea2c31a536f3f6ecfc771f3fcef90096c6229ab6dac7c6a
      41bf0028823b03414462
    DSI = G.DSI_ISK, b'CPaceDecaf448_ISK': (length: 17 bytes)
      435061636544656361663434385f49534b
    prefix_free_cat(DSI,sid,K)||MSGa||MSGb: (length: 214 bytes)
      11435061636544656361663434385f49534b105223e0cdc45d657566
      8d64c55200412438c655dc74dd0f67d22bf4508d3c0be27b035b60b2
      0a455564dbf5484499d2286ce96cf37d885a5d58fc511c5284658d3f
      cd4bc95be454d7ec382a2213c21a09e2469555ee11f6c3bde91183d3
      e0040a7a0f9b63ba37c5609a7e0d596a2f1492881b502c16f4a068ac
      edbd3546900c63803c0341446138805d70591bf8fdf7870e8fed7d57
      c397e8970429b081e98a6d110ea2c31a536f3f6ecfc771f3fcef9009
      6c6229ab6dac7c6a41bf0028823b03414462
    ISK result: (length: 64 bytes)
      657821b4f1846dc189574226e7a46d5e5e80cc24e4370f9652ab2ebf
      4939dbbb6b5966169490977dbaa6d369a16f205924739b0238bdec0c
      e88308298f08b822
~~~

###  Test vector for ISK calculation parallel execution

~~~
    ordered cat of transcript : (length: 122 bytes)
      38805d70591bf8fdf7870e8fed7d57c397e8970429b081e98a6d110e
      a2c31a536f3f6ecfc771f3fcef90096c6229ab6dac7c6a41bf002882
      3b03414462382a2213c21a09e2469555ee11f6c3bde91183d3e0040a
      7a0f9b63ba37c5609a7e0d596a2f1492881b502c16f4a068acedbd35
      46900c63803c03414461
    DSI = G.DSI_ISK, b'CPaceDecaf448_ISK': (length: 17 bytes)
      435061636544656361663434385f49534b
    prefix_free_cat(DSI,sid,K)||oCAT(MSGa,MSGb):
    (length: 214 bytes)
      11435061636544656361663434385f49534b105223e0cdc45d657566
      8d64c55200412438c655dc74dd0f67d22bf4508d3c0be27b035b60b2
      0a455564dbf5484499d2286ce96cf37d885a5d58fc511c5284658d3f
      cd4bc95be454d7ec38805d70591bf8fdf7870e8fed7d57c397e89704
      29b081e98a6d110ea2c31a536f3f6ecfc771f3fcef90096c6229ab6d
      ac7c6a41bf0028823b03414462382a2213c21a09e2469555ee11f6c3
      bde91183d3e0040a7a0f9b63ba37c5609a7e0d596a2f1492881b502c
      16f4a068acedbd3546900c63803c03414461
    ISK result: (length: 64 bytes)
      ecfad12334f92fc52d96f85a192fbced65604a47b7a1d08b4270aaba
      3932de37e25af86aef93461fbe99f221b48b336095ad0eb05d19fa72
      886804f422bc3b68
~~~

###  Corresponding ANSI-C initializers

~~~
const uint8_t tc_PRS[] = {
 0x50,0x61,0x73,0x73,0x77,0x6f,0x72,0x64,
};
const uint8_t tc_CI[] = {
 0x0a,0x41,0x69,0x6e,0x69,0x74,0x69,0x61,0x74,0x6f,0x72,0x0a,
 0x42,0x72,0x65,0x73,0x70,0x6f,0x6e,0x64,0x65,0x72,
};
const uint8_t tc_sid[] = {
 0x52,0x23,0xe0,0xcd,0xc4,0x5d,0x65,0x75,0x66,0x8d,0x64,0xc5,
 0x52,0x00,0x41,0x24,
};
const uint8_t tc_g[] = {
 0xc2,0x96,0x16,0x7d,0x6e,0xb9,0x53,0xa4,0x1a,0xed,0x15,0xa9,
 0x90,0x79,0x66,0x09,0x79,0xa0,0x48,0xf2,0xde,0xcc,0x53,0xcf,
 0x00,0xf2,0x22,0x75,0xd1,0xb8,0x7e,0x74,0x4f,0xab,0x5f,0xde,
 0xf9,0x1d,0x1a,0xf0,0x02,0xe8,0x9e,0x78,0xce,0x27,0xfb,0xec,
 0xc4,0x5a,0x46,0x7c,0xa0,0x03,0x29,0xc1,
};
const uint8_t tc_ya[] = {
 0x02,0x12,0x9e,0x24,0xbc,0x93,0x23,0x8e,0x60,0x69,0x2c,0x14,
 0x7a,0xbe,0x42,0x74,0xd3,0xf0,0x13,0x33,0xcc,0x30,0x42,0xa5,
 0x78,0x9f,0x52,0xa6,0x35,0xe5,0x06,0x73,0x43,0xe8,0x65,0xcd,
 0x1d,0xcb,0xc8,0x2c,0xbb,0x81,0xca,0x0e,0xfe,0xd2,0x46,0x71,
 0x1a,0xac,0x2d,0xb2,0x8f,0x1d,0x96,0x34,
};
const uint8_t tc_ADa[] = {
 0x41,0x44,0x61,
};
const uint8_t tc_Ya[] = {
 0x2a,0x22,0x13,0xc2,0x1a,0x09,0xe2,0x46,0x95,0x55,0xee,0x11,
 0xf6,0xc3,0xbd,0xe9,0x11,0x83,0xd3,0xe0,0x04,0x0a,0x7a,0x0f,
 0x9b,0x63,0xba,0x37,0xc5,0x60,0x9a,0x7e,0x0d,0x59,0x6a,0x2f,
 0x14,0x92,0x88,0x1b,0x50,0x2c,0x16,0xf4,0xa0,0x68,0xac,0xed,
 0xbd,0x35,0x46,0x90,0x0c,0x63,0x80,0x3c,
};
const uint8_t tc_yb[] = {
 0x41,0x51,0x72,0xa6,0x79,0x7b,0x46,0x80,0xac,0xdf,0xee,0x0a,
 0xcd,0xc1,0x87,0xb8,0x54,0xa8,0xff,0x87,0x30,0x48,0xe0,0x94,
 0xec,0xdc,0x2b,0xaf,0xfc,0x27,0xeb,0x04,0x0e,0x1e,0xb8,0xe7,
 0x6d,0x13,0xb0,0xb7,0x4a,0xc9,0x77,0x16,0x03,0xf6,0x42,0xe6,
 0xdf,0x98,0xbe,0x70,0x2a,0x37,0xe9,0x0a,
};
const uint8_t tc_ADb[] = {
 0x41,0x44,0x62,
};
const uint8_t tc_Yb[] = {
 0x80,0x5d,0x70,0x59,0x1b,0xf8,0xfd,0xf7,0x87,0x0e,0x8f,0xed,
 0x7d,0x57,0xc3,0x97,0xe8,0x97,0x04,0x29,0xb0,0x81,0xe9,0x8a,
 0x6d,0x11,0x0e,0xa2,0xc3,0x1a,0x53,0x6f,0x3f,0x6e,0xcf,0xc7,
 0x71,0xf3,0xfc,0xef,0x90,0x09,0x6c,0x62,0x29,0xab,0x6d,0xac,
 0x7c,0x6a,0x41,0xbf,0x00,0x28,0x82,0x3b,
};
const uint8_t tc_K[] = {
 0xc6,0x55,0xdc,0x74,0xdd,0x0f,0x67,0xd2,0x2b,0xf4,0x50,0x8d,
 0x3c,0x0b,0xe2,0x7b,0x03,0x5b,0x60,0xb2,0x0a,0x45,0x55,0x64,
 0xdb,0xf5,0x48,0x44,0x99,0xd2,0x28,0x6c,0xe9,0x6c,0xf3,0x7d,
 0x88,0x5a,0x5d,0x58,0xfc,0x51,0x1c,0x52,0x84,0x65,0x8d,0x3f,
 0xcd,0x4b,0xc9,0x5b,0xe4,0x54,0xd7,0xec,
};
const uint8_t tc_ISK_IR[] = {
 0x65,0x78,0x21,0xb4,0xf1,0x84,0x6d,0xc1,0x89,0x57,0x42,0x26,
 0xe7,0xa4,0x6d,0x5e,0x5e,0x80,0xcc,0x24,0xe4,0x37,0x0f,0x96,
 0x52,0xab,0x2e,0xbf,0x49,0x39,0xdb,0xbb,0x6b,0x59,0x66,0x16,
 0x94,0x90,0x97,0x7d,0xba,0xa6,0xd3,0x69,0xa1,0x6f,0x20,0x59,
 0x24,0x73,0x9b,0x02,0x38,0xbd,0xec,0x0c,0xe8,0x83,0x08,0x29,
 0x8f,0x08,0xb8,0x22,
};
const uint8_t tc_ISK_SY[] = {
 0xec,0xfa,0xd1,0x23,0x34,0xf9,0x2f,0xc5,0x2d,0x96,0xf8,0x5a,
 0x19,0x2f,0xbc,0xed,0x65,0x60,0x4a,0x47,0xb7,0xa1,0xd0,0x8b,
 0x42,0x70,0xaa,0xba,0x39,0x32,0xde,0x37,0xe2,0x5a,0xf8,0x6a,
 0xef,0x93,0x46,0x1f,0xbe,0x99,0xf2,0x21,0xb4,0x8b,0x33,0x60,
 0x95,0xad,0x0e,0xb0,0x5d,0x19,0xfa,0x72,0x88,0x68,0x04,0xf4,
 0x22,0xbc,0x3b,0x68,
};
~~~


### Test case for scalar\_mult with valid inputs


~~~
    s: (length: 56 bytes)
      dd1bc7015daabb7672129cc35a3ba815486b139deff9bdeca7a4fc61
      34323d34658761e90ff079972a7ca8aa5606498f4f4f0ebc0933a819
    X: (length: 56 bytes)
      befdc56347fa131a7cc6b84743489a88a6eac03a0ff9af7a309525b2
      296b99b61fc2fadb5cfe71f67b4fe455961e97d464754972be34fc98
    G.scalar_mult(s,decode(X)): (length: 56 bytes)
      c600b2a60c68a344f176db0ebba17af5f8fda604cdcbd41516804a8e
      ff217923db75ef8e36aa3e7b17c5bf7d14bd57771559527080e68823
    G.scalar_mult_vfy(s,X): (length: 56 bytes)
      c600b2a60c68a344f176db0ebba17af5f8fda604cdcbd41516804a8e
      ff217923db75ef8e36aa3e7b17c5bf7d14bd57771559527080e68823
~~~


### Invalid inputs for scalar\_mult\_vfy which MUST result in aborts

For these test cases scalar\_mult\_vfy(y,.) MUST return the representation of the neutral element G.I. A G.I result from scalar\_mult\_vfy MUST make the protocol abort!

~~~
    s: (length: 56 bytes)
      dd1bc7015daabb7672129cc35a3ba815486b139deff9bdeca7a4fc61
      34323d34658761e90ff079972a7ca8aa5606498f4f4f0ebc0933a819
    Y_i1: (length: 56 bytes)
      bdfdc56347fa131a7cc6b84743489a88a6eac03a0ff9af7a309525b2
      296b99b61fc2fadb5cfe71f67b4fe455961e97d464754972be34fc98
    G.I: (length: 56 bytes)
      00000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
    G.scalar_mult_vfy(s,Y_i1) = G.scalar_mult_vfy(s,G.I) = G.I
~~~

##  Test vector for CPace using group NIST P-256 and hash SHA-256


###  Test vectors for calculate\_generator with group NIST P-256

~~~
  Inputs
    H   = SHA-256 with input block size 64 bytes.
    PRS = b'Password' ; ZPAD length: 54 ;
    DSI = b'CPaceP256_XMD:SHA-256_SSWU_NU_'
    CI = b'\nAinitiator\nBresponder'
    CI = 0a41696e69746961746f720a42726573706f6e646572
    sid = 34b36454cab2e7842c389f7d88ecb7df
  Outputs
    string passed to map: (length: 135 bytes)
      0850617373776f726436000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      00000000000000001e4350616365503235365f584d443a5348412d32
      35365f535357555f4e555f160a41696e69746961746f720a42726573
      706f6e6465721034b36454cab2e7842c389f7d88ecb7df
    generator g: (length: 65 bytes)
      04eb5c50954c02e9409b0c426fb3310e5a593be34efb4b7b067574c6
      70a54a1dece484a1706e10c08110fa1151dd43bc42b5554e12f40df5
      2f4ab5f78fbdc9de4e
~~~

###  Test vector for MSGa

~~~
  Inputs
    ADa = b'ADa'
    ya (big endian): (length: 32 bytes)
      0bf9bb41ad6d4737d719bed466f694d98ac7a4f2865ea260515af619
      225b8dc7
  Outputs
    Ya: (length: 65 bytes)
      045c090885f4f7a54514796eb7bc87989dfc32c892816df5d6ac63c6
      85a9c7b03f78456668a89f34a4eb3b6de35a16da800776cfb7a74ec5
      ff759e3662c6633c41
    MSGa: (length: 70 bytes)
      41045c090885f4f7a54514796eb7bc87989dfc32c892816df5d6ac63
      c685a9c7b03f78456668a89f34a4eb3b6de35a16da800776cfb7a74e
      c5ff759e3662c6633c4103414461
~~~

###  Test vector for MSGb

~~~
  Inputs
    ADb = b'ADb'
    yb (big endian): (length: 32 bytes)
      f42ef5d49c642cf97d660dfaa4cff87ff7d0a675a41bddada4aed4d5
      44adfd45
  Outputs
    Yb: (length: 65 bytes)
      04d2bf0ff86d16690ec13f8179cfdd9a66fbf4e84f990c21409dc80a
      b134b3f90e1fe05bb32d29a4423637951c5113bef90896fdb934a19b
      81bf4c50141798e516
    MSGb: (length: 70 bytes)
      4104d2bf0ff86d16690ec13f8179cfdd9a66fbf4e84f990c21409dc8
      0ab134b3f90e1fe05bb32d29a4423637951c5113bef90896fdb934a1
      9b81bf4c50141798e51603414462
~~~

###  Test vector for secret points K

~~~
    scalar_mult_vfy(ya,Yb): (length: 32 bytes)
      b63c453b00d61e76595216bb4e1975045882da858c4e0689149160ea
      32a76e5e
    scalar_mult_vfy(yb,Ya): (length: 32 bytes)
      b63c453b00d61e76595216bb4e1975045882da858c4e0689149160ea
      32a76e5e
~~~


###  Test vector for ISK calculation initiator/responder

~~~
    unordered cat of transcript : (length: 140 bytes)
      41045c090885f4f7a54514796eb7bc87989dfc32c892816df5d6ac63
      c685a9c7b03f78456668a89f34a4eb3b6de35a16da800776cfb7a74e
      c5ff759e3662c6633c41034144614104d2bf0ff86d16690ec13f8179
      cfdd9a66fbf4e84f990c21409dc80ab134b3f90e1fe05bb32d29a442
      3637951c5113bef90896fdb934a19b81bf4c50141798e51603414462
    DSI = G.DSI_ISK, b'CPaceP256_XMD:SHA-256_SSWU_NU__ISK':
    (length: 34 bytes)
      4350616365503235365f584d443a5348412d3235365f535357555f4e
      555f5f49534b
    prefix_free_cat(DSI,sid,K)||MSGa||MSGb: (length: 225 bytes)
      224350616365503235365f584d443a5348412d3235365f535357555f
      4e555f5f49534b1034b36454cab2e7842c389f7d88ecb7df20b63c45
      3b00d61e76595216bb4e1975045882da858c4e0689149160ea32a76e
      5e41045c090885f4f7a54514796eb7bc87989dfc32c892816df5d6ac
      63c685a9c7b03f78456668a89f34a4eb3b6de35a16da800776cfb7a7
      4ec5ff759e3662c6633c41034144614104d2bf0ff86d16690ec13f81
      79cfdd9a66fbf4e84f990c21409dc80ab134b3f90e1fe05bb32d29a4
      423637951c5113bef90896fdb934a19b81bf4c50141798e516034144
      62
    ISK result: (length: 32 bytes)
      37ccfdc90de60424fe6f03a702a136df31b1554998f5f1000678d859
      220e55b9
~~~

###  Test vector for ISK calculation parallel execution

~~~
    ordered cat of transcript : (length: 140 bytes)
      4104d2bf0ff86d16690ec13f8179cfdd9a66fbf4e84f990c21409dc8
      0ab134b3f90e1fe05bb32d29a4423637951c5113bef90896fdb934a1
      9b81bf4c50141798e5160341446241045c090885f4f7a54514796eb7
      bc87989dfc32c892816df5d6ac63c685a9c7b03f78456668a89f34a4
      eb3b6de35a16da800776cfb7a74ec5ff759e3662c6633c4103414461
    DSI = G.DSI_ISK, b'CPaceP256_XMD:SHA-256_SSWU_NU__ISK':
    (length: 34 bytes)
      4350616365503235365f584d443a5348412d3235365f535357555f4e
      555f5f49534b
    prefix_free_cat(DSI,sid,K)||oCAT(MSGa,MSGb):
    (length: 225 bytes)
      224350616365503235365f584d443a5348412d3235365f535357555f
      4e555f5f49534b1034b36454cab2e7842c389f7d88ecb7df20b63c45
      3b00d61e76595216bb4e1975045882da858c4e0689149160ea32a76e
      5e4104d2bf0ff86d16690ec13f8179cfdd9a66fbf4e84f990c21409d
      c80ab134b3f90e1fe05bb32d29a4423637951c5113bef90896fdb934
      a19b81bf4c50141798e5160341446241045c090885f4f7a54514796e
      b7bc87989dfc32c892816df5d6ac63c685a9c7b03f78456668a89f34
      a4eb3b6de35a16da800776cfb7a74ec5ff759e3662c6633c41034144
      61
    ISK result: (length: 32 bytes)
      d33079797c5bcd69e4f7170c9b6411ab95463a695ba77407cb25d3fd
      901abb4b
~~~

###  Corresponding ANSI-C initializers

~~~
const uint8_t tc_PRS[] = {
 0x50,0x61,0x73,0x73,0x77,0x6f,0x72,0x64,
};
const uint8_t tc_CI[] = {
 0x0a,0x41,0x69,0x6e,0x69,0x74,0x69,0x61,0x74,0x6f,0x72,0x0a,
 0x42,0x72,0x65,0x73,0x70,0x6f,0x6e,0x64,0x65,0x72,
};
const uint8_t tc_sid[] = {
 0x34,0xb3,0x64,0x54,0xca,0xb2,0xe7,0x84,0x2c,0x38,0x9f,0x7d,
 0x88,0xec,0xb7,0xdf,
};
const uint8_t tc_g[] = {
 0x04,0xeb,0x5c,0x50,0x95,0x4c,0x02,0xe9,0x40,0x9b,0x0c,0x42,
 0x6f,0xb3,0x31,0x0e,0x5a,0x59,0x3b,0xe3,0x4e,0xfb,0x4b,0x7b,
 0x06,0x75,0x74,0xc6,0x70,0xa5,0x4a,0x1d,0xec,0xe4,0x84,0xa1,
 0x70,0x6e,0x10,0xc0,0x81,0x10,0xfa,0x11,0x51,0xdd,0x43,0xbc,
 0x42,0xb5,0x55,0x4e,0x12,0xf4,0x0d,0xf5,0x2f,0x4a,0xb5,0xf7,
 0x8f,0xbd,0xc9,0xde,0x4e,
};
const uint8_t tc_ya[] = {
 0x0b,0xf9,0xbb,0x41,0xad,0x6d,0x47,0x37,0xd7,0x19,0xbe,0xd4,
 0x66,0xf6,0x94,0xd9,0x8a,0xc7,0xa4,0xf2,0x86,0x5e,0xa2,0x60,
 0x51,0x5a,0xf6,0x19,0x22,0x5b,0x8d,0xc7,
};
const uint8_t tc_ADa[] = {
 0x41,0x44,0x61,
};
const uint8_t tc_Ya[] = {
 0x04,0x5c,0x09,0x08,0x85,0xf4,0xf7,0xa5,0x45,0x14,0x79,0x6e,
 0xb7,0xbc,0x87,0x98,0x9d,0xfc,0x32,0xc8,0x92,0x81,0x6d,0xf5,
 0xd6,0xac,0x63,0xc6,0x85,0xa9,0xc7,0xb0,0x3f,0x78,0x45,0x66,
 0x68,0xa8,0x9f,0x34,0xa4,0xeb,0x3b,0x6d,0xe3,0x5a,0x16,0xda,
 0x80,0x07,0x76,0xcf,0xb7,0xa7,0x4e,0xc5,0xff,0x75,0x9e,0x36,
 0x62,0xc6,0x63,0x3c,0x41,
};
const uint8_t tc_yb[] = {
 0xf4,0x2e,0xf5,0xd4,0x9c,0x64,0x2c,0xf9,0x7d,0x66,0x0d,0xfa,
 0xa4,0xcf,0xf8,0x7f,0xf7,0xd0,0xa6,0x75,0xa4,0x1b,0xdd,0xad,
 0xa4,0xae,0xd4,0xd5,0x44,0xad,0xfd,0x45,
};
const uint8_t tc_ADb[] = {
 0x41,0x44,0x62,
};
const uint8_t tc_Yb[] = {
 0x04,0xd2,0xbf,0x0f,0xf8,0x6d,0x16,0x69,0x0e,0xc1,0x3f,0x81,
 0x79,0xcf,0xdd,0x9a,0x66,0xfb,0xf4,0xe8,0x4f,0x99,0x0c,0x21,
 0x40,0x9d,0xc8,0x0a,0xb1,0x34,0xb3,0xf9,0x0e,0x1f,0xe0,0x5b,
 0xb3,0x2d,0x29,0xa4,0x42,0x36,0x37,0x95,0x1c,0x51,0x13,0xbe,
 0xf9,0x08,0x96,0xfd,0xb9,0x34,0xa1,0x9b,0x81,0xbf,0x4c,0x50,
 0x14,0x17,0x98,0xe5,0x16,
};
const uint8_t tc_K[] = {
 0xb6,0x3c,0x45,0x3b,0x00,0xd6,0x1e,0x76,0x59,0x52,0x16,0xbb,
 0x4e,0x19,0x75,0x04,0x58,0x82,0xda,0x85,0x8c,0x4e,0x06,0x89,
 0x14,0x91,0x60,0xea,0x32,0xa7,0x6e,0x5e,
};
const uint8_t tc_ISK_IR[] = {
 0x37,0xcc,0xfd,0xc9,0x0d,0xe6,0x04,0x24,0xfe,0x6f,0x03,0xa7,
 0x02,0xa1,0x36,0xdf,0x31,0xb1,0x55,0x49,0x98,0xf5,0xf1,0x00,
 0x06,0x78,0xd8,0x59,0x22,0x0e,0x55,0xb9,
};
const uint8_t tc_ISK_SY[] = {
 0xd3,0x30,0x79,0x79,0x7c,0x5b,0xcd,0x69,0xe4,0xf7,0x17,0x0c,
 0x9b,0x64,0x11,0xab,0x95,0x46,0x3a,0x69,0x5b,0xa7,0x74,0x07,
 0xcb,0x25,0xd3,0xfd,0x90,0x1a,0xbb,0x4b,
};
~~~


### Test case for scalar\_mult\_vfy with correct inputs


~~~
    s: (length: 32 bytes)
      f012501c091ff9b99a123fffe571d8bc01e8077ee581362e1bd21399
      0835643b
    X: (length: 65 bytes)
      04d0562b1f0126184d3fcb9fd40e2ce5d98f28cc73dcdc1180bf311b
      4be915208e658cb60cdb191afd34af40053710280d67909d26bd510d
      9806d0c6ba36f9b991
    G.scalar_mult(s,X) (full coordinates): (length: 65 bytes)
      04354d409cc6c5f6ec375a8c4b22cdcf985e2aac21d8a65d7b964dbc
      1ffb80a5bc78edc4df0acea5b8e63324d41dff4c210a0c4eb4777b56
      f78129519d32fc8404
    G.scalar_mult_vfy(s,X) (only X-coordinate):
    (length: 32 bytes)
      354d409cc6c5f6ec375a8c4b22cdcf985e2aac21d8a65d7b964dbc1f
      fb80a5bc
~~~


### Invalid inputs for scalar\_mult\_vfy which MUST result in aborts

For these test cases scalar\_mult\_vfy(y,.) MUST return the representation of the neutral element G.I. A G.I result from scalar\_mult\_vfy MUST make the protocol abort!


~~~
    s: (length: 32 bytes)
      f012501c091ff9b99a123fffe571d8bc01e8077ee581362e1bd21399
      0835643b
    Y_i1: (length: 65 bytes)
      04d0562b1f0126184d3fcb9fd40e2ce5d98f28cc73dcdc1180bf311b
      4be915208e658cb60cdb191afd34af40053710280d67909d26bd510d
      9806d0c6ba36f9b9b8
    Y_i2: (length: 1 bytes)
      00
    G.scalar_mult_vfy(s,Y_i1) = G.scalar_mult_vfy(s,Y_i2) = G.I
~~~

##  Test vector for CPace using group NIST P-384 and hash SHA-384


###  Test vectors for calculate\_generator with group NIST P-384

~~~
  Inputs
    H   = SHA-384 with input block size 128 bytes.
    PRS = b'Password' ; ZPAD length: 118 ;
    DSI = b'CPaceP384_XMD:SHA-384_SSWU_NU_'
    CI = b'\nAinitiator\nBresponder'
    CI = 0a41696e69746961746f720a42726573706f6e646572
    sid = 5b3773aa90e8f23c61563a4b645b276c
  Outputs
    string passed to map: (length: 199 bytes)
      0850617373776f726476000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      000000000000000000000000000000001e4350616365503338345f58
      4d443a5348412d3338345f535357555f4e555f160a41696e69746961
      746f720a42726573706f6e646572105b3773aa90e8f23c61563a4b64
      5b276c
    generator g: (length: 97 bytes)
      04bc9ba4e403361c65f5a9b84978ee9b2af55a0765bf503f2ec7e84f
      a9746c75bffc1d10c37b1b74a92a19581412b682d729009ca6a12387
      551a4fc0515c181b42cd44083c4546e8c53d0926d8780079ced987f8
      6d8e93cc885c162833fcc94c39
~~~

###  Test vector for MSGa

~~~
  Inputs
    ADa = b'ADa'
    ya (big endian): (length: 48 bytes)
      ef433dd5ad142c860e7cb6400dd315d388d5ec5420c550e9d6f0907f
      375d988bc4d704837e43561c497e7dd93edcdb9d
  Outputs
    Ya: (length: 97 bytes)
      04158b5d0a93e2a46d2e43fbf52952b4a8e0e677874d0a2aaf59cc43
      93a7dd742a1e60fd56162ac06200394183572c3828f0936da80dc533
      ad81a5174fe0bb33005622326a1448f7bffbfc8defbdebfcbfb1c9e7
      3a22cb8f934633f0235e0cf8a9
    MSGa: (length: 102 bytes)
      6104158b5d0a93e2a46d2e43fbf52952b4a8e0e677874d0a2aaf59cc
      4393a7dd742a1e60fd56162ac06200394183572c3828f0936da80dc5
      33ad81a5174fe0bb33005622326a1448f7bffbfc8defbdebfcbfb1c9
      e73a22cb8f934633f0235e0cf8a903414461
~~~

###  Test vector for MSGb

~~~
  Inputs
    ADb = b'ADb'
    yb (big endian): (length: 48 bytes)
      50b0e36b95a2edfaa8342b843dddc90b175330f2399c1b36586dedda
      3c255975f30be6a750f9404fccc62a6323b5e471
  Outputs
    Yb: (length: 97 bytes)
      04ee0dc36197ca37676cbb30b7468b263103e4c555b5362c0071052c
      b63a92fc159379c1d7f888034715cc45fb479c89e71da2c28214c86f
      5ee18caf9cd7d48153d4a2d8085cd90b20f61b67278727e98ce2c925
      11e3ec2b8b40d801fc563c44b9
    MSGb: (length: 102 bytes)
      6104ee0dc36197ca37676cbb30b7468b263103e4c555b5362c007105
      2cb63a92fc159379c1d7f888034715cc45fb479c89e71da2c28214c8
      6f5ee18caf9cd7d48153d4a2d8085cd90b20f61b67278727e98ce2c9
      2511e3ec2b8b40d801fc563c44b903414462
~~~

###  Test vector for secret points K

~~~
    scalar_mult_vfy(ya,Yb): (length: 48 bytes)
      61e31b1f3addb8fc8a8a675c8b317566d526707f475af2d50d99ad05
      6df273778f6e763efdd9ac097b6ed18534ccc715
    scalar_mult_vfy(yb,Ya): (length: 48 bytes)
      61e31b1f3addb8fc8a8a675c8b317566d526707f475af2d50d99ad05
      6df273778f6e763efdd9ac097b6ed18534ccc715
~~~


###  Test vector for ISK calculation initiator/responder

~~~
    unordered cat of transcript : (length: 204 bytes)
      6104158b5d0a93e2a46d2e43fbf52952b4a8e0e677874d0a2aaf59cc
      4393a7dd742a1e60fd56162ac06200394183572c3828f0936da80dc5
      33ad81a5174fe0bb33005622326a1448f7bffbfc8defbdebfcbfb1c9
      e73a22cb8f934633f0235e0cf8a9034144616104ee0dc36197ca3767
      6cbb30b7468b263103e4c555b5362c0071052cb63a92fc159379c1d7
      f888034715cc45fb479c89e71da2c28214c86f5ee18caf9cd7d48153
      d4a2d8085cd90b20f61b67278727e98ce2c92511e3ec2b8b40d801fc
      563c44b903414462
    DSI = G.DSI_ISK, b'CPaceP384_XMD:SHA-384_SSWU_NU__ISK':
    (length: 34 bytes)
      4350616365503338345f584d443a5348412d3338345f535357555f4e
      555f5f49534b
    prefix_free_cat(DSI,sid,K)||MSGa||MSGb: (length: 305 bytes)
      224350616365503338345f584d443a5348412d3338345f535357555f
      4e555f5f49534b105b3773aa90e8f23c61563a4b645b276c3061e31b
      1f3addb8fc8a8a675c8b317566d526707f475af2d50d99ad056df273
      778f6e763efdd9ac097b6ed18534ccc7156104158b5d0a93e2a46d2e
      43fbf52952b4a8e0e677874d0a2aaf59cc4393a7dd742a1e60fd5616
      2ac06200394183572c3828f0936da80dc533ad81a5174fe0bb330056
      22326a1448f7bffbfc8defbdebfcbfb1c9e73a22cb8f934633f0235e
      0cf8a9034144616104ee0dc36197ca37676cbb30b7468b263103e4c5
      55b5362c0071052cb63a92fc159379c1d7f888034715cc45fb479c89
      e71da2c28214c86f5ee18caf9cd7d48153d4a2d8085cd90b20f61b67
      278727e98ce2c92511e3ec2b8b40d801fc563c44b903414462
    ISK result: (length: 48 bytes)
      3af452c015d1e1e1f184ceb1c40d1f54ce0eb28f78cb71ee315a42ca
      edb97c37da0094d5f5cdca965869bc7c588e8e24
~~~

###  Test vector for ISK calculation parallel execution

~~~
    ordered cat of transcript : (length: 204 bytes)
      6104ee0dc36197ca37676cbb30b7468b263103e4c555b5362c007105
      2cb63a92fc159379c1d7f888034715cc45fb479c89e71da2c28214c8
      6f5ee18caf9cd7d48153d4a2d8085cd90b20f61b67278727e98ce2c9
      2511e3ec2b8b40d801fc563c44b9034144626104158b5d0a93e2a46d
      2e43fbf52952b4a8e0e677874d0a2aaf59cc4393a7dd742a1e60fd56
      162ac06200394183572c3828f0936da80dc533ad81a5174fe0bb3300
      5622326a1448f7bffbfc8defbdebfcbfb1c9e73a22cb8f934633f023
      5e0cf8a903414461
    DSI = G.DSI_ISK, b'CPaceP384_XMD:SHA-384_SSWU_NU__ISK':
    (length: 34 bytes)
      4350616365503338345f584d443a5348412d3338345f535357555f4e
      555f5f49534b
    prefix_free_cat(DSI,sid,K)||oCAT(MSGa,MSGb):
    (length: 305 bytes)
      224350616365503338345f584d443a5348412d3338345f535357555f
      4e555f5f49534b105b3773aa90e8f23c61563a4b645b276c3061e31b
      1f3addb8fc8a8a675c8b317566d526707f475af2d50d99ad056df273
      778f6e763efdd9ac097b6ed18534ccc7156104ee0dc36197ca37676c
      bb30b7468b263103e4c555b5362c0071052cb63a92fc159379c1d7f8
      88034715cc45fb479c89e71da2c28214c86f5ee18caf9cd7d48153d4
      a2d8085cd90b20f61b67278727e98ce2c92511e3ec2b8b40d801fc56
      3c44b9034144626104158b5d0a93e2a46d2e43fbf52952b4a8e0e677
      874d0a2aaf59cc4393a7dd742a1e60fd56162ac06200394183572c38
      28f0936da80dc533ad81a5174fe0bb33005622326a1448f7bffbfc8d
      efbdebfcbfb1c9e73a22cb8f934633f0235e0cf8a903414461
    ISK result: (length: 48 bytes)
      380455b1030b5235ba86900adef5361d67ac5ee1a9595a617c4a336d
      978b7f80d5f1936ee1ed4406d45b556e91c96c3f
~~~

###  Corresponding ANSI-C initializers

~~~
const uint8_t tc_PRS[] = {
 0x50,0x61,0x73,0x73,0x77,0x6f,0x72,0x64,
};
const uint8_t tc_CI[] = {
 0x0a,0x41,0x69,0x6e,0x69,0x74,0x69,0x61,0x74,0x6f,0x72,0x0a,
 0x42,0x72,0x65,0x73,0x70,0x6f,0x6e,0x64,0x65,0x72,
};
const uint8_t tc_sid[] = {
 0x5b,0x37,0x73,0xaa,0x90,0xe8,0xf2,0x3c,0x61,0x56,0x3a,0x4b,
 0x64,0x5b,0x27,0x6c,
};
const uint8_t tc_g[] = {
 0x04,0xbc,0x9b,0xa4,0xe4,0x03,0x36,0x1c,0x65,0xf5,0xa9,0xb8,
 0x49,0x78,0xee,0x9b,0x2a,0xf5,0x5a,0x07,0x65,0xbf,0x50,0x3f,
 0x2e,0xc7,0xe8,0x4f,0xa9,0x74,0x6c,0x75,0xbf,0xfc,0x1d,0x10,
 0xc3,0x7b,0x1b,0x74,0xa9,0x2a,0x19,0x58,0x14,0x12,0xb6,0x82,
 0xd7,0x29,0x00,0x9c,0xa6,0xa1,0x23,0x87,0x55,0x1a,0x4f,0xc0,
 0x51,0x5c,0x18,0x1b,0x42,0xcd,0x44,0x08,0x3c,0x45,0x46,0xe8,
 0xc5,0x3d,0x09,0x26,0xd8,0x78,0x00,0x79,0xce,0xd9,0x87,0xf8,
 0x6d,0x8e,0x93,0xcc,0x88,0x5c,0x16,0x28,0x33,0xfc,0xc9,0x4c,
 0x39,
};
const uint8_t tc_ya[] = {
 0xef,0x43,0x3d,0xd5,0xad,0x14,0x2c,0x86,0x0e,0x7c,0xb6,0x40,
 0x0d,0xd3,0x15,0xd3,0x88,0xd5,0xec,0x54,0x20,0xc5,0x50,0xe9,
 0xd6,0xf0,0x90,0x7f,0x37,0x5d,0x98,0x8b,0xc4,0xd7,0x04,0x83,
 0x7e,0x43,0x56,0x1c,0x49,0x7e,0x7d,0xd9,0x3e,0xdc,0xdb,0x9d,
};
const uint8_t tc_ADa[] = {
 0x41,0x44,0x61,
};
const uint8_t tc_Ya[] = {
 0x04,0x15,0x8b,0x5d,0x0a,0x93,0xe2,0xa4,0x6d,0x2e,0x43,0xfb,
 0xf5,0x29,0x52,0xb4,0xa8,0xe0,0xe6,0x77,0x87,0x4d,0x0a,0x2a,
 0xaf,0x59,0xcc,0x43,0x93,0xa7,0xdd,0x74,0x2a,0x1e,0x60,0xfd,
 0x56,0x16,0x2a,0xc0,0x62,0x00,0x39,0x41,0x83,0x57,0x2c,0x38,
 0x28,0xf0,0x93,0x6d,0xa8,0x0d,0xc5,0x33,0xad,0x81,0xa5,0x17,
 0x4f,0xe0,0xbb,0x33,0x00,0x56,0x22,0x32,0x6a,0x14,0x48,0xf7,
 0xbf,0xfb,0xfc,0x8d,0xef,0xbd,0xeb,0xfc,0xbf,0xb1,0xc9,0xe7,
 0x3a,0x22,0xcb,0x8f,0x93,0x46,0x33,0xf0,0x23,0x5e,0x0c,0xf8,
 0xa9,
};
const uint8_t tc_yb[] = {
 0x50,0xb0,0xe3,0x6b,0x95,0xa2,0xed,0xfa,0xa8,0x34,0x2b,0x84,
 0x3d,0xdd,0xc9,0x0b,0x17,0x53,0x30,0xf2,0x39,0x9c,0x1b,0x36,
 0x58,0x6d,0xed,0xda,0x3c,0x25,0x59,0x75,0xf3,0x0b,0xe6,0xa7,
 0x50,0xf9,0x40,0x4f,0xcc,0xc6,0x2a,0x63,0x23,0xb5,0xe4,0x71,
};
const uint8_t tc_ADb[] = {
 0x41,0x44,0x62,
};
const uint8_t tc_Yb[] = {
 0x04,0xee,0x0d,0xc3,0x61,0x97,0xca,0x37,0x67,0x6c,0xbb,0x30,
 0xb7,0x46,0x8b,0x26,0x31,0x03,0xe4,0xc5,0x55,0xb5,0x36,0x2c,
 0x00,0x71,0x05,0x2c,0xb6,0x3a,0x92,0xfc,0x15,0x93,0x79,0xc1,
 0xd7,0xf8,0x88,0x03,0x47,0x15,0xcc,0x45,0xfb,0x47,0x9c,0x89,
 0xe7,0x1d,0xa2,0xc2,0x82,0x14,0xc8,0x6f,0x5e,0xe1,0x8c,0xaf,
 0x9c,0xd7,0xd4,0x81,0x53,0xd4,0xa2,0xd8,0x08,0x5c,0xd9,0x0b,
 0x20,0xf6,0x1b,0x67,0x27,0x87,0x27,0xe9,0x8c,0xe2,0xc9,0x25,
 0x11,0xe3,0xec,0x2b,0x8b,0x40,0xd8,0x01,0xfc,0x56,0x3c,0x44,
 0xb9,
};
const uint8_t tc_K[] = {
 0x61,0xe3,0x1b,0x1f,0x3a,0xdd,0xb8,0xfc,0x8a,0x8a,0x67,0x5c,
 0x8b,0x31,0x75,0x66,0xd5,0x26,0x70,0x7f,0x47,0x5a,0xf2,0xd5,
 0x0d,0x99,0xad,0x05,0x6d,0xf2,0x73,0x77,0x8f,0x6e,0x76,0x3e,
 0xfd,0xd9,0xac,0x09,0x7b,0x6e,0xd1,0x85,0x34,0xcc,0xc7,0x15,
};
const uint8_t tc_ISK_IR[] = {
 0x3a,0xf4,0x52,0xc0,0x15,0xd1,0xe1,0xe1,0xf1,0x84,0xce,0xb1,
 0xc4,0x0d,0x1f,0x54,0xce,0x0e,0xb2,0x8f,0x78,0xcb,0x71,0xee,
 0x31,0x5a,0x42,0xca,0xed,0xb9,0x7c,0x37,0xda,0x00,0x94,0xd5,
 0xf5,0xcd,0xca,0x96,0x58,0x69,0xbc,0x7c,0x58,0x8e,0x8e,0x24,
};
const uint8_t tc_ISK_SY[] = {
 0x38,0x04,0x55,0xb1,0x03,0x0b,0x52,0x35,0xba,0x86,0x90,0x0a,
 0xde,0xf5,0x36,0x1d,0x67,0xac,0x5e,0xe1,0xa9,0x59,0x5a,0x61,
 0x7c,0x4a,0x33,0x6d,0x97,0x8b,0x7f,0x80,0xd5,0xf1,0x93,0x6e,
 0xe1,0xed,0x44,0x06,0xd4,0x5b,0x55,0x6e,0x91,0xc9,0x6c,0x3f,
};
~~~


### Test case for scalar\_mult\_vfy with correct inputs


~~~
    s: (length: 48 bytes)
      6e8a99a5cdd408eae98e1b8aed286e7b12adbbdac7f2c628d9060ce9
      2ae0d90bd57a564fd3500fbcce3425dc94ba0ade
    X: (length: 97 bytes)
      046dfe10be750ea1822cbfc25262c68ec0a7f52d99a364c02079941c
      d0b524de0e5547bc0508755b82e9e4f3d4a15758aac901a1bf63fca2
      edb5d0e0f2d1c8385d9cb964b5e7fe90b7d346af3ca6e8082e284e1b
      769f164f092da4cf4d0aff2fec
    G.scalar_mult(s,X) (full coordinates): (length: 97 bytes)
      04a6e1d9e9d81bbd2e2442a1a878a28acaa16a4d398b1eccfc1a8379
      8bc72c931b7d9b52c353fe06b29acf60615c491de3aabe5e604f9670
      1b354cee5592a035c1e9af7e8a36aaf2cbcaa115bf83901c7ef1388d
      7d09b92092e42f491fb9514546
    G.scalar_mult_vfy(s,X) (only X-coordinate):
    (length: 48 bytes)
      a6e1d9e9d81bbd2e2442a1a878a28acaa16a4d398b1eccfc1a83798b
      c72c931b7d9b52c353fe06b29acf60615c491de3
~~~


### Invalid inputs for scalar\_mult\_vfy which MUST result in aborts

For these test cases scalar\_mult\_vfy(y,.) MUST return the representation of the neutral element G.I. A G.I result from scalar\_mult\_vfy MUST make the protocol abort!


~~~
    s: (length: 48 bytes)
      6e8a99a5cdd408eae98e1b8aed286e7b12adbbdac7f2c628d9060ce9
      2ae0d90bd57a564fd3500fbcce3425dc94ba0ade
    Y_i1: (length: 97 bytes)
      046dfe10be750ea1822cbfc25262c68ec0a7f52d99a364c02079941c
      d0b524de0e5547bc0508755b82e9e4f3d4a15758aac901a1bf63fca2
      edb5d0e0f2d1c8385d9cb964b5e7fe90b7d346af3ca6e8082e284e1b
      769f164f092da4cf4d0aff2f2e
    Y_i2: (length: 1 bytes)
      00
    G.scalar_mult_vfy(s,Y_i1) = G.scalar_mult_vfy(s,Y_i2) = G.I
~~~

##  Test vector for CPace using group NIST P-521 and hash SHA-512


###  Test vectors for calculate\_generator with group NIST P-521

~~~
  Inputs
    H   = SHA-512 with input block size 128 bytes.
    PRS = b'Password' ; ZPAD length: 118 ;
    DSI = b'CPaceP521_XMD:SHA-512_SSWU_NU_'
    CI = b'\nAinitiator\nBresponder'
    CI = 0a41696e69746961746f720a42726573706f6e646572
    sid = 7e4b4791d6a8ef019b936c79fb7f2c57
  Outputs
    string passed to map: (length: 199 bytes)
      0850617373776f726476000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      000000000000000000000000000000001e4350616365503532315f58
      4d443a5348412d3531325f535357555f4e555f160a41696e69746961
      746f720a42726573706f6e646572107e4b4791d6a8ef019b936c79fb
      7f2c57
    generator g: (length: 133 bytes)
      0401b0848c0829a9745e7e2107a660df2205ec1a9bb44af522d34465
      f807df069fe262d0f7630842f40092d546bebe68c4ba52f104ca5d6b
      2c34db75f9fa445a689b4600d67aacc57ddef430ef1b1640b8c753e7
      df3f6aa186532f070d51fa29461e0bbb4d9e8325c2cbb6aa44c1c11c
      97987a16bbb92d6497205d94bebb40b1847efc2765
~~~

###  Test vector for MSGa

~~~
  Inputs
    ADa = b'ADa'
    ya (big endian): (length: 66 bytes)
      006367e9c2aeff9f1db19af600cca73343d47cbe446cebbd1ccd783f
      82755a872da86fd0707eb3767c6114f1803deb62d63bdd1e613f67e6
      3e8c141ee5310e3ee819
  Outputs
    Ya: (length: 133 bytes)
      0400b6ec4baf3b22b46e8157b0216706c3db0267f87e219bc32668ed
      06b6151a2cb13940337a45164fa8d4329ec318b6bd1e13080572c707
      53bddce288b54ebfae4a2301c6e8b8e74b3d5ad3954fc03cf62140d5
      bb2fce4436640a8089380d76313be72fbe1af05251c92c0434349651
      ee5cf62eefe01a27f2e1104046d122a9cb5f246a68
    MSGa: (length: 139 bytes)
      c2850400b6ec4baf3b22b46e8157b0216706c3db0267f87e219bc326
      68ed06b6151a2cb13940337a45164fa8d4329ec318b6bd1e13080572
      c70753bddce288b54ebfae4a2301c6e8b8e74b3d5ad3954fc03cf621
      40d5bb2fce4436640a8089380d76313be72fbe1af05251c92c043434
      9651ee5cf62eefe01a27f2e1104046d122a9cb5f246a6803414461
~~~

###  Test vector for MSGb

~~~
  Inputs
    ADb = b'ADb'
    yb (big endian): (length: 66 bytes)
      009227bf8dc741dacc9422f8bf3c0e96fce9587bc562eaafe0dc5f6f
      82f28594e4a6f98553560c62b75fa4abb198cecbbb86ebd41b0ea025
      4cde78ac68d39a240ae7
  Outputs
    Yb: (length: 133 bytes)
      0401243c19a2af4f0abb715bea87ea5767d423647b4ade980f85e218
      868c6b1ea3181b1202f8eafb5a60e74756244e084327689b86f10d12
      4d845a8a96e8dcf4075ec800876590b872693957c7c8989c29aa4491
      b3e64c6927b8b640d02f838b3f1fefba954cb959f663cf6e182ff950
      1fc1006b623a567e69c944027c721865303a0db77c
    MSGb: (length: 139 bytes)
      c2850401243c19a2af4f0abb715bea87ea5767d423647b4ade980f85
      e218868c6b1ea3181b1202f8eafb5a60e74756244e084327689b86f1
      0d124d845a8a96e8dcf4075ec800876590b872693957c7c8989c29aa
      4491b3e64c6927b8b640d02f838b3f1fefba954cb959f663cf6e182f
      f9501fc1006b623a567e69c944027c721865303a0db77c03414462
~~~

###  Test vector for secret points K

~~~
    scalar_mult_vfy(ya,Yb): (length: 66 bytes)
      015b9d8ec49558eb3182f0fa5aad80fc08374a88136e355f56ea4452
      d44a0dd51fe93c5b9b2086624444d42d146a35891d56e89c2adfa2ab
      89498e976c981a513422
    scalar_mult_vfy(yb,Ya): (length: 66 bytes)
      015b9d8ec49558eb3182f0fa5aad80fc08374a88136e355f56ea4452
      d44a0dd51fe93c5b9b2086624444d42d146a35891d56e89c2adfa2ab
      89498e976c981a513422
~~~


###  Test vector for ISK calculation initiator/responder

~~~
    unordered cat of transcript : (length: 278 bytes)
      c2850400b6ec4baf3b22b46e8157b0216706c3db0267f87e219bc326
      68ed06b6151a2cb13940337a45164fa8d4329ec318b6bd1e13080572
      c70753bddce288b54ebfae4a2301c6e8b8e74b3d5ad3954fc03cf621
      40d5bb2fce4436640a8089380d76313be72fbe1af05251c92c043434
      9651ee5cf62eefe01a27f2e1104046d122a9cb5f246a6803414461c2
      850401243c19a2af4f0abb715bea87ea5767d423647b4ade980f85e2
      18868c6b1ea3181b1202f8eafb5a60e74756244e084327689b86f10d
      124d845a8a96e8dcf4075ec800876590b872693957c7c8989c29aa44
      91b3e64c6927b8b640d02f838b3f1fefba954cb959f663cf6e182ff9
      501fc1006b623a567e69c944027c721865303a0db77c03414462
    DSI = G.DSI_ISK, b'CPaceP521_XMD:SHA-512_SSWU_NU__ISK':
    (length: 34 bytes)
      4350616365503532315f584d443a5348412d3531325f535357555f4e
      555f5f49534b
    prefix_free_cat(DSI,sid,K)||MSGa||MSGb: (length: 397 bytes)
      224350616365503532315f584d443a5348412d3531325f535357555f
      4e555f5f49534b107e4b4791d6a8ef019b936c79fb7f2c5742015b9d
      8ec49558eb3182f0fa5aad80fc08374a88136e355f56ea4452d44a0d
      d51fe93c5b9b2086624444d42d146a35891d56e89c2adfa2ab89498e
      976c981a513422c2850400b6ec4baf3b22b46e8157b0216706c3db02
      67f87e219bc32668ed06b6151a2cb13940337a45164fa8d4329ec318
      b6bd1e13080572c70753bddce288b54ebfae4a2301c6e8b8e74b3d5a
      d3954fc03cf62140d5bb2fce4436640a8089380d76313be72fbe1af0
      5251c92c0434349651ee5cf62eefe01a27f2e1104046d122a9cb5f24
      6a6803414461c2850401243c19a2af4f0abb715bea87ea5767d42364
      7b4ade980f85e218868c6b1ea3181b1202f8eafb5a60e74756244e08
      4327689b86f10d124d845a8a96e8dcf4075ec800876590b872693957
      c7c8989c29aa4491b3e64c6927b8b640d02f838b3f1fefba954cb959
      f663cf6e182ff9501fc1006b623a567e69c944027c721865303a0db7
      7c03414462
    ISK result: (length: 64 bytes)
      ed36dcf9c794a427d747d08b44d1071d87b6e7298059654fb819b961
      d904d5e345aeea8b5a5161f0e016c6db57351e63717cda814ce72ab7
      ccb26ffd43b2d3e9
~~~

###  Test vector for ISK calculation parallel execution

~~~
    ordered cat of transcript : (length: 278 bytes)
      c2850401243c19a2af4f0abb715bea87ea5767d423647b4ade980f85
      e218868c6b1ea3181b1202f8eafb5a60e74756244e084327689b86f1
      0d124d845a8a96e8dcf4075ec800876590b872693957c7c8989c29aa
      4491b3e64c6927b8b640d02f838b3f1fefba954cb959f663cf6e182f
      f9501fc1006b623a567e69c944027c721865303a0db77c03414462c2
      850400b6ec4baf3b22b46e8157b0216706c3db0267f87e219bc32668
      ed06b6151a2cb13940337a45164fa8d4329ec318b6bd1e13080572c7
      0753bddce288b54ebfae4a2301c6e8b8e74b3d5ad3954fc03cf62140
      d5bb2fce4436640a8089380d76313be72fbe1af05251c92c04343496
      51ee5cf62eefe01a27f2e1104046d122a9cb5f246a6803414461
    DSI = G.DSI_ISK, b'CPaceP521_XMD:SHA-512_SSWU_NU__ISK':
    (length: 34 bytes)
      4350616365503532315f584d443a5348412d3531325f535357555f4e
      555f5f49534b
    prefix_free_cat(DSI,sid,K)||oCAT(MSGa,MSGb):
    (length: 397 bytes)
      224350616365503532315f584d443a5348412d3531325f535357555f
      4e555f5f49534b107e4b4791d6a8ef019b936c79fb7f2c5742015b9d
      8ec49558eb3182f0fa5aad80fc08374a88136e355f56ea4452d44a0d
      d51fe93c5b9b2086624444d42d146a35891d56e89c2adfa2ab89498e
      976c981a513422c2850401243c19a2af4f0abb715bea87ea5767d423
      647b4ade980f85e218868c6b1ea3181b1202f8eafb5a60e74756244e
      084327689b86f10d124d845a8a96e8dcf4075ec800876590b8726939
      57c7c8989c29aa4491b3e64c6927b8b640d02f838b3f1fefba954cb9
      59f663cf6e182ff9501fc1006b623a567e69c944027c721865303a0d
      b77c03414462c2850400b6ec4baf3b22b46e8157b0216706c3db0267
      f87e219bc32668ed06b6151a2cb13940337a45164fa8d4329ec318b6
      bd1e13080572c70753bddce288b54ebfae4a2301c6e8b8e74b3d5ad3
      954fc03cf62140d5bb2fce4436640a8089380d76313be72fbe1af052
      51c92c0434349651ee5cf62eefe01a27f2e1104046d122a9cb5f246a
      6803414461
    ISK result: (length: 64 bytes)
      bb8b3f6f8a01c96fc22c953abc1df7c8d55e190581337664e51bb209
      37be3eb76749a57bd53a212dee183cee54ddf9da5f44bf9a029f2e41
      f3eee99a8d7f91af
~~~

###  Corresponding ANSI-C initializers

~~~
const uint8_t tc_PRS[] = {
 0x50,0x61,0x73,0x73,0x77,0x6f,0x72,0x64,
};
const uint8_t tc_CI[] = {
 0x0a,0x41,0x69,0x6e,0x69,0x74,0x69,0x61,0x74,0x6f,0x72,0x0a,
 0x42,0x72,0x65,0x73,0x70,0x6f,0x6e,0x64,0x65,0x72,
};
const uint8_t tc_sid[] = {
 0x7e,0x4b,0x47,0x91,0xd6,0xa8,0xef,0x01,0x9b,0x93,0x6c,0x79,
 0xfb,0x7f,0x2c,0x57,
};
const uint8_t tc_g[] = {
 0x04,0x01,0xb0,0x84,0x8c,0x08,0x29,0xa9,0x74,0x5e,0x7e,0x21,
 0x07,0xa6,0x60,0xdf,0x22,0x05,0xec,0x1a,0x9b,0xb4,0x4a,0xf5,
 0x22,0xd3,0x44,0x65,0xf8,0x07,0xdf,0x06,0x9f,0xe2,0x62,0xd0,
 0xf7,0x63,0x08,0x42,0xf4,0x00,0x92,0xd5,0x46,0xbe,0xbe,0x68,
 0xc4,0xba,0x52,0xf1,0x04,0xca,0x5d,0x6b,0x2c,0x34,0xdb,0x75,
 0xf9,0xfa,0x44,0x5a,0x68,0x9b,0x46,0x00,0xd6,0x7a,0xac,0xc5,
 0x7d,0xde,0xf4,0x30,0xef,0x1b,0x16,0x40,0xb8,0xc7,0x53,0xe7,
 0xdf,0x3f,0x6a,0xa1,0x86,0x53,0x2f,0x07,0x0d,0x51,0xfa,0x29,
 0x46,0x1e,0x0b,0xbb,0x4d,0x9e,0x83,0x25,0xc2,0xcb,0xb6,0xaa,
 0x44,0xc1,0xc1,0x1c,0x97,0x98,0x7a,0x16,0xbb,0xb9,0x2d,0x64,
 0x97,0x20,0x5d,0x94,0xbe,0xbb,0x40,0xb1,0x84,0x7e,0xfc,0x27,
 0x65,
};
const uint8_t tc_ya[] = {
 0x00,0x63,0x67,0xe9,0xc2,0xae,0xff,0x9f,0x1d,0xb1,0x9a,0xf6,
 0x00,0xcc,0xa7,0x33,0x43,0xd4,0x7c,0xbe,0x44,0x6c,0xeb,0xbd,
 0x1c,0xcd,0x78,0x3f,0x82,0x75,0x5a,0x87,0x2d,0xa8,0x6f,0xd0,
 0x70,0x7e,0xb3,0x76,0x7c,0x61,0x14,0xf1,0x80,0x3d,0xeb,0x62,
 0xd6,0x3b,0xdd,0x1e,0x61,0x3f,0x67,0xe6,0x3e,0x8c,0x14,0x1e,
 0xe5,0x31,0x0e,0x3e,0xe8,0x19,
};
const uint8_t tc_ADa[] = {
 0x41,0x44,0x61,
};
const uint8_t tc_Ya[] = {
 0x04,0x00,0xb6,0xec,0x4b,0xaf,0x3b,0x22,0xb4,0x6e,0x81,0x57,
 0xb0,0x21,0x67,0x06,0xc3,0xdb,0x02,0x67,0xf8,0x7e,0x21,0x9b,
 0xc3,0x26,0x68,0xed,0x06,0xb6,0x15,0x1a,0x2c,0xb1,0x39,0x40,
 0x33,0x7a,0x45,0x16,0x4f,0xa8,0xd4,0x32,0x9e,0xc3,0x18,0xb6,
 0xbd,0x1e,0x13,0x08,0x05,0x72,0xc7,0x07,0x53,0xbd,0xdc,0xe2,
 0x88,0xb5,0x4e,0xbf,0xae,0x4a,0x23,0x01,0xc6,0xe8,0xb8,0xe7,
 0x4b,0x3d,0x5a,0xd3,0x95,0x4f,0xc0,0x3c,0xf6,0x21,0x40,0xd5,
 0xbb,0x2f,0xce,0x44,0x36,0x64,0x0a,0x80,0x89,0x38,0x0d,0x76,
 0x31,0x3b,0xe7,0x2f,0xbe,0x1a,0xf0,0x52,0x51,0xc9,0x2c,0x04,
 0x34,0x34,0x96,0x51,0xee,0x5c,0xf6,0x2e,0xef,0xe0,0x1a,0x27,
 0xf2,0xe1,0x10,0x40,0x46,0xd1,0x22,0xa9,0xcb,0x5f,0x24,0x6a,
 0x68,
};
const uint8_t tc_yb[] = {
 0x00,0x92,0x27,0xbf,0x8d,0xc7,0x41,0xda,0xcc,0x94,0x22,0xf8,
 0xbf,0x3c,0x0e,0x96,0xfc,0xe9,0x58,0x7b,0xc5,0x62,0xea,0xaf,
 0xe0,0xdc,0x5f,0x6f,0x82,0xf2,0x85,0x94,0xe4,0xa6,0xf9,0x85,
 0x53,0x56,0x0c,0x62,0xb7,0x5f,0xa4,0xab,0xb1,0x98,0xce,0xcb,
 0xbb,0x86,0xeb,0xd4,0x1b,0x0e,0xa0,0x25,0x4c,0xde,0x78,0xac,
 0x68,0xd3,0x9a,0x24,0x0a,0xe7,
};
const uint8_t tc_ADb[] = {
 0x41,0x44,0x62,
};
const uint8_t tc_Yb[] = {
 0x04,0x01,0x24,0x3c,0x19,0xa2,0xaf,0x4f,0x0a,0xbb,0x71,0x5b,
 0xea,0x87,0xea,0x57,0x67,0xd4,0x23,0x64,0x7b,0x4a,0xde,0x98,
 0x0f,0x85,0xe2,0x18,0x86,0x8c,0x6b,0x1e,0xa3,0x18,0x1b,0x12,
 0x02,0xf8,0xea,0xfb,0x5a,0x60,0xe7,0x47,0x56,0x24,0x4e,0x08,
 0x43,0x27,0x68,0x9b,0x86,0xf1,0x0d,0x12,0x4d,0x84,0x5a,0x8a,
 0x96,0xe8,0xdc,0xf4,0x07,0x5e,0xc8,0x00,0x87,0x65,0x90,0xb8,
 0x72,0x69,0x39,0x57,0xc7,0xc8,0x98,0x9c,0x29,0xaa,0x44,0x91,
 0xb3,0xe6,0x4c,0x69,0x27,0xb8,0xb6,0x40,0xd0,0x2f,0x83,0x8b,
 0x3f,0x1f,0xef,0xba,0x95,0x4c,0xb9,0x59,0xf6,0x63,0xcf,0x6e,
 0x18,0x2f,0xf9,0x50,0x1f,0xc1,0x00,0x6b,0x62,0x3a,0x56,0x7e,
 0x69,0xc9,0x44,0x02,0x7c,0x72,0x18,0x65,0x30,0x3a,0x0d,0xb7,
 0x7c,
};
const uint8_t tc_K[] = {
 0x01,0x5b,0x9d,0x8e,0xc4,0x95,0x58,0xeb,0x31,0x82,0xf0,0xfa,
 0x5a,0xad,0x80,0xfc,0x08,0x37,0x4a,0x88,0x13,0x6e,0x35,0x5f,
 0x56,0xea,0x44,0x52,0xd4,0x4a,0x0d,0xd5,0x1f,0xe9,0x3c,0x5b,
 0x9b,0x20,0x86,0x62,0x44,0x44,0xd4,0x2d,0x14,0x6a,0x35,0x89,
 0x1d,0x56,0xe8,0x9c,0x2a,0xdf,0xa2,0xab,0x89,0x49,0x8e,0x97,
 0x6c,0x98,0x1a,0x51,0x34,0x22,
};
const uint8_t tc_ISK_IR[] = {
 0xed,0x36,0xdc,0xf9,0xc7,0x94,0xa4,0x27,0xd7,0x47,0xd0,0x8b,
 0x44,0xd1,0x07,0x1d,0x87,0xb6,0xe7,0x29,0x80,0x59,0x65,0x4f,
 0xb8,0x19,0xb9,0x61,0xd9,0x04,0xd5,0xe3,0x45,0xae,0xea,0x8b,
 0x5a,0x51,0x61,0xf0,0xe0,0x16,0xc6,0xdb,0x57,0x35,0x1e,0x63,
 0x71,0x7c,0xda,0x81,0x4c,0xe7,0x2a,0xb7,0xcc,0xb2,0x6f,0xfd,
 0x43,0xb2,0xd3,0xe9,
};
const uint8_t tc_ISK_SY[] = {
 0xbb,0x8b,0x3f,0x6f,0x8a,0x01,0xc9,0x6f,0xc2,0x2c,0x95,0x3a,
 0xbc,0x1d,0xf7,0xc8,0xd5,0x5e,0x19,0x05,0x81,0x33,0x76,0x64,
 0xe5,0x1b,0xb2,0x09,0x37,0xbe,0x3e,0xb7,0x67,0x49,0xa5,0x7b,
 0xd5,0x3a,0x21,0x2d,0xee,0x18,0x3c,0xee,0x54,0xdd,0xf9,0xda,
 0x5f,0x44,0xbf,0x9a,0x02,0x9f,0x2e,0x41,0xf3,0xee,0xe9,0x9a,
 0x8d,0x7f,0x91,0xaf,
};
~~~


### Test case for scalar\_mult\_vfy with correct inputs


~~~
    s: (length: 66 bytes)
      0182dd7925f1753419e4bf83429763acd37d64000cd5a175edf53a15
      87dd986bc95acc1506991702b6ba1a9ee2458fee8efc00198cf0088c
      480965ef65ff2048b856
    X: (length: 133 bytes)
      040035c91b4fb38fc22c9ec01d4983f3ca383fc2707e72c71b44b923
      b112fef65accfe15570851f390af32a528bb550ab10a93de4de8c611
      8f7f435f3bfcebb7ff1ccd00c175af70e49b9cea7ada85f1206668d1
      764288517b1de94675497103100e40766bd072decc226ebf7daa8a13
      832ce0c14f12e398a60bd35c9fcc3f412af545c529
    G.scalar_mult(s,X) (full coordinates): (length: 133 bytes)
      0401bca7bb39ecc32be4253b943c42f423fd0c52053c89a17ba30e9f
      5e82d46935b2242ffea447c5b36772fd7ebfe84e3f00e3f0aa3736a7
      2d2bf4d6d07dde4bcb899c007a7b71a2fc3530adfb283eadf073491d
      581002c3194509cd65da3cc5161856312d490d75082d17dd2a6194be
      968e64b675a3728d0c91870d7cb87c38eac2658272
    G.scalar_mult_vfy(s,X) (only X-coordinate):
    (length: 66 bytes)
      01bca7bb39ecc32be4253b943c42f423fd0c52053c89a17ba30e9f5e
      82d46935b2242ffea447c5b36772fd7ebfe84e3f00e3f0aa3736a72d
      2bf4d6d07dde4bcb899c
~~~


### Invalid inputs for scalar\_mult\_vfy which MUST result in aborts

For these test cases scalar\_mult\_vfy(y,.) MUST return the representation of the neutral element G.I. A G.I result from scalar\_mult\_vfy MUST make the protocol abort!


~~~
    s: (length: 66 bytes)
      0182dd7925f1753419e4bf83429763acd37d64000cd5a175edf53a15
      87dd986bc95acc1506991702b6ba1a9ee2458fee8efc00198cf0088c
      480965ef65ff2048b856
    Y_i1: (length: 133 bytes)
      040035c91b4fb38fc22c9ec01d4983f3ca383fc2707e72c71b44b923
      b112fef65accfe15570851f390af32a528bb550ab10a93de4de8c611
      8f7f435f3bfcebb7ff1ccd00c175af70e49b9cea7ada85f1206668d1
      764288517b1de94675497103100e40766bd072decc226ebf7daa8a13
      832ce0c14f12e398a60bd35c9fcc3f412af545c5c4
    Y_i2: (length: 1 bytes)
      00
    G.scalar_mult_vfy(s,Y_i1) = G.scalar_mult_vfy(s,Y_i2) = G.I
~~~

