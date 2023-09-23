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
    org: DFINITY - Zurich
    email: michel.abdalla@gmail.com
 -  ins: B. Haase
    name: Bjoern Haase
    org: Endress + Hauser Liquid Analysis - Gerlingen
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

  IEEE1363:
    title: Standard Specifications for Public Key Cryptography, IEEE 1363
    date: 2000

informative:
  ES21:
    title: The 'quantum annoying' property of password-authenticated key exchange protocols.
    target: https://eprint.iacr.org/2021/696
    author:
      -
        ins: E. Eaton
      -
        ins: D. Stebila

  ABKLX21:
    title: Algebraic Adversaries in the Universal Composability Framework.
    target: https://eprint.iacr.org/2021/1218
    author:
      -
        ins: M. Abdalla
      -
        ins: M. Barbosa
      -
        ins: J. Katz
      -
        ins: J. Loss
      -
        ins: J. Xu

  AHH21:
    title: "Security analysis of CPace"
    target: https://eprint.iacr.org/2021/114
    author:
      -
        ins: M. Abdalla
      -
        ins: B. Haase
      -
        ins: J. Hesse
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

  SEC2:
    title: "SEC 2: Recommended Elliptic Curve Domain Parameters"
    target: http://www.secg.org/sec2-v2.pdf
    date: Jan, 2010
    author:
      -
        org: Standards for Efficient Cryptography Group (SECG)

--- abstract

This document describes CPace which is a protocol that allows two
parties that share a low-entropy secret (password) to derive a strong shared key without
disclosing the secret to offline dictionary attacks.
The CPace protocol was tailored for constrained devices,
is compatible with any cyclic group of prime- and non-prime order.

--- middle

# Introduction

This document describes CPace which is a balanced Password-Authenticated-Key-Establishment (PAKE)
protocol for two parties where both parties derive a cryptographic key
of high entropy from a shared secret of low-entropy.
CPace protects the passwords against offline dictionary attacks by requiring
adversaries to actively interact with a protocol party and by allowing
for at most one single password guess per active interaction.

The CPace design was tailored considering the following main objectives:

- Efficiency: Deployment of CPace is feasible on resource-constrained devices.

- Versatility: CPace supports different application scenarios via versatile input formats, and by supporting applications with and without clear initiator and responder roles.

- Implementation error resistance: CPace avoids common implementation pitfalls already by-design, and it does not offer incentives for insecure speed-ups. For smooth integration into different cryptographic library ecosystems, this document provides a variety of cipher suites.

- Post-quantum annoyance: CPace comes with mitigations with respect to adversaries that become capable of breaking the discrete logarithm problem on elliptic curves.

## Outline of this document

- {{ApplicationPerspective}} describes the expected properties of an application using CPace, and discusses in particular which application-level aspects are relevant for CPace's security.

- {{CipherSuites}} gives an overview over the recommended
  cipher suites for CPace which were optimized for different types of cryptographic
  library ecosystems.

- {{Definition}} introduces the notation used throughout this document.

- {{protocol-section}} specifies the CPace protocol.

- The final section provides explicit reference implementations and test vectors of all of the
  functions defined for CPace in the appendix.

As this document is primarily written for implementers and application designers, we would like to refer the theory-inclined reader to the scientific paper {{AHH21}} which covers the detailed security analysis of the different CPace instantiations as defined in this document via the cipher suites.

# Requirements Notation

{::boilerplate bcp14}


# High-level application perspective {#ApplicationPerspective}

CPace enables balanced password-authenticated key establishment. CPace requires a shared secret octet string, the password-related string (PRS), is available for both parties A and B. PRS can be a low-entropy secret itself, for instance a clear-text password encoded according to {{?RFC8265}}, or any string derived from a common secret, for instance by use of a password-based key derivation function.

Applications with clients and servers where the server side is storing account and password information in its persistent memory are recommended to use augmented PAKE protocols such as OPAQUE {{!I-D.irtf-cfrg-opaque}}.

In the course of the CPace protocol, A sends one message MSGa to B and B sends one message MSGb to A. CPace does not mandate any ordering of these two messages. We use the term "initiator-responder" for CPace where A always speaks first, and the term "symmetric" setting where anyone can speak first.

CPace's output is an intermediate session key (ISK), but any party might abort in case of an invalid received message. A and B will produce the same ISK value only if both sides did initiate the protocol using the same protocol inputs, specifically the same PRS string and the same value for the optional input parameters CI, ADa, ADb and sid that will be specified in the upcoming sections.

The naming of ISK key as "intermediate" session key highlights the fact that it is RECOMMENDED that applications process ISK by use of a suitable strong key derivation function KDF (such as defined in {{?RFC5869}}) before using the key in a higher-level protocol.

## Optional CPace inputs

For accomodating different application settings, CPace offers the following OPTIONAL inputs, i.e. inputs which MAY also be the empty string:

- Channel identifier (CI). CI can be used to bind a session key exchanged with CPace to a specific networking channel which interconnects the protocol parties. Both parties are required to have the same view of CI. CI will not be publicly sent on the wire and may also include confidential information.

- Associated data fields (ADa and ADb).
  These fields can be used to authenticate public associated data alongside the CPace protocol. The values ADa (and ADb, respectively) are guaranteed to be authenticated in case both parties agree on a key.

  ADa and ADb can for instance include party identities or protocol
  version information of an application protocol (e.g. to avoid downgrade attacks).

  If party identities are not encoded as part of CI, party identities SHOULD be included in ADa and ADB
   (see {{sec-considerations-ids}}).
  In a setting with clear initiator and responder roles, identity information in ADa
  sent by the initiator can be used by the responder for choosing the right PRS string (respectively password) for this identity.

- Session identifier (sid).
  CPace comes with a security analysis {{AHH21}} in the framework of universal composability.
  This framework allows for modular analysis of a larger application protocol which uses CPace as a building block. For such analysis
  the CPace protocol is bound to a specific session of the larger protocol by use of a sid string that is globally unique. As a result, when used with a unique sid, CPace instances remain secure when running concurrently with other CPace instances, and even arbitrary other protocols.

  For this reason, it is RECOMMENDED that applications establish a unique session identifier sid
  prior to running the CPace protocol. This can be implemented by concatenating random bytes produced by A
  with random bytes produced by B. If such preceding round is not an option but
  parties are assigned clear initiator-responder roles, it is RECOMMENDED to let the initiator A choose a fresh
  random sid and send it to B together with the first message.
  If a sid string is used it SHOULD HAVE a length of at least 8 bytes.

## Responsibilities of the application layer

The following tasks are out of the scope of this document and left to the application layer

- Setup phase:

  - The application layer is responsible for the handshake that makes parties agree on a common CPace cipher suite.
  - The application layer needs to specify how to encode the CPace byte strings Ya / Yb and ADa / ADb defined in section
   {{protocol-section}}
    for transfer over the network.
    For CPace it is RECOMMENDED to encode network messages by using MSGa = lv\_cat(Ya,ADa) and MSGb = lv\_cat(Yb,ADb)
    using the length-value concatenation function lv\_cat
    speficied in {{notation-section}}.
    This document provides test vectors for lv\_cat-encoded messages.
    Alternative network encodings, e.g., the encoding method
    used for the client hello and server hello messages of the TLS protocol, MAY be used
    when considering the guidance given in {{sec-considerations}}.

- This document does not specify which encodings applications use for the mandatory PRS input and the optional inputs
  CI, sid, ADa and ADb. If PRS is a clear-text password or an octet string derived from a clear-text password,
  e.g. by use of a key-derivation function, the clear-text password SHOULD BE encoded according to {{?RFC8265}}.

- The application needs to settle whether CPace is used in the initiator-responder or the symmetric setting, as in the symmetric
  setting transcripts must be generated using ordered string concatenation. In this document we will provide test vectors
  for both, initiator-responder and symmetric settings.

# CPace cipher suites {#CipherSuites}

In the setup phase of CPace, both communication partners need to agree on a common cipher suite.
Cipher suites consist of a combination of a hash function H and an elliptic curve environment G.

For naming cipher suites we use the convention "CPACE-G-H". We RECOMMEND the following cipher suites:

- CPACE-X25519-SHA512. This suite uses the group environment G\_X25519 defined in {{CPaceMontgomery}} and SHA-512 as hash function.
  This cipher suite comes with the smallest messages on the wire and a low computational cost.

- CPACE-P256\_XMD:SHA-256\_SSWU_NU\_-SHA256.
This suite instantiates the group environment G as specified in {{CPaceWeierstrass}} using the encode_to_curve function P256\_XMD:SHA-256\_SSWU_NU\_
from {{?RFC9380}} on curve NIST-P256, and hash function SHA-256.

The following RECOMMENDED cipher suites provide higher security margins.

- CPACE-X448-SHAKE256. This suite uses the group environment G\_X448 defined in {{CPaceMontgomery}} and SHAKE-256 as hash function.

- CPACE-P384\_XMD:SHA-384\_SSWU_NU\_-SHA384.
This suite instantiates G as specified in {{CPaceWeierstrass}} using the encode_to_curve function P384\_XMD:SHA-384\_SSWU_NU\_
from {{?RFC9380}} on curve NIST-P384 with H = SHA-384.

- CPACE-P521\_XMD:SHA-512\_SSWU_NU\_-SHA512.
This suite instantiates G as specified in {{CPaceWeierstrass}} using the encode_to_curve function P521\_XMD:SHA-384\_SSWU_NU\_
from {{?RFC9380}} on curve NIST-P521 with H = SHA-512.


CPace can also securely be implemented using the cipher suites CPACE-RISTR255-SHA512 and CPACE-DECAF448-SHAKE256 defined in
{{CPaceCoffee}}. {{sec-considerations}} gives guidance on how to implement CPace on further elliptic curves.

# Definitions and notation {#Definition}

## Hash function H

Common choices for H are SHA-512 {{?RFC6234}} or SHAKE-256 {{FIPS202}}. (I.e. the hash function
outputs octet strings, and not group elements.)
For considering both variable-output-length hashes and fixed-output-length hashes, we use the following convention.
In case that the hash function is specified for a fixed-size output, we define H.hash(m,l) such
that it returns the first l octets of the output.

We use the following notation for referring to the specific properties of a hash function H:

- H.hash(m,l) is a function that operates on an input octet string m and returns a hashing result of l octets.

- H.b\_in\_bytes denotes the default output size in bytes corresponding to the symmetric
security level of the hash function. E.g. H.b\_in\_bytes = 64 for SHA-512 and SHAKE-256 and H.b\_in_bytes = 32 for
SHA-256 and SHAKE-128. We use the notation H.hash(m) = H.hash(m, H.b\_in\_bytes) and let the hash operation
output the default length if no explicit length parameter is given.

- H.bmax\_in\_bytes denotes the _maximum_ output size in octets supported by the hash function. In case of fixed-size
hashes such as SHA-256, this is the same as H.b\_in\_bytes, while there is no such limit for hash functions such as SHAKE-256.

- H.s\_in\_bytes denotes the _input block size_ used by H. For instance, for SHA-512 the input block size s\_in\_bytes is 128,
while for SHAKE-256 the input block size amounts to 136 bytes.

## Group environment G

The group environment G specifies an elliptic curve group (also denoted G for convenience)  and associated constants
and functions as detailed below. In this document we use multiplicative notation for the group operation.

- G.calculate\_generator(H,PRS,CI,sid) denotes a function that outputs a representation of a generator (referred to as "generator" from now on) of the group
which is derived from input octet strings PRS, CI, and sid and with the help of the hash function H.

- G.sample\_scalar() is a function returning a representation of a scalar (referred to as "scalar" from now on) appropriate as a
private Diffie-Hellman key for the group.

- G.scalar\_mult(y,g) is a function operating on a scalar
y and a group element g.
It returns an octet string representation of the group element Y = g^y.

- G.I denotes a unique octet string representation of the neutral element of the group. G.I is used for detecting and signaling certain error conditions.

- G.scalar\_mult\_vfy(y,g) is a function operating on
a scalar y and a group element g. It returns an octet string
representation of the group element g^y. Additionally, scalar\_mult\_vfy specifies validity conditions for y,g and g^y and outputs G.I in case they are not met.

- G.DSI denotes a domain-separation identifier string which SHALL be uniquely identifying the group environment G.

## Notation for string operations {#notation-section}

- bytes1 \|\| bytes2 and denotes concatenation of octet strings.

- len(S) denotes the number of octets in a string S.

- nil denotes an empty octet string, i.e., len(nil) = 0.

- prepend\_len(octet\_string) denotes the octet sequence that is obtained from prepending
  the length of the octet string to the string itself. The length shall be prepended by using an LEB128 encoding of the length.
  This will result in a single-byte encoding for values below 128. (Test vectors and reference implementations
  for prepend\_len and the LEB128 encodings are given in the appendix.)

- lv\_cat(a0,a1, ...) is the "length-value" encoding function which returns the concatenation of the input strings with an encoding of
  their respective length prepended. E.g. lv\_cat(a0,a1) returns
  prepend\_len(a0) \|\| prepend\_len(a1). The detailed specification of lv\_cat and a reference implementations are given in the appendix.

- network\_encode(Y,AD) denotes the function specified by the application layer that outputs an octet string encoding
  of the input octet strings Y and AD
  for transfer on the network. The implementation of MSG = network\_encode(Y,AD) SHALL allow the receiver party to parse MSG for the
  individual subcomponents Y and AD.
  For CPace we RECOMMEND to implement network\_encode(Y,AD) as network\_encode(Y,AD) = lv\_cat(Y,AD).

  Other prefix-free encodings, such as the network encoding
  used for the client-hello messages in TLS MAY also be used. We give guidance in the security consideration sections.
  but here the guidance given in the security consideration section MUST be considered.

- sample\_random\_bytes(n) denotes a function that returns n octets uniformly distributed between 0 and 255.

- zero\_bytes(n) denotes a function that returns n octets with value 0.

- oCat(bytes1,bytes2) denotes ordered concatenation of octet strings, which places the lexiographically larger octet
  string first. (Explicit reference code for this function is given in the appendix.)

- transcript(MSGa,MSGb) denotes function outputing a string for the protocol transcript with messages MSGa and MSGb.
  In applications where CPace is used without clear initiator and responder roles, i.e. where the ordering of messages is
  not enforced by the protocol flow, transcript(MSGa,MSGb) = oCat(MSGa,MSGb) SHOULD be used.
  In the initiator-responder setting transcript(MSGa,MSGb) SHOULD BE implemented such that the later message is appended to the
  earlier message, i.e., transcript(MSGa,MSGb) = MSGa\|\|MSGb if MSGa is sent first.

## Notation for group operations

We use multiplicative notation for the group, i.e., X^2  denotes the element that is obtained by computing X*X, for group element X and group operation *.

# The CPace protocol {#protocol-section}

CPace is a one round protocol between two parties, A and B. At invocation, A and B are provisioned with PRS,G,H and OPTIONAL CI,sid,ADa (for A) and CI,sid,ADb (for B).
A sends a message MSGa to B. MSGa contains the public share Ya
and OPTIONAL associated data ADa (i.e. an ADa field that MAY have a length of 0 bytes).
Likewise, B sends a message MSGb to A. MSGb contains the public share Yb
and OPTIONAL associated data ADb (i.e. an ADb field that MAY have a length of 0 bytes).
Both A and B use the received messages for deriving a shared intermediate session key, ISK.

## Protocol flow

Optional parameters and messages are denoted with [].

~~~
            public: G, H, [CI], [sid]

  A: PRS,[ADa]                    B: PRS,[ADb]
    ---------------------------------------
 compute Ya    |     Ya,[ADa]     |  compute Yb
               |----------------->|
               |     Yb,[ADb]     |
 verify inputs |<-----------------|  verify inputs
 derive ISK    |                  |  derive ISK
    ---------------------------------------
 output ISK                          output ISK

~~~

## CPace protocol instructions

A computes a generator g = G.calculate\_generator(H,PRS,CI,sid), scalar ya = G.sample\_scalar() and group element Ya = G.scalar\_mult (ya,g). A then transmits MSGa = network\_encode(Ya, ADa) with
optional associated data ADa to B.

B computes a generator g = G.calculate_generator(H,PRS,CI,sid), scalar yb = G.sample\_scalar() and group element Yb = G.scalar\_mult(yb,g). B sends MSGb = network\_encode(Yb, ADb) with optional associated data ADb to A.

Upon reception of MSGa, B checks that MSGa was properly generated conform with the chosen encoding of network messages (notably correct length fields).
If this parsing fails, then B MUST abort. (Testvectors of examples for invalid messages when using lv\_cat() as network\_encode function for
CPace are given in the appendix.)
B then computes K = G.scalar\_mult_vfy(yb,Ya). B MUST abort if K=G.I.
Otherwise B returns
ISK = H.hash(prefix\_free\_cat(G.DSI \|\| "\_ISK", sid, K)\|\|transcript(MSGa, MSGb)). B returns ISK and terminates.

Likewise upon reception of MSGb, A parses MSGb for Yb and ADb and checks for a valid encoding.
If this parsing fails, then A MUST abort. A then computes K = G.scalar\_mult\_vfy(ya,Yb). A MUST abort if K=G.I.
Otherwise A returns
ISK = H.hash(lv\_cat(G.DSI \|\| "\_ISK", sid, K) \|\| transcript(MSGa, MSGb)). A returns ISK and terminates.

The session key ISK returned by A and B is identical if and only if the supplied input parameters PRS, CI and sid match on both sides and transcript view (containing of MSGa and MSGb) of both parties match.

Note that in case of a symmetric protocol execution without clear initiator/responder roles, ordered concatenation needs to be used for
generating a matching view of the transcript by both parties.

# Implementation of recommended CPace cipher suites

## Common function for computing generators

The different cipher suites for CPace defined in the upcoming sections share the same method for deterministically combining the individual strings PRS, CI, sid and the domain-separation identifier G.DSI to a generator string that we describe here.

- generator\_string(G.DSI, PRS, CI, sid, s\_in\_bytes) denotes a function that returns the string
lv\_cat(G.DSI, PRS, zero\_bytes(len\_zpad), CI, sid).

- len\_zpad = MAX(0, s\_in\_bytes - len(prepend\_len(PRS)) - len(prepend\_len(G.DSI)) - 1)

The zero padding of length len\_zpad is designed such that the encoding of G.DSI and PRS together with the zero padding field completely
fills the first input block (of length s\_in\_bytes) of the hash.
As a result the number of bytes to hash becomes independent of the actual length of the password (PRS). (A reference implementation
and test vectors are provided in the appendix.)

The introduction of a zero-padding within the generator string also helps mitigating attacks of a side-channel adversary that
analyzes correlations between publicly known variable information with the low-entropy PRS string.
Note that the hash of the first block is intentionally made independent of session-specific inputs, such as sid or CI.

## CPace group objects G\_X25519 and G\_X448 for single-coordinate Ladders on Montgomery curves {#CPaceMontgomery}

In this section we consider the case of CPace when using the X25519 and X448 Diffie-Hellman functions
from {{?RFC7748}} operating on the Montgomery curves Curve25519 and Curve448 {{?RFC7748}}.
CPace implementations using single-coordinate ladders on further Montgomery curves SHALL use the definitions in line
with the specifications for X25519 and X448 and review the guidance given in {{sec-considerations}}.

For the group environment G\_X25519 the following definitions apply:

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
to use G\_X448 in combination with SHAKE-256.

For both G\_X448 and G\_X25519 the G.calculate\_generator(H, PRS,sid,CI) function shall be implemented as follows.

 - First gen\_str = generator\_string(G.DSI,PRS,CI,sid, H.s\_in\_bytes) SHALL BE calculated using the input block size of the
   chosen hash function.

 - This string SHALL then BE hashed to the required length
   gen\_str\_hash = H.hash(gen\_str, G.field\_size\_bytes).
   Note that this implies that the permissible output length H.maxb\_in\_bytes MUST BE larger or equal to the
   field size of the group G for making a hashing function suitable.

 - This result is then considered as a field coordinate using
   the u = decodeUCoordinate(gen\_str\_hash, G.field\_size\_bits) function from {{!RFC7748}} which we
   repeat in the appendix for convenience.

 - The result point g is then calculated as (g,v) = map\_to\_curve\_elligator2(u) using the function
   from {{?RFC9380}}. Note that the v coordinate produced by the map\_to\_curve\_elligator2 function
   is not required for CPace and discarded. The appendix repeats the definitions from {{?RFC9380}} for convenience.

In the appendix we show sage code that can be used as reference implementation.

### Verification tests

For single-coordinate Montgomery ladders on Montgomery curves verification tests according to {{verification}} SHALL
consider the u coordinate values that encode a low-order point on either, the curve or the quadratic twist.

In addition to that in case of G_X25519 the tests SHALL also verify that the implementation of G.scalar\_mult\_vfy(y,g) produces the
expected results for non-canonical u coordinate values with bit #255 set, which also encode low-order points.

Corresponding test vectors are provided in the appendix.

## CPace group objects G\_Ristretto255 and G\_Decaf448 for prime-order group abstractions {#CPaceCoffee}

In this section we consider the case of CPace using the Ristretto255 and Decaf448 group abstractions {{!I-D.draft-irtf-cfrg-ristretto255-decaf448}}.
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
    1381806680989511535200738674851542
    6880336692474882178609894547503885

CPace cipher suites using G\_Decaf448 MUST use a hash function producing at least H.b\_max\_in\_bytes >= 112 bytes of output.
It is RECOMMENDED to use G\_Decaf448 in combination with SHAKE-256.

For both abstractions the following definitions apply:

- It is RECOMMENDED to implement G.sample\_scalar() as follows.

  - Set scalar = sample\_random\_bytes(G.group\_size\_bytes).

  - Then clear the most significant bits larger than G.group\_size\_bits.

  - Interpret the result as the little-endian encoding of an integer value and return the result.

-  Alternatively, if G.sample\_scalar() is not implemented according to the above recommendation, it SHALL be implemented using uniform sampling between 1 and (G.group\_order - 1). Note that the more complex
uniform sampling process can provide a larger side-channel attack surface for embedded systems in hostile environments.

- G.scalar\_mult(y,\_g) SHALL operate on a scalar y and a group element \_g in the internal representation of the group abstraction environment. It returns the value Y = encode((\_g)^y), i.e. it returns a value using the public encoding.

- G.I = is the public encoding representation of the identity element.

- G.scalar\_mult\_vfy(y,X) operates on a value using the public encoding and a scalar and is implemented as follows. If the decode(X) function fails, it returns G.I. Otherwise it returns encode( decode(X)^y ).

- The G.calculate\_generator(H, PRS,sid,CI) function SHALL return a decoded point and SHALL BE implemented as follows.

   - First gen\_str = generator\_string(G.DSI,PRS,CI,sid, H.s\_in\_bytes) is calculated using the input block size of the chosen hash function.

   - This string is then hashed to the required length gen\_str\_hash = H.hash(gen\_str, 2 * G.field\_size\_bytes).  Note that this
     implies that the permissible output length H.maxb\_in\_bytes MUST BE larger or equal to twice the field size of the group
     G for making a
     hash function suitable.

   - Finally the internal representation of the generator \_g is calculated as \_g = one\_way\_map(gen\_str\_hash)
     using the element derivation function from the abstraction.

Note that with these definitions the scalar\_mult function operates on a decoded point \_g and returns an encoded point,
while the scalar\_mult\_vfy(y,X) function operates on an encoded point X (and also returns an encoded point).

### Verification tests

For group abstractions verification tests according to {{verification}} SHALL consider encodings of the neutral element and an octet string
that does not decode to a valid group element.

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

For CPace only the uncompressed full-coordinate encodings from {{SEC1}} (x and y coordinate) SHOULD be used.
Commonly used curve groups are specified in {{SEC2}} and {{?RFC5639}}. A typical representative of such a Short-Weierstrass curve is NIST-P256.
Point verification as used in ECKAS-DH1 is described in Annex A.16.10. of {{IEEE1363}}.

For deriving Diffie-Hellman shared secrets ECKAS-DH1 from {{IEEE1363}} specifies the use of an ECSVDP-DH method. We use ECSVDP-DH in combination with the identy map such that it either returns "error" or the x-coordinate of the Diffie-Hellman result point as shared secret in big endian format (fixed length output by FE2OSP without truncating leading zeros).

### Suitable encode\_to\_curve methods

All the encode\_to\_curve methods specified in {{?RFC9380}}
are suitable for CPace. For Short-Weierstrass curves it is RECOMMENDED to use the non-uniform variant of the SSWU
mapping primitive from {{?RFC9380}} if a SSWU mapping is available for the chosen curve. (We recommend non-uniform maps in order to give implementations
the flexibility to opt for x-coordinate-only scalar multiplication algorithms.)

### Definition of the group environment G for Short-Weierstrass curves

In this paragraph we use the following notation for defining the group object G for a selected curve and encode\_to\_curve method:

- With G.group\_order we denote the order of the elliptic curve which MUST BE a prime.

- With is\_valid(X) we denote a method which operates on an octet stream according to {{SEC1}} of a point on the group and returns true if the point is valid and returns false otherwise. This is\_valid(X) method SHALL be implemented according to Annex A.16.10. of {{IEEE1363}}. I.e. it shall return false if X encodes either the neutral element on the group or does not form a valid encoding of a point on the group.

- With encode\_to\_curve(str,DST) we denote a selected mapping function from {{?RFC9380}}. I.e. a function that maps
octet string str to a point on the group using domain separation tag DST. {{?RFC9380}} considers both, uniform and non-uniform mappings based on several different strategies. It is RECOMMENDED to use the nonuniform variant of the SSWU mapping primitive within {{?RFC9380}}.

- G.DSI denotes a domain-separation identifier string. G.DSI which SHALL BE obtained by the concatenation of "CPace" and the associated name of the cipher suite used for the encode\_to\_curve function as specified in {{?RFC9380}}. E.g. when using the map with the name "P384\_XMD:SHA-384\_SSWU\_NU\_"
on curve NIST-P384 the resulting value SHALL BE G.DSI = "CPaceP384\_XMD:SHA-384\_SSWU\_NU\_".

Using the above definitions, the CPace functions required for the group object G are defined as follows.

- G.DST denotes the domain-separation tag value to use in conjunction with the encode\_to\_curve function from {{?RFC9380}}. G.DST shall be obtained by concatenating G.DSI and "_DST".

- G.sample\_scalar() SHALL return a value between 1 and (G.group\_order - 1). The value sampling MUST BE uniformly random. It is RECOMMENDED to use rejection sampling for converting a uniform bitstring to a uniform value between 1 and (G.group\_order - 1).

- G.calculate\_generator(H, PRS,sid,CI) function SHALL be implemented as follows.

   - First gen\_str = generator\_string(G.DSI,PRS,CI,sid, H.s\_in\_bytes) is calculated.

   - Then the output of a call to encode\_to\_curve(gen\_str, G.DST) is returned, using the selected suite from {{?RFC9380}}.

- G.scalar\_mult(s,X) is a function that operates on a scalar s and an input point X. The input X shall use the same encoding as produced by the G.calculate\_generator method above.
G.scalar\_mult(s,X) SHALL return an encoding of either the point X^s or the point X^(-s) according to {{SEC1}}. Implementations SHOULD use the full-coordinate format without compression, as important protocols such as TLS 1.3 removed support for compression. Implementations of scalar\_mult(s,X) MAY output either X^s or X^(-s) as both points X^s and X^(-s) have the same x-coordinate and
result in the same Diffie-Hellman shared secrets K.
(This allows implementations to opt for x-coordinate-only scalar multiplication algorithms.)

- G.scalar\_mult\_vfy(s,X) merges verification of point X according to {{IEEE1363}} A.16.10. and the the ECSVDP-DH procedure from {{IEEE1363}}.
It SHALL BE implemented as follows:

   - If is\_valid(X) = False then G.scalar\_mult\_vfy(s,X) SHALL return "error" as specified in {{IEEE1363}} A.16.10 and 7.2.1.

   - Otherwise G.scalar\_mult\_vfy(s,X) SHALL return the result of the ECSVDP-DH procedure from {{IEEE1363}} (section 7.2.1). I.e. it shall
     either return "error" (in case that X^s is the neutral element) or the secret shared value "z" (otherwise). "z" SHALL be encoded by using
     the big-endian encoding of the x-coordinate of the result point X^s according to {{SEC1}}.

- We represent the neutral element G.I by using the representation of the "error" result case from {{IEEE1363}} as used in the G.scalar\_mult\_vfy method above.

### Verification tests

For Short-Weierstrass curves verification tests according to {{verification}} SHALL consider encodings of the point at infinity and an encoding of a point not on the group.

# Implementation verification {#verification}

Any CPace implementation MUST be tested against invalid or weak point attacks.
Implementation MUST be verified to abort upon conditions where G.scalar\_mult\_vfy functions outputs G.I.
For testing an implementation it is RECOMMENDED to include weak or invalid points in MSGa and MSGb and introduce this
in a protocol run. It SHALL be verified that the abort condition is properly handled.

Moreover any implementation MUST be tested with respect invalid encodings of MSGa and MSGb where the length of the message
does not match the specified encoding (i.e. where the sum of the prepended length information does not match the actual length
of the message).

Corresponding test vectors are given in the appendix for all recommended cipher suites.


# Security Considerations {#sec-considerations}

A security proof of CPace is found in {{AHH21}}. This proof covers all recommended cipher suites included in this document.
In the following sections we describe how to protect CPace against several attack families, such as relay-, length extension- or side channel attacks. We also describe aspects to consider when deviating from recommended cipher suites.

## Party identifiers and relay attacks {#sec-considerations-ids}

If unique strings identifying the protocol partners are included either as part of the channel identifier CI, the session id sid or the associated data fields ADa, ADb, the ISK will provide implicit authentication also regarding the party identities. Incorporating party identifier strings
is important for fending off relay attacks.
Such attacks become relevant in a setting where several parties, say, A, B and C, share the same password PRS. An adversary might relay messages from a honest user A, who aims at interacting with user B, to a party C instead. If no party identifier strings are used, and B and C use the same PRS value, A might be establishing a common ISK key with C while assuming to interact with party B.
Including and checking party identifiers can fend off such relay attacks.

## Network message encoding and hashing protocol transcripts

It is RECOMMENDED to encode the (Ya,ADa) and (Yb,ADb) fields on the network by using network\_encode(Y,AD) = lv\_cat(Y,AD). I.e. we RECOMMEND
to prepend an encoding of the length of the subfields. As the length
of the variable-size input strings are prepended this results in a so-called prefix-free encoding of transcript strings, using terminology introduced in {{CDMP05}}. This property allows for disregarding length-extension imperfections that come with the commonly used
Merkle-Damgard hash function constructions such as SHA256 and SHA512.

Other alternative network encoding formats which prepend an encoding of the length of variable-size data fields in the protocol
messages are equally suitable.
This includes, e.g., the type-length-value format specified in the DER encoding standard (X.690) or the protocol message encoding used in the TLS protocol family for the TLS client-hello or server-hello messages.

In case that an application whishes to use another form of network message encoding which is not prefix-free,
the guidance given in {{CDMP05}} SHOULD BE considered (e.g. by replacing hash functions with the HMAC constructions from{{?RFC2104}}).

## Key derivation {#key-derivation}

Although already K is a shared value, it MUST NOT itself be used as an application key. Instead, ISK MUST BE used. Leakage of K to an adversary can lead to offline dictionary attacks.

As noted already in {{protocol-section}} it is RECOMMENDED to process ISK
by use of a suitable strong key derivation function KDF (such as defined in {{?RFC5869}}) first,
before using the key in a higher-level protocol.

## Key confirmation

In many applications it is advisable to add an explicit key confirmation round after the CPace protocol flow. However, as some applications
might only require implicit authentication and as explicit authentication messages are already a built-in feature in many higher-level protocols (e.g. TLS 1.3) the CPace protocol described here does not mandate
use of a key confirmation on the level of the CPace sub-protocol.

Already without explicit key confirmation, CPace enjoys weak forward security under the sCDH and sSDH assumptions {{AHH21}}.
With added explicit confirmation, CPace enjoys perfect forward security also under the strong sCDH and sSDH assumptions {{AHH21}}.

Note that in {{ABKLX21}} it was shown that an idealized variant of CPace
also enjoys perfect forward security without explicit key confirmation. However this proof does not explicitly cover
the recommended cipher suites
in this document and requires the stronger assumption of an algebraic adversary model. For this reason, we recommend adding
explicit key confirmation if perfect forward security is required.

When implementing explicit key confirmation, it is recommended to use an appropriate message-authentication code (MAC)
such as HMAC {{?RFC2104}} or
CMAC {{?RFC4493}} using a key mac\_key derived from ISK.

One suitable option that works also in the parallel setting without message ordering is to proceed as follows.

- First calculate mac\_key as as mac\_key = H.hash(b"CPaceMac" \|\| ISK).

- Then let each party send an authenticator tag Ta, Tb that is calculated over the protocol message that it has sent previously. I.e.
  let party A calculate its transmitted authentication code Ta as Ta = MAC(mac\_key, MSGa) and let party B calculate its transmitted
  authentication code Tb as Tb = MAC(mac\_key, MSGb).

- Let the receiving party check the remote authentication tag for the correct value and abort in case that it's incorrect.


## Sampling of scalars

For curves over fields F\_p where p is a prime close to a power of two, we recommend sampling scalars as a uniform bit string of length field\_size\_bits. We do so in order to reduce both, complexity of the implementation and reducing the attack surface
with respect to side-channels for embedded systems in hostile environments.
The effect of non-uniform sampling on security was demonstrated to be begning in {{AHH21}} for the case of Curve25519 and Curve448.
This analysis however does not transfer to most curves in Short-Weierstrass form. As a result, we recommend rejection sampling if G is as in {{CPaceWeierstrass}}.

## Single-coordinate CPace on Montgomery curves

The recommended cipher suites for the Montgomery curves Curve25519 and Curve448 in {{CPaceMontgomery}} rely on the following properties  {{AHH21}}:

- The curve has order (p * c) with p prime and c a small cofactor. Also the curve's quadratic twist must be of order (p' * c') with p' prime and c' a cofactor.

- The cofactor c' of the twist MUST BE EQUAL to or an integer multiple of the cofactor c of the curve.

- Both field order q and group order p MUST BE close to a power of two along the lines of {{AHH21}}, Appendix E.

- The representation of the neutral element G.I MUST BE the same for both, the curve and its twist.

- The implementation of G.scalar\_mult\_vfy(y,X) MUST map all c low-order points on the curve and all c' low-order points on the twist to G.I.

Montgomery curves other than the ones recommended here can use the specifications given in {{CPaceMontgomery}}, given that the above properties hold.

## Nonce values

Secret scalars ya and yb MUST NOT be reused. Values for sid SHOULD NOT be reused since the composability
guarantees established by the simulation-based proof rely on the uniqueness of session ids {{AHH21}}.

If CPace is used in a concurrent system, it is RECOMMENDED that a unique sid is generated by the higher-level protocol and passed to CPace. One suitable option is that sid is generated by concatenating ephemeral random strings contributed by both parties.

## Side channel attacks

All state-of-the art methods for realizing constant-time execution SHOULD be used.
In case that side channel attacks are to be considered practical for a given application, it is RECOMMENDED to pay special
attention on computing
the secret generator G.calculate_generator(PRS,CI,sid).
The most critical substep to consider might be the processing of the first block of the hash that includes
the PRS string.
The zero-padding introduced when hashing the sensitive PRS string can be expected to make
the task for a side-channel attack somewhat more complex. Still this feature alone is not sufficient for ruling out power analysis attacks.

## Quantum computers

CPace is proven secure under the hardness of the strong computational Simultaneous Diffie-Hellmann (sSDH) and strong computational Diffie-Hellmann (sCDH)
assumptions in the group G (as defined in {{AHH21}}).
These assumptions are not expected to hold any longer when large-scale quantum computers (LSQC) are available.
Still, even in case that LSQC emerge, it is reasonable to assume that discrete-logarithm computations will remain costly. CPace with ephemeral session id values
sid forces the adversary to solve one computational Diffie-Hellman problem per password guess {{ES21}}.
In this sense, using the wording suggested by Steve Thomas on the CFRG mailing list, CPace is "quantum-annoying".

# IANA Considerations

No IANA action is required.

# Acknowledgements

We would like to thank the participants on the CFRG list for comments and advice. Any comment and advice is appreciated.

--- back





# CPace function definitions


## Definition and test vectors for string utility functions


### prepend\_len function


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


### lv\_cat function


~~~
  def lv_cat(*args):
      result = b""
      for arg in args:
          result += prepend_len(arg)
      return result
~~~


### Testvector for lv\_cat()

~~~
  lv_cat(b"1234",b"5",b"",b"6789"): (length: 13 bytes)
    04313233340135000436373839
~~~

### Examples for messages not obtained from a lv\_cat-based encoding


The following messages are examples which have invalid encoded length fields. I.e. they are examples
where parsing for the sum of the length of subfields as expected for a message generated using lv\_cat(Y,AD)
does not give the correct length of the message. Parties MUST abort upon reception of such invalid messages as MSGa or MSGb.



~~~
  Inv_MSG1 not encoded by lv_cat: (length: 3 bytes)
    ffffff
  Inv_MSG2 not encoded by lv_cat: (length: 3 bytes)
    ffff03
  Inv_MSG3 not encoded by lv_cat: (length: 4 bytes)
    00ffff03
  Inv_MSG4 not encoded by lv_cat: (length: 4 bytes)
    00ffffff
~~~

## Definition of generator\_string function.


~~~
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




~~~
  def oCAT(bytes1,bytes2):
      if lexiographically_larger(bytes1,bytes2):
          return bytes1 + bytes2
      else:
          return bytes2 + bytes1
~~~

### Test vectors ordered concatenation

~~~
  string comparison for oCAT:
    lexiographically_larger(b"\0", b"\0\0") == False
    lexiographically_larger(b"\1", b"\0\0") == True
    lexiographically_larger(b"\0\0", b"\0") == True
    lexiographically_larger(b"\0\0", b"\1") == False
    lexiographically_larger(b"\0\1", b"\1") == False
    lexiographically_larger(b"ABCD", b"BCD") == False

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

The values of the non-square Z only depend on the curve. The algorithm above
results in a value of Z = 2 for Curve25519 and Z=-1 for Ed448.

The following code maps a field element r to an encoded field element which
is a valid u-coordinate of a Montgomery curve with curve parameter A.

~~~
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
    CI = b'\nAinitiator\nBresponder'
    CI = 0a41696e69746961746f720a42726573706f6e646572
    sid = 7e4b4791d6a8ef019b936c79fb7f2c57
  Outputs
    generator_string(G.DSI,PRS,CI,sid,H.s_in_bytes):
    (length: 168 bytes)
      0843506163653235350850617373776f72646d000000000000000000
      00000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000160a41696e69746961746f72
      0a42726573706f6e646572107e4b4791d6a8ef019b936c79fb7f2c57
    hash generator string: (length: 32 bytes)
      10047198e8c4cacf0ab8a6d0ac337b8ae497209d042f7f3a50945863
      94e821fc
    decoded field element of 255 bits: (length: 32 bytes)
      10047198e8c4cacf0ab8a6d0ac337b8ae497209d042f7f3a50945863
      94e8217c
    generator g: (length: 32 bytes)
      4e6098733061c0e8486611a904fe5edb049804d26130a44131a6229e
      55c5c321
~~~

###  Test vector for MSGa

~~~
  Inputs
    ADa = b'ADa'
    ya (little endian): (length: 32 bytes)
      45acf93116ae5d3dae995a7c627df2924321a8e857d9a200807131e3
      8839b0c2
  Outputs
    Ya: (length: 32 bytes)
      6f7fd31863b18b0cc9830fc842c60dea80120ccf2fd375498225e45a
      52065361
    MSGa = lv_cat(Ya,ADa): (length: 37 bytes)
      206f7fd31863b18b0cc9830fc842c60dea80120ccf2fd375498225e4
      5a5206536103414461
~~~

###  Test vector for MSGb

~~~
  Inputs
    ADb = b'ADb'
    yb (little endian): (length: 32 bytes)
      a145e914b347002d298ce2051394f0ed68cf3623dfe5db082c78ffa5
      a667acdc
  Outputs
    Yb: (length: 32 bytes)
      e1b730a4956c0f853d96c5d125cebeeea46952c07c6f66da65bd9ffd
      2f71a462
    MSGb = lv_cat(Yb,ADb): (length: 37 bytes)
      20e1b730a4956c0f853d96c5d125cebeeea46952c07c6f66da65bd9f
      fd2f71a46203414462
~~~

###  Test vector for secret points K

~~~
    scalar_mult_vfy(ya,Yb): (length: 32 bytes)
      2a905bc5f0b93ee72ac4b6ea8723520941adfc892935bf6f86d9e199
      befa6024
    scalar_mult_vfy(yb,Ya): (length: 32 bytes)
      2a905bc5f0b93ee72ac4b6ea8723520941adfc892935bf6f86d9e199
      befa6024
~~~


###  Test vector for ISK calculation initiator/responder

~~~
    unordered cat of transcript : (length: 74 bytes)
      206f7fd31863b18b0cc9830fc842c60dea80120ccf2fd375498225e4
      5a520653610341446120e1b730a4956c0f853d96c5d125cebeeea469
      52c07c6f66da65bd9ffd2f71a46203414462
    DSI = G.DSI_ISK, b'CPace255_ISK': (length: 12 bytes)
      43506163653235355f49534b
    lv_cat(DSI,sid,K)||MSGa||MSGb: (length: 137 bytes)
      0c43506163653235355f49534b107e4b4791d6a8ef019b936c79fb7f
      2c57202a905bc5f0b93ee72ac4b6ea8723520941adfc892935bf6f86
      d9e199befa6024206f7fd31863b18b0cc9830fc842c60dea80120ccf
      2fd375498225e45a520653610341446120e1b730a4956c0f853d96c5
      d125cebeeea46952c07c6f66da65bd9ffd2f71a46203414462
    ISK result: (length: 64 bytes)
      99a9e0ff35acb94ad8af1cd6b32ac409dc7d00557ccd9a7d19d3b462
      9e5f1f084f9332096162438c7ecc78331b4eda17e1a229a47182eccc
      9ea58cd9cdcd8e9a
~~~

###  Test vector for ISK calculation parallel execution

~~~
    ordered cat of transcript : (length: 74 bytes)
      20e1b730a4956c0f853d96c5d125cebeeea46952c07c6f66da65bd9f
      fd2f71a46203414462206f7fd31863b18b0cc9830fc842c60dea8012
      0ccf2fd375498225e45a5206536103414461
    DSI = G.DSI_ISK, b'CPace255_ISK': (length: 12 bytes)
      43506163653235355f49534b
    lv_cat(DSI,sid,K)||oCAT(MSGa,MSGb): (length: 137 bytes)
      0c43506163653235355f49534b107e4b4791d6a8ef019b936c79fb7f
      2c57202a905bc5f0b93ee72ac4b6ea8723520941adfc892935bf6f86
      d9e199befa602420e1b730a4956c0f853d96c5d125cebeeea46952c0
      7c6f66da65bd9ffd2f71a46203414462206f7fd31863b18b0cc9830f
      c842c60dea80120ccf2fd375498225e45a5206536103414461
    ISK result: (length: 64 bytes)
      3cd6a9670fa3ff211d829b845baa0f5ba9ad580c3ba0ee790bd0e9cd
      556290a8ffce44419fbf94e4cb8e7fe9f454fd25dc13e689e4d6ab0a
      c2211c70a8ac0062
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
 0x4e,0x60,0x98,0x73,0x30,0x61,0xc0,0xe8,0x48,0x66,0x11,0xa9,
 0x04,0xfe,0x5e,0xdb,0x04,0x98,0x04,0xd2,0x61,0x30,0xa4,0x41,
 0x31,0xa6,0x22,0x9e,0x55,0xc5,0xc3,0x21,
};
const uint8_t tc_ya[] = {
 0x45,0xac,0xf9,0x31,0x16,0xae,0x5d,0x3d,0xae,0x99,0x5a,0x7c,
 0x62,0x7d,0xf2,0x92,0x43,0x21,0xa8,0xe8,0x57,0xd9,0xa2,0x00,
 0x80,0x71,0x31,0xe3,0x88,0x39,0xb0,0xc2,
};
const uint8_t tc_ADa[] = {
 0x41,0x44,0x61,
};
const uint8_t tc_Ya[] = {
 0x6f,0x7f,0xd3,0x18,0x63,0xb1,0x8b,0x0c,0xc9,0x83,0x0f,0xc8,
 0x42,0xc6,0x0d,0xea,0x80,0x12,0x0c,0xcf,0x2f,0xd3,0x75,0x49,
 0x82,0x25,0xe4,0x5a,0x52,0x06,0x53,0x61,
};
const uint8_t tc_yb[] = {
 0xa1,0x45,0xe9,0x14,0xb3,0x47,0x00,0x2d,0x29,0x8c,0xe2,0x05,
 0x13,0x94,0xf0,0xed,0x68,0xcf,0x36,0x23,0xdf,0xe5,0xdb,0x08,
 0x2c,0x78,0xff,0xa5,0xa6,0x67,0xac,0xdc,
};
const uint8_t tc_ADb[] = {
 0x41,0x44,0x62,
};
const uint8_t tc_Yb[] = {
 0xe1,0xb7,0x30,0xa4,0x95,0x6c,0x0f,0x85,0x3d,0x96,0xc5,0xd1,
 0x25,0xce,0xbe,0xee,0xa4,0x69,0x52,0xc0,0x7c,0x6f,0x66,0xda,
 0x65,0xbd,0x9f,0xfd,0x2f,0x71,0xa4,0x62,
};
const uint8_t tc_K[] = {
 0x2a,0x90,0x5b,0xc5,0xf0,0xb9,0x3e,0xe7,0x2a,0xc4,0xb6,0xea,
 0x87,0x23,0x52,0x09,0x41,0xad,0xfc,0x89,0x29,0x35,0xbf,0x6f,
 0x86,0xd9,0xe1,0x99,0xbe,0xfa,0x60,0x24,
};
const uint8_t tc_ISK_IR[] = {
 0x99,0xa9,0xe0,0xff,0x35,0xac,0xb9,0x4a,0xd8,0xaf,0x1c,0xd6,
 0xb3,0x2a,0xc4,0x09,0xdc,0x7d,0x00,0x55,0x7c,0xcd,0x9a,0x7d,
 0x19,0xd3,0xb4,0x62,0x9e,0x5f,0x1f,0x08,0x4f,0x93,0x32,0x09,
 0x61,0x62,0x43,0x8c,0x7e,0xcc,0x78,0x33,0x1b,0x4e,0xda,0x17,
 0xe1,0xa2,0x29,0xa4,0x71,0x82,0xec,0xcc,0x9e,0xa5,0x8c,0xd9,
 0xcd,0xcd,0x8e,0x9a,
};
const uint8_t tc_ISK_SY[] = {
 0x3c,0xd6,0xa9,0x67,0x0f,0xa3,0xff,0x21,0x1d,0x82,0x9b,0x84,
 0x5b,0xaa,0x0f,0x5b,0xa9,0xad,0x58,0x0c,0x3b,0xa0,0xee,0x79,
 0x0b,0xd0,0xe9,0xcd,0x55,0x62,0x90,0xa8,0xff,0xce,0x44,0x41,
 0x9f,0xbf,0x94,0xe4,0xcb,0x8e,0x7f,0xe9,0xf4,0x54,0xfd,0x25,
 0xdc,0x13,0xe6,0x89,0xe4,0xd6,0xab,0x0a,0xc2,0x21,0x1c,0x70,
 0xa8,0xac,0x00,0x62,
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

u0 ... ub MUST be verified to produce the correct results q0 ... qb:

Additionally, u0,u1,u2,u3,u4,u5 and u7 MUST trigger the abort case
when included in MSGa or MSGb.

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
    PRS = b'Password' ; ZPAD length: 117 ; DSI = b'CPace448'
    CI = b'\nAinitiator\nBresponder'
    CI = 0a41696e69746961746f720a42726573706f6e646572
    sid = 5223e0cdc45d6575668d64c552004124
  Outputs
    generator_string(G.DSI,PRS,CI,sid,H.s_in_bytes):
    (length: 176 bytes)
      0843506163653434380850617373776f726475000000000000000000
      00000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      000000000000000000000000000000000000000000000000160a4169
      6e69746961746f720a42726573706f6e646572105223e0cdc45d6575
      668d64c552004124
    hash generator string: (length: 56 bytes)
      769e06d6c41c8cf1c87aa3df8e687167f6d0a2e41821e856276a0221
      d88272359d0b43204b546174c9179c83c107b707f296eafaa1c5a293
    decoded field element of 448 bits: (length: 56 bytes)
      769e06d6c41c8cf1c87aa3df8e687167f6d0a2e41821e856276a0221
      d88272359d0b43204b546174c9179c83c107b707f296eafaa1c5a293
    generator g: (length: 56 bytes)
      6fdae14718eb7506dd96e3f7797896efdb8db9ec0797485c9c48a192
      2e44961da097f2908b084a5de33ab671630660d27d79ffd6ee8ec846
~~~

###  Test vector for MSGa

~~~
  Inputs
    ADa = b'ADa'
    ya (little endian): (length: 56 bytes)
      21b4f4bd9e64ed355c3eb676a28ebedaf6d8f17bdc365995b3190971
      53044080516bd083bfcce66121a3072646994c8430cc382b8dc543e8
  Outputs
    Ya: (length: 56 bytes)
      396bd11daf223711e575cac6021e3fa31558012048a1cec7876292b9
      6c61eda353fe04f33028d2352779668a934084da776c1c51a58ce4b5
    MSGa = lv_cat(Ya,ADa): (length: 61 bytes)
      38396bd11daf223711e575cac6021e3fa31558012048a1cec7876292
      b96c61eda353fe04f33028d2352779668a934084da776c1c51a58ce4
      b503414461
~~~

###  Test vector for MSGb

~~~
  Inputs
    ADb = b'ADb'
    yb (little endian): (length: 56 bytes)
      848b0779ff415f0af4ea14df9dd1d3c29ac41d836c7808896c4eba19
      c51ac40a439caf5e61ec88c307c7d619195229412eaa73fb2a5ea20d
  Outputs
    Yb: (length: 56 bytes)
      53c519fb490fde5a04bda8c18b327d0fc1a9391d19e0ac00c59df9c6
      0422284e593d6b092eac94f5aa644ed883f39bd4f04e4beb6af86d58
    MSGb = lv_cat(Yb,ADb): (length: 61 bytes)
      3853c519fb490fde5a04bda8c18b327d0fc1a9391d19e0ac00c59df9
      c60422284e593d6b092eac94f5aa644ed883f39bd4f04e4beb6af86d
      5803414462
~~~

###  Test vector for secret points K

~~~
    scalar_mult_vfy(ya,Yb): (length: 56 bytes)
      e00af217556a40ccbc9822cc27a43542e45166a653aa4df746d5f8e1
      e8df483e9baff71c9eb03ee20a688ad4e4d359f70ac9ec3f6a659997
    scalar_mult_vfy(yb,Ya): (length: 56 bytes)
      e00af217556a40ccbc9822cc27a43542e45166a653aa4df746d5f8e1
      e8df483e9baff71c9eb03ee20a688ad4e4d359f70ac9ec3f6a659997
~~~


###  Test vector for ISK calculation initiator/responder

~~~
    unordered cat of transcript : (length: 122 bytes)
      38396bd11daf223711e575cac6021e3fa31558012048a1cec7876292
      b96c61eda353fe04f33028d2352779668a934084da776c1c51a58ce4
      b5034144613853c519fb490fde5a04bda8c18b327d0fc1a9391d19e0
      ac00c59df9c60422284e593d6b092eac94f5aa644ed883f39bd4f04e
      4beb6af86d5803414462
    DSI = G.DSI_ISK, b'CPace448_ISK': (length: 12 bytes)
      43506163653434385f49534b
    lv_cat(DSI,sid,K)||MSGa||MSGb: (length: 209 bytes)
      0c43506163653434385f49534b105223e0cdc45d6575668d64c55200
      412438e00af217556a40ccbc9822cc27a43542e45166a653aa4df746
      d5f8e1e8df483e9baff71c9eb03ee20a688ad4e4d359f70ac9ec3f6a
      65999738396bd11daf223711e575cac6021e3fa31558012048a1cec7
      876292b96c61eda353fe04f33028d2352779668a934084da776c1c51
      a58ce4b5034144613853c519fb490fde5a04bda8c18b327d0fc1a939
      1d19e0ac00c59df9c60422284e593d6b092eac94f5aa644ed883f39b
      d4f04e4beb6af86d5803414462
    ISK result: (length: 64 bytes)
      4030297722c1914711da6b2a224a44b53b30c05ab02c2a3d3ccc7272
      a3333ce3a4564c17031b634e89f65681f52d5c3d1df7baeb88523d2e
      481b3858aed86315
~~~

###  Test vector for ISK calculation parallel execution

~~~
    ordered cat of transcript : (length: 122 bytes)
      3853c519fb490fde5a04bda8c18b327d0fc1a9391d19e0ac00c59df9
      c60422284e593d6b092eac94f5aa644ed883f39bd4f04e4beb6af86d
      580341446238396bd11daf223711e575cac6021e3fa31558012048a1
      cec7876292b96c61eda353fe04f33028d2352779668a934084da776c
      1c51a58ce4b503414461
    DSI = G.DSI_ISK, b'CPace448_ISK': (length: 12 bytes)
      43506163653434385f49534b
    lv_cat(DSI,sid,K)||oCAT(MSGa,MSGb): (length: 209 bytes)
      0c43506163653434385f49534b105223e0cdc45d6575668d64c55200
      412438e00af217556a40ccbc9822cc27a43542e45166a653aa4df746
      d5f8e1e8df483e9baff71c9eb03ee20a688ad4e4d359f70ac9ec3f6a
      6599973853c519fb490fde5a04bda8c18b327d0fc1a9391d19e0ac00
      c59df9c60422284e593d6b092eac94f5aa644ed883f39bd4f04e4beb
      6af86d580341446238396bd11daf223711e575cac6021e3fa3155801
      2048a1cec7876292b96c61eda353fe04f33028d2352779668a934084
      da776c1c51a58ce4b503414461
    ISK result: (length: 64 bytes)
      925e95d1095dad1af6378d5ef8b9a998bd3855bfc7d36cb5ca05b0a7
      a93346abcb8cef04bceb28c38fdaf0cc608fd1dcd462ab523f3b7f75
      2c77c411be3ac8fb
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
 0x6f,0xda,0xe1,0x47,0x18,0xeb,0x75,0x06,0xdd,0x96,0xe3,0xf7,
 0x79,0x78,0x96,0xef,0xdb,0x8d,0xb9,0xec,0x07,0x97,0x48,0x5c,
 0x9c,0x48,0xa1,0x92,0x2e,0x44,0x96,0x1d,0xa0,0x97,0xf2,0x90,
 0x8b,0x08,0x4a,0x5d,0xe3,0x3a,0xb6,0x71,0x63,0x06,0x60,0xd2,
 0x7d,0x79,0xff,0xd6,0xee,0x8e,0xc8,0x46,
};
const uint8_t tc_ya[] = {
 0x21,0xb4,0xf4,0xbd,0x9e,0x64,0xed,0x35,0x5c,0x3e,0xb6,0x76,
 0xa2,0x8e,0xbe,0xda,0xf6,0xd8,0xf1,0x7b,0xdc,0x36,0x59,0x95,
 0xb3,0x19,0x09,0x71,0x53,0x04,0x40,0x80,0x51,0x6b,0xd0,0x83,
 0xbf,0xcc,0xe6,0x61,0x21,0xa3,0x07,0x26,0x46,0x99,0x4c,0x84,
 0x30,0xcc,0x38,0x2b,0x8d,0xc5,0x43,0xe8,
};
const uint8_t tc_ADa[] = {
 0x41,0x44,0x61,
};
const uint8_t tc_Ya[] = {
 0x39,0x6b,0xd1,0x1d,0xaf,0x22,0x37,0x11,0xe5,0x75,0xca,0xc6,
 0x02,0x1e,0x3f,0xa3,0x15,0x58,0x01,0x20,0x48,0xa1,0xce,0xc7,
 0x87,0x62,0x92,0xb9,0x6c,0x61,0xed,0xa3,0x53,0xfe,0x04,0xf3,
 0x30,0x28,0xd2,0x35,0x27,0x79,0x66,0x8a,0x93,0x40,0x84,0xda,
 0x77,0x6c,0x1c,0x51,0xa5,0x8c,0xe4,0xb5,
};
const uint8_t tc_yb[] = {
 0x84,0x8b,0x07,0x79,0xff,0x41,0x5f,0x0a,0xf4,0xea,0x14,0xdf,
 0x9d,0xd1,0xd3,0xc2,0x9a,0xc4,0x1d,0x83,0x6c,0x78,0x08,0x89,
 0x6c,0x4e,0xba,0x19,0xc5,0x1a,0xc4,0x0a,0x43,0x9c,0xaf,0x5e,
 0x61,0xec,0x88,0xc3,0x07,0xc7,0xd6,0x19,0x19,0x52,0x29,0x41,
 0x2e,0xaa,0x73,0xfb,0x2a,0x5e,0xa2,0x0d,
};
const uint8_t tc_ADb[] = {
 0x41,0x44,0x62,
};
const uint8_t tc_Yb[] = {
 0x53,0xc5,0x19,0xfb,0x49,0x0f,0xde,0x5a,0x04,0xbd,0xa8,0xc1,
 0x8b,0x32,0x7d,0x0f,0xc1,0xa9,0x39,0x1d,0x19,0xe0,0xac,0x00,
 0xc5,0x9d,0xf9,0xc6,0x04,0x22,0x28,0x4e,0x59,0x3d,0x6b,0x09,
 0x2e,0xac,0x94,0xf5,0xaa,0x64,0x4e,0xd8,0x83,0xf3,0x9b,0xd4,
 0xf0,0x4e,0x4b,0xeb,0x6a,0xf8,0x6d,0x58,
};
const uint8_t tc_K[] = {
 0xe0,0x0a,0xf2,0x17,0x55,0x6a,0x40,0xcc,0xbc,0x98,0x22,0xcc,
 0x27,0xa4,0x35,0x42,0xe4,0x51,0x66,0xa6,0x53,0xaa,0x4d,0xf7,
 0x46,0xd5,0xf8,0xe1,0xe8,0xdf,0x48,0x3e,0x9b,0xaf,0xf7,0x1c,
 0x9e,0xb0,0x3e,0xe2,0x0a,0x68,0x8a,0xd4,0xe4,0xd3,0x59,0xf7,
 0x0a,0xc9,0xec,0x3f,0x6a,0x65,0x99,0x97,
};
const uint8_t tc_ISK_IR[] = {
 0x40,0x30,0x29,0x77,0x22,0xc1,0x91,0x47,0x11,0xda,0x6b,0x2a,
 0x22,0x4a,0x44,0xb5,0x3b,0x30,0xc0,0x5a,0xb0,0x2c,0x2a,0x3d,
 0x3c,0xcc,0x72,0x72,0xa3,0x33,0x3c,0xe3,0xa4,0x56,0x4c,0x17,
 0x03,0x1b,0x63,0x4e,0x89,0xf6,0x56,0x81,0xf5,0x2d,0x5c,0x3d,
 0x1d,0xf7,0xba,0xeb,0x88,0x52,0x3d,0x2e,0x48,0x1b,0x38,0x58,
 0xae,0xd8,0x63,0x15,
};
const uint8_t tc_ISK_SY[] = {
 0x92,0x5e,0x95,0xd1,0x09,0x5d,0xad,0x1a,0xf6,0x37,0x8d,0x5e,
 0xf8,0xb9,0xa9,0x98,0xbd,0x38,0x55,0xbf,0xc7,0xd3,0x6c,0xb5,
 0xca,0x05,0xb0,0xa7,0xa9,0x33,0x46,0xab,0xcb,0x8c,0xef,0x04,
 0xbc,0xeb,0x28,0xc3,0x8f,0xda,0xf0,0xcc,0x60,0x8f,0xd1,0xdc,
 0xd4,0x62,0xab,0x52,0x3f,0x3b,0x7f,0x75,0x2c,0x77,0xc4,0x11,
 0xbe,0x3a,0xc8,0xfb,
};
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
when included in the protocol messages MSGa or MSGb.
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
    PRS = b'Password' ; ZPAD length: 100 ;
    DSI = b'CPaceRistretto255'
    CI = b'\nAinitiator\nBresponder'
    CI = 0a41696e69746961746f720a42726573706f6e646572
    sid = 7e4b4791d6a8ef019b936c79fb7f2c57
  Outputs
    generator_string(G.DSI,PRS,CI,sid,H.s_in_bytes):
    (length: 168 bytes)
      11435061636552697374726574746f3235350850617373776f726464
      00000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000160a41696e69746961746f72
      0a42726573706f6e646572107e4b4791d6a8ef019b936c79fb7f2c57
    hash result: (length: 64 bytes)
      a5ce446f63a1ae6d1fee80fa67d0b4004a4b1283ec5549a462bf33a6
      c1ae06a0871f9bf48545f49b2a792eed255ac04f52758c9c60448306
      810b44e986e3dcbb
    encoded generator g: (length: 32 bytes)
      5e25411ca1ad7c9debfd0b33ad987a95cefef2d3f15dcc8bd26415a5
      dfe2e15a
~~~


###  Test vector for MSGa

~~~
  Inputs
    ADa = b'ADa'
    ya (little endian): (length: 32 bytes)
      da3d23700a9e5699258aef94dc060dfda5ebb61f02a5ea77fad53f4f
      f0976d08
  Outputs
    Ya: (length: 32 bytes)
      383a85dd236978f17f8c8545b50dabc52a39fcdab2cf8bc531ce040f
      f77ca82d
    MSGa = lv_cat(Ya,ADa): (length: 37 bytes)
      20383a85dd236978f17f8c8545b50dabc52a39fcdab2cf8bc531ce04
      0ff77ca82d03414461
~~~

###  Test vector for MSGb

~~~
  Inputs
    ADb = b'ADb'
    yb (little endian): (length: 32 bytes)
      d2316b454718c35362d83d69df6320f38578ed5984651435e2949762
      d900b80d
  Outputs
    Yb: (length: 32 bytes)
      a6206309c0e8e5f579295e35997ac4300ab3fecec3c17f7b604f3e69
      8fa1383c
    MSGb = lv_cat(Yb,ADb): (length: 37 bytes)
      20a6206309c0e8e5f579295e35997ac4300ab3fecec3c17f7b604f3e
      698fa1383c03414462
~~~

###  Test vector for secret points K

~~~
    scalar_mult_vfy(ya,Yb): (length: 32 bytes)
      fa1d0318864e2cacb26875f1b791c9ae83204fe8359addb53e95a2e9
      8893853f
    scalar_mult_vfy(yb,Ya): (length: 32 bytes)
      fa1d0318864e2cacb26875f1b791c9ae83204fe8359addb53e95a2e9
      8893853f
~~~


###  Test vector for ISK calculation initiator/responder

~~~
    unordered cat of transcript : (length: 74 bytes)
      20383a85dd236978f17f8c8545b50dabc52a39fcdab2cf8bc531ce04
      0ff77ca82d0341446120a6206309c0e8e5f579295e35997ac4300ab3
      fecec3c17f7b604f3e698fa1383c03414462
    DSI = G.DSI_ISK, b'CPaceRistretto255_ISK':
    (length: 21 bytes)
      435061636552697374726574746f3235355f49534b
    lv_cat(DSI,sid,K)||MSGa||MSGb: (length: 146 bytes)
      15435061636552697374726574746f3235355f49534b107e4b4791d6
      a8ef019b936c79fb7f2c5720fa1d0318864e2cacb26875f1b791c9ae
      83204fe8359addb53e95a2e98893853f20383a85dd236978f17f8c85
      45b50dabc52a39fcdab2cf8bc531ce040ff77ca82d0341446120a620
      6309c0e8e5f579295e35997ac4300ab3fecec3c17f7b604f3e698fa1
      383c03414462
    ISK result: (length: 64 bytes)
      e91ccb2c0f5e0d0993a33956e3be59754f3f2b07db57631f5394452e
      a2e7b4354674eb1f5686c078462bf83bec72e8743df440108e638f35
      26d9b90e85be096f
~~~

###  Test vector for ISK calculation parallel execution

~~~
    ordered cat of transcript : (length: 74 bytes)
      20a6206309c0e8e5f579295e35997ac4300ab3fecec3c17f7b604f3e
      698fa1383c0341446220383a85dd236978f17f8c8545b50dabc52a39
      fcdab2cf8bc531ce040ff77ca82d03414461
    DSI = G.DSI_ISK, b'CPaceRistretto255_ISK':
    (length: 21 bytes)
      435061636552697374726574746f3235355f49534b
    lv_cat(DSI,sid,K)||oCAT(MSGa,MSGb): (length: 146 bytes)
      15435061636552697374726574746f3235355f49534b107e4b4791d6
      a8ef019b936c79fb7f2c5720fa1d0318864e2cacb26875f1b791c9ae
      83204fe8359addb53e95a2e98893853f20a6206309c0e8e5f579295e
      35997ac4300ab3fecec3c17f7b604f3e698fa1383c0341446220383a
      85dd236978f17f8c8545b50dabc52a39fcdab2cf8bc531ce040ff77c
      a82d03414461
    ISK result: (length: 64 bytes)
      2472dedbff868bfc12b4c256f790539af0e2bab7efc28d1a995d18a1
      a58e5bec639273d4604512669ab7953153d437eb90314dcba7539724
      02b0d9c5ec5283f8
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
 0x5e,0x25,0x41,0x1c,0xa1,0xad,0x7c,0x9d,0xeb,0xfd,0x0b,0x33,
 0xad,0x98,0x7a,0x95,0xce,0xfe,0xf2,0xd3,0xf1,0x5d,0xcc,0x8b,
 0xd2,0x64,0x15,0xa5,0xdf,0xe2,0xe1,0x5a,
};
const uint8_t tc_ya[] = {
 0xda,0x3d,0x23,0x70,0x0a,0x9e,0x56,0x99,0x25,0x8a,0xef,0x94,
 0xdc,0x06,0x0d,0xfd,0xa5,0xeb,0xb6,0x1f,0x02,0xa5,0xea,0x77,
 0xfa,0xd5,0x3f,0x4f,0xf0,0x97,0x6d,0x08,
};
const uint8_t tc_ADa[] = {
 0x41,0x44,0x61,
};
const uint8_t tc_Ya[] = {
 0x38,0x3a,0x85,0xdd,0x23,0x69,0x78,0xf1,0x7f,0x8c,0x85,0x45,
 0xb5,0x0d,0xab,0xc5,0x2a,0x39,0xfc,0xda,0xb2,0xcf,0x8b,0xc5,
 0x31,0xce,0x04,0x0f,0xf7,0x7c,0xa8,0x2d,
};
const uint8_t tc_yb[] = {
 0xd2,0x31,0x6b,0x45,0x47,0x18,0xc3,0x53,0x62,0xd8,0x3d,0x69,
 0xdf,0x63,0x20,0xf3,0x85,0x78,0xed,0x59,0x84,0x65,0x14,0x35,
 0xe2,0x94,0x97,0x62,0xd9,0x00,0xb8,0x0d,
};
const uint8_t tc_ADb[] = {
 0x41,0x44,0x62,
};
const uint8_t tc_Yb[] = {
 0xa6,0x20,0x63,0x09,0xc0,0xe8,0xe5,0xf5,0x79,0x29,0x5e,0x35,
 0x99,0x7a,0xc4,0x30,0x0a,0xb3,0xfe,0xce,0xc3,0xc1,0x7f,0x7b,
 0x60,0x4f,0x3e,0x69,0x8f,0xa1,0x38,0x3c,
};
const uint8_t tc_K[] = {
 0xfa,0x1d,0x03,0x18,0x86,0x4e,0x2c,0xac,0xb2,0x68,0x75,0xf1,
 0xb7,0x91,0xc9,0xae,0x83,0x20,0x4f,0xe8,0x35,0x9a,0xdd,0xb5,
 0x3e,0x95,0xa2,0xe9,0x88,0x93,0x85,0x3f,
};
const uint8_t tc_ISK_IR[] = {
 0xe9,0x1c,0xcb,0x2c,0x0f,0x5e,0x0d,0x09,0x93,0xa3,0x39,0x56,
 0xe3,0xbe,0x59,0x75,0x4f,0x3f,0x2b,0x07,0xdb,0x57,0x63,0x1f,
 0x53,0x94,0x45,0x2e,0xa2,0xe7,0xb4,0x35,0x46,0x74,0xeb,0x1f,
 0x56,0x86,0xc0,0x78,0x46,0x2b,0xf8,0x3b,0xec,0x72,0xe8,0x74,
 0x3d,0xf4,0x40,0x10,0x8e,0x63,0x8f,0x35,0x26,0xd9,0xb9,0x0e,
 0x85,0xbe,0x09,0x6f,
};
const uint8_t tc_ISK_SY[] = {
 0x24,0x72,0xde,0xdb,0xff,0x86,0x8b,0xfc,0x12,0xb4,0xc2,0x56,
 0xf7,0x90,0x53,0x9a,0xf0,0xe2,0xba,0xb7,0xef,0xc2,0x8d,0x1a,
 0x99,0x5d,0x18,0xa1,0xa5,0x8e,0x5b,0xec,0x63,0x92,0x73,0xd4,
 0x60,0x45,0x12,0x66,0x9a,0xb7,0x95,0x31,0x53,0xd4,0x37,0xeb,
 0x90,0x31,0x4d,0xcb,0xa7,0x53,0x97,0x24,0x02,0xb0,0xd9,0xc5,
 0xec,0x52,0x83,0xf8,
};
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

For these test cases scalar\_mult\_vfy(y,.) MUST return the representation of the neutral element G.I. When points Y\_i1 or Y\_i2 are included in MSGa or MSGb the protocol MUST abort.

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

##  Test vector for CPace using group decaf448 and hash SHAKE-256


###  Test vectors for calculate\_generator with group decaf448

~~~
  Inputs
    H   = SHAKE-256 with input block size 136 bytes.
    PRS = b'Password' ; ZPAD length: 112 ;
    DSI = b'CPaceDecaf448'
    CI = b'\nAinitiator\nBresponder'
    CI = 0a41696e69746961746f720a42726573706f6e646572
    sid = 5223e0cdc45d6575668d64c552004124
  Outputs
    generator_string(G.DSI,PRS,CI,sid,H.s_in_bytes):
    (length: 176 bytes)
      0d435061636544656361663434380850617373776f72647000000000
      00000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      000000000000000000000000000000000000000000000000160a4169
      6e69746961746f720a42726573706f6e646572105223e0cdc45d6575
      668d64c552004124
    hash result: (length: 112 bytes)
      8955b426ff1d3a22032d21c013cf94134cee9a4235e93261a4911edb
      f68f2945f0267c983954262c7f59badb9caf468ebe21b7e9885657af
      b8f1a3b783c2047ba519e113ecf81b2b580dd481f499beabd401cc77
      1d28915fb750011209040f5f03b2ceb5e5eb259c96b478382d5a5c57
    encoded generator g: (length: 56 bytes)
      682d1a4f49fc2a4834356ae4d7f58636bc9481521c845e66e6fb0b29
      69341df45fbaeaea9e2221b3f5babc54c5f8ce456988ffc519defaeb
~~~


###  Test vector for MSGa

~~~
  Inputs
    ADa = b'ADa'
    ya (little endian): (length: 56 bytes)
      d8d2e26c821a12d7f59a8dee023d3f6155976152e16c73cbf68c303d
      f0404399f0a7b614a65df50a9788f00b410586b443f738ad7ff03930
  Outputs
    Ya: (length: 56 bytes)
      d4b87d2fcdcac1096dba1898361f27e29dc1e019f74f84a71199bfd3
      dc8d09d2b823038f579f517591474be366968e2fb599bf14e55704f4
    MSGa = lv_cat(Ya,ADa): (length: 61 bytes)
      38d4b87d2fcdcac1096dba1898361f27e29dc1e019f74f84a71199bf
      d3dc8d09d2b823038f579f517591474be366968e2fb599bf14e55704
      f403414461
~~~

###  Test vector for MSGb

~~~
  Inputs
    ADb = b'ADb'
    yb (little endian): (length: 56 bytes)
      91bae9793f4a8aceb1b5c54375a7ed1858a79a6e72dab959c8bdf3a7
      5ac9bb4de2a25af4d4a9a5c5bc5441d19b8e3f6fcce7196c6afc2236
  Outputs
    Yb: (length: 56 bytes)
      d61c6c039c01560e8b19b8299fb39513f39302eebd4c462694a33155
      a3a387e44aa613647fcf6303f918bad598aaab53bea849b9fd14da74
    MSGb = lv_cat(Yb,ADb): (length: 61 bytes)
      38d61c6c039c01560e8b19b8299fb39513f39302eebd4c462694a331
      55a3a387e44aa613647fcf6303f918bad598aaab53bea849b9fd14da
      7403414462
~~~

###  Test vector for secret points K

~~~
    scalar_mult_vfy(ya,Yb): (length: 56 bytes)
      e434cda1783ddaaef08fc1d5f2201f1540fbc295fe2dd7cc38f20385
      64824c98dbbe1978f121bdfead8e1a638913a6952cbec54867eb770a
    scalar_mult_vfy(yb,Ya): (length: 56 bytes)
      e434cda1783ddaaef08fc1d5f2201f1540fbc295fe2dd7cc38f20385
      64824c98dbbe1978f121bdfead8e1a638913a6952cbec54867eb770a
~~~


###  Test vector for ISK calculation initiator/responder

~~~
    unordered cat of transcript : (length: 122 bytes)
      38d4b87d2fcdcac1096dba1898361f27e29dc1e019f74f84a71199bf
      d3dc8d09d2b823038f579f517591474be366968e2fb599bf14e55704
      f40341446138d61c6c039c01560e8b19b8299fb39513f39302eebd4c
      462694a33155a3a387e44aa613647fcf6303f918bad598aaab53bea8
      49b9fd14da7403414462
    DSI = G.DSI_ISK, b'CPaceDecaf448_ISK': (length: 17 bytes)
      435061636544656361663434385f49534b
    lv_cat(DSI,sid,K)||MSGa||MSGb: (length: 214 bytes)
      11435061636544656361663434385f49534b105223e0cdc45d657566
      8d64c55200412438e434cda1783ddaaef08fc1d5f2201f1540fbc295
      fe2dd7cc38f2038564824c98dbbe1978f121bdfead8e1a638913a695
      2cbec54867eb770a38d4b87d2fcdcac1096dba1898361f27e29dc1e0
      19f74f84a71199bfd3dc8d09d2b823038f579f517591474be366968e
      2fb599bf14e55704f40341446138d61c6c039c01560e8b19b8299fb3
      9513f39302eebd4c462694a33155a3a387e44aa613647fcf6303f918
      bad598aaab53bea849b9fd14da7403414462
    ISK result: (length: 64 bytes)
      13636dc9b7d233ac24a2d5c4a85a72fe20145f7a47ad51cab40e087c
      057831b69ee59b9c828732bde171cfca99afda4852bcaf04fe9f0a97
      592cdf5e2c9a5948
~~~

###  Test vector for ISK calculation parallel execution

~~~
    ordered cat of transcript : (length: 122 bytes)
      38d61c6c039c01560e8b19b8299fb39513f39302eebd4c462694a331
      55a3a387e44aa613647fcf6303f918bad598aaab53bea849b9fd14da
      740341446238d4b87d2fcdcac1096dba1898361f27e29dc1e019f74f
      84a71199bfd3dc8d09d2b823038f579f517591474be366968e2fb599
      bf14e55704f403414461
    DSI = G.DSI_ISK, b'CPaceDecaf448_ISK': (length: 17 bytes)
      435061636544656361663434385f49534b
    lv_cat(DSI,sid,K)||oCAT(MSGa,MSGb): (length: 214 bytes)
      11435061636544656361663434385f49534b105223e0cdc45d657566
      8d64c55200412438e434cda1783ddaaef08fc1d5f2201f1540fbc295
      fe2dd7cc38f2038564824c98dbbe1978f121bdfead8e1a638913a695
      2cbec54867eb770a38d61c6c039c01560e8b19b8299fb39513f39302
      eebd4c462694a33155a3a387e44aa613647fcf6303f918bad598aaab
      53bea849b9fd14da740341446238d4b87d2fcdcac1096dba1898361f
      27e29dc1e019f74f84a71199bfd3dc8d09d2b823038f579f51759147
      4be366968e2fb599bf14e55704f403414461
    ISK result: (length: 64 bytes)
      999e8f8486670bc1bf874a4d8f1496b9ebd8909eb01cf46b275ec942
      2f22593064b272ba9e9e201a4a34a18729e48859a2d038c7c8cf0a0f
      e8a90ddcbdde1126
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
 0x68,0x2d,0x1a,0x4f,0x49,0xfc,0x2a,0x48,0x34,0x35,0x6a,0xe4,
 0xd7,0xf5,0x86,0x36,0xbc,0x94,0x81,0x52,0x1c,0x84,0x5e,0x66,
 0xe6,0xfb,0x0b,0x29,0x69,0x34,0x1d,0xf4,0x5f,0xba,0xea,0xea,
 0x9e,0x22,0x21,0xb3,0xf5,0xba,0xbc,0x54,0xc5,0xf8,0xce,0x45,
 0x69,0x88,0xff,0xc5,0x19,0xde,0xfa,0xeb,
};
const uint8_t tc_ya[] = {
 0xd8,0xd2,0xe2,0x6c,0x82,0x1a,0x12,0xd7,0xf5,0x9a,0x8d,0xee,
 0x02,0x3d,0x3f,0x61,0x55,0x97,0x61,0x52,0xe1,0x6c,0x73,0xcb,
 0xf6,0x8c,0x30,0x3d,0xf0,0x40,0x43,0x99,0xf0,0xa7,0xb6,0x14,
 0xa6,0x5d,0xf5,0x0a,0x97,0x88,0xf0,0x0b,0x41,0x05,0x86,0xb4,
 0x43,0xf7,0x38,0xad,0x7f,0xf0,0x39,0x30,
};
const uint8_t tc_ADa[] = {
 0x41,0x44,0x61,
};
const uint8_t tc_Ya[] = {
 0xd4,0xb8,0x7d,0x2f,0xcd,0xca,0xc1,0x09,0x6d,0xba,0x18,0x98,
 0x36,0x1f,0x27,0xe2,0x9d,0xc1,0xe0,0x19,0xf7,0x4f,0x84,0xa7,
 0x11,0x99,0xbf,0xd3,0xdc,0x8d,0x09,0xd2,0xb8,0x23,0x03,0x8f,
 0x57,0x9f,0x51,0x75,0x91,0x47,0x4b,0xe3,0x66,0x96,0x8e,0x2f,
 0xb5,0x99,0xbf,0x14,0xe5,0x57,0x04,0xf4,
};
const uint8_t tc_yb[] = {
 0x91,0xba,0xe9,0x79,0x3f,0x4a,0x8a,0xce,0xb1,0xb5,0xc5,0x43,
 0x75,0xa7,0xed,0x18,0x58,0xa7,0x9a,0x6e,0x72,0xda,0xb9,0x59,
 0xc8,0xbd,0xf3,0xa7,0x5a,0xc9,0xbb,0x4d,0xe2,0xa2,0x5a,0xf4,
 0xd4,0xa9,0xa5,0xc5,0xbc,0x54,0x41,0xd1,0x9b,0x8e,0x3f,0x6f,
 0xcc,0xe7,0x19,0x6c,0x6a,0xfc,0x22,0x36,
};
const uint8_t tc_ADb[] = {
 0x41,0x44,0x62,
};
const uint8_t tc_Yb[] = {
 0xd6,0x1c,0x6c,0x03,0x9c,0x01,0x56,0x0e,0x8b,0x19,0xb8,0x29,
 0x9f,0xb3,0x95,0x13,0xf3,0x93,0x02,0xee,0xbd,0x4c,0x46,0x26,
 0x94,0xa3,0x31,0x55,0xa3,0xa3,0x87,0xe4,0x4a,0xa6,0x13,0x64,
 0x7f,0xcf,0x63,0x03,0xf9,0x18,0xba,0xd5,0x98,0xaa,0xab,0x53,
 0xbe,0xa8,0x49,0xb9,0xfd,0x14,0xda,0x74,
};
const uint8_t tc_K[] = {
 0xe4,0x34,0xcd,0xa1,0x78,0x3d,0xda,0xae,0xf0,0x8f,0xc1,0xd5,
 0xf2,0x20,0x1f,0x15,0x40,0xfb,0xc2,0x95,0xfe,0x2d,0xd7,0xcc,
 0x38,0xf2,0x03,0x85,0x64,0x82,0x4c,0x98,0xdb,0xbe,0x19,0x78,
 0xf1,0x21,0xbd,0xfe,0xad,0x8e,0x1a,0x63,0x89,0x13,0xa6,0x95,
 0x2c,0xbe,0xc5,0x48,0x67,0xeb,0x77,0x0a,
};
const uint8_t tc_ISK_IR[] = {
 0x13,0x63,0x6d,0xc9,0xb7,0xd2,0x33,0xac,0x24,0xa2,0xd5,0xc4,
 0xa8,0x5a,0x72,0xfe,0x20,0x14,0x5f,0x7a,0x47,0xad,0x51,0xca,
 0xb4,0x0e,0x08,0x7c,0x05,0x78,0x31,0xb6,0x9e,0xe5,0x9b,0x9c,
 0x82,0x87,0x32,0xbd,0xe1,0x71,0xcf,0xca,0x99,0xaf,0xda,0x48,
 0x52,0xbc,0xaf,0x04,0xfe,0x9f,0x0a,0x97,0x59,0x2c,0xdf,0x5e,
 0x2c,0x9a,0x59,0x48,
};
const uint8_t tc_ISK_SY[] = {
 0x99,0x9e,0x8f,0x84,0x86,0x67,0x0b,0xc1,0xbf,0x87,0x4a,0x4d,
 0x8f,0x14,0x96,0xb9,0xeb,0xd8,0x90,0x9e,0xb0,0x1c,0xf4,0x6b,
 0x27,0x5e,0xc9,0x42,0x2f,0x22,0x59,0x30,0x64,0xb2,0x72,0xba,
 0x9e,0x9e,0x20,0x1a,0x4a,0x34,0xa1,0x87,0x29,0xe4,0x88,0x59,
 0xa2,0xd0,0x38,0xc7,0xc8,0xcf,0x0a,0x0f,0xe8,0xa9,0x0d,0xdc,
 0xbd,0xde,0x11,0x26,
};
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

For these test cases scalar\_mult\_vfy(y,.) MUST return the representation of the neutral element G.I. When points Y\_i1 or Y\_i2 are included in MSGa or MSGb the protocol MUST abort.

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

##  Test vector for CPace using group NIST P-256 and hash SHA-256


###  Test vectors for calculate\_generator with group NIST P-256

~~~
  Inputs
    H   = SHA-256 with input block size 64 bytes.
    PRS = b'Password' ; ZPAD length: 23 ;
    DSI = b'CPaceP256_XMD:SHA-256_SSWU_NU_'
    DST = b'CPaceP256_XMD:SHA-256_SSWU_NU__DST'
    CI = b'\nAinitiator\nBresponder'
    CI = 0a41696e69746961746f720a42726573706f6e646572
    sid = 34b36454cab2e7842c389f7d88ecb7df
  Outputs
    generator_string(PRS,G.DSI,CI,sid,H.s_in_bytes):
    (length: 104 bytes)
      1e4350616365503235365f584d443a5348412d3235365f535357555f
      4e555f0850617373776f726417000000000000000000000000000000
      0000000000000000160a41696e69746961746f720a42726573706f6e
      6465721034b36454cab2e7842c389f7d88ecb7df
    generator g: (length: 65 bytes)
      041b51433114e096c9d595f0955f5717a75169afb95557f4a6f51155
      035dee19c76887bce5c7c054fa1fe48a4a62c7fb96dc75e34259d2f7
      2b8d41f31b8e586bcd
~~~

###  Test vector for MSGa

~~~
  Inputs
    ADa = b'ADa'
    ya (big endian): (length: 32 bytes)
      37574cfbf1b95ff6a8e2d7be462d4d01e6dde2618f34f4de9df869b2
      4f532c5d
  Outputs
    Ya: (length: 65 bytes)
      04b75c1bcda84a0f324aabb7f25cf853ed7fb327c33f23db6aeb320d
      81df014649c2ac691925fce0eceac7dbc75eca25e6a1558066a610b4
      021488279e3b989d52
    Alternative correct value for Ya: g^(-ya):
    (length: 65 bytes)
      04b75c1bcda84a0f324aabb7f25cf853ed7fb327c33f23db6aeb320d
      81df0146493d5396e5da031f1415382438a135da195eaa7f9a59ef4b
      fdeb77d861c46762ad
    MSGa = lv_cat(Ya,ADa): (length: 70 bytes)
      4104b75c1bcda84a0f324aabb7f25cf853ed7fb327c33f23db6aeb32
      0d81df014649c2ac691925fce0eceac7dbc75eca25e6a1558066a610
      b4021488279e3b989d5203414461
~~~

###  Test vector for MSGb

~~~
  Inputs
    ADb = b'ADb'
    yb (big endian): (length: 32 bytes)
      e5672fc9eb4e721f41d80181ec4c9fd9886668acc48024d33c82bb10
      2aecba52
  Outputs
    Yb: (length: 65 bytes)
      04bb2783a57337e74671f76452876b27839c0ea9e044e3aadaad2e64
      777ed27a90e80a99438e2f1c072462f2895c6dadf1b43867b92ffb65
      562b78c793947dcada
    Alternative correct value for Yb: g^(-yb):
    (length: 65 bytes)
      04bb2783a57337e74671f76452876b27839c0ea9e044e3aadaad2e64
      777ed27a9017f566bb71d0e3f9db9d0d76a392520e4bc79847d0049a
      a9d487386c6b823525
    MSGb = lv_cat(Yb,ADb): (length: 70 bytes)
      4104bb2783a57337e74671f76452876b27839c0ea9e044e3aadaad2e
      64777ed27a90e80a99438e2f1c072462f2895c6dadf1b43867b92ffb
      65562b78c793947dcada03414462
~~~

###  Test vector for secret points K

~~~
    scalar_mult_vfy(ya,Yb): (length: 32 bytes)
      8fd12b283805750aeee6151bcd4211a6b71019e8fc416293ade24ed2
      bce12c39
    scalar_mult_vfy(yb,Ya): (length: 32 bytes)
      8fd12b283805750aeee6151bcd4211a6b71019e8fc416293ade24ed2
      bce12c39
~~~


###  Test vector for ISK calculation initiator/responder

~~~
    unordered cat of transcript : (length: 140 bytes)
      4104b75c1bcda84a0f324aabb7f25cf853ed7fb327c33f23db6aeb32
      0d81df014649c2ac691925fce0eceac7dbc75eca25e6a1558066a610
      b4021488279e3b989d52034144614104bb2783a57337e74671f76452
      876b27839c0ea9e044e3aadaad2e64777ed27a90e80a99438e2f1c07
      2462f2895c6dadf1b43867b92ffb65562b78c793947dcada03414462
    DSI = G.DSI_ISK, b'CPaceP256_XMD:SHA-256_SSWU_NU__ISK':
    (length: 34 bytes)
      4350616365503235365f584d443a5348412d3235365f535357555f4e
      555f5f49534b
    lv_cat(DSI,sid,K)||MSGa||MSGb: (length: 225 bytes)
      224350616365503235365f584d443a5348412d3235365f535357555f
      4e555f5f49534b1034b36454cab2e7842c389f7d88ecb7df208fd12b
      283805750aeee6151bcd4211a6b71019e8fc416293ade24ed2bce12c
      394104b75c1bcda84a0f324aabb7f25cf853ed7fb327c33f23db6aeb
      320d81df014649c2ac691925fce0eceac7dbc75eca25e6a1558066a6
      10b4021488279e3b989d52034144614104bb2783a57337e74671f764
      52876b27839c0ea9e044e3aadaad2e64777ed27a90e80a99438e2f1c
      072462f2895c6dadf1b43867b92ffb65562b78c793947dcada034144
      62
    ISK result: (length: 32 bytes)
      7ae1e916606e44652e3c0d7231198af6519226339c241e546afd0bbf
      48e1c96a
~~~

###  Test vector for ISK calculation parallel execution

~~~
    ordered cat of transcript : (length: 140 bytes)
      4104bb2783a57337e74671f76452876b27839c0ea9e044e3aadaad2e
      64777ed27a90e80a99438e2f1c072462f2895c6dadf1b43867b92ffb
      65562b78c793947dcada034144624104b75c1bcda84a0f324aabb7f2
      5cf853ed7fb327c33f23db6aeb320d81df014649c2ac691925fce0ec
      eac7dbc75eca25e6a1558066a610b4021488279e3b989d5203414461
    DSI = G.DSI_ISK, b'CPaceP256_XMD:SHA-256_SSWU_NU__ISK':
    (length: 34 bytes)
      4350616365503235365f584d443a5348412d3235365f535357555f4e
      555f5f49534b
    lv_cat(DSI,sid,K)||oCAT(MSGa,MSGb): (length: 225 bytes)
      224350616365503235365f584d443a5348412d3235365f535357555f
      4e555f5f49534b1034b36454cab2e7842c389f7d88ecb7df208fd12b
      283805750aeee6151bcd4211a6b71019e8fc416293ade24ed2bce12c
      394104bb2783a57337e74671f76452876b27839c0ea9e044e3aadaad
      2e64777ed27a90e80a99438e2f1c072462f2895c6dadf1b43867b92f
      fb65562b78c793947dcada034144624104b75c1bcda84a0f324aabb7
      f25cf853ed7fb327c33f23db6aeb320d81df014649c2ac691925fce0
      eceac7dbc75eca25e6a1558066a610b4021488279e3b989d52034144
      61
    ISK result: (length: 32 bytes)
      c5b4e6d44f5bbb7637a77ec67afd768a1343c410f7e1f76f6549eb00
      2623c0f1
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
 0x04,0x1b,0x51,0x43,0x31,0x14,0xe0,0x96,0xc9,0xd5,0x95,0xf0,
 0x95,0x5f,0x57,0x17,0xa7,0x51,0x69,0xaf,0xb9,0x55,0x57,0xf4,
 0xa6,0xf5,0x11,0x55,0x03,0x5d,0xee,0x19,0xc7,0x68,0x87,0xbc,
 0xe5,0xc7,0xc0,0x54,0xfa,0x1f,0xe4,0x8a,0x4a,0x62,0xc7,0xfb,
 0x96,0xdc,0x75,0xe3,0x42,0x59,0xd2,0xf7,0x2b,0x8d,0x41,0xf3,
 0x1b,0x8e,0x58,0x6b,0xcd,
};
const uint8_t tc_ya[] = {
 0x37,0x57,0x4c,0xfb,0xf1,0xb9,0x5f,0xf6,0xa8,0xe2,0xd7,0xbe,
 0x46,0x2d,0x4d,0x01,0xe6,0xdd,0xe2,0x61,0x8f,0x34,0xf4,0xde,
 0x9d,0xf8,0x69,0xb2,0x4f,0x53,0x2c,0x5d,
};
const uint8_t tc_ADa[] = {
 0x41,0x44,0x61,
};
const uint8_t tc_Ya[] = {
 0x04,0xb7,0x5c,0x1b,0xcd,0xa8,0x4a,0x0f,0x32,0x4a,0xab,0xb7,
 0xf2,0x5c,0xf8,0x53,0xed,0x7f,0xb3,0x27,0xc3,0x3f,0x23,0xdb,
 0x6a,0xeb,0x32,0x0d,0x81,0xdf,0x01,0x46,0x49,0xc2,0xac,0x69,
 0x19,0x25,0xfc,0xe0,0xec,0xea,0xc7,0xdb,0xc7,0x5e,0xca,0x25,
 0xe6,0xa1,0x55,0x80,0x66,0xa6,0x10,0xb4,0x02,0x14,0x88,0x27,
 0x9e,0x3b,0x98,0x9d,0x52,
};
const uint8_t tc_yb[] = {
 0xe5,0x67,0x2f,0xc9,0xeb,0x4e,0x72,0x1f,0x41,0xd8,0x01,0x81,
 0xec,0x4c,0x9f,0xd9,0x88,0x66,0x68,0xac,0xc4,0x80,0x24,0xd3,
 0x3c,0x82,0xbb,0x10,0x2a,0xec,0xba,0x52,
};
const uint8_t tc_ADb[] = {
 0x41,0x44,0x62,
};
const uint8_t tc_Yb[] = {
 0x04,0xbb,0x27,0x83,0xa5,0x73,0x37,0xe7,0x46,0x71,0xf7,0x64,
 0x52,0x87,0x6b,0x27,0x83,0x9c,0x0e,0xa9,0xe0,0x44,0xe3,0xaa,
 0xda,0xad,0x2e,0x64,0x77,0x7e,0xd2,0x7a,0x90,0xe8,0x0a,0x99,
 0x43,0x8e,0x2f,0x1c,0x07,0x24,0x62,0xf2,0x89,0x5c,0x6d,0xad,
 0xf1,0xb4,0x38,0x67,0xb9,0x2f,0xfb,0x65,0x56,0x2b,0x78,0xc7,
 0x93,0x94,0x7d,0xca,0xda,
};
const uint8_t tc_K[] = {
 0x8f,0xd1,0x2b,0x28,0x38,0x05,0x75,0x0a,0xee,0xe6,0x15,0x1b,
 0xcd,0x42,0x11,0xa6,0xb7,0x10,0x19,0xe8,0xfc,0x41,0x62,0x93,
 0xad,0xe2,0x4e,0xd2,0xbc,0xe1,0x2c,0x39,
};
const uint8_t tc_ISK_IR[] = {
 0x7a,0xe1,0xe9,0x16,0x60,0x6e,0x44,0x65,0x2e,0x3c,0x0d,0x72,
 0x31,0x19,0x8a,0xf6,0x51,0x92,0x26,0x33,0x9c,0x24,0x1e,0x54,
 0x6a,0xfd,0x0b,0xbf,0x48,0xe1,0xc9,0x6a,
};
const uint8_t tc_ISK_SY[] = {
 0xc5,0xb4,0xe6,0xd4,0x4f,0x5b,0xbb,0x76,0x37,0xa7,0x7e,0xc6,
 0x7a,0xfd,0x76,0x8a,0x13,0x43,0xc4,0x10,0xf7,0xe1,0xf7,0x6f,
 0x65,0x49,0xeb,0x00,0x26,0x23,0xc0,0xf1,
};
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

For these test cases scalar\_mult\_vfy(y,.) MUST return the representation of the neutral element G.I. When including Y\_i1 or Y\_i2 in MSGa or MSGb the protocol MUST abort.


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

##  Test vector for CPace using group NIST P-384 and hash SHA-384


###  Test vectors for calculate\_generator with group NIST P-384

~~~
  Inputs
    H   = SHA-384 with input block size 128 bytes.
    PRS = b'Password' ; ZPAD length: 87 ;
    DSI = b'CPaceP384_XMD:SHA-384_SSWU_NU_'
    DST = b'CPaceP384_XMD:SHA-384_SSWU_NU__DST'
    CI = b'\nAinitiator\nBresponder'
    CI = 0a41696e69746961746f720a42726573706f6e646572
    sid = 5b3773aa90e8f23c61563a4b645b276c
  Outputs
    generator_string(PRS,G.DSI,CI,sid,H.s_in_bytes):
    (length: 168 bytes)
      1e4350616365503338345f584d443a5348412d3338345f535357555f
      4e555f0850617373776f726457000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000160a41696e69746961746f72
      0a42726573706f6e646572105b3773aa90e8f23c61563a4b645b276c
    generator g: (length: 97 bytes)
      04f35a925fe82e54350e80b084a8013b1960cb3f73c49b0c2ae9b523
      997846ddd14c66f24f62223112cf35b866065f91ad86674cce2a2876
      84904e49f01287b54666bb518df2ea53cec627fa6e1283f14c6ed4bc
      d11b33fbb962da3e2e4ff1345c
~~~

###  Test vector for MSGa

~~~
  Inputs
    ADa = b'ADa'
    ya (big endian): (length: 48 bytes)
      7d5bc6a8959f9db2655b8b6642e393dc13d25150d69c6675fb3efd41
      ae6255bf54202b960f9aacd97fd6d2841b461f18
  Outputs
    Ya: (length: 97 bytes)
      048b65b9ef4c5726664391ceeae241834b275960a6f9316799f5c974
      eceb71dfb6d36e989addf2ae8c4e338f204b2cd754e1c43b43a12692
      8d8d81ce2e6edbc22a99ed478ad3487b87e1052bce2d94b6464a2228
      eab73c01f79d6b290af6b218cf
    Alternative correct value for Ya: g^(-ya):
    (length: 97 bytes)
      048b65b9ef4c5726664391ceeae241834b275960a6f9316799f5c974
      eceb71dfb6d36e989addf2ae8c4e338f204b2cd7541e3bc4bc5ed96d
      72727e31d191243dd56612b8752cb784781efad431d26b49b8b5ddd7
      1448c3fe086294d6f6094de730
    MSGa = lv_cat(Ya,ADa): (length: 102 bytes)
      61048b65b9ef4c5726664391ceeae241834b275960a6f9316799f5c9
      74eceb71dfb6d36e989addf2ae8c4e338f204b2cd754e1c43b43a126
      928d8d81ce2e6edbc22a99ed478ad3487b87e1052bce2d94b6464a22
      28eab73c01f79d6b290af6b218cf03414461
~~~

###  Test vector for MSGb

~~~
  Inputs
    ADb = b'ADb'
    yb (big endian): (length: 48 bytes)
      5cc9465bdb3ae626b77521ea36218fc93a9693c36ff126899e3d8777
      c126ef05483e34c05576c9e8c64b1a0b6f5b53d1
  Outputs
    Yb: (length: 97 bytes)
      04cb68451813699abda3dc0ed9d521baf9108bc2c4b2a1dbcd90a083
      63f5e458938d6fe634ed6393bc8440ec9b9f8a30841ffcc7cd65d9cf
      9617155e129bccded9888ac738f78e940f9887f9089ab6275d36c3ab
      1bccbd048b088b1b80a0f56f27
    Alternative correct value for Yb: g^(-yb):
    (length: 97 bytes)
      04cb68451813699abda3dc0ed9d521baf9108bc2c4b2a1dbcd90a083
      63f5e458938d6fe634ed6393bc8440ec9b9f8a3084e00338329a2630
      69e8eaa1ed64332126777538c708716bf0677806f76549d8a1c93c54
      e33342fb74f774e4805f0a90d8
    MSGb = lv_cat(Yb,ADb): (length: 102 bytes)
      6104cb68451813699abda3dc0ed9d521baf9108bc2c4b2a1dbcd90a0
      8363f5e458938d6fe634ed6393bc8440ec9b9f8a30841ffcc7cd65d9
      cf9617155e129bccded9888ac738f78e940f9887f9089ab6275d36c3
      ab1bccbd048b088b1b80a0f56f2703414462
~~~

###  Test vector for secret points K

~~~
    scalar_mult_vfy(ya,Yb): (length: 48 bytes)
      c862709d6bfe7cc02f0c11dafdbf4ef8db1c5e4cb13a22985a83bef1
      8631361ed7d8cd97b12931844b7ac61b2f31d332
    scalar_mult_vfy(yb,Ya): (length: 48 bytes)
      c862709d6bfe7cc02f0c11dafdbf4ef8db1c5e4cb13a22985a83bef1
      8631361ed7d8cd97b12931844b7ac61b2f31d332
~~~


###  Test vector for ISK calculation initiator/responder

~~~
    unordered cat of transcript : (length: 204 bytes)
      61048b65b9ef4c5726664391ceeae241834b275960a6f9316799f5c9
      74eceb71dfb6d36e989addf2ae8c4e338f204b2cd754e1c43b43a126
      928d8d81ce2e6edbc22a99ed478ad3487b87e1052bce2d94b6464a22
      28eab73c01f79d6b290af6b218cf034144616104cb68451813699abd
      a3dc0ed9d521baf9108bc2c4b2a1dbcd90a08363f5e458938d6fe634
      ed6393bc8440ec9b9f8a30841ffcc7cd65d9cf9617155e129bccded9
      888ac738f78e940f9887f9089ab6275d36c3ab1bccbd048b088b1b80
      a0f56f2703414462
    DSI = G.DSI_ISK, b'CPaceP384_XMD:SHA-384_SSWU_NU__ISK':
    (length: 34 bytes)
      4350616365503338345f584d443a5348412d3338345f535357555f4e
      555f5f49534b
    lv_cat(DSI,sid,K)||MSGa||MSGb: (length: 305 bytes)
      224350616365503338345f584d443a5348412d3338345f535357555f
      4e555f5f49534b105b3773aa90e8f23c61563a4b645b276c30c86270
      9d6bfe7cc02f0c11dafdbf4ef8db1c5e4cb13a22985a83bef1863136
      1ed7d8cd97b12931844b7ac61b2f31d33261048b65b9ef4c57266643
      91ceeae241834b275960a6f9316799f5c974eceb71dfb6d36e989add
      f2ae8c4e338f204b2cd754e1c43b43a126928d8d81ce2e6edbc22a99
      ed478ad3487b87e1052bce2d94b6464a2228eab73c01f79d6b290af6
      b218cf034144616104cb68451813699abda3dc0ed9d521baf9108bc2
      c4b2a1dbcd90a08363f5e458938d6fe634ed6393bc8440ec9b9f8a30
      841ffcc7cd65d9cf9617155e129bccded9888ac738f78e940f9887f9
      089ab6275d36c3ab1bccbd048b088b1b80a0f56f2703414462
    ISK result: (length: 48 bytes)
      db1e8133be8359b9aa8cd563043ee784344f26580876862e28b3f98b
      51b2f611a65362c1d77db66c879de466f5b6148a
~~~

###  Test vector for ISK calculation parallel execution

~~~
    ordered cat of transcript : (length: 204 bytes)
      6104cb68451813699abda3dc0ed9d521baf9108bc2c4b2a1dbcd90a0
      8363f5e458938d6fe634ed6393bc8440ec9b9f8a30841ffcc7cd65d9
      cf9617155e129bccded9888ac738f78e940f9887f9089ab6275d36c3
      ab1bccbd048b088b1b80a0f56f270341446261048b65b9ef4c572666
      4391ceeae241834b275960a6f9316799f5c974eceb71dfb6d36e989a
      ddf2ae8c4e338f204b2cd754e1c43b43a126928d8d81ce2e6edbc22a
      99ed478ad3487b87e1052bce2d94b6464a2228eab73c01f79d6b290a
      f6b218cf03414461
    DSI = G.DSI_ISK, b'CPaceP384_XMD:SHA-384_SSWU_NU__ISK':
    (length: 34 bytes)
      4350616365503338345f584d443a5348412d3338345f535357555f4e
      555f5f49534b
    lv_cat(DSI,sid,K)||oCAT(MSGa,MSGb): (length: 305 bytes)
      224350616365503338345f584d443a5348412d3338345f535357555f
      4e555f5f49534b105b3773aa90e8f23c61563a4b645b276c30c86270
      9d6bfe7cc02f0c11dafdbf4ef8db1c5e4cb13a22985a83bef1863136
      1ed7d8cd97b12931844b7ac61b2f31d3326104cb68451813699abda3
      dc0ed9d521baf9108bc2c4b2a1dbcd90a08363f5e458938d6fe634ed
      6393bc8440ec9b9f8a30841ffcc7cd65d9cf9617155e129bccded988
      8ac738f78e940f9887f9089ab6275d36c3ab1bccbd048b088b1b80a0
      f56f270341446261048b65b9ef4c5726664391ceeae241834b275960
      a6f9316799f5c974eceb71dfb6d36e989addf2ae8c4e338f204b2cd7
      54e1c43b43a126928d8d81ce2e6edbc22a99ed478ad3487b87e1052b
      ce2d94b6464a2228eab73c01f79d6b290af6b218cf03414461
    ISK result: (length: 48 bytes)
      519bfbb1477652e8ed1b4ec5774e310c4f44da46f3c36be91b0dd6b4
      e3a3245942cf4d9db8f79023dad6e1b57aed4891
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
 0x04,0xf3,0x5a,0x92,0x5f,0xe8,0x2e,0x54,0x35,0x0e,0x80,0xb0,
 0x84,0xa8,0x01,0x3b,0x19,0x60,0xcb,0x3f,0x73,0xc4,0x9b,0x0c,
 0x2a,0xe9,0xb5,0x23,0x99,0x78,0x46,0xdd,0xd1,0x4c,0x66,0xf2,
 0x4f,0x62,0x22,0x31,0x12,0xcf,0x35,0xb8,0x66,0x06,0x5f,0x91,
 0xad,0x86,0x67,0x4c,0xce,0x2a,0x28,0x76,0x84,0x90,0x4e,0x49,
 0xf0,0x12,0x87,0xb5,0x46,0x66,0xbb,0x51,0x8d,0xf2,0xea,0x53,
 0xce,0xc6,0x27,0xfa,0x6e,0x12,0x83,0xf1,0x4c,0x6e,0xd4,0xbc,
 0xd1,0x1b,0x33,0xfb,0xb9,0x62,0xda,0x3e,0x2e,0x4f,0xf1,0x34,
 0x5c,
};
const uint8_t tc_ya[] = {
 0x7d,0x5b,0xc6,0xa8,0x95,0x9f,0x9d,0xb2,0x65,0x5b,0x8b,0x66,
 0x42,0xe3,0x93,0xdc,0x13,0xd2,0x51,0x50,0xd6,0x9c,0x66,0x75,
 0xfb,0x3e,0xfd,0x41,0xae,0x62,0x55,0xbf,0x54,0x20,0x2b,0x96,
 0x0f,0x9a,0xac,0xd9,0x7f,0xd6,0xd2,0x84,0x1b,0x46,0x1f,0x18,
};
const uint8_t tc_ADa[] = {
 0x41,0x44,0x61,
};
const uint8_t tc_Ya[] = {
 0x04,0x8b,0x65,0xb9,0xef,0x4c,0x57,0x26,0x66,0x43,0x91,0xce,
 0xea,0xe2,0x41,0x83,0x4b,0x27,0x59,0x60,0xa6,0xf9,0x31,0x67,
 0x99,0xf5,0xc9,0x74,0xec,0xeb,0x71,0xdf,0xb6,0xd3,0x6e,0x98,
 0x9a,0xdd,0xf2,0xae,0x8c,0x4e,0x33,0x8f,0x20,0x4b,0x2c,0xd7,
 0x54,0xe1,0xc4,0x3b,0x43,0xa1,0x26,0x92,0x8d,0x8d,0x81,0xce,
 0x2e,0x6e,0xdb,0xc2,0x2a,0x99,0xed,0x47,0x8a,0xd3,0x48,0x7b,
 0x87,0xe1,0x05,0x2b,0xce,0x2d,0x94,0xb6,0x46,0x4a,0x22,0x28,
 0xea,0xb7,0x3c,0x01,0xf7,0x9d,0x6b,0x29,0x0a,0xf6,0xb2,0x18,
 0xcf,
};
const uint8_t tc_yb[] = {
 0x5c,0xc9,0x46,0x5b,0xdb,0x3a,0xe6,0x26,0xb7,0x75,0x21,0xea,
 0x36,0x21,0x8f,0xc9,0x3a,0x96,0x93,0xc3,0x6f,0xf1,0x26,0x89,
 0x9e,0x3d,0x87,0x77,0xc1,0x26,0xef,0x05,0x48,0x3e,0x34,0xc0,
 0x55,0x76,0xc9,0xe8,0xc6,0x4b,0x1a,0x0b,0x6f,0x5b,0x53,0xd1,
};
const uint8_t tc_ADb[] = {
 0x41,0x44,0x62,
};
const uint8_t tc_Yb[] = {
 0x04,0xcb,0x68,0x45,0x18,0x13,0x69,0x9a,0xbd,0xa3,0xdc,0x0e,
 0xd9,0xd5,0x21,0xba,0xf9,0x10,0x8b,0xc2,0xc4,0xb2,0xa1,0xdb,
 0xcd,0x90,0xa0,0x83,0x63,0xf5,0xe4,0x58,0x93,0x8d,0x6f,0xe6,
 0x34,0xed,0x63,0x93,0xbc,0x84,0x40,0xec,0x9b,0x9f,0x8a,0x30,
 0x84,0x1f,0xfc,0xc7,0xcd,0x65,0xd9,0xcf,0x96,0x17,0x15,0x5e,
 0x12,0x9b,0xcc,0xde,0xd9,0x88,0x8a,0xc7,0x38,0xf7,0x8e,0x94,
 0x0f,0x98,0x87,0xf9,0x08,0x9a,0xb6,0x27,0x5d,0x36,0xc3,0xab,
 0x1b,0xcc,0xbd,0x04,0x8b,0x08,0x8b,0x1b,0x80,0xa0,0xf5,0x6f,
 0x27,
};
const uint8_t tc_K[] = {
 0xc8,0x62,0x70,0x9d,0x6b,0xfe,0x7c,0xc0,0x2f,0x0c,0x11,0xda,
 0xfd,0xbf,0x4e,0xf8,0xdb,0x1c,0x5e,0x4c,0xb1,0x3a,0x22,0x98,
 0x5a,0x83,0xbe,0xf1,0x86,0x31,0x36,0x1e,0xd7,0xd8,0xcd,0x97,
 0xb1,0x29,0x31,0x84,0x4b,0x7a,0xc6,0x1b,0x2f,0x31,0xd3,0x32,
};
const uint8_t tc_ISK_IR[] = {
 0xdb,0x1e,0x81,0x33,0xbe,0x83,0x59,0xb9,0xaa,0x8c,0xd5,0x63,
 0x04,0x3e,0xe7,0x84,0x34,0x4f,0x26,0x58,0x08,0x76,0x86,0x2e,
 0x28,0xb3,0xf9,0x8b,0x51,0xb2,0xf6,0x11,0xa6,0x53,0x62,0xc1,
 0xd7,0x7d,0xb6,0x6c,0x87,0x9d,0xe4,0x66,0xf5,0xb6,0x14,0x8a,
};
const uint8_t tc_ISK_SY[] = {
 0x51,0x9b,0xfb,0xb1,0x47,0x76,0x52,0xe8,0xed,0x1b,0x4e,0xc5,
 0x77,0x4e,0x31,0x0c,0x4f,0x44,0xda,0x46,0xf3,0xc3,0x6b,0xe9,
 0x1b,0x0d,0xd6,0xb4,0xe3,0xa3,0x24,0x59,0x42,0xcf,0x4d,0x9d,
 0xb8,0xf7,0x90,0x23,0xda,0xd6,0xe1,0xb5,0x7a,0xed,0x48,0x91,
};
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

For these test cases scalar\_mult\_vfy(y,.) MUST return the representation of the neutral element G.I. When including Y\_i1 or Y\_i2 in MSGa or MSGb the protocol MUST abort.


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

##  Test vector for CPace using group NIST P-521 and hash SHA-512


###  Test vectors for calculate\_generator with group NIST P-521

~~~
  Inputs
    H   = SHA-512 with input block size 128 bytes.
    PRS = b'Password' ; ZPAD length: 87 ;
    DSI = b'CPaceP521_XMD:SHA-512_SSWU_NU_'
    DST = b'CPaceP521_XMD:SHA-512_SSWU_NU__DST'
    CI = b'\nAinitiator\nBresponder'
    CI = 0a41696e69746961746f720a42726573706f6e646572
    sid = 7e4b4791d6a8ef019b936c79fb7f2c57
  Outputs
    generator_string(PRS,G.DSI,CI,sid,H.s_in_bytes):
    (length: 168 bytes)
      1e4350616365503532315f584d443a5348412d3531325f535357555f
      4e555f0850617373776f726457000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000160a41696e69746961746f72
      0a42726573706f6e646572107e4b4791d6a8ef019b936c79fb7f2c57
    generator g: (length: 133 bytes)
      0400dc927958f0b69ccad8fb67ef008905354b58c7c9c92ad50060a9
      e6afb10437d6ca8a26164e8573702b897275a25d05ed4407af2a3849
      86dca7e243b92c5dd500d40057012121a9c8e34373fa619f918f7d47
      9c23f85f0485379ef0f05284398de26653b49a155324c9d7b138be84
      d0b49bb58e232b7bf697798de6ee8afd6b92b6fa2f
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
      04003701ec35caafa3dd416cad29ba1774551f9d2ed89f7e1065706d
      ca230b86a11d02e4cee8b3fde64380d4a05983167d8a2414bc594ad5
      286c068792ab7ca60ff6ea00919c41c00e789dabc2f42fd94178d7bf
      d8fbe1aff1c1854b3dafb3a0ea13f5a5fc1703860f022bd271740469
      bb322b07c179c7c225499b31727c0ea3ee65578634
    Alternative correct value for Ya: g^(-ya):
    (length: 133 bytes)
      04003701ec35caafa3dd416cad29ba1774551f9d2ed89f7e1065706d
      ca230b86a11d02e4cee8b3fde64380d4a05983167d8a2414bc594ad5
      286c068792ab7ca60ff6ea016e63be3ff18762543d0bd026be872840
      27041e500e3e7ab4c2504c5f15ec0a5a03e8fc79f0fdd42d8e8bfb96
      44cdd4f83e86383ddab664ce8d83f15c119aa879cb
    MSGa = lv_cat(Ya,ADa): (length: 139 bytes)
      850104003701ec35caafa3dd416cad29ba1774551f9d2ed89f7e1065
      706dca230b86a11d02e4cee8b3fde64380d4a05983167d8a2414bc59
      4ad5286c068792ab7ca60ff6ea00919c41c00e789dabc2f42fd94178
      d7bfd8fbe1aff1c1854b3dafb3a0ea13f5a5fc1703860f022bd27174
      0469bb322b07c179c7c225499b31727c0ea3ee6557863403414461
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
      0400f5cb68bf0117bd1a65412a2bc800af92013f9969cf546e1ea6d3
      bcf08643fdc482130aec1eecc33a2b5f33600be51295047fa3399fa2
      82cc1a78de91f3a4e30b5d01a085b453f22bf3dc947386b042e5fc4e
      c691fee47fe3c3ec6408c22a17c26bc0ab73940910614d6fcee32daf
      bfd2d340d6e382d71b1fc763d7cec502fbcbcf93b4
    Alternative correct value for Yb: g^(-yb):
    (length: 133 bytes)
      0400f5cb68bf0117bd1a65412a2bc800af92013f9969cf546e1ea6d3
      bcf08643fdc482130aec1eecc33a2b5f33600be51295047fa3399fa2
      82cc1a78de91f3a4e30b5d005f7a4bac0dd40c236b8c794fbd1a03b1
      396e011b801c3c139bf73dd5e83d943f548c6bf6ef9eb290311cd250
      402d2cbf291c7d28e4e0389c28313afd0434306c4b
    MSGb = lv_cat(Yb,ADb): (length: 139 bytes)
      85010400f5cb68bf0117bd1a65412a2bc800af92013f9969cf546e1e
      a6d3bcf08643fdc482130aec1eecc33a2b5f33600be51295047fa339
      9fa282cc1a78de91f3a4e30b5d01a085b453f22bf3dc947386b042e5
      fc4ec691fee47fe3c3ec6408c22a17c26bc0ab73940910614d6fcee3
      2dafbfd2d340d6e382d71b1fc763d7cec502fbcbcf93b403414462
~~~

###  Test vector for secret points K

~~~
    scalar_mult_vfy(ya,Yb): (length: 66 bytes)
      00503e75e38e012a6dc6f3561980e4cf540dbcff3de3a4a6f09d79c3
      2cc45764d3a6605eb45df1dc63fb7937b7879f2820da1b3266b69fa0
      99bf8720dd8f6a07e8ed
    scalar_mult_vfy(yb,Ya): (length: 66 bytes)
      00503e75e38e012a6dc6f3561980e4cf540dbcff3de3a4a6f09d79c3
      2cc45764d3a6605eb45df1dc63fb7937b7879f2820da1b3266b69fa0
      99bf8720dd8f6a07e8ed
~~~


###  Test vector for ISK calculation initiator/responder

~~~
    unordered cat of transcript : (length: 278 bytes)
      850104003701ec35caafa3dd416cad29ba1774551f9d2ed89f7e1065
      706dca230b86a11d02e4cee8b3fde64380d4a05983167d8a2414bc59
      4ad5286c068792ab7ca60ff6ea00919c41c00e789dabc2f42fd94178
      d7bfd8fbe1aff1c1854b3dafb3a0ea13f5a5fc1703860f022bd27174
      0469bb322b07c179c7c225499b31727c0ea3ee655786340341446185
      010400f5cb68bf0117bd1a65412a2bc800af92013f9969cf546e1ea6
      d3bcf08643fdc482130aec1eecc33a2b5f33600be51295047fa3399f
      a282cc1a78de91f3a4e30b5d01a085b453f22bf3dc947386b042e5fc
      4ec691fee47fe3c3ec6408c22a17c26bc0ab73940910614d6fcee32d
      afbfd2d340d6e382d71b1fc763d7cec502fbcbcf93b403414462
    DSI = G.DSI_ISK, b'CPaceP521_XMD:SHA-512_SSWU_NU__ISK':
    (length: 34 bytes)
      4350616365503532315f584d443a5348412d3531325f535357555f4e
      555f5f49534b
    lv_cat(DSI,sid,K)||MSGa||MSGb: (length: 397 bytes)
      224350616365503532315f584d443a5348412d3531325f535357555f
      4e555f5f49534b107e4b4791d6a8ef019b936c79fb7f2c574200503e
      75e38e012a6dc6f3561980e4cf540dbcff3de3a4a6f09d79c32cc457
      64d3a6605eb45df1dc63fb7937b7879f2820da1b3266b69fa099bf87
      20dd8f6a07e8ed850104003701ec35caafa3dd416cad29ba1774551f
      9d2ed89f7e1065706dca230b86a11d02e4cee8b3fde64380d4a05983
      167d8a2414bc594ad5286c068792ab7ca60ff6ea00919c41c00e789d
      abc2f42fd94178d7bfd8fbe1aff1c1854b3dafb3a0ea13f5a5fc1703
      860f022bd271740469bb322b07c179c7c225499b31727c0ea3ee6557
      86340341446185010400f5cb68bf0117bd1a65412a2bc800af92013f
      9969cf546e1ea6d3bcf08643fdc482130aec1eecc33a2b5f33600be5
      1295047fa3399fa282cc1a78de91f3a4e30b5d01a085b453f22bf3dc
      947386b042e5fc4ec691fee47fe3c3ec6408c22a17c26bc0ab739409
      10614d6fcee32dafbfd2d340d6e382d71b1fc763d7cec502fbcbcf93
      b403414462
    ISK result: (length: 64 bytes)
      ed208a15af3ef8a67a5cac4acb360d03154570e3b1b1c54867f53a72
      53cb919d13aa47efc647375be2250cb39ad965afa4ddfcb6be47d586
      d28c7eef6d654525
~~~

###  Test vector for ISK calculation parallel execution

~~~
    ordered cat of transcript : (length: 278 bytes)
      85010400f5cb68bf0117bd1a65412a2bc800af92013f9969cf546e1e
      a6d3bcf08643fdc482130aec1eecc33a2b5f33600be51295047fa339
      9fa282cc1a78de91f3a4e30b5d01a085b453f22bf3dc947386b042e5
      fc4ec691fee47fe3c3ec6408c22a17c26bc0ab73940910614d6fcee3
      2dafbfd2d340d6e382d71b1fc763d7cec502fbcbcf93b40341446285
      0104003701ec35caafa3dd416cad29ba1774551f9d2ed89f7e106570
      6dca230b86a11d02e4cee8b3fde64380d4a05983167d8a2414bc594a
      d5286c068792ab7ca60ff6ea00919c41c00e789dabc2f42fd94178d7
      bfd8fbe1aff1c1854b3dafb3a0ea13f5a5fc1703860f022bd2717404
      69bb322b07c179c7c225499b31727c0ea3ee6557863403414461
    DSI = G.DSI_ISK, b'CPaceP521_XMD:SHA-512_SSWU_NU__ISK':
    (length: 34 bytes)
      4350616365503532315f584d443a5348412d3531325f535357555f4e
      555f5f49534b
    lv_cat(DSI,sid,K)||oCAT(MSGa,MSGb): (length: 397 bytes)
      224350616365503532315f584d443a5348412d3531325f535357555f
      4e555f5f49534b107e4b4791d6a8ef019b936c79fb7f2c574200503e
      75e38e012a6dc6f3561980e4cf540dbcff3de3a4a6f09d79c32cc457
      64d3a6605eb45df1dc63fb7937b7879f2820da1b3266b69fa099bf87
      20dd8f6a07e8ed85010400f5cb68bf0117bd1a65412a2bc800af9201
      3f9969cf546e1ea6d3bcf08643fdc482130aec1eecc33a2b5f33600b
      e51295047fa3399fa282cc1a78de91f3a4e30b5d01a085b453f22bf3
      dc947386b042e5fc4ec691fee47fe3c3ec6408c22a17c26bc0ab7394
      0910614d6fcee32dafbfd2d340d6e382d71b1fc763d7cec502fbcbcf
      93b403414462850104003701ec35caafa3dd416cad29ba1774551f9d
      2ed89f7e1065706dca230b86a11d02e4cee8b3fde64380d4a0598316
      7d8a2414bc594ad5286c068792ab7ca60ff6ea00919c41c00e789dab
      c2f42fd94178d7bfd8fbe1aff1c1854b3dafb3a0ea13f5a5fc170386
      0f022bd271740469bb322b07c179c7c225499b31727c0ea3ee655786
      3403414461
    ISK result: (length: 64 bytes)
      aae7320b73ba2516f289f71088662d41c4314d00521c48ea3c9c85ea
      ca57112e55eb2b4094d4a0c7813ddd95c5d80c5596ad686d2eba876b
      a1cd92f90407aa3d
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
 0x04,0x00,0xdc,0x92,0x79,0x58,0xf0,0xb6,0x9c,0xca,0xd8,0xfb,
 0x67,0xef,0x00,0x89,0x05,0x35,0x4b,0x58,0xc7,0xc9,0xc9,0x2a,
 0xd5,0x00,0x60,0xa9,0xe6,0xaf,0xb1,0x04,0x37,0xd6,0xca,0x8a,
 0x26,0x16,0x4e,0x85,0x73,0x70,0x2b,0x89,0x72,0x75,0xa2,0x5d,
 0x05,0xed,0x44,0x07,0xaf,0x2a,0x38,0x49,0x86,0xdc,0xa7,0xe2,
 0x43,0xb9,0x2c,0x5d,0xd5,0x00,0xd4,0x00,0x57,0x01,0x21,0x21,
 0xa9,0xc8,0xe3,0x43,0x73,0xfa,0x61,0x9f,0x91,0x8f,0x7d,0x47,
 0x9c,0x23,0xf8,0x5f,0x04,0x85,0x37,0x9e,0xf0,0xf0,0x52,0x84,
 0x39,0x8d,0xe2,0x66,0x53,0xb4,0x9a,0x15,0x53,0x24,0xc9,0xd7,
 0xb1,0x38,0xbe,0x84,0xd0,0xb4,0x9b,0xb5,0x8e,0x23,0x2b,0x7b,
 0xf6,0x97,0x79,0x8d,0xe6,0xee,0x8a,0xfd,0x6b,0x92,0xb6,0xfa,
 0x2f,
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
 0x04,0x00,0x37,0x01,0xec,0x35,0xca,0xaf,0xa3,0xdd,0x41,0x6c,
 0xad,0x29,0xba,0x17,0x74,0x55,0x1f,0x9d,0x2e,0xd8,0x9f,0x7e,
 0x10,0x65,0x70,0x6d,0xca,0x23,0x0b,0x86,0xa1,0x1d,0x02,0xe4,
 0xce,0xe8,0xb3,0xfd,0xe6,0x43,0x80,0xd4,0xa0,0x59,0x83,0x16,
 0x7d,0x8a,0x24,0x14,0xbc,0x59,0x4a,0xd5,0x28,0x6c,0x06,0x87,
 0x92,0xab,0x7c,0xa6,0x0f,0xf6,0xea,0x00,0x91,0x9c,0x41,0xc0,
 0x0e,0x78,0x9d,0xab,0xc2,0xf4,0x2f,0xd9,0x41,0x78,0xd7,0xbf,
 0xd8,0xfb,0xe1,0xaf,0xf1,0xc1,0x85,0x4b,0x3d,0xaf,0xb3,0xa0,
 0xea,0x13,0xf5,0xa5,0xfc,0x17,0x03,0x86,0x0f,0x02,0x2b,0xd2,
 0x71,0x74,0x04,0x69,0xbb,0x32,0x2b,0x07,0xc1,0x79,0xc7,0xc2,
 0x25,0x49,0x9b,0x31,0x72,0x7c,0x0e,0xa3,0xee,0x65,0x57,0x86,
 0x34,
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
 0x04,0x00,0xf5,0xcb,0x68,0xbf,0x01,0x17,0xbd,0x1a,0x65,0x41,
 0x2a,0x2b,0xc8,0x00,0xaf,0x92,0x01,0x3f,0x99,0x69,0xcf,0x54,
 0x6e,0x1e,0xa6,0xd3,0xbc,0xf0,0x86,0x43,0xfd,0xc4,0x82,0x13,
 0x0a,0xec,0x1e,0xec,0xc3,0x3a,0x2b,0x5f,0x33,0x60,0x0b,0xe5,
 0x12,0x95,0x04,0x7f,0xa3,0x39,0x9f,0xa2,0x82,0xcc,0x1a,0x78,
 0xde,0x91,0xf3,0xa4,0xe3,0x0b,0x5d,0x01,0xa0,0x85,0xb4,0x53,
 0xf2,0x2b,0xf3,0xdc,0x94,0x73,0x86,0xb0,0x42,0xe5,0xfc,0x4e,
 0xc6,0x91,0xfe,0xe4,0x7f,0xe3,0xc3,0xec,0x64,0x08,0xc2,0x2a,
 0x17,0xc2,0x6b,0xc0,0xab,0x73,0x94,0x09,0x10,0x61,0x4d,0x6f,
 0xce,0xe3,0x2d,0xaf,0xbf,0xd2,0xd3,0x40,0xd6,0xe3,0x82,0xd7,
 0x1b,0x1f,0xc7,0x63,0xd7,0xce,0xc5,0x02,0xfb,0xcb,0xcf,0x93,
 0xb4,
};
const uint8_t tc_K[] = {
 0x00,0x50,0x3e,0x75,0xe3,0x8e,0x01,0x2a,0x6d,0xc6,0xf3,0x56,
 0x19,0x80,0xe4,0xcf,0x54,0x0d,0xbc,0xff,0x3d,0xe3,0xa4,0xa6,
 0xf0,0x9d,0x79,0xc3,0x2c,0xc4,0x57,0x64,0xd3,0xa6,0x60,0x5e,
 0xb4,0x5d,0xf1,0xdc,0x63,0xfb,0x79,0x37,0xb7,0x87,0x9f,0x28,
 0x20,0xda,0x1b,0x32,0x66,0xb6,0x9f,0xa0,0x99,0xbf,0x87,0x20,
 0xdd,0x8f,0x6a,0x07,0xe8,0xed,
};
const uint8_t tc_ISK_IR[] = {
 0xed,0x20,0x8a,0x15,0xaf,0x3e,0xf8,0xa6,0x7a,0x5c,0xac,0x4a,
 0xcb,0x36,0x0d,0x03,0x15,0x45,0x70,0xe3,0xb1,0xb1,0xc5,0x48,
 0x67,0xf5,0x3a,0x72,0x53,0xcb,0x91,0x9d,0x13,0xaa,0x47,0xef,
 0xc6,0x47,0x37,0x5b,0xe2,0x25,0x0c,0xb3,0x9a,0xd9,0x65,0xaf,
 0xa4,0xdd,0xfc,0xb6,0xbe,0x47,0xd5,0x86,0xd2,0x8c,0x7e,0xef,
 0x6d,0x65,0x45,0x25,
};
const uint8_t tc_ISK_SY[] = {
 0xaa,0xe7,0x32,0x0b,0x73,0xba,0x25,0x16,0xf2,0x89,0xf7,0x10,
 0x88,0x66,0x2d,0x41,0xc4,0x31,0x4d,0x00,0x52,0x1c,0x48,0xea,
 0x3c,0x9c,0x85,0xea,0xca,0x57,0x11,0x2e,0x55,0xeb,0x2b,0x40,
 0x94,0xd4,0xa0,0xc7,0x81,0x3d,0xdd,0x95,0xc5,0xd8,0x0c,0x55,
 0x96,0xad,0x68,0x6d,0x2e,0xba,0x87,0x6b,0xa1,0xcd,0x92,0xf9,
 0x04,0x07,0xaa,0x3d,
};
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

For these test cases scalar\_mult\_vfy(y,.) MUST return the representation of the neutral element G.I. When including Y\_i1 or Y\_i2 in MSGa or MSGb the protocol MUST abort.


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

