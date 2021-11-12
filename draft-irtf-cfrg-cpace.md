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

The CPace method was tailored for constrained devices and
specifically considers efficiency and hardware side-channel attack mitigations at the protocol level.
CPace is designed to be compatible with any group of both prime- and non-prime order by explicitly
handling the complexity of cofactor clearing on the protcol level. CPace
comes with both, game-based and simulation-based proofs where the latter provides composability guarantees.
As a protocol, CPace is designed
to be compatible with so-called "single-coordinate-only" Diffie-Hellman implementations on elliptic curve
groups.

CPace is designed to be suitable as both, a building block within a larger protocol construction using CPace as substep,
and as a standalone protocol.
Finally, the CPace protocol design aims at considering the constraints imposed by constrained secure-element chipsets.

# Requirements Notation

{::boilerplate bcp14}

# Definition CPace

## Setup

For CPace both communication partners need to agree on a common cipher suite which consists of choosing a common
hash function H and an elliptic curve environment G. With "environment" we denote a compilation of all of
an elliptic curve group with an associated Diffie-Hellman protocol and a mapping primitive.

Throughout this document we will be using an object-style notation such as X.constant_name and X.function_name(a)
for refering to constants and functions applying to G and H.

With H we denote a hash primitive with a hash function H.hash(m,l)
that operates on an input octet string m and returns a hash result containing the first l result octets
calculated by the primitive. Common choices for H are SHA512 {{?RFC6234}} or SHAKE256 {{FIPS202}}.
For considering both, variable-output-length primitives and fixed-length output primitives we use the following
notations and definitions which were chosen in line with the definitions in {?RFC6234}}

With H.b_in_bytes we denote the default output size in bytes corresponding to the symmetric
security level of the hash primitive. E.g. H.b_in_bytes = 64 for SHA512 and SHAKE256 and H.b_in_bytes = 32 for
SHA256 and SHAKE128. We use the notation H.hash(m) = H.hash(m, H.b_in_bytes) and let the hash primitive
output the default length if no length parameter is given.

With H.bmax_in_bytes we denote the maximum output size in octets supported by the hash primitive.

With H.s_in_bytes we denote the input block size used by H.
For instance, for SHA512 the input block size s_in_bytes is 128, while for SHAKE256 the
input block size amounts to 136 bytes.

For a given group G this document specifies how to define the following set of group-specific
functions and constants for the protocol execution. For making the implicit dependence of the respective
functions and constants on the group G transparent, we use an object-style notation
G.function_name() and G.constant_name.

With G.I we denote a unique octet string representation of the neutral element of the group G.

g = G.calculate_generator(H,PRS,CI,sid). With calculate_generator we denote a function that outputs a
representation of a group element in G which is derived from input octet strings PRS, CI, sid using
the hash function primitive H.

y = G.sample_scalar(). This function returns a representation of a scalar value appropriate as a
private Diffie-Hellman key for the group G.

Y = G.scalar_mult(y,g). This function takes a generator g as first parameter and a scalar y as second
parameter and returns an octet string representation of a group element Y.

K = G.scalar_mult_vfy(y,X). This function returns an octet string representation of a group element K which is
calculated from a scalar y and a group element X. Moreover scalar_mult_vfy implements validity verifications of the inputs
and returns the neutral element G.I if the validity check fails.

## Inputs

With PRS we denote a password-related octet string which is a MANDATORY input for all CPace instantiations.
Typically PRS is derived from a low-entropy secret such as a user-supplied password (pw) or a personal
identification number.

With CI we denote an OPTIONAL octet string for the channel identifier. CI can be used for
binding CPace to one specific communication channel, for which CI needs to be
available to both protocol partners upon protocol start.

With sid we denote an OPTIONAL octet string input containing a session id. In application scenarios
where a higher-level protocol has established a unique sid this parameter can be used to bind the CPace protocol execution
to one specific session.

With ADa and ADb we denote OPTIONAL octet strings of parties A and B that contain associated public data
of the communication partners.
ADa and ADb could for instance include party identifiers or a protocol version (e.g. for avoiding downgrade attacks).
In a setting with clear initiator and responder roles the information ADa sent by the initiator
can be helpful for the responder for identifying which among possibly several different passwords are to be used for
the given protocol session.

## Notation

With str1 \|\| str2 we denote concatenation of octet strings.

With oCAT(str1,str2) we denote ordered concatenation of octet strings such that oCAT(str1,str2) = str1 \|\| str2
if str2 > str1 and oCAT(str1,str2) = str2 \|\| str1 otherwise.

CONCAT(str1,str2) defines a concatenation function that depends on the application scenario.
In applications where CPace is used without clear initiator and responder roles, i.e. where the ordering of
messages is not enforced by the protocol flow, ordered concatenation SHALL BE used,
i.e. CONCAT(str1,str2) == oCAT(str1,str2).

In settings with defined initiator and responder roles
CONCAT(str1,str2) SHALL BE defined as unordered concatenation: CONCAT(str1,str2) == str1 \|\| str2.

With len(S) we denote the number of octets in a string S, and we let nil represent an empty octet string, i.e., len(nil) = 0.

With prepend_len(octet_string) we denote the octet sequence that is obtained from prepending
the length of the octet string as an utf-8 string to the byte sequence itself. This will prepend one
single octet for sequences shorter than 128 bytes and more octets otherwise.

With prefix_free_cat(a0,a1, ...) we denote a function that outputs the prefix-free encoding of
all input octet strings as the concatenation of the individual strings with their respective
length prepended: prepend_len(a0) \|\| prepend_len(a1) \|\| ... . Use of this function allows for
easy parsing of strings and guarantees a prefix-free encoding.

With sample_random_bytes(n) we denote a function that returns n octets uniformly sampled between 0 and 255.
With zero_bytes(n) we denote a function that returns n octets with value 0.

With ISK we denote the intermediate session key output string provided by CPace. It is RECOMMENDED to convert the
intermediate session key ISK to a final session key by using a suitable KDF function prior to using the key in a
higher-level protocol.

With G.DSI we denote domain-separation identifier strings specific for a given CPace cipher suite.

## Hashing of the password-related string in CPace

The different instantiations in CPace share the same method for combining all of PRS, CI, sid and a domain-separation string G.DSI
whithin a generator string.

With generator_string(PRS,DSI,CI,sid, H.s_in_bytes) we denote a function that returns the string
prefix_free_cat(PRS,zero_bytes(len_zpad), DSI, CI, sid) in which all input strings are concatenated.
The zero padding is designed such that the encoding of PRS together with the zero padding field completely fills the first
input block of the hash.

The length len_zpad of the zero padding is calculated as len_zpad = MAX(0, H.s_in_bytes - len(prepend_length(PRS)) - 1).



## Protocol Flow

CPace is a one round protocol.

In a setup phase (not depicted here) both sides agree on a common hash function H and a group
environment G.

Prior to invocation, A and B are provisioned with public (CI) and secret
information (PRS) as prerequisite for running the protocol.

A sends a message MSGa to B. A contains the public share Ya
and OPTIONAL associated data ADa.

Similarly B sends MSGb to A containing its public share Yb and OPTIONAL associated data ADb.

CPace does allow for the initiator/responder setting where party A starts and party B replies.
CPace does also allow for the symmetric setting where no clear ordering of MSGa and MSGb is enforced.

Both A and B then derive a shared intermediate session key ISK. The notation "intermediate"
and "ISK" was chosen in order to stress that it is RECOMMENDED to use an additional
strong key-derivation function outside of the scope of CPace for the keys used in a higher-level
protocol (see security consideration section for details).

When starting the protocol, A and B dispose of a sid string which can also be the emtpy string nil.
I.e. use of the sid string is OPTIONAL.
Preferably, sid will be pre-established by a higher-level protocol invoking CPace.
In a setting with clear initiator and responder roles where no such sid is available from a higher-level
protocol, a suitable approach for defining the session id is to let A choose a fresh random sid
string and send it to B together with the first message. This method is shown in the
setup protocol section below prior to the actual protocol flow.

In the following, we describe the protocol using the example of an initiator/responder instantiation
of CPace where party A starts with the protocol flow.

~~~
              A                  B
              | (setup protocol  |
(sample sid)  |     and sid)     |
              |----------------->|
    ---------------------------------------
              |                  |
(compute Ya)  |      Ya, ADa     |
              |----------------->|
              |      Yb, ADb     | (compute Yb)
              |<-----------------|
              |   (verify data)  |
(derive ISK)  |                  | (derive ISK)
~~~

## CPace

To begin, A calculates a generator g = G.calculate_generator(H, PRS,CI,sid).

A samples ya = G.sample_scalar() randomly according to the specification for group G.
A then calculates Ya= G.scalar_mult (ya,g). A then transmits MSGa = prefix_free_cat(Ya, ADa) with
Ya and the optional associated data ADa to B. Note that prefixing the transmitted components with their
respective lengths allows for unambigous parsing of MSGa by the receiver and guarantees a
prefix-free encoding.

B picks yb = G.sample_scalar() randomly. B then calculates
g = G.calculate_generator(H, PRS,CI,sid) and
Yb = G.scalar_mult(yb,g). B then calculates K = G.scalar_mult_vfy(yb,Ya).
B MUST abort if K is the encoding of the neutral element G.I.
Otherwise B sends MSGb = prefix_free_cat(Yb, ADb) to A and proceeds as follows.

B returns ISK = H.hash(prefix_free_cat(G.DSI \|\| "ISK", sid, K, CONCAT(MSGa, MSGb))).

Upon reception of Yb, A calculates K = scalar_mult_vfy(Yb,ya). A MUST abort if K is the neutral element I.
If K is different from G.I, A returns ISK = H.hash(prefix_free_cat(G.DSI \|\| "ISK", sid, K, CONCAT(MSGa, MSGb))).

Upon completion of this protocol, the session key ISK returned by A and B will be identical by both
parties if and only if the supplied input parameters sid, PRS and CI match on both sides and the
transcripts match.

In application scenarios which are guaranteed to enforce clear initiator and responder roles
unordered concatenation SHOULD BE used for the CONCAT(MSGa,MSGb) function. In applications
without enforced ordering of the transmission of MSGa and MSGb,
CONCAT() MUST BE implemented by using the ordered concatenation function oCAT().

# Ciphersuites

This section documents CPACE ciphersuite configurations. A ciphersuite
is REQUIRED to specify,
- a group G with associated definitions for G.sample_scalar(), G.scalar_mult() and G. scalar_mult_vfy() and G.calculate_generator() functions and an associated domain separation string G.DSI.
- a hash function H.

Currently, test vectors are available for the cipher suites
CPACE-X25519-SHA512,
CPACE-X448-SHAKE256,
CPACE-P256_XMD:SHA-256_SSWU_NU_-SHA256,
CPACE-RISTR255-SHA512,
CPACE-DECAF448-SHAKE256.

# CPace on single-coordinate Ladders on Montgomery curves {#cpace_montgomery}

In this section we consider the case of CPace using the X25519 and X448 Diffie-Hellman functions
from {{?RFC7748}} operating on the Montgomery curves Curve25519 and Curve448 {{?RFC7748}}.

CPace implementations using single-coordinate ladders on further Montgomery curves SHALL use the definitions in line
with the specifications for X25519 and X448 and review the guidance given in the security consideration section {{sec-considerations}} and
{{CPacePaper}}.

For X25519 the following definitions apply:

- G.field_size_bytes = 32

- G.field_size_bits = 255

- G.sample_scalar() = sample_random_bytes(G.field_size_bytes)

- G.scalar_mult(y,g) = G.scalar_mult_vfy(y,g) = X25519(y,g)

- G.I = zero_bytes(G.field_size_bytes)

- G.DSI = "CPace255"

For X448 the following definitions apply:

- G.field_size_bytes = 56

- G.field_size_bits = 448

- G.sample_scalar() = sample_random_bytes(G.field_size_bytes)

- G.scalar_mult(y,g) = G.scalar_mult_vfy(y,g) = X448(y,g)

- G.I = zero_bytes(G.field_size_bytes)

- G.DSI = "CPace448"

The G.calculate_generator(H, PRS,sid,CI) function shall be implemented as follows.

- First gen_str = generator_string(PRS,G.DSI,CI,sid, H.s_in_bytes) is calculated using the input block size of the
  chosen hash primitive.

- This string is then hashed to the required length
  gen_str_hash = H.hash(gen_str, G.field_size_bytes).
  Note that this implies that the permissible output length H.maxb_in_bytes MUST BE larger or equal to the
  field size of the group G for making a hashing primitive suitable.

- This result is then considered as a field coordinate using
  the u = decodeUCoordinate(gen_str_hash, G.field_size_bits) function from {{!RFC7748}} which we
  repeat in the appendix for convenience.

- The result point g is then calculated as (g,v) = map_to_curve_elligator2(u) using the function
  from {{!I-D.irtf-cfrg-hash-to-curve}}. Note that the v coordinate produced by the map_to_curve_elligator2 function
  is not required for CPace and discarded.

In the appendix we show sage code that can be used as reference implementation for the calculate_generator and
key generation functions.

The definitions above aim at making the protocol suitable for outsourcing CPace to
secure elements (SE) where nested hash function constructions such as defined in {{?RFC5869}}
have to be considered to be particularly costly. Moreover as all hash operations are executed using strings
with a prefix-free encoding also Merkle-Damgard constructions such as the SHA2 family can be considered as
a representation of a random oracle, given that the permutation function is considered as a random oracle.

Finally, with the introduction of a zero-padding within the generator string gen_str (introduced after the PRS string),
the CPace design aims at mitigating
attacks of a side-channel adversary that analyzes correlations between publicly known variable
information with the low-entropy PRS string.

# CPace on prime-order group abstractions

In this section we consider the case of CPace using the ristretto25519 and decaf448 group abstractions.
These abstractions define an encode and decode function, group exponentiation
and a one-way-map. With the group abstractions there is a distinction between an internal represenation
of group elements and an external encoding of the same group element. In order to distinguish between these
different representations, we prepend an underscore before values using the internal representation within this
section.

For ristretto255 the following definitions apply:

- G.DSI = "CPaceRistretto"

- G.field_size_bytes = 32

- G.group_size_bits = 252

- G.group_order = 2^252 + 27742317777372353535851937790883648493

For decaf448 the following definitions apply:

- G.DSI = "CPaceDecaf"

- G.field_size_bytes = 56

- G.group_size_bits = 445

- G.group_order = l = 2^446 -
    13818066809895115352007386748515426880336692474882178609894547503885

For both abstractions the following definitions apply:

- It is RECOMMENDED to implement G.sample_scalar() as follows. First set scalar = sample_random_bytes(G.group_size_bytes). Then clear the most significant bits larger than group_size_bits,  interpret the result as an integer value and return the result. Alternatively, it is also acceptable to use uniform sampling between 1 and (G.group_order - 1).

- G.scalar_mult(y,_g) operates on a scalar y and a group element _g in the internal representation of the group abstraction environment. It returns the value Y = encode(_g^y), i.e. a value using the public encoding.

- G.I = is the public encoding representation of the identity element.

- G.scalar_mult_vfy(y,X) operates on a value using the public encoding and a scalar and is implemented as follows. If the decode(X) function fails, it returns G.I. Otherwise it returns encode( decode(X)^y ).

Note that with these definitions the scalar_mult function operates on a decoded point _g and returns an encoded point,
while the scalar_mult_vfy(y,X) function operates on a scalar and an encoded point X.

The G.calculate_generator(H, PRS,sid,CI) function shall return a decoded point and be implemented as follows.

- First gen_str = generator_string(PRS,G.DSI,CI,sid, H.s_in_bytes) is calculated using the input block size of the chosen hash primitive.

- This string is then hashed to the required length gen_str_hash = H.hash(gen_str, 2 * G.field_size_bytes).  Note that this implies that the permissible output length H.maxb_in_bytes MUST BE larger or equal to twice the field size of the group G for making a hashing primitive suitable. Finally the internal representation of the generator _g is calculated as _g = one_way_map(gen_str_hash) using the one-way map function from the abstraction.

# CPace on curves in Short-Weierstrass representation {#weierstrass}
In this section we target ecosystems using elliptic-curve representations in Short-Weierstrass form as discussed, e.g. in
{{IEEE1363}}. A typical
representative might be the curve NIST-P256. In the procedures specified in this section we follow
existing encoding practices, e.g. {{SEC1}}, curve
standards, e.g. {{SEC2}} {{?RFC5639}} and deployment in current TLS standards closely. We do soe, even if this results
in some efficency loss, e.g. by using full-coordinate representation of field elements instead of compressed encodings.

For the procedures described in this section any suitable group MUST BE of prime order.

Here, any elliptic curve in Short-Weierstrass form is characterized by

- An integer constant G.group_order which MUST BE a prime.

- A verification function G.is_in_group(X) which returns true if the input X is a valid octet stream according to {{SEC1}} of a point on the group using full (x,y) coordinates.

- G.I is an octet string encoding of the field element x according to {{SEC1}} which encodes the x-coordinate of the
neutral element of the group.
.

- G.encode_to_curve(str) is a mapping function defined in {{!I-D.irtf-cfrg-hash-to-curve}} that maps string str to a point on the group. {{!I-D.irtf-cfrg-hash-to-curve}} provides both, uniform and non-uniform mappings based on several different strategies. It is RECOMMENDED to use the nonuniform variant of the SSWU mapping primitive within {{!I-D.irtf-cfrg-hash-to-curve}}.

- A string G.DSI which shall be defined by the concatenation of "CPace" and the cipher suite used for the encode_to_curve function from {{!I-D.irtf-cfrg-hash-to-curve}}.

Here the following definition of the CPace functions applies.

- Here G.sample_scalar() is a function that samples a value between 1 and (G.group_order - 1)  which MUST BE uniformly random. It is RECOMMENDED to use rejection sampling for converting a uniform bitstring to a   uniform value between 1 and (G.group_order - 1).

- G.scalar_mult(s,X) is a function that operates on a scalar s and an input point X encoded in full coordinates according to {{SEC1}}. It also returns a full-coordinate output (i.e. both, x and y coordinates of the point in Short-Weierstrass form).

- G.scalar_mult_vfy(s,X) operates on the representation of a scalar s and a full-coordinate point X. It MUST BE implemented as follows. if G.is_in_group(X) is false, G.scalar_mult_vfy(s,X) MUST return G.I . Otherwise G.scalar_mult_vfy(s,X) MUST returns an octet string encoding of the x-coordinate of X^s according to {{SEC1}}.

For the Short-Weierstrass use-case the G.calculate_generator(H, PRS,sid,CI) function SHALL be implemented as follows.

- First gen_str = generator_string(PRS,G.DSI,CI,sid, H.s_in_bytes) is calculated using the input block size of the chosen hash primitive.

- Then the output of a call to G.encode_to_curve(gen_str) is returned.

# Security Considerations {#sec-considerations}

A security proof of CPace is found in {{CPacePaper}}.

## Security considerations for sampling scalars
In {{CPacePaper}} also the effect of slightly non-uniform sampling of scalars is considered for groups where the group order is close to a power of two,
which is the case for Curve25519 and Curve448. For these curves we recommend to sample scalars slightly non-uniformly as binary strings as any arithmetic
operation on secret scalars such as reduction may increase the attack surface when facing an adversary exploiting side-channel leakage.
OPTIONALLY also the conventional strategy of uniform sampling of scalars is suitable.


## Security considerations regarding hashing and key derivation

In order to prevent analysis of length-extension attacks on hash functions, all hash input strings in CPace are designed to be prefix-free strings with
prepended length information prior to any data field. This choice was made in order to make CPace suitable for hash function instantiations using
Merkle-Damgard constructions such as SHA2 or SHA512 along the lines of {{CDMP05}}. This is guaranteed by the design of the prefix_free_cat() function.

Although already K is a shared value, still it MUST NOT be used as a shared secret key. Leakage of K to an adversary may lead to offline-dictionary attacks.
Note that calculation of ISK from K includes the protocol transcript and
prevents key malleability with respect to man-in-the-middle attacks from active adversaries.

CPace does not by itself include a strong key derivation function construction.
Instead CPace uses a simple hash operation on a prefix-free string input for generating its
intermediate key ISK.
This was done for maintaining compatibility with constrained hardware such as secure element chipsets.

It is RECOMMENDED that the ISK is post-processed by a KDF such as {{?RFC5869}}
according the needs of the higher-level protocol.

## Security considerations for single-coordinate CPace on Montgomery curves

The definitions given for the case of the Montgomery curves Curve25519 and Curve448 in {{cpace_montgomery}} rely on the following properties  {{CPacePaper}}:

- The curve has order (p * c) with p prime and c a small cofactor. Also the curve's quadratic twist must be of order (p' * c') with p' prime and c' a cofactor.

- The cofactor c' of the twist MUST BE EQUAL to or an integer multiple of the cofactor c of the curve.

- Both field order q and group order p MUST BE close to a power of two along the lines of {{CPacePaper}}, Appendix E.

- The representation of the neutral element G.I MUST BE the same for both, the curve and its twist.

- The implementation of G.scalar_mult_vfy(y,c) MUST map all c low-orer points on the curve and all c' low-order points on the twist  on the representation of the identity element G.I.

All of the above properties MUST hold for any further single-coordinate Montgomery curve implemented according the specifications given in the section handling X25519 and X448 {{cpace_montgomery}}.

The Curve25519-based cipher suite employs the twist security feature of the curve for point validation.
As such, it is MANDATORY to check that any actual X448 and X25519 function implementation maps
all low-order points on both the curve and the twist on the neutral element.
Corresponding test vectors are provided in the appendix.

## Security considerations for CPace on idealized group abstractions

The procedures from the section dealing with the case of idealized group abstractions
rely on the property that both, field order q and group order p MUST BE close to a power of two.
For a detailed discussion see {{CPacePaper}}, Appendix E.

Elements received from a peer MUST be checked by a proper implementation of the scalar_mult_vfy methods.
Failure to properly validate group elements can lead to trivial attacks.


## Nonce values

Secret scalars ya and yb MUST NOT be reused. Values for sid SHOULD NOT be reused as the composability
guarantees of the simulation-based proof rely on uniqueness of session ids {{CPacePaper}}.

If CPace is used as a building block of higher-level protocols, it is RECOMMENDED that sid
is generated by the higher-level protocol and passed to CPace. One suitable option is that sid
is generated by concatenating ephemeral random strings from both parties.


## Application frameworks

CPace was not originally meant to be used in conjunction with servers supporting several users and, thus
several different username/password pairs. As such it does not provide mechanisms for agreeing on salt values which are required
for iterated password-hashing functions which should be used for storing credentials (see e.g. the discussion in {{AUCPacePaper}} where
CPace has been used as building block within the augmented AuCPace protocol {{AUCPacePaper}}).

In a setting of a server with several distinct users it is RECOMMENDED to seriously
consider the augmented PAKE protocol OPAQUE {{?I-D.draft-irtf-cfrg-opaque}} instead.

## Side channel and quantum computing considerations

In case that side-channel attacks are to be considered practical for a given application, it is RECOMMENDED to focus
side-channel protections such as masking and redundant execution (faults) on the process of calculating
the secret generator G.calculate_generator(PRS,CI,sid).
The most critical aspect to consider is the processing of the first block of the hash that includes
the PRS string. The CPace protocol construction considers the fact that side-channel protections of hash functions might
be particularly resource hungry. For this reason, CPace aims at minimizing the number
of hash functions invocations in the
specified calculate_generator function.

While the zero-padding introduced when hashing the sensitive PRS string can be expected to make
the task for a side-channel adversary significantly more complex, this feature allone is not sufficient
for ruling out power analysis attacks.

CPace is proven secure under the hardness of the computational Simultaneous Diffie-Hellmann (SDH)
assumption in the group G (as defined in {{CPacePaper}}).
This assumption is not expected to hold in the event that large-scale quantum computers (LSQC) will become available.
Still here CPace forces an active adversary to solve one computational Diffie-Hellman problem per password guess {{CPacePaper2}}.
In this sense, using the wording suggested by Steve Thomas on the CFRG mailing list,
CPace is "quantum-annoying".

# IANA Considerations

No IANA action is required.

# Acknowledgements

Thanks to the members of the CFRG for comments and advice. Any comment and advice is appreciated.

Comments are specifically invited regarding the inclusion or exclusion of both,
initiator/responder and symmetric settings. Currently we plan to consider both application
settings in this draft.

--- back

# Sage definitions for the CPace functions

## Sage definitions for string utility functions
TBD.

## Sage definitions for hash primitives
TBD.

## Sage definitions for single-coordinate CPace on Montgomery curves
TBD.

## Sage definitions for group abstractions
TBD.

## Sage definitions for Short-Weierstrass
TBD.


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
  prepend_length_to_bytes(bytes(range(127))): (length: 128 bytes)
    7f000102030405060708090a0b0c0d0e0f101112131415161718191a1b
    1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738
    393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f505152535455
    565758595a5b5c5d5e5f606162636465666768696a6b6c6d6e6f707172
    737475767778797a7b7c7d7e
  prepend_length_to_bytes(bytes(range(128))): (length: 130 bytes)
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
  prefix_free_cat(b"1234",b"5",b"",b"6789"): (length: 13 bytes)
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
# Test vectors

## Test vectors for X25519 low order points

Points that need to return neutral element when input to
plain X25519 that also accept un-normalized inputs with
bit #255 set in the input point encoding.

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

Results for X25519 implementations not clearing bit #255:
(i.e. with X25519 not implemented according to RFC7748!):
s = af46e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449aff
rN = X25519(s,uX);
r0: 0000000000000000000000000000000000000000000000000000000000000000
r1: 0000000000000000000000000000000000000000000000000000000000000000
r2: 0000000000000000000000000000000000000000000000000000000000000000
r3: 0000000000000000000000000000000000000000000000000000000000000000
r4: 0000000000000000000000000000000000000000000000000000000000000000
r5: 0000000000000000000000000000000000000000000000000000000000000000
r6: 0000000000000000000000000000000000000000000000000000000000000000
r7: 0000000000000000000000000000000000000000000000000000000000000000
r8: 0000000000000000000000000000000000000000000000000000000000000000
r9: 0000000000000000000000000000000000000000000000000000000000000000
ra: 0000000000000000000000000000000000000000000000000000000000000000
rb: 0000000000000000000000000000000000000000000000000000000000000000

Results for X25519 implementations that clear bit #255:
(i.e. implemented according to RFC7748!):
s = af46e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449aff
qN = X25519(s, uX & ((1 << 255) - 1));
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

##  Test vector for CPace using group X25519 and hash SHA-512


###  Test vectors for calculate_generator with group X25519

~~~
  Inputs
    H   = SHA-512 with input block size 128 bytes.
    PRS = b'password' ; ZPAD length: 118 ; DSI = b'CPace255'
    CI = b'\nAinitiator\nBresponder'
    CI = 0a41696e69746961746f720a42726573706f6e646572
    sid = 7e4b4791d6a8ef019b936c79fb7f2c57
  Outputs
    hash generator string: (length: 32 bytes)
      5cb423cc3a5a9355bb90fceb67c97a7b5787df93faf4562789d705e3
      b2848d86
    after decoding to coordinate: (length: 32 bytes)
      5cb423cc3a5a9355bb90fceb67c97a7b5787df93faf4562789d705e3
      b2848d06
    generator g: (length: 32 bytes)
      2cddcc94b38d059a7b305bb0b8934b5b1ed45c5a5cb039f9cd00ab11
      ce92730d
~~~

###  Test vector for MSGa

~~~
  Inputs
    ADa = b'ADa'
    ya (little endian): (length: 32 bytes)
      232527dee2cfde76fb425b6d88818630eea7ea263fac28d89f52d096
      c563b1e6
  Outputs
    Ya: (length: 32 bytes)
      5448fd9633734e703210b61d5cabb1310a28382895d56d490551436a
      b3398644
    MSGa: (length: 37 bytes)
      205448fd9633734e703210b61d5cabb1310a28382895d56d49055143
      6ab339864403414461
~~~

###  Test vector for MSGb

~~~
  Inputs
    ADb = b'ADb'
    yb (little endian): (length: 32 bytes)
      871ebb1d5ecbeffa5a47e32c40d2da6894d9f2865efdad6ad8535a1b
      e7e487d6
  Outputs
    Yb: (length: 32 bytes)
      d8fe025158c0c08d7ea93a84718a56111bff54bf4b960c8343e64f02
      5eead608
    MSGb: (length: 37 bytes)
      20d8fe025158c0c08d7ea93a84718a56111bff54bf4b960c8343e64f
      025eead60803414462
~~~

###  Test vector for secret points K

~~~
    scalar_mult_vfy(ya,Yb): (length: 32 bytes)
      4aa59ccfda03691c3e9cf4dab329a13bcc9707e38f54e784e30f7843
      78dbcb49
    scalar_mult_vfy(yb,Ya): (length: 32 bytes)
      4aa59ccfda03691c3e9cf4dab329a13bcc9707e38f54e784e30f7843
      78dbcb49
~~~


###  Test vector for ISK calculation initiator/responder

~~~
    unordered cat of transcript : (length: 74 bytes)
      205448fd9633734e703210b61d5cabb1310a28382895d56d49055143
      6ab33986440341446120d8fe025158c0c08d7ea93a84718a56111bff
      54bf4b960c8343e64f025eead60803414462
    input to final ISK hash: (length: 137 bytes)
      0c43506163653235355f49534b107e4b4791d6a8ef019b936c79fb7f
      2c57204aa59ccfda03691c3e9cf4dab329a13bcc9707e38f54e784e3
      0f784378dbcb49205448fd9633734e703210b61d5cabb1310a283828
      95d56d490551436ab33986440341446120d8fe025158c0c08d7ea93a
      84718a56111bff54bf4b960c8343e64f025eead60803414462
    ISK result: (length: 64 bytes)
      eeaebbac8a5a057cf94c3e8dba6cf0edddb953357532d0028e3e0cd4
      a85ce7a4b42511d5fb06c60f3b0775c357f267ccc9e24b81338231b9
      a61855fcebd4a026
~~~

###  Test vector for ISK calculation parallel execution

~~~
    ordered cat of transcript : (length: 74 bytes)
      20d8fe025158c0c08d7ea93a84718a56111bff54bf4b960c8343e64f
      025eead60803414462205448fd9633734e703210b61d5cabb1310a28
      382895d56d490551436ab339864403414461
    input to final ISK hash: (length: 137 bytes)
      0c43506163653235355f49534b107e4b4791d6a8ef019b936c79fb7f
      2c57204aa59ccfda03691c3e9cf4dab329a13bcc9707e38f54e784e3
      0f784378dbcb4920d8fe025158c0c08d7ea93a84718a56111bff54bf
      4b960c8343e64f025eead60803414462205448fd9633734e703210b6
      1d5cabb1310a28382895d56d490551436ab339864403414461
    ISK result: (length: 64 bytes)
      170a1df42f03da082b9d250be646be04c8c6b4490af17b27c4a0916f
      e8482289d10ea0534455ab578deb88dae75db4a8bf24fb111825e630
      2ad3c0d903341f83
~~~

###  Corresponding ANSI-C initializers

~~~
const uint8_t tc_PRS[] = {
 0x70,0x61,0x73,0x73,0x77,0x6f,0x72,0x64,
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
 0x2c,0xdd,0xcc,0x94,0xb3,0x8d,0x05,0x9a,0x7b,0x30,0x5b,0xb0,
 0xb8,0x93,0x4b,0x5b,0x1e,0xd4,0x5c,0x5a,0x5c,0xb0,0x39,0xf9,
 0xcd,0x00,0xab,0x11,0xce,0x92,0x73,0x0d,
};
const uint8_t tc_ya[] = {
 0x23,0x25,0x27,0xde,0xe2,0xcf,0xde,0x76,0xfb,0x42,0x5b,0x6d,
 0x88,0x81,0x86,0x30,0xee,0xa7,0xea,0x26,0x3f,0xac,0x28,0xd8,
 0x9f,0x52,0xd0,0x96,0xc5,0x63,0xb1,0xe6,
};
const uint8_t tc_ADa[] = {
 0x41,0x44,0x61,
};
const uint8_t tc_Ya[] = {
 0x54,0x48,0xfd,0x96,0x33,0x73,0x4e,0x70,0x32,0x10,0xb6,0x1d,
 0x5c,0xab,0xb1,0x31,0x0a,0x28,0x38,0x28,0x95,0xd5,0x6d,0x49,
 0x05,0x51,0x43,0x6a,0xb3,0x39,0x86,0x44,
};
const uint8_t tc_yb[] = {
 0x87,0x1e,0xbb,0x1d,0x5e,0xcb,0xef,0xfa,0x5a,0x47,0xe3,0x2c,
 0x40,0xd2,0xda,0x68,0x94,0xd9,0xf2,0x86,0x5e,0xfd,0xad,0x6a,
 0xd8,0x53,0x5a,0x1b,0xe7,0xe4,0x87,0xd6,
};
const uint8_t tc_ADb[] = {
 0x41,0x44,0x62,
};
const uint8_t tc_Yb[] = {
 0xd8,0xfe,0x02,0x51,0x58,0xc0,0xc0,0x8d,0x7e,0xa9,0x3a,0x84,
 0x71,0x8a,0x56,0x11,0x1b,0xff,0x54,0xbf,0x4b,0x96,0x0c,0x83,
 0x43,0xe6,0x4f,0x02,0x5e,0xea,0xd6,0x08,
};
const uint8_t tc_K[] = {
 0x4a,0xa5,0x9c,0xcf,0xda,0x03,0x69,0x1c,0x3e,0x9c,0xf4,0xda,
 0xb3,0x29,0xa1,0x3b,0xcc,0x97,0x07,0xe3,0x8f,0x54,0xe7,0x84,
 0xe3,0x0f,0x78,0x43,0x78,0xdb,0xcb,0x49,
};
const uint8_t tc_ISK_IR[] = {
 0xee,0xae,0xbb,0xac,0x8a,0x5a,0x05,0x7c,0xf9,0x4c,0x3e,0x8d,
 0xba,0x6c,0xf0,0xed,0xdd,0xb9,0x53,0x35,0x75,0x32,0xd0,0x02,
 0x8e,0x3e,0x0c,0xd4,0xa8,0x5c,0xe7,0xa4,0xb4,0x25,0x11,0xd5,
 0xfb,0x06,0xc6,0x0f,0x3b,0x07,0x75,0xc3,0x57,0xf2,0x67,0xcc,
 0xc9,0xe2,0x4b,0x81,0x33,0x82,0x31,0xb9,0xa6,0x18,0x55,0xfc,
 0xeb,0xd4,0xa0,0x26,
};
const uint8_t tc_ISK_SY[] = {
 0x17,0x0a,0x1d,0xf4,0x2f,0x03,0xda,0x08,0x2b,0x9d,0x25,0x0b,
 0xe6,0x46,0xbe,0x04,0xc8,0xc6,0xb4,0x49,0x0a,0xf1,0x7b,0x27,
 0xc4,0xa0,0x91,0x6f,0xe8,0x48,0x22,0x89,0xd1,0x0e,0xa0,0x53,
 0x44,0x55,0xab,0x57,0x8d,0xeb,0x88,0xda,0xe7,0x5d,0xb4,0xa8,
 0xbf,0x24,0xfb,0x11,0x18,0x25,0xe6,0x30,0x2a,0xd3,0xc0,0xd9,
 0x03,0x34,0x1f,0x83,
};
~~~


## Test vectors for X448 low order points

Points that need to return neutral element when input to
plain X448 that also accept non-canonical inputs larger
than the field prime.

### Weak points for X448 smaller than the field prime (canonical)

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

### Weak points for X448 larger or equal to the field prime (non-canonical)

~~~
  u3: (length: 56 bytes)
    fffffffffffffffffffffffffffffffffffffffffffffffffffffffffe
    ffffffffffffffffffffffffffffffffffffffffffffffffffffff
  u4: (length: 56 bytes)
    00000000000000000000000000000000000000000000000000000000ff
    ffffffffffffffffffffffffffffffffffffffffffffffffffffff
~~~

### Expected results for X448

~~~
  scalar s: (length: 56 bytes)
    af8a14218bf2a2062926d2ea9b8fe4e8b6817349b6ed2feb1e5d64d7a4
    523f15fceec70fb111e870dc58d191e66a14d3e9d482d04432cadd
  X448(s,u0): (length: 56 bytes)
    0000000000000000000000000000000000000000000000000000000000
    000000000000000000000000000000000000000000000000000000
  X448(s,u1): (length: 56 bytes)
    0000000000000000000000000000000000000000000000000000000000
    000000000000000000000000000000000000000000000000000000
  X448(s,u2): (length: 56 bytes)
    0000000000000000000000000000000000000000000000000000000000
    000000000000000000000000000000000000000000000000000000
  X448(s,u3): (length: 56 bytes)
    0000000000000000000000000000000000000000000000000000000000
    000000000000000000000000000000000000000000000000000000
  X448(s,u4): (length: 56 bytes)
    0000000000000000000000000000000000000000000000000000000000
    000000000000000000000000000000000000000000000000000000
~~~

##  Test vector for CPace using group X448 and hash SHAKE-256


###  Test vectors for calculate_generator with group X448

~~~
  Inputs
    H   = SHAKE-256 with input block size 136 bytes.
    PRS = b'password' ; ZPAD length: 126 ; DSI = b'CPace448'
    CI = b'\nAinitiator\nBresponder'
    CI = 0a41696e69746961746f720a42726573706f6e646572
    sid = 5223e0cdc45d6575668d64c552004124
  Outputs
    hash generator string: (length: 56 bytes)
      c1658ad06392f4eb5a23294d49210744aea89bf56cd9d1497b0b6ca0
      d4a9172fedd1e9d8376794c166ebbe05b598c051cbad24b03892e841
    after decoding to coordinate: (length: 32 bytes)
      c1658ad06392f4eb5a23294d49210744aea89bf56cd9d1497b0b6ca0
      d4a9172f
    generator g: (length: 56 bytes)
      402906591ba645f89b94dc93559c9c423a35d5eaf2878da0fd11b912
      aee50ffbf537a6b3bf72c28f3a12cf521eac520d2630806ee2b2f41d
~~~

###  Test vector for MSGa

~~~
  Inputs
    ADa = b'ADa'
    ya (little endian): (length: 56 bytes)
      e7f541f33bf50afed97b2fafd43bed219d1a0dad7361ea576b25de79
      bcdcf50c0f238a18e865c8d5fd6b1768719e0a5a45b6c34b23852a93
  Outputs
    Ya: (length: 56 bytes)
      7a2454a2ffa18c09f8b5b60ac900f19d2d3fb7b01bb9cfe07d5ae99d
      27bf891aeb321c3563a17fbd45bb3b809565d16e15a951dc7e466000
    MSGa: (length: 61 bytes)
      387a2454a2ffa18c09f8b5b60ac900f19d2d3fb7b01bb9cfe07d5ae9
      9d27bf891aeb321c3563a17fbd45bb3b809565d16e15a951dc7e4660
      0003414461
~~~

###  Test vector for MSGb

~~~
  Inputs
    ADb = b'ADb'
    yb (little endian): (length: 56 bytes)
      cbb76860fa66e048a2daea5f03fe88f5e57c1286a5ad770d6cb175b3
      3a0d4249c56d5d64e4550e8862da5c69cf5d04d66a1c61e88d349b00
  Outputs
    Yb: (length: 56 bytes)
      9dce85b5c3252bf80c41428324d4dead4160d99073da2a53f6eab677
      aae5559d295f91a336ca654e44e8b3831cd1b568107c7269a64651e9
    MSGb: (length: 61 bytes)
      389dce85b5c3252bf80c41428324d4dead4160d99073da2a53f6eab6
      77aae5559d295f91a336ca654e44e8b3831cd1b568107c7269a64651
      e903414462
~~~

###  Test vector for secret points K

~~~
    scalar_mult_vfy(ya,Yb): (length: 56 bytes)
      8cb51a7fe5283c717ccc03be38a1948924db188581fef349ef08366c
      b110fdf0181e37576bdbe8c419d30b28ba89681eea2ce6cb0c5f9323
    scalar_mult_vfy(yb,Ya): (length: 56 bytes)
      8cb51a7fe5283c717ccc03be38a1948924db188581fef349ef08366c
      b110fdf0181e37576bdbe8c419d30b28ba89681eea2ce6cb0c5f9323
~~~


###  Test vector for ISK calculation initiator/responder

~~~
    unordered cat of transcript : (length: 122 bytes)
      387a2454a2ffa18c09f8b5b60ac900f19d2d3fb7b01bb9cfe07d5ae9
      9d27bf891aeb321c3563a17fbd45bb3b809565d16e15a951dc7e4660
      0003414461389dce85b5c3252bf80c41428324d4dead4160d99073da
      2a53f6eab677aae5559d295f91a336ca654e44e8b3831cd1b568107c
      7269a64651e903414462
    input to final ISK hash: (length: 209 bytes)
      0c43506163653434385f49534b105223e0cdc45d6575668d64c55200
      4124388cb51a7fe5283c717ccc03be38a1948924db188581fef349ef
      08366cb110fdf0181e37576bdbe8c419d30b28ba89681eea2ce6cb0c
      5f9323387a2454a2ffa18c09f8b5b60ac900f19d2d3fb7b01bb9cfe0
      7d5ae99d27bf891aeb321c3563a17fbd45bb3b809565d16e15a951dc
      7e46600003414461389dce85b5c3252bf80c41428324d4dead4160d9
      9073da2a53f6eab677aae5559d295f91a336ca654e44e8b3831cd1b5
      68107c7269a64651e903414462
    ISK result: (length: 64 bytes)
      69c13d8ea9257357439f74198ab5a7943106f1b98dd69f3c58b017c2
      47d93c7262a341d6c47016e61fc97809ec30c8cd685f8dd5c2e9f464
      83e1faf02c67b9f6
~~~

###  Test vector for ISK calculation parallel execution

~~~
    ordered cat of transcript : (length: 122 bytes)
      389dce85b5c3252bf80c41428324d4dead4160d99073da2a53f6eab6
      77aae5559d295f91a336ca654e44e8b3831cd1b568107c7269a64651
      e903414462387a2454a2ffa18c09f8b5b60ac900f19d2d3fb7b01bb9
      cfe07d5ae99d27bf891aeb321c3563a17fbd45bb3b809565d16e15a9
      51dc7e46600003414461
    input to final ISK hash: (length: 209 bytes)
      0c43506163653434385f49534b105223e0cdc45d6575668d64c55200
      4124388cb51a7fe5283c717ccc03be38a1948924db188581fef349ef
      08366cb110fdf0181e37576bdbe8c419d30b28ba89681eea2ce6cb0c
      5f9323389dce85b5c3252bf80c41428324d4dead4160d99073da2a53
      f6eab677aae5559d295f91a336ca654e44e8b3831cd1b568107c7269
      a64651e903414462387a2454a2ffa18c09f8b5b60ac900f19d2d3fb7
      b01bb9cfe07d5ae99d27bf891aeb321c3563a17fbd45bb3b809565d1
      6e15a951dc7e46600003414461
    ISK result: (length: 64 bytes)
      83022985a2b757a59418c49c842c5f623f70f629ec18d1d70236119e
      ffcc5ba3015a81b0ab00ca64afdce78f76af749718ec4710350320d9
      106162da846ee943
~~~

###  Corresponding ANSI-C initializers

~~~
const uint8_t tc_PRS[] = {
 0x70,0x61,0x73,0x73,0x77,0x6f,0x72,0x64,
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
 0x40,0x29,0x06,0x59,0x1b,0xa6,0x45,0xf8,0x9b,0x94,0xdc,0x93,
 0x55,0x9c,0x9c,0x42,0x3a,0x35,0xd5,0xea,0xf2,0x87,0x8d,0xa0,
 0xfd,0x11,0xb9,0x12,0xae,0xe5,0x0f,0xfb,0xf5,0x37,0xa6,0xb3,
 0xbf,0x72,0xc2,0x8f,0x3a,0x12,0xcf,0x52,0x1e,0xac,0x52,0x0d,
 0x26,0x30,0x80,0x6e,0xe2,0xb2,0xf4,0x1d,
};
const uint8_t tc_ya[] = {
 0xe7,0xf5,0x41,0xf3,0x3b,0xf5,0x0a,0xfe,0xd9,0x7b,0x2f,0xaf,
 0xd4,0x3b,0xed,0x21,0x9d,0x1a,0x0d,0xad,0x73,0x61,0xea,0x57,
 0x6b,0x25,0xde,0x79,0xbc,0xdc,0xf5,0x0c,0x0f,0x23,0x8a,0x18,
 0xe8,0x65,0xc8,0xd5,0xfd,0x6b,0x17,0x68,0x71,0x9e,0x0a,0x5a,
 0x45,0xb6,0xc3,0x4b,0x23,0x85,0x2a,0x93,
};
const uint8_t tc_ADa[] = {
 0x41,0x44,0x61,
};
const uint8_t tc_Ya[] = {
 0x7a,0x24,0x54,0xa2,0xff,0xa1,0x8c,0x09,0xf8,0xb5,0xb6,0x0a,
 0xc9,0x00,0xf1,0x9d,0x2d,0x3f,0xb7,0xb0,0x1b,0xb9,0xcf,0xe0,
 0x7d,0x5a,0xe9,0x9d,0x27,0xbf,0x89,0x1a,0xeb,0x32,0x1c,0x35,
 0x63,0xa1,0x7f,0xbd,0x45,0xbb,0x3b,0x80,0x95,0x65,0xd1,0x6e,
 0x15,0xa9,0x51,0xdc,0x7e,0x46,0x60,0x00,
};
const uint8_t tc_yb[] = {
 0xcb,0xb7,0x68,0x60,0xfa,0x66,0xe0,0x48,0xa2,0xda,0xea,0x5f,
 0x03,0xfe,0x88,0xf5,0xe5,0x7c,0x12,0x86,0xa5,0xad,0x77,0x0d,
 0x6c,0xb1,0x75,0xb3,0x3a,0x0d,0x42,0x49,0xc5,0x6d,0x5d,0x64,
 0xe4,0x55,0x0e,0x88,0x62,0xda,0x5c,0x69,0xcf,0x5d,0x04,0xd6,
 0x6a,0x1c,0x61,0xe8,0x8d,0x34,0x9b,0x00,
};
const uint8_t tc_ADb[] = {
 0x41,0x44,0x62,
};
const uint8_t tc_Yb[] = {
 0x9d,0xce,0x85,0xb5,0xc3,0x25,0x2b,0xf8,0x0c,0x41,0x42,0x83,
 0x24,0xd4,0xde,0xad,0x41,0x60,0xd9,0x90,0x73,0xda,0x2a,0x53,
 0xf6,0xea,0xb6,0x77,0xaa,0xe5,0x55,0x9d,0x29,0x5f,0x91,0xa3,
 0x36,0xca,0x65,0x4e,0x44,0xe8,0xb3,0x83,0x1c,0xd1,0xb5,0x68,
 0x10,0x7c,0x72,0x69,0xa6,0x46,0x51,0xe9,
};
const uint8_t tc_K[] = {
 0x8c,0xb5,0x1a,0x7f,0xe5,0x28,0x3c,0x71,0x7c,0xcc,0x03,0xbe,
 0x38,0xa1,0x94,0x89,0x24,0xdb,0x18,0x85,0x81,0xfe,0xf3,0x49,
 0xef,0x08,0x36,0x6c,0xb1,0x10,0xfd,0xf0,0x18,0x1e,0x37,0x57,
 0x6b,0xdb,0xe8,0xc4,0x19,0xd3,0x0b,0x28,0xba,0x89,0x68,0x1e,
 0xea,0x2c,0xe6,0xcb,0x0c,0x5f,0x93,0x23,
};
const uint8_t tc_ISK_IR[] = {
 0x69,0xc1,0x3d,0x8e,0xa9,0x25,0x73,0x57,0x43,0x9f,0x74,0x19,
 0x8a,0xb5,0xa7,0x94,0x31,0x06,0xf1,0xb9,0x8d,0xd6,0x9f,0x3c,
 0x58,0xb0,0x17,0xc2,0x47,0xd9,0x3c,0x72,0x62,0xa3,0x41,0xd6,
 0xc4,0x70,0x16,0xe6,0x1f,0xc9,0x78,0x09,0xec,0x30,0xc8,0xcd,
 0x68,0x5f,0x8d,0xd5,0xc2,0xe9,0xf4,0x64,0x83,0xe1,0xfa,0xf0,
 0x2c,0x67,0xb9,0xf6,
};
const uint8_t tc_ISK_SY[] = {
 0x83,0x02,0x29,0x85,0xa2,0xb7,0x57,0xa5,0x94,0x18,0xc4,0x9c,
 0x84,0x2c,0x5f,0x62,0x3f,0x70,0xf6,0x29,0xec,0x18,0xd1,0xd7,
 0x02,0x36,0x11,0x9e,0xff,0xcc,0x5b,0xa3,0x01,0x5a,0x81,0xb0,
 0xab,0x00,0xca,0x64,0xaf,0xdc,0xe7,0x8f,0x76,0xaf,0x74,0x97,
 0x18,0xec,0x47,0x10,0x35,0x03,0x20,0xd9,0x10,0x61,0x62,0xda,
 0x84,0x6e,0xe9,0x43,
};
~~~

##  Test vector for CPace using group ristretto255 and hash SHA-512


###  Test vectors for calculate_generator with group ristretto255

~~~
  Inputs
    H   = SHA-512 with input block size 128 bytes.
    PRS = b'password' ; ZPAD length: 118 ; DSI = b'CPaceristretto255'
    CI = b'\nAinitiator\nBresponder'
    CI = 0a41696e69746961746f720a42726573706f6e646572
    sid = 7e4b4791d6a8ef019b936c79fb7f2c57
  Outputs
    hash generator string: (length: 186 bytes)
      0870617373776f726476000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000114350616365726973747265
      74746f323535160a41696e69746961746f720a42726573706f6e6465
      72107e4b4791d6a8ef019b936c79fb7f2c57
    hash result: (length: 64 bytes)
      d1fefeb0032c916c88e31a74c8f46308ae6db6ce4ef9971bf9a0c530
      f829a230565c9824d8d2181ca4caa0b6ff2978d744d92a987e95dc78
      feacf2f2b3500478
    encoded generator g: (length: 32 bytes)
      80a71e8a8a0c2b4dd351c21fabfa99c8f01efb1b42f0c7025c4e24de
      8ae2cd1e
~~~


###  Test vector for MSGa

~~~
  Inputs
    ADa = b'ADa'
    ya (little endian): (length: 32 bytes)
      1433dd19359992d4e06d740d3993d429af6338ffb4531ce175d22449
      853a790b
  Outputs
    Ya: (length: 32 bytes)
      68af16733a0a0ae7aa68768a83b91a25c11e41996ca833bdf844cf0c
      f8d36d6f
    MSGa: (length: 37 bytes)
      2068af16733a0a0ae7aa68768a83b91a25c11e41996ca833bdf844cf
      0cf8d36d6f03414461
~~~

###  Test vector for MSGb

~~~
  Inputs
    ADb = b'ADb'
    yb (little endian): (length: 32 bytes)
      0e6566d32d80a5a1135f99c27f2d637aa24da23027c3fa76b9d1cfd9
      742fdc00
  Outputs
    Yb: (length: 32 bytes)
      905cb62b365f497c8bb05c422ab66ad814ef0bd7e13dd55757e1a379
      43b0307b
    MSGb: (length: 37 bytes)
      20905cb62b365f497c8bb05c422ab66ad814ef0bd7e13dd55757e1a3
      7943b0307b03414462
~~~

###  Test vector for secret points K

~~~
    scalar_mult_vfy(ya,Yb): (length: 32 bytes)
      0075247d9956cf507a3c6f5a961e42bd2a9006bc067e4112a5795afb
      fe3f784b
    scalar_mult_vfy(yb,Ya): (length: 32 bytes)
      0075247d9956cf507a3c6f5a961e42bd2a9006bc067e4112a5795afb
      fe3f784b
~~~


###  Test vector for ISK calculation initiator/responder

~~~
    unordered cat of transcript : (length: 74 bytes)
      2068af16733a0a0ae7aa68768a83b91a25c11e41996ca833bdf844cf
      0cf8d36d6f0341446120905cb62b365f497c8bb05c422ab66ad814ef
      0bd7e13dd55757e1a37943b0307b03414462
    input to final ISK hash: (length: 146 bytes)
      15435061636572697374726574746f3235355f49534b107e4b4791d6
      a8ef019b936c79fb7f2c57200075247d9956cf507a3c6f5a961e42bd
      2a9006bc067e4112a5795afbfe3f784b2068af16733a0a0ae7aa6876
      8a83b91a25c11e41996ca833bdf844cf0cf8d36d6f0341446120905c
      b62b365f497c8bb05c422ab66ad814ef0bd7e13dd55757e1a37943b0
      307b03414462
    ISK result: (length: 64 bytes)
      eb3e5c2ca1df3849ae4ba385b705afc08c33662048d7853ed63bc3f2
      1c22c01f306d43b45df60f62ba698077d0809d542701021039f28385
      8467f03eae5f6917
~~~

###  Test vector for ISK calculation parallel execution

~~~
    ordered cat of transcript : (length: 74 bytes)
      20905cb62b365f497c8bb05c422ab66ad814ef0bd7e13dd55757e1a3
      7943b0307b034144622068af16733a0a0ae7aa68768a83b91a25c11e
      41996ca833bdf844cf0cf8d36d6f03414461
    input to final ISK hash: (length: 146 bytes)
      15435061636572697374726574746f3235355f49534b107e4b4791d6
      a8ef019b936c79fb7f2c57200075247d9956cf507a3c6f5a961e42bd
      2a9006bc067e4112a5795afbfe3f784b20905cb62b365f497c8bb05c
      422ab66ad814ef0bd7e13dd55757e1a37943b0307b034144622068af
      16733a0a0ae7aa68768a83b91a25c11e41996ca833bdf844cf0cf8d3
      6d6f03414461
    ISK result: (length: 64 bytes)
      444984cc07374662a5a6d6cd1943a8bf513b71ff180901cc9e12e337
      19ec9bb30ea3788ed2b8b5e097a708f29dfd83a2d43d13aaf6f53359
      c1a752a703c5d35d
~~~

###  Corresponding ANSI-C initializers

~~~
const uint8_t tc_PRS[] = {
 0x70,0x61,0x73,0x73,0x77,0x6f,0x72,0x64,
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
 0x80,0xa7,0x1e,0x8a,0x8a,0x0c,0x2b,0x4d,0xd3,0x51,0xc2,0x1f,
 0xab,0xfa,0x99,0xc8,0xf0,0x1e,0xfb,0x1b,0x42,0xf0,0xc7,0x02,
 0x5c,0x4e,0x24,0xde,0x8a,0xe2,0xcd,0x1e,
};
const uint8_t tc_ya[] = {
 0x14,0x33,0xdd,0x19,0x35,0x99,0x92,0xd4,0xe0,0x6d,0x74,0x0d,
 0x39,0x93,0xd4,0x29,0xaf,0x63,0x38,0xff,0xb4,0x53,0x1c,0xe1,
 0x75,0xd2,0x24,0x49,0x85,0x3a,0x79,0x0b,
};
const uint8_t tc_ADa[] = {
 0x41,0x44,0x61,
};
const uint8_t tc_Ya[] = {
 0x68,0xaf,0x16,0x73,0x3a,0x0a,0x0a,0xe7,0xaa,0x68,0x76,0x8a,
 0x83,0xb9,0x1a,0x25,0xc1,0x1e,0x41,0x99,0x6c,0xa8,0x33,0xbd,
 0xf8,0x44,0xcf,0x0c,0xf8,0xd3,0x6d,0x6f,
};
const uint8_t tc_yb[] = {
 0x0e,0x65,0x66,0xd3,0x2d,0x80,0xa5,0xa1,0x13,0x5f,0x99,0xc2,
 0x7f,0x2d,0x63,0x7a,0xa2,0x4d,0xa2,0x30,0x27,0xc3,0xfa,0x76,
 0xb9,0xd1,0xcf,0xd9,0x74,0x2f,0xdc,0x00,
};
const uint8_t tc_ADb[] = {
 0x41,0x44,0x62,
};
const uint8_t tc_Yb[] = {
 0x90,0x5c,0xb6,0x2b,0x36,0x5f,0x49,0x7c,0x8b,0xb0,0x5c,0x42,
 0x2a,0xb6,0x6a,0xd8,0x14,0xef,0x0b,0xd7,0xe1,0x3d,0xd5,0x57,
 0x57,0xe1,0xa3,0x79,0x43,0xb0,0x30,0x7b,
};
const uint8_t tc_K[] = {
 0x00,0x75,0x24,0x7d,0x99,0x56,0xcf,0x50,0x7a,0x3c,0x6f,0x5a,
 0x96,0x1e,0x42,0xbd,0x2a,0x90,0x06,0xbc,0x06,0x7e,0x41,0x12,
 0xa5,0x79,0x5a,0xfb,0xfe,0x3f,0x78,0x4b,
};
const uint8_t tc_ISK_IR[] = {
 0xeb,0x3e,0x5c,0x2c,0xa1,0xdf,0x38,0x49,0xae,0x4b,0xa3,0x85,
 0xb7,0x05,0xaf,0xc0,0x8c,0x33,0x66,0x20,0x48,0xd7,0x85,0x3e,
 0xd6,0x3b,0xc3,0xf2,0x1c,0x22,0xc0,0x1f,0x30,0x6d,0x43,0xb4,
 0x5d,0xf6,0x0f,0x62,0xba,0x69,0x80,0x77,0xd0,0x80,0x9d,0x54,
 0x27,0x01,0x02,0x10,0x39,0xf2,0x83,0x85,0x84,0x67,0xf0,0x3e,
 0xae,0x5f,0x69,0x17,
};
const uint8_t tc_ISK_SY[] = {
 0x44,0x49,0x84,0xcc,0x07,0x37,0x46,0x62,0xa5,0xa6,0xd6,0xcd,
 0x19,0x43,0xa8,0xbf,0x51,0x3b,0x71,0xff,0x18,0x09,0x01,0xcc,
 0x9e,0x12,0xe3,0x37,0x19,0xec,0x9b,0xb3,0x0e,0xa3,0x78,0x8e,
 0xd2,0xb8,0xb5,0xe0,0x97,0xa7,0x08,0xf2,0x9d,0xfd,0x83,0xa2,
 0xd4,0x3d,0x13,0xaa,0xf6,0xf5,0x33,0x59,0xc1,0xa7,0x52,0xa7,
 0x03,0xc5,0xd3,0x5d,
};
~~~

##  Test vector for CPace using group decaf448 and hash SHAKE-256


###  Test vectors for calculate_generator with group decaf448

~~~
  Inputs
    H   = SHAKE-256 with input block size 136 bytes.
    PRS = b'password' ; ZPAD length: 126 ; DSI = b'CPacedecaf448'
    CI = b'\nAinitiator\nBresponder'
    CI = 0a41696e69746961746f720a42726573706f6e646572
    sid = 5223e0cdc45d6575668d64c552004124
  Outputs
    hash generator string: (length: 190 bytes)
      0870617373776f72647e000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000000d435061
      63656465636166343438160a41696e69746961746f720a4272657370
      6f6e646572105223e0cdc45d6575668d64c552004124
    hash result: (length: 112 bytes)
      ae4cf9e238aa40b02814456e2dbb74c237d206931b6eff10dc709008
      62e51f64832c6f50a7f378954d9ed3f508fd43eb010b3de440290ccb
      8b0271a96d67197a927484c24f1221a04abf105e84e7c731487849a5
      9f073d61ee9439ce0a91019ed95fa1dbcb71aba8537681063114bd6d
    encoded generator g: (length: 56 bytes)
      7245c964b4aee304eb8da88463d85d642c8a38a9a4e1c86507dcb1bb
      1cf3d4dabf6518c3fb928fc011a3fad4b11926b0727c8ef7c5f6d81a
~~~


###  Test vector for MSGa

~~~
  Inputs
    ADa = b'ADa'
    ya (little endian): (length: 56 bytes)
      33d561f13cfc0dca279c30e8cde895175dc25483892819eba132d58c
      13c0462a8eb0d73fda941950594bef5191d8394691f86edffcad6c1e
  Outputs
    Ya: (length: 56 bytes)
      64bab0e2e5b4e580b48c1cb27114baeefcbb00da0f791054145989b4
      8cf6e53b2ae929b4f61e197560a2c26897b1d505c4536e8267e6d7c3
    MSGa: (length: 61 bytes)
      3864bab0e2e5b4e580b48c1cb27114baeefcbb00da0f791054145989
      b48cf6e53b2ae929b4f61e197560a2c26897b1d505c4536e8267e6d7
      c303414461
~~~

###  Test vector for MSGb

~~~
  Inputs
    ADb = b'ADb'
    yb (little endian): (length: 56 bytes)
      2523c969f68fa2b2aea294c2539ef36eb1e0558abd14712a7828f16a
      85ed2c7e77e2bdd418994405fb1b57b6bbaadd66849892aac9d81402
  Outputs
    Yb: (length: 56 bytes)
      c29b5b6da0052b720f2c4f8ffab9315d247dbd5090d360272f49daab
      f3cd933601cd99103416f19887a2f831fd851b5ff48e941def9c3939
    MSGb: (length: 61 bytes)
      38c29b5b6da0052b720f2c4f8ffab9315d247dbd5090d360272f49da
      abf3cd933601cd99103416f19887a2f831fd851b5ff48e941def9c39
      3903414462
~~~

###  Test vector for secret points K

~~~
    scalar_mult_vfy(ya,Yb): (length: 56 bytes)
      62b09c5f63f58fca11fc8432ff40adc47815a4286e277bb8cef92ea6
      65ebabf4f14f24211fe3ce08c1f983c307b67b06026cab3f7d7b1799
    scalar_mult_vfy(yb,Ya): (length: 56 bytes)
      62b09c5f63f58fca11fc8432ff40adc47815a4286e277bb8cef92ea6
      65ebabf4f14f24211fe3ce08c1f983c307b67b06026cab3f7d7b1799
~~~


###  Test vector for ISK calculation initiator/responder

~~~
    unordered cat of transcript : (length: 122 bytes)
      3864bab0e2e5b4e580b48c1cb27114baeefcbb00da0f791054145989
      b48cf6e53b2ae929b4f61e197560a2c26897b1d505c4536e8267e6d7
      c30341446138c29b5b6da0052b720f2c4f8ffab9315d247dbd5090d3
      60272f49daabf3cd933601cd99103416f19887a2f831fd851b5ff48e
      941def9c393903414462
    input to final ISK hash: (length: 214 bytes)
      11435061636564656361663434385f49534b105223e0cdc45d657566
      8d64c5520041243862b09c5f63f58fca11fc8432ff40adc47815a428
      6e277bb8cef92ea665ebabf4f14f24211fe3ce08c1f983c307b67b06
      026cab3f7d7b17993864bab0e2e5b4e580b48c1cb27114baeefcbb00
      da0f791054145989b48cf6e53b2ae929b4f61e197560a2c26897b1d5
      05c4536e8267e6d7c30341446138c29b5b6da0052b720f2c4f8ffab9
      315d247dbd5090d360272f49daabf3cd933601cd99103416f19887a2
      f831fd851b5ff48e941def9c393903414462
    ISK result: (length: 64 bytes)
      6fb210448f0eb49f9058c9be0c42f3d58a8d51e31bddbe88c0751360
      d91f71ce4e7e7602cce4daee46be49b16f01b40d83bb0303df91d8c4
      01658fdb8942569e
~~~

###  Test vector for ISK calculation parallel execution

~~~
    ordered cat of transcript : (length: 122 bytes)
      38c29b5b6da0052b720f2c4f8ffab9315d247dbd5090d360272f49da
      abf3cd933601cd99103416f19887a2f831fd851b5ff48e941def9c39
      39034144623864bab0e2e5b4e580b48c1cb27114baeefcbb00da0f79
      1054145989b48cf6e53b2ae929b4f61e197560a2c26897b1d505c453
      6e8267e6d7c303414461
    input to final ISK hash: (length: 214 bytes)
      11435061636564656361663434385f49534b105223e0cdc45d657566
      8d64c5520041243862b09c5f63f58fca11fc8432ff40adc47815a428
      6e277bb8cef92ea665ebabf4f14f24211fe3ce08c1f983c307b67b06
      026cab3f7d7b179938c29b5b6da0052b720f2c4f8ffab9315d247dbd
      5090d360272f49daabf3cd933601cd99103416f19887a2f831fd851b
      5ff48e941def9c3939034144623864bab0e2e5b4e580b48c1cb27114
      baeefcbb00da0f791054145989b48cf6e53b2ae929b4f61e197560a2
      c26897b1d505c4536e8267e6d7c303414461
    ISK result: (length: 64 bytes)
      a37f87e303ebe668ef9b541e0c780c56d21a9d376dfe1586fb4335a4
      b9d415c540d8f23efdb02c9b1d2d3a6442b4e5a70cfc436eeea77a96
      441e38018ee2d788
~~~

###  Corresponding ANSI-C initializers

~~~
const uint8_t tc_PRS[] = {
 0x70,0x61,0x73,0x73,0x77,0x6f,0x72,0x64,
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
 0x72,0x45,0xc9,0x64,0xb4,0xae,0xe3,0x04,0xeb,0x8d,0xa8,0x84,
 0x63,0xd8,0x5d,0x64,0x2c,0x8a,0x38,0xa9,0xa4,0xe1,0xc8,0x65,
 0x07,0xdc,0xb1,0xbb,0x1c,0xf3,0xd4,0xda,0xbf,0x65,0x18,0xc3,
 0xfb,0x92,0x8f,0xc0,0x11,0xa3,0xfa,0xd4,0xb1,0x19,0x26,0xb0,
 0x72,0x7c,0x8e,0xf7,0xc5,0xf6,0xd8,0x1a,
};
const uint8_t tc_ya[] = {
 0x33,0xd5,0x61,0xf1,0x3c,0xfc,0x0d,0xca,0x27,0x9c,0x30,0xe8,
 0xcd,0xe8,0x95,0x17,0x5d,0xc2,0x54,0x83,0x89,0x28,0x19,0xeb,
 0xa1,0x32,0xd5,0x8c,0x13,0xc0,0x46,0x2a,0x8e,0xb0,0xd7,0x3f,
 0xda,0x94,0x19,0x50,0x59,0x4b,0xef,0x51,0x91,0xd8,0x39,0x46,
 0x91,0xf8,0x6e,0xdf,0xfc,0xad,0x6c,0x1e,
};
const uint8_t tc_ADa[] = {
 0x41,0x44,0x61,
};
const uint8_t tc_Ya[] = {
 0x64,0xba,0xb0,0xe2,0xe5,0xb4,0xe5,0x80,0xb4,0x8c,0x1c,0xb2,
 0x71,0x14,0xba,0xee,0xfc,0xbb,0x00,0xda,0x0f,0x79,0x10,0x54,
 0x14,0x59,0x89,0xb4,0x8c,0xf6,0xe5,0x3b,0x2a,0xe9,0x29,0xb4,
 0xf6,0x1e,0x19,0x75,0x60,0xa2,0xc2,0x68,0x97,0xb1,0xd5,0x05,
 0xc4,0x53,0x6e,0x82,0x67,0xe6,0xd7,0xc3,
};
const uint8_t tc_yb[] = {
 0x25,0x23,0xc9,0x69,0xf6,0x8f,0xa2,0xb2,0xae,0xa2,0x94,0xc2,
 0x53,0x9e,0xf3,0x6e,0xb1,0xe0,0x55,0x8a,0xbd,0x14,0x71,0x2a,
 0x78,0x28,0xf1,0x6a,0x85,0xed,0x2c,0x7e,0x77,0xe2,0xbd,0xd4,
 0x18,0x99,0x44,0x05,0xfb,0x1b,0x57,0xb6,0xbb,0xaa,0xdd,0x66,
 0x84,0x98,0x92,0xaa,0xc9,0xd8,0x14,0x02,
};
const uint8_t tc_ADb[] = {
 0x41,0x44,0x62,
};
const uint8_t tc_Yb[] = {
 0xc2,0x9b,0x5b,0x6d,0xa0,0x05,0x2b,0x72,0x0f,0x2c,0x4f,0x8f,
 0xfa,0xb9,0x31,0x5d,0x24,0x7d,0xbd,0x50,0x90,0xd3,0x60,0x27,
 0x2f,0x49,0xda,0xab,0xf3,0xcd,0x93,0x36,0x01,0xcd,0x99,0x10,
 0x34,0x16,0xf1,0x98,0x87,0xa2,0xf8,0x31,0xfd,0x85,0x1b,0x5f,
 0xf4,0x8e,0x94,0x1d,0xef,0x9c,0x39,0x39,
};
const uint8_t tc_K[] = {
 0x62,0xb0,0x9c,0x5f,0x63,0xf5,0x8f,0xca,0x11,0xfc,0x84,0x32,
 0xff,0x40,0xad,0xc4,0x78,0x15,0xa4,0x28,0x6e,0x27,0x7b,0xb8,
 0xce,0xf9,0x2e,0xa6,0x65,0xeb,0xab,0xf4,0xf1,0x4f,0x24,0x21,
 0x1f,0xe3,0xce,0x08,0xc1,0xf9,0x83,0xc3,0x07,0xb6,0x7b,0x06,
 0x02,0x6c,0xab,0x3f,0x7d,0x7b,0x17,0x99,
};
const uint8_t tc_ISK_IR[] = {
 0x6f,0xb2,0x10,0x44,0x8f,0x0e,0xb4,0x9f,0x90,0x58,0xc9,0xbe,
 0x0c,0x42,0xf3,0xd5,0x8a,0x8d,0x51,0xe3,0x1b,0xdd,0xbe,0x88,
 0xc0,0x75,0x13,0x60,0xd9,0x1f,0x71,0xce,0x4e,0x7e,0x76,0x02,
 0xcc,0xe4,0xda,0xee,0x46,0xbe,0x49,0xb1,0x6f,0x01,0xb4,0x0d,
 0x83,0xbb,0x03,0x03,0xdf,0x91,0xd8,0xc4,0x01,0x65,0x8f,0xdb,
 0x89,0x42,0x56,0x9e,
};
const uint8_t tc_ISK_SY[] = {
 0xa3,0x7f,0x87,0xe3,0x03,0xeb,0xe6,0x68,0xef,0x9b,0x54,0x1e,
 0x0c,0x78,0x0c,0x56,0xd2,0x1a,0x9d,0x37,0x6d,0xfe,0x15,0x86,
 0xfb,0x43,0x35,0xa4,0xb9,0xd4,0x15,0xc5,0x40,0xd8,0xf2,0x3e,
 0xfd,0xb0,0x2c,0x9b,0x1d,0x2d,0x3a,0x64,0x42,0xb4,0xe5,0xa7,
 0x0c,0xfc,0x43,0x6e,0xee,0xa7,0x7a,0x96,0x44,0x1e,0x38,0x01,
 0x8e,0xe2,0xd7,0x88,
};
~~~

##  Test vector for CPace using group NIST P-256 and hash SHA-256


###  Test vectors for calculate_generator with group NIST P-256

~~~
  Inputs
    H   = SHA-256 with input block size 64 bytes.
    PRS = b'password' ; ZPAD length: 54 ;
    DSI = b'CPaceP256_XMD:SHA-256_SSWU_NU_'
    CI = b'\nAinitiator\nBresponder'
    CI = 0a41696e69746961746f720a42726573706f6e646572
    sid = 34b36454cab2e7842c389f7d88ecb7df
  Outputs
    string passed to map: (length: 135 bytes)
      0870617373776f726436000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      00000000000000001e4350616365503235365f584d443a5348412d32
      35365f535357555f4e555f160a41696e69746961746f720a42726573
      706f6e6465721034b36454cab2e7842c389f7d88ecb7df
    generator g: (length: 65 bytes)
      04617d04154ab8670aa9b4099a3fd5e9c6fa365afb834eaa33e44648
      092c4278849697c7e77daa946c9997217bd28fc23b6762a03dde504c
      9de1ea8d9df6270191
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
      041dc910359e26f44b3a16300337e1932fd84ea26a4144b61d3a4dc1
      16641d4f66b768c8078e07df31541f357525b96d0348936bdf63ea9a
      fb7e64ee14cc2ddd66
    MSGa: (length: 70 bytes)
      41041dc910359e26f44b3a16300337e1932fd84ea26a4144b61d3a4d
      c116641d4f66b768c8078e07df31541f357525b96d0348936bdf63ea
      9afb7e64ee14cc2ddd6603414461
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
      04da32021f687db46e8d290bbe661ceb8799e47c215ebb25a5aa357d
      b06b59b67c178004f4702b0a120aca8f0d2964cabacd058ff58e75fa
      250e1829bdca18420d
    MSGb: (length: 70 bytes)
      4104da32021f687db46e8d290bbe661ceb8799e47c215ebb25a5aa35
      7db06b59b67c178004f4702b0a120aca8f0d2964cabacd058ff58e75
      fa250e1829bdca18420d03414462
~~~

###  Test vector for secret points K

~~~
    scalar_mult_vfy(ya,Yb): (length: 32 bytes)
      bd20b9ce554c1d9fd461c0b0fda0765ee5e9d21730614c06a14bc6f9
      6c0f3810
    scalar_mult_vfy(yb,Ya): (length: 32 bytes)
      bd20b9ce554c1d9fd461c0b0fda0765ee5e9d21730614c06a14bc6f9
      6c0f3810
~~~


###  Test vector for ISK calculation initiator/responder

~~~
    unordered cat of transcript : (length: 140 bytes)
      41041dc910359e26f44b3a16300337e1932fd84ea26a4144b61d3a4d
      c116641d4f66b768c8078e07df31541f357525b96d0348936bdf63ea
      9afb7e64ee14cc2ddd66034144614104da32021f687db46e8d290bbe
      661ceb8799e47c215ebb25a5aa357db06b59b67c178004f4702b0a12
      0aca8f0d2964cabacd058ff58e75fa250e1829bdca18420d03414462
    input to final ISK hash: (length: 225 bytes)
      224350616365503235365f584d443a5348412d3235365f535357555f
      4e555f5f49534b1034b36454cab2e7842c389f7d88ecb7df20bd20b9
      ce554c1d9fd461c0b0fda0765ee5e9d21730614c06a14bc6f96c0f38
      1041041dc910359e26f44b3a16300337e1932fd84ea26a4144b61d3a
      4dc116641d4f66b768c8078e07df31541f357525b96d0348936bdf63
      ea9afb7e64ee14cc2ddd66034144614104da32021f687db46e8d290b
      be661ceb8799e47c215ebb25a5aa357db06b59b67c178004f4702b0a
      120aca8f0d2964cabacd058ff58e75fa250e1829bdca18420d034144
      62
    ISK result: (length: 32 bytes)
      82729aab5893e56ac56610e95347f79cfdec54ec97276ec5ca1a2e6d
      b58c99a5
~~~

###  Test vector for ISK calculation parallel execution

~~~
    ordered cat of transcript : (length: 140 bytes)
      4104da32021f687db46e8d290bbe661ceb8799e47c215ebb25a5aa35
      7db06b59b67c178004f4702b0a120aca8f0d2964cabacd058ff58e75
      fa250e1829bdca18420d0341446241041dc910359e26f44b3a163003
      37e1932fd84ea26a4144b61d3a4dc116641d4f66b768c8078e07df31
      541f357525b96d0348936bdf63ea9afb7e64ee14cc2ddd6603414461
    input to final ISK hash: (length: 225 bytes)
      224350616365503235365f584d443a5348412d3235365f535357555f
      4e555f5f49534b1034b36454cab2e7842c389f7d88ecb7df20bd20b9
      ce554c1d9fd461c0b0fda0765ee5e9d21730614c06a14bc6f96c0f38
      104104da32021f687db46e8d290bbe661ceb8799e47c215ebb25a5aa
      357db06b59b67c178004f4702b0a120aca8f0d2964cabacd058ff58e
      75fa250e1829bdca18420d0341446241041dc910359e26f44b3a1630
      0337e1932fd84ea26a4144b61d3a4dc116641d4f66b768c8078e07df
      31541f357525b96d0348936bdf63ea9afb7e64ee14cc2ddd66034144
      61
    ISK result: (length: 32 bytes)
      78ea7caa0bf7d98ec048cf06910d4721763140d6beb54d4a406db586
      deff0063
~~~

###  Corresponding ANSI-C initializers

~~~
const uint8_t tc_PRS[] = {
 0x70,0x61,0x73,0x73,0x77,0x6f,0x72,0x64,
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
 0x04,0x61,0x7d,0x04,0x15,0x4a,0xb8,0x67,0x0a,0xa9,0xb4,0x09,
 0x9a,0x3f,0xd5,0xe9,0xc6,0xfa,0x36,0x5a,0xfb,0x83,0x4e,0xaa,
 0x33,0xe4,0x46,0x48,0x09,0x2c,0x42,0x78,0x84,0x96,0x97,0xc7,
 0xe7,0x7d,0xaa,0x94,0x6c,0x99,0x97,0x21,0x7b,0xd2,0x8f,0xc2,
 0x3b,0x67,0x62,0xa0,0x3d,0xde,0x50,0x4c,0x9d,0xe1,0xea,0x8d,
 0x9d,0xf6,0x27,0x01,0x91,
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
 0x04,0x1d,0xc9,0x10,0x35,0x9e,0x26,0xf4,0x4b,0x3a,0x16,0x30,
 0x03,0x37,0xe1,0x93,0x2f,0xd8,0x4e,0xa2,0x6a,0x41,0x44,0xb6,
 0x1d,0x3a,0x4d,0xc1,0x16,0x64,0x1d,0x4f,0x66,0xb7,0x68,0xc8,
 0x07,0x8e,0x07,0xdf,0x31,0x54,0x1f,0x35,0x75,0x25,0xb9,0x6d,
 0x03,0x48,0x93,0x6b,0xdf,0x63,0xea,0x9a,0xfb,0x7e,0x64,0xee,
 0x14,0xcc,0x2d,0xdd,0x66,
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
 0x04,0xda,0x32,0x02,0x1f,0x68,0x7d,0xb4,0x6e,0x8d,0x29,0x0b,
 0xbe,0x66,0x1c,0xeb,0x87,0x99,0xe4,0x7c,0x21,0x5e,0xbb,0x25,
 0xa5,0xaa,0x35,0x7d,0xb0,0x6b,0x59,0xb6,0x7c,0x17,0x80,0x04,
 0xf4,0x70,0x2b,0x0a,0x12,0x0a,0xca,0x8f,0x0d,0x29,0x64,0xca,
 0xba,0xcd,0x05,0x8f,0xf5,0x8e,0x75,0xfa,0x25,0x0e,0x18,0x29,
 0xbd,0xca,0x18,0x42,0x0d,
};
const uint8_t tc_K[] = {
 0xbd,0x20,0xb9,0xce,0x55,0x4c,0x1d,0x9f,0xd4,0x61,0xc0,0xb0,
 0xfd,0xa0,0x76,0x5e,0xe5,0xe9,0xd2,0x17,0x30,0x61,0x4c,0x06,
 0xa1,0x4b,0xc6,0xf9,0x6c,0x0f,0x38,0x10,
};
const uint8_t tc_ISK_IR[] = {
 0x82,0x72,0x9a,0xab,0x58,0x93,0xe5,0x6a,0xc5,0x66,0x10,0xe9,
 0x53,0x47,0xf7,0x9c,0xfd,0xec,0x54,0xec,0x97,0x27,0x6e,0xc5,
 0xca,0x1a,0x2e,0x6d,0xb5,0x8c,0x99,0xa5,
};
const uint8_t tc_ISK_SY[] = {
 0x78,0xea,0x7c,0xaa,0x0b,0xf7,0xd9,0x8e,0xc0,0x48,0xcf,0x06,
 0x91,0x0d,0x47,0x21,0x76,0x31,0x40,0xd6,0xbe,0xb5,0x4d,0x4a,
 0x40,0x6d,0xb5,0x86,0xde,0xff,0x00,0x63,
};
~~~

##  Test vector for CPace using group NIST P-384 and hash SHA-384


###  Test vectors for calculate_generator with group NIST P-384

~~~
  Inputs
    H   = SHA-384 with input block size 128 bytes.
    PRS = b'password' ; ZPAD length: 118 ;
    DSI = b'CPaceP384_XMD:SHA-384_SSWU_NU_'
    CI = b'\nAinitiator\nBresponder'
    CI = 0a41696e69746961746f720a42726573706f6e646572
    sid = 5b3773aa90e8f23c61563a4b645b276c
  Outputs
    string passed to map: (length: 199 bytes)
      0870617373776f726476000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      000000000000000000000000000000001e4350616365503338345f58
      4d443a5348412d3338345f535357555f4e555f160a41696e69746961
      746f720a42726573706f6e646572105b3773aa90e8f23c61563a4b64
      5b276c
    generator g: (length: 97 bytes)
      049a2397fd5cf8fa3ea34adf5a72b46516eb4cc6ab27594d40405c2f
      c656965b041b34ffff0f6b99dbc2e8c9273ba6c9a1e7eae6d07694df
      2eb48ea70be9321f0e9906f8327ba20f42bf6633fe9d7e03b7089562
      bf089448d2eaac9a4c6fce5505
~~~

###  Test vector for MSGa

~~~
  Inputs
    ADa = b'ADa'
    ya (big endian): (length: 48 bytes)
      0d3d3d5deff62ffc36d6d45acbb2649227dd931fa86921805ebf2c5a
      dba4ff0b7fe94a9b3878c0cf193f657230bbd0bd
  Outputs
    Ya: (length: 97 bytes)
      04ce004f548156542325f2f8eca9a8a328007d33aa283353b4608dd4
      4a3d926276a0fb2000b4fba0856ce01de5a78b2e9e98448e7859af2d
      f1b6f2a1921af8a9a2ad482f5cf25d63cb35cadf6077fc8c79964e61
      78536a69fecaf6f2ad95007a92
    MSGa: (length: 102 bytes)
      6104ce004f548156542325f2f8eca9a8a328007d33aa283353b4608d
      d44a3d926276a0fb2000b4fba0856ce01de5a78b2e9e98448e7859af
      2df1b6f2a1921af8a9a2ad482f5cf25d63cb35cadf6077fc8c79964e
      6178536a69fecaf6f2ad95007a9203414461
~~~

###  Test vector for MSGb

~~~
  Inputs
    ADb = b'ADb'
    yb (big endian): (length: 48 bytes)
      eeddc8115e25c0faa5a9c28dd5b973ac3a0cd3e0d2435d3ec0b3ed51
      bc286f2085df0f94e812cfd4e67a87bff4ae73bf
  Outputs
    Yb: (length: 97 bytes)
      04e35b85645e5d8321a2d349e285dbb3428fd709ceabb1332d145e88
      15b4205215dcca324cac5fc5350511610c0b40bcbf57f9429017d72c
      74800e1da20aa4d8cc0512c929cb326be3b6cdd5f33e4e957f79cf7d
      6bc8c3543b175b3b20eae23259
    MSGb: (length: 102 bytes)
      6104e35b85645e5d8321a2d349e285dbb3428fd709ceabb1332d145e
      8815b4205215dcca324cac5fc5350511610c0b40bcbf57f9429017d7
      2c74800e1da20aa4d8cc0512c929cb326be3b6cdd5f33e4e957f79cf
      7d6bc8c3543b175b3b20eae2325903414462
~~~

###  Test vector for secret points K

~~~
    scalar_mult_vfy(ya,Yb): (length: 48 bytes)
      e6406a79c7049287953f136c200c015e9b65972883aee5eb58b95dd9
      b96ae8d0980f5e869768fc049cefa16fb5c5fdfb
    scalar_mult_vfy(yb,Ya): (length: 48 bytes)
      e6406a79c7049287953f136c200c015e9b65972883aee5eb58b95dd9
      b96ae8d0980f5e869768fc049cefa16fb5c5fdfb
~~~


###  Test vector for ISK calculation initiator/responder

~~~
    unordered cat of transcript : (length: 204 bytes)
      6104ce004f548156542325f2f8eca9a8a328007d33aa283353b4608d
      d44a3d926276a0fb2000b4fba0856ce01de5a78b2e9e98448e7859af
      2df1b6f2a1921af8a9a2ad482f5cf25d63cb35cadf6077fc8c79964e
      6178536a69fecaf6f2ad95007a92034144616104e35b85645e5d8321
      a2d349e285dbb3428fd709ceabb1332d145e8815b4205215dcca324c
      ac5fc5350511610c0b40bcbf57f9429017d72c74800e1da20aa4d8cc
      0512c929cb326be3b6cdd5f33e4e957f79cf7d6bc8c3543b175b3b20
      eae2325903414462
    input to final ISK hash: (length: 305 bytes)
      224350616365503338345f584d443a5348412d3338345f535357555f
      4e555f5f49534b105b3773aa90e8f23c61563a4b645b276c30e6406a
      79c7049287953f136c200c015e9b65972883aee5eb58b95dd9b96ae8
      d0980f5e869768fc049cefa16fb5c5fdfb6104ce004f548156542325
      f2f8eca9a8a328007d33aa283353b4608dd44a3d926276a0fb2000b4
      fba0856ce01de5a78b2e9e98448e7859af2df1b6f2a1921af8a9a2ad
      482f5cf25d63cb35cadf6077fc8c79964e6178536a69fecaf6f2ad95
      007a92034144616104e35b85645e5d8321a2d349e285dbb3428fd709
      ceabb1332d145e8815b4205215dcca324cac5fc5350511610c0b40bc
      bf57f9429017d72c74800e1da20aa4d8cc0512c929cb326be3b6cdd5
      f33e4e957f79cf7d6bc8c3543b175b3b20eae2325903414462
    ISK result: (length: 48 bytes)
      f0098a081504c1ee7bb139e9744fe554e3198c31dca2da7f882c6be4
      4f4ee6bc764d322178f478d26edf084536ddfd6f
~~~

###  Test vector for ISK calculation parallel execution

~~~
    ordered cat of transcript : (length: 204 bytes)
      6104e35b85645e5d8321a2d349e285dbb3428fd709ceabb1332d145e
      8815b4205215dcca324cac5fc5350511610c0b40bcbf57f9429017d7
      2c74800e1da20aa4d8cc0512c929cb326be3b6cdd5f33e4e957f79cf
      7d6bc8c3543b175b3b20eae23259034144626104ce004f5481565423
      25f2f8eca9a8a328007d33aa283353b4608dd44a3d926276a0fb2000
      b4fba0856ce01de5a78b2e9e98448e7859af2df1b6f2a1921af8a9a2
      ad482f5cf25d63cb35cadf6077fc8c79964e6178536a69fecaf6f2ad
      95007a9203414461
    input to final ISK hash: (length: 305 bytes)
      224350616365503338345f584d443a5348412d3338345f535357555f
      4e555f5f49534b105b3773aa90e8f23c61563a4b645b276c30e6406a
      79c7049287953f136c200c015e9b65972883aee5eb58b95dd9b96ae8
      d0980f5e869768fc049cefa16fb5c5fdfb6104e35b85645e5d8321a2
      d349e285dbb3428fd709ceabb1332d145e8815b4205215dcca324cac
      5fc5350511610c0b40bcbf57f9429017d72c74800e1da20aa4d8cc05
      12c929cb326be3b6cdd5f33e4e957f79cf7d6bc8c3543b175b3b20ea
      e23259034144626104ce004f548156542325f2f8eca9a8a328007d33
      aa283353b4608dd44a3d926276a0fb2000b4fba0856ce01de5a78b2e
      9e98448e7859af2df1b6f2a1921af8a9a2ad482f5cf25d63cb35cadf
      6077fc8c79964e6178536a69fecaf6f2ad95007a9203414461
    ISK result: (length: 48 bytes)
      4f81f51c2104d0e9b4a618f4df3ef63cd31e6bb624a6b2760ad6a78e
      9884ddc5458e4bf333ca80ba0bffe7e165552553
~~~

###  Corresponding ANSI-C initializers

~~~
const uint8_t tc_PRS[] = {
 0x70,0x61,0x73,0x73,0x77,0x6f,0x72,0x64,
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
 0x04,0x9a,0x23,0x97,0xfd,0x5c,0xf8,0xfa,0x3e,0xa3,0x4a,0xdf,
 0x5a,0x72,0xb4,0x65,0x16,0xeb,0x4c,0xc6,0xab,0x27,0x59,0x4d,
 0x40,0x40,0x5c,0x2f,0xc6,0x56,0x96,0x5b,0x04,0x1b,0x34,0xff,
 0xff,0x0f,0x6b,0x99,0xdb,0xc2,0xe8,0xc9,0x27,0x3b,0xa6,0xc9,
 0xa1,0xe7,0xea,0xe6,0xd0,0x76,0x94,0xdf,0x2e,0xb4,0x8e,0xa7,
 0x0b,0xe9,0x32,0x1f,0x0e,0x99,0x06,0xf8,0x32,0x7b,0xa2,0x0f,
 0x42,0xbf,0x66,0x33,0xfe,0x9d,0x7e,0x03,0xb7,0x08,0x95,0x62,
 0xbf,0x08,0x94,0x48,0xd2,0xea,0xac,0x9a,0x4c,0x6f,0xce,0x55,
 0x05,
};
const uint8_t tc_ya[] = {
 0x0d,0x3d,0x3d,0x5d,0xef,0xf6,0x2f,0xfc,0x36,0xd6,0xd4,0x5a,
 0xcb,0xb2,0x64,0x92,0x27,0xdd,0x93,0x1f,0xa8,0x69,0x21,0x80,
 0x5e,0xbf,0x2c,0x5a,0xdb,0xa4,0xff,0x0b,0x7f,0xe9,0x4a,0x9b,
 0x38,0x78,0xc0,0xcf,0x19,0x3f,0x65,0x72,0x30,0xbb,0xd0,0xbd,
};
const uint8_t tc_ADa[] = {
 0x41,0x44,0x61,
};
const uint8_t tc_Ya[] = {
 0x04,0xce,0x00,0x4f,0x54,0x81,0x56,0x54,0x23,0x25,0xf2,0xf8,
 0xec,0xa9,0xa8,0xa3,0x28,0x00,0x7d,0x33,0xaa,0x28,0x33,0x53,
 0xb4,0x60,0x8d,0xd4,0x4a,0x3d,0x92,0x62,0x76,0xa0,0xfb,0x20,
 0x00,0xb4,0xfb,0xa0,0x85,0x6c,0xe0,0x1d,0xe5,0xa7,0x8b,0x2e,
 0x9e,0x98,0x44,0x8e,0x78,0x59,0xaf,0x2d,0xf1,0xb6,0xf2,0xa1,
 0x92,0x1a,0xf8,0xa9,0xa2,0xad,0x48,0x2f,0x5c,0xf2,0x5d,0x63,
 0xcb,0x35,0xca,0xdf,0x60,0x77,0xfc,0x8c,0x79,0x96,0x4e,0x61,
 0x78,0x53,0x6a,0x69,0xfe,0xca,0xf6,0xf2,0xad,0x95,0x00,0x7a,
 0x92,
};
const uint8_t tc_yb[] = {
 0xee,0xdd,0xc8,0x11,0x5e,0x25,0xc0,0xfa,0xa5,0xa9,0xc2,0x8d,
 0xd5,0xb9,0x73,0xac,0x3a,0x0c,0xd3,0xe0,0xd2,0x43,0x5d,0x3e,
 0xc0,0xb3,0xed,0x51,0xbc,0x28,0x6f,0x20,0x85,0xdf,0x0f,0x94,
 0xe8,0x12,0xcf,0xd4,0xe6,0x7a,0x87,0xbf,0xf4,0xae,0x73,0xbf,
};
const uint8_t tc_ADb[] = {
 0x41,0x44,0x62,
};
const uint8_t tc_Yb[] = {
 0x04,0xe3,0x5b,0x85,0x64,0x5e,0x5d,0x83,0x21,0xa2,0xd3,0x49,
 0xe2,0x85,0xdb,0xb3,0x42,0x8f,0xd7,0x09,0xce,0xab,0xb1,0x33,
 0x2d,0x14,0x5e,0x88,0x15,0xb4,0x20,0x52,0x15,0xdc,0xca,0x32,
 0x4c,0xac,0x5f,0xc5,0x35,0x05,0x11,0x61,0x0c,0x0b,0x40,0xbc,
 0xbf,0x57,0xf9,0x42,0x90,0x17,0xd7,0x2c,0x74,0x80,0x0e,0x1d,
 0xa2,0x0a,0xa4,0xd8,0xcc,0x05,0x12,0xc9,0x29,0xcb,0x32,0x6b,
 0xe3,0xb6,0xcd,0xd5,0xf3,0x3e,0x4e,0x95,0x7f,0x79,0xcf,0x7d,
 0x6b,0xc8,0xc3,0x54,0x3b,0x17,0x5b,0x3b,0x20,0xea,0xe2,0x32,
 0x59,
};
const uint8_t tc_K[] = {
 0xe6,0x40,0x6a,0x79,0xc7,0x04,0x92,0x87,0x95,0x3f,0x13,0x6c,
 0x20,0x0c,0x01,0x5e,0x9b,0x65,0x97,0x28,0x83,0xae,0xe5,0xeb,
 0x58,0xb9,0x5d,0xd9,0xb9,0x6a,0xe8,0xd0,0x98,0x0f,0x5e,0x86,
 0x97,0x68,0xfc,0x04,0x9c,0xef,0xa1,0x6f,0xb5,0xc5,0xfd,0xfb,
};
const uint8_t tc_ISK_IR[] = {
 0xf0,0x09,0x8a,0x08,0x15,0x04,0xc1,0xee,0x7b,0xb1,0x39,0xe9,
 0x74,0x4f,0xe5,0x54,0xe3,0x19,0x8c,0x31,0xdc,0xa2,0xda,0x7f,
 0x88,0x2c,0x6b,0xe4,0x4f,0x4e,0xe6,0xbc,0x76,0x4d,0x32,0x21,
 0x78,0xf4,0x78,0xd2,0x6e,0xdf,0x08,0x45,0x36,0xdd,0xfd,0x6f,
};
const uint8_t tc_ISK_SY[] = {
 0x4f,0x81,0xf5,0x1c,0x21,0x04,0xd0,0xe9,0xb4,0xa6,0x18,0xf4,
 0xdf,0x3e,0xf6,0x3c,0xd3,0x1e,0x6b,0xb6,0x24,0xa6,0xb2,0x76,
 0x0a,0xd6,0xa7,0x8e,0x98,0x84,0xdd,0xc5,0x45,0x8e,0x4b,0xf3,
 0x33,0xca,0x80,0xba,0x0b,0xff,0xe7,0xe1,0x65,0x55,0x25,0x53,
};
~~~

##  Test vector for CPace using group NIST P-521 and hash SHA-512


###  Test vectors for calculate_generator with group NIST P-521

~~~
  Inputs
    H   = SHA-512 with input block size 128 bytes.
    PRS = b'password' ; ZPAD length: 118 ;
    DSI = b'CPaceP521_XMD:SHA-512_SSWU_NU_'
    CI = b'\nAinitiator\nBresponder'
    CI = 0a41696e69746961746f720a42726573706f6e646572
    sid = 7e4b4791d6a8ef019b936c79fb7f2c57
  Outputs
    string passed to map: (length: 199 bytes)
      0870617373776f726476000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      000000000000000000000000000000001e4350616365503532315f58
      4d443a5348412d3531325f535357555f4e555f160a41696e69746961
      746f720a42726573706f6e646572107e4b4791d6a8ef019b936c79fb
      7f2c57
    generator g: (length: 133 bytes)
      0401fa498271cb395616ea73faaa7bce3b2a52fb16cc1a9dc6e1e229
      fcd6724746aa8dd0030dfabc94a53cd39636d6d3d47ed275c9900458
      a40b1b20ac3248b9f024cc0033dd49aa84cb9f97e5f04c8b7a9778d9
      328790ca7bdf1d492b7e662954af96890b32680209caaeceb652aaf0
      d705175968ec43c3590b93c81a581f9cccf4f5d2d9
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
      040115dce4775b5253b8483e77e1a9368e4766f326966287127f2a83
      91b0eb257ef058501fe7eddd95e72a01747195d65514ddc273ca4c79
      0e67560e98be194b3a07bf018e841c4ca119b36ea78246eec26178b3
      72aca02a33c7b5cee0db9c38828a11c1a7691fa2486b4053cfcf94ec
      f742d669eec7c629b0de88da9c1829add203664ea5
    MSGa: (length: 139 bytes)
      c285040115dce4775b5253b8483e77e1a9368e4766f326966287127f
      2a8391b0eb257ef058501fe7eddd95e72a01747195d65514ddc273ca
      4c790e67560e98be194b3a07bf018e841c4ca119b36ea78246eec261
      78b372aca02a33c7b5cee0db9c38828a11c1a7691fa2486b4053cfcf
      94ecf742d669eec7c629b0de88da9c1829add203664ea503414461
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
      04016f0cc4e2c6d5a836a108c3e490ed4d03d2971ba51d0613f4eea8
      742dbc0cb3779e7eb65b9637e88e8de41783127fcad0e2902051d367
      571d55f0d48e0b0b32b2f3012ccdfebdd5f508a5cf30456a8f957174
      41fc0968a1fdf88cf0bc25558839781747b79e35a3e8a309983c2893
      06ceb93415a8c3723cf4c25aba8260c37455f228a8
    MSGb: (length: 139 bytes)
      c28504016f0cc4e2c6d5a836a108c3e490ed4d03d2971ba51d0613f4
      eea8742dbc0cb3779e7eb65b9637e88e8de41783127fcad0e2902051
      d367571d55f0d48e0b0b32b2f3012ccdfebdd5f508a5cf30456a8f95
      717441fc0968a1fdf88cf0bc25558839781747b79e35a3e8a309983c
      289306ceb93415a8c3723cf4c25aba8260c37455f228a803414462
~~~

###  Test vector for secret points K

~~~
    scalar_mult_vfy(ya,Yb): (length: 66 bytes)
      00a2b32f0d1f346d1e5479df5b55cb28eb7e1df1b123aaa8a2405e2b
      1a629af879bf8feae62a94dcd1c0238d644e4eb828541e431e992405
      0d4d8716c8b0fb145bf2
    scalar_mult_vfy(yb,Ya): (length: 66 bytes)
      00a2b32f0d1f346d1e5479df5b55cb28eb7e1df1b123aaa8a2405e2b
      1a629af879bf8feae62a94dcd1c0238d644e4eb828541e431e992405
      0d4d8716c8b0fb145bf2
~~~


###  Test vector for ISK calculation initiator/responder

~~~
    unordered cat of transcript : (length: 278 bytes)
      c285040115dce4775b5253b8483e77e1a9368e4766f326966287127f
      2a8391b0eb257ef058501fe7eddd95e72a01747195d65514ddc273ca
      4c790e67560e98be194b3a07bf018e841c4ca119b36ea78246eec261
      78b372aca02a33c7b5cee0db9c38828a11c1a7691fa2486b4053cfcf
      94ecf742d669eec7c629b0de88da9c1829add203664ea503414461c2
      8504016f0cc4e2c6d5a836a108c3e490ed4d03d2971ba51d0613f4ee
      a8742dbc0cb3779e7eb65b9637e88e8de41783127fcad0e2902051d3
      67571d55f0d48e0b0b32b2f3012ccdfebdd5f508a5cf30456a8f9571
      7441fc0968a1fdf88cf0bc25558839781747b79e35a3e8a309983c28
      9306ceb93415a8c3723cf4c25aba8260c37455f228a803414462
    input to final ISK hash: (length: 397 bytes)
      224350616365503532315f584d443a5348412d3531325f535357555f
      4e555f5f49534b107e4b4791d6a8ef019b936c79fb7f2c574200a2b3
      2f0d1f346d1e5479df5b55cb28eb7e1df1b123aaa8a2405e2b1a629a
      f879bf8feae62a94dcd1c0238d644e4eb828541e431e9924050d4d87
      16c8b0fb145bf2c285040115dce4775b5253b8483e77e1a9368e4766
      f326966287127f2a8391b0eb257ef058501fe7eddd95e72a01747195
      d65514ddc273ca4c790e67560e98be194b3a07bf018e841c4ca119b3
      6ea78246eec26178b372aca02a33c7b5cee0db9c38828a11c1a7691f
      a2486b4053cfcf94ecf742d669eec7c629b0de88da9c1829add20366
      4ea503414461c28504016f0cc4e2c6d5a836a108c3e490ed4d03d297
      1ba51d0613f4eea8742dbc0cb3779e7eb65b9637e88e8de41783127f
      cad0e2902051d367571d55f0d48e0b0b32b2f3012ccdfebdd5f508a5
      cf30456a8f95717441fc0968a1fdf88cf0bc25558839781747b79e35
      a3e8a309983c289306ceb93415a8c3723cf4c25aba8260c37455f228
      a803414462
    ISK result: (length: 64 bytes)
      65ea5240c129e516c75c7321271a23720d8454dddd3adc51a05df949
      3a106d6fdb5cbd757868945c756e71728d9503ea13e46bf80467e722
      676e72b3856ce95d
~~~

###  Test vector for ISK calculation parallel execution

~~~
    ordered cat of transcript : (length: 278 bytes)
      c28504016f0cc4e2c6d5a836a108c3e490ed4d03d2971ba51d0613f4
      eea8742dbc0cb3779e7eb65b9637e88e8de41783127fcad0e2902051
      d367571d55f0d48e0b0b32b2f3012ccdfebdd5f508a5cf30456a8f95
      717441fc0968a1fdf88cf0bc25558839781747b79e35a3e8a309983c
      289306ceb93415a8c3723cf4c25aba8260c37455f228a803414462c2
      85040115dce4775b5253b8483e77e1a9368e4766f326966287127f2a
      8391b0eb257ef058501fe7eddd95e72a01747195d65514ddc273ca4c
      790e67560e98be194b3a07bf018e841c4ca119b36ea78246eec26178
      b372aca02a33c7b5cee0db9c38828a11c1a7691fa2486b4053cfcf94
      ecf742d669eec7c629b0de88da9c1829add203664ea503414461
    input to final ISK hash: (length: 397 bytes)
      224350616365503532315f584d443a5348412d3531325f535357555f
      4e555f5f49534b107e4b4791d6a8ef019b936c79fb7f2c574200a2b3
      2f0d1f346d1e5479df5b55cb28eb7e1df1b123aaa8a2405e2b1a629a
      f879bf8feae62a94dcd1c0238d644e4eb828541e431e9924050d4d87
      16c8b0fb145bf2c28504016f0cc4e2c6d5a836a108c3e490ed4d03d2
      971ba51d0613f4eea8742dbc0cb3779e7eb65b9637e88e8de4178312
      7fcad0e2902051d367571d55f0d48e0b0b32b2f3012ccdfebdd5f508
      a5cf30456a8f95717441fc0968a1fdf88cf0bc25558839781747b79e
      35a3e8a309983c289306ceb93415a8c3723cf4c25aba8260c37455f2
      28a803414462c285040115dce4775b5253b8483e77e1a9368e4766f3
      26966287127f2a8391b0eb257ef058501fe7eddd95e72a01747195d6
      5514ddc273ca4c790e67560e98be194b3a07bf018e841c4ca119b36e
      a78246eec26178b372aca02a33c7b5cee0db9c38828a11c1a7691fa2
      486b4053cfcf94ecf742d669eec7c629b0de88da9c1829add203664e
      a503414461
    ISK result: (length: 64 bytes)
      ad0a5988b4629b1ed37b49aebe2944c94b31cc76c39b2644cff5c28c
      58ad1223dbd3f2afaa800c3d5b55ae16aa46b68b22f878c962600813
      06cac7f23bac864d
~~~

###  Corresponding ANSI-C initializers

~~~
const uint8_t tc_PRS[] = {
 0x70,0x61,0x73,0x73,0x77,0x6f,0x72,0x64,
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
 0x04,0x01,0xfa,0x49,0x82,0x71,0xcb,0x39,0x56,0x16,0xea,0x73,
 0xfa,0xaa,0x7b,0xce,0x3b,0x2a,0x52,0xfb,0x16,0xcc,0x1a,0x9d,
 0xc6,0xe1,0xe2,0x29,0xfc,0xd6,0x72,0x47,0x46,0xaa,0x8d,0xd0,
 0x03,0x0d,0xfa,0xbc,0x94,0xa5,0x3c,0xd3,0x96,0x36,0xd6,0xd3,
 0xd4,0x7e,0xd2,0x75,0xc9,0x90,0x04,0x58,0xa4,0x0b,0x1b,0x20,
 0xac,0x32,0x48,0xb9,0xf0,0x24,0xcc,0x00,0x33,0xdd,0x49,0xaa,
 0x84,0xcb,0x9f,0x97,0xe5,0xf0,0x4c,0x8b,0x7a,0x97,0x78,0xd9,
 0x32,0x87,0x90,0xca,0x7b,0xdf,0x1d,0x49,0x2b,0x7e,0x66,0x29,
 0x54,0xaf,0x96,0x89,0x0b,0x32,0x68,0x02,0x09,0xca,0xae,0xce,
 0xb6,0x52,0xaa,0xf0,0xd7,0x05,0x17,0x59,0x68,0xec,0x43,0xc3,
 0x59,0x0b,0x93,0xc8,0x1a,0x58,0x1f,0x9c,0xcc,0xf4,0xf5,0xd2,
 0xd9,
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
 0x04,0x01,0x15,0xdc,0xe4,0x77,0x5b,0x52,0x53,0xb8,0x48,0x3e,
 0x77,0xe1,0xa9,0x36,0x8e,0x47,0x66,0xf3,0x26,0x96,0x62,0x87,
 0x12,0x7f,0x2a,0x83,0x91,0xb0,0xeb,0x25,0x7e,0xf0,0x58,0x50,
 0x1f,0xe7,0xed,0xdd,0x95,0xe7,0x2a,0x01,0x74,0x71,0x95,0xd6,
 0x55,0x14,0xdd,0xc2,0x73,0xca,0x4c,0x79,0x0e,0x67,0x56,0x0e,
 0x98,0xbe,0x19,0x4b,0x3a,0x07,0xbf,0x01,0x8e,0x84,0x1c,0x4c,
 0xa1,0x19,0xb3,0x6e,0xa7,0x82,0x46,0xee,0xc2,0x61,0x78,0xb3,
 0x72,0xac,0xa0,0x2a,0x33,0xc7,0xb5,0xce,0xe0,0xdb,0x9c,0x38,
 0x82,0x8a,0x11,0xc1,0xa7,0x69,0x1f,0xa2,0x48,0x6b,0x40,0x53,
 0xcf,0xcf,0x94,0xec,0xf7,0x42,0xd6,0x69,0xee,0xc7,0xc6,0x29,
 0xb0,0xde,0x88,0xda,0x9c,0x18,0x29,0xad,0xd2,0x03,0x66,0x4e,
 0xa5,
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
 0x04,0x01,0x6f,0x0c,0xc4,0xe2,0xc6,0xd5,0xa8,0x36,0xa1,0x08,
 0xc3,0xe4,0x90,0xed,0x4d,0x03,0xd2,0x97,0x1b,0xa5,0x1d,0x06,
 0x13,0xf4,0xee,0xa8,0x74,0x2d,0xbc,0x0c,0xb3,0x77,0x9e,0x7e,
 0xb6,0x5b,0x96,0x37,0xe8,0x8e,0x8d,0xe4,0x17,0x83,0x12,0x7f,
 0xca,0xd0,0xe2,0x90,0x20,0x51,0xd3,0x67,0x57,0x1d,0x55,0xf0,
 0xd4,0x8e,0x0b,0x0b,0x32,0xb2,0xf3,0x01,0x2c,0xcd,0xfe,0xbd,
 0xd5,0xf5,0x08,0xa5,0xcf,0x30,0x45,0x6a,0x8f,0x95,0x71,0x74,
 0x41,0xfc,0x09,0x68,0xa1,0xfd,0xf8,0x8c,0xf0,0xbc,0x25,0x55,
 0x88,0x39,0x78,0x17,0x47,0xb7,0x9e,0x35,0xa3,0xe8,0xa3,0x09,
 0x98,0x3c,0x28,0x93,0x06,0xce,0xb9,0x34,0x15,0xa8,0xc3,0x72,
 0x3c,0xf4,0xc2,0x5a,0xba,0x82,0x60,0xc3,0x74,0x55,0xf2,0x28,
 0xa8,
};
const uint8_t tc_K[] = {
 0x00,0xa2,0xb3,0x2f,0x0d,0x1f,0x34,0x6d,0x1e,0x54,0x79,0xdf,
 0x5b,0x55,0xcb,0x28,0xeb,0x7e,0x1d,0xf1,0xb1,0x23,0xaa,0xa8,
 0xa2,0x40,0x5e,0x2b,0x1a,0x62,0x9a,0xf8,0x79,0xbf,0x8f,0xea,
 0xe6,0x2a,0x94,0xdc,0xd1,0xc0,0x23,0x8d,0x64,0x4e,0x4e,0xb8,
 0x28,0x54,0x1e,0x43,0x1e,0x99,0x24,0x05,0x0d,0x4d,0x87,0x16,
 0xc8,0xb0,0xfb,0x14,0x5b,0xf2,
};
const uint8_t tc_ISK_IR[] = {
 0x65,0xea,0x52,0x40,0xc1,0x29,0xe5,0x16,0xc7,0x5c,0x73,0x21,
 0x27,0x1a,0x23,0x72,0x0d,0x84,0x54,0xdd,0xdd,0x3a,0xdc,0x51,
 0xa0,0x5d,0xf9,0x49,0x3a,0x10,0x6d,0x6f,0xdb,0x5c,0xbd,0x75,
 0x78,0x68,0x94,0x5c,0x75,0x6e,0x71,0x72,0x8d,0x95,0x03,0xea,
 0x13,0xe4,0x6b,0xf8,0x04,0x67,0xe7,0x22,0x67,0x6e,0x72,0xb3,
 0x85,0x6c,0xe9,0x5d,
};
const uint8_t tc_ISK_SY[] = {
 0xad,0x0a,0x59,0x88,0xb4,0x62,0x9b,0x1e,0xd3,0x7b,0x49,0xae,
 0xbe,0x29,0x44,0xc9,0x4b,0x31,0xcc,0x76,0xc3,0x9b,0x26,0x44,
 0xcf,0xf5,0xc2,0x8c,0x58,0xad,0x12,0x23,0xdb,0xd3,0xf2,0xaf,
 0xaa,0x80,0x0c,0x3d,0x5b,0x55,0xae,0x16,0xaa,0x46,0xb6,0x8b,
 0x22,0xf8,0x78,0xc9,0x62,0x60,0x08,0x13,0x06,0xca,0xc7,0xf2,
 0x3b,0xac,0x86,0x4d,
};
~~~

