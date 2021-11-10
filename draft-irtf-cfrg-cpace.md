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
    org: IBM, Zürich Research Laboratory
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
parties for deriving a strong shared secret from a low-entropy secret (password) without
disclosing the secret to offline dictionary attacks.

The CPace method was tailored for constrained devices and
specifically considers efficiency and hardware side-channel attack mitigations at the protocol level.
CPace is designed to be compatible with any group of both prime- and non-prime order by explicitly
handling the complexity of cofactor clearing on the protcol level. CPace
comes with both, game-based and simulation based proofs where the latter provides composability guarantees.
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
calculated by the primitive. Common choices for H might be SHA512 {{?RFC6234}} or SHAKE256 {{FIPS202}}.
For considering both, variable-output-length primitives and fixed-length output primitives we use the following
notations and definitions which were chosen in line with the definitions in {?RFC6234}}

With H.b_in_bytes we denote the default output size in bytes corresponding to the symmetric
security level of the primitive. E.g. H.b_in_bytes = 64 for SHA512 and SHAKE256 and H.b_in_bytes = 32 for
SHA256 and SHAKE128. We use the notation H.hash(m) = H.hash(m, H.b_in_bytes) and let the hash primitive
output the default length if no length parameter is given.

With H.bmax_in_bytes we denote the maximum output size in octets supported by the hash primitive.

With H.s_in_bytes we denote the input block size used by H.
For instance, for SHA512 the input block size s_in_bytes is 128, while for SHAKE256 the
input block size amounts to 136 bytes.

For a given group G this document specifies how to define the following set of group-specific
functions and constants for the protocol execution. For making the implicit dependence of the respective
functions and constants on the group G transparent, we use a object-style notation
G.function_name() and G.constant_name.

With G.I we denote a unique octet string representation of the neutral element of group G.

g = G.calculate_generator(H, PRS,CI,sid). With calculate_generator we denote a function that outputs a
representation of a group element in G which is derived from input octet strings PRS, CI, sid using
the hash function primitive H.

y = G.sample_scalar(). This function returns a representation of a scalar value appropriate as a
private Diffie-Hellman key for group G.

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
binding CPace to one specific communication channel, if a common octet string representation for CI is
available for both protocol partners upon protocol start.

With sid we denote an OPTIONAL octet string input containing a session id. In application scenarios
where a higher-level protocol has established a unique sid this parameter can be used to bind the CPace protocol execution
to one specific session.

With ADa and ADb we denote OPTIONAL octet strings of parties A and B that contain associated public data
of the communication partners.
ADa and ADb could for instance include party identifiers or a protocol version (e.g. for avoiding downgrade attacks).
In a setting with clear initiator and responder roles the the information ADa sent by the initiator
can be helpful for the responder for identifying which among possibly several different passwords are to be used for
the given protocol session.

## Notation

With str1 \|\| str2 we denote concatenation of octet strings.

With oCAT(str1,str2) we denote ordered concatenation of octet strings such that oCAT(str1,str2) = str1 \|\| str2
if str2 > str1 and oCAT(str1,str2) = str2 \|\| str1 otherwise.

CONCAT(str1,str2) defines a concatenation function that depends on the application scenario.
In applications where CPace is used without clear initiator and responder roles, i.e. where the ordering of
messages is not enforced by the protocol flow ordered concatenation SHALL BE used,
i.e. CONCAT(str1,str2) == oCAT(str1,str2).

In settings with defined initiator and responder roles
CONCAT(str1,str2) SHALL BE defined as unordered concatenation: CONCAT(str1,str2) == str1 \|\| str2.

With len(S) we denote the number of octets in a string S.

Finally, we let nil represent an empty octet string, i.e., len(nil) = 0.

With prepend_len(octet_string) we denote the octet sequence that is obtained from prepending
the length of the octet string as an utf-8 string to the byte sequence itself. This will prepend one
single octet for sequences shorter than 128 bytes and more octets otherwise.

With prefix_free_cat(a0,a1, ...) we denote a function that outputs the prefix-free encoding of
all input octet strings as the concatenation of the individual strings with their respective
length prepended: prepend_len(a0) \|\| prepend_len(a1) \|\| ... . Use of this function allows for a
easy parsing of strings and guarantees a prefix-free encoding.

With sample_random_bytes(n) we denote a function that returns n octets uniformly sampled between 0 and 255.
With zero_bytes(n) we denote a function that returns n octets with value 0.

With ISK we denote the intermediate session key output string provided by CPace. It is RECOMMENDED to convert the
intermediate session key ISK ot a final session key by using a suitable KDF function prior to using the key in a
higher-level protocol.

With G.DSI we denote domain-separation identifier strings specific for a given CPace cipher suite.

## Hashing of the password related string in CPace

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
- a group G with associated definitions for G.sample_scalar(), G.scalar_mult() and G. scalar_mult.vfy() and G.calculate_generator() functions and an associated domain separation string G.DSI.
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

# Test vectors

##  Test vector for CPace using group X25519 and hash SHA512


###  Test vectors for calculate_generator with group X25519

~~~
  Inputs
    H   = SHA512 with input block size 128 bytes.
    PRS = b'password' ; ZPAD length: 118 ; DSI = b'CPace255'
    CI = b'\nAinitiator\nBresponder'
    CI = 0a41696e69746961746f720a42726573706f6e646572
    sid = 7e4b4791d6a8ef019b936c79fb7f2c57
  Outputs
    hash generator string: (length: 32 bytes)
      5cb423cc3a5a9355bb90fceb67c97a7b5787df93faf4562789d705e3
      b2848d8
    after decoding to coordinate: (length: 32 bytes)
      5cb423cc3a5a9355bb90fceb67c97a7b5787df93faf4562789d705e3
      b2848d0
    generator g: (length: 32 bytes)
      2cddcc94b38d059a7b305bb0b8934b5b1ed45c5a5cb039f9cd00ab11
      ce92730
~~~

###  Test vector for MSGa

~~~
  Inputs
    ADa = b'ADa'
    ya (little endian): (length: 32 bytes)
      232527dee2cfde76fb425b6d88818630eea7ea263fac28d89f52d096
      c563b1e
  Outputs
    Ya: (length: 32 bytes)
      5448fd9633734e703210b61d5cabb1310a28382895d56d490551436a
      b339864
    MSGa: (length: 37 bytes)
      205448fd9633734e703210b61d5cabb1310a28382895d56d49055143
      6ab33986440341446
~~~

###  Test vector for MSGb

~~~
  Inputs
    ADb = b'ADb'
    yb (little endian): (length: 32 bytes)
      871ebb1d5ecbeffa5a47e32c40d2da6894d9f2865efdad6ad8535a1b
      e7e487d
  Outputs
    Yb: (length: 32 bytes)
      d8fe025158c0c08d7ea93a84718a56111bff54bf4b960c8343e64f02
      5eead60
    MSGb: (length: 37 bytes)
      20d8fe025158c0c08d7ea93a84718a56111bff54bf4b960c8343e64f
      025eead6080341446
~~~

###  Test vector for secret points K

~~~
    scalar_mult_vfy(ya,Yb): (length: 32 bytes)
      4aa59ccfda03691c3e9cf4dab329a13bcc9707e38f54e784e30f7843
      78dbcb4
    scalar_mult_vfy(yb,Ya): (length: 32 bytes)
      4aa59ccfda03691c3e9cf4dab329a13bcc9707e38f54e784e30f7843
      78dbcb4
~~~


###  Test vector for ISK calculation initiator/responder

~~~
    unordered cat of transcript : (length: 74 bytes)
      205448fd9633734e703210b61d5cabb1310a28382895d56d49055143
      6ab33986440341446120d8fe025158c0c08d7ea93a84718a56111bff
      54bf4b960c8343e64f025eead608034144
    input to final ISK hash: (length: 137 bytes)
      0c43506163653235355f49534b107e4b4791d6a8ef019b936c79fb7f
      2c57204aa59ccfda03691c3e9cf4dab329a13bcc9707e38f54e784e3
      0f784378dbcb49205448fd9633734e703210b61d5cabb1310a283828
      95d56d490551436ab33986440341446120d8fe025158c0c08d7ea93a
      84718a56111bff54bf4b960c8343e64f025eead6080341
    ISK result: (length: 64 bytes)
      eeaebbac8a5a057cf94c3e8dba6cf0edddb953357532d0028e3e0cd4
      a85ce7a4b42511d5fb06c60f3b0775c357f267ccc9e24b81338231b9
      a61855fcebd4a0
~~~

###  Test vector for ISK calculation parallel execution

~~~
    ordered cat of transcript : (length: 74 bytes)
      20d8fe025158c0c08d7ea93a84718a56111bff54bf4b960c8343e64f
      025eead60803414462205448fd9633734e703210b61d5cabb1310a28
      382895d56d490551436ab3398644034144
    input to final ISK hash: (length: 137 bytes)
      0c43506163653235355f49534b107e4b4791d6a8ef019b936c79fb7f
      2c57204aa59ccfda03691c3e9cf4dab329a13bcc9707e38f54e784e3
      0f784378dbcb4920d8fe025158c0c08d7ea93a84718a56111bff54bf
      4b960c8343e64f025eead60803414462205448fd9633734e703210b6
      1d5cabb1310a28382895d56d490551436ab33986440341
    ISK result: (length: 64 bytes)
      170a1df42f03da082b9d250be646be04c8c6b4490af17b27c4a0916f
      e8482289d10ea0534455ab578deb88dae75db4a8bf24fb111825e630
      2ad3c0d903341f
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

##  Test vector for CPace using group X448 and hash SHAKE256


###  Test vectors for calculate_generator with group X448

~~~
  Inputs
    H   = SHAKE256 with input block size 136 bytes.
    PRS = b'password' ; ZPAD length: 126 ; DSI = b'CPace448'
    CI = b'\nAinitiator\nBresponder'
    CI = 0a41696e69746961746f720a42726573706f6e646572
    sid = 5223e0cdc45d6575668d64c552004124
  Outputs
    hash generator string: (length: 56 bytes)
      c1658ad06392f4eb5a23294d49210744aea89bf56cd9d1497b0b6ca0
      d4a9172fedd1e9d8376794c166ebbe05b598c051cbad24b03892e84
    after decoding to coordinate: (length: 32 bytes)
      c1658ad06392f4eb5a23294d49210744aea89bf56cd9d1497b0b6ca0
      d4a9172
    generator g: (length: 56 bytes)
      402906591ba645f89b94dc93559c9c423a35d5eaf2878da0fd11b912
      aee50ffbf537a6b3bf72c28f3a12cf521eac520d2630806ee2b2f41
~~~

###  Test vector for MSGa

~~~
  Inputs
    ADa = b'ADa'
    ya (little endian): (length: 56 bytes)
      e7f541f33bf50afed97b2fafd43bed219d1a0dad7361ea576b25de79
      bcdcf50c0f238a18e865c8d5fd6b1768719e0a5a45b6c34b23852a9
  Outputs
    Ya: (length: 56 bytes)
      7a2454a2ffa18c09f8b5b60ac900f19d2d3fb7b01bb9cfe07d5ae99d
      27bf891aeb321c3563a17fbd45bb3b809565d16e15a951dc7e46600
    MSGa: (length: 61 bytes)
      387a2454a2ffa18c09f8b5b60ac900f19d2d3fb7b01bb9cfe07d5ae9
      9d27bf891aeb321c3563a17fbd45bb3b809565d16e15a951dc7e4660
      00034144
~~~

###  Test vector for MSGb

~~~
  Inputs
    ADb = b'ADb'
    yb (little endian): (length: 56 bytes)
      cbb76860fa66e048a2daea5f03fe88f5e57c1286a5ad770d6cb175b3
      3a0d4249c56d5d64e4550e8862da5c69cf5d04d66a1c61e88d349b0
  Outputs
    Yb: (length: 56 bytes)
      9dce85b5c3252bf80c41428324d4dead4160d99073da2a53f6eab677
      aae5559d295f91a336ca654e44e8b3831cd1b568107c7269a64651e
    MSGb: (length: 61 bytes)
      389dce85b5c3252bf80c41428324d4dead4160d99073da2a53f6eab6
      77aae5559d295f91a336ca654e44e8b3831cd1b568107c7269a64651
      e9034144
~~~

###  Test vector for secret points K

~~~
    scalar_mult_vfy(ya,Yb): (length: 56 bytes)
      8cb51a7fe5283c717ccc03be38a1948924db188581fef349ef08366c
      b110fdf0181e37576bdbe8c419d30b28ba89681eea2ce6cb0c5f932
    scalar_mult_vfy(yb,Ya): (length: 56 bytes)
      8cb51a7fe5283c717ccc03be38a1948924db188581fef349ef08366c
      b110fdf0181e37576bdbe8c419d30b28ba89681eea2ce6cb0c5f932
~~~


###  Test vector for ISK calculation initiator/responder

~~~
    unordered cat of transcript : (length: 122 bytes)
      387a2454a2ffa18c09f8b5b60ac900f19d2d3fb7b01bb9cfe07d5ae9
      9d27bf891aeb321c3563a17fbd45bb3b809565d16e15a951dc7e4660
      0003414461389dce85b5c3252bf80c41428324d4dead4160d99073da
      2a53f6eab677aae5559d295f91a336ca654e44e8b3831cd1b568107c
      7269a64651e90341
    input to final ISK hash: (length: 209 bytes)
      0c43506163653434385f49534b105223e0cdc45d6575668d64c55200
      4124388cb51a7fe5283c717ccc03be38a1948924db188581fef349ef
      08366cb110fdf0181e37576bdbe8c419d30b28ba89681eea2ce6cb0c
      5f9323387a2454a2ffa18c09f8b5b60ac900f19d2d3fb7b01bb9cfe0
      7d5ae99d27bf891aeb321c3563a17fbd45bb3b809565d16e15a951dc
      7e46600003414461389dce85b5c3252bf80c41428324d4dead4160d9
      9073da2a53f6eab677aae5559d295f91a336ca654e44e8b3831cd1b5
      68107c7269a64651e90
    ISK result: (length: 64 bytes)
      69c13d8ea9257357439f74198ab5a7943106f1b98dd69f3c58b017c2
      47d93c7262a341d6c47016e61fc97809ec30c8cd685f8dd5c2e9f464
      83e1faf02c67b9
~~~

###  Test vector for ISK calculation parallel execution

~~~
    ordered cat of transcript : (length: 122 bytes)
      389dce85b5c3252bf80c41428324d4dead4160d99073da2a53f6eab6
      77aae5559d295f91a336ca654e44e8b3831cd1b568107c7269a64651
      e903414462387a2454a2ffa18c09f8b5b60ac900f19d2d3fb7b01bb9
      cfe07d5ae99d27bf891aeb321c3563a17fbd45bb3b809565d16e15a9
      51dc7e4660000341
    input to final ISK hash: (length: 209 bytes)
      0c43506163653434385f49534b105223e0cdc45d6575668d64c55200
      4124388cb51a7fe5283c717ccc03be38a1948924db188581fef349ef
      08366cb110fdf0181e37576bdbe8c419d30b28ba89681eea2ce6cb0c
      5f9323389dce85b5c3252bf80c41428324d4dead4160d99073da2a53
      f6eab677aae5559d295f91a336ca654e44e8b3831cd1b568107c7269
      a64651e903414462387a2454a2ffa18c09f8b5b60ac900f19d2d3fb7
      b01bb9cfe07d5ae99d27bf891aeb321c3563a17fbd45bb3b809565d1
      6e15a951dc7e4660000
    ISK result: (length: 64 bytes)
      83022985a2b757a59418c49c842c5f623f70f629ec18d1d70236119e
      ffcc5ba3015a81b0ab00ca64afdce78f76af749718ec4710350320d9
      106162da846ee9
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

##  Test vector for CPace using group ristretto255 and hash SHA512


###  Test vectors for calculate_generator with group ristretto255

~~~
  Inputs
    H   = SHA512 with input block size 128 bytes.
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
      72107e4b4791d6a8ef019b936c79fb
    hash result: (length: 64 bytes)
      d1fefeb0032c916c88e31a74c8f46308ae6db6ce4ef9971bf9a0c530
      f829a230565c9824d8d2181ca4caa0b6ff2978d744d92a987e95dc78
      feacf2f2b35004
    encoded generator g: (length: 32 bytes)
      80a71e8a8a0c2b4dd351c21fabfa99c8f01efb1b42f0c7025c4e24de
      8ae2cd1
~~~


###  Test vector for MSGa

~~~
  Inputs
    ADa = b'ADa'
    ya (little endian): (length: 32 bytes)
      1433dd19359992d4e06d740d3993d429af6338ffb4531ce175d22449
      853a790
  Outputs
    Ya: (length: 32 bytes)
      68af16733a0a0ae7aa68768a83b91a25c11e41996ca833bdf844cf0c
      f8d36d6
    MSGa: (length: 37 bytes)
      2068af16733a0a0ae7aa68768a83b91a25c11e41996ca833bdf844cf
      0cf8d36d6f0341446
~~~

###  Test vector for MSGb

~~~
  Inputs
    ADb = b'ADb'
    yb (little endian): (length: 32 bytes)
      0e6566d32d80a5a1135f99c27f2d637aa24da23027c3fa76b9d1cfd9
      742fdc0
  Outputs
    Yb: (length: 32 bytes)
      905cb62b365f497c8bb05c422ab66ad814ef0bd7e13dd55757e1a379
      43b0307
    MSGb: (length: 37 bytes)
      20905cb62b365f497c8bb05c422ab66ad814ef0bd7e13dd55757e1a3
      7943b0307b0341446
~~~

###  Test vector for secret points K

~~~
    scalar_mult_vfy(ya,Yb): (length: 32 bytes)
      0075247d9956cf507a3c6f5a961e42bd2a9006bc067e4112a5795afb
      fe3f784
    scalar_mult_vfy(yb,Ya): (length: 32 bytes)
      0075247d9956cf507a3c6f5a961e42bd2a9006bc067e4112a5795afb
      fe3f784
~~~


###  Test vector for ISK calculation initiator/responder

~~~
    unordered cat of transcript : (length: 74 bytes)
      2068af16733a0a0ae7aa68768a83b91a25c11e41996ca833bdf844cf
      0cf8d36d6f0341446120905cb62b365f497c8bb05c422ab66ad814ef
      0bd7e13dd55757e1a37943b0307b034144
    input to final ISK hash: (length: 146 bytes)
      15435061636572697374726574746f3235355f49534b107e4b4791d6
      a8ef019b936c79fb7f2c57200075247d9956cf507a3c6f5a961e42bd
      2a9006bc067e4112a5795afbfe3f784b2068af16733a0a0ae7aa6876
      8a83b91a25c11e41996ca833bdf844cf0cf8d36d6f0341446120905c
      b62b365f497c8bb05c422ab66ad814ef0bd7e13dd55757e1a37943b0
      307b034
    ISK result: (length: 64 bytes)
      eb3e5c2ca1df3849ae4ba385b705afc08c33662048d7853ed63bc3f2
      1c22c01f306d43b45df60f62ba698077d0809d542701021039f28385
      8467f03eae5f69
~~~

###  Test vector for ISK calculation parallel execution

~~~
    ordered cat of transcript : (length: 74 bytes)
      20905cb62b365f497c8bb05c422ab66ad814ef0bd7e13dd55757e1a3
      7943b0307b034144622068af16733a0a0ae7aa68768a83b91a25c11e
      41996ca833bdf844cf0cf8d36d6f034144
    input to final ISK hash: (length: 146 bytes)
      15435061636572697374726574746f3235355f49534b107e4b4791d6
      a8ef019b936c79fb7f2c57200075247d9956cf507a3c6f5a961e42bd
      2a9006bc067e4112a5795afbfe3f784b20905cb62b365f497c8bb05c
      422ab66ad814ef0bd7e13dd55757e1a37943b0307b034144622068af
      16733a0a0ae7aa68768a83b91a25c11e41996ca833bdf844cf0cf8d3
      6d6f034
    ISK result: (length: 64 bytes)
      444984cc07374662a5a6d6cd1943a8bf513b71ff180901cc9e12e337
      19ec9bb30ea3788ed2b8b5e097a708f29dfd83a2d43d13aaf6f53359
      c1a752a703c5d3
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

##  Test vector for CPace using group decaf448 and hash SHAKE256


###  Test vectors for calculate_generator with group decaf448

~~~
  Inputs
    H   = SHAKE256 with input block size 136 bytes.
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
      6f6e646572105223e0cdc45d6575668d64c552
    hash result: (length: 112 bytes)
      ae4cf9e238aa40b02814456e2dbb74c237d206931b6eff10dc709008
      62e51f64832c6f50a7f378954d9ed3f508fd43eb010b3de440290ccb
      8b0271a96d67197a927484c24f1221a04abf105e84e7c731487849a5
      9f073d61ee9439ce0a91019ed95fa1dbcb71aba8537681063114b
    encoded generator g: (length: 56 bytes)
      7245c964b4aee304eb8da88463d85d642c8a38a9a4e1c86507dcb1bb
      1cf3d4dabf6518c3fb928fc011a3fad4b11926b0727c8ef7c5f6d81
~~~


###  Test vector for MSGa

~~~
  Inputs
    ADa = b'ADa'
    ya (little endian): (length: 56 bytes)
      33d561f13cfc0dca279c30e8cde895175dc25483892819eba132d58c
      13c0462a8eb0d73fda941950594bef5191d8394691f86edffcad6c1
  Outputs
    Ya: (length: 56 bytes)
      64bab0e2e5b4e580b48c1cb27114baeefcbb00da0f791054145989b4
      8cf6e53b2ae929b4f61e197560a2c26897b1d505c4536e8267e6d7c
    MSGa: (length: 61 bytes)
      3864bab0e2e5b4e580b48c1cb27114baeefcbb00da0f791054145989
      b48cf6e53b2ae929b4f61e197560a2c26897b1d505c4536e8267e6d7
      c3034144
~~~

###  Test vector for MSGb

~~~
  Inputs
    ADb = b'ADb'
    yb (little endian): (length: 56 bytes)
      2523c969f68fa2b2aea294c2539ef36eb1e0558abd14712a7828f16a
      85ed2c7e77e2bdd418994405fb1b57b6bbaadd66849892aac9d8140
  Outputs
    Yb: (length: 56 bytes)
      c29b5b6da0052b720f2c4f8ffab9315d247dbd5090d360272f49daab
      f3cd933601cd99103416f19887a2f831fd851b5ff48e941def9c393
    MSGb: (length: 61 bytes)
      38c29b5b6da0052b720f2c4f8ffab9315d247dbd5090d360272f49da
      abf3cd933601cd99103416f19887a2f831fd851b5ff48e941def9c39
      39034144
~~~

###  Test vector for secret points K

~~~
    scalar_mult_vfy(ya,Yb): (length: 56 bytes)
      62b09c5f63f58fca11fc8432ff40adc47815a4286e277bb8cef92ea6
      65ebabf4f14f24211fe3ce08c1f983c307b67b06026cab3f7d7b179
    scalar_mult_vfy(yb,Ya): (length: 56 bytes)
      62b09c5f63f58fca11fc8432ff40adc47815a4286e277bb8cef92ea6
      65ebabf4f14f24211fe3ce08c1f983c307b67b06026cab3f7d7b179
~~~


###  Test vector for ISK calculation initiator/responder

~~~
    unordered cat of transcript : (length: 122 bytes)
      3864bab0e2e5b4e580b48c1cb27114baeefcbb00da0f791054145989
      b48cf6e53b2ae929b4f61e197560a2c26897b1d505c4536e8267e6d7
      c30341446138c29b5b6da0052b720f2c4f8ffab9315d247dbd5090d3
      60272f49daabf3cd933601cd99103416f19887a2f831fd851b5ff48e
      941def9c39390341
    input to final ISK hash: (length: 214 bytes)
      11435061636564656361663434385f49534b105223e0cdc45d657566
      8d64c5520041243862b09c5f63f58fca11fc8432ff40adc47815a428
      6e277bb8cef92ea665ebabf4f14f24211fe3ce08c1f983c307b67b06
      026cab3f7d7b17993864bab0e2e5b4e580b48c1cb27114baeefcbb00
      da0f791054145989b48cf6e53b2ae929b4f61e197560a2c26897b1d5
      05c4536e8267e6d7c30341446138c29b5b6da0052b720f2c4f8ffab9
      315d247dbd5090d360272f49daabf3cd933601cd99103416f19887a2
      f831fd851b5ff48e941def9c39390
    ISK result: (length: 64 bytes)
      6fb210448f0eb49f9058c9be0c42f3d58a8d51e31bddbe88c0751360
      d91f71ce4e7e7602cce4daee46be49b16f01b40d83bb0303df91d8c4
      01658fdb894256
~~~

###  Test vector for ISK calculation parallel execution

~~~
    ordered cat of transcript : (length: 122 bytes)
      38c29b5b6da0052b720f2c4f8ffab9315d247dbd5090d360272f49da
      abf3cd933601cd99103416f19887a2f831fd851b5ff48e941def9c39
      39034144623864bab0e2e5b4e580b48c1cb27114baeefcbb00da0f79
      1054145989b48cf6e53b2ae929b4f61e197560a2c26897b1d505c453
      6e8267e6d7c30341
    input to final ISK hash: (length: 214 bytes)
      11435061636564656361663434385f49534b105223e0cdc45d657566
      8d64c5520041243862b09c5f63f58fca11fc8432ff40adc47815a428
      6e277bb8cef92ea665ebabf4f14f24211fe3ce08c1f983c307b67b06
      026cab3f7d7b179938c29b5b6da0052b720f2c4f8ffab9315d247dbd
      5090d360272f49daabf3cd933601cd99103416f19887a2f831fd851b
      5ff48e941def9c3939034144623864bab0e2e5b4e580b48c1cb27114
      baeefcbb00da0f791054145989b48cf6e53b2ae929b4f61e197560a2
      c26897b1d505c4536e8267e6d7c30
    ISK result: (length: 64 bytes)
      a37f87e303ebe668ef9b541e0c780c56d21a9d376dfe1586fb4335a4
      b9d415c540d8f23efdb02c9b1d2d3a6442b4e5a70cfc436eeea77a96
      441e38018ee2d7
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

##  Test vector for CPace using group NIST P-256 and hash SHA256


###  Test vectors for calculate_generator with group NIST P-256

~~~
  Inputs
    H   = SHA256 with input block size 64 bytes.
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
      706f6e6465721034b36454cab2e7842c389f7d88ec
    generator g: (length: 65 bytes)
      04617d04154ab8670aa9b4099a3fd5e9c6fa365afb834eaa33e44648
      092c4278849697c7e77daa946c9997217bd28fc23b6762a03dde504c
      9de1ea8d9df62701
~~~

###  Test vector for MSGa

~~~
  Inputs
    ADa = b'ADa'
    ya (big endian): (length: 32 bytes)
      37574cfbf1b95ff6a8e2d7be462d4d01e6dde2618f34f4de9df869b2
      4f532c5
  Outputs
    Ya: (length: 65 bytes)
      041dc910359e26f44b3a16300337e1932fd84ea26a4144b61d3a4dc1
      16641d4f66b768c8078e07df31541f357525b96d0348936bdf63ea9a
      fb7e64ee14cc2ddd
    MSGa: (length: 70 bytes)
      41041dc910359e26f44b3a16300337e1932fd84ea26a4144b61d3a4d
      c116641d4f66b768c8078e07df31541f357525b96d0348936bdf63ea
      9afb7e64ee14cc2ddd66034144
~~~

###  Test vector for MSGb

~~~
  Inputs
    ADb = b'ADb'
    yb (big endian): (length: 32 bytes)
      e5672fc9eb4e721f41d80181ec4c9fd9886668acc48024d33c82bb10
      2aecba5
  Outputs
    Yb: (length: 65 bytes)
      04da32021f687db46e8d290bbe661ceb8799e47c215ebb25a5aa357d
      b06b59b67c178004f4702b0a120aca8f0d2964cabacd058ff58e75fa
      250e1829bdca1842
    MSGb: (length: 70 bytes)
      4104da32021f687db46e8d290bbe661ceb8799e47c215ebb25a5aa35
      7db06b59b67c178004f4702b0a120aca8f0d2964cabacd058ff58e75
      fa250e1829bdca18420d034144
~~~

###  Test vector for secret points K

~~~
    scalar_mult_vfy(ya,Yb): (length: 32 bytes)
      bd20b9ce554c1d9fd461c0b0fda0765ee5e9d21730614c06a14bc6f9
      6c0f381
    scalar_mult_vfy(yb,Ya): (length: 32 bytes)
      bd20b9ce554c1d9fd461c0b0fda0765ee5e9d21730614c06a14bc6f9
      6c0f381
~~~


###  Test vector for ISK calculation initiator/responder

~~~
    unordered cat of transcript : (length: 140 bytes)
      41041dc910359e26f44b3a16300337e1932fd84ea26a4144b61d3a4d
      c116641d4f66b768c8078e07df31541f357525b96d0348936bdf63ea
      9afb7e64ee14cc2ddd66034144614104da32021f687db46e8d290bbe
      661ceb8799e47c215ebb25a5aa357db06b59b67c178004f4702b0a12
      0aca8f0d2964cabacd058ff58e75fa250e1829bdca18420d0341
    input to final ISK hash: (length: 225 bytes)
      224350616365503235365f584d443a5348412d3235365f535357555f
      4e555f5f49534b1034b36454cab2e7842c389f7d88ecb7df20bd20b9
      ce554c1d9fd461c0b0fda0765ee5e9d21730614c06a14bc6f96c0f38
      1041041dc910359e26f44b3a16300337e1932fd84ea26a4144b61d3a
      4dc116641d4f66b768c8078e07df31541f357525b96d0348936bdf63
      ea9afb7e64ee14cc2ddd66034144614104da32021f687db46e8d290b
      be661ceb8799e47c215ebb25a5aa357db06b59b67c178004f4702b0a
      120aca8f0d2964cabacd058ff58e75fa250e1829bdca18420d0
    ISK result: (length: 32 bytes)
      82729aab5893e56ac56610e95347f79cfdec54ec97276ec5ca1a2e6d
      b58c99a
~~~

###  Test vector for ISK calculation parallel execution

~~~
    ordered cat of transcript : (length: 140 bytes)
      4104da32021f687db46e8d290bbe661ceb8799e47c215ebb25a5aa35
      7db06b59b67c178004f4702b0a120aca8f0d2964cabacd058ff58e75
      fa250e1829bdca18420d0341446241041dc910359e26f44b3a163003
      37e1932fd84ea26a4144b61d3a4dc116641d4f66b768c8078e07df31
      541f357525b96d0348936bdf63ea9afb7e64ee14cc2ddd660341
    input to final ISK hash: (length: 225 bytes)
      224350616365503235365f584d443a5348412d3235365f535357555f
      4e555f5f49534b1034b36454cab2e7842c389f7d88ecb7df20bd20b9
      ce554c1d9fd461c0b0fda0765ee5e9d21730614c06a14bc6f96c0f38
      104104da32021f687db46e8d290bbe661ceb8799e47c215ebb25a5aa
      357db06b59b67c178004f4702b0a120aca8f0d2964cabacd058ff58e
      75fa250e1829bdca18420d0341446241041dc910359e26f44b3a1630
      0337e1932fd84ea26a4144b61d3a4dc116641d4f66b768c8078e07df
      31541f357525b96d0348936bdf63ea9afb7e64ee14cc2ddd660
    ISK result: (length: 32 bytes)
      78ea7caa0bf7d98ec048cf06910d4721763140d6beb54d4a406db586
      deff006
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

##  Test vector for CPace using group NIST P-384 and hash SHA512


###  Test vectors for calculate_generator with group NIST P-384

~~~
  Inputs
    H   = SHA512 with input block size 128 bytes.
    PRS = b'password' ; ZPAD length: 118 ;
    DSI = b'CPaceP384_XMD:SHA-384_SSWU_NU_'
    CI = b'\nAinitiator\nBresponder'
    CI = 0a41696e69746961746f720a42726573706f6e646572
    sid = 7e4b4791d6a8ef019b936c79fb7f2c57
  Outputs
    string passed to map: (length: 199 bytes)
      0870617373776f726476000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      000000000000000000000000000000001e4350616365503338345f58
      4d443a5348412d3338345f535357555f4e555f160a41696e69746961
      746f720a42726573706f6e646572107e4b4791d6a8ef019b936c79fb
    generator g: (length: 97 bytes)
      047a150362b4d77b37d1af4a74209381886225b869328dbb40ee387c
      1dcf656c9a571bd82d008387fbffa1b2c07186dd9ccd7abe0bdcf9e7
      900f1b2144e391ad078b3bacb5e4ea2e8a8c95981a2ef73fa97d3d1e
      4394e6c1428652cca357707
~~~

###  Test vector for MSGa

~~~
  Inputs
    ADa = b'ADa'
    ya (big endian): (length: 48 bytes)
      ef433dd5ad142c860e7cb6400dd315d388d5ec5420c550e9d6f0907f
      375d988bc4d704837e43561c497e7dd93edcdb9
  Outputs
    Ya: (length: 97 bytes)
      041fd07146117cf52b9714082f7ddf6eb08542fea3f0eae676639612
      28aa2c52df3ac84fe0e41937573ab5199dcbf0a15084041349f882af
      1ae924f408ee190c8956cb7f7ac618743261f57e281af0e0a42c2cc3
      04802dc8dc5d34d33b512d0
    MSGa: (length: 102 bytes)
      61041fd07146117cf52b9714082f7ddf6eb08542fea3f0eae6766396
      1228aa2c52df3ac84fe0e41937573ab5199dcbf0a15084041349f882
      af1ae924f408ee190c8956cb7f7ac618743261f57e281af0e0a42c2c
      c304802dc8dc5d34d33b512d0b8603414
~~~

###  Test vector for MSGb

~~~
  Inputs
    ADb = b'ADb'
    yb (big endian): (length: 48 bytes)
      50b0e36b95a2edfaa8342b843dddc90b175330f2399c1b36586dedda
      3c255975f30be6a750f9404fccc62a6323b5e47
  Outputs
    Yb: (length: 97 bytes)
      04ea496f6e5b17a50206fee4405b99713f1a919fb36f813645d7fcb9
      18de23305830c0a482d20d04165d37d30f2d6c2ae84ed0b798f8cf34
      94aa7e28643365190888db3aac57522cadd9bfc289f86a5fbaeadd17
      54f7afdcedb1fd8be3aea48
    MSGb: (length: 102 bytes)
      6104ea496f6e5b17a50206fee4405b99713f1a919fb36f813645d7fc
      b918de23305830c0a482d20d04165d37d30f2d6c2ae84ed0b798f8cf
      3494aa7e28643365190888db3aac57522cadd9bfc289f86a5fbaeadd
      1754f7afdcedb1fd8be3aea4884603414
~~~

###  Test vector for secret points K

~~~
    scalar_mult_vfy(ya,Yb): (length: 48 bytes)
      c2ffb79b7adbf1abb25a4bbfddfe2707a2eaa7d45412f458a1bb7fe6
      f318d248be363fb1ece1385368769b98bc7b546
    scalar_mult_vfy(yb,Ya): (length: 48 bytes)
      c2ffb79b7adbf1abb25a4bbfddfe2707a2eaa7d45412f458a1bb7fe6
      f318d248be363fb1ece1385368769b98bc7b546
~~~


###  Test vector for ISK calculation initiator/responder

~~~
    unordered cat of transcript : (length: 204 bytes)
      61041fd07146117cf52b9714082f7ddf6eb08542fea3f0eae6766396
      1228aa2c52df3ac84fe0e41937573ab5199dcbf0a15084041349f882
      af1ae924f408ee190c8956cb7f7ac618743261f57e281af0e0a42c2c
      c304802dc8dc5d34d33b512d0b86034144616104ea496f6e5b17a502
      06fee4405b99713f1a919fb36f813645d7fcb918de23305830c0a482
      d20d04165d37d30f2d6c2ae84ed0b798f8cf3494aa7e286433651908
      88db3aac57522cadd9bfc289f86a5fbaeadd1754f7afdcedb1fd8be3
      aea488460
    input to final ISK hash: (length: 305 bytes)
      224350616365503338345f584d443a5348412d3338345f535357555f
      4e555f5f49534b107e4b4791d6a8ef019b936c79fb7f2c5730c2ffb7
      9b7adbf1abb25a4bbfddfe2707a2eaa7d45412f458a1bb7fe6f318d2
      48be363fb1ece1385368769b98bc7b546e61041fd07146117cf52b97
      14082f7ddf6eb08542fea3f0eae67663961228aa2c52df3ac84fe0e4
      1937573ab5199dcbf0a15084041349f882af1ae924f408ee190c8956
      cb7f7ac618743261f57e281af0e0a42c2cc304802dc8dc5d34d33b51
      2d0b86034144616104ea496f6e5b17a50206fee4405b99713f1a919f
      b36f813645d7fcb918de23305830c0a482d20d04165d37d30f2d6c2a
      e84ed0b798f8cf3494aa7e28643365190888db3aac57522cadd9bfc2
      89f86a5fbaeadd1754f7afdcedb1fd8be3aea488
    ISK result: (length: 64 bytes)
      73752856197a807728c28acc147a4ff08532bfd9f983f3d56e204bc7
      777896d962cb70cb23e2d1ee789573d13d8a2a2bb4131e93c9be827f
      01981d7932a619
~~~

###  Test vector for ISK calculation parallel execution

~~~
    ordered cat of transcript : (length: 204 bytes)
      6104ea496f6e5b17a50206fee4405b99713f1a919fb36f813645d7fc
      b918de23305830c0a482d20d04165d37d30f2d6c2ae84ed0b798f8cf
      3494aa7e28643365190888db3aac57522cadd9bfc289f86a5fbaeadd
      1754f7afdcedb1fd8be3aea488460341446261041fd07146117cf52b
      9714082f7ddf6eb08542fea3f0eae67663961228aa2c52df3ac84fe0
      e41937573ab5199dcbf0a15084041349f882af1ae924f408ee190c89
      56cb7f7ac618743261f57e281af0e0a42c2cc304802dc8dc5d34d33b
      512d0b860
    input to final ISK hash: (length: 305 bytes)
      224350616365503338345f584d443a5348412d3338345f535357555f
      4e555f5f49534b107e4b4791d6a8ef019b936c79fb7f2c5730c2ffb7
      9b7adbf1abb25a4bbfddfe2707a2eaa7d45412f458a1bb7fe6f318d2
      48be363fb1ece1385368769b98bc7b546e6104ea496f6e5b17a50206
      fee4405b99713f1a919fb36f813645d7fcb918de23305830c0a482d2
      0d04165d37d30f2d6c2ae84ed0b798f8cf3494aa7e28643365190888
      db3aac57522cadd9bfc289f86a5fbaeadd1754f7afdcedb1fd8be3ae
      a488460341446261041fd07146117cf52b9714082f7ddf6eb08542fe
      a3f0eae67663961228aa2c52df3ac84fe0e41937573ab5199dcbf0a1
      5084041349f882af1ae924f408ee190c8956cb7f7ac618743261f57e
      281af0e0a42c2cc304802dc8dc5d34d33b512d0b
    ISK result: (length: 64 bytes)
      fc619d2d01e76b957a7b52f47d9dcedc62d2843bdd929c89254e979e
      e84ed9fd00dc580b7592fbcfad7b6e11a7d41475e1c7d8269b29a5fc
      b694149f6653ee
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
 0x04,0x7a,0x15,0x03,0x62,0xb4,0xd7,0x7b,0x37,0xd1,0xaf,0x4a,
 0x74,0x20,0x93,0x81,0x88,0x62,0x25,0xb8,0x69,0x32,0x8d,0xbb,
 0x40,0xee,0x38,0x7c,0x1d,0xcf,0x65,0x6c,0x9a,0x57,0x1b,0xd8,
 0x2d,0x00,0x83,0x87,0xfb,0xff,0xa1,0xb2,0xc0,0x71,0x86,0xdd,
 0x9c,0xcd,0x7a,0xbe,0x0b,0xdc,0xf9,0xe7,0x90,0x0f,0x1b,0x21,
 0x44,0xe3,0x91,0xad,0x07,0x8b,0x3b,0xac,0xb5,0xe4,0xea,0x2e,
 0x8a,0x8c,0x95,0x98,0x1a,0x2e,0xf7,0x3f,0xa9,0x7d,0x3d,0x1e,
 0x43,0x94,0xe6,0xc1,0x42,0x86,0x52,0xcc,0xa3,0x57,0x70,0x79,
 0x2d,
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
 0x04,0x1f,0xd0,0x71,0x46,0x11,0x7c,0xf5,0x2b,0x97,0x14,0x08,
 0x2f,0x7d,0xdf,0x6e,0xb0,0x85,0x42,0xfe,0xa3,0xf0,0xea,0xe6,
 0x76,0x63,0x96,0x12,0x28,0xaa,0x2c,0x52,0xdf,0x3a,0xc8,0x4f,
 0xe0,0xe4,0x19,0x37,0x57,0x3a,0xb5,0x19,0x9d,0xcb,0xf0,0xa1,
 0x50,0x84,0x04,0x13,0x49,0xf8,0x82,0xaf,0x1a,0xe9,0x24,0xf4,
 0x08,0xee,0x19,0x0c,0x89,0x56,0xcb,0x7f,0x7a,0xc6,0x18,0x74,
 0x32,0x61,0xf5,0x7e,0x28,0x1a,0xf0,0xe0,0xa4,0x2c,0x2c,0xc3,
 0x04,0x80,0x2d,0xc8,0xdc,0x5d,0x34,0xd3,0x3b,0x51,0x2d,0x0b,
 0x86,
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
 0x04,0xea,0x49,0x6f,0x6e,0x5b,0x17,0xa5,0x02,0x06,0xfe,0xe4,
 0x40,0x5b,0x99,0x71,0x3f,0x1a,0x91,0x9f,0xb3,0x6f,0x81,0x36,
 0x45,0xd7,0xfc,0xb9,0x18,0xde,0x23,0x30,0x58,0x30,0xc0,0xa4,
 0x82,0xd2,0x0d,0x04,0x16,0x5d,0x37,0xd3,0x0f,0x2d,0x6c,0x2a,
 0xe8,0x4e,0xd0,0xb7,0x98,0xf8,0xcf,0x34,0x94,0xaa,0x7e,0x28,
 0x64,0x33,0x65,0x19,0x08,0x88,0xdb,0x3a,0xac,0x57,0x52,0x2c,
 0xad,0xd9,0xbf,0xc2,0x89,0xf8,0x6a,0x5f,0xba,0xea,0xdd,0x17,
 0x54,0xf7,0xaf,0xdc,0xed,0xb1,0xfd,0x8b,0xe3,0xae,0xa4,0x88,
 0x46,
};
const uint8_t tc_K[] = {
 0xc2,0xff,0xb7,0x9b,0x7a,0xdb,0xf1,0xab,0xb2,0x5a,0x4b,0xbf,
 0xdd,0xfe,0x27,0x07,0xa2,0xea,0xa7,0xd4,0x54,0x12,0xf4,0x58,
 0xa1,0xbb,0x7f,0xe6,0xf3,0x18,0xd2,0x48,0xbe,0x36,0x3f,0xb1,
 0xec,0xe1,0x38,0x53,0x68,0x76,0x9b,0x98,0xbc,0x7b,0x54,0x6e,
};
const uint8_t tc_ISK_IR[] = {
 0x73,0x75,0x28,0x56,0x19,0x7a,0x80,0x77,0x28,0xc2,0x8a,0xcc,
 0x14,0x7a,0x4f,0xf0,0x85,0x32,0xbf,0xd9,0xf9,0x83,0xf3,0xd5,
 0x6e,0x20,0x4b,0xc7,0x77,0x78,0x96,0xd9,0x62,0xcb,0x70,0xcb,
 0x23,0xe2,0xd1,0xee,0x78,0x95,0x73,0xd1,0x3d,0x8a,0x2a,0x2b,
 0xb4,0x13,0x1e,0x93,0xc9,0xbe,0x82,0x7f,0x01,0x98,0x1d,0x79,
 0x32,0xa6,0x19,0xc1,
};
const uint8_t tc_ISK_SY[] = {
 0xfc,0x61,0x9d,0x2d,0x01,0xe7,0x6b,0x95,0x7a,0x7b,0x52,0xf4,
 0x7d,0x9d,0xce,0xdc,0x62,0xd2,0x84,0x3b,0xdd,0x92,0x9c,0x89,
 0x25,0x4e,0x97,0x9e,0xe8,0x4e,0xd9,0xfd,0x00,0xdc,0x58,0x0b,
 0x75,0x92,0xfb,0xcf,0xad,0x7b,0x6e,0x11,0xa7,0xd4,0x14,0x75,
 0xe1,0xc7,0xd8,0x26,0x9b,0x29,0xa5,0xfc,0xb6,0x94,0x14,0x9f,
 0x66,0x53,0xee,0x1e,
};
~~~

##  Test vector for CPace using group NIST P-521 and hash SHAKE256


###  Test vectors for calculate_generator with group NIST P-521

~~~
  Inputs
    H   = SHAKE256 with input block size 136 bytes.
    PRS = b'password' ; ZPAD length: 126 ;
    DSI = b'CPaceP521_XMD:SHA-512_SSWU_NU_'
    CI = b'\nAinitiator\nBresponder'
    CI = 0a41696e69746961746f720a42726573706f6e646572
    sid = 5223e0cdc45d6575668d64c552004124
  Outputs
    string passed to map: (length: 207 bytes)
      0870617373776f72647e000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      00000000000000000000000000000000000000000000000000000000
      0000000000000000000000000000000000000000000000001e435061
      6365503532315f584d443a5348412d3531325f535357555f4e555f16
      0a41696e69746961746f720a42726573706f6e646572105223e0cdc4
      5d6575668d64c55
    generator g: (length: 133 bytes)
      0400e57b3189e5cc2b85fb50f530aa0024ca635b6f69570b0b330aa9
      c158b750a552c8f61d9a3feac9e9223957a90344b4c27a539cc60276
      8711d301fc164cb8f1d0a401fddd20ead83057e4a279adaf73ec8d8f
      ecf3b7f4463731853900a2c1147f4000a2dc83b75c00f2e2bc9b5eec
      b88a2f4f8b231145824fc66e2d151f1daa02bb
~~~

###  Test vector for MSGa

~~~
  Inputs
    ADa = b'ADa'
    ya (big endian): (length: 66 bytes)
      015e139e751725a89c486d7d69118692d3d8daff4c2162823b749f40
      8c08b68af3903da32ec1519ead186953a00be4470ca57aa30c39885b
      15b951cef4b0ed06b0
  Outputs
    Ya: (length: 133 bytes)
      040150411db8d33955bd836a5f213c5d61b4571a20f0d06b5cb68745
      b86619286ac661840008068c6c955083f6f732477ffbe3773eaf06ce
      e01d1cbcde2e72891ebc2401eb8fac801bcd58e97dabc960f7c4b197
      22d32854f4cd1e66507ad0376a4acce6f935bb6eb7f08ebf3b9a5663
      d0321a065fa7888236fd4911d8b40621cdd699
    MSGa: (length: 139 bytes)
      c285040150411db8d33955bd836a5f213c5d61b4571a20f0d06b5cb6
      8745b86619286ac661840008068c6c955083f6f732477ffbe3773eaf
      06cee01d1cbcde2e72891ebc2401eb8fac801bcd58e97dabc960f7c4
      b19722d32854f4cd1e66507ad0376a4acce6f935bb6eb7f08ebf3b9a
      5663d0321a065fa7888236fd4911d8b40621cdd69930900341
~~~

###  Test vector for MSGb

~~~
  Inputs
    ADb = b'ADb'
    yb (big endian): (length: 66 bytes)
      01f901a57bcc47b4d1ca8a7e8e815849107fcf1a14ed1ee60f555cb6
      0453115c04a30aa8cf4870f34cd39c3bcb8b5b8f9c5d7fbf996a411d
      b75336d32e3753994f
  Outputs
    Yb: (length: 133 bytes)
      0401cbe4a4d5229996eb0ecfd66d37530ee7b7b5e12d9f3c4685eabd
      b4ba062a55ffa5cac893d0d017cb973b53a34630ffd87bdc531d2bcf
      370fe9e09d5c95ea153b6b000c89e938aabd31320e86dae1fba7550d
      b057ec29d84b204d1639470f91e8dd2951172872432a94e0de998bf3
      9c4fc7d5207ed22445f0da0059bd0a1ef6fa1f
    MSGb: (length: 139 bytes)
      c2850401cbe4a4d5229996eb0ecfd66d37530ee7b7b5e12d9f3c4685
      eabdb4ba062a55ffa5cac893d0d017cb973b53a34630ffd87bdc531d
      2bcf370fe9e09d5c95ea153b6b000c89e938aabd31320e86dae1fba7
      550db057ec29d84b204d1639470f91e8dd2951172872432a94e0de99
      8bf39c4fc7d5207ed22445f0da0059bd0a1ef6fa1feeaf0341
~~~

###  Test vector for secret points K

~~~
    scalar_mult_vfy(ya,Yb): (length: 66 bytes)
      01be654e65c4427dcc60a32859f797cd9b17210de03e196ed995449b
      5a78112de1465bffce82957fae255359013cfdd9f91736c7e53eccbb
      f4088303ab74993e7d
    scalar_mult_vfy(yb,Ya): (length: 66 bytes)
      01be654e65c4427dcc60a32859f797cd9b17210de03e196ed995449b
      5a78112de1465bffce82957fae255359013cfdd9f91736c7e53eccbb
      f4088303ab74993e7d
~~~


###  Test vector for ISK calculation initiator/responder

~~~
    unordered cat of transcript : (length: 278 bytes)
      c285040150411db8d33955bd836a5f213c5d61b4571a20f0d06b5cb6
      8745b86619286ac661840008068c6c955083f6f732477ffbe3773eaf
      06cee01d1cbcde2e72891ebc2401eb8fac801bcd58e97dabc960f7c4
      b19722d32854f4cd1e66507ad0376a4acce6f935bb6eb7f08ebf3b9a
      5663d0321a065fa7888236fd4911d8b40621cdd699309003414461c2
      850401cbe4a4d5229996eb0ecfd66d37530ee7b7b5e12d9f3c4685ea
      bdb4ba062a55ffa5cac893d0d017cb973b53a34630ffd87bdc531d2b
      cf370fe9e09d5c95ea153b6b000c89e938aabd31320e86dae1fba755
      0db057ec29d84b204d1639470f91e8dd2951172872432a94e0de998b
      f39c4fc7d5207ed22445f0da0059bd0a1ef6fa1feea
    input to final ISK hash: (length: 397 bytes)
      224350616365503532315f584d443a5348412d3531325f535357555f
      4e555f5f49534b105223e0cdc45d6575668d64c5520041244201be65
      4e65c4427dcc60a32859f797cd9b17210de03e196ed995449b5a7811
      2de1465bffce82957fae255359013cfdd9f91736c7e53eccbbf40883
      03ab74993e7d12c285040150411db8d33955bd836a5f213c5d61b457
      1a20f0d06b5cb68745b86619286ac661840008068c6c955083f6f732
      477ffbe3773eaf06cee01d1cbcde2e72891ebc2401eb8fac801bcd58
      e97dabc960f7c4b19722d32854f4cd1e66507ad0376a4acce6f935bb
      6eb7f08ebf3b9a5663d0321a065fa7888236fd4911d8b40621cdd699
      309003414461c2850401cbe4a4d5229996eb0ecfd66d37530ee7b7b5
      e12d9f3c4685eabdb4ba062a55ffa5cac893d0d017cb973b53a34630
      ffd87bdc531d2bcf370fe9e09d5c95ea153b6b000c89e938aabd3132
      0e86dae1fba7550db057ec29d84b204d1639470f91e8dd2951172872
      432a94e0de998bf39c4fc7d5207ed22445f0da0059bd0a1ef6fa1
    ISK result: (length: 64 bytes)
      703681a6823c3e35da4a93528d844a50b9a708fb9e317e991540b530
      8a8f3cd9d073d08a3721007e9d1a1434d95ca40a48408ff0724f3790
      87c1f5251d6ad1
~~~

###  Test vector for ISK calculation parallel execution

~~~
    ordered cat of transcript : (length: 278 bytes)
      c2850401cbe4a4d5229996eb0ecfd66d37530ee7b7b5e12d9f3c4685
      eabdb4ba062a55ffa5cac893d0d017cb973b53a34630ffd87bdc531d
      2bcf370fe9e09d5c95ea153b6b000c89e938aabd31320e86dae1fba7
      550db057ec29d84b204d1639470f91e8dd2951172872432a94e0de99
      8bf39c4fc7d5207ed22445f0da0059bd0a1ef6fa1feeaf03414462c2
      85040150411db8d33955bd836a5f213c5d61b4571a20f0d06b5cb687
      45b86619286ac661840008068c6c955083f6f732477ffbe3773eaf06
      cee01d1cbcde2e72891ebc2401eb8fac801bcd58e97dabc960f7c4b1
      9722d32854f4cd1e66507ad0376a4acce6f935bb6eb7f08ebf3b9a56
      63d0321a065fa7888236fd4911d8b40621cdd699309
    input to final ISK hash: (length: 397 bytes)
      224350616365503532315f584d443a5348412d3531325f535357555f
      4e555f5f49534b105223e0cdc45d6575668d64c5520041244201be65
      4e65c4427dcc60a32859f797cd9b17210de03e196ed995449b5a7811
      2de1465bffce82957fae255359013cfdd9f91736c7e53eccbbf40883
      03ab74993e7d12c2850401cbe4a4d5229996eb0ecfd66d37530ee7b7
      b5e12d9f3c4685eabdb4ba062a55ffa5cac893d0d017cb973b53a346
      30ffd87bdc531d2bcf370fe9e09d5c95ea153b6b000c89e938aabd31
      320e86dae1fba7550db057ec29d84b204d1639470f91e8dd29511728
      72432a94e0de998bf39c4fc7d5207ed22445f0da0059bd0a1ef6fa1f
      eeaf03414462c285040150411db8d33955bd836a5f213c5d61b4571a
      20f0d06b5cb68745b86619286ac661840008068c6c955083f6f73247
      7ffbe3773eaf06cee01d1cbcde2e72891ebc2401eb8fac801bcd58e9
      7dabc960f7c4b19722d32854f4cd1e66507ad0376a4acce6f935bb6e
      b7f08ebf3b9a5663d0321a065fa7888236fd4911d8b40621cdd69
    ISK result: (length: 64 bytes)
      9baba844632a9775deae06be46d9c21125da809093876ee8542ff2fc
      f4c02a88ac2328ea470e88ab0cfebd3e85517475b57e8391879d5b36
      740652b24ba310
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
 0x04,0x00,0xe5,0x7b,0x31,0x89,0xe5,0xcc,0x2b,0x85,0xfb,0x50,
 0xf5,0x30,0xaa,0x00,0x24,0xca,0x63,0x5b,0x6f,0x69,0x57,0x0b,
 0x0b,0x33,0x0a,0xa9,0xc1,0x58,0xb7,0x50,0xa5,0x52,0xc8,0xf6,
 0x1d,0x9a,0x3f,0xea,0xc9,0xe9,0x22,0x39,0x57,0xa9,0x03,0x44,
 0xb4,0xc2,0x7a,0x53,0x9c,0xc6,0x02,0x76,0x87,0x11,0xd3,0x01,
 0xfc,0x16,0x4c,0xb8,0xf1,0xd0,0xa4,0x01,0xfd,0xdd,0x20,0xea,
 0xd8,0x30,0x57,0xe4,0xa2,0x79,0xad,0xaf,0x73,0xec,0x8d,0x8f,
 0xec,0xf3,0xb7,0xf4,0x46,0x37,0x31,0x85,0x39,0x00,0xa2,0xc1,
 0x14,0x7f,0x40,0x00,0xa2,0xdc,0x83,0xb7,0x5c,0x00,0xf2,0xe2,
 0xbc,0x9b,0x5e,0xec,0xb8,0x8a,0x2f,0x4f,0x8b,0x23,0x11,0x45,
 0x82,0x4f,0xc6,0x6e,0x2d,0x15,0x1f,0x1d,0xaa,0x02,0xbb,0x66,
 0x96,
};
const uint8_t tc_ya[] = {
 0x01,0x5e,0x13,0x9e,0x75,0x17,0x25,0xa8,0x9c,0x48,0x6d,0x7d,
 0x69,0x11,0x86,0x92,0xd3,0xd8,0xda,0xff,0x4c,0x21,0x62,0x82,
 0x3b,0x74,0x9f,0x40,0x8c,0x08,0xb6,0x8a,0xf3,0x90,0x3d,0xa3,
 0x2e,0xc1,0x51,0x9e,0xad,0x18,0x69,0x53,0xa0,0x0b,0xe4,0x47,
 0x0c,0xa5,0x7a,0xa3,0x0c,0x39,0x88,0x5b,0x15,0xb9,0x51,0xce,
 0xf4,0xb0,0xed,0x06,0xb0,0x7a,
};
const uint8_t tc_ADa[] = {
 0x41,0x44,0x61,
};
const uint8_t tc_Ya[] = {
 0x04,0x01,0x50,0x41,0x1d,0xb8,0xd3,0x39,0x55,0xbd,0x83,0x6a,
 0x5f,0x21,0x3c,0x5d,0x61,0xb4,0x57,0x1a,0x20,0xf0,0xd0,0x6b,
 0x5c,0xb6,0x87,0x45,0xb8,0x66,0x19,0x28,0x6a,0xc6,0x61,0x84,
 0x00,0x08,0x06,0x8c,0x6c,0x95,0x50,0x83,0xf6,0xf7,0x32,0x47,
 0x7f,0xfb,0xe3,0x77,0x3e,0xaf,0x06,0xce,0xe0,0x1d,0x1c,0xbc,
 0xde,0x2e,0x72,0x89,0x1e,0xbc,0x24,0x01,0xeb,0x8f,0xac,0x80,
 0x1b,0xcd,0x58,0xe9,0x7d,0xab,0xc9,0x60,0xf7,0xc4,0xb1,0x97,
 0x22,0xd3,0x28,0x54,0xf4,0xcd,0x1e,0x66,0x50,0x7a,0xd0,0x37,
 0x6a,0x4a,0xcc,0xe6,0xf9,0x35,0xbb,0x6e,0xb7,0xf0,0x8e,0xbf,
 0x3b,0x9a,0x56,0x63,0xd0,0x32,0x1a,0x06,0x5f,0xa7,0x88,0x82,
 0x36,0xfd,0x49,0x11,0xd8,0xb4,0x06,0x21,0xcd,0xd6,0x99,0x30,
 0x90,
};
const uint8_t tc_yb[] = {
 0x01,0xf9,0x01,0xa5,0x7b,0xcc,0x47,0xb4,0xd1,0xca,0x8a,0x7e,
 0x8e,0x81,0x58,0x49,0x10,0x7f,0xcf,0x1a,0x14,0xed,0x1e,0xe6,
 0x0f,0x55,0x5c,0xb6,0x04,0x53,0x11,0x5c,0x04,0xa3,0x0a,0xa8,
 0xcf,0x48,0x70,0xf3,0x4c,0xd3,0x9c,0x3b,0xcb,0x8b,0x5b,0x8f,
 0x9c,0x5d,0x7f,0xbf,0x99,0x6a,0x41,0x1d,0xb7,0x53,0x36,0xd3,
 0x2e,0x37,0x53,0x99,0x4f,0xff,
};
const uint8_t tc_ADb[] = {
 0x41,0x44,0x62,
};
const uint8_t tc_Yb[] = {
 0x04,0x01,0xcb,0xe4,0xa4,0xd5,0x22,0x99,0x96,0xeb,0x0e,0xcf,
 0xd6,0x6d,0x37,0x53,0x0e,0xe7,0xb7,0xb5,0xe1,0x2d,0x9f,0x3c,
 0x46,0x85,0xea,0xbd,0xb4,0xba,0x06,0x2a,0x55,0xff,0xa5,0xca,
 0xc8,0x93,0xd0,0xd0,0x17,0xcb,0x97,0x3b,0x53,0xa3,0x46,0x30,
 0xff,0xd8,0x7b,0xdc,0x53,0x1d,0x2b,0xcf,0x37,0x0f,0xe9,0xe0,
 0x9d,0x5c,0x95,0xea,0x15,0x3b,0x6b,0x00,0x0c,0x89,0xe9,0x38,
 0xaa,0xbd,0x31,0x32,0x0e,0x86,0xda,0xe1,0xfb,0xa7,0x55,0x0d,
 0xb0,0x57,0xec,0x29,0xd8,0x4b,0x20,0x4d,0x16,0x39,0x47,0x0f,
 0x91,0xe8,0xdd,0x29,0x51,0x17,0x28,0x72,0x43,0x2a,0x94,0xe0,
 0xde,0x99,0x8b,0xf3,0x9c,0x4f,0xc7,0xd5,0x20,0x7e,0xd2,0x24,
 0x45,0xf0,0xda,0x00,0x59,0xbd,0x0a,0x1e,0xf6,0xfa,0x1f,0xee,
 0xaf,
};
const uint8_t tc_K[] = {
 0x01,0xbe,0x65,0x4e,0x65,0xc4,0x42,0x7d,0xcc,0x60,0xa3,0x28,
 0x59,0xf7,0x97,0xcd,0x9b,0x17,0x21,0x0d,0xe0,0x3e,0x19,0x6e,
 0xd9,0x95,0x44,0x9b,0x5a,0x78,0x11,0x2d,0xe1,0x46,0x5b,0xff,
 0xce,0x82,0x95,0x7f,0xae,0x25,0x53,0x59,0x01,0x3c,0xfd,0xd9,
 0xf9,0x17,0x36,0xc7,0xe5,0x3e,0xcc,0xbb,0xf4,0x08,0x83,0x03,
 0xab,0x74,0x99,0x3e,0x7d,0x12,
};
const uint8_t tc_ISK_IR[] = {
 0x70,0x36,0x81,0xa6,0x82,0x3c,0x3e,0x35,0xda,0x4a,0x93,0x52,
 0x8d,0x84,0x4a,0x50,0xb9,0xa7,0x08,0xfb,0x9e,0x31,0x7e,0x99,
 0x15,0x40,0xb5,0x30,0x8a,0x8f,0x3c,0xd9,0xd0,0x73,0xd0,0x8a,
 0x37,0x21,0x00,0x7e,0x9d,0x1a,0x14,0x34,0xd9,0x5c,0xa4,0x0a,
 0x48,0x40,0x8f,0xf0,0x72,0x4f,0x37,0x90,0x87,0xc1,0xf5,0x25,
 0x1d,0x6a,0xd1,0x40,
};
const uint8_t tc_ISK_SY[] = {
 0x9b,0xab,0xa8,0x44,0x63,0x2a,0x97,0x75,0xde,0xae,0x06,0xbe,
 0x46,0xd9,0xc2,0x11,0x25,0xda,0x80,0x90,0x93,0x87,0x6e,0xe8,
 0x54,0x2f,0xf2,0xfc,0xf4,0xc0,0x2a,0x88,0xac,0x23,0x28,0xea,
 0x47,0x0e,0x88,0xab,0x0c,0xfe,0xbd,0x3e,0x85,0x51,0x74,0x75,
 0xb5,0x7e,0x83,0x91,0x87,0x9d,0x5b,0x36,0x74,0x06,0x52,0xb2,
 0x4b,0xa3,0x10,0x6b,
};
~~~

