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
  NonceDisrespecting:
    target: https://eprint.iacr.org/2016/475.pdf
    title: "Nonce-Disrespecting Adversaries -- Practical Forgery Attacks on GCM in TLS"
    author:
      - ins: H. Bock
      - ins: A. Zauner
      - ins: S. Devlin
      - ins: J. Somorovsky
      - ins: P. Jovanovic
    date: 2016-05-17

--- abstract

This document describes CPace which is a protocol for two
parties that share a low-entropy secret (password) to derive a strong shared key without
disclosing the secret to offline dictionary attacks. This method was tailored for constrained devices,
is compatible with any group of both prime- and non-prime order,
and comes with  a security proof providing composability guarantees.

--- middle

# Introduction

This document describes CPace which is a protocol for two
parties that share a low-entropy secret (password) to derive a to derive a strong shared key without
disclosing the secret to offline dictionary attacks.

The CPace method was tailored for constrained devices and
specifically considers efficiency and hardware side-channel attack mitigations at the protocol level.
CPace is designed to be compatible with any group of both prime- and non-prime order and explicitly
handles the complexity of cofactor clearing on the protcol level. CPace
comes with game-based and simulation based proofs where the latter provides composability guarantees.
As a protocol, CPace is designed
to be compatible with so-called "x-coordinate-only" Diffie-Hellman implementations on elliptic curve
groups.

CPace is designed to be suitable as both, a building block within a larger protocol construction using CPace as substep,
and as a standalone protocol.

It is considered, that for composed larger protocol constructions, the CPace subprotocol might be best executed in a
separate cryptographic hardware, such as secure element chipsets. The CPace protocol design aims at considering
the resulting constraints.

# Requirements Notation

{::boilerplate bcp14}

# Definition CPace

## Setup

For CPace both communication partners need to agree on a common cipher suite which consists of choosing a common
hash function H and an elliptic curve group G.

With H we denote a hash primitive with a hash function H.hash(m,l)
that operates on an input octet string m and returns a hash result containing the first l result octets
calculated by the primitive.

A given hash function H is characterized by its input and its preferred output sizes.
We use an object-style notation H.constant_name.
With H.b_in_bytes we denote the preferred output size in bytes of the primitive such
that the hash function returns the full length of the hash if the second length parameter is not
given: H.hash(m) = H.hash(m, H.b_in_bytes).

With H.bmax_in_bytes we denote the maximum output size in octets supported by the hash primitive.

A first common choice for H is SHA512 {{?RFC6234}} where b_in_bytes = bmax_in_bytes = 64
as a fixed-length output of 64 bytes is produced.
Another suitable choice for H is SHAKE256 {{FIPS202}} which is also designed for a preferred length
and security parameter of b_in_bytes = 64 but which allows for variable-length outputs without
a fixed limit bmax_in_bytes.

With H.s_in_bytes we denote the input block size used by H.
For SHA512, e.g. the input block size s_in_bytes is 128, while for SHAKE256 the
input block size amounts to 136 bytes.

For a given group G this document specifies how to define the following set of group-specific
functions and constants for the protocol execution. For making the implicit dependence of the respective
functions and constants on the group G transparent, we use a object-style notation
G.function_name() and G.constant_name.

With G.I we denote a unique octet string representation of the neutral element of group G.

g = G.calculate_generator(H, PRS,CI,sid). With calculate_generator we denote a function that outputs a
octet string representation of a group element in G which is derived from input octet strings PRS, CI, sid using
a hash function primitive.

y = G.sample_scalar(). This function returns an octet string representation of a scalar value appropriate as a
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
ADa could for instance include party identifiers.

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
the length of the octet string as an utf-8 string to the byte sequence itself. (This will prepend one
single octet for sequences shorter than 128 bytes and more octets otherwise).

With prefix_free_cat(a0,a1, ...) we denote a function that outputs the prefix-free encoding of
all input octet strings as the concatenation of the individual strings with their respective
length prepended: prepend_len(a0) \|\| prepend_len(a1) \|\| ... . Use of this function allows for a
easy parsing of strings and guarantees a prefix-free encoding.

With sample_random_bytes(n) we denote a function that returns n octets uniformly sampled between 0 and 255.
With zero_bytes(n) we denote a function that returns n octets with value 0.

With ISK we denote the intermediate session key output string provided by CPace. It is RECOMMENDED to convert the
intermediate session key ISK ot a final session key by using a suitable KDF function prior to using the key in a
higher-level protocol.

With DSI we denote domain-separation identifier strings.

## Protocol Flow

CPace is a one round protocol to establish an intermediate shared secret ISK
with implicit mutual authentication.
In the setup phase both sides agree on a common hash function H and a group G.

Prior to invocation, A and B are provisioned with public (CI) and secret
information (PRS) as prerequisite for running the protocol.
During the first round, A sends a public share Ya
to B, and B responds with its own public share Yb.
Both A and B then derive a shared secret ISK. ISK is meant to be
used for producing encryption and authentication keys by a KDF function
outside of the scope of CPace.

Optionally when starting the protocol, A and B dispose of a sid string.
sid is typically pre-established by a higher-level protocol
invoking CPace. If no such sid is available from a higher-level
protocol, a suitable approach is to let A choose a fresh random sid
string and send it to B together with the first message. This method is shown in the
setup protocol section below.

This sample trace is shown below.

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
        |   (derive ISK)   |
~~~

## CPace

In the setup phase, both parties A,B agreed on the group G a hash H. If a higher-level protocol provided a session id sid, both parties SHALL use this value in the protocol execution. If there is a clear initiator (party A) and responder (party B) role assigned in the application setting, A SHOULD sample a fresh random value sid and transmit it together with its first message. If the application scenario does not enforce an ordering of the two messages and no sid value is available from a higher-level protocol, then the empty string shall be used for the session id.

To begin, A calculates a generator g = G.calculate_generator(H, PRS,CI,sid).

A samples ya = G.sample_scalar() randomly according to the requirements for group G.
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
If K is different from I, A returns ISK = H.hash(prefix_free_cat(G.DSI \|\| "ISK", sid, K, CONCAT(MSGa, MSGb))).

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
CPACE-P256-SHA256,
CPACE-RISTR255-SHA512,
CPACE-DECAF448-SHAKE256.

# Use of the hash function in CPace

With generator_string(PRS,DSI,CI,sid, H.s_in_bytes) we denote a function that returns a string
prefix_free_cat(PRS,zero_bytes(len_zpad), DSI, CI, sid) in which all input strings are concatenated
such that the encoding of PRS together with a suitable zero pad field completely fills the first input block
of the hash.

The length len_zpad of the zero padding is calculated as len_zpad = MAX(0, H.s_in_bytes - len(prepend_length(PRS)) - 1).

# CPace on single-coordinate Ladders on Montgomery curves

In this section we consider the case of CPace using the X25519 and X448 Diffie-Hellman functions
from {{?RFC7748}} operating on the Montgomery curves Curve25519 and Curve448 {{?RFC7748}}.

CPace implementations using single-coordinate ladders on further Montgomery curves SHALL use the definitions in line
with the specifications for X25519 and X448 and review the guidance given in the security consideration section and
{{CPacePaper}}.

For X25519 the following definitions apply:
- G.sample_scalar() = sample_random_bytes(32)
- G.scalar_mult(y,g) = G.scalar_mult_vfy(y,g) = X25519(y,g)
- G.I = zero_bytes(32)
- G.DSI = "CPace255"
- G.field_size_bytes = 32
- G.field_size_bits = 255

For X448 the following definitions apply:
- G.sample_scalar() = sample_random_bytes(56)
- G.scalar_mult(y,g) = G.scalar_mult_vfy(y,g) = X448(y,g)
- G.I = zero_bytes(56)
- G.DSI = "CPace448"
- G.field_size_bytes = 56
- G.field_size_bits = 448

The G.calculate_generator(H, PRS,sid,CI) function shall be implemented as follows.
- First gen_str = generator_string(PRS,G.DSI,CI,sid, H.s_in_bytes) is calculated using the input block size of the
  chosen hash primitive.
- This string is then hashed to the required length
  gen_str_hash = H.hash(gen_str, G.field_size_bytes).
  Note that this implies that the permissible output length H.maxb_in_bytes MUST BE larger or equal to the
  field size of the group G for making a hashing primitive suitable.
- This result is then considered as a field coordinate using
  the u = decodeUCoordinate(gen_str_hash, G.field_size_bits) function from {{?RFC7748}} which we
  repeat in the appendix for convenience.
- The result point g is then calculated as (g,v) = map_to_curve_elligator2(u) using the function
  from {{?I-D.irtf-cfrg-hash-to-curve}}. Note that the v coordinate produced by the map_to_curve_elligator2 function
  is not required for CPace and discarded.

In the appendix we show sage code that can be used as reference implementation for the calculate_generator and
key generation functions.

The definitions above aim at making the protocol suitable for outsourcing CPace to
secure elements (SE) where nested hash function constructions such as defined in {{?RFC5869}}
have to be considered to be particularly costly. Moreover as all hash operations are executed using strings
with a prefix-free encoding also Merkle-Damgard constructions such as the SHA2 family can be considered as
a representation of a random oracle, given that the permutation function is considered as a random oracle.

Finally, with the introduction of a zero-padding after the PRS string, the CPace design aims at mitigating
attacks of a side-channel adversary that analyzes correlations between publicly known information with
the low-entropy PRS string.

# CPace on prime-order group abstractions

In this section we consider the case of CPace using the ristretto25519 and decafX448 group abstractions.
These abstractions define an encode and decode function, group exponentiation
and a one-way-map.

For ristretto255 the following definitions apply:
- G.DSI = "CPaceRistretto"
- G.field_size_bytes = 32
- G.group_size_bits = 252

For decaf448 the following definitions apply:
- G.DSI = "CPaceDecaf"
- G.field_size_bytes = 56
- G.group_size_bits = 488

For both abstractions the following definitions apply:
- G.sample_scalar() = sample_random_bytes(G.group_size_bits) (Todo: add masking the upper bits!).
- G.scalar_mult(y,g) = encode(g^y)
- G.I = encode(g^0), where g is an arbitrary generator
- G.scalar_mult_vfy(y,X) is implemented as follows. If the decode(X) function fails, it returns G.I. Otherwise it returns encode( decode(X)^y )

Note that with these definitions the scalar_mult function operates on a decoded point g and returns an encoded point,
while the scalar_mult_vfy(y,X) function operates on a scalar and an encoded point X.

The G.calculate_generator(H, PRS,sid,CI) function shall return a decoded point and be implemented as follows.
- First gen_str = generator_string(PRS,G.DSI,CI,sid, H.s_in_bytes) is calculated using the input block size of the
  chosen hash primitive.
- This string is then hashed to the required length
  gen_str_hash = H.hash(gen_str, 2 * G.field_size_bytes).
  Note that this implies that the permissible output length H.maxb_in_bytes MUST BE larger or equal to twice the
  field size of the group G for making a hashing primitive suitable.
  Finally the generator g is calculated as g = one_way_map(gen_str_hash) using the one-way map function
  from the abstraction.

# Security Considerations {#sec-considerations}

A security proof of CPace is found in {{CPacePaper}}.

In order to prevent length-extension attacks, all hash inputs MUST be prefix-free strings in order to
make CPace suitable when Merkle-Damgard hashing constructions such as SHA2 or SHA512
are considered {{CDMP05}}. Otherwise so-called length-extension attacks of the hash
would have to be considered. This is guaranteed by the design of the prefix_free_cat() function.

Although already K is a shared value, still it MUST NOT be used as a shared secret key.
Note that calculation of ISK from K includes the protocol transcript and
prevents key malleability with respect to man-in-the-middle attacks from active adversaries.

The definitions given for the case of Curve25519 and Curve448 rely on the following properties of the
elliptic curves {{CPacePaper}}:
- The curve has order (p * c) with p prime and c a small cofactor. Also the curve's quadratic twist must be of
          order (p' * c') with p' prime and c' a cofactor.
- The cofactor c' of the twist MUST BE EQUAL to or an integer multiple of the cofactor c of the curve.
- The representation of the neutral element G.I MUST BE the same for both, the curve and its twist.
- Both field order q and group order p are close to a power of two such that randomly sampled binary strings
          can be used as representation for field elements and scalars {{CPacePaper}} .

Elements received from a peer MUST be checked by a proper implementation of the scalar_mult_vfy methods.
Failure to properly validate group elements can lead to attacks. The Curve25519-based cipher suite employs
the twist security feature of the curve for point validation.
As such, it is mandatory to check that any actual X25519 function implementation maps
all low-order points on both the curve and the twist on the neutral element.
Corresponding test vectors are provided in the appendix.

The randomly generated values ya and yb MUST NOT be reused.

CPace is not originally meant to be used in conjunction with servers supporting several users and, thus
several different username/password pairs.
In this setting it is RECOMMENDED to consider the augmented PAKE protocol OPAQUE or
to use CPace as building block of the augmented AuCPace protocol {{AUCPacePaper}}.

If CPace is used as a building block of higher-level protocols, it is RECOMMENDED that sid
is generated by the higher-level protocol and passed to CPace. One suitable option is that sid
is generated by concatenating ephemeral random strings from both parties.

Since CPace is designed to be used as a building block in higher-level protocols and for
compatibility with constrained hardware,
it does not by itself include a strong key derivation function construction.
Instead CPace uses a simple hash operation on a prefix-free string input for generating its
intermediate key ISK.
It is RECOMMENDED that the ISK is post-processed by a KDF such as {{?RFC5869}}
according the needs of the higher-level protocol. In case
that the CPace protocol is delegated to a secure element hardware, it is RECOMMENDED that the calculation of
the KDF function is implemented in the main processing unit.

In case that side-channel attacks are to be considered practical for a given application, it is RECOMMENDED to focus
side-channel protections such as masking and redundant execution (faults) on the process of calculating
the secret generator G.calculate_generator(PRS,CI,sid).
The most critical aspect to consider is the processing of the first block of the hash that includes
the PRS string. The CPace protocol construction considers the fact that side-channel protections of hash functions might
be particularly resource hungry. For this reason, CPace aims at minimizing the number
of hash functions invocations in the
specified calculate_generator function.

CPace is proven secure under the hardness of the computational Simultaneous Diffie-Hellmann (SDH)
assumption in the group G (as defined in {{CPacePaper}}).
Still, even for the event that large-scale quantum computers (LSQC) will become available, CPace forces an active
adversary to solve one CDH per password guess {{CPacePaper2}}.
In this sense, using the wording suggested by Steve Thomas on the CFRG mailing list,
CPace is "quantum-annoying".

While the zero-padding introduced when hashing the sensitive PRS string can be expected to make
the task for a side-channel
adversary more complex, this feature allone is not sufficient for preventing power analysis attacks.

# IANA Considerations

No IANA action is required.

# Acknowledgements

Thanks to the members of the CFRG for comments and advice. Any comment and advice is appreciated.

Comments are specifically invited regarding the inclusion or exclusion of both,
initiator/responder and symmetric settings. Currently we plan to consider both application
settings in this draft.

--- back