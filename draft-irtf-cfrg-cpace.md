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
  IEEE1363:
    title: Standard Specifications for Public Key Cryptography, IEEE 1363
    date: 2000

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

# CPace on single-coordinate Ladders on Montgomery curves

In this section we consider the case of CPace using the X25519 and X448 Diffie-Hellman functions
from {{?RFC7748}} operating on the Montgomery curves Curve25519 and Curve448 {{?RFC7748}}.

CPace implementations using single-coordinate ladders on further Montgomery curves SHALL use the definitions in line
with the specifications for X25519 and X448 and review the guidance given in the security consideration section and
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

# CPace on curves in Short-Weierstrass representation.
In this section we target ecosystems using elliptic-curve representations in Short-Weierstrass form. A typical
representative might be the curve NIST-P256. In the procedures specified in this section existing encoding and curve
standards are re-used wherever possible even if this results in some efficiency loss.
For the procedures described in this section any suitable group MUST BE of prime order.

Here, any elliptic curve in Short-Weierstrass form is characterized by

- An integer constant G.group_order which MUST BE a prime.

- A verification function G.is_in_group(X) which returns true if the input X is a valid encoding according to {{IEEE1363}} of a point on the group.

- G.I is an encoding of the x-coordinate according to {{IEEE1363}} of the neutral element on the curve.

- G.encode_to_curve(str) is a mapping function defined in {{!I-D.irtf-cfrg-hash-to-curve}} that maps string str to a point on the group. {{!I-D.irtf-cfrg-hash-to-curve}} provides both, uniform and non-uniform mappings based on several different strategies. It is RECOMMENDED to use the nonuniform variant of the SSWU mapping primitive within {{!I-D.irtf-cfrg-hash-to-curve}}.

- A string G.DSI which shall be defined by the concatenation of "CPace" and the cipher suite used for the encode_to_curve function from {{!I-D.irtf-cfrg-hash-to-curve}}.

Here the following definition of the CPace functions applies.

- Here G.sample_scalar() is a function that samples a value between 1 and (G.group_order - 1)  which MUST BE uniformly random. It is RECOMMENDED to use rejection sampling for converting a uniform bitstring to a   uniform value between 1 and (G.group_order - 1).

- G.scalar_mult(s,X) is a function that operates on a scalar s and an input point X encoded in full coordinates according to {{IEEE1363}}. It also returns a full-coordinate output (i.e. both, x and y coordinates of the point in Short-Weierstrass form).

- G.scalar_mult_vfy(s,X) operates on the representation of a scalar s and a full-coordinate point X. It MUST BE implemented as follows. if G.is_in_group(X) is false, G.scalar_mult_vfy(s,X) MUST return G.I . Otherwise G.scalar_mult_vfy(s,X) MUST returns an encoding of the x-coordinate of X^s according to {{IEEE1363}}.

For the Short-Weierstrass use-case the G.calculate_generator(H, PRS,sid,CI) function SHALL be implemented as follows.

- First gen_str = generator_string(PRS,G.DSI,CI,sid, H.s_in_bytes) is calculated using the input block size of the chosen hash primitive.

- Then the output of a call to G.encode_to_curve(gen_str) is returned.

# Security Considerations {#sec-considerations}

A security proof of CPace is found in {{CPacePaper}}.

In {{CPacePaper}} also the effect of slightly non-uniform sampling of scalars is considered for groups where the group order is close to a power of two,
which is the case for Curve25519 and Curve448. For these curves we recommend to sample scalars slightly non-uniformly as binary strings as any arithmetic
operation on secret scalars such as reduction may increase the attack surface when facing an adversary exploiting side-channel leakage.
OPTIONALLY also the conventional strategy of uniform sampling of scalars is suitable.

In order to prevent analysis of length-extension attacks on hash functions, all hash input strings in CPace are designed to be prefix-free strings with
prepended length information prior to any data field. This choice was made in order to make CPace suitable for hash function instantiations using
Merkle-Damgard constructions such as SHA2 or SHA512 along the lines of {{CDMP05}}. This is guaranteed by the design of the prefix_free_cat() function.

Although already K is a shared value, still it MUST NOT be used as a shared secret key. Leakage of K to an adversary may lead to offline-dictionary attacks.
Note that calculation of ISK from K includes the protocol transcript and
prevents key malleability with respect to man-in-the-middle attacks from active adversaries.

The definitions given for the case of the Montgomery curves Curve25519 and Curve448 rely on the following properties  {{CPacePaper}}:

- The curve has order (p * c) with p prime and c a small cofactor. Also the curve's quadratic twist must be of order (p' * c') with p' prime and c' a cofactor.

- The cofactor c' of the twist MUST BE EQUAL to or an integer multiple of the cofactor c of the curve.

- Both field order q and group order p MUST BE close to a power of two along the lines of {{CPacePaper}}, Appendix E.

- The representation of the neutral element G.I MUST BE the same for both, the curve and its twist.

- The implementation of G.scalar_mult_vfy(y,c) MUST map all c low-orer points on the curve and all c' low-order points on the twist  on the representation of the identity element G.I.

All of the above properties MUST hold for any further single-coordinate Montgomery curve implemented according the specifications given in the section for X25519 and X448.

The Curve25519-based cipher suite employs the twist security feature of the curve for point validation.
As such, it is MANDATORY to check that any actual X25519 function implementation maps
all low-order points on both the curve and the twist on the neutral element.
Corresponding test vectors are provided in the appendix.

The procedures from the section dealing with the case of idealized group abstractions
rely on the property that both, field order q and group order p MUST BE close to a power of two.
For a detailed discussion see {{CPacePaper}}, Appendix E.

Elements received from a peer MUST be checked by a proper implementation of the scalar_mult_vfy methods.
Failure to properly validate group elements can lead to trivial attacks.

Secret scalars ya and yb MUST NOT be reused. Values for sid SHOULD NOT be reused as the composability
guarantees of the simulation-based proof rely on uniqueness of session ids {{CPacePaper}}.


CPace was not originally meant to be used in conjunction with servers supporting several users and, thus
several different username/password pairs. As such it does not provide mechanisms for agreeing on salt values which are required
for iterated password-hashing functions which should be used for storing credentials (see e.g. the discussion in {{AUCPacePaper}} where
CPace has been used as building block within the augmented AuCPace protocol {{AUCPacePaper}}).

In a setting of a server with several distinct users it is RECOMMENDED to seriously
consider the augmented PAKE protocol OPAQUE {{!I-D.draft-irtf-cfrg-opaque}} instead.

If CPace is used as a building block of higher-level protocols, it is RECOMMENDED that sid
is generated by the higher-level protocol and passed to CPace. One suitable option is that sid
is generated by concatenating ephemeral random strings from both parties.

CPace does not by itself include a strong key derivation function construction.
Instead CPace uses a simple hash operation on a prefix-free string input for generating its
intermediate key ISK.
This was done for maintaining compatibility with constrained hardware such as secure element chipsets.

It is RECOMMENDED that the ISK is post-processed by a KDF such as {{?RFC5869}}
according the needs of the higher-level protocol.

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
