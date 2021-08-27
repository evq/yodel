# yodel

*SPEKE + STROBE*

*SPEKE* is a simple and elegant Password Authenticated Key Exchange protocol (PAKE). PAKE
protocols allow you to negotiate a strong shared key using a weak shared
secret. Unfortunately the original specification has many known issues.

*STROBE* is a simple and lightweight symmetric cryptography protocol framework which
is suitable for use for performing hashing, encryption, pseudorandom number
generation, key derivation and authentication all from a single cryptographic primitive.
STROBE's small size makes it easy to audit and possible to use from constrained
embedded contexts. It keeps a running transcript dependant on all prior operations.

By bringing them together the yodel leverages a STROBE transcript's dependence
on all prior inputs to mitigate issues with the original SPEKE specification.

The strategy for these mitigations stems from the paper
[Analysing and Patching SPEKE in ISO/IEC.](https://arxiv.org/pdf/1802.04900.pdf)

Later modifications attempt to align strongly with [CPACE](https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-cpace), another balanced PAKE protocol based on SPEKE.

# Notes

A yodel handshake results in full-duplex STROBE construction, with distinct TX and RX
transcripts. The two parties participating in the handshake will share these
common secret transcripts and can therefore form an encrypted channel for communicating.

The duplex transcripts combined with a required binding of self determined user identity to
the transcript neatly prevents the issue of message replay within and across concurrent
sessions without breaking protocol symmetry, even in misuse scenarios where
a session id is not passed in the initiating transcript or it's uniqueness is not enforced.

# Use

Don't.

I'm not a cryptographer, this code has not been audited in any capacity.

# TODO

The current upstream STROBE library used requires passing vecs, which means this library
isn't ideal for use in a `no_std` environment without alloc. This library is
intended to be fully `no_std` compatible so that embedded devices can take
advantage of the STROBE based construction. As a result this relies on a fork
which has not yet been upstreamed.

The session identifier type should be tweaked.

# Considerations for use

It may be useful to incorporate shared randomness into the transcript
before the yodel handshake if your application involves multiple runs
with the same password.  An approach in this vein has been suggested as
a way of increasing resistance to side channel attacks; similar to
suggested mitigations for [power supply analysis attacks that have broken
certain implementations of EdDSA signing.](https://eprint.iacr.org/2017/985.pdf)
