# yodel

**SPEKE + STROBE = YODEL**

This crate takes a STROBE based approach to applying the mitigations suggested in
[Analysing and Patching SPEKE in ISO/IEC](https://arxiv.org/pdf/1802.04900.pdf)
to address known vulnerabilities in the original SPEKE specification.

STROBE elegantly binds unique session information to the transcript - resulting
in a full-duplex construction whereby distinct TX and RX transcripts result
from the handshake completion.

These transcripts have had a strong `KEY` set as a result of the SPEKE handshake
and as such are ready for direct use in further STROBE protocols, such as the
[AEAD example protocol](https://strobe.sourceforge.io/examples/aead/).

# Use

Don't.

I'm not a cryptographer, this code has not been audited in any capacity.

# TODO

The current STROBE library used requires passing vecs, which means this library
isn't ideal for use in a no_std environment without alloc.
