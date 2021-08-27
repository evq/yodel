#![no_std]
#![deny(missing_docs)]
#![cfg_attr(feature = "nightly", feature(external_doc))]
#![cfg_attr(feature = "nightly", doc(include = "../README.md"))]
//!
extern crate curve25519_dalek;
extern crate rand_core;
extern crate strobe_rs;

use core::cmp;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use strobe_rs::{SecParam, Strobe};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

const ORIGINATOR_ID_LENGTH: usize = 32;
const SESSION_ID_LENGTH: usize = 32;
const SESSION_HANDSHAKE_LENGTH: usize = SESSION_ID_LENGTH;

/// The SessionHandshake sub-protocol is used to arrive at a shared session id
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SessionHandshake {
    id: [u8; SESSION_ID_LENGTH],
}

impl SessionHandshake {
    /// Initiate a new handshake to arrive at a shared session id
    pub fn initiate<T>(rng: &mut T) -> SessionHandshake
    where
        T: RngCore + CryptoRng,
    {
        let mut session = SessionHandshake {
            id: [0u8; SESSION_ID_LENGTH],
        };
        rng.fill_bytes(&mut session.id[..]);
        session
    }

    /// Complete the handshake, resulting in a STROBE transcript bound to the session id
    pub fn complete(self, transcript: Option<Strobe>, handshake: SessionHandshake) -> Strobe {
        let mut transcript = transcript
            .map(|mut transcript| {
                transcript.ad(
                    b"https://github.com/evq/yodel/cpace/session/handshake",
                    false,
                );
                transcript
            })
            .unwrap_or_else(|| {
                Strobe::new(
                    b"https://github.com/evq/yodel/cpace/session/handshake",
                    SecParam::B256,
                )
            });
        // Inspired by "Analysing and Patching SPEKE in ISO/IEC." session key computation (A.)
        transcript.ad(cmp::min(self.id.as_ref(), handshake.id.as_ref()), false);
        transcript.ad(cmp::max(self.id.as_ref(), handshake.id.as_ref()), false);
        transcript
    }

    /// Convert the session handshake to bytes
    pub fn to_bytes(&self) -> [u8; SESSION_HANDSHAKE_LENGTH] {
        self.id
    }

    /// Construct a Handshake from a slice of bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<SessionHandshake, ()> {
        if bytes.len() != SESSION_HANDSHAKE_LENGTH {
            return Err(());
        }

        let mut id: [u8; SESSION_ID_LENGTH] = [0u8; SESSION_ID_LENGTH];
        id.copy_from_slice(&bytes[..SESSION_ID_LENGTH]);

        Ok(SessionHandshake { id })
    }
}

/// A Yodeler holds local state about a yodel session that is in progress
///
/// The resulting transcripts have had a strong `KEY` set as a result of the SPEKE handshake
/// and as such are ready for direct use in further STROBE protocols, such as the
/// [AEAD example protocol](https://strobe.sourceforge.io/examples/aead/).
/// There is no explicit key confirmation performed.
///
pub struct Yodeler {
    tx_transcript: Strobe,
    rx_transcript: Strobe,
    blind: Scalar,
    handshake: Handshake,
}

/// A Handshake results from creating a new yodel session and should be exchanged with the other party
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Handshake {
    session_id: Option<[u8; SESSION_ID_LENGTH]>,
    originator_id: [u8; ORIGINATOR_ID_LENGTH],
    blinded_password: CompressedRistretto,
}

/// Duplex is an output type wrapper around the tx and rx transcripts
pub struct Duplex {
    /// The transmitter transcript - shares state with the other party's reciever transcript
    pub tx: Strobe,
    /// The reciever transcript - shares state with the other party's transmitter transcript
    pub rx: Strobe,
}

const HANDSHAKE_LENGTH: usize = 96;

impl Handshake {
    /// Convert the handshake to bytes
    pub fn to_bytes(&self) -> [u8; HANDSHAKE_LENGTH] {
        let mut bytes: [u8; HANDSHAKE_LENGTH] = [0u8; HANDSHAKE_LENGTH];
        if let Some(session_id) = self.session_id {
            bytes[..SESSION_ID_LENGTH].copy_from_slice(&session_id);
        }
        bytes[SESSION_ID_LENGTH..SESSION_ID_LENGTH + ORIGINATOR_ID_LENGTH]
            .copy_from_slice(&self.originator_id);
        bytes[SESSION_ID_LENGTH + ORIGINATOR_ID_LENGTH..]
            .copy_from_slice(self.blinded_password.as_bytes());
        bytes
    }

    /// Construct a Handshake from a slice of bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Handshake, ()> {
        if bytes.len() != HANDSHAKE_LENGTH {
            return Err(());
        }
        let mut session_id: [u8; SESSION_ID_LENGTH] = [0u8; SESSION_ID_LENGTH];
        session_id.copy_from_slice(&bytes[..SESSION_ID_LENGTH]);

        let mut originator_id: [u8; ORIGINATOR_ID_LENGTH] = [0u8; ORIGINATOR_ID_LENGTH];
        originator_id
            .copy_from_slice(&bytes[SESSION_ID_LENGTH..SESSION_ID_LENGTH + ORIGINATOR_ID_LENGTH]);

        let mut bits: [u8; 32] = [0u8; 32];
        bits.copy_from_slice(&bytes[SESSION_ID_LENGTH + ORIGINATOR_ID_LENGTH..]);

        Ok(Handshake {
            session_id: session_id.iter().any(|x| *x != 0).then(|| session_id),
            originator_id,
            blinded_password: CompressedRistretto(bits),
        })
    }

    pub(crate) fn consume(self) -> CompressedRistretto {
        self.blinded_password
    }

    /// Respond to a handshake directly
    ///
    /// This is intended for use in cases where there is no shared session transcript.
    /// It will error if this handshake was created using a session transcript.
    pub fn respond<T>(
        self,
        rng: &mut T,
        password: &[u8],
        self_identity: &[u8],
    ) -> Result<(Duplex, Handshake), ()>
    where
        T: RngCore + CryptoRng,
    {
        match self.session_id {
            None => Err(()),
            Some(session_id) => {
                let mut transcript = Strobe::new(
                    b"https://github.com/evq/yodel/cpace/session/unilateral",
                    SecParam::B128,
                );
                transcript.ad(&session_id, false);
                let (yodeler, handshake) =
                    Yodeler::new(Some(transcript), rng, password, self_identity);
                Ok((yodeler.complete(self)?, handshake))
            }
        }
    }
}

fn transcript_into_generator(mut transcript: Strobe) -> RistrettoPoint {
    // hash the transcript (and thus password) to a point.
    //
    // NOTE using from_uniform_bytes (which performs two Elligator2 mappings
    // and adds them) avoids the original SPEKE basepoint generation issue which allowed
    // for multiple guesses per online run due to exponential equivalence between passwords.
    //
    // there is a second issue possible when deriving the base point, namely when hashing to
    // a twisted curve it is possible to either land on the curve or the twist. in
    // situations where the same password is being used with a different transcript this
    // would leak 1 bit per run. use of ristretto eliminates this issue
    let mut buf = [0; 64];
    transcript.prf(&mut buf, false);
    RistrettoPoint::from_uniform_bytes(&buf)
}

fn derive_originator_id(self_identity: &[u8]) -> [u8; ORIGINATOR_ID_LENGTH] {
    let mut originator_id_transcript = Strobe::new(
        b"https://github.com/evq/yodel/cpace/originator_id",
        SecParam::B128,
    );
    originator_id_transcript.ad(self_identity, false);
    let mut originator_id = [0u8; ORIGINATOR_ID_LENGTH];
    originator_id_transcript.prf(&mut originator_id, false);

    originator_id
}

impl Yodeler {
    /// Create a new Yodeler
    ///
    /// The session transcript SHOULD include a session identifier
    /// (ensured to be distinct from any concurrent sessions by the application),
    /// an encoding of the known user idenities ( including network ids such as IP/port,
    /// MAC address, etc ) and any other additional data that the parties wish to authenticate.
    ///
    /// If a transcript is not provided, one will be created and a random
    /// session id will be chosen and bound. In this case, the other user must use the
    /// Handshake.respond method as the symmetry of the protocol has been broken.
    ///
    /// NOTE that it's critical the identity passed is self determined and does NOT change
    /// while there are active sessions. Use of an identity which is assigned outside of your control
    /// may lead to impersonation attacks in contexts that allow concurrent sessions
    pub fn new<T>(
        session_transcript: Option<Strobe>,
        rng: &mut T,
        password: &[u8],
        self_identity: &[u8],
    ) -> (Self, Handshake)
    where
        T: RngCore + CryptoRng,
    {
        let (session_id, mut transcript) = match session_transcript {
            Some(transcript) => (None, transcript),
            None => {
                let mut transcript = Strobe::new(
                    b"https://github.com/evq/yodel/cpace/session/unilateral",
                    SecParam::B128,
                );
                let mut session_id = [0u8; SESSION_ID_LENGTH];
                rng.fill_bytes(&mut session_id[..]);
                transcript.ad(&session_id, false);

                (Some(session_id), transcript)
            }
        };

        // prepare for the protocol becoming full-duplex
        let mut rx_transcript = transcript.clone();
        let mut tx_transcript = transcript.clone();

        // tx/rx domain seperators
        tx_transcript.ad(b"https://github.com/evq/yodel/cpace", false);
        rx_transcript.ad(b"https://github.com/evq/yodel/cpace", false);

        // add the password to the original transcript
        transcript.ad(b"https://github.com/evq/yodel/cpace/password", false);
        transcript.key(password, false);

        // after this point we will no longer use the original transcript which had the password
        // mixed into it. this is to ensure that if a session key is leaked it provides no useful
        // information about the password to an attacker
        let g = transcript_into_generator(transcript);

        // generate a random blind (x)
        let blind = Scalar::random(rng);
        // X = g ^ x
        let blinded_password = (g * blind).compress();

        // NOTE this ensures that messages cannot be replayed between concurrent sessions
        // when combined with a check when we complete the handshake
        let originator_id = derive_originator_id(self_identity);

        let handshake = Handshake {
            session_id,
            originator_id,
            blinded_password: blinded_password,
        };
        tx_transcript.send_clr(&handshake.to_bytes(), false);

        (
            Yodeler {
                tx_transcript,
                rx_transcript,
                blind,
                handshake,
            },
            handshake,
        )
    }

    /// Complete the handshake, resulting in duplex STROBE transcripts
    pub fn complete(mut self, handshake: Handshake) -> Result<Duplex, ()> {
        if handshake.originator_id == self.handshake.originator_id {
            // Deny attempt to replay our own concurrent sessions
            return Err(());
        }

        // apply the incoming handshake
        self.tx_transcript.recv_clr(&handshake.to_bytes(), false);

        // catch the rx transcript up
        self.rx_transcript.recv_clr(&handshake.to_bytes(), false);
        self.rx_transcript
            .send_clr(&self.handshake.to_bytes(), false);

        // NOTE since the transcripts are bound to both handshakes, a MITM attempt at
        // a key malleability attack will fail (as it would change the blinded_password)

        // Y ^ x = (g ^ y) ^ x
        let shared_secret = handshake.consume().decompress().ok_or(())? * self.blind;

        self.tx_transcript
            .key(shared_secret.compress().as_bytes(), false);
        self.rx_transcript
            .key(shared_secret.compress().as_bytes(), false);

        Ok(Duplex {
            tx: self.tx_transcript,
            rx: self.rx_transcript,
        })
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;
    use strobe_rs::SecParam;

    use crate::*;

    #[test]
    #[allow(non_snake_case)]
    fn same_password_works() {
        let mut rng = OsRng;

        let s_a = Some(Strobe::new(b"yodeltest", SecParam::B128));
        let s_b = Some(Strobe::new(b"yodeltest", SecParam::B128));

        let (yodeler_a, X) = Yodeler::new(s_a, &mut rng, "testpassword".as_bytes(), "A".as_bytes());
        let (yodeler_b, Y) = Yodeler::new(s_b, &mut rng, "testpassword".as_bytes(), "B".as_bytes());

        let X = Handshake::from_bytes(&X.to_bytes()).unwrap();
        let Y = Handshake::from_bytes(&Y.to_bytes()).unwrap();

        let Duplex {
            tx: mut tx_a,
            rx: mut rx_a,
        } = yodeler_a.complete(Y).unwrap();
        let Duplex {
            tx: mut tx_b,
            rx: mut rx_b,
        } = yodeler_b.complete(X).unwrap();

        let mut tx_a_prf = [0u8; 64];
        tx_a.prf(&mut tx_a_prf, false);
        let mut rx_b_prf = [0u8; 64];
        rx_b.prf(&mut rx_b_prf, false);

        assert_eq!(tx_a_prf.as_ref(), rx_b_prf.as_ref());

        let mut tx_b_prf = [0u8; 64];
        tx_b.prf(&mut tx_b_prf, false);
        let mut rx_a_prf = [0u8; 64];
        rx_a.prf(&mut rx_a_prf, false);

        assert_eq!(tx_b_prf.as_ref(), rx_a_prf.as_ref());
    }

    #[test]
    #[allow(non_snake_case)]
    fn same_password_no_transcript_works() {
        let mut rng = OsRng;

        let (yodeler_a, X) =
            Yodeler::new(None, &mut rng, "testpassword".as_bytes(), "A".as_bytes());
        let X = Handshake::from_bytes(&X.to_bytes()).unwrap();

        let (
            Duplex {
                tx: mut tx_b,
                rx: mut rx_b,
            },
            Y,
        ) = X
            .respond(&mut rng, "testpassword".as_bytes(), "B".as_bytes())
            .unwrap();

        let Duplex {
            tx: mut tx_a,
            rx: mut rx_a,
        } = yodeler_a.complete(Y).unwrap();

        let mut tx_a_prf = [0u8; 64];
        tx_a.prf(&mut tx_a_prf, false);
        let mut rx_b_prf = [0u8; 64];
        rx_b.prf(&mut rx_b_prf, false);

        assert_eq!(tx_a_prf.as_ref(), rx_b_prf.as_ref());

        let mut tx_b_prf = [0u8; 64];
        tx_b.prf(&mut tx_b_prf, false);
        let mut rx_a_prf = [0u8; 64];
        rx_a.prf(&mut rx_a_prf, false);

        assert_eq!(tx_b_prf.as_ref(), rx_a_prf.as_ref());
    }

    #[test]
    #[allow(non_snake_case)]
    fn different_password_fails() {
        let mut rng = OsRng;

        let s_a = Some(Strobe::new(b"yodeltest", SecParam::B128));
        let s_b = Some(Strobe::new(b"yodeltest", SecParam::B128));

        let (yodeler_a, X) = Yodeler::new(s_a, &mut rng, "testpassword".as_bytes(), "A".as_bytes());
        let (yodeler_b, Y) = Yodeler::new(s_b, &mut rng, "passwordtest".as_bytes(), "B".as_bytes());

        let Duplex {
            tx: mut tx_a,
            rx: mut rx_a,
        } = yodeler_a.complete(Y).unwrap();
        let Duplex {
            tx: mut tx_b,
            rx: mut rx_b,
        } = yodeler_b.complete(X).unwrap();

        let mut tx_a_prf = [0u8; 64];
        tx_a.prf(&mut tx_a_prf, false);
        let mut rx_b_prf = [0u8; 64];
        rx_b.prf(&mut rx_b_prf, false);

        assert_ne!(tx_a_prf.as_ref(), rx_b_prf.as_ref());

        let mut tx_b_prf = [0u8; 64];
        tx_b.prf(&mut tx_b_prf, false);
        let mut rx_a_prf = [0u8; 64];
        rx_a.prf(&mut rx_a_prf, false);

        assert_ne!(tx_b_prf.as_ref(), rx_a_prf.as_ref());
    }

    #[test]
    #[allow(non_snake_case)]
    fn different_transcript_fails() {
        let mut rng = OsRng;

        let s_a = Some(Strobe::new(b"yodeltest", SecParam::B128));
        let s_b = Some(Strobe::new(b"fail", SecParam::B128));

        let (yodeler_a, X) = Yodeler::new(s_a, &mut rng, "testpassword".as_bytes(), "A".as_bytes());
        let (yodeler_b, Y) = Yodeler::new(s_b, &mut rng, "testpassword".as_bytes(), "B".as_bytes());

        let Duplex {
            tx: mut tx_a,
            rx: mut rx_a,
        } = yodeler_a.complete(Y).unwrap();
        let Duplex {
            tx: mut tx_b,
            rx: mut rx_b,
        } = yodeler_b.complete(X).unwrap();

        let mut tx_a_prf = [0u8; 64];
        tx_a.prf(&mut tx_a_prf, false);
        let mut rx_b_prf = [0u8; 64];
        rx_b.prf(&mut rx_b_prf, false);

        assert_ne!(tx_a_prf.as_ref(), rx_b_prf.as_ref());

        let mut tx_b_prf = [0u8; 64];
        tx_b.prf(&mut tx_b_prf, false);
        let mut rx_a_prf = [0u8; 64];
        rx_a.prf(&mut rx_a_prf, false);

        assert_ne!(tx_b_prf.as_ref(), rx_a_prf.as_ref());
    }

    #[test]
    #[allow(non_snake_case)]
    fn self_fails() {
        let mut rng = OsRng;

        let s_a_1 = Some(Strobe::new(b"yodeltest", SecParam::B128));

        // A attempts to connect to B, but C replays the result

        let (yodeler_a_1, X) =
            Yodeler::new(s_a_1, &mut rng, "testpassword".as_bytes(), "A".as_bytes());

        assert!(yodeler_a_1.complete(X).is_err());
    }

    #[test]
    #[allow(non_snake_case)]
    fn same_originator_id_fails() {
        let mut rng = OsRng;

        let s_a_1 = Some(Strobe::new(b"yodeltest", SecParam::B128));
        let s_a_2 = s_a_1.clone();

        // A attempts to connect to B, but C captures the result and uses it to initiate a new
        // session with A

        let (yodeler_a_1, X) =
            Yodeler::new(s_a_1, &mut rng, "testpassword".as_bytes(), "A".as_bytes());
        let (yodeler_a_2, Y) =
            Yodeler::new(s_a_2, &mut rng, "testpassword".as_bytes(), "A".as_bytes());

        assert!(yodeler_a_2.complete(X).is_err());
        assert!(yodeler_a_1.complete(Y).is_err());
    }

    #[test]
    #[allow(non_snake_case)]
    fn tampering_originator_id_fails() {
        let mut rng = OsRng;

        let s_a_1 = Some(Strobe::new(b"yodeltest", SecParam::B128));
        let s_a_2 = s_a_1.clone();

        // again A attempts to connect to B, but C captures the result,
        // this time tampering with it and using it to initiate a new session with A

        let (yodeler_a_1, mut X) =
            Yodeler::new(s_a_1, &mut rng, "testpassword".as_bytes(), "A".as_bytes());
        let (yodeler_a_2, mut Y) =
            Yodeler::new(s_a_2, &mut rng, "testpassword".as_bytes(), "A".as_bytes());

        X.originator_id = derive_originator_id("B".as_bytes());
        Y.originator_id = derive_originator_id("B".as_bytes());

        let result_a_2 = yodeler_a_2.complete(X);
        let result_a_1 = yodeler_a_1.complete(Y);

        let Duplex {
            tx: mut tx_a_2,
            rx: mut rx_a_2,
        } = result_a_2.unwrap();

        let Duplex {
            tx: mut tx_a_1,
            rx: mut rx_a_1,
        } = result_a_1.unwrap();

        let mut tx_a_1_prf = [0u8; 64];
        tx_a_1.prf(&mut tx_a_1_prf, false);
        let mut rx_a_2_prf = [0u8; 64];
        rx_a_2.prf(&mut rx_a_2_prf, false);

        assert_ne!(tx_a_1_prf.as_ref(), rx_a_2_prf.as_ref());

        let mut tx_a_2_prf = [0u8; 64];
        tx_a_2.prf(&mut tx_a_2_prf, false);
        let mut rx_a_1_prf = [0u8; 64];
        rx_a_1.prf(&mut rx_a_1_prf, false);

        assert_ne!(tx_a_2_prf.as_ref(), rx_a_1_prf.as_ref());
    }

    #[test]
    #[allow(non_snake_case)]
    fn session_id_agreement_works() {
        let mut rng = OsRng;

        let s_a = SessionHandshake::initiate(&mut rng);
        let s_b = SessionHandshake::initiate(&mut rng);

        let s_a_bytes = s_a.to_bytes();
        let s_b_bytes = s_b.to_bytes();

        let (yodeler_a, X) = Yodeler::new(
            Some(s_a.complete(None, SessionHandshake::from_bytes(&s_b_bytes).unwrap())),
            &mut rng,
            "testpassword".as_bytes(),
            "A".as_bytes(),
        );
        let (yodeler_b, Y) = Yodeler::new(
            Some(s_b.complete(None, SessionHandshake::from_bytes(&s_a_bytes).unwrap())),
            &mut rng,
            "testpassword".as_bytes(),
            "B".as_bytes(),
        );

        let Duplex {
            tx: mut tx_a,
            rx: mut rx_a,
        } = yodeler_a.complete(Y).unwrap();
        let Duplex {
            tx: mut tx_b,
            rx: mut rx_b,
        } = yodeler_b.complete(X).unwrap();

        let mut tx_a_prf = [0u8; 64];
        tx_a.prf(&mut tx_a_prf, false);
        let mut rx_b_prf = [0u8; 64];
        rx_b.prf(&mut rx_b_prf, false);

        assert_eq!(tx_a_prf.as_ref(), rx_b_prf.as_ref());

        let mut tx_b_prf = [0u8; 64];
        tx_b.prf(&mut tx_b_prf, false);
        let mut rx_a_prf = [0u8; 64];
        rx_a.prf(&mut rx_a_prf, false);

        assert_eq!(tx_b_prf.as_ref(), rx_a_prf.as_ref());
    }
}
