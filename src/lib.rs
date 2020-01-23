#![no_std]
#![deny(missing_docs)]
#![cfg_attr(feature = "nightly", feature(external_doc))]
#![cfg_attr(feature = "nightly", doc(include = "../README.md"))]
//!
extern crate curve25519_dalek;
extern crate rand;
extern crate strobe_rs;

use core::cmp;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand::{CryptoRng, Rng};
use strobe_rs::{SecParam, Strobe};

/// The SessionHandshake sub-protocol is used to arrive at a shared session id
pub struct SessionHandshake {
    id: [u8; 64],
}

const SESSION_HANDSHAKE_LENGTH: usize = 64;

impl SessionHandshake {
    /// Initiate a new handshake to arrive at a shared session id
    pub fn initiate<T>(rng: &mut T) -> SessionHandshake
    where
        T: Rng + CryptoRng,
    {
        let mut session = SessionHandshake { id: [0u8; 64] };
        rng.fill(&mut session.id[..]);
        session
    }

    /// Complete the handshake, resulting in a STROBE transcript bound to the session id
    pub fn complete(self, transcript: Option<Strobe>, handshake: SessionHandshake) -> Strobe {
        let mut transcript = transcript
            .map(|mut transcript| {
                transcript.ad(b"https://github.com/evq/yodel/session/handshake", false);
                transcript
            })
            .unwrap_or_else(|| {
                Strobe::new(
                    b"https://github.com/evq/yodel/session/handshake",
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

        let mut id: [u8; 64] = [0u8; 64];
        id.copy_from_slice(&bytes[..64]);

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
#[derive(Clone, Copy)]
pub struct Handshake {
    session_id: [u8; 64],
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
        bytes[..64].copy_from_slice(&self.session_id);
        bytes[64..].copy_from_slice(self.blinded_password.as_bytes());
        bytes
    }

    /// Construct a Handshake from a slice of bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Handshake, ()> {
        if bytes.len() != HANDSHAKE_LENGTH {
            return Err(());
        }

        let mut session_id: [u8; 64] = [0u8; 64];
        session_id.copy_from_slice(&bytes[..64]);

        let mut bits: [u8; 32] = [0u8; 32];
        bits.copy_from_slice(&bytes[64..]);

        Ok(Handshake {
            session_id,
            blinded_password: CompressedRistretto(bits),
        })
    }

    pub(crate) fn consume(self) -> CompressedRistretto {
        self.blinded_password
    }
}

impl Yodeler {
    /// Create a new Yodeler
    pub fn new<T>(mut transcript: Strobe, rng: &mut T, password: &[u8]) -> (Self, Handshake)
    where
        T: Rng + CryptoRng,
    {
        // domain seperator
        transcript.ad(b"https://github.com/evq/yodel/pace", false);

        // add the password to the transcript
        transcript.ad(password, false);

        // hash the transcript (and thus password) to a point.
        //
        // NOTE using from_uniform_bytes (which performs two Elligator2 mappings
        // and adds them) avoids the original SPEKE basepoint generation issue which allowed
        // for multiple guesses per online run due to exponential equivalence between passwords.
        //
        // there is a second issue possible when deriving the base point, namely when hashing to
        // a twisted curve it is possible to either land on the curve or the twist. in
        // situations where the same password is being used with a different transcript this
        // would leak 1 bit per run. Elligator2 should ensure all points land on the curve and
        // the Ristretto implementation of scalar multiplication will reject points on the twist,
        // so this should not be an issue in this implementation.
        let mut buf = [0; 64];
        transcript.prf(&mut buf, false);
        let g = RistrettoPoint::from_uniform_bytes(&buf);

        // TODO should we RATCHET here?

        // protocol becomes full-duplex
        let rx_transcript = transcript.clone();
        let mut tx_transcript = transcript.clone();

        // the session identifier (A)
        //
        // NOTE ensures that messages cannot be replayed from between sessions
        let mut session_id = [0u8; 64];
        rng.fill(&mut session_id[..]);

        // generate a random blind (x)
        let blind = Scalar::random(rng);
        // X = g ^ x
        let blinded_password = g * blind;

        let handshake = Handshake {
            session_id,
            blinded_password: blinded_password.compress(),
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
        let mut rng = OsRng::new().unwrap();

        let s_a = Strobe::new(b"yodeltest", SecParam::B128);
        let s_b = Strobe::new(b"yodeltest", SecParam::B128);

        let (yodeler_a, X) = Yodeler::new(s_a, &mut rng, "testpassword".as_bytes());
        let (yodeler_b, Y) = Yodeler::new(s_b, &mut rng, "testpassword".as_bytes());

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
    fn different_password_fails() {
        let mut rng = OsRng::new().unwrap();

        let s_a = Strobe::new(b"yodeltest", SecParam::B128);
        let s_b = Strobe::new(b"yodeltest", SecParam::B128);

        let (yodeler_a, X) = Yodeler::new(s_a, &mut rng, "testpassword".as_bytes());
        let (yodeler_b, Y) = Yodeler::new(s_b, &mut rng, "passwordtest".as_bytes());

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
    fn session_id_works() {
        let mut rng = OsRng::new().unwrap();

        let s_a = SessionHandshake::initiate(&mut rng);
        let s_b = SessionHandshake::initiate(&mut rng);

        let s_a_bytes = s_a.to_bytes();
        let s_b_bytes = s_b.to_bytes();

        let (yodeler_a, X) = Yodeler::new(
            s_a.complete(None, SessionHandshake::from_bytes(&s_b_bytes).unwrap()),
            &mut rng,
            "testpassword".as_bytes(),
        );
        let (yodeler_b, Y) = Yodeler::new(
            s_b.complete(None, SessionHandshake::from_bytes(&s_a_bytes).unwrap()),
            &mut rng,
            "testpassword".as_bytes(),
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
