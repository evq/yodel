#![feature(alloc)]
#![deny(missing_docs)]
#![cfg_attr(feature = "nightly", feature(external_doc))]
#![cfg_attr(feature = "nightly", doc(include = "../README.md"))]
//!
extern crate alloc;

extern crate curve25519_dalek;
extern crate rand;
extern crate strobe_rs;

use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand::{CryptoRng, Rng};
use strobe_rs::Strobe;

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
        transcript.ad(b"https://github.com/evq/yodel".to_vec(), None, false);

        // add the password to the transcript
        transcript.ad(password.to_vec(), None, false);

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
        buf.copy_from_slice(&transcript.prf(64, None, false));
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
        tx_transcript.send_clr(handshake.to_bytes().to_vec(), None, false);

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
        self.tx_transcript
            .recv_clr(handshake.to_bytes().to_vec(), None, false);

        // catch the rx transcript up
        self.rx_transcript
            .recv_clr(handshake.to_bytes().to_vec(), None, false);
        self.rx_transcript
            .send_clr(self.handshake.to_bytes().to_vec(), None, false);

        // NOTE since the transcripts are bound to both handshakes, a MITM attempt at
        // a key malleability attack will fail (as it would change the blinded_password)

        // Y ^ x = (g ^ y) ^ x
        let shared_secret = handshake.consume().decompress().ok_or(())? * self.blind;

        self.tx_transcript
            .key(shared_secret.compress().as_bytes().to_vec(), None, false);
        self.rx_transcript
            .key(shared_secret.compress().as_bytes().to_vec(), None, false);

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

        let s_a = Strobe::new(b"yodeltest".to_vec(), SecParam::B128);
        let s_b = Strobe::new(b"yodeltest".to_vec(), SecParam::B128);

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

        assert_eq!(tx_a.prf(64, None, false), rx_b.prf(64, None, false));
        assert_eq!(tx_b.prf(64, None, false), rx_a.prf(64, None, false));
    }

    #[test]
    #[allow(non_snake_case)]
    fn different_password_fails() {
        let mut rng = OsRng::new().unwrap();

        let s_a = Strobe::new(b"yodeltest".to_vec(), SecParam::B128);
        let s_b = Strobe::new(b"yodeltest".to_vec(), SecParam::B128);

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

        assert_ne!(tx_a.prf(64, None, false), rx_b.prf(64, None, false));
        assert_ne!(tx_b.prf(64, None, false), rx_a.prf(64, None, false));
    }
}
