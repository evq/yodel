/// This crate takes a STROBE based approach to the patched SPEKE described in
/// https://arxiv.org/pdf/1802.04900.pdf
extern crate alloc;

extern crate curve25519_dalek;
extern crate rand_core;
extern crate strobe_rs;

use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar::Scalar;
use rand_core::{CryptoRng, RngCore};
use strobe_rs::Strobe;

#[cfg(test)]
mod tests {
    extern crate rand;
    use strobe_rs::SecParam;
    use tests::rand::rngs::OsRng;

    use *;

    #[test]
    #[allow(non_snake_case)]
    fn same_password_works() {
        let mut rng = OsRng::new().unwrap();

        let s_a = Strobe::new(b"yodeltest".to_vec(), SecParam::B128);
        let s_b = Strobe::new(b"yodeltest".to_vec(), SecParam::B128);

        let (yodeler_a, X) = Yodeler::new(s_a, &mut rng, "testpassword".as_bytes());
        let (yodeler_b, Y) = Yodeler::new(s_b, &mut rng, "testpassword".as_bytes());

        let (mut tx_a, mut rx_a) = yodeler_a.complete(Y);
        let (mut tx_b, mut rx_b) = yodeler_b.complete(X);

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

        let (mut tx_a, mut rx_a) = yodeler_a.complete(Y);
        let (mut tx_b, mut rx_b) = yodeler_b.complete(X);

        assert_ne!(tx_a.prf(64, None, false), rx_b.prf(64, None, false));
        assert_ne!(tx_b.prf(64, None, false), rx_a.prf(64, None, false));
    }
}

pub struct Yodeler {
    tx_transcript: Strobe,
    rx_transcript: Strobe,
    blind: Scalar,
    handshake: Handshake,
}

#[derive(Clone, Copy)]
pub struct Handshake {
    session_id: [u8; 64],
    blinded_password: RistrettoPoint,
}

impl Handshake {
    pub fn to_bytes(&self) -> [u8; 96] {
        let mut bytes: [u8; 96] = [0u8; 96];
        bytes[..64].copy_from_slice(&self.session_id);
        bytes[64..].copy_from_slice(self.blinded_password.compress().as_bytes());
        bytes
    }

    pub fn consume(self) -> RistrettoPoint {
        self.blinded_password
    }
}

impl Yodeler {
    pub fn new<T>(mut transcript: Strobe, rng: &mut T, password: &[u8]) -> (Self, Handshake)
    where
        T: RngCore + CryptoRng,
    {
        // domain seperator
        transcript.ad(b"https://github.com/evq/yodel".to_vec(), None, false);

        // add the password to the transcript
        transcript.ad(password.to_vec(), None, false);

        // hash the password to a point
        let mut buf = [0; 64];
        buf.copy_from_slice(&transcript.prf(64, None, false));
        let g = RistrettoPoint::from_uniform_bytes(&buf);

        // protocol becomes full-duplex
        let rx_transcript = transcript.clone();
        let mut tx_transcript = transcript.clone();

        // NOTE the session identifier (A) ensures that messages cannot be replayed from between sessions
        let mut session_id = [0u8; 64];
        rng.fill_bytes(&mut session_id[..]);

        // generate a random blind (x)
        let blind = Scalar::random(rng);
        // X = g ^ x
        let blinded_password = g * blind;

        let handshake = Handshake {
            session_id,
            blinded_password,
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

    pub fn complete(mut self, handshake: Handshake) -> (Strobe, Strobe) {
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
        let shared_secret = handshake.consume() * self.blind;

        self.tx_transcript
            .key(shared_secret.compress().as_bytes().to_vec(), None, false);
        self.rx_transcript
            .key(shared_secret.compress().as_bytes().to_vec(), None, false);

        (self.tx_transcript, self.rx_transcript)
    }
}
