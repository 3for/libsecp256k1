use ecmult::ECMULT_GEN_CONTEXT;
use secp256k1::hmac_drbg::HmacDRBG;
use super::sha2::{Digest, Sha256};
use secp256k1::typenum::U32;
use secp256k1::scalar::Scalar;
use secp256k1::error::Error;
use secp256k1::keys::{ SecretKey};
use Signature;
use secp256k1::recovery_id::RecoveryId;

#[derive(Debug, Clone, Eq, PartialEq)]
/// Hashed message input to an ECDSA signature.
pub struct Message(pub Scalar);

impl Message {
    pub fn hash(b: &[u8]) -> Result<Message, Error> {
        let hash = Sha256::digest(b);
        let s = SecretKey::parse(array_ref!(hash,0, 32))?;
        Ok(Message::from(s))
    }

    pub fn parse(p: &[u8; 32]) -> Message {
        let mut m = Scalar::default();
        m.set_b32(p);

        Message(m)
    }

    pub fn serialize(&self) -> [u8; 32] {
        self.0.b32()
    }

    /// Sign a message using the secret key.
    pub fn sign(message: &Message, seckey: &SecretKey) -> Result<(Signature, RecoveryId), Error> {
        let seckey_b32 = seckey.0.b32();
        let message_b32 = message.0.b32();

        let mut drbg = HmacDRBG::<Sha256>::new(&seckey_b32, &message_b32, &[]);
        let generated = drbg.generate::<U32>(None);
        let mut nonce = Scalar::default();
        let mut overflow = nonce.set_b32(array_ref!(generated, 0, 32));

        while overflow || nonce.is_zero() {
            let generated = drbg.generate::<U32>(None);
            overflow = nonce.set_b32(array_ref!(generated, 0, 32));
        }

        let result = ECMULT_GEN_CONTEXT.sign_raw(&seckey.0, &message.0, &nonce);
        #[allow(unused_assignments)]
        {
            nonce = Scalar::default();
        }
        if let Ok((sigr, sigs, recid)) = result {
            return Ok((Signature { r: sigr, s: sigs }, RecoveryId(recid)));
        } else {
            return Err(result.err().unwrap());
        }
    }
}

impl From<SecretKey> for Message {
    fn from(k: SecretKey) -> Self {
        Message(k.0)
    }
}

#[test]
fn message_constructor() {
    let s = b"secret";
    assert!(Message::hash(s).is_ok());
}
