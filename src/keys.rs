use core::ops::{Add, Mul, Neg};
use ecmult::ECMULT_CONTEXT;
use ecmult::ECMULT_GEN_CONTEXT;
use field::Field;
use group::{Affine, Jacobian};
use rand::Rng;
use scalar::Scalar;
use Error;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
/// Public key on a secp256k1 curve.
pub struct PublicKey(pub(crate) Affine);

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
/// Secret key (256-bit) on a secp256k1 curve.
pub struct SecretKey(pub(crate) Scalar);

impl PublicKey {
    /// Create a public key from a private key by performing P = k.G
    pub fn from_secret_key(seckey: &SecretKey) -> PublicKey {
        let mut pj = Jacobian::default();
        ECMULT_GEN_CONTEXT.ecmult_gen(&mut pj, &seckey.0);
        let mut p = Affine::default();
        p.set_gej(&pj);
        PublicKey(p)
    }

    /// Create a public key from a compressed public key. Remember that Public keys are just points on the elliptic
    /// curve, so you can derive the full point by supplying the x-coordinate and the parity. By convention, compressed
    /// public keys hold the parity in the first byte and the x-coordinate in the next 32 bytes.
    pub fn parse_compressed(p: &[u8; 33]) -> Result<PublicKey, Error> {
        if !(p[0] == 0x02 || p[0] == 0x03) {
            return Err(Error::InvalidPublicKey);
        }
        let mut x = Field::default();
        if !x.set_b32(array_ref!(p, 1, 32)) {
            return Err(Error::InvalidPublicKey);
        }
        let mut elem = Affine::default();
        if !elem.set_xo_var(&x, p[0] == 0x03) {
            return Err(Error::InvalidPublicKey);
        }
        if elem.is_infinity() {
            return Err(Error::InvalidPublicKey);
        }
        if elem.is_valid_var() {
            return Ok(PublicKey(elem));
        } else {
            return Err(Error::InvalidPublicKey);
        }
    }

    /// Create a PublicKey from 65-byte binary representation of a public key. The first byte is a prefix (must be 4,6,
    /// or 7). The next 32 bytes represent the x-coordinate; and the last 32 bytes represent thew y-coordinate.
    pub fn parse(p: &[u8; 65]) -> Result<PublicKey, Error> {
        use util::{TAG_PUBKEY_HYBRID_EVEN, TAG_PUBKEY_HYBRID_ODD};

        if !(p[0] == 0x04 || p[0] == 0x06 || p[0] == 0x07) {
            return Err(Error::InvalidPublicKey);
        }
        let mut x = Field::default();
        let mut y = Field::default();
        if !x.set_b32(array_ref!(p, 1, 32)) {
            return Err(Error::InvalidPublicKey);
        }
        if !y.set_b32(array_ref!(p, 33, 32)) {
            return Err(Error::InvalidPublicKey);
        }
        let mut elem = Affine::default();
        elem.set_xy(&x, &y);
        if (p[0] == TAG_PUBKEY_HYBRID_EVEN || p[0] == TAG_PUBKEY_HYBRID_ODD)
            && (y.is_odd() != (p[0] == TAG_PUBKEY_HYBRID_ODD))
        {
            return Err(Error::InvalidPublicKey);
        }
        if elem.is_infinity() {
            return Err(Error::InvalidPublicKey);
        }
        if elem.is_valid_var() {
            return Ok(PublicKey(elem));
        } else {
            return Err(Error::InvalidPublicKey);
        }
    }

    /// Return the 65-bit serialization of the public key. The first byte is always 0x04 to represent an uncompressed
    ///public key.
    pub fn serialize(&self) -> [u8; 65] {
        use util::TAG_PUBKEY_UNCOMPRESSED;

        debug_assert!(!self.0.is_infinity());

        let mut ret = [0u8; 65];
        let mut elem = self.0.clone();

        elem.x.normalize_var();
        elem.y.normalize_var();
        elem.x.fill_b32(array_mut_ref!(ret, 1, 32));
        elem.y.fill_b32(array_mut_ref!(ret, 33, 32));
        ret[0] = TAG_PUBKEY_UNCOMPRESSED;

        ret
    }

    /// Return the 33-bit serialization of the compressed public key.
    pub fn serialize_compressed(&self) -> [u8; 33] {
        use util::{TAG_PUBKEY_EVEN, TAG_PUBKEY_ODD};

        debug_assert!(!self.0.is_infinity());

        let mut ret = [0u8; 33];
        let mut elem = self.0.clone();

        elem.x.normalize_var();
        elem.y.normalize_var();
        elem.x.fill_b32(array_mut_ref!(ret, 1, 32));
        ret[0] = if elem.y.is_odd() {
            TAG_PUBKEY_ODD
        } else {
            TAG_PUBKEY_EVEN
        };

        ret
    }
}

impl Into<Affine> for PublicKey {
    fn into(self) -> Affine {
        self.0
    }
}

impl Add for PublicKey {
    type Output = PublicKey;

    fn add(self, rhs: PublicKey) -> <Self as Add<PublicKey>>::Output {
        let mut j1 = Jacobian::default();
        j1.set_ge(&self.0);
        let j2 = j1.add_ge(&rhs.0);
        let mut ret = Affine::default();
        ret.set_gej(&j2);
        PublicKey(ret)
    }
}

impl SecretKey {
    /// Read a 32-byte array into a Secret key
    pub fn parse(p: &[u8; 32]) -> Result<SecretKey, Error> {
        let mut elem = Scalar::default();
        if !elem.set_b32(p) && !elem.is_zero() {
            Ok(SecretKey(elem))
        } else {
            Err(Error::InvalidSecretKey)
        }
    }

    /// Create a new random secret key
    /// # Examples
    /// ```
    /// extern crate rand;
    /// extern crate secp256k1;
    /// use rand::thread_rng;
    /// use secp256k1::SecretKey;
    ///
    /// let k1 = SecretKey::random(&mut thread_rng());
    /// ```
    pub fn random<R: Rng>(rng: &mut R) -> SecretKey {
        loop {
            let mut ret = [0u8; 32];
            rng.fill_bytes(&mut ret);

            match Self::parse(&ret) {
                Ok(key) => return key,
                Err(_) => (),
            }
        }
    }

    /// Represent a SecretKey as a 32-byte array
    pub fn serialize(&self) -> [u8; 32] {
        self.0.b32()
    }
}

impl Into<Scalar> for SecretKey {
    fn into(self) -> Scalar {
        self.0
    }
}

impl Add for SecretKey {
    type Output = SecretKey;

    fn add(self, rhs: SecretKey) -> <Self as Add<SecretKey>>::Output {
        SecretKey(self.0 + rhs.0)
    }
}

impl Mul<SecretKey> for SecretKey {
    type Output = SecretKey;

    fn mul(self, rhs: SecretKey) -> SecretKey {
        SecretKey(self.0 * rhs.0)
    }
}

impl Mul<PublicKey> for SecretKey {
    type Output = PublicKey;

    fn mul(self, rhs: PublicKey) -> PublicKey {
        let mut pj = Jacobian::default();
        ECMULT_CONTEXT.ecmult_const(&mut pj, &rhs.0, &self.0);
        let mut p = Affine::default();
        p.set_gej(&pj);
        PublicKey(p)
    }
}

impl Neg for SecretKey {
    type Output = SecretKey;

    fn neg(self) -> <Self as Neg>::Output {
        SecretKey(-self.0)
    }
}
