extern crate libsecp256k1_rs as secp256k1;

use secp256k1::{SecretKey, PublicKey, thread_rng, Message};
use secp256k1::schnorr::{Challenge};

fn main() {
    // Create a random private key
    let m = Message::hash(b"Meet me at 12").unwrap();
    let mut rng = thread_rng();
    let k = SecretKey::random(&mut rng);
    println!("My private key: {}", k);
    let P = PublicKey::from_secret_key(&k);
    
    //BAD signature without nonce. UNSAFE
    {
        // Challenge, e = H(P || m)
        let e = Challenge::new(&[&P, &m]).as_scalar().unwrap();

        //Signature
        let s = e * k;

        //Verify the signature
        assert_eq!(PublicKey::from_secret_key(&s), e*P);
        println!("UNSAFE Signature is valid!");
        //But let's try calculate the private key from known information
        let hacked = s * e.inv();
        assert_eq!(k, hacked);
        println!("Hacked key: {}", k);
    }

    // The above is without nounce. The schnorr should with nonce.
    {
        let nonce = SecretKey::random(&mut rng);
        println!("Nonce is: {}", nonce);
        let R = PublicKey::from_secret_key(&nonce);
        // Challenge, e = H(R||P||m)
        let e = Challenge::new(&[&R, &P, &m]).as_scalar().unwrap();
        //let e = Challenge::new(&[&P, &R, &m]).as_scalar().unwrap();//No matter with the `R P m` order.

        //Signature
        let s = nonce + e * k;

        //Verify the signature
        assert_eq!(PublicKey::from_secret_key(&s), e*P + R);
        println!("GOOD Signature is valid!");
    }
    
}