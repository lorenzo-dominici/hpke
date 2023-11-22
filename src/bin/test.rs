use hpke::{*, kem::*, kdf::*, aead::*, };
use rand::{rngs::StdRng, SeedableRng};
use hex;

// These types define the ciphersuite Alice and Bob will be using
type KEM = X25519HkdfSha256;
type AEAD = AesGcm128;
type KDF = HkdfSha256;

fn main() {
    let mut csprng = StdRng::from_entropy();

    let bob_pk = hex::decode("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d").unwrap();
    let bob_sk = hex::decode("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8").unwrap();

    let bob_pk = <KEM as hpke::Kem>::PublicKey::from_bytes(&bob_pk).unwrap();
    let bob_sk = <KEM as hpke::Kem>::PrivateKey::from_bytes(&bob_sk).unwrap();
    
    // This is a description string for the session. Both Alice and Bob need to know this value.
    // It's not secret.
    let info_str = b"Alice and Bob's weekly chat";
    
    // Alice initiates a session with Bob. OpModeS::Base means that Alice is not authenticating
    // herself at all. If she had a public key herself, or a pre-shared secret that Bob also
    // knew, she'd be able to authenticate herself. See the OpModeS and OpModeR types for more
    // detail.
    let (encapsulated_key, mut encryption_context) =
        hpke::setup_sender::<AEAD, KDF, KEM, _>(&OpModeS::Base, &bob_pk, info_str, &mut csprng)
            .expect("invalid server pubkey!");
    
    // Alice encrypts a message to Bob. `aad` is authenticated associated data that is not
    // encrypted.
    let msg = b"fronthand or backhand?";
    let aad = b"a gentleman's game";
    // To seal without allocating:
    //     let auth_tag = encryption_context.seal_in_place_detached(&mut msg, aad)?;
    // To seal with allocating:
    let ciphertext = encryption_context.seal(msg, aad).expect("encryption failed!");
    
    // ~~~
    // Alice sends the encapsulated key, message ciphertext, AAD, and auth tag to Bob over the
    // internet. Alice doesn't care if it's an insecure connection, because only Bob can read
    // her ciphertext.
    // ~~~
    
    // Somewhere far away, Bob receives the data and makes a decryption session
    let mut decryption_context =
        hpke::setup_receiver::<AEAD, KDF, KEM>(
            &OpModeR::Base,
            &bob_sk,
            &encapsulated_key,
            info_str,
        ).expect("failed to set up receiver!");
    // To open without allocating:
    //     decryption_context.open_in_place_detached(&mut ciphertext, aad, &auth_tag)
    // To open with allocating:
    let plaintext = decryption_context.open(&ciphertext, aad).expect("invalid ciphertext!");
    
    assert_eq!(&plaintext, b"fronthand or backhand?");
    println!("pt: {}", std::str::from_utf8(msg).unwrap());
    println!("ct: {}", hex::encode(msg));
    println!("pt: {}", std::str::from_utf8(&plaintext).unwrap());
}
