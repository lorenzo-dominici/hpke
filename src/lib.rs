use error::*;
use hpke::{self, kem::{self, Kem}, kdf::{self, Kdf}, aead::{self, Aead}, OpModeR, OpModeS, HpkeError, Serializable, Deserializable, PskBundle};
use serde_json;
use std::fs;
use rand;

mod config;
pub mod error;

pub fn test(tests: Vec<String>) {
    todo!()
}

pub fn encrypt(config: &str, data: &str) {
    let cfg_str = fs::read_to_string(config).expect_or_exit("Error: config file reading failed");
    let sender: config::Entity = serde_json::from_str(&cfg_str).expect_or_exit("Error: config file ill formatted");
    let data_str = fs::read_to_string(data).expect_or_exit("Error: data file reading failed");

    if !config::check_sender(&sender, data_str.as_bytes()) {
        exit_println("Error: inconsistent data or parameters");
    }
    //TODO: call sss_ipd
    todo!()
}

pub fn decrypt(config: &str, data: &str) {
    let cfg_str = fs::read_to_string(config).expect_or_exit("Error: config file reading failed");
    let receiver: config::Entity = serde_json::from_str(&cfg_str).expect_or_exit("Error: config file ill formatted");
    let data_str = fs::read_to_string(data).expect_or_exit("Error: data file reading failed");
    let exc_data: config::ExchangedData = serde_json::from_str(&data_str).expect_or_exit("Error: data file ill formatted");

    if !config::check_receiver(&receiver, &exc_data) {
        exit_println("Error: inconsistent data or parameters");
    }
    //TODO: call sso_ipd
    todo!()
}

fn sss_ipd(kem_id: u16, kdf_id: u16, aead_id: u16, mode: u8, psk: Option<Vec<u8>>, psk_id: Option<Vec<u8>>, pk_s: Option<Vec<u8>>, sk_s: Option<Vec<u8>>, pk_r: &[u8], info: &[u8], pt: &mut [u8], aad: &[u8], csprng: &mut rand::rngs::StdRng) -> (Vec<u8>, Vec<u8>) {
    set_enc_kem(kem_id, kdf_id, aead_id, mode, psk, psk_id, pk_s, sk_s, pk_r, info, pt, aad, csprng)
}

fn set_enc_kem(kem_id: u16, kdf_id: u16, aead_id: u16, mode: u8, psk: Option<Vec<u8>>, psk_id: Option<Vec<u8>>, pk_s: Option<Vec<u8>>, sk_s: Option<Vec<u8>>, pk_r: &[u8], info: &[u8], pt: &mut [u8], aad: &[u8], csprng: &mut rand::rngs::StdRng) -> (Vec<u8>, Vec<u8>) {
    match kem_id {
        kem::DhP256HkdfSha256::KEM_ID => set_enc_kdf::<kem::DhP256HkdfSha256>(kdf_id, aead_id, mode, psk, psk_id, pk_s, sk_s, pk_r, info, pt, aad, csprng),
        kem::DhP384HkdfSha384::KEM_ID => set_enc_kdf::<kem::DhP384HkdfSha384>(kdf_id, aead_id, mode, psk, psk_id, pk_s, sk_s, pk_r, info, pt, aad, csprng),
        kem::X25519HkdfSha256::KEM_ID => set_enc_kdf::<kem::X25519HkdfSha256>(kdf_id, aead_id, mode, psk, psk_id, pk_s, sk_s, pk_r, info, pt, aad, csprng),
        _ => exit_println("Error: invalid `kem_id`"),
    }
}

fn set_enc_kdf<Kem_: Kem>(kdf_id: u16, aead_id: u16, mode: u8, psk: Option<Vec<u8>>, psk_id: Option<Vec<u8>>, pk_s: Option<Vec<u8>>, sk_s: Option<Vec<u8>>, pk_r: &[u8], info: &[u8], pt: &mut [u8], aad: &[u8], csprng: &mut rand::rngs::StdRng) -> (Vec<u8>, Vec<u8>) {
    let psk_v: Vec<u8>;
    let psk_id_v: Vec<u8>;
    let mode = match mode {
        0 => OpModeS::Base,
        1 => OpModeS::Psk(PskBundle {psk: {psk_v = psk.unwrap(); &psk_v}, psk_id: {psk_id_v = psk_id.unwrap(); &psk_id_v}}),
        2 => OpModeS::Auth((<Kem_ as Kem>::PrivateKey::from_bytes(&sk_s.unwrap()).unwrap(), <Kem_ as Kem>::PublicKey::from_bytes(&pk_s.unwrap()).unwrap())),
        3 => OpModeS::AuthPsk((<Kem_ as Kem>::PrivateKey::from_bytes(&sk_s.unwrap()).unwrap(), <Kem_ as Kem>::PublicKey::from_bytes(&pk_s.unwrap()).unwrap()), PskBundle {psk: {psk_v = psk.unwrap(); &psk_v}, psk_id: {psk_id_v = psk_id.unwrap(); &psk_id_v}}),
        _ => exit_println("Error: invalid `mode`")
    };
    match kdf_id {
        kdf::HkdfSha256::KDF_ID => set_enc_aead::<Kem_, kdf::HkdfSha256>(aead_id, mode, pk_r, info, pt, aad, csprng),
        kdf::HkdfSha384::KDF_ID => set_enc_aead::<Kem_, kdf::HkdfSha384>(aead_id, mode, pk_r, info, pt, aad, csprng),
        kdf::HkdfSha512::KDF_ID => set_enc_aead::<Kem_, kdf::HkdfSha512>(aead_id, mode, pk_r, info, pt, aad, csprng),
        _ => exit_println("Error: invalid `kdf_id`"),
    }
}

fn set_enc_aead<Kem_: Kem, Kdf_: Kdf>(aead_id: u16, mode: OpModeS<Kem_>, pk_r: &[u8], info: &[u8], pt: &mut [u8], aad: &[u8], csprng: &mut rand::rngs::StdRng) -> (Vec<u8>, Vec<u8>) {
    match aead_id {
        aead::AesGcm128::AEAD_ID => single_shot_enc::<Kem_, Kdf_, aead::AesGcm128>(mode, pk_r, info, pt, aad, csprng),
        aead::AesGcm256::AEAD_ID => single_shot_enc::<Kem_, Kdf_, aead::AesGcm256>(mode, pk_r, info, pt, aad, csprng),
        aead::ChaCha20Poly1305::AEAD_ID => single_shot_enc::<Kem_, Kdf_, aead::ChaCha20Poly1305>(mode, pk_r, info, pt, aad, csprng),
        _ => exit_println("Error: invalid `aead_id`"),
    }
}

fn single_shot_enc<Kem_: Kem, Kdf_: Kdf, Aead_: Aead>(mode: OpModeS<Kem_>, pk_r: &[u8], info: &[u8], pt: &mut [u8], aad: &[u8], csprng: &mut rand::rngs::StdRng) -> (Vec<u8>, Vec<u8>) {
    let pk_r= <Kem_ as Kem>::PublicKey::from_bytes(pk_r).expect_or_exit("Error: invalid `pk_r`");
    let (enc, aead_tag) = hpke::single_shot_seal_in_place_detached::<Aead_, Kdf_, Kem_, _>(&mode, &pk_r, info, pt, aad, csprng).expect_or_exit("Error: encryption failed");
    (enc.to_bytes().to_vec(), aead_tag.to_bytes().to_vec())
}

fn sso_ipd(kem_id: u16, kdf_id: u16, aead_id: u16, mode: u8, psk: Option<Vec<u8>>, psk_id: Option<Vec<u8>>, pk_s: Option<Vec<u8>>, sk_r: &[u8], enc: &[u8], info: &[u8], ct: &mut [u8], aad: &[u8], tag: &[u8]) {
    set_dec_kem(kem_id, kdf_id, aead_id, mode, psk, psk_id, pk_s, sk_r, enc, info, ct, aad, tag);
}

fn set_dec_kem(kem_id: u16, kdf_id: u16, aead_id: u16, mode: u8, psk: Option<Vec<u8>>, psk_id: Option<Vec<u8>>, pk_s: Option<Vec<u8>>, sk_r: &[u8], enc: &[u8], info: &[u8], ct: &mut [u8], aad: &[u8], tag: &[u8]) {
    match kem_id {
        kem::DhP256HkdfSha256::KEM_ID => set_dec_kdf::<kem::DhP256HkdfSha256>(kdf_id, aead_id, mode, psk, psk_id, pk_s, sk_r, enc, info, ct, aad, tag),
        kem::DhP384HkdfSha384::KEM_ID => set_dec_kdf::<kem::DhP384HkdfSha384>(kdf_id, aead_id, mode, psk, psk_id, pk_s, sk_r, enc, info, ct, aad, tag),
        kem::X25519HkdfSha256::KEM_ID => set_dec_kdf::<kem::X25519HkdfSha256>(kdf_id, aead_id, mode, psk, psk_id, pk_s, sk_r, enc, info, ct, aad, tag),
        _ => exit_println("Error: invalid `kem_id`"),
    };
}

fn set_dec_kdf<Kem_: Kem>(kdf_id: u16, aead_id: u16, mode: u8, psk: Option<Vec<u8>>, psk_id: Option<Vec<u8>>, pk_s: Option<Vec<u8>>, sk_r: &[u8], enc: &[u8], info: &[u8], ct: &mut [u8], aad: &[u8], tag: &[u8]) {
    let psk_v: Vec<u8>;
    let psk_id_v: Vec<u8>;
    let mode = match mode {
        0 => OpModeR::Base,
        1 => OpModeR::Psk(PskBundle {psk: {psk_v = psk.unwrap(); &psk_v}, psk_id: {psk_id_v = psk_id.unwrap(); &psk_id_v}}),
        2 => OpModeR::Auth(<Kem_ as Kem>::PublicKey::from_bytes(&pk_s.unwrap()).unwrap()),
        3 => OpModeR::AuthPsk(<Kem_ as Kem>::PublicKey::from_bytes(&pk_s.unwrap()).unwrap(), PskBundle {psk: {psk_v = psk.unwrap(); &psk_v}, psk_id: {psk_id_v = psk_id.unwrap(); &psk_id_v}}),
        _ => exit_println("Error: invalid `mode`")
    };
    match kdf_id {
        kdf::HkdfSha256::KDF_ID => set_dec_aead::<Kem_, kdf::HkdfSha256>(aead_id, &mode, sk_r, enc, info, ct, aad, tag),
        kdf::HkdfSha384::KDF_ID => set_dec_aead::<Kem_, kdf::HkdfSha384>(aead_id, &mode, sk_r, enc, info, ct, aad, tag),
        kdf::HkdfSha512::KDF_ID => set_dec_aead::<Kem_, kdf::HkdfSha512>(aead_id, &mode, sk_r, enc, info, ct, aad, tag),
        _ => exit_println("Error: invalid `kdf_id`"),
    }
}

fn set_dec_aead<Kem_: Kem, Kdf_: Kdf>(aead_id: u16, mode: &OpModeR<Kem_>, sk_r: &[u8], enc: &[u8], info: &[u8], ct: &mut [u8], aad: &[u8], tag: &[u8]) {
    match aead_id {
        aead::AesGcm128::AEAD_ID => single_shot_dec::<Kem_, Kdf_, aead::AesGcm128>(mode, sk_r, enc, info, ct, aad, tag),
        aead::AesGcm256::AEAD_ID => single_shot_dec::<Kem_, Kdf_, aead::AesGcm256>(mode, sk_r, enc, info, ct, aad, tag),
        aead::ChaCha20Poly1305::AEAD_ID => single_shot_dec::<Kem_, Kdf_, aead::ChaCha20Poly1305>(mode, sk_r, enc, info, ct, aad, tag),
        _ => exit_println("Error: invalid `aead_id`"),
    };
}

fn single_shot_dec<Kem_: Kem, Kdf_: Kdf, Aead_: Aead>(mode: &OpModeR<Kem_>, sk_r: &[u8], enc: &[u8], info: &[u8], ct: &mut [u8], aad: &[u8], tag: &[u8]) {
    let sk_r= <Kem_ as Kem>::PrivateKey::from_bytes(sk_r).expect_or_exit("Error: invalid `sk_r`");
    let enc = <Kem_ as Kem>::EncappedKey::from_bytes(enc).expect_or_exit("Error: invalid `enc`");
    let tag = aead::AeadTag::<Aead_>::from_bytes(tag).expect_or_exit("Error: invalid `tag`");
    hpke::single_shot_open_in_place_detached::<Aead_, Kdf_, Kem_>(&mode, &sk_r, &enc, info, ct, aad, &tag).expect_or_exit("Error: encryption failed");
}