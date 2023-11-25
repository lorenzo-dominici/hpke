//! This crates offers basic functions for encryption, decryption and testing using the HPKE framework
//! defined in the [RFC 9180](https://datatracker.ietf.org/doc/rfc9180/ "Hybrid Public Key Encryption").
//!   
//! This crate is developed upon the [hpke](https://docs.rs/hpke/0.11.0/hpke/ "docs.rs/hpke") crate to add more flexibility in the choice of algorithms used,
//! and to integrate command line utilities.
//!   
//! The schema to use for the various files can be found in the original [github repository](https://github.com/lorenzo-dominici/hpke-cl).

use config::{Data, ExchangedData, Entity};
use error::*;
use serde_json;
use std::fs;
use rand::{self, SeedableRng};

mod config;
pub mod error;
mod darkmagic;


/// Tests the input files and parameters by checking data consistency through a cycle of enrcyption and decryption.
/// 
/// # Parameters
/// - `config_s` : filepath of the configuration file of the sender.
/// - `config_r` : filepath of the configuration file of the receiver.
/// - `data` : filepath of the structured plain data.
/// 
/// # Returns
/// - A `String` containing the outcome of the test.
pub fn test(config_s: &str, config_r: &str, data: &str) -> String {
    let cfg_s = fs::read_to_string(config_s).expect_or_exit("Error: sender config file reading failed");
    let sender: Entity = serde_json::from_str(&cfg_s).expect_or_exit("Error: sender config file ill formatted");
    let cfg_r = fs::read_to_string(config_r).expect_or_exit("Error: receiver config file reading failed");
    let receiver: Entity = serde_json::from_str(&cfg_r).expect_or_exit("Error: receiver config file ill formatted");
    let data_str = fs::read_to_string(data).expect_or_exit("Error: data file reading failed");
    let pre_data: Data = serde_json::from_str(&data_str).expect_or_exit("Error: data file ill formatted");

    if !(config::check(&sender) && config::check(&receiver) && (sender.pub_data == receiver.pub_data)) {
        exit_println("Error: inconsistent data or parameters");
    }

    let Data {mut pt, aad} = pre_data.clone();
    
    let (enc, tag) = darkmagic::sss_ipd(sender.pub_data.kem_id, sender.pub_data.kdf_id, sender.pub_data.aead_id, sender.pub_data.mode, sender.info.psk, sender.info.psk_id, sender.pub_data.pk_s.clone(), sender.info.sk, &sender.pub_data.pk_r, &sender.pub_data.info, &mut pt, &aad, &mut rand::rngs::StdRng::from_entropy());

    let mut ct = pt;

    darkmagic::sso_ipd(receiver.pub_data.kem_id, receiver.pub_data.kdf_id, receiver.pub_data.aead_id, receiver.pub_data.mode, receiver.info.psk, receiver.info.psk_id, receiver.pub_data.pk_s, &receiver.info.sk.unwrap(), &enc, &receiver.pub_data.info, &mut ct, &aad, &tag);

    let pt = ct;

    let post_data = Data {pt, aad};

    if post_data == pre_data {
        "Test: passed\n".to_string()
    } else {
        "Test: failed\n".to_string()
    }
}

/// Encrypts the input data with the input parameters.
/// 
/// # Parameters
/// - `config` : filepath of the configuration file of the sender.
/// - `data` : filepath of the structured plain data.
/// 
/// # Returns
/// - A `String` containing the structured encrypted data.
pub fn encrypt(config: &str, data: &str) -> String {
    let cfg_str = fs::read_to_string(config).expect_or_exit("Error: config file reading failed");
    let sender: Entity = serde_json::from_str(&cfg_str).expect_or_exit("Error: config file ill formatted");
    let data_str = fs::read_to_string(data).expect_or_exit("Error: data file reading failed");
    let data: Data = serde_json::from_str(&data_str).expect_or_exit("Error: data file ill formatted");

    if !config::check(&sender) {
        exit_println("Error: inconsistent data or parameters");
    }

    let Data {mut pt, aad} = data;
    
    let (enc, tag) = darkmagic::sss_ipd(sender.pub_data.kem_id, sender.pub_data.kdf_id, sender.pub_data.aead_id, sender.pub_data.mode, sender.info.psk, sender.info.psk_id, sender.pub_data.pk_s, sender.info.sk, &sender.pub_data.pk_r, &sender.pub_data.info, &mut pt, &aad, &mut rand::rngs::StdRng::from_entropy());

    let data = ExchangedData {enc, ct: pt, aad, tag};
    let str_out = serde_json::to_string(&data).expect_or_exit("Error: serialization failed");
    str_out
}

/// Decrypts the input encrypted data with the input parameters.
/// 
/// # Parameters
/// - `config` : filepath of the configuration file of the receiver.
/// - `data` : filepath of the structured encrypted data.
/// 
/// # Returns
/// - A `String` containing the structured plain data.
pub fn decrypt(config: &str, data: &str) -> String {
    let cfg_str = fs::read_to_string(config).expect_or_exit("Error: config file reading failed");
    let receiver: Entity = serde_json::from_str(&cfg_str).expect_or_exit("Error: config file ill formatted");
    let data_str = fs::read_to_string(data).expect_or_exit("Error: data file reading failed");
    let exc_data: ExchangedData = serde_json::from_str(&data_str).expect_or_exit("Error: data file ill formatted");

    if !config::check(&receiver) {
        exit_println("Error: inconsistent data or parameters");
    }
    
    let ExchangedData {enc, mut ct, aad, tag} = exc_data;

    darkmagic::sso_ipd(receiver.pub_data.kem_id, receiver.pub_data.kdf_id, receiver.pub_data.aead_id, receiver.pub_data.mode, receiver.info.psk, receiver.info.psk_id, receiver.pub_data.pk_s, &receiver.info.sk.unwrap(), &enc, &receiver.pub_data.info, &mut ct, &aad, &tag);

    let pt = ct;

    let data = Data {pt, aad};
    let str_out = serde_json::to_string(&data).expect_or_exit("Error: serialization failed");
    str_out
}

