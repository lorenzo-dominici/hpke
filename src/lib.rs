use config::{Data, ExchangedData, Entity};
use error::*;
use serde_json;
use std::fs;
use rand::{self, SeedableRng};

mod config;
pub mod error;
mod darkmagic;

pub fn test(config_s: &str, config_r: &str, data: &str) -> String {
    let cfg_s = fs::read_to_string(config_s).expect_or_exit("Error: sender config file reading failed");
    let sender: Entity = serde_json::from_str(&cfg_s).expect_or_exit("Error: sender config file ill formatted");
    let cfg_r = fs::read_to_string(config_r).expect_or_exit("Error: receiver config file reading failed");
    let receiver: Entity = serde_json::from_str(&cfg_r).expect_or_exit("Error: receiver config file ill formatted");
    let data_str = fs::read_to_string(data).expect_or_exit("Error: data file reading failed");
    let pre_data: Data = serde_json::from_str(&data_str).expect_or_exit("Error: data file ill formatted");

    if !config::check_test(&sender, &receiver, &pre_data) {
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

pub fn encrypt(config: &str, data: &str) -> String {
    let cfg_str = fs::read_to_string(config).expect_or_exit("Error: config file reading failed");
    let sender: Entity = serde_json::from_str(&cfg_str).expect_or_exit("Error: config file ill formatted");
    let data_str = fs::read_to_string(data).expect_or_exit("Error: data file reading failed");
    let data: Data = serde_json::from_str(&data_str).expect_or_exit("Error: data file ill formatted");

    if !config::check_sender(&sender, &data) {
        exit_println("Error: inconsistent data or parameters");
    }

    let Data {mut pt, aad} = data;
    
    let (enc, tag) = darkmagic::sss_ipd(sender.pub_data.kem_id, sender.pub_data.kdf_id, sender.pub_data.aead_id, sender.pub_data.mode, sender.info.psk, sender.info.psk_id, sender.pub_data.pk_s, sender.info.sk, &sender.pub_data.pk_r, &sender.pub_data.info, &mut pt, &aad, &mut rand::rngs::StdRng::from_entropy());

    let data = ExchangedData {enc, ct: pt, aad, tag};
    let str_out = serde_json::to_string(&data).expect_or_exit("Error: serialization failed");
    str_out
}

pub fn decrypt(config: &str, data: &str) -> String {
    let cfg_str = fs::read_to_string(config).expect_or_exit("Error: config file reading failed");
    let receiver: Entity = serde_json::from_str(&cfg_str).expect_or_exit("Error: config file ill formatted");
    let data_str = fs::read_to_string(data).expect_or_exit("Error: data file reading failed");
    let exc_data: ExchangedData = serde_json::from_str(&data_str).expect_or_exit("Error: data file ill formatted");

    if !config::check_receiver(&receiver, &exc_data) {
        exit_println("Error: inconsistent data or parameters");
    }
    
    let ExchangedData {enc, mut ct, aad, tag} = exc_data;

    darkmagic::sso_ipd(receiver.pub_data.kem_id, receiver.pub_data.kdf_id, receiver.pub_data.aead_id, receiver.pub_data.mode, receiver.info.psk, receiver.info.psk_id, receiver.pub_data.pk_s, &receiver.info.sk.unwrap(), &enc, &receiver.pub_data.info, &mut ct, &aad, &tag);

    let pt = ct;

    let data = Data {pt, aad};
    let str_out = serde_json::to_string(&data).expect_or_exit("Error: serialization failed");
    str_out
}

