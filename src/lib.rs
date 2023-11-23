use error::*;
use serde_json;
use std::fs;

mod config;
pub mod error;
mod darkmagic;

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

