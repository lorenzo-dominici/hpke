use serde::{Serialize, Deserialize, Deserializer, Serializer, de::Error};
use hex;
pub use hex::{encode, decode};

#[derive(PartialEq, Eq, Clone, Serialize, Deserialize)]
pub struct Data {
    #[serde(serialize_with="bytes_to_hex", deserialize_with="hex_to_bytes")]
    pub pt: Vec<u8>,
    #[serde(serialize_with="bytes_to_hex", deserialize_with="hex_to_bytes")]
    pub aad: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct EntityInfo {
    #[serde(serialize_with="bytes_to_hex_opt", deserialize_with="hex_to_bytes_opt")]
    pub psk: Option<Vec<u8>>,
    #[serde(serialize_with="bytes_to_hex_opt", deserialize_with="hex_to_bytes_opt")]
    pub psk_id: Option<Vec<u8>>,
    #[serde(serialize_with="bytes_to_hex_opt", deserialize_with="hex_to_bytes_opt")]
    pub sk: Option<Vec<u8>>,
}

#[derive(PartialEq, Eq, Serialize, Deserialize)]
pub struct PubData {
    pub mode: u8,
    pub kem_id: u16,
    pub kdf_id: u16,
    pub aead_id: u16,
    #[serde(serialize_with="bytes_to_hex", deserialize_with="hex_to_bytes")]
    pub info: Vec<u8>,
    #[serde(serialize_with="bytes_to_hex_opt", deserialize_with="hex_to_bytes_opt")]
    pub pk_s: Option<Vec<u8>>,
    #[serde(serialize_with="bytes_to_hex", deserialize_with="hex_to_bytes")]
    pub pk_r: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub struct Entity {
    pub info: EntityInfo,
    pub pub_data: PubData,
}

#[derive(Serialize, Deserialize)]
pub struct ExchangedData {
    #[serde(serialize_with="bytes_to_hex", deserialize_with="hex_to_bytes")]
    pub enc: Vec<u8>,
    #[serde(serialize_with="bytes_to_hex", deserialize_with="hex_to_bytes")]
    pub ct: Vec<u8>,
    #[serde(serialize_with="bytes_to_hex", deserialize_with="hex_to_bytes")]
    pub aad: Vec<u8>,
    #[serde(serialize_with="bytes_to_hex", deserialize_with="hex_to_bytes")]
    pub tag: Vec<u8>,
}

pub fn check(entity: &Entity) -> bool {
    let mut is_ok = true;

    is_ok &= match entity.pub_data.mode {
        0 => true,
        1 => entity.info.psk.is_some() && entity.info.psk_id.is_some(),
        2 => entity.info.sk.is_some() && entity.pub_data.pk_s.is_some(),
        3 => entity.info.sk.is_some() && entity.pub_data.pk_s.is_some() && entity.info.psk.is_some() && entity.info.psk_id.is_some(),
        _ => false,
    };

    is_ok &= match entity.pub_data.kem_id {
        16 | 17 | 18 | 32 | 33 => true,
        _ => false,
    };

    is_ok &= match entity.pub_data.kdf_id {
        1 | 2 | 3 => true,
        _ => false,
    };

    is_ok &= match entity.pub_data.aead_id {
        1 | 2 | 3 => true,
        _ => false,
    };

    is_ok
}

fn hex_to_bytes<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
    let mut hex_str = String::deserialize(deserializer)?;
    // Prepend a 0 if it's not even length
    if hex_str.len() % 2 == 1 {
        hex_str.insert(0, '0');
    }
    hex::decode(hex_str).map_err(|e| Error::custom(format!("{:?}", e)))
}

fn hex_to_bytes_opt<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<Vec<u8>>, D::Error> {
    hex_to_bytes(deserializer).map(|v| Some(v))
}

fn bytes_to_hex<S: Serializer>(vec: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error> {
    let hex_str = hex::encode(vec);
    serializer.serialize_str(&hex_str)
}

fn bytes_to_hex_opt<S: Serializer>(opt: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error> {
    /*
    let mut map = serializer.serialize_map(None)?;
    if let Some(foo) = opt {
        map.serialize_entry("key", &foo)?;
    }
    map.end()
    */
    match opt {
        Some(v) => bytes_to_hex(v, serializer),
        None => serializer.serialize_str(""),
    }
}