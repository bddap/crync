use hex::{decode, encode, FromHexError};
use safe_crypto::{PublicEncryptKey, SecretEncryptKey};

pub fn sk_from_hex(src: &str) -> Result<SecretEncryptKey, ParseErr> {
    parse_as_array32(src).map(SecretEncryptKey::from_bytes)
}

pub fn pk_from_hex(src: &str) -> Result<PublicEncryptKey, ParseErr> {
    parse_as_array32(src).map(PublicEncryptKey::from_bytes)
}

pub fn sk_to_hex(sk: SecretEncryptKey) -> String {
    encode(sk.into_bytes())
}

pub fn pk_to_hex(pk: PublicEncryptKey) -> String {
    encode(pk.into_bytes())
}

fn parse_as_array32(src: &str) -> Result<[u8; 32], ParseErr> {
    decode(src)
        .map_err(std::convert::Into::into)
        .and_then(vec_to_array32)
}

fn vec_to_array32(bytes: Vec<u8>) -> Result<[u8; 32], ParseErr> {
    if bytes.len() != 32 {
        Err(ParseErr::BadLength)
    } else {
        let mut slice = [0; 32];
        for (i, byte) in bytes.iter().enumerate() {
            slice[i] = *byte;
        }
        Ok(slice)
    }
}

#[derive(Debug)]
pub enum ParseErr {
    InvalidHex(FromHexError),
    BadLength,
}

impl ToString for ParseErr {
    fn to_string(&self) -> String {
        "ParseErr".into()
    }
}

impl From<FromHexError> for ParseErr {
    fn from(other: FromHexError) -> Self {
        ParseErr::InvalidHex(other)
    }
}
