use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::traits::IsIdentity;
use curve25519_dalek::MontgomeryPoint;
use ed25519_dalek::SecretKey as Ed25519SecretKey;
use fi_common::error::Error;
use x25519_dalek::StaticSecret as X25519SecretKey;

// multibase base58-btc header
pub const MULTIBASE_BASE58BTC_HEADER: &str = "z";

pub fn ed25519_to_x25519(secret_key: Ed25519SecretKey) -> X25519SecretKey {
    let ed25519_bytes = secret_key;

    let mut x25519_bytes = ed25519_bytes;

    x25519_bytes[0] &= 248;
    x25519_bytes[31] &= 127;
    x25519_bytes[31] |= 64;

    X25519SecretKey::from(x25519_bytes)
}

pub fn multibase_decode(header: &[u8; 2], text: &String) -> Result<Vec<u8>, Error> {
    let value_builder = multibase::decode(&text);
    let (_, value) = match value_builder {
        Ok(val) => val,
        Err(error) => {
            return Err(Error::new(error.to_string().as_str()));
        }
    };

    if value[0] == header[0] && value[1] == header[1] {
        return Ok(String::from(&text[2..]).as_bytes().to_vec());
    }

    Err(Error::new("Multibase value does not have expected header."))
}

pub fn multibase_encode(header: &[u8; 2], bytes: &mut Vec<u8>) -> String {
    let mut content_bytes: Vec<u8> = Vec::from(header);
    content_bytes.append(bytes);

    let encoded_content_bytes = multibase::encode(multibase::Base::Base58Btc, content_bytes);

    return encoded_content_bytes;
}
