use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::traits::IsIdentity;
use curve25519_dalek::MontgomeryPoint;
use fi_common::error::Error;
use sha2::Digest;
use sha2::Sha512;

// multibase base58-btc header
pub const MULTIBASE_BASE58BTC_HEADER: &str = "z";

pub fn multibase_decode(header: &[u8; 2], text: &String) -> Result<Vec<u8>, Error> {
    let value_builder = multibase::decode(&text);
    let (_, mut value) = match value_builder {
        Ok(val) => val,
        Err(error) => {
            return Err(Error::new(error.to_string().as_str()));
        }
    };

    if value[0] == header[0] && value[1] == header[1] {
        value.remove(0);
        value.remove(0);

        return Ok(value);
    }

    Err(Error::new("Multibase value does not have expected header."))
}

pub fn multibase_encode(header: &[u8; 2], bytes: &mut Vec<u8>) -> String {
    let mut content_bytes: Vec<u8> = Vec::from(header);
    content_bytes.append(bytes);

    let encoded_content_bytes = multibase::encode(multibase::Base::Base58Btc, content_bytes);

    return encoded_content_bytes;
}

pub fn get_key_bytes_from_key_pair_bytes(
    bytes: &mut Vec<u8>,
    is_pub_key: bool,
) -> Result<[u8; 32], Error> {
    let len = bytes.len();
    if len < 32 && len != 46 && len != 64 {
        return Err(Error::new("Key pair byte length is not valid"));
    }

    while bytes.len() > 32 {
        if is_pub_key || len != 64 {
            bytes.remove(0);
        } else {
            bytes.remove(bytes.len() - 1);
        }
    }

    let bytes_32: [u8; 32] = match (*bytes).clone().try_into() {
        Ok(val) => val,
        Err(_error) => {
            return Err(Error::new("'ed25519_secret_key' length did not match"));
        }
    };

    return Ok(bytes_32);
}

pub fn ed25519_to_x25519_pubkey(ed25519_pubkey_bytes: &[u8; 32]) -> Result<[u8; 32], Error> {
    // Convert the Ed25519 public key bytes into a CompressedEdwardsY point
    let ed25519_point = CompressedEdwardsY(*ed25519_pubkey_bytes);

    // Decompress the point to get the Edwards form of the point
    let edwards_point = ed25519_point
        .decompress()
        .ok_or("Invalid Ed25519 public key")
        .unwrap();

    // Ensure the point is not the identity (neutral element)
    if edwards_point.is_identity() {
        return Err(Error::new(
            "Invalid Ed25519 public key: point is the identity element",
        ));
    }

    // Convert the Edwards point to the corresponding Montgomery point
    let montgomery_point: MontgomeryPoint = edwards_point.to_montgomery();

    // Return the Montgomery point as a byte array, which is the X25519 public key
    Ok(montgomery_point.to_bytes())
}

pub fn ed25519_to_x25519_privkey(ed25519_privkey_bytes: &[u8; 32]) -> [u8; 32] {
    // Step 1: Hash the Ed25519 private key using SHA-512
    let hashed = Sha512::digest(ed25519_privkey_bytes);

    // Step 2: Use the first 32 bytes of the hash as the X25519 private key
    let mut x25519_privkey_bytes: [u8; 32] =
        hashed[..32].try_into().expect("Slice must be 32 bytes");

    // Step 3: Clamp the private key (set necessary bits)
    x25519_privkey_bytes[0] &= 248; // Clear the 3 least significant bits
    x25519_privkey_bytes[31] &= 127; // Clear the highest bit
    x25519_privkey_bytes[31] |= 64; // Set the second highest bit

    x25519_privkey_bytes
}
