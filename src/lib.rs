use did::DidDoc;
use fi_common::did::{DidDocument, KeyPairToDidDocument};
use fi_common::error::Error;
use fi_common::keys::{KeyPair, VerificationKey};

pub mod did;
pub mod ed25519_verification_key2018;
pub mod ed25519_verification_key2020;
mod util;
pub mod x25519_key_agreement_key2019;
pub mod x25519_key_agreement_key2020;

pub fn resolve_did(
    did: &str,
    suit_id: &str,
) -> Result<(Option<DidDocument>, Option<KeyPair>), Error> {
    let splitted_did: Vec<&str> = did.split('#').collect();
    let did_authority = splitted_did[0];

    let fingerprint = &did_authority["did:key:".len()..];
    let verification_key_pair: Box<dyn VerificationKey> = match suit_id {
        ed25519_verification_key2018::SUITE_ID => {
            match ed25519_verification_key2018::Ed25519VerificationKey2018::from_fingerprint(
                fingerprint,
            ) {
                Ok(val) => Box::new(val),
                Err(error) => {
                    return Err(error);
                }
            }
        }
        ed25519_verification_key2020::SUITE_ID => {
            match ed25519_verification_key2020::Ed25519VerificationKey2020::from_fingerprint(
                fingerprint,
            ) {
                Ok(val) => Box::new(val),
                Err(error) => {
                    return Err(error);
                }
            }
        }
        _ => {
            return Err(Error::new(
                format!(
                    "Cannot derive key verification key from suite id {}",
                    suit_id
                )
                .as_str(),
            ))
        }
    };

    let did_doc = match DidDoc::key_pair_to_did_doc(&verification_key_pair, fingerprint) {
        Ok(val) => val,
        Err(error) => return Err(error),
    };

    if splitted_did.len() > 1 {
        let key_id_fragment = splitted_did[1];
        let key = match did_doc.get_key_pair(key_id_fragment) {
            Ok(val) => val,
            Err(error) => return Err(error),
        };

        return Ok((None, Some(key)));
    }

    return Ok((Some(did_doc), None));
}
