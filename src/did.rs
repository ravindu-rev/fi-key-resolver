use fi_common::{
    did::{DidDocument, KeyPairToDidDocument, DID_CONTEXT_URL},
    error::Error,
    keys::{AgreementKey, VerificationKey},
};

use crate::{
    ed25519_verification_key2018, ed25519_verification_key2020,
    x25519_key_agreement_key2019::X25519KeyAgreementKey2019,
    x25519_key_agreement_key2020::X25519KeyAgreementKey2020,
};

pub struct DidDoc(DidDocument);

impl KeyPairToDidDocument for DidDoc {
    fn key_pair_to_did_doc(
        key_pair: &Box<dyn VerificationKey>,
        fingerprint: &str,
    ) -> Result<DidDocument, Error> {
        let did = format!("did:key:{}", fingerprint);

        let mut contexts: Vec<String> = Vec::from([String::from(DID_CONTEXT_URL)]);

        let agreement_key: Box<dyn AgreementKey> = match key_pair.get_current_suite_id() {
            ed25519_verification_key2018::SUITE_ID => {
                let agreement_key =
                    match X25519KeyAgreementKey2019::from_ed25519_verification_key2018(&key_pair) {
                        Ok(val) => val,
                        Err(error) => return Err(error),
                    };

                contexts.push(String::from(key_pair.get_current_suite_context()));
                contexts.push(String::from(agreement_key.get_current_suite_context()));

                Box::new(agreement_key)
            }
            ed25519_verification_key2020::SUITE_ID => {
                let agreement_key =
                    match X25519KeyAgreementKey2020::from_ed25519_verification_key2020(&key_pair) {
                        Ok(val) => val,
                        Err(error) => return Err(error),
                    };
                contexts.push(String::from(key_pair.get_current_suite_context()));
                contexts.push(String::from(agreement_key.get_current_suite_context()));

                Box::new(agreement_key)
            }
            _ => {
                return Err(Error::new(
                    format!(
                        "Cannot derive key agreement key from verification key type {}",
                        key_pair.get_type()
                    )
                    .as_str(),
                ))
            }
        };

        let public_ed_key = key_pair.export(true, false, false);
        let public_dh_key = agreement_key.export(true, false, false);

        let ed_id = public_ed_key.id.clone();
        let public_ed_key_id = match ed_id {
            None => String::from(""),
            Some(val) => val,
        };

        let did_doc = DidDocument {
            id: did,
            key_agreement: Vec::from([public_dh_key]),
            context: contexts,
            verification_method: Vec::from([public_ed_key]),
            assertion_method: Vec::from([public_ed_key_id.clone()]),
            authentication: Vec::from([public_ed_key_id.clone()]),
            capability_delegation: Vec::from([public_ed_key_id.clone()]),
            capability_invocation: Vec::from([public_ed_key_id]),
        };

        Ok(did_doc)
    }
}
