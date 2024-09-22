use fi_common::error::Error;

use crate::{
    common::{AgreementKey, KeyPair, VerificationKey},
    ed25519_verification_key2020::Ed25519VerificationKey2020,
    util::{self, multibase_decode, multibase_encode, MULTIBASE_BASE58BTC_HEADER},
};
use sha2::{Digest, Sha512};

pub const SUITE_ID: &str = "X25519KeyAgreementKey2020";

pub const SUITE_CONTEXT: &str = "https://w3id.org/security/suites/x25519-2020/v1";

// multicodec ed25519-pub header as varint
const MULTICODEC_ED25519_PUB_HEADER: [u8; 2] = [0xed, 0x01];
// multicodec ed25519-priv header as varint
const MULTICODEC_ED25519_PRIV_HEADER: [u8; 2] = [0x80, 0x26];
// multicodec x25519-pub header as varint
const MULTICODEC_X25519_PUB_HEADER: [u8; 2] = [0xec, 0x01];
// multicodec x25519-priv header as varint
const MULTICODEC_X25519_PRIV_HEADER: [u8; 2] = [0x82, 0x26];

pub struct X25519KeyAgreementKey2020 {
    _type: String,
    id: Option<String>,
    controller: Option<String>,
    public_key_multibase: String,
    private_key_multibase: Option<String>,
    revoked: bool,
}

impl X25519KeyAgreementKey2020 {
    pub fn new(
        controller: Option<String>,
        public_key_multibase: String,
        private_key_multibase: Option<String>,
        fingerprint: Option<String>,
    ) -> Self {
        let mut id: Option<String> = None;
        if controller.is_some() && fingerprint.is_some() {
            let ctrler = controller.clone().unwrap();
            let fprint = fingerprint.clone().unwrap();
            id = Some(format!("{}#{}", ctrler, fprint));
        }
        X25519KeyAgreementKey2020 {
            _type: String::from(SUITE_ID),
            id,
            controller,
            private_key_multibase,
            public_key_multibase,
            revoked: false,
        }
    }

    pub fn from_ed25519_verification_key2020(
        key_pair: &Box<dyn VerificationKey>,
    ) -> Result<X25519KeyAgreementKey2020, Error> {
        if !key_pair
            .get_current_suite_id()
            .eq(Ed25519VerificationKey2020::get_suite_id())
        {
            return Err(Error::new(
                "'key_pair' is not a Ed25519VerificationKey2020 struct instance",
            ));
        }

        let public_key_content = key_pair.get_public_key_content();

        if !public_key_content.starts_with(MULTIBASE_BASE58BTC_HEADER) {
            return Err(Error::new(
                format!("Expecting 'publicKeyMultibase' value to be multibase base58btc {} encoded (must start with 'z').", public_key_content).as_str(),
            ));
        }

        let public_key_multibase = match convert_from_ed_public_key(public_key_content) {
            Ok(val) => val,
            Err(error) => return Err(error),
        };

        let private_key_content_option = key_pair.get_private_key_content().clone();

        let mut private_key_multibase: Option<String> = None;
        if private_key_content_option.is_some() {
            let private_key_content = private_key_content_option.unwrap();

            if !public_key_content.starts_with(MULTIBASE_BASE58BTC_HEADER) {
                return Err(Error::new(
                format!("Expecting 'privateKeyMultibase' value to be multibase base58btc {} encoded (must start with 'z').", private_key_content).as_str(),
            ));
            }

            let private_key = match convert_from_ed_private_key(&private_key_content) {
                Ok(val) => val,
                Err(error) => return Err(error),
            };

            private_key_multibase = Some(private_key);
        }

        Ok(X25519KeyAgreementKey2020::new(
            key_pair.get_controller().clone(),
            public_key_multibase,
            private_key_multibase,
            Some(key_pair.get_public_key_content().clone()),
        ))
    }
}

fn convert_from_ed_public_key(public_key_multibase: &String) -> Result<String, Error> {
    let ed_pub_key_bytes =
        match multibase_decode(&MULTICODEC_ED25519_PUB_HEADER, public_key_multibase) {
            Ok(val) => val,
            Err(error) => return Err(error),
        };

    let ed25519_secret_key: [u8; 32] = match get_ed25519_secret_key(ed_pub_key_bytes).try_into() {
        Ok(val) => val,
        Err(_error) => {
            return Err(Error::new("'ed25519_secret_key' length did not match"));
        }
    };

    let dh_pubkey_bytes = util::ed25519_to_x25519(ed25519_secret_key);

    Ok(multibase_encode(
        &MULTICODEC_X25519_PUB_HEADER,
        &mut dh_pubkey_bytes.as_bytes().to_vec(),
    ))
}

fn convert_from_ed_private_key(private_key_multibase: &String) -> Result<String, Error> {
    let ed_pri_key_bytes =
        match multibase_decode(&MULTICODEC_ED25519_PRIV_HEADER, private_key_multibase) {
            Ok(val) => val,
            Err(error) => return Err(error),
        };

    let ed25519_secret_key: [u8; 32] = match get_ed25519_secret_key(ed_pri_key_bytes).try_into() {
        Ok(val) => val,
        Err(_error) => {
            return Err(Error::new("'ed25519_secret_key' length did not match"));
        }
    };

    let dh_privkey_bytes = util::ed25519_to_x25519(ed25519_secret_key);

    Ok(multibase_encode(
        &MULTICODEC_X25519_PRIV_HEADER,
        &mut dh_privkey_bytes.as_bytes().to_vec(),
    ))
}

fn get_ed25519_secret_key(ed_privkey_bytes: Vec<u8>) -> Vec<u8> {
    let mut hasher = Sha512::new();
    hasher.update(ed_privkey_bytes);
    let mut result: Vec<u8> = hasher.finalize().to_vec();

    while result.len() < 32 {
        result.push(0);
    }

    result
}

impl AgreementKey for X25519KeyAgreementKey2020 {
    fn export(&self, public_key: bool, private_key: bool, include_context: bool) -> KeyPair {
        KeyPair {
            id: self.id.clone(),
            _type: self._type.clone(),
            context: match include_context {
                true => Some(String::from(SUITE_CONTEXT)),
                false => None,
            },
            public_key_base58: None,
            private_key_base58: None,
            private_key_multibase: match private_key {
                true => self.private_key_multibase.clone(),
                false => None,
            },
            public_key_multibase: match public_key {
                true => Some(self.public_key_multibase.clone()),
                false => None,
            },
            revoked: self.revoked,
            controller: self.controller.clone(),
        }
    }

    fn get_controller(&self) -> &Option<String> {
        &self.controller
    }

    fn get_private_key_content(&self) -> &Option<String> {
        &self.private_key_multibase
    }

    fn get_public_key_content(&self) -> &String {
        &self.public_key_multibase
    }

    fn get_suite_context() -> &'static str
    where
        Self: Sized,
    {
        SUITE_CONTEXT
    }

    fn get_current_suite_context(&self) -> &'static str
    where
        Self: Sized,
    {
        SUITE_CONTEXT
    }
}
