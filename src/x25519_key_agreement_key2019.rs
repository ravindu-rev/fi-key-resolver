use bs58::encode;
use fi_common::{
    error::Error,
    keys::{AgreementKey, KeyPair, VerificationKey},
};

use crate::{
    ed25519_verification_key2018::Ed25519VerificationKey2018,
    util::{
        ed25519_to_x25519_privkey, ed25519_to_x25519_pubkey, get_key_bytes_from_key_pair_bytes,
        MULTIBASE_BASE58BTC_HEADER,
    },
};

pub const SUITE_ID: &str = "X25519KeyAgreementKey2019";

pub const SUITE_CONTEXT: &str = "https://w3id.org/security/suites/x25519-2019/v1";

pub struct X25519KeyAgreementKey2019 {
    _type: String,
    id: Option<String>,
    controller: Option<String>,
    public_key_base58: String,
    private_key_base58: Option<String>,
    revoked: bool,
}

impl X25519KeyAgreementKey2019 {
    pub fn new(
        controller: Option<String>,
        public_key_base58: String,
        private_key_base58: Option<String>,
        fingerprint: Option<String>,
    ) -> Self {
        let mut id: Option<String> = None;
        if controller.is_some() && fingerprint.is_some() {
            let ctrler = controller.clone().unwrap();
            let fprint = fingerprint.clone().unwrap();
            id = Some(format!("{}#{}", ctrler, fprint));
        }

        X25519KeyAgreementKey2019 {
            _type: String::from(SUITE_ID),
            id,
            controller,
            public_key_base58,
            private_key_base58,
            revoked: false,
        }
    }

    pub fn from_ed25519_verification_key2018(
        key_pair: &Box<dyn VerificationKey>,
    ) -> Result<X25519KeyAgreementKey2019, Error> {
        if !key_pair
            .get_current_suite_id()
            .eq(Ed25519VerificationKey2018::get_suite_id())
        {
            return Err(Error::new(
                "'key_pair' is not a Ed25519VerificationKey2018 struct instance",
            ));
        }

        let public_key_content = key_pair.get_public_key_content();

        let public_key_base58 = match convert_from_ed_public_key(public_key_content) {
            Ok(val) => val,
            Err(error) => return Err(error),
        };

        let private_key_content_option = key_pair.get_private_key_content();

        let mut private_key_base58: Option<String> = None;
        if private_key_content_option.is_some() {
            let private_key_content = private_key_content_option.clone().unwrap();

            if !public_key_content.starts_with(MULTIBASE_BASE58BTC_HEADER) {
                return Err(Error::new(
                format!("Expecting 'privateKeyMultibase' value to be multibase base58btc {} encoded (must start with 'z').", private_key_content).as_str(),
            ));
            }

            let private_key = match convert_from_ed_private_key(&private_key_content) {
                Ok(val) => val,
                Err(error) => return Err(error),
            };

            private_key_base58 = Some(private_key);
        }

        Ok(X25519KeyAgreementKey2019::new(
            key_pair.get_controller().clone(),
            public_key_base58,
            private_key_base58,
            Some(key_pair.get_public_key_content().clone()),
        ))
    }
}

fn convert_from_ed_public_key(public_key_base58: &String) -> Result<String, Error> {
    let ed_pub_key_bytes_builder = bs58::decode(public_key_base58);

    let mut ed_pub_key_bytes = match ed_pub_key_bytes_builder.into_vec() {
        Ok(val) => val,
        Err(error) => return Err(Error::new(error.to_string().as_str())),
    };

    let ed25519_pub_key: [u8; 32] =
        match get_key_bytes_from_key_pair_bytes(&mut ed_pub_key_bytes, true) {
            Ok(val) => val,
            Err(error) => {
                return Err(error);
            }
        };

    let dh_pub_key_bytes = match ed25519_to_x25519_pubkey(&ed25519_pub_key) {
        Ok(val) => val,
        Err(error) => return Err(error),
    };

    let dh_pub_key_bytes_base58_builder = encode(dh_pub_key_bytes);

    Ok(dh_pub_key_bytes_base58_builder.into_string())
}

fn convert_from_ed_private_key(private_key_base58: &String) -> Result<String, Error> {
    let ed_pri_key_bytes_builder = bs58::decode(private_key_base58);

    let mut ed_pri_key_bytes = match ed_pri_key_bytes_builder.into_vec() {
        Ok(val) => val,
        Err(error) => return Err(Error::new(error.to_string().as_str())),
    };

    let ed25519_priv_key: [u8; 32] =
        match get_key_bytes_from_key_pair_bytes(&mut ed_pri_key_bytes, false) {
            Ok(val) => val,
            Err(error) => {
                return Err(error);
            }
        };

    let dh_priv_key_bytes = ed25519_to_x25519_privkey(&ed25519_priv_key);

    let dh_priv_key_bytes_base58_builder = encode(dh_priv_key_bytes);

    Ok(dh_priv_key_bytes_base58_builder.into_string())
}

impl AgreementKey for X25519KeyAgreementKey2019 {
    fn export(&self, public_key: bool, private_key: bool, include_context: bool) -> KeyPair {
        KeyPair {
            id: self.id.clone(),
            _type: self._type.clone(),
            context: match include_context {
                true => Some(Vec::from([String::from(SUITE_CONTEXT)])),
                false => None,
            },
            public_key_base58: match public_key {
                true => Some(self.public_key_base58.clone()),
                false => None,
            },
            private_key_base58: match private_key {
                true => self.private_key_base58.clone(),
                false => None,
            },
            private_key_multibase: None,
            public_key_multibase: None,
            revoked: Some(self.revoked),
            controller: self.controller.clone(),
            blockchain_account_id: None,
            public_key_hex: None,
            public_key_base64: None,
            public_key_pem: None,
            private_key_hex: None,
            private_key_base64: None,
            private_key_pem: None,
            value: None,
            ethereum_address: None,
            public_key_jwk: None,
        }
    }

    fn get_controller(&self) -> &Option<String> {
        &self.controller
    }

    fn get_private_key_content(&self) -> &Option<String> {
        &self.private_key_base58
    }

    fn get_public_key_content(&self) -> &String {
        &self.public_key_base58
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
