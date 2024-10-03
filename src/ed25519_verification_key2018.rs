use fi_common::{
    error::Error,
    keys::{KeyPair, VerificationKey},
};

pub(crate) const SUITE_ID: &str = "Ed25519VerificationKey2018";
pub(crate) const SUITE_CONTEXT: &str = "https://w3id.org/security/suites/ed25519-2018/v1";

pub struct Ed25519VerificationKey2018 {
    _type: String,
    id: Option<String>,
    controller: Option<String>,
    public_key_base58: String,
    private_key_base58: Option<String>,
    revoked: bool,
}

impl Ed25519VerificationKey2018 {
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

        return Ed25519VerificationKey2018 {
            _type: String::from(SUITE_ID),
            id,
            controller,
            private_key_base58,
            public_key_base58,
            revoked: false,
        };
    }
}

impl VerificationKey for Ed25519VerificationKey2018 {
    fn from_fingerprint(fingerprint: &str) -> Result<Self, Error> {
        if !fingerprint[0..1].eq("z") {
            return Err(Error::new(
                "`fingerprint` must be a multibase encoded string.",
            ));
        }

        let buffer = bs58::decode(&fingerprint[1..]);
        let decoded = match buffer.into_vec() {
            Ok(val) => val,
            Err(_error) => {
                return Err(Error::new(
                    "Couldn't convert decoded bs58 values into a vec",
                ));
            }
        };

        if decoded[0] == 0xed && decoded[1] == 0x01 {
            let encoded_public_key_builder = bs58::encode(&decoded[2..]);
            let encoded_public_key = encoded_public_key_builder.into_string();
            return Ok(Ed25519VerificationKey2018::new(
                None,
                encoded_public_key,
                None,
                Some(String::from(fingerprint)),
            ));
        }

        return Err(Error::new(
            format!("Unsupported fingerprint {}", fingerprint).as_str(),
        ));
    }

    fn get_suite_id() -> &'static str
    where
        Self: Sized,
    {
        SUITE_ID
    }

    fn get_private_key_content(&self) -> &Option<String> {
        &self.private_key_base58
    }
    fn get_public_key_content(&self) -> &String {
        &self.public_key_base58
    }

    fn get_current_suite_id(&self) -> &'static str
    where
        Self: Sized,
    {
        SUITE_ID
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

    fn get_controller(&self) -> &Option<String> {
        &self.controller
    }

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

    fn get_type(&self) -> String {
        self._type.clone()
    }
}
