use fi_common::error::Error;

use crate::common::{KeyPair, VerificationKey};

pub(crate) const SUITE_ID: &str = "Ed25519VerificationKey2020";
pub(crate) const SUITE_CONTEXT: &str = "https://w3id.org/security/suites/ed25519-2020/v1";

// multibase base58-btc header
const MULTIBASE_BASE58BTC_HEADER: &str = "z";
// multicodec ed25519-pub header as varint
const MULTICODEC_ED25519_PUB_HEADER: [u8; 2] = [0xed, 0x01];
// multicodec ed25519-priv header as varint
const MULTICODEC_ED25519_PRIV_HEADER: [u8; 2] = [0xed, 0x01];

pub struct Ed25519VerificationKey2020 {
    _type: String,
    id: Option<String>,
    controller: Option<String>,
    public_key_multibase: String,
    private_key_multibase: Option<String>,
    revoked: bool,
}

impl Ed25519VerificationKey2020 {
    pub fn new(
        controller: Option<String>,
        public_key_multibase: String,
        private_key_multibase: Option<String>,
        fingerprint: Option<String>,
    ) -> Result<Self, Error> {
        if !Ed25519VerificationKey2020::is_valid_key_header(
            &public_key_multibase,
            &MULTICODEC_ED25519_PUB_HEADER,
        ) {
            return Err(Error::new(
                format!(
                    "'publicKeyMultibase' has invalid header bytes: '{}'.",
                    public_key_multibase
                )
                .as_str(),
            ));
        }

        if private_key_multibase.is_some()
            && !Ed25519VerificationKey2020::is_valid_key_header(
                &private_key_multibase.clone().unwrap(),
                &MULTICODEC_ED25519_PRIV_HEADER,
            )
        {
            return Err(Error::new(
                format!(
                    "'publicKeyMultibase' has invalid header bytes: '{}'.",
                    private_key_multibase.unwrap()
                )
                .as_str(),
            ));
        }

        let mut id: Option<String> = None;
        if controller.is_some() && fingerprint.is_some() {
            let ctrler = controller.clone().unwrap();
            let fprint = fingerprint.clone().unwrap();
            id = Some(format!("{}#{}", ctrler, fprint));
        }

        Ok(Ed25519VerificationKey2020 {
            _type: String::from(SUITE_ID),
            id,
            controller,
            public_key_multibase,
            private_key_multibase,
            revoked: false,
        })
    }

    fn is_valid_key_header(multibase_key: &String, expected_header: &[u8; 2]) -> bool {
        if !multibase_key[0..1].eq(MULTIBASE_BASE58BTC_HEADER) {
            return false;
        }

        let decoded = multibase::decode(&multibase_key);
        let (_, decoded_key_bytes) = match decoded {
            Ok(val) => val,
            Err(_error) => return false,
        };

        decoded_key_bytes[0] == expected_header[0] && decoded_key_bytes[1] == expected_header[1]
    }
}

impl VerificationKey for Ed25519VerificationKey2020 {
    fn from_fingerprint(fingerprint: &str) -> Result<Self, Error> {
        Ed25519VerificationKey2020::new(
            None,
            String::from(fingerprint),
            None,
            Some(String::from(fingerprint)),
        )
    }

    fn get_suite_id() -> &'static str
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
    fn get_private_key_content(&self) -> &Option<String> {
        &self.private_key_multibase
    }
    fn get_public_key_content(&self) -> &String {
        &self.public_key_multibase
    }

    fn get_current_suite_id(&self) -> &'static str
    where
        Self: Sized,
    {
        SUITE_ID
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

    fn get_type(&self) -> String {
        self._type.clone()
    }
}
