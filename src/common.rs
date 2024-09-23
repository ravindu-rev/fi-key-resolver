use fi_common::error::Error;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeyPair {
    pub id: Option<String>,
    #[serde(rename = "type")]
    pub _type: String,
    #[serde(rename = "@context")]
    pub context: Option<String>,
    pub public_key_base58: Option<String>,
    pub private_key_base58: Option<String>,
    pub public_key_multibase: Option<String>,
    pub private_key_multibase: Option<String>,
    pub revoked: bool,
    pub controller: Option<String>,
}

pub trait VerificationKey {
    fn from_fingerprint(fingerprint: &str) -> Result<Self, Error>
    where
        Self: Sized;

    fn get_suite_id() -> &'static str
    where
        Self: Sized;

    fn get_current_suite_id(&self) -> &'static str;

    fn get_suite_context() -> &'static str
    where
        Self: Sized;

    fn get_current_suite_context(&self) -> &'static str;

    fn get_controller(&self) -> &Option<String>;

    fn get_type(&self) -> String;

    fn get_private_key_content(&self) -> &Option<String>;
    fn get_public_key_content(&self) -> &String;

    fn export(&self, public_key: bool, private_key: bool, include_context: bool) -> KeyPair;
}

pub trait AgreementKey {
    fn get_suite_context() -> &'static str
    where
        Self: Sized;

    fn get_current_suite_context(&self) -> &'static str;

    fn get_controller(&self) -> &Option<String>;

    fn get_private_key_content(&self) -> &Option<String>;
    fn get_public_key_content(&self) -> &String;

    fn export(&self, public_key: bool, private_key: bool, include_context: bool) -> KeyPair;
}
