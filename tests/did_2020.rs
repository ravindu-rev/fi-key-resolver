use fi_key_resolver::resolve_did;

#[test]
pub fn test_did_key_1() {
    let did = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH";
    let verification_key_public_key_multibase = "z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH";
    let agreement_key_public_key_multibase = "z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc";
    let suite = "Ed25519VerificationKey2020";

    let (did_doc_option, _) = match resolve_did(did, suite) {
        Ok(val) => (val.0, val.1),
        Err(error) => {
            eprintln!("{}", error.to_string());
            assert!(false);
            return;
        }
    };

    if did_doc_option.is_some() {
        let did_doc = did_doc_option.unwrap();

        assert_eq!(
            did_doc.verification_method.unwrap()[0]
                .public_key_multibase
                .clone()
                .expect("Public key multibase not found"),
            verification_key_public_key_multibase
        );

        let key_pair = &did_doc.key_agreement.unwrap()[0];

        assert_eq!(
            key_pair
                .public_key_multibase
                .clone()
                .expect("Public key multibase not found"),
            agreement_key_public_key_multibase
        );
    }
}

#[test]
pub fn test_did_key_2() {
    let did = "did:key:z6MkvEoFWxZ9B5RDGSTLo2MqE3YJTxrDfLLZyZKjFRtcUSyw";
    let verification_key_public_key_multibase = "z6MkvEoFWxZ9B5RDGSTLo2MqE3YJTxrDfLLZyZKjFRtcUSyw";
    let agreement_key_public_key_multibase = "z6LSjSGy9kLkMotj3zv1eQEYoo66LaBobzb5EabEhZh72wJQ";
    let suite = "Ed25519VerificationKey2020";

    let (did_doc_option, _) = match resolve_did(did, suite) {
        Ok(val) => (val.0, val.1),
        Err(error) => {
            eprintln!("{}", error.to_string());
            assert!(false);
            return;
        }
    };

    if did_doc_option.is_some() {
        let did_doc = did_doc_option.unwrap();

        assert_eq!(
            did_doc.verification_method.unwrap()[0]
                .public_key_multibase
                .clone()
                .expect("Public key multibase not found"),
            verification_key_public_key_multibase
        );

        let key_pair = &did_doc.key_agreement.unwrap()[0];

        assert_eq!(
            key_pair
                .public_key_multibase
                .clone()
                .expect("Public key multibase not found"),
            agreement_key_public_key_multibase
        );
    }
}
