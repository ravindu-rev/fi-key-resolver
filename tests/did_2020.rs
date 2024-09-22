use key_resolver::resolve_did;

#[test]
pub fn test_did() {
    let did = "did:key:z6MkvEoFWxZ9B5RDGSTLo2MqE3YJTxrDfLLZyZKjFRtcUSyw#z6MkvEoFWxZ9B5RDGSTLo2MqE3YJTxrDfLLZyZKjFRtcUSyw";
    let verification_key_public_key_multibase = "z6MkvEoFWxZ9B5RDGSTLo2MqE3YJTxrDfLLZyZKjFRtcUSyw";
    let agreement_key_public_key_multibase = "z6LSjSGy9kLkMotj3zv1eQEYoo66LaBobzb5EabEhZh72wJQ";
    let suite = "Ed25519VerificationKey2020";

    let (did_doc_option, key_pair_option) = match resolve_did(did, suite) {
        Ok(val) => (val.0, val.1),
        Err(error) => {
            eprintln!("{}", error.to_string());
            assert!(false);
            return;
        }
    };

    if did_doc_option.is_some() {
        let did_doc = did_doc_option.unwrap();
        println!("{}", serde_json::to_string_pretty(&did_doc).unwrap());
        assert_eq!(
            did_doc.verification_method[0]
                .public_key_multibase
                .clone()
                .expect("Public key multi base not found"),
            verification_key_public_key_multibase
        );
    }

    if key_pair_option.is_some() {
        let key_pair = key_pair_option.unwrap();

        assert_eq!(
            key_pair
                .public_key_multibase
                .clone()
                .expect("Public key multi base not found"),
            agreement_key_public_key_multibase
        );
    }

    assert!(true)
}
