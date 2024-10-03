use fi_key_resolver::resolve_did;

#[test]
pub fn test_did_key_1() {
    let did = "did:key:z6MkpVCWpibzht7gFFkBsnNigRvXiQWQgV2vqq8eN8zGkGGN";
    let verification_key_public_key_base58 = "B2wUEUMZNLdD8kuVCDQsqLNXtqEZGbna9pDiXs2Fq3Uz";
    let agreement_key_public_key_base58 = "FTuUZW4g4pFAWjfreUWGyqGuV6iW6qfR7nmeEP4xRP5a";
    let suite = "Ed25519VerificationKey2018";

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
                .public_key_base58
                .clone()
                .expect("Public key base 58 not found"),
            verification_key_public_key_base58
        );

        let key_pair = &did_doc.key_agreement.unwrap()[0];

        assert_eq!(
            key_pair
                .public_key_base58
                .clone()
                .expect("Public key base 58 not found"),
            agreement_key_public_key_base58
        );
    }
}

#[test]
pub fn test_did_key_2() {
    let did = "did:key:z6Mkr4zjFPqDsoQPo9t17N7pXo5oQXfjCFJ2bFDqpKnf9rBv";
    let verification_key_public_key_base58 = "Ccjgf9anYFuvgf3JRo9yghXoaxPsnN3fuEJuz3peEdQY";
    let agreement_key_public_key_base58 = "CbXfq23t36uB18TJJJJ6aAdAh5JpkrpoumS7mtLTAoTB";
    let suite = "Ed25519VerificationKey2018";

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
                .public_key_base58
                .clone()
                .expect("Public key base 58 not found"),
            verification_key_public_key_base58
        );

        let key_pair = &did_doc.key_agreement.unwrap()[0];

        assert_eq!(
            key_pair
                .public_key_base58
                .clone()
                .expect("Public key base 58 not found"),
            agreement_key_public_key_base58
        );
    }
}
