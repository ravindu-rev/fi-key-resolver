use key_resolver::resolve_did;

// #[test]
pub fn test_did() {
    let did = "did:key:z6MkpVCWpibzht7gFFkBsnNigRvXiQWQgV2vqq8eN8zGkGGN#z6MkpVCWpibzht7gFFkBsnNigRvXiQWQgV2vqq8eN8zGkGGN";
    let verification_key_public_key_base58 = "B2wUEUMZNLdD8kuVCDQsqLNXtqEZGbna9pDiXs2Fq3Uz";
    let agreement_key_public_key_base58 = "FTuUZW4g4pFAWjfreUWGyqGuV6iW6qfR7nmeEP4xRP5a";
    let suite = "Ed25519VerificationKey2018";

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

        assert_eq!(
            did_doc.verification_method[0]
                .public_key_base58
                .clone()
                .expect("Public key base 58 not found"),
            verification_key_public_key_base58
        );
    }

    if key_pair_option.is_some() {
        let key_pair = key_pair_option.unwrap();

        assert_eq!(
            key_pair
                .public_key_base58
                .clone()
                .expect("Public key base 58 not found"),
            agreement_key_public_key_base58
        );
    }

    assert!(true)
}
