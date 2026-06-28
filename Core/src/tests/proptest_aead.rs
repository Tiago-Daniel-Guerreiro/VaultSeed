use proptest::prelude::*;

use crate::services::crypto::CryptoServiceImpl;
use crate::core::CryptoService;

proptest! {
    #[test]
    fn aead_roundtrip_and_aad_rejection(plaintext in proptest::collection::vec(any::<u8>(), 0..1024), aad in proptest::collection::vec(any::<u8>(), 0..128)) {
        let crypto = CryptoServiceImpl::new();

        let key = crypto.generate_random_32().expect("gen key");
        let nonce = crypto.generate_random_24().expect("gen nonce");

        let ciphertext = crypto.encrypt_aead(&key, &nonce, &aad, &plaintext).expect("encrypt");

        let decrypted = crypto.decrypt_aead(&key, &nonce, &aad, &ciphertext).expect("decrypt");
        prop_assert_eq!(decrypted, plaintext);

        let mut tampered_aad = aad.clone();
        if tampered_aad.is_empty() {
            tampered_aad.push(0x01);
        } else {
            tampered_aad[0] ^= 0xFF;
        }

        prop_assert!(crypto.decrypt_aead(&key, &nonce, &tampered_aad, &ciphertext).is_err());
    }
}
