use proptest::prelude::*;
use unicode_normalization::UnicodeNormalization;

use crate::models::{canonicalize_name, canonicalize_domain};
use crate::core::MasterKeyInput;
use crate::tests::common;

proptest! {
    #[test]
    fn canonicalize_name_idempotent_and_trim_lower_nfc(s in "[\u{0000}-\u{10FFFF}]{0,20}") {
        let raw = s.clone();
        let transformed = raw.trim().to_lowercase().nfc().collect::<String>();

        let c1 = canonicalize_name(&raw);
        let c2 = canonicalize_name(&transformed);
        prop_assert_eq!(c1.as_str(), c2.as_str());
        prop_assert_eq!(canonicalize_name(&c1), c1.clone());
    }

    #[test]
    fn canonicalize_domain_trailing_dot_idempotent(s in "[\u{0020}-\u{10FFFF}]{0,30}") {
        // empty and whitespace-only inputs are excluded: idna may reject them
        let base = s.trim();
        prop_assume!(!base.is_empty());
        prop_assume!(!base.chars().any(char::is_whitespace));

        let with_dot = format!("{}.", base);

        let d1 = canonicalize_domain(base);
        let d2 = canonicalize_domain(&with_dot);
        prop_assert_eq!(d1.as_str(), d2.as_str());
        prop_assert_eq!(canonicalize_domain(&d1), d1.clone());
    }

    #[test]
    fn folder_path_rename_exact_match_behavior(a in ".{0,20}", b in ".{0,20}"){
        let vault = common::build_test_vault();
        let master = MasterKeyInput::new("k1-path".to_string(), "k2-path".to_string());
        let (device_uuid, _r) = common::setup_basic_session(&vault, &master);

        let plaintext = crate::models::StaticPasswordPlaintext { label: "l".to_string(), value: "v".to_string(), notes: String::new(), compromised: false };
        let _ = vault.add_static_password(device_uuid, &a, "lab", plaintext.clone(), &master).expect("add static");

        if a.trim() != a {
            // renaming with the trimmed variant must NOT match: folder lookup requires exact equality
            let err = vault.rename_static_password_folder(device_uuid, &a.trim(), &b);
            prop_assert!(err.is_err());
        } else {
            let res = vault.rename_static_password_folder(device_uuid, &a, &b);
            prop_assert!(res.is_ok());
            let list = vault.list_static_passwords(device_uuid).expect("list");
            prop_assert!(list.iter().any(|s| s.folder_path == b));
        }
    }
}
