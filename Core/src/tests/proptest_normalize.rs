use proptest::prelude::*;
use unicode_normalization::UnicodeNormalization;

use crate::models::normalize_secrets;

proptest! {
    #[test]
    fn normalize_secrets_idempotent(s1 in proptest::collection::vec(any::<char>(), 0..20), s2 in proptest::collection::vec(any::<char>(), 0..20)) {
        let s1: String = s1.into_iter().collect();
        let s2: String = s2.into_iter().collect();

        let raw = normalize_secrets(&[&s1, &s2]).expect("normalize raw");

        let n1 = s1.trim().nfc().collect::<String>();
        let n2 = s2.trim().nfc().collect::<String>();

        let normed = normalize_secrets(&[&n1, &n2]).expect("normalize normed");

        prop_assert_eq!(raw, normed);
    }
}
