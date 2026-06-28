use proptest::prelude::*;

use crate::models::GenerationParams;
use crate::generator::log2_millibits;

proptest! {
    #[test]
    fn bytes_to_derive_matches_reference(alphabet in proptest::collection::vec(0usize..=1000usize, 0..200)) {
        let expected_bytes = if alphabet.is_empty() {
            32
        } else {
            let bits_needed_millibits: u64 = alphabet
                .iter()
                .filter(|&&size| size > 1)
                .map(|&size| log2_millibits(size))
                .sum();

            let bits_needed_ceil = (bits_needed_millibits + 999) / 1000;
            const ENTROPY_MARGIN_BITS: u64 = 64;

            let bits_to_derive = bits_needed_ceil + ENTROPY_MARGIN_BITS;
            ((bits_to_derive + 7) / 8) as usize
        };

        let got = GenerationParams::compute_bytes_to_derive(&alphabet);
        prop_assert_eq!(got, expected_bytes);
    }
}
