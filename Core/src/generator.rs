#![allow(dead_code)]

use std::collections::HashMap;

pub use alphabet::build_alphabet_dictionary;
pub use engine::generate_password;
pub use sizing::build_max_masks;

use num_bigint::BigUint;
use num_traits::ToPrimitive;
use uuid::Uuid;

use crate::models::CryptoContext;

/// Constrói o contexto "v1|domain:…|variation:…|device:…|restriction:…" usado
/// como input do KMAC256 - delega no formato canónico de `CryptoContext`
/// (Core/src/models.rs) para não haver duas implementações do mesmo formato.
pub fn build_context(domain_canonical: &str, variation: u32, device: &str, restriction: &str) -> String {
    let device = Uuid::parse_str(device).expect("build_context: device UUID inválido");
    let restriction =
        Uuid::parse_str(restriction).expect("build_context: restriction UUID inválido");
    CryptoContext::DerivedPassword {
        domain_canonical,
        variation,
        device,
        restriction,
    }
    .build()
}

type AlphabetDictionary = HashMap<u32, Vec<String>>;
type ExtractedIndex = (u32, usize);

const LOG2_SCALE: u64 = 1000;
const LOG2_FRAC_BITS: u32 = 32;

pub mod constants {
    /// Margem de segurança contra modulo bias na extração de índices a artir do XOF do KMAC256 - somada a qualquer alvo de entropia antes de dimensionar quantas posições do formato são necessárias.
    pub const ENTROPY_MARGIN_BITS: u64 = 64;
}

mod sizing {
    use std::collections::HashMap;

    use crate::models::MaskOrLiteral;

    use super::{alphabet::alphabet_for_mask, constants::ENTROPY_MARGIN_BITS, log2_millibits, LOG2_SCALE};

    pub fn calculate_max_length(total_bits: u64, alphabet_size: usize) -> u32 {
        if alphabet_size <= 1 {
            return 0;
        }

        let bits_per_char_milli = log2_millibits(alphabet_size);
        if bits_per_char_milli == 0 {
            return 0;
        }

        (total_bits.saturating_mul(LOG2_SCALE)).div_ceil(bits_per_char_milli) as u32
    }

    pub fn alphabet_cost_millibits(alphabet_size: usize) -> u128 {
        if alphabet_size <= 1 {
            return 0;
        }

        log2_millibits(alphabet_size) as u128
    }

    pub fn compute_bytes_to_derive(alphabet_sizes: &[usize]) -> usize {
        crate::models::GenerationParams::compute_bytes_to_derive(alphabet_sizes)
    }

    pub fn build_max_masks(
        effective_mask: u32,
        bit_lists: &HashMap<u8, Vec<String>>,
        derive_bits: u32,
    ) -> Vec<MaskOrLiteral> {
        let Some(alphabet) = alphabet_for_mask(bit_lists, effective_mask) else {
            return vec![MaskOrLiteral::Mask(effective_mask)];
        };

        if alphabet.len() <= 1 {
            return vec![MaskOrLiteral::Mask(effective_mask)];
        }

        let max_len = calculate_max_length(
            derive_bits as u64 + ENTROPY_MARGIN_BITS,
            alphabet.len(),
        ) as usize;

        vec![MaskOrLiteral::Mask(effective_mask); max_len]
    }
}

mod alphabet {
    use std::collections::{HashMap, HashSet};

    use crate::errors::PasswordError;
    use crate::models::MaskOrLiteral;

    use super::AlphabetDictionary;

    pub fn build_alphabet_dictionary(
        bit_lists: &HashMap<u8, Vec<String>>,
        masks: &[MaskOrLiteral],
    ) -> Result<AlphabetDictionary, PasswordError> {
        let mut dict = AlphabetDictionary::new();

        for mask in masks.iter().filter_map(MaskOrLiteral::as_mask) {
            let alphabet = alphabet_for_mask(bit_lists, mask).ok_or(PasswordError::EmptyAlphabet)?;
            dict.entry(mask).or_insert(alphabet);
        }

        Ok(dict)
    }

    pub(crate) fn alphabet_for_mask(
        bit_lists: &HashMap<u8, Vec<String>>,
        mask: u32,
    ) -> Option<Vec<String>> {
        let mut alphabet = HashSet::new();

        for bit in enabled_bits(mask) {
            if let Some(list) = bit_lists.get(&bit) {
                alphabet.extend(list.iter().cloned());
            }
        }

        if alphabet.is_empty() {
            return None;
        }

        let mut alphabet: Vec<String> = alphabet.into_iter().collect();
        alphabet.sort();
        Some(alphabet)
    }

    fn enabled_bits(mask: u32) -> impl Iterator<Item = u8> {
        (0u8..32).filter(move |bit| (mask & (1u32 << *bit)) != 0)
    }
}

mod extraction {
    use crate::errors::PasswordError;
    use crate::models::MaskOrLiteral;

    use super::{AlphabetDictionary, BigUint, ExtractedIndex, ToPrimitive, log2_millibits};

    pub(crate) struct ExtractionResult {
        pub indices: Vec<ExtractedIndex>,
        pub total_entropy_millibits: u64,
    }

    pub(crate) fn extract_indices(
        entropy: &BigUint,
        masks: &[MaskOrLiteral],
        dict: &AlphabetDictionary,
    ) -> Result<ExtractionResult, PasswordError> {
        let mut value = entropy.clone();
        let mut indices = Vec::new();
        let mut total_entropy_millibits = 0u64;

        for item in masks.iter().rev() {
            let Some(mask) = item.as_mask() else {
                continue;
            };

            let alphabet = dict.get(&mask).ok_or(PasswordError::EmptyAlphabet)?;

            match alphabet.len() {
                0 => return Err(PasswordError::EmptyAlphabet),
                1 => {
                    indices.push((mask, 0));
                }
                base_size => {
                    let base = BigUint::from(base_size as u64);
                    // div_rem numa só chamada: metade do custo/temporários com material derivado da seed.
                    let (quotient, remainder) = num_integer::Integer::div_rem(&value, &base);
                    let index = remainder
                        .to_usize()
                        .expect("Índice demasiado grande para usize");

                    total_entropy_millibits = total_entropy_millibits
                        .saturating_add(log2_millibits(base_size));
                    indices.push((mask, index));
                    value = quotient;
                }
            }
        }

        indices.reverse();

        Ok(ExtractionResult {
            indices,
            total_entropy_millibits,
        })
    }

    pub(crate) fn resolve_password(
        masks: &[MaskOrLiteral],
        indices: &[ExtractedIndex],
        dict: &AlphabetDictionary,
    ) -> Result<String, PasswordError> {
        let mut password = String::new();
        let mut index_iter = indices.iter();

        for item in masks {
            match item {
                MaskOrLiteral::Literal(text) => password.push_str(text),
                MaskOrLiteral::Mask(mask) => {
                    let Some((stored_mask, index)) = index_iter.next() else {
                        return Err(PasswordError::GenerationFailed(
                            "Índices insuficientes para as máscaras".to_string(),
                        ));
                    };

                    debug_assert_eq!(
                        *stored_mask, *mask,
                        "Desalinhamento entre máscara e índice"
                    );

                    let alphabet = dict.get(mask).ok_or(PasswordError::EmptyAlphabet)?;
                    password.push_str(&alphabet[*index]);
                }
            }
        }

        Ok(password)
    }
}

mod engine {
    use std::collections::HashMap;

    use crate::errors::PasswordError;
    use crate::models::MaskOrLiteral;

    use super::{
        alphabet::build_alphabet_dictionary,
        extraction::{extract_indices, resolve_password},
        BigUint,
    };

    pub struct GenerationResult {
        pub password: String,
        pub total_entropy_millibits: u64,
    }

    pub fn generate_password(
        entropy: &[u8],
        masks: &[MaskOrLiteral],
        bit_lists: &HashMap<u8, Vec<String>>,
    ) -> Result<GenerationResult, PasswordError> {
        let dict = build_alphabet_dictionary(bit_lists, masks)?;
        let entropy_int = BigUint::from_bytes_be(entropy);

        let extraction = extract_indices(&entropy_int, masks, &dict)?;
        let password = resolve_password(masks, &extraction.indices, &dict)?;

        Ok(GenerationResult {
            password,
            total_entropy_millibits: extraction.total_entropy_millibits,
        })
    }
}

pub(crate) fn log2_millibits(value: usize) -> u64 {
    if value <= 1 {
        return 0;
    }

    let n = value as u128;
    let integer_bits = 127u32 - n.leading_zeros();
    let one = 1u128 << LOG2_FRAC_BITS;
    let two = one << 1;
    let mut y = (n << LOG2_FRAC_BITS) >> integer_bits;
    let mut fraction_bits = 0u64;

    for bit_index in 0..LOG2_FRAC_BITS {
        y = (y * y) >> LOG2_FRAC_BITS;
        if y >= two {
            y >>= 1;
            fraction_bits |= 1u64 << (LOG2_FRAC_BITS - 1 - bit_index);
        }
    }

    let fraction_milli = (fraction_bits as u128 * LOG2_SCALE as u128
        + (1u128 << (LOG2_FRAC_BITS - 1)))
        >> LOG2_FRAC_BITS;

    (integer_bits as u64).saturating_mul(LOG2_SCALE) + fraction_milli as u64
}

pub fn format_millibits(value: u64) -> String {
    format!("{}.{}", value / LOG2_SCALE, (value % LOG2_SCALE) / 100)
}