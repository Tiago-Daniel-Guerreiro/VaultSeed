use std::collections::HashMap;

use crate::core::{GeneratedPassword, GeneratorService};
use crate::errors::PasswordError;
use crate::generator;
use crate::models::{Device, MaskOrLiteral, Restriction};

#[derive(Clone, Copy)]
pub struct GeneratorServiceImpl;

impl Default for GeneratorServiceImpl {
    fn default() -> Self {
        Self::new()
    }
}

impl GeneratorServiceImpl {
    pub fn new() -> Self {
        Self
    }
}

impl GeneratorService for GeneratorServiceImpl {
    fn generate_password(
        &self,
        entropy: &[u8],
        restriction: &Restriction,
        device: &Device,
    ) -> Result<GeneratedPassword, PasswordError> {
        let bit_lists = restriction.build_bit_lists();
        let masks = resolve_masks(restriction, &bit_lists)?;

        if masks.is_empty() {
            return Err(PasswordError::InsufficientEntropy);
        }

        let result = generator::generate_password(entropy, &masks, &bit_lists)?;

        Ok(GeneratedPassword {
            password: result.password,
            entropy_millibits: result.total_entropy_millibits,
            variation: 0,
            domain_uuid: uuid::Uuid::nil(),
            restriction_uuid: restriction.uuid,
            device_uuid: device.uuid,
        })
    }
}

fn resolve_masks(
    restriction: &Restriction,
    bit_lists: &HashMap<u8, Vec<String>>,
) -> Result<Vec<MaskOrLiteral>, PasswordError> {
    let default_mask = restriction.generation.effective_default_mask();

    match restriction.generation.resolved_sequence() {
        Some(resolved) => {
            validate_masks(&resolved, bit_lists)?;
            Ok(resolved)
        }
        None => {
            let bytes = restriction.generation.effective_bytes_to_derive();
            let derive_bits = (bytes * 8) as u32;
            let max_masks = generator::build_max_masks(default_mask, bit_lists, derive_bits);

            if max_masks.is_empty() {
                return Err(PasswordError::EmptyAlphabet);
            }

            Ok(max_masks)
        }
    }
}

fn validate_masks(
    masks: &[MaskOrLiteral],
    bit_lists: &HashMap<u8, Vec<String>>,
) -> Result<(), PasswordError> {
    for item in masks {
        if let MaskOrLiteral::Mask(mask) = item {
            if *mask == 0 {
                return Err(PasswordError::UnsupportedMask);
            }

            let has_chars = (0u8..32)
                .filter(|bit| (mask & (1u32 << *bit)) != 0)
                .any(|bit| {
                    bit_lists
                        .get(&bit)
                        .is_some_and(|list| !list.is_empty())
                });

            if !has_chars {
                return Err(PasswordError::EmptyAlphabet);
            }
        }
    }

    Ok(())
}