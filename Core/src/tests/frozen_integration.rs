use crate::core::{MasterKeyInput, PasswordRequest, VaultCore};
use crate::services::generator::GeneratorServiceImpl;
use crate::models::{Argon2Params, LocalState};
use crate::services::crypto::CryptoServiceImpl;
use crate::services::file::FileServiceImpl;

#[test]
fn frozen_integration_real_crypto() {
    let vault = VaultCore::new(
        LocalState::new(),
        CryptoServiceImpl::new(),
        GeneratorServiceImpl::new(),
        FileServiceImpl::new(),
        false,
    );

    let master_key = MasterKeyInput::new("fint-k1".to_string(), "fint-k2".to_string());

    let argon = Argon2Params {
        m_cost_kib: 1024,
        t_cost: 2,
        p_cost: 1,
    };

    vault
        .create_new_session([9u8; 32], argon, false, None)
        .expect("create session");

    let device_uuid = vault.add_device("Device-Frozen-Int", &master_key).expect("add device");
    let restriction_uuid = vault
        .list_restrictions(device_uuid)
        .expect("list restrictions")
        .first()
        .expect("default restriction")
        .uuid;

    let domain_uuid = vault
        .add_domain("frozen.integration.example", restriction_uuid)
        .expect("add domain");

    let original = vault
        .generate_password(
            PasswordRequest {
                domain_uuid,
                forced_variation: Some(0),
            },
            &master_key,
        )
        .expect("generate original password");

    vault
        .mark_domain_compromised(domain_uuid, 0, &master_key)
        .expect("freeze current password");

    vault
        .add_char_list_to_restriction(
            restriction_uuid,
            "extra-int",
            16,
            vec!["x".to_string(), "y".to_string()],
        )
        .expect("add extra char list");

    vault
        .insert_restriction_mask_position(restriction_uuid, 16, 0)
        .expect("change active format");

    let frozen = vault
        .generate_password_from_frozen(domain_uuid, 0, &master_key)
        .expect("generate frozen password");

    assert_eq!(frozen.password, original.password);
    assert_eq!(frozen.domain_uuid, domain_uuid);
    assert_eq!(frozen.variation, 0);

    let active_err = vault.generate_password(PasswordRequest { domain_uuid, forced_variation: Some(0) }, &master_key);
    assert!(matches!(active_err, Err(crate::errors::CoreError::Password(crate::errors::PasswordError::EmptyAlphabet))));
}
