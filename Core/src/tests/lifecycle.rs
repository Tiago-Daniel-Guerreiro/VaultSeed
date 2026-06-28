use super::common;

use crate::core::MasterKeyInput;
use crate::errors::{CommonError, CoreError, DomainError, RestrictionError};
use crate::models::{GenerationParams, MaskOrLiteral};

#[test]
fn remove_restriction_em_uso() {
    let vault = common::build_test_vault();
    let master_key = MasterKeyInput::new("k1-rm-r".to_string(), "k2-rm-r".to_string());
    let (device_uuid, restriction_uuid) = common::setup_basic_session(&vault, &master_key);

    let _ = vault
        .add_domain("used.example", restriction_uuid)
        .expect("add domain");

    let err = vault
        .remove_restriction(restriction_uuid)
        .expect_err("restriction in use should fail");

    assert!(matches!(err, CoreError::Restriction(RestrictionError::RestrictionInUse { domain_count: 1 })));

    let _ = device_uuid;
}

#[test]
fn remove_restriction_ok() {
    let vault = common::build_test_vault();
    let master_key = MasterKeyInput::new("k1-rm-ok".to_string(), "k2-rm-ok".to_string());
    let (device_uuid, restriction_uuid) = common::setup_basic_session(&vault, &master_key);

    let removable = vault
        .add_restriction("temporary", device_uuid, GenerationParams::default())
        .expect("add removable restriction");

    vault.remove_restriction(removable).expect("remove restriction");
    let err = vault.get_restriction(removable).expect_err("removed restriction should disappear");
    assert!(matches!(err, CoreError::Restriction(RestrictionError::UuidNotFound(_))));

    assert!(vault.get_restriction(restriction_uuid).is_ok());
}

#[test]
fn rename_restriction_ok() {
    let vault = common::build_test_vault();
    let master_key = MasterKeyInput::new("k1-rn-ok".to_string(), "k2-rn-ok".to_string());
    let (_device_uuid, restriction_uuid) = common::setup_basic_session(&vault, &master_key);

    vault
        .rename_restriction(restriction_uuid, "  Nova Restricao  ")
        .expect("rename restriction");

    let restriction = vault.get_restriction(restriction_uuid).expect("get restriction");
    assert_eq!(restriction.name, "nova restricao");
}

#[test]
fn rename_restriction_conflito_mesmo_device() {
    let vault = common::build_test_vault();
    let master_key = MasterKeyInput::new("k1-rn-conf".to_string(), "k2-rn-conf".to_string());
    let (device_uuid, restriction_uuid) = common::setup_basic_session(&vault, &master_key);

    let _ = vault
        .add_restriction("B", device_uuid, GenerationParams::default())
        .expect("add second restriction");

    let err = vault
        .rename_restriction(restriction_uuid, "b")
        .expect_err("same-device rename collision should fail");

    assert!(matches!(err, CoreError::Restriction(RestrictionError::NameAlreadyExists(name)) if name == "b"));
}

#[test]
fn rename_restriction_sem_conflito_device_diferente() {
    let vault = common::build_test_vault();
    let master_key = MasterKeyInput::new("k1-rn-diff".to_string(), "k2-rn-diff".to_string());
    let (device_a, restriction_a) = common::setup_basic_session(&vault, &master_key);
    let device_b = vault.add_device("Device-B", &master_key).expect("add second device");
    let _ = vault
        .add_restriction("B", device_b, GenerationParams::default())
        .expect("add restriction on other device");

    vault
        .rename_restriction(restriction_a, "b")
        .expect("rename across devices should be allowed");

    assert_eq!(vault.get_restriction(restriction_a).expect("get restriction").name, "b");
    let _ = device_a;
}

#[test]
fn select_restriction_limpa_domain() {
    let vault = common::build_test_vault();
    let master_key = MasterKeyInput::new("k1-sel-r".to_string(), "k2-sel-r".to_string());
    let (_device_uuid, restriction_uuid) = common::setup_basic_session(&vault, &master_key);
    let domain_uuid = vault
        .add_domain("domain.example", restriction_uuid)
        .expect("add domain");

    vault.select_domain(domain_uuid).expect("select domain");
    vault.select_restriction(restriction_uuid).expect("select restriction");

    let state = vault.state();
    let state = state.read().unwrap();
    let session = state.session.as_ref().expect("session");
    assert_eq!(session.selected_restriction, Some(restriction_uuid));
    assert!(session.selected_domain.is_none());
}

#[test]
fn select_restriction_uuid_inexistente() {
    let vault = common::build_test_vault();
    let master_key = MasterKeyInput::new("k1-sel-r-err".to_string(), "k2-sel-r-err".to_string());
    let (_device_uuid, _restriction_uuid) = common::setup_basic_session(&vault, &master_key);

    let err = vault
        .select_restriction(uuid::Uuid::new_v4())
        .expect_err("missing restriction should fail");

    assert!(matches!(err, CoreError::Restriction(RestrictionError::UuidNotFound(_))));
}

#[test]
fn add_char_list_ok() {
    let vault = common::build_test_vault();
    let master_key = MasterKeyInput::new("k1-cl-add".to_string(), "k2-cl-add".to_string());
    let (_device_uuid, restriction_uuid) = common::setup_basic_session(&vault, &master_key);

    let uuid = vault
        .add_char_list_to_restriction(restriction_uuid, "custom", 16, vec!["€".to_string(), "£".to_string()])
        .expect("add char list");

    let lists = vault.list_char_lists(restriction_uuid).expect("list char lists");
    assert!(lists.iter().any(|item| item.uuid == uuid));
}

#[test]
fn remove_char_list_ok() {
    let vault = common::build_test_vault();
    let master_key = MasterKeyInput::new("k1-cl-rm".to_string(), "k2-cl-rm".to_string());
    let (_device_uuid, restriction_uuid) = common::setup_basic_session(&vault, &master_key);

    let uuid = vault
        .add_char_list_to_restriction(restriction_uuid, "custom", 16, vec!["x".to_string()])
        .expect("add char list");

    vault
        .remove_char_list_from_restriction(restriction_uuid, uuid)
        .expect("remove char list");

    let lists = vault.list_char_lists(restriction_uuid).expect("list char lists");
    assert!(!lists.iter().any(|item| item.uuid == uuid));
}

#[test]
fn update_char_list_ok() {
    let vault = common::build_test_vault();
    let master_key = MasterKeyInput::new("k1-cl-upd".to_string(), "k2-cl-upd".to_string());
    let (_device_uuid, restriction_uuid) = common::setup_basic_session(&vault, &master_key);

    let uuid = vault
        .add_char_list_to_restriction(restriction_uuid, "custom", 16, vec!["x".to_string()])
        .expect("add char list");

    vault
        .update_char_list_elements(restriction_uuid, uuid, vec!["y".to_string(), "z".to_string()])
        .expect("update char list");

    let lists = vault.list_char_lists(restriction_uuid).expect("list char lists");
    let updated = lists.iter().find(|item| item.uuid == uuid).expect("updated char list");
    assert_eq!(updated.elements, vec!["y".to_string(), "z".to_string()]);
}

#[test]
fn insert_mask_posicao_valida_inicio() {
    let vault = common::build_test_vault();
    let master_key = MasterKeyInput::new("k1-ins-mask".to_string(), "k2-ins-mask".to_string());
    let (_device_uuid, restriction_uuid) = common::setup_basic_session(&vault, &master_key);

    let before = vault.get_restriction(restriction_uuid).expect("get restriction");
    let before_len = before.generation.sequence().map(|seq| seq.len()).unwrap_or(0);

    vault
        .insert_restriction_mask_position(restriction_uuid, 16, 0)
        .expect("insert mask");

    let after = vault.get_restriction(restriction_uuid).expect("get restriction");
    let sequence = after.generation.sequence().expect("sequence");

    assert_eq!(sequence.len(), before_len + 1);
    assert_eq!(sequence.first(), Some(&MaskOrLiteral::Mask(16)));
}

#[test]
fn insert_literal_posicao_valida() {
    let vault = common::build_test_vault();
    let master_key = MasterKeyInput::new("k1-ins-lit".to_string(), "k2-ins-lit".to_string());
    let (_device_uuid, restriction_uuid) = common::setup_basic_session(&vault, &master_key);

    vault
        .insert_restriction_literal_position(restriction_uuid, "-", 2)
        .expect("insert literal");

    let restriction = vault.get_restriction(restriction_uuid).expect("get restriction");
    let sequence = restriction.generation.sequence().expect("sequence");
    assert_eq!(sequence.get(2), Some(&MaskOrLiteral::Literal("-".to_string())));
}

#[test]
fn insert_mask_posicao_fora_intervalo() {
    let vault = common::build_test_vault();
    let master_key = MasterKeyInput::new("k1-ins-out".to_string(), "k2-ins-out".to_string());
    let (_device_uuid, restriction_uuid) = common::setup_basic_session(&vault, &master_key);
    let len = vault.get_restriction(restriction_uuid).expect("restriction").generation.sequence().map(|seq| seq.len()).unwrap_or(0);

    let err = vault
        .insert_restriction_mask_position(restriction_uuid, 16, len + 1)
        .expect_err("out of range should fail");

    assert!(matches!(err, CoreError::Common(CommonError::OutOfRange(_))));
}

#[test]
fn extend_ja_tem_bits_suficientes() {
    let vault = common::build_test_vault();
    let master_key = MasterKeyInput::new("k1-ext0".to_string(), "k2-ext0".to_string());
    let (_device_uuid, restriction_uuid) = common::setup_basic_session(&vault, &master_key);

    let added = vault
        .extend_restriction_format_to_entropy(restriction_uuid, 0)
        .expect("extend zero target");

    assert_eq!(added, 0);
}

#[test]
fn extend_adiciona_posicoes_corretas() {
    let vault = common::build_test_vault();
    let master_key = MasterKeyInput::new("k1-ext128".to_string(), "k2-ext128".to_string());
    let (_device_uuid, restriction_uuid) = common::setup_basic_session(&vault, &master_key);

    let mut restriction = vault.get_restriction(restriction_uuid).expect("restriction");
    let mut params = restriction.generation.clone();
    params.format_sequence = Some(Vec::new());
    vault
        .update_restriction_generation(restriction_uuid, params)
        .expect("reset sequence");

    restriction = vault.get_restriction(restriction_uuid).expect("restriction");
    let before = restriction.generation.sequence().map(|seq| seq.len()).unwrap_or(0);
    let added = vault
        .extend_restriction_format_to_entropy(restriction_uuid, 128)
        .expect("extend target");

    let after = vault.get_restriction(restriction_uuid).expect("restriction");
    let after_len = after.generation.sequence().map(|seq| seq.len()).unwrap_or(0);

    assert!(added > 0);
    assert_eq!(after_len, before + added);
}

#[test]
fn add_domain_ok() {
    let vault = common::build_test_vault();
    let master_key = MasterKeyInput::new("k1-dom-ok".to_string(), "k2-dom-ok".to_string());
    let (_device_uuid, restriction_uuid) = common::setup_basic_session(&vault, &master_key);

    let uuid = vault.add_domain("example.com", restriction_uuid).expect("add domain");
    assert!(vault.list_domains(restriction_uuid).expect("list domains").iter().any(|domain| domain.uuid == uuid));
}

#[test]
fn remove_domain_ok() {
    let vault = common::build_test_vault();
    let master_key = MasterKeyInput::new("k1-dom-rm".to_string(), "k2-dom-rm".to_string());
    let (_device_uuid, restriction_uuid) = common::setup_basic_session(&vault, &master_key);

    let uuid = vault.add_domain("example.com", restriction_uuid).expect("add domain");
    vault.remove_domain(uuid).expect("remove domain");

    assert!(!vault.list_domains(restriction_uuid).expect("list domains").iter().any(|domain| domain.uuid == uuid));
}

#[test]
fn remove_domain_limpa_selecao() {
    let vault = common::build_test_vault();
    let master_key = MasterKeyInput::new("k1-dom-sel".to_string(), "k2-dom-sel".to_string());
    let (_device_uuid, restriction_uuid) = common::setup_basic_session(&vault, &master_key);

    let uuid = vault.add_domain("example.com", restriction_uuid).expect("add domain");
    vault.select_domain(uuid).expect("select domain");
    vault.remove_domain(uuid).expect("remove selected domain");

    let state = vault.state();
    let state = state.read().unwrap();
    let session = state.session.as_ref().expect("session");
    assert!(session.selected_domain.is_none());
}

#[test]
fn remove_domain_uuid_inexistente() {
    let vault = common::build_test_vault();
    let master_key = MasterKeyInput::new("k1-dom-nf".to_string(), "k2-dom-nf".to_string());
    let (_device_uuid, restriction_uuid) = common::setup_basic_session(&vault, &master_key);

    vault.add_domain("example.com", restriction_uuid).expect("add domain");
    vault.remove_domain(uuid::Uuid::new_v4()).expect("retain should be silent");
}

#[test]
fn select_domain_ok() {
    let vault = common::build_test_vault();
    let master_key = MasterKeyInput::new("k1-dom-sel-ok".to_string(), "k2-dom-sel-ok".to_string());
    let (_device_uuid, restriction_uuid) = common::setup_basic_session(&vault, &master_key);

    let uuid = vault.add_domain("example.com", restriction_uuid).expect("add domain");
    vault.select_domain(uuid).expect("select domain");

    let state = vault.state();
    let state = state.read().unwrap();
    let session = state.session.as_ref().expect("session");
    assert_eq!(session.selected_domain, Some(uuid));
}

#[test]
fn select_domain_uuid_inexistente() {
    let vault = common::build_test_vault();
    let master_key = MasterKeyInput::new("k1-dom-sel-nf".to_string(), "k2-dom-sel-nf".to_string());
    let (_device_uuid, _restriction_uuid) = common::setup_basic_session(&vault, &master_key);

    let err = vault.select_domain(uuid::Uuid::new_v4()).expect_err("missing domain should fail");
    assert!(matches!(err, CoreError::Domain(DomainError::UuidNotFound(_))));
}

#[test]
fn change_domain_restriction_ok() {
    let vault = common::build_test_vault();
    let master_key = MasterKeyInput::new("k1-dom-chg".to_string(), "k2-dom-chg".to_string());
    let (device_uuid, restriction_uuid) = common::setup_basic_session(&vault, &master_key);
    let new_restriction = vault
        .add_restriction("secondary", device_uuid, GenerationParams::default())
        .expect("add new restriction");
    let domain_uuid = vault.add_domain("example.com", restriction_uuid).expect("add domain");

    vault
        .change_domain_restriction(domain_uuid, new_restriction)
        .expect("change restriction");

    assert_eq!(vault.get_domain(domain_uuid).expect("domain").restriction_uuid, new_restriction);
}

#[test]
fn change_domain_restriction_device_diferente() {
    let vault = common::build_test_vault();
    let master_key = MasterKeyInput::new("k1-dom-mismatch".to_string(), "k2-dom-mismatch".to_string());
    let (device_a, restriction_a) = common::setup_basic_session(&vault, &master_key);
    let device_b = vault.add_device("Device-B", &master_key).expect("add second device");
    let restriction_b = vault
        .add_restriction("secondary", device_b, GenerationParams::default())
        .expect("add restriction on device b");
    let domain_uuid = vault.add_domain("example.com", restriction_a).expect("add domain");

    let err = vault
        .change_domain_restriction(domain_uuid, restriction_b)
        .expect_err("cross-device restriction change should fail");

    assert!(matches!(err, CoreError::Domain(DomainError::RestrictionDeviceMismatch)));
    let _ = device_a;
}

#[test]
fn change_domain_uuid_inexistente() {
    let vault = common::build_test_vault();
    let master_key = MasterKeyInput::new("k1-dom-uid-nf".to_string(), "k2-dom-uid-nf".to_string());
    let (device_uuid, restriction_uuid) = common::setup_basic_session(&vault, &master_key);
    let new_restriction = vault
        .add_restriction("secondary", device_uuid, GenerationParams::default())
        .expect("add restriction");
    let _domain_uuid = vault.add_domain("example.com", restriction_uuid).expect("add domain");

    let err = vault
        .change_domain_restriction(uuid::Uuid::new_v4(), new_restriction)
        .expect_err("missing domain should fail");

    assert!(matches!(err, CoreError::Domain(DomainError::UuidNotFound(_))));
}

#[test]
fn change_domain_nova_restriction_inexistente() {
    let vault = common::build_test_vault();
    let master_key = MasterKeyInput::new("k1-dom-rest-nf".to_string(), "k2-dom-rest-nf".to_string());
    let (_device_uuid, restriction_uuid) = common::setup_basic_session(&vault, &master_key);
    let domain_uuid = vault.add_domain("example.com", restriction_uuid).expect("add domain");

    let err = vault
        .change_domain_restriction(domain_uuid, uuid::Uuid::new_v4())
        .expect_err("missing restriction should fail");

    assert!(matches!(err, CoreError::Domain(DomainError::RestrictionNotFound)));
}

#[test]
fn get_compromise_history_dominio_sem_historico() {
    let vault = common::build_test_vault();
    let master_key = MasterKeyInput::new("k1-history".to_string(), "k2-history".to_string());
    let (_device_uuid, restriction_uuid) = common::setup_basic_session(&vault, &master_key);
    let domain_uuid = vault.add_domain("example.com", restriction_uuid).expect("add domain");

    assert!(vault.get_compromise_history(domain_uuid).expect("history").is_empty());
}