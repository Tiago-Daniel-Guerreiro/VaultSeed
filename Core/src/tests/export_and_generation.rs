use super::common;

use crate::core::{MasterKeyInput, PasswordRequest};
use crate::crypto;
use crate::generator;
use crate::models::{ExportEntry, MaskOrLiteral, PasswordExportData};

#[test]
fn deterministic_generation_matches_reference_binary() {
    let seed = [0u8; 32];
    let context = generator::build_context(
        "example.com",
        0,
        "00000000-0000-0000-0000-000000000001",
        "00000000-0000-0000-0000-000000000002",
    );

    let mut entropy = [0u8; 32];
    crypto::kmac256_xof(&seed, context.as_bytes(), &mut entropy);

    assert_eq!(
        hex::encode(entropy),
        "9d60c00f2dcaa574e2358402708b6c82ab3ee3489b712b8fb17e5c037e0ab12d"
    );

    let bit_lists = common::build_default_bit_lists();
    let masks = vec![MaskOrLiteral::Mask(7); 4];
    let result = generator::generate_password(&entropy, &masks, &bit_lists)
        .expect("password generation");

    assert_eq!(result.password, "gtZt");
    assert_eq!(result.password.len(), 4);
    assert_eq!(result.total_entropy_millibits, 23_816);
}

#[test]
fn password_export_txt_groups_by_device_and_group() {
    let mut export = PasswordExportData::new(true);
    export.entries.push(ExportEntry {
        entry_type: "derivada".to_string(),
        device_name: "device-a".to_string(),
        group_name: "grupo-1".to_string(),
        identifier: "exemplo".to_string(),
        password: "secret-123".to_string(),
        variation: Some(2),
        is_compromised: true,
        compromise_date: Some("2026-05-23".to_string()),
    });
    export.entries.push(ExportEntry {
        entry_type: "estática".to_string(),
        device_name: "device-a".to_string(),
        group_name: "grupo-1".to_string(),
        identifier: "outra".to_string(),
        password: "static-456".to_string(),
        variation: None,
        is_compromised: false,
        compromise_date: None,
    });

    let txt = export.to_txt();

    let expected = concat!(
        "Device: device-a\n",
        "  grupo-1\n",
        "    exemplo [var:2] [COMPROMETIDA]: secret-123\n",
        "    outra: static-456\n",
        "\n",
    );

    assert_eq!(txt, expected);
}

#[test]
fn password_export_json_contains_entries() {
    let mut export = PasswordExportData::new(false);
    export.entries.push(ExportEntry {
        entry_type: "derivada".to_string(),
        device_name: "device-b".to_string(),
        group_name: "grupo-2".to_string(),
        identifier: "id-1".to_string(),
        password: "pw".to_string(),
        variation: None,
        is_compromised: false,
        compromise_date: None,
    });

    let json = export.to_json();

    let expected = concat!(
        "[\n",
        "  {\n",
        "    \"entry_type\": \"derivada\",\n",
        "    \"device_name\": \"device-b\",\n",
        "    \"group_name\": \"grupo-2\",\n",
        "    \"identifier\": \"id-1\",\n",
        "    \"password\": \"pw\",\n",
        "    \"variation\": null,\n",
        "    \"is_compromised\": false,\n",
        "    \"compromise_date\": null\n",
        "  }\n",
        "]",
    );

    assert_eq!(json, expected);
}

#[test]
fn password_export_csv_escaping() {
    let mut export = PasswordExportData::new(true);
    export.entries.push(ExportEntry {
        entry_type: "derivada".to_string(),
        device_name: "dev,one".to_string(),
        group_name: "g1".to_string(),
        identifier: "id\"quote\"".to_string(),
        password: "line1\nline2".to_string(),
        variation: None,
        is_compromised: false,
        compromise_date: None,
    });

    let csv = export.to_csv();

    let expected = concat!(
        "entry_type,device_name,group_name,identifier,variation,is_compromised,compromise_date,password\n",
        "derivada,\"dev,one\",g1,\"id\"\"quote\"\"\",,0,,\"line1\nline2\"\n",
    );

    assert_eq!(csv, expected);
}

#[test]
fn generate_password_via_core_matches_forced_variation() {
    let vault = common::build_test_vault();
    let master_key = MasterKeyInput::new("k1-core-gen".to_string(), "k2-core-gen".to_string());
    let (_device_uuid, restriction_uuid) = common::setup_basic_session(&vault, &master_key);
    let domain_uuid = vault.add_domain("example.com", restriction_uuid).expect("add domain");

    let generated = vault
        .generate_password(PasswordRequest { domain_uuid, forced_variation: Some(0) }, &master_key)
        .expect("generate password via core");

    assert_eq!(generated.domain_uuid, domain_uuid);
    assert_eq!(generated.variation, 0);
}
