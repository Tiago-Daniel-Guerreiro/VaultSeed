#![allow(dead_code)]

use crossterm::cursor::MoveTo;
use crossterm::terminal::{Clear, ClearType};
use std::io::{self};

use crate::core::USER_CHAR_LIST_BIT_MIN;
use crate::core::USER_CHAR_LIST_SLOT_COUNT;
use crate::generator;
use crate::models::{
    CharacterList, Device, Domain, LocalState, MaskOrLiteral,
    Restriction, StaticPasswordPlaintext,
};

pub(crate) fn clear_screen() {
    let mut stdout = io::stdout();
    let _ = crossterm::execute!(stdout, Clear(ClearType::All), MoveTo(0, 0));
}

pub(crate) fn pause() {
    #[cfg(feature = "desktop")]
    {
        use crossterm::event::{read, Event, KeyEventKind};
        use crossterm::terminal::{disable_raw_mode, enable_raw_mode};

        println!("Pressione qualquer tecla para continuar...");
        if enable_raw_mode().is_ok() {
            loop {
                if let Ok(Event::Key(key)) = read() {
                    if key.kind == KeyEventKind::Press {
                        break;
                    }
                }
            }
            let _ = disable_raw_mode();
        } else {
            let mut buffer = String::new();
            let _ = io::stdin().read_line(&mut buffer);
        }
    }

    #[cfg(not(feature = "desktop"))]
    {
        println!("Pressione Enter para continuar...");
        let mut buffer = String::new();
        let _ = io::stdin().read_line(&mut buffer);
    }

    println!();
}

pub(crate) fn print_invalid_option() {
    println!("Opção inválida!");
    pause();
}

pub(crate) fn stub(name: &str) {
    println!();
    println!("--- {} ---", name);
    println!("(não implementado)");
    pause();
}

pub(crate) fn bit_to_slot(bit: u8) -> u8 {
    bit - USER_CHAR_LIST_BIT_MIN + 1
}

pub(crate) fn slot_to_bit(slot: u8) -> u8 {
    USER_CHAR_LIST_BIT_MIN + (slot - 1)
}

pub(crate) fn mask_bits_string(mask: u32) -> String {
    (0..32u8)
        .filter(|&bit| (mask & (1u32 << bit)) != 0)
        .map(|bit| bit.to_string())
        .collect::<Vec<_>>()
        .join(",")
}

pub(crate) fn count_bits(mask: u32) -> u32 {
    mask.count_ones()
}

pub(crate) fn copy_to_clipboard(_value: &str) -> Result<(), String> {
    #[cfg(all(feature = "clipboard", not(target_os = "ios")))]
    {
        use arboard::Clipboard;
        let mut clipboard = Clipboard::new().map_err(|e| e.to_string())?;
        clipboard.set_text(_value).map_err(|e| e.to_string())
    }
    #[cfg(not(all(feature = "clipboard", not(target_os = "ios"))))]
    {
        Err("Clipboard não disponível nesta plataforma.".to_string())
    }
}

pub(crate) fn print_menu_box(title: &str, width: usize, body_lines: &[&str]) {
    let content_width = width.saturating_sub(4).max(1);
    let border = "═".repeat(content_width + 2);
    println!("╔{}╗", border);
    println!("║ {:^content_width$} ║", title);
    for line in body_lines {
        println!("║ {:<content_width$} ║", line);
    }
    println!("╚{}╝", border);
}

pub(crate) fn print_mask_help() {
    println!("Ajuda de máscaras: Use número decimal ou 0xHEX para especificar máscara.");
}

pub(crate) fn show_mask_help() {
    print_mask_help();
    pause();
}

pub(crate) fn print_devices_menu_list(devices: &[Device]) {
    if devices.is_empty() {
        println!("║  (nenhum dispositivo)            ║");
    } else {
        for (i, dev) in devices.iter().enumerate() {
            println!("║  {}. {}  ║", i + 1, dev.name);
        }
    }
}

pub(crate) fn print_selectable_device_list(devices: &[Device]) {
    if devices.is_empty() {
        println!("Nenhum dispositivo disponível.");
        return;
    }
    for (i, device) in devices.iter().enumerate() {
        println!("  {}. {}", i + 1, device.name);
    }
    println!("  0. Cancelar");
}

pub(crate) fn print_device_summary(device: &Device) {
    println!("╔══════════════════════════════════╗");
    println!("║          DISPOSITIVO             ║");
    println!("╠══════════════════════════════════╣");
    println!("║ Nome: {}", device.name);
    println!("║ UUID: {}", device.uuid);
    println!("╚══════════════════════════════════╝");
}

pub(crate) fn print_device_config(device: &Device) {
    println!("╔══════════════════════════════════╗");
    println!("║      VER CONFIGURAÇÕES           ║");
    println!("╚══════════════════════════════════╝");
    println!();
    println!("Nome: {}", device.name);
    println!("UUID: {}", device.uuid);
    println!("Salt device: {}", hex::encode(device.salt_device));
    println!("Argon2:");
    println!("  m_cost: {} KiB", device.argon2.m_cost_kib);
    println!("  t_cost: {}", device.argon2.t_cost);
    println!("  p_cost: {}", device.argon2.p_cost);
    println!("Seed nonce: {}", hex::encode(device.seed_envelope.nonce));
    println!(
        "Seed ciphertext: {} bytes",
        device.seed_envelope.ciphertext.len()
    );
}

pub(crate) fn print_device_removal_summary(name: &str, uuid: uuid::Uuid) {
    println!();
    println!("  Nome: {}", name);
    println!("  UUID: {}", uuid);
}

pub(crate) fn print_restriction_char_lists_summary(char_lists: &[CharacterList]) {
    if char_lists.is_empty() {
        println!("  Listas: (nenhuma)");
    } else {
        println!("  Listas:");
        for list in char_lists {
            println!(
                "    {}/{}: {} ({} elementos)",
                bit_to_slot(list.bit),
                USER_CHAR_LIST_SLOT_COUNT,
                list.name,
                list.elements.len()
            );
        }
    }
}

pub(crate) fn print_charlists_view(
    restriction: Option<&Restriction>,
    char_lists: &[CharacterList],
) {
    println!("╔══════════════════════════════════╗");
    println!("║   LISTAS DE CARACTERES           ║");
    println!("╚══════════════════════════════════╝");
    println!();
    if let Some(r) = restriction {
        println!("Restrição: {} ({})", r.name, r.uuid);
        println!();
    }
    for cl in char_lists {
        println!(
            "  posição {}/{}: {}",
            bit_to_slot(cl.bit),
            USER_CHAR_LIST_SLOT_COUNT,
            cl.name
        );
        println!("    UUID: {}", cl.uuid);
        println!(
            "    Elementos ({}): {}",
            cl.elements.len(),
            cl.elements.join(", ")
        );
        println!();
    }
}

pub(crate) fn print_restriction_config_header(
    name: &str,
    uuid: uuid::Uuid,
    device_uuid: uuid::Uuid,
    default_mask: u32,
    bytes_to_derive: usize,
    format_visual: &str,
) {
    println!("╔══════════════════════════════════════════════╗");
    println!("║        CONFIGURAÇÃO DA RESTRIÇÃO            ║");
    println!("╚══════════════════════════════════════════════╝");
    println!();
    println!("  Nome:              {}", name);
    println!("  UUID:              {}", uuid);
    println!("  Device UUID:       {}", device_uuid);
    println!("  Máscara padrão:    {}", default_mask);
    println!("  Bytes KMAC XOF:    {}", bytes_to_derive);
    println!("  Formato visual:    {}", format_visual);
    println!();
}

pub(crate) fn print_restriction_sequence_items(lines: &[String]) {
    if lines.is_empty() {
        println!("  Sequência: (não definida)");
        return;
    }
    println!("  Posições ({}):", lines.len());
    for line in lines {
        println!("{}", line);
    }
}

pub(crate) fn print_restriction_remove_summary(name: &str, uuid: uuid::Uuid) {
    println!();
    println!("  Restrição: {} ({})", name, uuid);
}

pub(crate) fn print_sequence_with_indexes(sequence: &[MaskOrLiteral]) {
    for (i, item) in sequence.iter().enumerate() {
        match item {
            MaskOrLiteral::Mask(mask) => println!(
                "{}. Mask: {} (bits: {})",
                i + 1,
                mask,
                mask_bits_string(*mask)
            ),
            MaskOrLiteral::Literal(value) => println!("{}. Literal: /{}/", i + 1, value),
        }
    }
}

pub(crate) fn print_domain_selection_list(domains: &[Domain]) {
    if domains.is_empty() {
        println!("Nenhum domínio disponível.");
        return;
    }
    println!();
    println!("Selecione um domínio:");
    for (i, domain) in domains.iter().enumerate() {
        let compromised = if domain.compromise_history.is_empty() {
            ""
        } else {
            " [tem histórico]"
        };
        println!(
            "  {}. {} (var: {}){}",
            i + 1,
            domain.identifier_canonical,
            domain.active_variation,
            compromised,
        );
    }
    println!("  0. Cancelar");
}

pub(crate) fn print_domain_header(domain: &Domain) {
    println!("╔══════════════════════════════════╗");
    println!("║  DOMÍNIO: {}  ║", domain.identifier_canonical);
    println!("╠══════════════════════════════════╣");
    println!("║  Variação ativa: {}  ║", domain.active_variation);
    println!(
        "║  Versões comprometidas: {}  ║",
        domain.compromise_history.len()
    );
    println!("║  UUID: {}  ║", domain.uuid);
}

pub(crate) fn print_domain_removal_summary(identifier: &str, uuid: uuid::Uuid) {
    println!();
    println!("  Domínio: {}", identifier);
    println!("  UUID:    {}", uuid);
}

pub(crate) fn print_mark_domain_compromised_intro(domain_identifier: &str, variation: u32) {
    println!("╔══════════════════════════════════╗");
    println!("║  MARCAR COMO COMPROMETIDA        ║");
    println!("╚══════════════════════════════════╝");
    println!();
    println!("  Domínio:   {}", domain_identifier);
    println!("  Variação:  {}", variation);
    println!();
    println!("Esta operação:");
    println!("  1. Guarda um snapshot da configuração atual");
    println!("  2. Incrementa a variação ativa");
    println!("  3. A nova senha será completamente diferente");
    println!();
    println!("A senha antiga poderá ser recuperada em 'Versões comprometidas'.");
    println!();
}

pub(crate) fn print_change_domain_restriction_warning(current_restriction_uuid: uuid::Uuid) {
    println!("ATENÇÃO: Mudar a restrição altera a senha gerada!");
    println!("Considere marcar a senha como comprometida primeiro.");
    println!();
    println!("Restrição atual: {}", current_restriction_uuid);
}

pub(crate) fn print_domain_change_restriction_list(
    current_restriction_uuid: uuid::Uuid,
    restrictions: &[(String, uuid::Uuid)],
) {
    println!();
    println!("Restrições disponíveis:");
    for (i, (name, uuid)) in restrictions.iter().enumerate() {
        let current = if *uuid == current_restriction_uuid {
            " [ATUAL]"
        } else {
            ""
        };
        println!("  {}. {} ({}){}", i + 1, name, uuid, current);
    }
    println!("  0. Cancelar");
}

pub(crate) fn print_derived_password_result(
    password: &str,
    variation: u32,
    entropy_millibits: u64,
    device_uuid: uuid::Uuid,
    restriction_uuid: uuid::Uuid,
) {
    println!();
    println!("╔══════════════════════════════════╗");
    println!("║          RESULTADO               ║");
    println!("╠══════════════════════════════════╣");
    println!("║  Senha: {}  ║", password);
    println!("╠══════════════════════════════════╣");
    println!("║  Comprimento:    {}  ║", password.len());
    println!("║  Variação:       {}  ║", variation);
    println!(
        "║  Entropia:       {} bits  ║",
        generator::format_millibits(entropy_millibits)
    );
    println!("║  Device:         {}  ║", device_uuid);
    println!("║  Restriction:    {}  ║", restriction_uuid);
    println!("╚══════════════════════════════════╝");
}

pub(crate) fn print_frozen_password_result(
    password: &str,
    variation: u32,
    entropy_millibits: u64,
) {
    println!();
    println!("╔══════════════════════════════════╗");
    println!("║          RESULTADO               ║");
    println!("╠══════════════════════════════════╣");
    println!("║  Senha: {}  ║", password);
    println!("╠══════════════════════════════════╣");
    println!("║  Comprimento:   {}  ║", password.len());
    println!("║  Variação:      {}  ║", variation);
    println!(
        "║  Entropia:      {} bits  ║",
        generator::format_millibits(entropy_millibits)
    );
    println!("╚══════════════════════════════════╝");
}

pub(crate) fn print_compromised_version_header(variation: u32) {
    println!("╔══════════════════════════════════╗");
    println!("║  SENHA COMPROMETIDA (var: {})  ║", variation);
    println!("╚══════════════════════════════════╝");
    println!();
}

pub(crate) fn print_compromise_version_list(entries: &[(u32, String, String)]) {
    if entries.is_empty() {
        println!("Nenhuma versão comprometida.");
        return;
    }
    println!();
    println!("Selecione uma versão:");
    for (index, (variation, date, frozen_id)) in entries.iter().enumerate() {
        println!(
            "  {}. variação {} - {} (domínio: {})",
            index + 1,
            variation,
            date,
            frozen_id,
        );
    }
    println!("  0. Cancelar");
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn print_frozen_details(
    record_uuid: uuid::Uuid,
    variation: u32,
    timestamp: &str,
    config_version: u8,
    kmac_context: &str,
    identifier_frozen: &str,
    default_mask_snapshot: u32,
    password_hmac: Option<&[u8; 32]>,
    sequence_lines: &[String],
    char_lists: &[CharacterList],
) {
    println!("╔══════════════════════════════════╗");
    println!("║  DETALHES DO SNAPSHOT            ║");
    println!("╚══════════════════════════════════╝");
    println!();
    println!("  Record UUID:     {}", record_uuid);
    println!("  Variação:        {}", variation);
    println!("  Timestamp:       {}", timestamp);
    println!();
    println!("  Config version:  {}", config_version);
    println!("  Contexto KMAC:   {}", kmac_context);
    println!("  ID congelado:    {}", identifier_frozen);
    println!("  Máscara padrão:  {}", default_mask_snapshot);
    println!(
        "  HMAC:            {}",
        password_hmac
            .map(hex::encode)
            .unwrap_or_else(|| "(não disponível)".to_string())
    );
    println!();
    if sequence_lines.is_empty() {
        println!("  Sequência: (não definida)");
    } else {
        println!("  Sequência ({} posições):", sequence_lines.len());
        for line in sequence_lines {
            println!("{}", line);
        }
    }
    println!();
    println!("  Listas de caracteres ({}):", char_lists.len());
    for cl in char_lists {
        println!(
            "    bit {:>2}: {} ({} elementos)",
            cl.bit, cl.name, cl.elements.len()
        );
    }
}

pub(crate) fn print_static_password_plaintext(
    plaintext: &StaticPasswordPlaintext,
    compromised_label: &str,
) {
    println!();
    println!("  Label:        {}", plaintext.label);
    println!("  Valor:        {}", plaintext.value);
    println!("  Notas:        {}", plaintext.notes);
    println!("  Comprometida: {}", compromised_label);
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn print_session_overview(
    schema_version: u32,
    salt_session: &[u8; 32],
    argon2_m_cost_kib: u32,
    argon2_t_cost: u32,
    argon2_p_cost: u32,
    hardware_enabled: bool,
    salt_hkdf: Option<&[u8; 32]>,
    nonce_global: &[u8; 24],
    ciphertext_global_len: usize,
    device_count: usize,
    restriction_count: usize,
    domain_count: usize,
    static_password_count: usize,
) {
    println!("╔══════════════════════════════════╗");
    println!("║    PARÂMETROS DA SESSÃO          ║");
    println!("╚══════════════════════════════════╝");
    println!();
    println!("  Schema version:  {}", schema_version);
    println!("  Salt session:    {}", hex::encode(salt_session));
    println!();
    println!("  Argon2id:");
    println!(
        "    m_cost:  {} KiB ({} MiB)",
        argon2_m_cost_kib,
        argon2_m_cost_kib / 1024
    );
    println!("    t_cost:  {}", argon2_t_cost);
    println!("    p_cost:  {}", argon2_p_cost);
    println!();
    println!(
        "  Fator físico:    {}",
        if hardware_enabled { "ATIVO" } else { "INATIVO" }
    );
    if let Some(salt) = salt_hkdf {
        println!("  Salt HKDF:       {}", hex::encode(salt));
    }
    println!();
    println!("  Nonce global:    {}", hex::encode(nonce_global));
    println!("  Ciphertext:      {} bytes", ciphertext_global_len);
    println!();
    println!("  Dispositivos:    {}", device_count);
    println!("  Restrições:      {}", restriction_count);
    println!("  Domínios:        {}", domain_count);
    println!("  Senhas estáticas: {}", static_password_count);
}

pub(crate) fn print_local_state_calibration(local_state: &LocalState) {
    let min = local_state
        .calibration_min_target_ms
        .map(|v| format!("{} ms", v))
        .unwrap_or_else(|| "(não definido)".to_string());
    let max = local_state
        .calibration_max_target_ms
        .map(|v| format!("{} ms", v))
        .unwrap_or_else(|| "(não definido)".to_string());
    println!("║  Tempo calibração mín: {}", min);
    println!("║  Tempo calibração máx: {}", max);
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum SelectionNodeType {
    Device,
    Restriction,
    Folder,
    DerivedPassword,
    StaticPassword,
}

#[derive(Debug, Clone)]
pub(crate) struct SelectionNode {
    pub uuid: uuid::Uuid,
    pub label: String,
    pub node_type: SelectionNodeType,
    pub selected: bool,
    pub children: Vec<SelectionNode>,
}

pub(crate) fn flatten_tree_for_display(tree: &[SelectionNode]) -> Vec<(usize, String, bool)> {
    let mut result = Vec::new();
    flatten_recursive(tree, 0, &mut result);
    result
}

fn flatten_recursive(
    nodes: &[SelectionNode],
    indent: usize,
    result: &mut Vec<(usize, String, bool)>,
) {
    for node in nodes {
        result.push((indent, node.label.clone(), node.selected));
        flatten_recursive(&node.children, indent + 1, result);
    }
}

pub(crate) fn print_selection_tree(tree: &[SelectionNode]) {
    let flat = flatten_tree_for_display(tree);
    for (i, (indent, label, selected)) in flat.iter().enumerate() {
        let tag = if *selected { "[on] " } else { "[off]" };
        let prefix = "  ".repeat(*indent);
        println!("  {:>3}. {}{} {}", i + 1, prefix, tag, label);
    }
}

pub(crate) fn count_selected(tree: &[SelectionNode]) -> usize {
    tree.iter().fold(0, |acc, node| {
        let self_count = if node.selected && node.children.is_empty() {
            1
        } else {
            0
        };
        acc + self_count + count_selected(&node.children)
    })
}

pub(crate) fn extract_selected_uuids(
    tree: &[SelectionNode],
) -> (
    Vec<uuid::Uuid>,
    Vec<uuid::Uuid>,
    Vec<uuid::Uuid>,
    Vec<uuid::Uuid>,
) {
    let mut device_uuids = Vec::new();
    let mut restriction_uuids = Vec::new();
    let mut domain_uuids = Vec::new();
    let mut static_uuids = Vec::new();

    for device in tree {
        if !device.selected {
            continue;
        }
        device_uuids.push(device.uuid);
        for group in &device.children {
            if !group.selected {
                continue;
            }
            match group.node_type {
                SelectionNodeType::Restriction => {
                    restriction_uuids.push(group.uuid);
                    for entry in &group.children {
                        if entry.selected {
                            domain_uuids.push(entry.uuid);
                        }
                    }
                }
                SelectionNodeType::Folder => {
                    for entry in &group.children {
                        if entry.selected {
                            static_uuids.push(entry.uuid);
                        }
                    }
                }
                _ => {}
            }
        }
    }

    (device_uuids, restriction_uuids, domain_uuids, static_uuids)
}