#![allow(dead_code)]

use crate::core::{
    CryptoService, FileService, GeneratorService, VaultCore,
};
use crate::errors::{CoreError, SessionError};
use crate::generator;
use crate::models::{Argon2Params, MaskOrLiteral, StaticPassword};
use zeroize::Zeroize;

use crate::display::{
    bit_to_slot, clear_screen, copy_to_clipboard, count_selected, extract_selected_uuids,
    mask_bits_string, pause, print_change_domain_restriction_warning,
    print_charlists_view, print_compromise_version_list, print_compromised_version_header,
    print_derived_password_result, print_device_config, print_device_removal_summary,
    print_devices_menu_list, print_domain_change_restriction_list,
    print_domain_removal_summary, print_domain_selection_list, print_frozen_details,
    print_frozen_password_result, print_invalid_option, print_mark_domain_compromised_intro,
    print_menu_box, print_restriction_char_lists_summary, print_restriction_config_header,
    print_restriction_remove_summary, print_restriction_sequence_items,
    print_selectable_device_list, print_selection_tree, print_sequence_with_indexes,
    print_session_overview, print_static_password_plaintext, SelectionNode, SelectionNodeType,
};

use crate::input::{
    ask_argon2_params_optional, ask_char_list_elements, ask_hex_32, ask_insert_position,
    ask_known_32byte_input_or_manual, ask_known_session_path, ask_known_xor_path,
    ask_master_key, ask_master_key_from_sources, ask_optional_hex_32,
    ask_optional_string, ask_position, ask_seed_creation_flow, ask_string, ask_u128_optional,
    ask_u32_optional, ask_u32_with_min, ask_xor_key_piece, confirm, get_option, get_option_alpha,
    parse_mask_selection, SeedCreationFlow,
};

macro_rules! try_or_return {
    ($expr:expr) => {
        match $expr {
            Ok(v) => v,
            Err(e) => {
                println!("Erro: {}", e);
                pause();
                return;
            }
        }
    };
}

macro_rules! try_or_return_false {
    ($expr:expr) => {
        match $expr {
            Ok(v) => v,
            Err(e) => {
                println!("Erro: {}", e);
                pause();
                return false;
            }
        }
    };
}

macro_rules! some_or_return {
    ($expr:expr) => {
        match $expr {
            Some(v) => v,
            None => return,
        }
    };
}

macro_rules! require_master_key {
    () => {
        some_or_return!(ask_master_key())
    };
}

macro_rules! require_master_key_from {
    ($vault:expr) => {
        some_or_return!(ask_master_key_from_sources($vault))
    };
}

macro_rules! require_session_path {
    ($vault:expr, $label:expr) => {
        match ask_known_session_path($vault, $label) {
            Some(p) if !p.is_empty() => Some(p),
            _ => {
                println!("Caminho inválido.");
                pause();
                None
            }
        }
    };
}

macro_rules! require_string {
    ($prompt:expr) => {
        match ask_string($prompt) {
            Some(s) if !s.is_empty() => s,
            _ => {
                println!("Valor inválido.");
                pause();
                return;
            }
        }
    };
}

macro_rules! require_k_ext_if_needed {
    ($vault:expr) => {{
        match $vault.is_session_hardware_enabled() {
            Ok(true) => match ask_known_32byte_input_or_manual($vault, "K_ext") {
                Some(k) => Some(k),
                None => {
                    println!("K_ext necessário mas não fornecido.");
                    pause();
                    return;
                }
            },
            Ok(false) => None,
            Err(e) => {
                println!("Erro: {}", e);
                pause();
                return;
            }
        }
    }};
}

#[allow(unused_macros)]
macro_rules! menu_loop {
    ($title:expr, $width:expr, $lines:expr, $($pat:pat => $body:expr),+ $(,)?) => {
        loop {
            clear_screen();
            print_menu_box($title, $width, $lines);
            match get_option() {
                $($pat => $body),+,
                _ => print_invalid_option(),
            }
        }
    };
}

pub fn start_menu<C, G, F>(vault: &VaultCore<C, G, F>)
where C: CryptoService, G: GeneratorService, F: FileService, {
    loop {
        clear_screen();
        print_menu_box("VAULTSEED", 40, &[
            "1. Carregar ficheiro de sessão",
            "2. Iniciar nova sessão (Configuração inicial)",
            "3. Configurações Locais",
            "4. Benchmark",
            "0. Sair",
        ]);
        match get_option() {
            Some(1) => { if try_open_session(vault) { menu_principal(vault); } }
            Some(2) => { crate::tutorial::start_tutorial(vault); return; }
            Some(3) => local_state_menu(vault),
            Some(4) => benchmark_menu(vault),
            Some(0) => { return; }
            _ => print_invalid_option(),
        }
    }
}

fn benchmark_menu<C, G, F>(vault: &VaultCore<C, G, F>)
where
    C: CryptoService,
    G: GeneratorService,
    F: FileService,
{
    loop {
        clear_screen();
        print_menu_box("BENCHMARK", 34, &[
            "1. Calibração Argon2id",
            "2. Exportação de senhas",
            "3. Configurações",
            "0. Voltar",
        ]);

        match get_option() {
            Some(1) => benchmark_calibration_prompt(vault),
            Some(2) => benchmark_export_prompt(vault),
            Some(3) => benchmark_settings_prompt(vault),
            Some(0) => return,
            _ => print_invalid_option(),
        }
    }
}

fn benchmark_calibration_prompt<C, G, F>(vault: &VaultCore<C, G, F>)
where
    C: CryptoService,
    G: GeneratorService,
    F: FileService,
{
    clear_screen();
    println!("--- Benchmark de calibração Argon2id ---");
    println!();

    let local_state = vault.get_local_state();
    let min_target = local_state
        .calibration_min_target_ms
        .unwrap_or(crate::crypto::ARGON2_CALIBRATION_TARGET_MIN_MS);
    let max_target = local_state
        .calibration_max_target_ms
        .unwrap_or(crate::crypto::ARGON2_CALIBRATION_TARGET_MAX_MS);

    println!("  alvo mínimo: {} ms{}", min_target, if local_state.calibration_min_target_ms.is_none() { " (mínimo)" } else { "" });
    println!("  alvo máximo: {} ms{}", max_target, if local_state.calibration_max_target_ms.is_none() { " (máximo)" } else { "" });
    println!();

    let started_at = std::time::Instant::now();
    let calibration = crate::crypto::Calibrator::new()
        .with_min(min_target)
        .with_max(max_target)
        .run();
    let calibration_duration = started_at.elapsed();

    println!("  calibração demorou: {} ms", calibration_duration.as_millis());
    println!(
        "  resultado Argon2id: m={} KiB, t={}, p={}",
        calibration.m_cost_kib, calibration.t_cost, calibration.p_cost
    );
    println!("  tempo do Argon2id com esses parâmetros: {} ms", calibration.duration.as_millis());

    let duration_ms = calibration.duration.as_millis();
    if duration_ms < min_target {
        println!("  comparação: {} ms abaixo do alvo mínimo", min_target - duration_ms);
    } else if duration_ms > max_target {
        println!("  comparação: {} ms acima do alvo máximo", duration_ms - max_target);
    } else {
        println!("  comparação: dentro do intervalo alvo");
    }

    pause();
}

fn benchmark_export_prompt<C, G, F>(vault: &VaultCore<C, G, F>)
where
    C: CryptoService,
    G: GeneratorService,
    F: FileService,
{
    clear_screen();
    println!("--- Benchmark da exportação de senhas ---");
    println!();

    let local_state = vault.get_local_state();
    let m_cost = local_state.benchmark_argon2_m_cost_kib.unwrap_or(crate::crypto::MIN_M_COST_KIB);
    let t_cost = local_state.benchmark_argon2_t_cost.unwrap_or(crate::crypto::MIN_T_COST);
    let p_cost = local_state.benchmark_argon2_p_cost.unwrap_or(crate::crypto::MIN_P_COST);

    println!("A usar:");
    println!("  Argon2id m_cost: {} KiB{}", m_cost, if local_state.benchmark_argon2_m_cost_kib.is_none() { " (mínimo)" } else { "" });
    println!("  Argon2id t_cost: {}{}", t_cost, if local_state.benchmark_argon2_t_cost.is_none() { " (mínimo)" } else { "" });
    println!("  Argon2id p_cost: {}{}", p_cost, if local_state.benchmark_argon2_p_cost.is_none() { " (mínimo)" } else { "" });
    println!("  restantes parâmetros: valores padrão do core");
    println!();

    match vault.run_export_benchmark() {
        Ok(report) => {
            println!("  dispositivos: {}", report.device_count);
            println!("  domínios totais: {}", report.domain_count);
            println!("  senhas estáticas totais: {}", report.static_password_count);
            println!("  setup: {} ms", report.setup_duration.as_millis());
            println!("  preparação do export: {} ms", report.prepare_duration.as_millis());
            println!("  geração: {} ms", report.generation_duration.as_millis());
            println!("  derivação/desencriptação: {} ms", report.export_duration.as_millis());
            println!("  total: {} ms", report.total_duration.as_millis());
        }
        Err(e) => println!("Erro no benchmark: {}", e),
    }

    pause();
}

fn benchmark_settings_prompt<C, G, F>(vault: &VaultCore<C, G, F>)
where
    C: CryptoService,
    G: GeneratorService,
    F: FileService,
{
    loop {
        clear_screen();
        let ls = vault.get_local_state();
        let min_target = ls
            .calibration_min_target_ms
            .map(|v| format!("{} ms", v))
            .unwrap_or_else(|| format!("{} ms (mínimo)", crate::crypto::ARGON2_CALIBRATION_TARGET_MIN_MS));
        let max_target = ls
            .calibration_max_target_ms
            .map(|v| format!("{} ms", v))
            .unwrap_or_else(|| format!("{} ms (máximo)", crate::crypto::ARGON2_CALIBRATION_TARGET_MAX_MS));
        let argon2_m = ls
            .benchmark_argon2_m_cost_kib
            .map(|v| format!("{} KiB", v))
            .unwrap_or_else(|| format!("{} KiB (mínimo)", crate::crypto::MIN_M_COST_KIB));
        let argon2_t = ls
            .benchmark_argon2_t_cost
            .map(|v| v.to_string())
            .unwrap_or_else(|| format!("{} (mínimo)", crate::crypto::MIN_T_COST));
        let argon2_p = ls
            .benchmark_argon2_p_cost
            .map(|v| v.to_string())
            .unwrap_or_else(|| format!("{} (mínimo)", crate::crypto::MIN_P_COST));
        let device_count = ls.benchmark_device_count.map(|v| v.to_string()).unwrap_or_else(|| "2 (padrão)".to_string());
        let domains_per_device = ls
            .benchmark_domains_per_device
            .map(|v| v.to_string())
            .unwrap_or_else(|| "100 (padrão)".to_string());
        let static_passwords_per_device = ls
            .benchmark_static_passwords_per_device
            .map(|v| v.to_string())
            .unwrap_or_else(|| "100 (padrão)".to_string());
        let k1_len = ls.benchmark_k1_len.map(|v| v.to_string()).unwrap_or_else(|| "12 (padrão)".to_string());
        let k2_len = ls.benchmark_k2_len.map(|v| v.to_string()).unwrap_or_else(|| "12 (padrão)".to_string());

        let lines = [
            format!("Calibração: {} .. {}", min_target, max_target),
            format!("Argon2id benchmark: m={} t={} p={}", argon2_m, argon2_t, argon2_p),
            format!("Exportação: disp={} dom={} static={} k1={} k2={}", device_count, domains_per_device, static_passwords_per_device, k1_len, k2_len),
        ];
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        print_menu_box("CONFIGURAÇÕES BENCHMARK", 72, &[
            refs[0],
            refs[1],
            refs[2],
            "1. Definir calibração",
            "2. Definir parâmetros Argon2id",
            "3. Definir exportação",
            "0. Voltar",
        ]);

        match get_option() {
            Some(1) => {
                set_expected_calibration_time_prompt(vault);
                pause();
            }
            Some(2) => {
                if set_benchmark_argon2_prompt(vault) {
                    println!("Atualizado.");
                }
                pause();
            }
            Some(3) => {
                if set_benchmark_export_prompt(vault) {
                    println!("Atualizado.");
                }
                pause();
            }
            Some(0) => return,
            _ => print_invalid_option(),
        }
    }
}

fn set_benchmark_argon2_prompt<C, G, F>(vault: &VaultCore<C, G, F>) -> bool
where
    C: CryptoService,
    G: GeneratorService,
    F: FileService,
{
    clear_screen();
    println!("--- Definir parâmetros Argon2id de benchmark ---");
    println!("(vazio = usar mínimo)");
    println!();

    let m = ask_u32_optional("m_cost (KiB)").map(|value| value.max(crate::crypto::MIN_M_COST_KIB));
    let t = ask_u32_optional("t_cost").map(|value| value.max(crate::crypto::MIN_T_COST));
    let p = ask_u32_optional("p_cost").map(|value| value.max(crate::crypto::MIN_P_COST));

    if let Err(e) = vault.set_benchmark_argon2_params(m, t, p) {
        println!("Erro: {}", e);
        return false;
    }

    println!("  m_cost: {}", m.map(|v| format!("{} KiB", v)).unwrap_or_else(|| format!("mínimo ({} KiB)", crate::crypto::MIN_M_COST_KIB)));
    println!("  t_cost: {}", t.map(|v| v.to_string()).unwrap_or_else(|| format!("mínimo ({})", crate::crypto::MIN_T_COST)));
    println!("  p_cost: {}", p.map(|v| v.to_string()).unwrap_or_else(|| format!("mínimo ({})", crate::crypto::MIN_P_COST)));
    true
}

fn set_benchmark_export_prompt<C, G, F>(vault: &VaultCore<C, G, F>) -> bool
where
    C: CryptoService,
    G: GeneratorService,
    F: FileService,
{
    clear_screen();
    println!("--- Definir benchmark da exportação ---");
    println!("(vazio = manter valor padrão)");
    println!();

    let device_count = ask_u32_optional("Número de dispositivos").map(|value| value.max(1) as usize);
    let domains_per_device = ask_u32_optional("Domínios por dispositivo").map(|value| value.max(1) as usize);
    let static_passwords_per_device = ask_u32_optional("Senhas estáticas por dispositivo").map(|value| value.max(1) as usize);
    let k1_len = ask_u32_optional("Tamanho de K1").map(|value| value.max(1) as usize);
    let k2_len = ask_u32_optional("Tamanho de K2").map(|value| value.max(1) as usize);

    if let Err(e) = vault.set_benchmark_export_settings(
        device_count,
        domains_per_device,
        static_passwords_per_device,
        k1_len,
        k2_len,
    ) {
        println!("Erro: {}", e);
        return false;
    }

    println!("  dispositivos: {}", device_count.map(|v| v.to_string()).unwrap_or_else(|| "padrão (2)".to_string()));
    println!("  domínios por dispositivo: {}", domains_per_device.map(|v| v.to_string()).unwrap_or_else(|| "padrão (100)".to_string()));
    println!("  senhas estáticas por dispositivo: {}", static_passwords_per_device.map(|v| v.to_string()).unwrap_or_else(|| "padrão (100)".to_string()));
    println!("  tamanho K1: {}", k1_len.map(|v| v.to_string()).unwrap_or_else(|| "padrão (12)".to_string()));
    println!("  tamanho K2: {}", k2_len.map(|v| v.to_string()).unwrap_or_else(|| "padrão (12)".to_string()));
    true
}

fn menu_principal<C, G, F>(vault: &VaultCore<C, G, F>)
where C: CryptoService, G: GeneratorService, F: FileService, {
    loop {
        clear_screen();
        print_menu_box("MENU PRINCIPAL", 34, &[ "1. Dispositivos", "2. Sessão", "3. Pesquisar", "4. Configurações Locais", "0. Sair", ]);
        match get_option() {
            Some(1) => menu_dispositivos(vault),
            Some(2) => menu_sessao(vault),
            Some(3) => search_prompt(vault),
            Some(4) => local_state_menu(vault),
            Some(0) => {
                if confirm("Deseja guardar a sessão antes de sair?") { save_session_prompt(vault); }
                let _ = vault.close_session();
                println!("Sessão fechada. Até à próxima!");
                return;
            }
            _ => print_invalid_option(),
        }
    }
}

/// Pesquisa global de domínios e senhas estáticas.
fn search_prompt<C, G, F>(vault: &VaultCore<C, G, F>)
where C: CryptoService, G: GeneratorService, F: FileService, {
    clear_screen();
    let query = some_or_return!(ask_string("Pesquisar (domínios e senhas estáticas)"));
    if query.trim().is_empty() {
        println!("Pesquisa vazia.");
        pause();
        return;
    }

    let domain_results = vault.search_domains(&query).unwrap_or_default();
    let static_results = vault.search_static_passwords(&query).unwrap_or_default();

    if domain_results.is_empty() && static_results.is_empty() {
        println!("Sem resultados para \"{}\".", query);
        pause();
        return;
    }

    enum Hit {
        Domain { device: uuid::Uuid, restriction: uuid::Uuid, domain: uuid::Uuid },
        Static { uuid: uuid::Uuid, compromised: bool },
    }

    let mut rows: Vec<(u32, String, Hit)> = Vec::new();

    for r in &domain_results {
        rows.push((
            r.score,
            format!("[domínio] {} ({} › {})", r.identifier, r.device_name, r.restriction_name),
            Hit::Domain { device: r.device_uuid, restriction: r.restriction_uuid, domain: r.domain_uuid },
        ));
    }
    for r in &static_results {
        let folder = if r.folder_path.is_empty() { "(raiz)" } else { r.folder_path.as_str() };
        rows.push((
            r.score,
            format!("[estática] {} ({} › {}){}", r.label, r.device_name, folder, if r.compromised { " [COMP]" } else { "" }),
            Hit::Static { uuid: r.uuid, compromised: r.compromised },
        ));
    }
    rows.sort_by_key(|(score, _, _)| *score);

    println!("Resultados para \"{}\":", query);
    for (i, (_, label, _)) in rows.iter().enumerate() {
        println!("  {}. {}", i + 1, label);
    }
    println!("  0. Cancelar");

    let i = match get_option() {
        Some(0) => return,
        Some(n) if n >= 1 && (n as usize) <= rows.len() => (n - 1) as usize,
        _ => { print_invalid_option(); return; }
    };

    match &rows[i].2 {
        Hit::Domain { device, restriction, domain } => {
            let _ = vault.select_device(*device);
            let _ = vault.select_restriction(*restriction);
            match vault.select_domain(*domain) {
                Ok(()) => menu_dominio_selecionado(vault, *device, *restriction, *domain),
                Err(e) => { println!("Erro: {}", e); pause(); }
            }
        }
        Hit::Static { uuid, compromised } => menu_senha_estatica(vault, *uuid, *compromised),
    }
}

fn try_open_session<C, G, F>(vault: &VaultCore<C, G, F>) -> bool
where C: CryptoService, G: GeneratorService, F: FileService, {
    let path = match require_session_path!(vault, "carregar a sessão") {
        Some(path) => path,
        None => return false,
    };
    let session_file = try_or_return_false!(vault.files.load_session_file(&path));

    if session_file.session_hmac.is_none() {
        println!("AVISO: Este ficheiro não contém HMAC.");
        if !confirm("Continuar sem verificação?") { return false; }
    } else {
        println!("HMAC encontrado: será verificado.");
    }

    let k_ext = if session_file.header.hardware_enabled {
        println!("Esta sessão requer fator físico (K_ext).");
        match ask_known_32byte_input_or_manual(vault, "K_ext") {
            Some(k) => Some(k),
            None => { 
                println!("K_ext inválido."); 
                pause(); 
                return false; 
            }
        }
    } else { None };

    let master_key = match ask_master_key_from_sources(vault) {
        Some(mk) => mk,
        None => { pause(); return false; }
    };

    let backup = session_file.clone();
    let result = match vault.open_session(session_file, &master_key, k_ext.as_ref(), true) {
        Ok(()) => Ok(()),
        Err(e) if matches!(e, CoreError::Session(SessionError::SessionFileTampered)) => {
            println!("AVISO: HMAC não corresponde.");
            if confirm("Tentar abrir mesmo assim?") {vault.open_session(backup, &master_key, k_ext.as_ref(), false) } 
            else { Err(e) }
        }
        Err(e) => Err(e),
    };

    match result {
        Ok(()) => { 
            let _ = vault.set_last_session_path(Some(path)); 
            println!("Sessão aberta!"); 
            pause(); 
            true 
        }
        Err(e) => { 
            println!("Erro: {}", e); 
            pause(); 
            false 
        }
    }
}

fn menu_sessao<C, G, F>(vault: &VaultCore<C, G, F>)
where C: CryptoService, G: GeneratorService, F: FileService, {
    loop {
        clear_screen();
        print_menu_box("SESSÃO", 34, &[
            "1. Ver parâmetros", "2. Mudar parâmetros", "3. Ativar fator físico",
            "4. Desativar fator físico", "5. Criar ficheiros XOR", "6. Guardar sessão",
            "7. Carregar outra sessão", "8. Rotacionar K1/K2", "9. Exportar senhas",
            "0. Voltar",
        ]);
        match get_option() {
            Some(1) => view_session_params(vault),
            Some(2) => edit_session_params(vault),
            Some(3) => activate_hardware_factor(vault),
            Some(4) => deactivate_hardware_factor(vault),
            Some(5) => create_xor_prompt(vault),
            Some(6) => save_session_prompt(vault),
            Some(7) => {
                if confirm("Substituir sessão atual? Guardar antes?") { save_session_prompt(vault); }
                if confirm("Continuar?") {
                    let _ = vault.close_session();
                    if try_open_session(vault) { 
                        println!("Nova sessão carregada."); 
                        pause(); 
                        return; 
                    }
                }
            }
            Some(8) => rotate_master_key_prompt(vault),
            Some(9) => menu_exportar_senhas(vault),
            Some(0) => return,
            _ => print_invalid_option(),
        }
    }
}

fn view_session_params<C, G, F>(vault: &VaultCore<C, G, F>)
where C: CryptoService, G: GeneratorService, F: FileService, {
    clear_screen();
    let o = try_or_return!(vault.get_session_overview());
    let h = &o.header;
    print_session_overview(
        h.schema_version, &h.salt_session, h.argon2.m_cost_kib, h.argon2.t_cost,
        h.argon2.p_cost, h.hardware_enabled, h.salt_hkdf.as_ref(), &o.nonce_global,
        o.ciphertext_global_len, o.device_count, o.restriction_count,
        o.domain_count, o.static_password_count,
    );
    pause();
}

fn edit_session_params<C, G, F>(vault: &VaultCore<C, G, F>)
where C: CryptoService, G: GeneratorService, F: FileService, {
    loop {
        clear_screen();
        let header = try_or_return!(vault.get_session_header());
        let (cm, ct, cp) = (header.argon2.m_cost_kib, header.argon2.t_cost, header.argon2.p_cost);

        let lines = [
            format!("Atuais: m={} KiB t={} p={}", cm, ct, cp),
            "1. Calibração por tempo alvo".to_string(),
            "2. Definir manualmente".to_string(),
            "3. Regenerar salt da sessão".to_string(),
            "0. Voltar".to_string(),
        ];
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        print_menu_box("MUDAR PARÂMETROS ARGON2ID", 34, &refs);

        match get_option() {
            Some(1) => {
                let secs = some_or_return!(ask_u32_with_min("Tempo alvo (segundos)", 1));
                let (min_ms, max_ms) = (u128::from(secs) * 1000, u128::from(secs) * 1000 + 1000);
                println!("A calibrar...");
                let cal = crate::crypto::Calibrator::new().with_min(min_ms).with_max(max_ms).run();
                println!("Resultado: m={} t={} p={} ({}ms)", cal.m_cost_kib, cal.t_cost, cal.p_cost, cal.duration.as_millis());
                if confirm("Aplicar?") {
                    let r = vault.update_session_argon2_params(Argon2Params { m_cost_kib: cal.m_cost_kib, t_cost: cal.t_cost, p_cost: cal.p_cost });
                    match r { Ok(()) => println!("Atualizado. Guarde a sessão."), Err(e) => println!("Erro: {}", e) }
                }
                pause();
            }
            Some(2) => {
                if let (Some(m), Some(t), Some(p)) = (ask_u32_with_min("m_cost (KiB)", 65536), ask_u32_with_min("t_cost", 3), ask_u32_with_min("p_cost", 4)) {
                    println!("A testar...");
                    let d = crate::crypto::benchmark_argon2(m, t, p);
                    println!("Duração: {}ms", d.as_millis());
                    if confirm("Aplicar?") {
                        match vault.update_session_argon2_params(Argon2Params { m_cost_kib: m, t_cost: t, p_cost: p }) {
                            Ok(()) => println!("Atualizado. Guarde a sessão."),
                            Err(e) => println!("Erro: {}", e),
                        }
                    }
                }
                pause();
            }
            Some(3) => {
                if confirm("Regenerar salt? Invalida backups.") {
                    match vault.regenerate_session_salt() {
                        Ok(s) => println!("Salt: {}. Guarde a sessão.", hex::encode(s)),
                        Err(e) => println!("Erro: {}", e),
                    }
                }
                pause();
            }
            Some(0) => return,
            _ => print_invalid_option(),
        }
    }
}

fn save_session_prompt<C, G, F>(vault: &VaultCore<C, G, F>)
where C: CryptoService, G: GeneratorService, F: FileService, {
    clear_screen();
    let path = some_or_return!(require_session_path!(vault, "guardar"));
    let mk = require_master_key_from!(vault);
    let k_ext = require_k_ext_if_needed!(vault);
    let hmac = confirm("Criar HMAC? (recomendado)");
    if !hmac && !confirm("Guardar sem HMAC?") { return; }
    match vault.save_session(&path, &mk, k_ext.as_ref(), hmac) {
        Ok(()) => println!("Guardada em: {}", path),
        Err(e) => println!("Erro: {}", e),
    }
    pause();
}

fn rotate_master_key_prompt<C, G, F>(vault: &VaultCore<C, G, F>)
where C: CryptoService, G: GeneratorService, F: FileService, {
    clear_screen();
    println!("ROTACIONAR K1/K2 - reencripta seeds, senhas NÃO mudam.");
    println!("ATENÇÃO: K1/K2 antigos deixam de funcionar!\n");
    if !confirm("Continuar?") { return; }

    let path = some_or_return!(require_session_path!(vault, "guardar"));
    println!("--- K1/K2 atuais ---");
    let old = require_master_key_from!(vault);
    println!("--- Novos K1/K2 ---");
    let new_key = require_master_key_from!(vault);
    println!("--- Confirmar novos ---");
    let confirm_key = require_master_key_from!(vault);

    if new_key.normalize_and_concat() != confirm_key.normalize_and_concat() {
        println!("Não correspondem. Cancelado."); pause(); return;
    }

    let k_ext = require_k_ext_if_needed!(vault);
    match vault.rotate_master_key(&old, &new_key, &path, k_ext.as_ref()) {
        Ok(()) => println!("Rotacionados! Guardada em: {}", path),
        Err(e) => println!("Erro: {}", e),
    }
    pause();
}

fn activate_hardware_factor<C, G, F>(vault: &VaultCore<C, G, F>)
where C: CryptoService, G: GeneratorService, F: FileService, {
    clear_screen();
    match vault.is_session_hardware_enabled() {
        Ok(true) => { 
            println!("Já está ATIVO."); 
            pause(); 
            return; 
        }
        Ok(false) => {}
        Err(e) => { 
            println!("Erro: {}", e);
            pause(); 
            return; 
        }
    }

    println!("ATIVAR FATOR FÍSICO - ficheiro 32 bytes necessário no futuro.");
    println!("ATENÇÃO: Se perder o K_ext, a sessão fica inacessível!\n");
    if !confirm("Continuar?") { return; }

    let path = some_or_return!(require_session_path!(vault, "guardar"));
    println!("Fonte K_ext:");
    println!("  1. Ficheiro existente  2. Hex  3. Criar novo  0. Cancelar");

    let k_ext = match get_option() {
        Some(1) => {
            let p = require_string!("Caminho K_ext");
            let bytes = try_or_return!(std::fs::read(&p).map_err(|e| e.to_string()));
            if bytes.len() != 32 { 
                println!("Não tem 32 bytes."); 
                pause();
                return; 
            }
            let mut arr = [0u8; 32]; arr.copy_from_slice(&bytes); arr
        }
        Some(2) => some_or_return!(ask_hex_32("K_ext (hex)")),
        Some(3) => {
            let p = require_string!("Caminho novo K_ext");
            let k = crate::crypto::generate_salt();
            try_or_return!(std::fs::write(&p, k).map_err(|e| e.to_string()));
            println!("Criado: {}", p); k
        }
        _ => return,
    };

    let salt = crate::crypto::generate_salt();
    let mk = require_master_key_from!(vault);
    match vault.rotate_kext(&mk, Some(&k_ext), Some(salt), &path) {
        Ok(()) => { println!("ATIVADO. Salt HKDF: {}\nGuardada: {}", hex::encode(salt), path); }
        Err(e) => println!("Erro: {}", e),
    }
    pause();
}

fn deactivate_hardware_factor<C, G, F>(vault: &VaultCore<C, G, F>)
where C: CryptoService, G: GeneratorService, F: FileService, {
    clear_screen();
    match vault.is_session_hardware_enabled() {
        Ok(false) => { println!("Já está INATIVO."); pause(); return; }
        Ok(true) => {}
        Err(e) => { println!("Erro: {}", e); pause(); return; }
    }
    println!("DESATIVAR FATOR FÍSICO - protecção apenas por K1/K2.\n");
    if !confirm("Continuar?") { return; }
    let path = some_or_return!(require_session_path!(vault, "guardar"));
    let mk = require_master_key_from!(vault);
    match vault.rotate_kext(&mk, None, None, &path) {
        Ok(()) => println!("DESATIVADO. Guardada: {}", path),
        Err(e) => println!("Erro: {}", e),
    }
    pause();
}

fn create_xor_prompt<C, G, F>(vault: &VaultCore<C, G, F>)
where C: CryptoService, G: GeneratorService, F: FileService, {
    clear_screen();
    println!("CRIAR FICHEIROS XOR - armazenar K1/K2 separados.\n");

    let pa = some_or_return!(ask_known_xor_path(vault, "Share A"));
    let pb = some_or_return!(ask_known_xor_path(vault, "Share B"));
    if pa == pb { println!("Caminhos iguais!"); pause(); return; }

    let k1 = some_or_return!(ask_xor_key_piece(vault, "K1"));
    let k2 = some_or_return!(ask_xor_key_piece(vault, "K2"));
    if k1.is_empty() && k2.is_empty() { println!("Pelo menos uma chave."); pause(); return; }

    match vault.create_xor_files(&k1, &k2, &pa, &pb) {
        Ok(()) => {
            println!("Criados: {} / {}", pa, pb);
            if confirm("Verificar agora?") {
                match vault.recover_keys_from_xor(&pa, &pb) {
                    Ok(r) if r.k1 == k1 && r.k2 == k2 => println!("OK ✓"),
                    Ok(_) => println!("AVISO: Não correspondem!"),
                    Err(e) => println!("Erro: {}", e),
                }
            }
        }
        Err(e) => println!("Erro: {}", e),
    }
    pause();
}

fn set_expected_calibration_time_prompt<C, G, F>(vault: &VaultCore<C, G, F>)
where C: CryptoService, G: GeneratorService, F: FileService, {
    let min = some_or_return!(ask_u128_optional("Mínimo (ms)"));
    let max = some_or_return!(ask_u128_optional("Máximo (ms)"));
    if min >= max { println!("Mín >= Máx."); return; }
    if max - min < 200 { println!("Diferença < 200ms."); return; }
    match vault.set_calibration_targets(Some(min), Some(max)) {
        Ok(()) => println!("Atualizado."), Err(e) => println!("Erro: {}", e),
    }
}

fn local_state_menu<C, G, F>(vault: &VaultCore<C, G, F>)
where C: CryptoService, G: GeneratorService, F: FileService, {
    loop {
        clear_screen();
        let ls = vault.get_local_state();
        let min = ls.calibration_min_target_ms.map(|v| format!("Mín: {} ms", v)).unwrap_or("Mín: -".into());
        let max = ls.calibration_max_target_ms.map(|v| format!("Máx: {} ms", v)).unwrap_or("Máx: -".into());
        let lines = [min, max];
        print_menu_box("Configurações Locais", 34, &[
            lines[0].as_str(), lines[1].as_str(),
            "1. Definir calibração", "2. Limpar calibração", "3. Configurações de benchmark", "4. Apagar local", "0. Voltar",
        ]);
        match get_option() {
            Some(1) => { set_expected_calibration_time_prompt(vault); pause(); }
            Some(2) => {
                 match vault.set_calibration_targets(None, None) 
                 { 
                    Ok(()) => println!("Limpo."), 
                    Err(e) => println!("{}", e) 
                }
                pause(); 
            }
            Some(3) => { benchmark_settings_prompt(vault); }
            Some(4) => {
                if confirm("Apagar ficheiro local?") {
                    match vault.delete_local_state() { 
                        Ok(()) => println!("Apagado."), 
                        Err(e) => println!("{}", e) 
                    }
                }
                pause();
            }
            Some(0) => return,
            _ => print_invalid_option(),
        }
    }
}

fn menu_dispositivos<C, G, F>(vault: &VaultCore<C, G, F>)
where
    C: CryptoService, G: GeneratorService, F: FileService,
{
    loop {
        clear_screen();
        println!("╔══════════════════════════════════╗");
        println!("║         DISPOSITIVOS             ║");
        println!("╠══════════════════════════════════╣");
        match vault.list_devices() { 
            Ok(d) => print_devices_menu_list(&d), 
            Err(e) => println!("║ Erro: {} ║", e) 
        }
        println!("╠══════════════════════════════════╣");
        println!("║ A. Adicionar  S. Selecionar      ║");
        println!("║ 0. Voltar                        ║");
        println!("╚══════════════════════════════════╝");
        match get_option_alpha() {
            Some('a') | Some('A') => add_device_prompt(vault),
            Some('s') | Some('S') => select_device_prompt(vault),
            Some('0') => return,
            _ => print_invalid_option(),
        }
    }
}

fn select_device_prompt<C, G, F>(vault: &VaultCore<C, G, F>)
where
    C: CryptoService, G: GeneratorService, F: FileService,
{
    clear_screen();
    let devices = try_or_return!(vault.list_devices());
    if devices.is_empty() { 
        println!("Nenhum dispositivo."); 
        pause();
        return; 
    }
    print_selectable_device_list(&devices);
    let i = match get_option() { 
        Some(0) => return, 
        Some(n) if n >= 1 && (n as usize) <= devices.len() => (n-1) as usize, 
        _ => { 
            print_invalid_option();
            return; 
        } 
    };
    match vault.select_device(devices[i].uuid) {
        Ok(()) => menu_dispositivo_selecionado(vault, devices[i].uuid),
        Err(e) => { println!("Erro: {}", e); pause(); }
    }
}

fn add_device_prompt<C, G, F>(vault: &VaultCore<C, G, F>)
where C: CryptoService, G: GeneratorService, F: FileService, {
    clear_screen();
    let name = require_string!("Nome do dispositivo");
    let def_a = vault.get_session_header().map(|h| h.argon2).unwrap_or(Argon2Params { m_cost_kib: 65536, t_cost: 3, p_cost: 4 });
    let argon2 = ask_argon2_params_optional(&def_a).unwrap_or(def_a);
    let salt = ask_optional_hex_32("Salt (vazio=novo)").unwrap_or_else(|| vault.crypto.generate_random_32().unwrap());
    let dev_uuid = uuid::Uuid::new_v4();
    let seed_flow = ask_seed_creation_flow();
    let mk = require_master_key_from!(vault);

    let envelope = match seed_flow {
        SeedCreationFlow::Random => {
            let s = vault.crypto.generate_random_32().unwrap();
            try_or_return!(vault.encrypt_device_seed_envelope(dev_uuid, &salt, &argon2, &mk, &s))
        }
        SeedCreationFlow::Plaintext(s) => try_or_return!(vault.encrypt_device_seed_envelope(dev_uuid, &salt, &argon2, &mk, &s)),
        SeedCreationFlow::Encrypted(env) => {
            match vault.decrypt_device_seed_envelope(dev_uuid, &salt, &argon2, &mk, &env) {
                Ok(_) => env,
                Err(_) => {
                    println!("Inválida - seed aleatória.");
                    let s = vault.crypto.generate_random_32().unwrap();
                    try_or_return!(vault.encrypt_device_seed_envelope(dev_uuid, &salt, &argon2, &mk, &s))
                }
            }
        }
    };

    match vault.add_device_with_details(&name, dev_uuid, salt, argon2, envelope) {
        Ok(uuid) => { 
            println!("Dispositivo: {}", uuid); 
            pause(); 
            menu_dispositivo_selecionado(vault, uuid); 
        }
        Err(e) => { println!("Erro: {}", e); pause(); }
    }
}

fn menu_dispositivo_selecionado<C, G, F>(vault: &VaultCore<C, G, F>, dev: uuid::Uuid)
where
    C: CryptoService, G: GeneratorService, F: FileService,
{
    loop {
        clear_screen();
        let device = try_or_return!(vault.get_device(dev));
        let lines = [format!("{} ({})", device.name, device.uuid),
            "1. Restrições".into(), "2. Senhas estáticas".into(), "3. Ver config".into(),
            "4. Editar config".into(), "5. Remover".into(), "0. Voltar".into()];
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        print_menu_box("DISPOSITIVO", 34, &refs);
        match get_option() {
            Some(1) => menu_restricoes(vault, dev),
            Some(2) => menu_senhas_estaticas(vault, dev),
            Some(3) => { clear_screen(); print_device_config(&device); pause(); }
            Some(4) => edit_device_config_prompt(vault, dev),
            Some(5) => { if remove_device_prompt(vault, dev) { return; } }
            Some(0) => return,
            _ => print_invalid_option(),
        }
    }
}

fn edit_device_config_prompt<C, G, F>(vault: &VaultCore<C, G, F>, dev: uuid::Uuid)
where
    C: CryptoService, G: GeneratorService, F: FileService,
{
    loop {
        clear_screen();
        let device = try_or_return!(vault.get_device(dev));
        print_menu_box(&format!("EDITAR: {}", device.name), 34, &[
            "1. Renomear", "2. Alterar Argon2+salt", "3. Alterar nonce seed", "0. Voltar",
        ]);
        match get_option() {
            Some(1) => {
                let n = require_string!("Novo nome");
                match vault.rename_device(dev, &n) { 
                    Ok(()) => println!("Renomeado."), 
                    Err(e) => println!("Erro: {}", e) 
                }
                pause();
            }
            Some(2) => {
                let a = ask_argon2_params_optional(&device.argon2).unwrap_or(device.argon2.clone());
                let mk = require_master_key_from!(vault);
                match vault.update_device_argon2_and_regenerate_salt(dev, &mk, a) {
                    Ok(_) => println!("Atualizado."), 
                    Err(e) => println!("Erro: {}", e),
                }
                pause();
            }
            Some(3) => {
                let mk = require_master_key_from!(vault);
                match vault.update_device_seed_nonce(dev, &mk) {
                    Ok(_) => println!("Nonce atualizado."),
                    Err(e) => println!("Erro: {}", e),
                }
                pause();
            }
            Some(0) => return,
            _ => print_invalid_option(),
        }
    }
}

fn remove_device_prompt<C, G, F>(vault: &VaultCore<C, G, F>, dev: uuid::Uuid) -> bool
where
    C: CryptoService, G: GeneratorService, F: FileService,
{
    let device = try_or_return_false!(vault.get_device(dev));
    print_device_removal_summary(&device.name, device.uuid);
    let restrictions = vault.list_restrictions(dev).unwrap_or_default();
    if !restrictions.is_empty() {
        println!("AVISO: {} restrição(ões). Remova-as primeiro.", restrictions.len());
        pause(); return false;
    }
    if !confirm("Remover este dispositivo?") || !confirm("IRREVERSÍVEL. Confirmar?") { return false; }
    match vault.remove_device(dev) {
        Ok(()) => { println!("Removido."); pause(); true }
        Err(e) => { println!("Erro: {}", e); pause(); false }
    }
}

fn menu_restricoes<C, G, F>(vault: &VaultCore<C, G, F>, dev: uuid::Uuid)
where
    C: CryptoService, G: GeneratorService, F: FileService,
{
    loop {
        clear_screen();
        let rs = vault.list_restrictions(dev).unwrap_or_default();
        let mut lines: Vec<String> = if rs.is_empty() { vec!["(nenhuma)".into()] } else {
            rs.iter().enumerate().map(|(i,r)| format!("{}. {} (m:{} p:{})", 
            i+1, r.name, r.generation.effective_default_mask(), 
            r.generation.sequence().map(|s|s.len()).unwrap_or(0))).collect()
        };
        lines.extend(["A. Adicionar".into(), "S. Selecionar".into(), "0. Voltar".into()]);
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        print_menu_box("RESTRIÇÕES", 34, &refs);
        match get_option_alpha() {
            Some('a')|Some('A') => add_restriction_prompt(vault, dev),
            Some('s')|Some('S') => select_restriction_prompt(vault, dev),
            Some('0') => return,
            _ => print_invalid_option(),
        }
    }
}

fn add_restriction_prompt<C, G, F>(vault: &VaultCore<C, G, F>, dev: uuid::Uuid)
where
    C: CryptoService, G: GeneratorService, F: FileService,
{
    let name = some_or_return!(ask_string("Nome da restrição"));
    match vault.add_restriction(&name, dev, crate::models::GenerationParams::default()) {
        Ok(u) => println!("Adicionada: {}", u), Err(e) => println!("Erro: {}", e),
    }
    pause();
}

fn select_restriction_prompt<C, G, F>(vault: &VaultCore<C, G, F>, dev: uuid::Uuid)
where
    C: CryptoService, G: GeneratorService, F: FileService,
{
    let rs = vault.list_restrictions(dev).unwrap_or_default();
    if rs.is_empty() { println!("Nenhuma."); pause(); return; }
    for (i,r) in rs.iter().enumerate() { 
        println!("  {}. {} ({})", i+1, r.name, r.uuid); 
    }
    println!("  0. Cancelar");
    let i = match get_option() { 
        Some(0) => return, 
        Some(n) if n>=1 && (n as usize)<=rs.len() => (n-1) as usize, 
        _ => { print_invalid_option(); return; } 
    };
    match vault.select_restriction(rs[i].uuid) {
        Ok(()) => menu_restricao_selecionada(vault, dev, rs[i].uuid),
        Err(e) => { println!("Erro: {}", e); pause(); }
    }
}

fn menu_restricao_selecionada<C, G, F>(vault: &VaultCore<C, G, F>, dev: uuid::Uuid, rid: uuid::Uuid)
where C: CryptoService, G: GeneratorService, F: FileService, {
    loop {
        clear_screen();
        let r = try_or_return!(vault.get_restriction(rid));
        let doms = vault.list_domains(rid).unwrap_or_default();
        let cl_count = vault.list_char_lists(rid).map(|l|l.len()).unwrap_or(0);
        let lines: Vec<String> = vec![
            format!("{} | fmt:{} | m:{} | pos:{} | bytes:{} | dom:{} | listas:{}",
                r.name, r.generation.format_visual(), r.generation.effective_default_mask(),
                r.generation.random_position_count(), r.generation.effective_bytes_to_derive(),
                doms.len(), cl_count),
            "1. +Domínio  2. Selec. domínio".into(), "3. Ver config  4. Editar config".into(),
            "5. +Lista  6. -Lista  7. Ver listas".into(), "8. Editar elementos  9. Remover".into(), "0. Voltar".into(),
        ];
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        print_menu_box("RESTRIÇÃO", 50, &refs);
        match get_option() {
            Some(1) => add_domain_prompt(vault, rid),
            Some(2) => select_domain_prompt(vault, dev, rid),
            Some(3) => view_restriction_config(vault, rid),
            Some(4) => edit_restriction_prompt(vault, rid),
            Some(5) => add_charlist_prompt(vault, rid),
            Some(6) => remove_charlist_prompt(vault, rid),
            Some(7) => { 
                clear_screen(); 
                let r2 = try_or_return!(vault.get_restriction(rid)); 
                let cl = try_or_return!(vault.list_char_lists(rid)); 
                print_charlists_view(Some(&r2), &cl); pause(); 
            }
            Some(8) => edit_charlist_elements_prompt(vault, rid),
            Some(9) => { if remove_restriction_prompt(vault, rid) { return; } }
            Some(0) => return,
            _ => print_invalid_option(),
        }
    }
}

fn view_restriction_config<C, G, F>(vault: &VaultCore<C, G, F>, rid: uuid::Uuid)
where C: CryptoService, G: GeneratorService, F: FileService, {
    clear_screen();
    let r = try_or_return!(vault.get_restriction(rid));
    let seq_lines: Vec<String> = r.generation.sequence().unwrap_or(&[]).iter().enumerate().map(|(i,item)| match item {
        MaskOrLiteral::Mask(m) => format!("    {:>3}. máscara {} ({})", i+1, m, mask_bits_string(*m)),
        MaskOrLiteral::Literal(t) => format!("    {:>3}. literal '{}'", i+1, t),
    }).collect();
    print_restriction_config_header(&r.name, r.uuid, r.device_uuid, r.generation.effective_default_mask(), r.generation.effective_bytes_to_derive(), &r.generation.format_visual());
    print_restriction_sequence_items(&seq_lines);
    println!();
    print_restriction_char_lists_summary(&r.char_lists);
    pause();
}

fn edit_restriction_prompt<C, G, F>(vault: &VaultCore<C, G, F>, rid: uuid::Uuid)
where
    C: CryptoService, G: GeneratorService, F: FileService,
{
    loop {
        clear_screen();
        let r = try_or_return!(vault.get_restriction(rid));
        print_menu_box(&format!("EDITAR: {}", r.name), 34, &["1. Renomear", "2. Editar formato", "3. Estender entropia", "0. Voltar"]);
        match get_option() {
            Some(1) => { 
                let n = require_string!("Novo nome"); 
                match vault.rename_restriction(rid, &n) { 
                    Ok(())=>println!("Renomeada."), 
                    Err(e)=>println!("Erro: {}",e) 
                } 
                pause(); 
            }
            Some(2) => edit_restriction_format_menu(vault, rid),
            Some(3) => { 
                let b = some_or_return!(ask_u32_with_min("Bits alvo", 1));
                match vault.extend_restriction_format_to_entropy(rid, b) { 
                    Ok(n)=>println!("+{} posições.",n), 
                    Err(e)=>println!("Erro: {}",e) 
                } 
                pause(); 
            }
            Some(0) => return,
            _ => print_invalid_option(),
        }
    }
}

fn edit_restriction_format_menu<C, G, F>(vault: &VaultCore<C, G, F>, rid: uuid::Uuid)
where C: CryptoService, G: GeneratorService, F: FileService, {
    loop {
        clear_screen();
        let cl = vault.list_char_lists(rid).unwrap_or_default();
        print_restriction_char_lists_summary(&cl);
        print_menu_box("EDITAR FORMATO", 34, &["1. Ver  2. Trocar  3. +Aleatória", "4. +Literal  5. Remover  0. Voltar"]);
        match get_option() {
            Some(1) => { 
                let r = try_or_return!(vault.get_restriction(rid)); 
                match r.generation.sequence() { 
                    Some(s) => print_sequence_with_indexes(s),
                    None => println!("Sem sequência.") 
                } 
                pause(); 
            }
            Some(2) => swap_format_positions(vault, rid),
            Some(3) => {
                crate::display::print_mask_help();
                let s = some_or_return!(ask_string("Máscara"));
                let mask = match parse_mask_selection(&s) { 
                    Ok(m)=>m, 
                    Err(e) => { 
                        println!("{}",e); 
                        pause(); 
                        continue; 
                    } 
                };
                let len = vault.get_restriction(rid).ok().and_then(|r| r.generation.sequence().map(|s|s.len())).unwrap_or(0);
                let pos = ask_insert_position(len);
                match vault.insert_restriction_mask_position(rid, mask, pos) { 
                    Ok(())=>println!("Adicionada."), 
                    Err(e)=>println!("Erro: {}",e) 
                } 
                pause();
            }
            Some(4) => {
                let lit = some_or_return!(ask_string("Literal"));
                let len = vault.get_restriction(rid).ok().and_then(|r| r.generation.sequence().map(|s|s.len())).unwrap_or(0);
                let pos = ask_insert_position(len);
                match vault.insert_restriction_literal_position(rid, lit, pos) { 
                    Ok(())=>println!("Adicionado."), 
                    Err(e)=>println!("Erro: {}",e) 
                } 
                pause();
            }
            Some(5) => remove_format_position(vault, rid),
            Some(0) => return,
            _ => print_invalid_option(),
        }
    }
}

fn swap_format_positions<C, G, F>(vault: &VaultCore<C, G, F>, rid: uuid::Uuid)
where C: CryptoService, G: GeneratorService, F: FileService, {
    let r = try_or_return!(vault.get_restriction(rid));
    let mut seq = match r.generation.sequence() { 
        Some(s) => s.to_vec(), 
        None => { 
            println!("Sem sequência."); 
            pause(); 
            return; 
        } 
    };
    if seq.len() < 2 { 
        println!("< 2 posições."); 
        pause();
        return; 
    }
    print_sequence_with_indexes(&seq);
    let a = some_or_return!(ask_position(seq.len(), "Pos A"));
    let b = some_or_return!(ask_position(seq.len(), "Pos B"));
    seq.swap(a, b);
    let mut p = r.generation.clone(); p.format_sequence = Some(seq);
    match vault.update_restriction_generation(rid, p) { 
        Ok(())=>println!("Trocadas."), 
        Err(e)=>println!("Erro: {}",e) 
    } 
    pause();
}

fn remove_format_position<C, G, F>(vault: &VaultCore<C, G, F>, rid: uuid::Uuid)
where C: CryptoService, G: GeneratorService, F: FileService, {
    let r = try_or_return!(vault.get_restriction(rid));
    let mut seq = match r.generation.sequence() { 
        Some(s) => s.to_vec(), 
        None => { 
            println!("Sem sequência."); 
            pause(); 
            return; 
        } 
    };
    if seq.is_empty() { 
        println!("Vazia."); 
        pause();
        return; 
    }
    print_sequence_with_indexes(&seq);
    let i = some_or_return!(ask_position(seq.len(), "Posição"));
    seq.remove(i);
    let mut p = r.generation.clone(); p.format_sequence = Some(seq);
    match vault.update_restriction_generation(rid, p) {
        Ok(())=>println!("Removida."), 
        Err(e)=>println!("Erro: {}",e) 
    } 
    pause();
}

fn add_charlist_prompt<C, G, F>(vault: &VaultCore<C, G, F>, rid: uuid::Uuid)
where C: CryptoService, G: GeneratorService, F: FileService, {
    let name = require_string!("Nome da lista");
    let bit: u8 = match ask_string("Bit") { 
        Some(s) => match s.parse() { 
            Ok(b)=>b, 
            Err(_) => { 
                println!("Inválido."); 
                pause();
                return; 
            } 
        }, 
        None => return 
    };
    let elems = some_or_return!(ask_char_list_elements());
    match vault.add_char_list_to_restriction(rid, &name, bit, elems) {
        Ok(u) => println!("Lista: {}", u), 
        Err(e) => println!("Erro: {}", e),
    }
    pause();
}

fn remove_charlist_prompt<C, G, F>(vault: &VaultCore<C, G, F>, rid: uuid::Uuid)
where C: CryptoService, G: GeneratorService, F: FileService, { 
    let lists = try_or_return!(vault.list_char_lists(rid));
    if lists.is_empty() { 
        println!("Nenhuma."); 
        pause(); 
        return; 
    }
    print_restriction_char_lists_summary(&lists);
    println!("  0. Cancelar");
    let i = match get_option() { 
        Some(0) => return, 
        Some(n) if n>=1 && (n as usize)<=lists.len() => (n-1) as usize, 
        _ => {
            print_invalid_option(); 
            return; 
        } 
    };
    if !confirm(&format!("Remover '{}'?", lists[i].name)) { return; }
    match vault.remove_char_list_from_restriction(rid, lists[i].uuid) { 
        Ok(())=>println!("Removida."), 
        Err(e)=>println!("Erro: {}",e) 
    }
    pause();
}

fn edit_charlist_elements_prompt<C, G, F>(vault: &VaultCore<C, G, F>, rid: uuid::Uuid)
where C: CryptoService, G: GeneratorService, F: FileService, {
    let cls = try_or_return!(vault.list_char_lists(rid));
    let editable: Vec<_> = cls.iter().filter(|c| c.bit >= crate::core::USER_CHAR_LIST_BIT_MIN).collect();
    if editable.is_empty() { 
        println!("Nenhuma editável.");
        pause(); 
        return; 
    }
    for (i,c) in editable.iter().enumerate() { 
        println!("  {}. {}/{}: {} ({})", i+1, bit_to_slot(c.bit), crate::core::USER_CHAR_LIST_SLOT_COUNT, c.name, c.elements.len()); 
    }
    println!("  0. Cancelar");
    let i = match get_option() { 
        Some(0) => return, 
        Some(n) if n>=1 && (n as usize)<=editable.len() => (n-1) as usize,
        _ => { print_invalid_option(); return; } 
    };
    println!("Atual ({}): {}", editable[i].elements.len(), editable[i].elements.join(", "));
    let elems = some_or_return!(ask_char_list_elements());
    if !confirm("Aplicar?") { return; }
    match vault.update_char_list_elements(rid, editable[i].uuid, elems) { 
        Ok(())=>println!("Atualizada."), 
        Err(e)=>println!("Erro: {}",e) 
    }
    pause();
}

fn remove_restriction_prompt<C, G, F>(vault: &VaultCore<C, G, F>, rid: uuid::Uuid) -> bool
where C: CryptoService, G: GeneratorService, F: FileService, {
    let r = try_or_return_false!(vault.get_restriction(rid));
    print_restriction_remove_summary(&r.name, r.uuid);
    if !confirm("Remover?") || !confirm("IRREVERSÍVEL. Confirmar?") { return false; }
    match vault.remove_restriction(rid) { 
        Ok(())=>{ 
            println!("Removida."); 
            pause(); 
            true 
        } 
        Err(e)=>{ 
            println!("Erro: {}",e); 
            pause(); 
            false 
        } 
    }
}

fn add_domain_prompt<C, G, F>(vault: &VaultCore<C, G, F>, rid: uuid::Uuid)
where C: CryptoService, G: GeneratorService, F: FileService, {
    let id = require_string!("Identificador (ex: github.com)");
    match vault.add_domain(&id, rid) { 
        Ok(u)=>println!("Domínio: {}",u), 
        Err(e)=>println!("Erro: {}",e) 
    }
    pause();
}

fn select_domain_prompt<C, G, F>(vault: &VaultCore<C, G, F>, dev: uuid::Uuid, rid: uuid::Uuid)
where C: CryptoService, G: GeneratorService, F: FileService, {
    let doms = vault.list_domains(rid).unwrap_or_default();
    if doms.is_empty() { println!("Nenhum."); pause(); return; }
    print_domain_selection_list(&doms);
    let i = match get_option() { 
        Some(0)=>return, 
        Some(n) if n>=1 && (n as usize)<=doms.len() => (n-1) as usize, 
        _ => { print_invalid_option(); return; } 
    };
    match vault.select_domain(doms[i].uuid) {
        Ok(()) => menu_dominio_selecionado(vault, dev, rid, doms[i].uuid),
        Err(e) => { println!("Erro: {}", e); pause(); }
    }
}

fn menu_dominio_selecionado<C, G, F>(vault: &VaultCore<C, G, F>, dev: uuid::Uuid, _rid: uuid::Uuid, did: uuid::Uuid)
where C: CryptoService, G: GeneratorService, F: FileService, {
    loop {
        clear_screen();
        let d = try_or_return!(vault.get_domain(did));
        let lines = [
            format!("{} | var:{} | hist:{}", d.identifier_canonical, d.active_variation, d.compromise_history.len()),
            "1. Ver  2. Copiar  3. Comprometer".into(), "4. Histórico  5. Mudar restrição  6. Remover".into(), "0. Voltar".into(),
        ];
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        print_menu_box("DOMÍNIO", 44, &refs);
        match get_option() {
            Some(1) => view_derived_password(vault, did),
            Some(2) => copy_derived_password(vault, did),
            Some(3) => mark_domain_compromised_prompt(vault, did),
            Some(4) => menu_versoes_comprometidas(vault, dev, did),
            Some(5) => change_domain_restriction_prompt(vault, dev, did),
            Some(6) => { if remove_domain_prompt(vault, did) { return; } }
            Some(0) => return,
            _ => print_invalid_option(),
        }
    }
}

fn view_derived_password<C, G, F>(vault: &VaultCore<C, G, F>, did: uuid::Uuid)
where
    C: CryptoService, G: GeneratorService, F: FileService,
{
    clear_screen();
    let mk = require_master_key!();
    let req = crate::core::PasswordRequest { domain_uuid: did, forced_variation: None };
    match vault.generate_password(req, &mk) {
        Ok(mut r) => {
            print_derived_password_result(&r.password, r.variation, r.entropy_millibits, r.device_uuid, r.restriction_uuid);
            r.password.zeroize(); // limpa a senha da RAM (já foi mostrada)
        }
        Err(e) => println!("Erro: {}", e),
    }
    pause();
}

fn copy_derived_password<C, G, F>(vault: &VaultCore<C, G, F>, did: uuid::Uuid)
where
    C: CryptoService, G: GeneratorService, F: FileService,
{
    let mk = require_master_key!();
    let req = crate::core::PasswordRequest { domain_uuid: did, forced_variation: None };
    match vault.generate_password(req, &mk) {
        Ok(mut r) => {
            match copy_to_clipboard(&r.password) {
                Ok(()) => println!("Copiada. Var:{} Ent:{} bits", r.variation, generator::format_millibits(r.entropy_millibits)),
                Err(e) => println!("Erro: {}", e),
            }
            r.password.zeroize(); // limpa a senha da RAM (já foi para a clipboard)
        }
        Err(e) => println!("Erro: {}", e),
    }
    pause();
}

fn mark_domain_compromised_prompt<C, G, F>(vault: &VaultCore<C, G, F>, did: uuid::Uuid)
where C: CryptoService, G: GeneratorService, F: FileService, {
    clear_screen();
    let d = try_or_return!(vault.get_domain(did));
    print_mark_domain_compromised_intro(&d.identifier_canonical, d.active_variation);
    if !confirm("Rotacionar?") { return; }
    let mk = require_master_key!();
    match vault.rotate_domain_password(did, &mk) {
        Ok(nv) => println!("Rotacionada! {} -> {}", d.active_variation, nv),
        Err(e) => println!("Erro: {}", e),
    }
    pause();
}

fn change_domain_restriction_prompt<C, G, F>(vault: &VaultCore<C, G, F>, dev: uuid::Uuid, did: uuid::Uuid)
where C: CryptoService, G: GeneratorService, F: FileService, {
    clear_screen();
    let d = try_or_return!(vault.get_domain(did));
    print_change_domain_restriction_warning(d.restriction_uuid);
    let rs = vault.list_restrictions(dev).unwrap_or_default();
    if rs.is_empty() { 
        println!("Nenhuma."); 
        pause(); 
        return; 
    }
    let list: Vec<_> = rs.iter().map(|r| (r.name.clone(), r.uuid)).collect();
    print_domain_change_restriction_list(d.restriction_uuid, &list);
    let i = match get_option() { 
        Some(0)=>return, 
        Some(n) if n>=1 && (n as usize)<=rs.len() => (n-1) as usize, 
        _ => { print_invalid_option(); return; } 
    };
    if rs[i].uuid == d.restriction_uuid { 
        println!("Já é a atual."); 
        pause(); 
        return; 
    }
    if !confirm(&format!("Mudar para '{}'?", rs[i].name)) { return; }
    match vault.change_domain_restriction(did, rs[i].uuid) { 
        Ok(())=>println!("Alterada."), 
        Err(e)=>println!("Erro: {}",e) 
    }
    pause();
}

fn remove_domain_prompt<C, G, F>(vault: &VaultCore<C, G, F>, did: uuid::Uuid) -> bool
where C: CryptoService, G: GeneratorService, F: FileService, {
    let d = try_or_return_false!(vault.get_domain(did));
    print_domain_removal_summary(&d.identifier_canonical, d.uuid);
    if !d.compromise_history.is_empty() {
        println!("AVISO: {} versões comprometidas serão perdidas.", 
        d.compromise_history.len()); 
    }
    if !confirm("Remover?") || !confirm("IRREVERSÍVEL?") { return false; }
    match vault.remove_domain(did) { 
        Ok(())=>{ 
            println!("Removido."); 
            pause(); 
            true 
        } 
        Err(e)=>{ 
            println!("Erro: {}",e); 
            pause(); 
            false 
        } 
    }
}

fn menu_versoes_comprometidas<C, G, F>(vault: &VaultCore<C, G, F>, dev: uuid::Uuid, did: uuid::Uuid)
where C: CryptoService, G: GeneratorService, F: FileService, {
    loop {
        clear_screen();
        let hist = try_or_return!(vault.get_compromise_history(did));
        let d = try_or_return!(vault.get_domain(did));
        let mut lines = vec![format!("DOMÍNIO: {}", d.identifier_canonical)];
        if hist.is_empty() { 
            lines.push("(nenhuma)".into()); 
        } else {
            let mut sorted = hist.clone(); sorted.sort_by_key(|r| std::cmp::Reverse(r.timestamp));
            for (i,r) in sorted.iter().enumerate() {
                lines.push(format!("{}. var:{} ({})", i+1, r.variation, r.timestamp.format("%Y-%m-%d %H:%M:%S"))); 
            }
        }
        lines.extend(["S. Selecionar".into(), "0. Voltar".into()]);
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        print_menu_box("VERSÕES COMPROMETIDAS", 34, &refs);
        match get_option_alpha() {
            Some('s')|Some('S') => select_compromised_version(vault, dev, did),
            Some('0') => return,
            _ => print_invalid_option(),
        }
    }
}

fn select_compromised_version<C, G, F>(vault: &VaultCore<C, G, F>, _dev: uuid::Uuid, did: uuid::Uuid)
where C: CryptoService, G: GeneratorService, F: FileService, {
    let hist = try_or_return!(vault.get_compromise_history(did));
    if hist.is_empty() { 
        println!("Nenhuma."); 
        pause(); 
        return; 
    }
    let mut sorted = hist.clone(); sorted.sort_by_key(|r| std::cmp::Reverse(r.timestamp));
    let rows: Vec<_> = sorted.iter().map(|r| (r.variation, r.timestamp.format("%Y-%m-%d %H:%M:%S").to_string(), r.frozen_config.identifier_frozen.clone())).collect();
    print_compromise_version_list(&rows);
    let i = match get_option() { 
        Some(0)=>return, 
        Some(n) if n>=1 && (n as usize)<=sorted.len() => (n-1) as usize, 
        _ => { print_invalid_option(); return; } 
    };
    menu_versao_comprometida(vault, did, sorted[i].variation, sorted[i].uuid);
}

fn menu_versao_comprometida<C, G, F>(vault: &VaultCore<C, G, F>, did: uuid::Uuid, var: u32, rec: uuid::Uuid)
where C: CryptoService, G: GeneratorService, F: FileService, {
    loop {
        clear_screen();
        print_compromised_version_header(var);
        print_menu_box("", 34, &["1. Ver  2. Copiar  3. Detalhes", "4. Apagar  0. Voltar"]);
        match get_option() {
            Some(1) => view_frozen_password(vault, did, var),
            Some(2) => copy_frozen_password(vault, did, var),
            Some(3) => view_frozen_details(vault, did, var),
            Some(4) => { if delete_compromise_entry(vault, did, rec) { return; } }
            Some(0) => return,
            _ => print_invalid_option(),
        }
    }
}

fn view_frozen_password<C, G, F>(vault: &VaultCore<C, G, F>, did: uuid::Uuid, var: u32)
where C: CryptoService, G: GeneratorService, F: FileService, {
    clear_screen();
    let mk = require_master_key!();
    // Gera e verifica o HMAC numa única desencriptação da seed (1 Argon2id).
    match vault.generate_password_from_frozen_checked(did, var, &mk) {
        Ok((mut r, hmac_status)) => {
            print_frozen_password_result(&r.password, r.variation, r.entropy_millibits);
            print_frozen_hmac_status(hmac_status);
            r.password.zeroize(); // limpa a senha da RAM
        }
        Err(e) => println!("Erro: {}", e),
    }
    pause();
}

fn copy_frozen_password<C, G, F>(vault: &VaultCore<C, G, F>, did: uuid::Uuid, var: u32)
where C: CryptoService, G: GeneratorService, F: FileService, {
    let mk = require_master_key!();
    // Gera e verifica o HMAC numa única desencriptação da seed (1 Argon2id).
    match vault.generate_password_from_frozen_checked(did, var, &mk) {
        Ok((mut r, hmac_status)) => {
            match copy_to_clipboard(&r.password) {
                Ok(())=>println!("Copiada (var:{}).",var),
                Err(e)=>println!("Erro: {}",e)
            }
            print_frozen_hmac_status(hmac_status);
            r.password.zeroize(); // limpa a senha da RAM (já foi para a clipboard)
        }
        Err(e) => println!("Erro: {}", e),
    }
    pause();
}

fn view_frozen_details<C, G, F>(vault: &VaultCore<C, G, F>, did: uuid::Uuid, var: u32)
where C: CryptoService, G: GeneratorService, F: FileService, {
    clear_screen();
    let hist = try_or_return!(vault.get_compromise_history(did));
    let rec = match hist.iter().find(|r| r.variation == var) { 
        Some(r)=>r, 
        None => { 
            println!("Não encontrada."); 
            pause(); 
            return; } 
        };
    let fc = &rec.frozen_config;
    let seq_lines: Vec<String> = fc.format_sequence_snapshot.as_deref().unwrap_or(&[]).iter().enumerate().map(|(i,item)| match item {
        MaskOrLiteral::Mask(m) => format!("    {:>3}. máscara {}", i+1, m),
        MaskOrLiteral::Literal(t) => format!("    {:>3}. literal '{}'", i+1, t),
    }).collect();
    print_frozen_details(rec.uuid, rec.variation, &rec.timestamp.format("%Y-%m-%d %H:%M:%S UTC").to_string(), fc.config_version, &fc.kmac_context, &fc.identifier_frozen, fc.default_mask_snapshot, fc.password_hmac.as_ref(), &seq_lines, &fc.char_lists_snapshot);
    pause();
}

/// HMAC calculado pelo core em `generate_password_from_frozen_checked` (passagem única, sem segundo Argon2id).
/// Some(true) = corresponde · Some(false) = não corresponde · None = indisponível.
fn print_frozen_hmac_status(status: Option<bool>) {
    match status {
        Some(true)  => println!("  HMAC verificado."),
        Some(false) => println!("  HMAC NÃO corresponde!"),
        None        => println!("  HMAC não disponível."),
    }
}

fn delete_compromise_entry<C, G, F>(vault: &VaultCore<C, G, F>, did: uuid::Uuid, rec: uuid::Uuid) -> bool
where
    C: CryptoService, G: GeneratorService, F: FileService,
{
    println!("AVISO: Remove permanentemente o snapshot.");
    if !confirm("Apagar?") || !confirm("IRREVERSÍVEL?") { return false; }
    match vault.remove_compromise_record(did, rec) {
        Ok(true) => { 
            println!("Removida."); 
            pause(); 
            true 
        }
        Ok(false) => { 
            println!("Não encontrada."); 
            pause(); 
            false 
        }
        Err(_) => { 
            println!("Erro."); 
            pause(); 
            false 
        }
    }
}

fn menu_senhas_estaticas<C, G, F>(vault: &VaultCore<C, G, F>, dev: uuid::Uuid)
where C: CryptoService, G: GeneratorService, F: FileService, {
    loop {
        clear_screen();
        let pws = vault.list_static_passwords(dev).unwrap_or_default();
        let mut folders = std::collections::BTreeSet::new();
        for sp in &pws { folders.insert(sp.folder_path.clone()); }
        let mut lines: Vec<String> = Vec::new();
        if folders.is_empty() { lines.push("(nenhuma pasta)".into()); } else {
            for f in &folders {
                let disp = if f.is_empty() { "(raiz)" } else { f.as_str() };
                let n = pws.iter().filter(|s| s.folder_path == *f && !s.compromised).count();
                let c = pws.iter().filter(|s| s.folder_path == *f && s.compromised).count();
                lines.push(format!("📁 {} ({} | comp:{})", disp, n, c));
            }
        }
        lines.extend(["1. Abrir  2. Abrir(comp)  3. +Pasta".into(), "4. Renomear  5. Remover  0. Voltar".into()]);
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        print_menu_box("SENHAS ESTÁTICAS", 40, &refs);
        match get_option() {
            Some(1) => open_folder_prompt(vault, dev, false),
            Some(2) => open_folder_prompt(vault, dev, true),
            Some(3) => { 
                let f = some_or_return!(ask_string("Nome da pasta")); 
                add_static_password_prompt(vault, dev, &f); 
            }
            Some(4) => rename_folder_prompt(vault, dev),
            Some(5) => remove_folder_prompt(vault, dev),
            Some(0) => return,
            _ => print_invalid_option(),
        }
    }
}

fn get_unique_folders(pws: &[StaticPassword]) -> Vec<String> {
    let mut s = std::collections::BTreeSet::new();
    for sp in pws { s.insert(sp.folder_path.clone()); }
    s.into_iter().collect()
}

fn open_folder_prompt<C, G, F>(vault: &VaultCore<C, G, F>, dev: uuid::Uuid, comp: bool)
where C: CryptoService, G: GeneratorService, F: FileService, {
    let pws = vault.list_static_passwords(dev).unwrap_or_default();
    let folders = get_unique_folders(&pws);
    if folders.is_empty() { 
        println!("Nenhuma pasta."); 
        pause(); 
        return; 
    }
    let label = if comp { "comprometidas" } else { "normais" };
    println!("Pasta ({}):", label);
    for (i,f) in folders.iter().enumerate() {
        let d = if f.is_empty() { "(raiz)" } else { f.as_str() };
        let c = pws.iter().filter(|s| s.folder_path == *f && s.compromised == comp).count();
        println!("  {}. {} ({})", i+1, d, c);
    }
    println!("  0. Cancelar");
    let i = match get_option() { 
        Some(0)=>return, 
        Some(n) if n>=1 && (n as usize)<=folders.len() => (n-1) as usize, 
        _ => { print_invalid_option(); return; } 
    };
    menu_pasta_aberta(vault, dev, &folders[i], comp);
}

fn menu_pasta_aberta<C, G, F>(vault: &VaultCore<C, G, F>, dev: uuid::Uuid, folder: &str, comp: bool)
where C: CryptoService, G: GeneratorService, F: FileService, {
    loop {
        clear_screen();
        let disp = if folder.is_empty() { "(raiz)" } else { folder };
        let suf = if comp { " [COMP]" } else { "" };
        let pws = vault.list_static_passwords(dev).unwrap_or_default();
        let filtered: Vec<_> = pws.iter().filter(|s| s.folder_path == folder && s.compromised == comp).collect();
        let mut lines: Vec<String> = vec![format!("📁 {}{}", disp, suf)];
        if filtered.is_empty() { lines.push("(vazia)".into()); } else {
            for (i,sp) in filtered.iter().enumerate() { lines.push(format!("{}. {}", i+1, sp.label)); }
        }
        if !comp { lines.push("1. Adicionar".into()); }
        lines.extend(["2. Selecionar".into(), "0. Voltar".into()]);
        let refs: Vec<&str> = lines.iter().map(String::as_str).collect();
        print_menu_box("PASTA", 34, &refs);
        match get_option() {
            Some(1) if !comp => add_static_password_prompt(vault, dev, folder),
            Some(2) => {
                if filtered.is_empty() { 
                    println!("Vazia."); 
                    pause(); 
                    continue; 
                }
                println!("Selecione (0=cancelar):");
                for (i,sp) in filtered.iter().enumerate() { println!("  {}. {}", i+1, sp.label); }
                let j = match get_option() { 
                    Some(0)=>continue, 
                    Some(n) if n>=1 && (n as usize)<=filtered.len() => (n-1) as usize, 
                    _ => { print_invalid_option(); continue; } 
                };
                menu_senha_estatica(vault, filtered[j].uuid, comp);
            }
            Some(0) => return,
            _ => print_invalid_option(),
        }
    }
}

fn menu_senha_estatica<C, G, F>(vault: &VaultCore<C, G, F>, sp: uuid::Uuid, comp: bool)
where
    C: CryptoService, G: GeneratorService, F: FileService,
{
    loop {
        clear_screen();
        let title = if comp { "SENHA COMPROMETIDA" } else { "SENHA ESTÁTICA" };
        let opts: Vec<&str> = if comp { vec!["1. Ver  2. Copiar  3. Remover", "0. Voltar"] } 
        else { vec!["1. Ver  2. Copiar  3. Comprometer  4. Remover", "0. Voltar"] };
        print_menu_box(title, 40, &opts);
        match (get_option(), comp) {
            (Some(1), _) => {
                let mk = require_master_key!();
                match vault.get_static_password(sp, &mk) {
                    Ok(mut pt) => {
                        print_static_password_plaintext(&pt, if pt.compromised {"SIM"} else {"NÃO"});
                        pt.value.zeroize();
                        pt.notes.zeroize();
                    }
                    Err(e)=>println!("Erro: {}",e)
                }
                pause();
            }
            (Some(2), _) => {
                let mk = require_master_key!();
                match vault.get_static_password(sp, &mk) {
                    Ok(mut pt) => {
                        match copy_to_clipboard(&pt.value) {
                            Ok(())=>println!("Copiada."),
                            Err(e)=>println!("{}",e)
                        }
                        pt.value.zeroize();
                        pt.notes.zeroize();
                    }
                    Err(e)=>println!("Erro: {}",e)
                }
                pause();
            }
            (Some(3), false) => { 
                if confirm("Comprometer?") { 
                    let mk = require_master_key!(); 
                    match vault.mark_static_password_compromised(sp, &mk) { 
                        Ok(())=>println!("Comprometida."),
                        Err(e)=>println!("Erro: {}",e) 
                    } 
                    pause(); 
                } 
            }
            (Some(4), false) | (Some(3), true) => { 
                if confirm("Remover? IRREVERSÍVEL") { 
                    match vault.remove_static_password(sp) { 
                        Ok(())=>{ 
                            println!("Removida.");
                            pause(); 
                            return; 
                        } 
                        Err(e)=>println!("Erro: {}",e) 
                    } pause(); 
                } 
            }
            (Some(0), _) => return,
            _ => print_invalid_option(),
        }
    }
}

fn add_static_password_prompt<C, G, F>(vault: &VaultCore<C, G, F>, dev: uuid::Uuid, folder: &str)
where C: CryptoService, G: GeneratorService, F: FileService, {
    let label = require_string!("Etiqueta");
    let value = some_or_return!(crate::input::ask_secret("Valor da senha"));
    let notes = ask_optional_string("Notas").unwrap_or_default();
    let mk = require_master_key_from!(vault);
    let pt = crate::models::StaticPasswordPlaintext { label: label.clone(), value, notes, compromised: false };
    match vault.add_static_password(dev, folder, &label, pt, &mk) {
        Ok(u) => println!("Adicionada: {}", u), 
        Err(e) => println!("Erro: {}", e),
    }
    pause();
}

fn rename_folder_prompt<C, G, F>(vault: &VaultCore<C, G, F>, dev: uuid::Uuid)
where C: CryptoService, G: GeneratorService, F: FileService, {
    let pws = vault.list_static_passwords(dev).unwrap_or_default();
    let folders = get_unique_folders(&pws);
    if folders.is_empty() { 
        println!("Nenhuma."); 
        pause(); 
        return; 
    }
    for (i,f) in folders.iter().enumerate() {
        println!("  {}. {}", i+1, if f.is_empty() {"(raiz)"} else {f.as_str()}); 
    }
    println!("  0. Cancelar");
    let i = match get_option() { 
        Some(0)=>return, 
        Some(n) if n>=1 && (n as usize)<=folders.len() => (n-1) as usize, 
        _ => { 
            print_invalid_option(); 
            return; 
        } 
    };
    let new = require_string!("Novo nome");
    if folders[i] == new { println!("Igual."); pause(); return; }
    match vault.rename_static_password_folder(dev, &folders[i], &new) { 
        Ok(())=>println!("Renomeada."), 
        Err(e)=>println!("Erro: {}",e) 
    }
    pause();
}

fn remove_folder_prompt<C, G, F>(vault: &VaultCore<C, G, F>, dev: uuid::Uuid)
where C: CryptoService, G: GeneratorService, F: FileService, {
    let pws = vault.list_static_passwords(dev).unwrap_or_default();
    let folders = get_unique_folders(&pws);
    if folders.is_empty() { println!("Nenhuma."); pause(); return; }
    for (i,f) in folders.iter().enumerate() { 
        println!("  {}. {}", i+1, if f.is_empty() {"(raiz)"} else {f.as_str()}); 
    }
    println!("  0. Cancelar");
    let i = match get_option() { 
        Some(0)=>return, 
        Some(n) if n>=1 && (n as usize)<=folders.len() => (n-1) as usize, 
        _ => { 
            print_invalid_option(); 
            return; 
        } 
    };
    if !confirm("Mover senhas para raiz?") { return; }
    match vault.clear_static_password_folder(dev, &folders[i]) { 
        Ok(())=>println!("Removida."), 
        Err(e)=>println!("Erro: {}",e) 
    }
    pause();
}

fn menu_exportar_senhas<C, G, F>(vault: &VaultCore<C, G, F>)
where C: CryptoService, G: GeneratorService, F: FileService, {
    clear_screen();
    println!("EXPORTAR SENHAS - TEXTO CLARO. Apenas para migração.");
    if !confirm("Continuar?") { return; }

    let mut tree = match build_selection_tree(vault) { 
        Some(t)=>t, 
        None => { 
            println!("Nada para exportar."); 
            pause(); 
            return; 
        } 
    };

    loop {
        clear_screen();
        print_menu_box("FILTRO", 34, &["1. Tudo  2. Por dispositivo  3. Por grupo", "0. Cancelar"]);
        match get_option() {
            Some(1) => { set_all_selected(&mut tree, true); break; }
            Some(2) => { filter_by_device(&mut tree); break; }
            Some(3) => { filter_by_group(&mut tree); break; }
            Some(0) => return,
            _ => print_invalid_option(),
        }
    }

    selection_loop(&mut tree);
    if count_selected(&tree) == 0 { 
        println!("Nada selecionado."); 
        pause(); 
        return; 
    }

    let inc_comp = confirm("Incluir comprometidas?");
    let inc_meta = confirm("Incluir metadados?");
    let fname = require_string!("Nome ficheiro (sem extensão)");
    let fdir = require_string!("Pasta destino");

    println!("Formato: 1.CSV 2.JSON 3.TXT 0.Cancelar");
    let (fmt, ext) = match get_option() {
        Some(1) => (crate::models::ExportFormat::Csv, "csv"),
        Some(2) => (crate::models::ExportFormat::Json, "json"),
        Some(3) => (crate::models::ExportFormat::Txt, "txt"),
        _ => return,
    };

    let path = format!("{}/{}.{}", fdir.trim_end_matches('/'), fname, ext);
    let (devs, rests, doms, statics) = extract_selected_uuids(&tree);
    let prep = try_or_return!(vault.prepare_export(&devs, &rests, &doms, &statics, inc_comp, inc_meta));
    let mk = require_master_key_from!(vault);
    let (data, _generation_duration) = try_or_return!(vault.execute_export(&prep, &mk));
    let mut content = match fmt {
        crate::models::ExportFormat::Csv => data.to_csv(),
        crate::models::ExportFormat::Json => data.to_json(),
        crate::models::ExportFormat::Txt => data.to_txt()
    };
    drop(data); // liberta os dados estruturados em claro logo após formatar
    save_export_file(&content, &path);
    content.zeroize(); // limpa o conteúdo exportado (todas as senhas) da RAM
}

fn build_selection_tree<C, G, F>(vault: &VaultCore<C, G, F>) -> Option<Vec<SelectionNode>>
where C: CryptoService, G: GeneratorService, F: FileService, {
    let devices = vault.list_devices().ok()?;
    if devices.is_empty() { return None; }
    let mut tree = Vec::new();
    for dev in &devices {
        let mut dn = SelectionNode { 
            uuid: dev.uuid, 
            label: dev.name.clone(), 
            node_type: SelectionNodeType::Device, 
            selected: false, 
            children: Vec::new() 
        };
        for r in vault.list_restrictions(dev.uuid).unwrap_or_default() {
            let mut rn = SelectionNode { 
                uuid: r.uuid, 
                label: r.name.clone(), 
                node_type: SelectionNodeType::Restriction, 
                selected: false, children: Vec::new() 
            };
            for d in vault.list_domains(r.uuid).unwrap_or_default() {
                rn.children.push(SelectionNode { 
                    uuid: d.uuid, 
                    label: d.identifier_canonical.clone(), 
                    node_type: SelectionNodeType::DerivedPassword, 
                    selected: false, 
                    children: Vec::new() 
                });
            }
            dn.children.push(rn);
        }
        let statics = vault.list_static_passwords(dev.uuid).unwrap_or_default();
        let mut folders: std::collections::BTreeMap<String, Vec<_>> = std::collections::BTreeMap::new();
        for sp in &statics { 
            if !sp.compromised { 
                folders.entry(sp.folder_path.clone()).or_default().push(sp); 
            } 
        }
        for (f, entries) in &folders {
            let fl = if f.is_empty() { "(estáticas - raiz)".into() } else { format!("(estáticas - {})", f) };
            let mut fn_node = SelectionNode { 
                uuid: uuid::Uuid::new_v4(), 
                label: fl, 
                node_type: SelectionNodeType::Folder, 
                selected: false, 
                children: Vec::new() 
            };
            for sp in entries {
                 fn_node.children.push(SelectionNode { 
                    uuid: sp.uuid, 
                    label: sp.label.clone(), 
                    node_type: SelectionNodeType::StaticPassword, 
                    selected: false, 
                    children: Vec::new() 
                }); 
            }
            dn.children.push(fn_node);
        }
        tree.push(dn);
    }
    Some(tree)
}

fn set_all_selected(tree: &mut [SelectionNode], sel: bool) {
    for n in tree.iter_mut() {
        n.selected = sel; 
        set_all_selected(&mut n.children, sel); 
    }
}

fn toggle_by_flat_index(tree: &mut [SelectionNode], target: usize) {
    let mut c = 0; toggle_recursive(tree, target, &mut c);
}

fn toggle_recursive(nodes: &mut [SelectionNode], target: usize, c: &mut usize) -> bool {
    for n in nodes.iter_mut() {
        if *c == target { 
            let s = !n.selected; n.selected = s; 
            set_all_selected(&mut n.children, s); 
            return true; 
        }
        *c += 1;
        if toggle_recursive(&mut n.children, target, c) { 
            return true; 
        }
    }
    false
}

fn filter_by_device(tree: &mut [SelectionNode]) {
    for (i,n) in tree.iter().enumerate() { 
        println!("  {}. {}", i+1, n.label); 
    }
    println!("  0. Todos");
    match get_option() {
        Some(0) => set_all_selected(tree, true),
        Some(n) if n>=1 && (n as usize)<=tree.len() => { 
            let i=(n-1) as usize; tree[i].selected=true; 
            set_all_selected(&mut tree[i].children, true); 
        }
        _ => print_invalid_option(),
    }
}

fn filter_by_group(tree: &mut [SelectionNode]) {
    let mut flat: Vec<(usize,usize,String)> = Vec::new();
    for (di,d) in tree.iter().enumerate() { 
        for (gi,g) in d.children.iter().enumerate() { 
            flat.push((di,gi,format!("{} -> {}",d.label,g.label))); 
        } 
    }
    for (i,(_,_,l)) in flat.iter().enumerate() { println!("  {}. {}", i+1, l); }
    println!("  0. Cancelar");
    match get_option() {
        Some(0) => {},
        Some(n) if n>=1 && (n as usize)<=flat.len() => { 
            let (di,gi,_)=&flat[(n-1) as usize]; 
            tree[*di].selected=true; tree[*di].children[*gi].selected=true; 
            set_all_selected(&mut tree[*di].children[*gi].children, true); 
        }
        _ => print_invalid_option(),
    }
}

fn selection_loop(tree: &mut [SelectionNode]) {
    loop {
        clear_screen();
        println!("SELECÇÃO (0=confirmar):");
        print_selection_tree(tree);
        match get_option() { 
            Some(0)=>return, 
            Some(n) if n>=1 => toggle_by_flat_index(tree, (n-1) as usize),
            _ => print_invalid_option() 
        }
    }
}

fn save_export_file(content: &str, path: &str) {
    let mut p = path.to_string();
    // BOM UTF-8 em CSV/TXT - sem isto, editores como o Notepad assumem a codificação ANSI/Latin-1 do sistema e mostram acentos corrompidos

    let needs_bom = p.ends_with(".csv") || p.ends_with(".txt");
    let mut bytes = Vec::with_capacity(content.len() + 3);
    if needs_bom {
        bytes.extend_from_slice(&[0xEF, 0xBB, 0xBF]);
    }
    bytes.extend_from_slice(content.as_bytes());
    loop {
        match std::fs::write(&p, &bytes) {
            Ok(()) => {
                println!("Exportado: {} ({} bytes)", p, bytes.len());
                pause(); return; 
            }
            Err(e) => {
                println!("Erro: {} ({})", e, p);
                match ask_optional_string("Novo caminho (vazio=cancelar)") { 
                    Some(np) if !np.is_empty() => p = np, _ => { 
                        println!("Cancelado."); 
                        pause(); 
                        return; 
                    } 
                }
            }
        }
    }
}
