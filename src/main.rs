// Ponto de entrada: GUI Slint (padrão), CLI (--cli) ou comandos técnicos (--<comando>).

// No Windows com subsistema GUI, suprime a janela de consola
#![cfg_attr(
    all(target_os = "windows", not(feature = "console")),
    windows_subsystem = "windows"
)]

use std::env;
use std::path::Path;
use std::process;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;

#[cfg(feature = "desktop")]
use slint::ComponentHandle;
use uuid::Uuid;

use vaultseed::core::{MasterKeyInput, VaultCore};
use vaultseed::services::crypto::CryptoServiceImpl;
use vaultseed::services::file::FileServiceImpl;
use vaultseed::services::generator::GeneratorServiceImpl;
use vaultseed::{crypto, generator, models};

#[cfg(not(target_family = "wasm"))]
use vaultseed::console;

#[cfg(feature = "desktop")]
use vaultseed::AppWindow;

#[cfg(feature = "desktop")]
use vaultseed::gui::{AppState, register_all_handlers};

fn main() {
    let args: Vec<String> = env::args().collect();

    if has_flag(&args, "--help") {
        ensure_console_for_cli();
        // --help sempre mostra na consola mesmo no Windows GUI
        print_help();
        pause_if_requested(&args);
        process::exit(0);
    }

    if has_flag(&args, "--cli") {
        ensure_console_for_cli();
        #[cfg(target_family = "wasm")]
        {
            eprintln!("CLI não está disponível neste alvo. Compile para um alvo nativo para usar --cli.");
            process::exit(1);
        }

        #[cfg(not(target_family = "wasm"))]
        {
        let vault = build_vault_direct();
        console::navigation::start_menu(&vault);
        process::exit(0);
        }
    }

    if has_flag(&args, "--gui") || args.len() <= 1 {
        run_gui();
        process::exit(0);
    }

    #[cfg(not(target_family = "wasm"))]
    let needs_console = get_command(&args).is_some();
    #[cfg(target_family = "wasm")]
    let needs_console = false;

    if needs_console {
        ensure_console_for_cli();
    }

    let result = match get_command(&args) {
        Some("--calibrate")          => cmd_calibrate(&args),
        Some("--derive-key")         => cmd_derive_key(&args),
        Some("--derive-kek-session") => cmd_derive_kek_session(&args),
        Some("--kmac")               => cmd_kmac(&args),
        Some("--hmac")               => cmd_hmac(&args),
        Some("--encrypt")            => cmd_encrypt(&args),
        Some("--decrypt")            => cmd_decrypt(&args),
        Some("--generate")           => cmd_generate(&args),
        Some("--generate-static")    => cmd_generate_static(&args),
        Some("--hkdf")               => cmd_hkdf(&args),
        None                         => Ok(()),
        _ => {
            eprintln!("Comando não reconhecido. Use --help.");
            process::exit(1);
        }
    };

    if let Err(e) = result {
        eprintln!();
        eprintln!("ERRO: {}", e);
        pause_if_requested(&args);
        process::exit(1);
    }

    pause_if_requested(&args);
}

#[cfg(feature = "desktop")]
fn run_gui() {
    // sem persistência automática - a GUI gere o ciclo de vida do vault
    let vault = build_vault_direct();

    let state = Arc::new(Mutex::new(AppState::new(vault)));

    let ui = AppWindow::new().unwrap_or_else(|e| {
        eprintln!("Erro ao criar janela: {}", e);
        process::exit(1);
    });

    vaultseed::gui::init_app_window(&ui, &state);

    register_all_handlers(&ui, Arc::clone(&state));

    offer_last_session_path_if_available(&ui, &state);

    // Tentar fechar a janela (botão "X", Alt+F4, etc.) com alterações por
    // guardar pendentes mostra o mesmo diálogo de aviso usado em "Bloquear",
    // em vez de fechar imediatamente e perder o trabalho.
    {
        let ui_handle = ui.as_weak();
        let state     = Arc::clone(&state);
        ui.window().on_close_requested(move || {
            let ui = ui_handle.unwrap();

            // Se o aviso de alterações pendentes já está visível, o
            // utilizador já foi informado - um novo pedido de fecho (ex:
            // clicar no X outra vez, Alt+F4 outra vez) deve fechar a
            // janela em vez de ficar bloqueado a reabrir o mesmo aviso.
            if ui.get_lock_unsaved_confirm_show() {
                return slint::CloseRequestResponse::HideWindow;
            }

            let has_unsaved = {
                let s     = state.lock().unwrap();
                let vault = s.vault.lock().unwrap();
                vault.has_unsaved_changes().unwrap_or(false)
            };

            if has_unsaved {
                ui.set_lock_unsaved_is_quit(true);
                ui.set_lock_unsaved_confirm_show(true);
                slint::CloseRequestResponse::KeepWindowShown
            } else {
                slint::CloseRequestResponse::HideWindow
            }
        });
    }

    ui.run().unwrap_or_else(|e| {
        eprintln!("Erro no event loop: {}", e);
        process::exit(1);
    });
}

#[cfg(not(feature = "desktop"))]
fn run_gui() {
    eprintln!(
        "GUI não está habilitada nesta compilação. Compile com --features desktop para ativar a GUI."
    );
    process::exit(1);
}

fn build_vault_direct() -> VaultCore<CryptoServiceImpl, GeneratorServiceImpl, FileServiceImpl> {
    VaultCore::new(
        models::LocalState::new(),
        CryptoServiceImpl::new(),
        GeneratorServiceImpl::new(),
        FileServiceImpl::new(),
        true, // persist_local_state
    )
}

#[allow(dead_code)]
fn visual_environment_available() -> bool {
    #[cfg(target_os = "windows")]
    { return true; }

    #[cfg(target_os = "macos")]
    { return true; }

    #[cfg(target_os = "linux")]
    {
        let has_wayland = env::var_os("WAYLAND_DISPLAY").is_some();
        let has_x11     = env::var_os("DISPLAY").is_some();
        let has_session = env::var("XDG_SESSION_TYPE")
            .map(|v| v.eq_ignore_ascii_case("wayland") || v.eq_ignore_ascii_case("x11"))
            .unwrap_or(false);
        return has_wayland || has_x11 || has_session;
    }

    #[allow(unreachable_code)]
    false
}

fn print_help() {
    let version = env!("CARGO_PKG_VERSION");
    println!("VaultSeed v{}", version);
    println!();
    println!("Uso: VaultSeed [MODO] [COMANDO] [PARÂMETROS]");
    println!();
    println!("Modos:");
    println!("  (sem args)             Abre a interface gráfica (padrão)");
    println!("  --gui                  Força interface gráfica Slint");
    println!("  --cli                  Força modo consola interativo");
    println!("  --help                 Mostra esta ajuda");
    println!("  --pause                Aguarda Enter antes de sair (ver saída na consola)");
    println!();
    println!("Comandos técnicos:");
    println!("  --calibrate            Calibrar parâmetros Argon2id");
    println!("  --derive-key           Derivar chave via Argon2id");
    println!("  --derive-kek-session   Derivar KEK_session completo");
    println!("  --kmac                 Derivar entropia via KMAC256");
    println!("  --hmac                 Calcular HMAC-SHA256");
    println!("  --encrypt              Encriptar dados com XChaCha20-Poly1305");
    println!("  --decrypt              Desencriptar dados com XChaCha20-Poly1305");
    println!("  --generate             Gerar senha derivada (pipeline completo)");
    println!("  --generate-static      Encriptar/desencriptar senha estática");
    println!("  --hkdf                 Derivar via HKDF-SHA256");
    println!();
    println!("Parâmetros comuns:");
    println!("  --k1 <valor>           Segredo K1");
    println!("  --k2 <valor>           Segredo K2");
    println!("  --salt <hex>           Salt (32 bytes hex, gerado se omitido)");
    println!("  --nonce <hex>          Nonce (24 bytes hex, gerado se omitido)");
    println!("  --seed <hex>           Seed (32 bytes hex)");
    println!("  --key <hex>            Chave (32 bytes hex)");
    println!("  --domain <nome>        Domínio para contexto KMAC");
    println!("  --variation <n>        Variação (padrão: 0)");
    println!("  --device-uuid <uuid>   UUID do dispositivo");
    println!("  --restriction-uuid <u> UUID da restrição");
    println!("  --m-cost <KiB>         Argon2id m_cost");
    println!("  --t-cost <n>           Argon2id t_cost");
    println!("  --p-cost <n>           Argon2id p_cost");
    println!("  --aad <texto>          AAD para AEAD");
    println!("  --plaintext <texto>    Dados para encriptar");
    println!("  --ciphertext <hex>     Dados para desencriptar");
    println!("  --mask <n>             Máscara padrão (padrão: 7)");
    println!("  --masks <lista>        Sequência de máscaras/literais");
    println!("  --length <n>           Comprimento para --generate");
    println!("  --k-ext <hex>          Fator físico (32 bytes hex)");
    println!("  --static-value <texto> Valor da senha estática");
    println!("  --mode <enc|dec>       Modo para --generate-static");
    println!("  --label <texto>        Rótulo da senha estática");
    println!("  --notes <texto>        Notas da senha estática");
    println!("  --entry-uuid <uuid>    UUID da entrada estática");
    println!("  --context <texto>      Contexto explícito para --kmac");
    println!("  --output-len <n>       Bytes de saída para --kmac (padrão: 32)");
    println!("  --info <texto>         Info para --hkdf");
    println!("  --output-hex           Output em hexadecimal");
    println!("  --min-target <ms>      Alvo mínimo de calibração");
    println!("  --max-target <ms>      Alvo máximo de calibração");
}

fn cmd_calibrate(args: &[String]) -> Result<(), String> {
    println!("--- Calibração Argon2id ---");
    println!();

    let mut calibrator = crypto::Calibrator::new();

    if let Some(min) = get_u128_optional_alias(args, &["--min-target", "--min-ms"])? {
        println!("  Target Min MS: {} (fornecido)", min);
        calibrator = calibrator.with_min(min);
    }

    if let Some(max) = get_u128_optional_alias(args, &["--max-target", "--max-ms"])? {
        println!("  Target Max MS: {} (fornecido)", max);
        calibrator = calibrator.with_max(max);
    }

    let cal = calibrator.run();

    println!("Resultado:");
    println!("  m: {} KiB ({} MiB)", cal.m_cost_kib, cal.m_cost_kib / 1024);
    println!("  t: {}", cal.t_cost);
    println!("  p: {}", cal.p_cost);
    println!("  duração: {} ms", cal.duration.as_millis());

    Ok(())
}

fn cmd_derive_key(args: &[String]) -> Result<(), String> {
    println!("--- Derivação Argon2id ---");

    let k1   = require_arg(args, "--k1")?;
    let k2   = require_arg(args, "--k2")?;
    let salt = get_or_generate_salt(args)?;
    let (m, t, p) = get_argon2_params(args, None);

    let master   = MasterKeyInput::new(k1, k2);
    let mut password = master.normalize_and_concat();

    println!("  Salt: {}", hex::encode(salt));
    println!("  Params: m={}, t={}, p={}", m, t, p);

    let key = crypto::derive_key_argon2id(&password, &salt, m, t, p, 32)?;
    password.iter_mut().for_each(|b| *b = 0);

    println!("  Chave derivada: {}", hex::encode(&key));
    Ok(())
}

fn cmd_derive_kek_session(args: &[String]) -> Result<(), String> {
    println!("--- Derivação KEK_session ---");

    let k1    = require_arg(args, "--k1")?;
    let k2    = require_arg(args, "--k2")?;
    let salt  = get_or_generate_salt(args)?;
    let (m, t, p) = get_argon2_params(args, None);
    let k_ext     = get_hex_32_optional(args, "--k-ext");
    let salt_hkdf = get_hex_32_optional(args, "--salt-hkdf");

    println!("  Salt session: {}", hex::encode(salt));
    println!("  Params: m={}, t={}, p={}", m, t, p);
    println!("  K_ext: {}", if k_ext.is_some() { "sim" } else { "não" });

    let kek = crypto::derive_kek_session(
        &k1, &k2, &salt, m, t, p,
        k_ext.as_ref(),
        salt_hkdf.as_ref(),
    ).map_err(|e| format!("Falha: {}", e))?;

    println!("  KEK_session: {}", hex::encode(kek));
    Ok(())
}

fn cmd_kmac(args: &[String]) -> Result<(), String> {
    println!("--- KMAC256 ---");

    let seed       = require_hex_32(args, "--seed")?;
    let context    = get_context_string(args)?;
    let output_len = get_arg_u32(args, "--output-len").unwrap_or(32) as usize;

    println!("  Seed: {}", hex::encode(seed));
    println!("  Contexto: {}", context);
    println!("  Bytes de saída: {}", output_len);

    let mut output = vec![0u8; output_len];
    crypto::kmac256_xof(&seed, context.as_bytes(), &mut output);

    println!("  Entropia: {}", hex::encode(&output));
    Ok(())
}

fn cmd_hmac(args: &[String]) -> Result<(), String> {
    println!("--- HMAC-SHA256 ---");

    let key  = require_hex_32(args, "--key")?;
    let data = require_arg(args, "--plaintext")?;

    println!("  Chave: {}", hex::encode(key));
    println!("  Dados: {} bytes", data.len());

    let result = crypto::hmac_sha256(&key, data.as_bytes());

    println!("  HMAC: {}", hex::encode(result));
    Ok(())
}

fn cmd_encrypt(args: &[String]) -> Result<(), String> {
    println!("--- Encriptação XChaCha20-Poly1305 ---");

    let key       = require_hex_32(args, "--key")?;
    let nonce     = get_or_generate_nonce(args)?;
    let aad       = get_arg_str(args, "--aad").unwrap_or_default();
    let plaintext = require_arg(args, "--plaintext")?;

    println!("  Nonce: {}", hex::encode(nonce));
    println!("  AAD: '{}'", aad);
    println!("  Plaintext: {} bytes", plaintext.len());

    let (_nonce_result, ciphertext) =
        crypto::xchacha20poly1305_encrypt(&key, &nonce, plaintext.as_bytes(), aad.as_bytes());

    println!("  Ciphertext: {}", hex::encode(&ciphertext));
    Ok(())
}

fn cmd_decrypt(args: &[String]) -> Result<(), String> {
    println!("--- Desencriptação XChaCha20-Poly1305 ---");

    let key            = require_hex_32(args, "--key")?;
    let nonce          = require_hex_24(args, "--nonce")?;
    let aad            = get_arg_str(args, "--aad").unwrap_or_default();
    let ciphertext_hex = require_arg(args, "--ciphertext")?;
    let ciphertext     = hex::decode(&ciphertext_hex)
        .map_err(|_| "Ciphertext hex inválido".to_string())?;

    println!("  Nonce: {}", hex::encode(nonce));
    println!("  AAD: '{}'", aad);
    println!("  Ciphertext: {} bytes", ciphertext.len());

    let plaintext =
        crypto::xchacha20poly1305_decrypt(&key, &nonce, &ciphertext, aad.as_bytes())
            .map_err(|e| format!("Desencriptação falhou: {}", e))?;

    if has_flag(args, "--output-hex") {
        println!("  Plaintext (hex): {}", hex::encode(&plaintext));
    } else {
        match String::from_utf8(plaintext.clone()) {
            Ok(text) => println!("  Plaintext: {}", text),
            Err(_)   => println!("  Plaintext (hex): {}", hex::encode(&plaintext)),
        }
    }
    Ok(())
}

fn cmd_generate(args: &[String]) -> Result<(), String> {
    println!("--- Geração de Senha Derivada ---");

    let seed             = require_hex_32(args, "--seed")?;
    let domain           = get_arg_str(args, "--domain").unwrap_or_else(|| "example.com".to_string());
    let variation        = get_arg_u32(args, "--variation").unwrap_or(0);
    let device_uuid      = get_arg_uuid(args, "--device-uuid")
        .unwrap_or_else(|| Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap());
    let restriction_uuid = get_arg_uuid(args, "--restriction-uuid")
        .unwrap_or_else(|| Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap());
    let mask             = get_mask_u32(args, "--mask")?.unwrap_or(7);

    println!("  Seed: {}", hex::encode(seed));
    println!("  Domínio: {}", domain);
    println!("  Variação: {}", variation);
    println!("  Device: {}", device_uuid);
    println!("  Restriction: {}", restriction_uuid);
    println!("  Máscara: {}", mask);

    let context = generator::build_context(
        &domain,
        variation,
        &device_uuid.to_string(),
        &restriction_uuid.to_string(),
    );
    println!("  Contexto: {}", context);

    let bit_lists    = build_default_bit_lists();
    let masks        = resolve_masks_from_args(args, mask, &bit_lists)?;
    let resolved     = resolve_default_mask_sentinels(&masks, mask);
    let sizes        = compute_alphabet_sizes_for_masks(&resolved, &bit_lists)?;
    let bytes_needed = models::GenerationParams::compute_bytes_to_derive(&sizes);

    println!("  Posições: {}", masks.len());
    println!("  Bytes KMAC XOF: {}", bytes_needed);

    let mut entropy = vec![0u8; bytes_needed];
    crypto::kmac256_xof(&seed, context.as_bytes(), &mut entropy);
    println!("  Entropia: {}", hex::encode(&entropy));

    let result = generator::generate_password(&entropy, &resolved, &bit_lists)
        .map_err(|e| e.to_string())?;

    println!();
    println!("=== Resultado ===");
    println!("  Senha: {}", result.password);
    println!("  Comprimento: {}", result.password.len());
    println!(
        "  Entropia usada: {} bits",
        generator::format_millibits(result.total_entropy_millibits)
    );
    Ok(())
}

fn cmd_generate_static(args: &[String]) -> Result<(), String> {
    println!("--- Senha Estática ---");

    let mode         = require_arg(args, "--mode")?;
    let seed         = require_hex_32(args, "--seed")?;
    let entry_uuid   = get_arg_uuid(args, "--entry-uuid").unwrap_or_else(Uuid::new_v4);
    let device_uuid  = get_arg_uuid(args, "--device-uuid")
        .unwrap_or_else(|| Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap());

    let aad          = format!("v1|STATIC|senha_estatica:{}|device:{}", entry_uuid, device_uuid);
    let kmac_context = format!("v1|STATIC|{}", entry_uuid);

    let mut key = [0u8; 32];
    crypto::kmac256_xof(&seed, kmac_context.as_bytes(), &mut key);

    println!("  Entry UUID: {}", entry_uuid);
    println!("  Device UUID: {}", device_uuid);
    println!("  AAD: {}", aad);
    println!("  Chave derivada: {}", hex::encode(key));

    match mode.as_str() {
        "enc" => {
            let value     = require_arg(args, "--static-value")?;
            let nonce     = get_or_generate_nonce(args)?;
            let plaintext = serde_json::json!({
                "value": value,
                "label": get_arg_str(args, "--label").unwrap_or_default(),
                "notes": get_arg_str(args, "--notes").unwrap_or_default(),
                "compromised": false,
            });
            let plaintext_bytes = serde_json::to_vec(&plaintext)
                .map_err(|e| format!("Serialização falhou: {}", e))?;

            println!("  Nonce: {}", hex::encode(nonce));
            println!("  Plaintext: {} bytes", plaintext_bytes.len());

            let (_, ciphertext) =
                crypto::xchacha20poly1305_encrypt(&key, &nonce, &plaintext_bytes, aad.as_bytes());

            println!();
            println!("=== Resultado ===");
            println!("  Nonce: {}", hex::encode(nonce));
            println!("  Ciphertext: {}", hex::encode(&ciphertext));
        }
        "dec" => {
            let nonce          = require_hex_24(args, "--nonce")?;
            let ciphertext_hex = require_arg(args, "--ciphertext")?;
            let ciphertext     = hex::decode(&ciphertext_hex)
                .map_err(|_| "Ciphertext hex inválido".to_string())?;
            let plaintext_bytes =
                crypto::xchacha20poly1305_decrypt(&key, &nonce, &ciphertext, aad.as_bytes())
                    .map_err(|e| format!("Desencriptação falhou: {}", e))?;
            let plaintext: serde_json::Value = serde_json::from_slice(&plaintext_bytes)
                .map_err(|e| format!("Deserialização falhou: {}", e))?;

            println!();
            println!("=== Resultado ===");
            println!("  Valor: {}", plaintext["value"]);
            println!("  Label: {}", plaintext["label"]);
            println!("  Notas: {}", plaintext["notes"]);
            println!("  Comprometida: {}", plaintext["compromised"]);
        }
        _ => return Err("--mode deve ser 'enc' ou 'dec'".to_string()),
    }

    Ok(())
}

fn cmd_hkdf(args: &[String]) -> Result<(), String> {
    println!("--- HKDF-SHA256 ---");

    let ikm    = require_hex(args, "--key")?;
    let salt   = get_hex_optional(args, "--salt");
    let info   = get_arg_str(args, "--info").unwrap_or_default();
    let length = get_arg_u32(args, "--length").unwrap_or(32) as usize;

    println!("  IKM: {} bytes", ikm.len());
    println!(
        "  Salt: {}",
        salt.as_ref().map_or("nenhum".to_string(), |s| format!("{} bytes", s.len()))
    );
    println!("  Info: '{}'", info);
    println!("  Output: {} bytes", length);

    let result = crypto::hkdf_extract_expand(&ikm, salt.as_deref(), info.as_bytes(), length);

    println!("  Resultado: {}", hex::encode(&result));
    Ok(())
}

fn get_command(args: &[String]) -> Option<&str> {
    const CONTROL_FLAGS: &[&str] = &["--cli", "--gui", "--help", "--pause"];
    args.iter()
        .skip(1)
        .find(|a| a.starts_with("--") && !CONTROL_FLAGS.contains(&a.as_str()))
        .map(|s| s.as_str())
}

#[cfg(windows)]
fn ensure_console_for_cli() {
    use windows_sys::Win32::System::Console::AllocConsole;

    unsafe {
        let _ = AllocConsole();
    }
}

#[cfg(not(windows))]
fn ensure_console_for_cli() {}

/// Se `--pause` estiver presente, espera por Enter antes de sair.
/// Útil no Windows para ler a saída antes da janela de consola fechar.
fn pause_if_requested(args: &[String]) {
    if !has_flag(args, "--pause") {
        return;
    }
    use std::io::{self, BufRead, Write};
    print!("\nPressione Enter para continuar...");
    let _ = io::stdout().flush();
    let mut line = String::new();
    let _ = io::stdin().lock().read_line(&mut line);
}

fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
}

fn get_arg_str(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .filter(|v| !v.starts_with("--"))
        .cloned()
}

fn require_arg(args: &[String], name: &str) -> Result<String, String> {
    get_arg_str(args, name)
        .ok_or_else(|| format!("Argumento obrigatório em falta: {}", name))
}

fn get_arg_u32(args: &[String], name: &str) -> Option<u32> {
    get_arg_str(args, name).and_then(|v| v.parse().ok())
}

fn parse_u32_token(value: &str) -> Result<u32, String> {
    let trimmed = value.trim();
    if let Some(hex) = trimmed.strip_prefix("0x").or_else(|| trimmed.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16)
            .map_err(|_| format!("Valor hexadecimal inválido: {}", value))
    } else {
        trimmed.parse::<u32>()
            .map_err(|_| format!("Valor inválido: {}", value))
    }
}

fn get_mask_u32(args: &[String], name: &str) -> Result<Option<u32>, String> {
    match get_arg_str(args, name) {
        Some(value) => parse_u32_token(&value).map(Some),
        None        => Ok(None),
    }
}

fn get_arg_uuid(args: &[String], name: &str) -> Option<Uuid> {
    get_arg_str(args, name).and_then(|v| Uuid::parse_str(&v).ok())
}

fn get_argon2_params(args: &[String], defaults: Option<(u32, u32, u32)>) -> (u32, u32, u32) {
    let (dm, dt, dp) = defaults.unwrap_or((65536, 3, 4));
    let m = get_arg_u32(args, "--m-cost").unwrap_or(dm).max(65536);
    let t = get_arg_u32(args, "--t-cost").unwrap_or(dt).max(3);
    let p = get_arg_u32(args, "--p-cost").unwrap_or(dp).max(4);
    (m, t, p)
}

fn require_hex(args: &[String], name: &str) -> Result<Vec<u8>, String> {
    let value = require_arg(args, name)?;
    hex::decode(&value).map_err(|_| format!("{} não é hex válido", name))
}

fn require_hex_32(args: &[String], name: &str) -> Result<[u8; 32], String> {
    let bytes = require_hex(args, name)?;
    if bytes.len() != 32 {
        return Err(format!(
            "{} deve ter 32 bytes (64 hex chars), recebido: {}",
            name, bytes.len()
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn require_hex_24(args: &[String], name: &str) -> Result<[u8; 24], String> {
    let bytes = require_hex(args, name)?;
    if bytes.len() != 24 {
        return Err(format!(
            "{} deve ter 24 bytes (48 hex chars), recebido: {}",
            name, bytes.len()
        ));
    }
    let mut arr = [0u8; 24];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn get_hex_optional(args: &[String], name: &str) -> Option<Vec<u8>> {
    get_arg_str(args, name).and_then(|v| hex::decode(&v).ok())
}

fn get_hex_32_optional(args: &[String], name: &str) -> Option<[u8; 32]> {
    get_hex_optional(args, name).and_then(|bytes| {
        if bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Some(arr)
        } else {
            None
        }
    })
}

fn get_or_generate_salt(args: &[String]) -> Result<[u8; 32], String> {
    match get_hex_32_optional(args, "--salt") {
        Some(salt) => { println!("  Salt: fornecido"); Ok(salt) }
        None       => { println!("  Salt: gerado automaticamente"); Ok(crypto::generate_salt()) }
    }
}

fn get_flag_value(args: &[String], flag: &str) -> Option<String> {
    let pos = args.iter().position(|a| a == flag)?;
    args.get(pos + 1).cloned()
}

fn get_u128_optional_alias(args: &[String], flags: &[&str]) -> Result<Option<u128>, String> {
    for flag in flags {
        if let Some(val_str) = get_flag_value(args, flag) {
            let val = val_str.parse::<u128>()
                .map_err(|_| format!("O valor de {} deve ser um inteiro.", flag))?;
            return Ok(Some(val));
        }
    }
    Ok(None)
}

fn get_or_generate_nonce(args: &[String]) -> Result<[u8; 24], String> {
    match get_arg_str(args, "--nonce") {
        Some(hex_str) => {
            let bytes = hex::decode(&hex_str)
                .map_err(|_| "Nonce hex inválido".to_string())?;
            if bytes.len() != 24 {
                return Err(format!("Nonce deve ter 24 bytes, recebido: {}", bytes.len()));
            }
            let mut arr = [0u8; 24];
            arr.copy_from_slice(&bytes);
            Ok(arr)
        }
        None => {
            let mut nonce = [0u8; 24];
            getrandom::fill(&mut nonce).expect("OS RNG indisponível");
            Ok(nonce)
        }
    }
}

fn get_context_string(args: &[String]) -> Result<String, String> {
    if let Some(ctx) = get_arg_str(args, "--context") {
        return Ok(ctx);
    }
    let domain = get_arg_str(args, "--domain")
        .ok_or("É necessário --domain ou --context")?;
    let variation        = get_arg_u32(args, "--variation").unwrap_or(0);
    let device_uuid      = get_arg_uuid(args, "--device-uuid")
        .unwrap_or_else(|| Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap());
    let restriction_uuid = get_arg_uuid(args, "--restriction-uuid")
        .unwrap_or_else(|| Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap());

    Ok(generator::build_context(
        &domain,
        variation,
        &device_uuid.to_string(),
        &restriction_uuid.to_string(),
    ))
}

fn build_default_bit_lists() -> HashMap<u8, Vec<String>> {
    vaultseed::core::build_default_bit_lists()
}

fn resolve_masks_from_args(
    args:      &[String],
    default_mask: u32,
    bit_lists: &HashMap<u8, Vec<String>>,
) -> Result<Vec<models::MaskOrLiteral>, String> {
    if let Some(masks_str) = get_arg_str(args, "--masks") {
        let mut masks = Vec::new();
        for part in masks_str.split(',') {
            let trimmed = part.trim();
            if trimmed.starts_with('/') && trimmed.ends_with('/') {
                masks.push(
                    models::MaskOrLiteral::from_literal(trimmed)
                        .map_err(|e| format!("Literal inválido: {}", e))?
                );
            } else {
                let value = parse_u32_token(trimmed)?;
                masks.push(models::MaskOrLiteral::Mask(if value == 0 { 0 } else { value }));
            }
        }
        Ok(masks)
    } else if let Some(length) = get_arg_u32(args, "--length") {
        Ok(vec![models::MaskOrLiteral::Mask(0); length as usize])
    } else {
        Ok(generator::build_max_masks(default_mask, bit_lists, 256)
            .into_iter()
            .map(|item| match item {
                models::MaskOrLiteral::Mask(m) if m == default_mask =>
                    models::MaskOrLiteral::Mask(0),
                other => other,
            })
            .collect())
    }
}

fn resolve_default_mask_sentinels(
    masks:        &[models::MaskOrLiteral],
    default_mask: u32,
) -> Vec<models::MaskOrLiteral> {
    masks.iter().map(|item| match item {
        models::MaskOrLiteral::Mask(0) => models::MaskOrLiteral::Mask(default_mask),
        other                          => other.clone(),
    }).collect()
}

fn compute_alphabet_sizes_for_masks(
    masks:     &[models::MaskOrLiteral],
    bit_lists: &HashMap<u8, Vec<String>>,
) -> Result<Vec<usize>, String> {
    let dict = generator::build_alphabet_dictionary(bit_lists, masks)
        .map_err(|e| format!("Falha ao construir dicionário: {}", e))?;

    Ok(masks.iter()
        .filter_map(|item| item.as_mask())
        .filter_map(|mask| dict.get(&mask).map(|alpha| alpha.len()))
        .collect())
}

#[cfg(feature = "desktop")]
fn offer_last_session_path_if_available(
    ui: &AppWindow,
    state: &Arc<Mutex<AppState<CryptoServiceImpl, GeneratorServiceImpl, FileServiceImpl>>>,
) {
    let last_session_path = {
        let s = state.lock().unwrap();
        let vault = s.vault.lock().unwrap();
        vault.get_local_state().last_session_path
    };

    let Some(path) = last_session_path else {
        return;
    };

    if path.trim().is_empty() || !Path::new(&path).exists() {
        return;
    }

    // sem modal de confirmação - o utilizador pode sempre alterar no campo de login
    ui.set_login_default_path(path.into());
}

#[cfg(not(feature = "desktop"))]
fn offer_last_session_path_if_available< T1, T2, T3 >(
    _ui: &T1,
    _state: &T2,
) where
    T2: std::any::Any,
{
}