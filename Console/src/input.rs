#![allow(dead_code)]

use std::io::{self, Write};
use crate::core::{MasterKeyInput, VaultCore, CryptoService, GeneratorService, FileService};
use crate::models::{Argon2Params, SeedEnvelope};

pub(crate) fn get_option() -> Option<u32> {
    print!("\nEscolha: ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().parse().ok()
}

pub(crate) fn get_option_alpha() -> Option<char> {
    print!("\nEscolha: ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    input.trim().chars().next()
}

pub(crate) fn ask_string(prompt: &str) -> Option<String> {
    print!("{}: ", prompt);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let trimmed = input.trim().to_string();
    if trimmed.is_empty() { None } else { Some(trimmed) }
}

pub(crate) fn ask_optional_string(prompt: &str) -> Option<String> {
    print!("{} (enter = vazio): ", prompt);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let trimmed = input.trim().to_string();
    if trimmed.is_empty() { None } else { Some(trimmed) }
}

pub(crate) fn ask_string_with_default(prompt: &str, default: &str) -> Option<String> {
    print!("{} [{}]: ", prompt, default);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let trimmed = input.trim();
    if trimmed.is_empty() {
        Some(default.to_string())
    } else {
        Some(trimmed.to_string())
    }
}

pub(crate) fn ask_secret(prompt: &str) -> Option<String> {
    rpassword::prompt_password(format!("{}: ", prompt))
        .ok()
        .and_then(|v| {
            let t = v.trim().to_string();
            if t.is_empty() { None } else { Some(t) }
        })
}

pub(crate) fn ask_secret_any(prompt: &str) -> String {
    rpassword::prompt_password(format!("{}: ", prompt))
        .unwrap_or_default()
        .trim()
        .to_string()
}

pub(crate) fn confirm(prompt: &str) -> bool {
    print!("{} (s/n): ", prompt);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    matches!(
        input.trim().to_lowercase().as_str(),
        "s" | "sim" | "y" | "yes"
    )
}

pub(crate) fn ask_u32_with_min(prompt: &str, min: u32) -> Option<u32> {
    print!("{} (mínimo {}): ", prompt, min);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    match input.trim().parse::<u32>() {
        Ok(v) => {
            let clamped = v.max(min);
            if clamped != v {
                println!("  (ajustado para mínimo: {})", min);
            }
            Some(clamped)
        }
        Err(_) => {
            println!("  Valor inválido.");
            None
        }
    }
}

pub(crate) fn ask_u32_with_default_min(prompt: &str, default: u32, min: u32) -> Option<u32> {
    print!("{} [{}] (mínimo {}): ", prompt, default, min);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Some(default.max(min));
    }
    match trimmed.parse::<u32>() {
        Ok(v) => {
            let clamped = v.max(min);
            if clamped != v {
                println!("  (ajustado para mínimo: {})", min);
            }
            Some(clamped)
        }
        Err(_) => {
            println!("  Valor inválido.");
            None
        }
    }
}

pub(crate) fn ask_u32_optional(prompt: &str) -> Option<u32> {
    print!("{} (vazio para manter): ", prompt);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let trimmed = input.trim();
    if trimmed.is_empty() { None } else { trimmed.parse::<u32>().ok() }
}

pub(crate) fn ask_u128_optional(prompt: &str) -> Option<u128> {
    print!("{} (vazio para limpar): ", prompt);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let trimmed = input.trim();
    if trimmed.is_empty() { None } else { trimmed.parse::<u128>().ok() }
}

pub(crate) fn ask_hex_32(prompt: &str) -> Option<[u8; 32]> {
    let input = ask_string(prompt)?;
    if let Ok(bytes) = std::fs::read(&input) {
        if bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            return Some(arr);
        }
    }
    let bytes = hex::decode(&input).ok()?;
    if bytes.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Some(arr)
    } else {
        None
    }
}

pub(crate) fn ask_hex_24(prompt: &str) -> Option<[u8; 24]> {
    let input = ask_string(prompt)?;
    if let Ok(bytes) = std::fs::read(&input) {
        if bytes.len() == 24 {
            let mut arr = [0u8; 24];
            arr.copy_from_slice(&bytes);
            return Some(arr);
        }
    }
    let bytes = hex::decode(&input).ok()?;
    if bytes.len() == 24 {
        let mut arr = [0u8; 24];
        arr.copy_from_slice(&bytes);
        Some(arr)
    } else {
        None
    }
}

pub(crate) fn ask_optional_hex_32(prompt: &str) -> Option<[u8; 32]> {
    print!("{}: ", prompt);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).ok()?;
    let trimmed = input.trim();
    if trimmed.is_empty() { return None; }
    ask_hex_32_from_str(trimmed)
}

fn ask_hex_32_from_str(trimmed: &str) -> Option<[u8; 32]> {
    if let Ok(bytes) = std::fs::read(trimmed) {
        if bytes.len() == 32 {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            return Some(arr);
        }
    }
    let bytes = hex::decode(trimmed).ok()?;
    if bytes.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Some(arr)
    } else {
        None
    }
}

pub(crate) fn ask_argon2_params_optional(default: &Argon2Params) -> Option<Argon2Params> {
    println!();
    println!("Argon2 (deixe em branco para usar o valor padrão da sessão)");
    let m = ask_u32_optional(&format!("m_cost [{}]", default.m_cost_kib))?;
    let t = ask_u32_optional(&format!("t_cost [{}]", default.t_cost))?;
    let p = ask_u32_optional(&format!("p_cost [{}]", default.p_cost))?;
    Some(Argon2Params {
        m_cost_kib: m.max(1),
        t_cost: t.max(1),
        p_cost: p.max(1),
    })
}

pub(crate) fn parse_mask_selection(input: &str) -> Result<u32, String> {
    let s = input.trim();
    if s.is_empty() { return Err("Entrada vazia".into()); }
    if let Some(rest) = s.strip_prefix("0x") {
        u32::from_str_radix(rest, 16).map_err(|e| format!("Parse error: {}", e))
    } else {
        s.parse::<u32>().map_err(|e| format!("Parse error: {}", e))
    }
}

pub(crate) fn ask_char_list_elements() -> Option<Vec<String>> {
    println!();
    println!("Introduza elementos separados por vírgula (ex: a,b,c)");
    let s = ask_string("Elementos")?;
    let v: Vec<String> = s
        .split(',')
        .map(|p| p.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect();
    if v.is_empty() {
        println!("Lista vazia.");
        None
    } else {
        Some(v)
    }
}

pub(crate) fn ask_insert_position(max: usize) -> usize {
    println!("Posição para inserir (1-{}, 0=final):", max);
    match ask_string("Inserir posição") {
        Some(s) => match s.parse::<usize>() {
            Ok(0) => max,
            Ok(n) if n >= 1 && n <= max => n - 1,
            _ => {
                println!("Posição inválida, usando fim.");
                max
            }
        },
        None => max,
    }
}

pub(crate) fn ask_position(len: usize, prompt: &str) -> Option<usize> {
    println!("{} (1-{}, 0 cancelar):", prompt, len);
    match ask_string(prompt) {
        Some(s) => match s.parse::<usize>() {
            Ok(0) => None,
            Ok(n) if n >= 1 && n <= len => Some(n - 1),
            _ => {
                println!("Posição inválida.");
                None
            }
        },
        None => None,
    }
}

pub(crate) fn ask_seed_envelope() -> Option<SeedEnvelope> {
    println!("Introduza a seed encriptada como JSON ou caminho de ficheiro.");
    let input = ask_string("Seed encriptada")?;
    if let Ok(bytes) = std::fs::read(&input) {
        if let Ok(envelope) = serde_json::from_slice::<SeedEnvelope>(&bytes) {
            return Some(envelope);
        }
    }
    serde_json::from_str::<SeedEnvelope>(&input).ok()
}

pub(crate) fn ask_master_key() -> Option<MasterKeyInput> {
    println!();
    let k1 = ask_secret("K1")?;
    let k2 = ask_secret("K2")?;
    let mk = MasterKeyInput::new(k1, k2);
    if let Err(e) = mk.validate() {
        println!("Erro de validação: {}", e);
        return None;
    }
    Some(mk)
}

pub(crate) fn ask_master_key_from_sources<C, G, F>(
    vault: &VaultCore<C, G, F>,
) -> Option<MasterKeyInput>
where
    C: CryptoService,
    G: GeneratorService,
    F: FileService,
{
    println!();
    println!("Fonte de K1/K2:");
    println!("  1. Introduzir manualmente");
    println!("  2. Carregar de ficheiros XOR");
    println!("  0. Cancelar");

    match get_option() {
        Some(1) => ask_master_key(),
        Some(2) => {
            let path_a = ask_known_xor_path(vault, "Share A")?;
            let path_b = ask_known_xor_path(vault, "Share B")?;
            match vault.files.read_xor_files(&path_a, &path_b) {
                Ok((k1, k2)) => Some(MasterKeyInput::new(k1, k2)),
                Err(e) => {
                    println!("Erro ao ler ficheiros XOR: {}", e);
                    None
                }
            }
        }
        _ => None,
    }
}

pub(crate) fn ask_xor_key_piece<C, G, F>(
    vault: &VaultCore<C, G, F>,
    label: &str,
) -> Option<String>
where
    C: CryptoService,
    G: GeneratorService,
    F: FileService,
{
    println!();
    println!("Fonte para {}:", label);
    println!("  1. Introduzir manualmente");
    println!("  2. Carregar de ficheiros XOR");
    println!("  3. Deixar em branco");
    println!("  0. Cancelar");

    match get_option() {
        Some(1) => Some(ask_secret_any(label)),
        Some(2) => {
            let path_a = ask_known_xor_path(vault, "Share A")?;
            let path_b = ask_known_xor_path(vault, "Share B")?;
            let (k1, k2) = match vault.files.read_xor_files(&path_a, &path_b) {
                Ok(pair) => pair,
                Err(e) => {
                    println!("Erro ao ler ficheiros XOR: {}", e);
                    return None;
                }
            };
            println!("Qual peça usar?");
            println!("  1. K1");
            println!("  2. K2");
            println!("  0. Cancelar");
            match get_option() {
                Some(1) => Some(k1),
                Some(2) => Some(k2),
                _ => None,
            }
        }
        Some(3) => Some(String::new()),
        _ => None,
    }
}

pub(crate) fn ask_known_session_path<C, G, F>(
    vault: &VaultCore<C, G, F>,
    label: &str,
) -> Option<String>
where
    C: CryptoService,
    G: GeneratorService,
    F: FileService,
{
    let default_path = vault
        .get_local_state()
        .last_session_path
        .or_else(|| {
            vault
                .default_session_path()
                .ok()
                .map(|p| p.display().to_string())
        })
        .unwrap_or_else(|| "session.vaultseed".to_string());

    println!();
    println!("Caminho de sessão para {} (vazio = {})", label, default_path);
    ask_string_with_default(
        &format!("Caminho para {}", label),
        &default_path,
    )
}

pub(crate) fn ask_known_xor_path<C, G, F>(
    vault: &VaultCore<C, G, F>,
    label: &str,
) -> Option<String>
where
    C: CryptoService,
    G: GeneratorService,
    F: FileService,
{
    let _ = vault;
    ask_string(&format!("Caminho XOR para {}", label))
}

pub(crate) fn ask_known_32byte_input_or_manual<C, G, F>(
    vault: &VaultCore<C, G, F>,
    label: &str,
) -> Option<[u8; 32]>
where
    C: CryptoService,
    G: GeneratorService,
    F: FileService,
{
    println!();
    println!("Fonte para {} (32 bytes):", label);
    println!("  1. Caminho de ficheiro");
    println!("  2. Hex de 32 bytes");
    println!("  0. Cancelar");

    match get_option() {
        Some(1) => {
            let path = ask_known_xor_path(vault, label)?;
            read_32_bytes_from_file(&path)
        }
        Some(2) => ask_hex_32(&format!("{} (hex)", label)),
        _ => None,
    }
}

fn read_32_bytes_from_file(path: &str) -> Option<[u8; 32]> {
    match std::fs::read(path) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            Some(arr)
        }
        Ok(bytes) => {
            println!(
                "Ficheiro '{}' tem {} bytes, esperado 32.",
                path,
                bytes.len()
            );
            None
        }
        Err(e) => {
            println!("Erro ao ler '{}': {}", path, e);
            None
        }
    }
}

pub(crate) enum SeedCreationFlow {
    Random,
    Plaintext([u8; 32]),
    Encrypted(SeedEnvelope),
}

pub(crate) fn ask_seed_creation_flow() -> SeedCreationFlow {
    println!();
    println!("Seed do dispositivo:");
    println!("  1. Nova seed aleatória");
    println!("  2. Seed desencriptada (32 bytes hex/ficheiro)");
    println!("  3. Seed encriptada (JSON/ficheiro)");

    match get_option() {
        Some(2) => match ask_optional_hex_32("Seed desencriptada") {
            Some(seed) => SeedCreationFlow::Plaintext(seed),
            None => {
                println!("Seed inválida. Será usada uma seed aleatória.");
                SeedCreationFlow::Random
            }
        },
        Some(3) => match ask_seed_envelope() {
            Some(envelope) => SeedCreationFlow::Encrypted(envelope),
            None => {
                println!("Seed encriptada inválida. Será usada uma seed aleatória.");
                SeedCreationFlow::Random
            }
        },
        _ => SeedCreationFlow::Random,
    }
}