use std::env;

use crate::core::{CryptoService, FileService, GeneratorService, MasterKeyInput, PasswordRequest, VaultCore};
use crate::display::pause;
use crate::input::{ask_master_key, ask_string, ask_string_with_default, get_option};
use crate::models::Argon2Params;

pub fn start_tutorial<C, G, F>(vault: &VaultCore<C, G, F>)
where
    C: CryptoService,
    G: GeneratorService,
    F: FileService,
{
    println!("--- Configuração Inicial---");

    let session_path_default = match vault.default_session_path() {
        Ok(path) => path.display().to_string(),
        Err(_) => "session.vaultseed".to_string(),
    };

    println!("Para usar a pasta local automática, deixe o caminho em branco.");
    let session_path = match ask_string_with_default(
        "Caminho do ficheiro de sessão",
        &session_path_default,
    ) {
        Some(value) if !value.is_empty() => value,
        _ => session_path_default,
    };

    let detected_device_name = detect_device_name();
    println!(
        "Para usar o nome detetado ({}) deixe o campo em branco.",
        detected_device_name
    );
    let device_name = match ask_string_with_default("Nome do dispositivo", &detected_device_name) {
        Some(value) if !value.is_empty() => value,
        _ => detected_device_name,
    };

    let domain_name = match ask_string("Primeiro domínio") {
        Some(value) if !value.is_empty() => value,
        _ => {
            println!("Domínio inválido.");
            pause();
            return;
        }
    };

    let salt_session = match vault.crypto.generate_random_32() {
        Ok(value) => value,
        Err(e) => {
            println!("Erro ao gerar salt da sessão: {}", e);
            pause();
            return;
        }
    };

    let argon2 = Argon2Params {
        m_cost_kib: 65_536,
        t_cost: 3,
        p_cost: 4,
    };

    let master_key = match ask_master_key() {
        Some(value) => value,
        None => {
            println!("K1/K2 inválidos.");
            pause();
            return;
        }
    };

    if let Err(e) = vault.create_new_session(salt_session, argon2, false, None) {
        println!("Erro ao criar sessão: {}", e);
        pause();
        return;
    }

    let device_uuid = match vault.add_device(&device_name, &master_key) {
        Ok(value) => value,
        Err(e) => {
            println!("Erro ao criar dispositivo: {}", e);
            pause();
            return;
        }
    };

    let restriction_uuid = match vault.list_restrictions(device_uuid) {
        Ok(restrictions) => match restrictions.first() {
            Some(restriction) => restriction.uuid,
            None => {
                println!("Erro: restrição inicial não encontrada.");
                pause();
                return;
            }
        },
        Err(e) => {
            println!("Erro ao listar restrições: {}", e);
            pause();
            return;
        }
    };

    let domain_uuid = match vault.add_domain(&domain_name, restriction_uuid) {
        Ok(uuid) => uuid,
        Err(e) => {
            println!("Erro ao criar domínio: {}", e);
            pause();
            return;
        }
    };

    let verified_master_key = match verify_master_key_for_save(vault, domain_uuid) {
        Some(value) => value,
        None => return,
    };

    if let Err(e) = vault.save_session(&session_path, &verified_master_key, None, true) {
        println!("Erro ao guardar sessão: {}", e);
        pause();
        return;
    }

    println!("Sessão criada em: {}", session_path);
    println!("Configuração inicial concluída! A aplicação vai fechar agora.");
    println!("Após reabrir pode usar a aplicação para gerar senhas e explorar as funcionalidades.");
    pause();
}

fn verify_master_key_for_save<C, G, F>(
    vault: &VaultCore<C, G, F>,
    domain_uuid: uuid::Uuid,
) -> Option<MasterKeyInput>
where
    C: CryptoService,
    G: GeneratorService,
    F: FileService,
{
    loop {
        println!();
        println!("--- Confirmar K1/K2 antes de gravar ---");

        let verification_key = ask_master_key()?;

        match vault.generate_password(
            PasswordRequest {
                domain_uuid,
                forced_variation: None,
            },
            &verification_key,
        ) {
            Ok(result) => {
                println!();
                println!("Senha derivada do primeiro domínio:");
                println!("{}", result.password);
                println!();
                return Some(verification_key);
            }
            Err(e) => {
                println!("K1/K2 não coincidem com a sessão atual: {}", e);
                println!("  1. Reintroduzir");
                println!("  2. Apagar sessão e recomeçar Configuração Inicial");

                match get_option() {
                    Some(1) => continue,
                    Some(2) => {
                        let _ = vault.close_session();
                        start_tutorial(vault);
                        return None;
                    }
                    _ => {
                        println!("Opção inválida.");
                        pause();
                        continue;
                    }
                }
            }
        }
    }
}

fn detect_device_name() -> String {
    env::var("COMPUTERNAME")
        .or_else(|_| env::var("HOSTNAME"))
        .unwrap_or_else(|_| "Meu_Pc".to_string())
        .trim()
        .to_string()
}
