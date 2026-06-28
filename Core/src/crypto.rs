#![allow(dead_code)]

use argon2::{Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    Key, XChaCha20Poly1305, XNonce,
};
use hkdf::Hkdf;
use sha2::Sha256;
use std::time::Duration;
use tiny_keccak::{Hasher, Kmac};
use web_time::Instant;
use zeroize::Zeroize;

pub const MIN_M_COST_KIB: u32 = 65536; // 64 MiB
pub const MIN_T_COST: u32 = 3;
pub const MIN_P_COST: u32 = 4;

pub const ARGON2_CALIBRATION_TARGET_MIN_MS: u128 = 500;
pub const ARGON2_CALIBRATION_TARGET_MAX_MS: u128 = 1_000;

const MAX_MEMORY_CAP_BYTES: u64 = 2 * 1024 * 1024 * 1024; // 2 GiB
const MAX_CALIBRATION_T_COST: u32 = 10_000;

const BENCHMARK_ITERATIONS: u32 = 3;

pub fn generate_salt() -> [u8; 32] {
    let mut salt = [0u8; 32];
    getrandom::fill(&mut salt).expect("getrandom: fonte de entropia do SO indisponível");
    salt
}

/// K1 e K2 são normalizados (NFC) individualmente e concatenados sem separador (secção 3).
pub fn normalize_secrets(inputs: &[&str]) -> Result<Vec<u8>, String> {
    crate::models::normalize_secrets(inputs)
}

/// HMAC-SHA256 para verificação de integridade em snapshots comprometidos, usando a seed do dispositivo como chave
pub fn hmac_sha256(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    use hmac::digest::KeyInit;
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC-SHA256 aceita qualquer tamanho de chave");
    mac.update(data);
    let result = mac.finalize().into_bytes();

    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

/// Valida parâmetros Argon2 vindos de fontes não confiáveis (evitando panic ou esgotamento de memória)
pub fn validate_argon2_params(m_cost_kib: u32, t_cost: u32, p_cost: u32) -> Result<(), String> {
    let max_m_kib = (MAX_MEMORY_CAP_BYTES / 1024) as u32;
    if t_cost == 0 || p_cost == 0 {
        return Err(format!("Parâmetros Argon2 inválidos: t={t_cost}, p={p_cost}"));
    }
    if m_cost_kib < 8 * p_cost || m_cost_kib > max_m_kib {
        return Err(format!(
            "m_cost fora do intervalo válido: {m_cost_kib} KiB (máx {max_m_kib} KiB)"
        ));
    }
    Ok(())
}

pub fn derive_key_argon2id(
    password: &[u8],
    salt: &[u8; 32],
    m_cost_kib: u32,
    t_cost: u32,
    p_cost: u32,
    output_len: usize,
) -> Result<Vec<u8>, String> {
    validate_argon2_params(m_cost_kib, t_cost, p_cost)?;

    let params = Params::new(m_cost_kib, t_cost, p_cost, Some(output_len))
        .map_err(|e| format!("Parâmetros Argon2 inválidos: {e}"))?;
    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, Version::V0x13, params);

    let mut output = vec![0u8; output_len];
    argon2
        .hash_password_into(password, salt, &mut output)
        .map_err(|e| format!("Falha na derivação Argon2id: {e}"))?;
    Ok(output)
}

pub fn kmac256_xof(key: &[u8; 32], context: &[u8], output: &mut [u8]) {
    let mut kmac = Kmac::v256(key, b"VAULTSEED-v1");
    kmac.update(context);
    kmac.finalize(output);
}

pub fn xchacha20poly1305_encrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    plaintext: &[u8],
    aad: &[u8],
) -> ([u8; 24], Vec<u8>) {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let nonce_bytes = XNonce::from_slice(nonce);
    let ciphertext = cipher
        .encrypt(nonce_bytes, Payload { msg: plaintext, aad })
        .expect("XChaCha20-Poly1305 encryption failed");

    (*nonce, ciphertext)
}

pub fn xchacha20poly1305_decrypt(
    key: &[u8; 32],
    nonce: &[u8; 24],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, String> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let nonce = XNonce::from_slice(nonce);

    cipher
        .decrypt(nonce, Payload { msg: ciphertext, aad })
        .map_err(|e| format!("Decryption failed: {}", e))
}

pub fn hkdf_extract_expand(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    output_len: usize,
) -> Vec<u8> {
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut okm = vec![0u8; output_len];
    hk.expand(info, &mut okm).expect("HKDF expansion failed");
    okm
}

pub fn derive_kek_session(
    k1: &str,
    k2: &str,
    salt_session: &[u8; 32],
    argon_m: u32,
    argon_t: u32,
    argon_p: u32,
    k_ext: Option<&[u8; 32]>,
    salt_hkdf: Option<&[u8; 32]>,
) -> Result<[u8; 32], String> {
    if k_ext.is_some() && salt_hkdf.is_none() {
        return Err("salt_hkdf is required when physical factor (k_ext) is present".to_string());
    }

    let k_user_bytes = zeroize::Zeroizing::new(normalize_secrets(&[k1, k2])?);

    let k_user_derived = zeroize::Zeroizing::new(derive_key_argon2id(
        &k_user_bytes,
        salt_session,
        argon_m,
        argon_t,
        argon_p,
        32,
    )?);
    drop(k_user_bytes);

    let combined = zeroize::Zeroizing::new(if let Some(ext_key) = k_ext {
        let salt = salt_hkdf.unwrap();
        let k_ext_derived =
            zeroize::Zeroizing::new(hkdf_extract_expand(ext_key, Some(salt), b"SESSION_HW_V1", 32));
        [k_user_derived.as_slice(), k_ext_derived.as_slice()].concat()
    } else {
        k_user_derived.to_vec()
    });
    drop(k_user_derived);

    let final_key_vec =
        zeroize::Zeroizing::new(hkdf_extract_expand(&combined, None, b"SESSION_FINAL_V1", 32));
    drop(combined);

    let final_key: [u8; 32] = final_key_vec
        .as_slice()
        .try_into()
        .map_err(|_| "HKDF output length error".to_string())?;

    Ok(final_key)
}

pub fn benchmark_argon2(m_cost_kib: u32, t_cost: u32, p_cost: u32) -> Duration {
    let dummy = ["benchmark_key_1", "benchmark_key_2"];
    let mut normalized = normalize_secrets(&dummy).expect("benchmark normalize failed");
    let salt = [0u8; 32];

    let mut total = Duration::ZERO;
    for _ in 0..BENCHMARK_ITERATIONS {
        let start = Instant::now();
        let _ = derive_key_argon2id(&normalized, &salt, m_cost_kib, t_cost, p_cost, 32)
            .expect("benchmark com parâmetros constantes válidos");
        total += start.elapsed();
    }

    normalized.zeroize();
    total / BENCHMARK_ITERATIONS
}

fn benchmark_argon2_once(m_cost_kib: u32, t_cost: u32, p_cost: u32) -> Duration {
    let dummy = ["benchmark_key_1", "benchmark_key_2"];
    let mut normalized = normalize_secrets(&dummy).expect("benchmark normalize failed");
    let salt = [0u8; 32];

    let start = Instant::now();
    let _ = derive_key_argon2id(&normalized, &salt, m_cost_kib, t_cost, p_cost, 32)
        .expect("benchmark com parâmetros constantes válidos");
    let elapsed = start.elapsed();

    normalized.zeroize();
    elapsed
}

pub struct CalibrationResult {
    pub m_cost_kib: u32,
    pub t_cost: u32,
    pub p_cost: u32,
    pub duration: Duration,
}

pub struct Calibrator {
    target_min_ms: Option<u128>,
    target_max_ms: Option<u128>,
}

impl Default for Calibrator {
    fn default() -> Self {
        Self::new()
    }
}

impl Calibrator {
    pub fn new() -> Self {
        Self {
            target_min_ms: None,
            target_max_ms: None,
        }
    }

    pub fn with_min(mut self, min: u128) -> Self {
        self.target_min_ms = Some(min);
        self
    }

    pub fn with_max(mut self, max: u128) -> Self {
        self.target_max_ms = Some(max);
        self
    }

    pub fn run(self) -> CalibrationResult {
        let min_ms = self.target_min_ms.unwrap_or(ARGON2_CALIBRATION_TARGET_MIN_MS);
        let max_ms = self.target_max_ms.unwrap_or(ARGON2_CALIBRATION_TARGET_MAX_MS);

        let available_mem_kib = available_memory_kib();
        let memory_limit = (available_mem_kib / 4).min(MAX_MEMORY_CAP_BYTES / 1024) as u32;
        let cores = std::thread::available_parallelism()
            .map(|n| n.get() as u32)
            .unwrap_or(1)
            .max(1);

        let mut m_cost = MIN_M_COST_KIB;
        let mut t_cost = MIN_T_COST;
        let mut p_cost = MIN_P_COST;

        let mut duration = benchmark_argon2_once(m_cost, t_cost, p_cost);
        if duration.as_millis() > max_ms {
            return build_result(m_cost, t_cost, p_cost, benchmark_argon2(m_cost, t_cost, p_cost));
        }

        let multipliers: [f64; 3] = [2.0, 1.5, 1.25];

        let mut combo_index = 0;
        while duration.as_millis() < min_ms && combo_index < multipliers.len() {
            let multiplier = multipliers[combo_index];
            let draft_m = (((m_cost as f64) * multiplier).round() as u32).min(memory_limit);
            let draft_t = (((t_cost as f64) * multiplier).round() as u32)
                .max(t_cost + 1)
                .min(MAX_CALIBRATION_T_COST);
            let draft_p = (((p_cost as f64) * multiplier).round() as u32)
                .max(p_cost + 1)
                .min(cores);

            if draft_m <= m_cost && draft_t <= t_cost && draft_p <= p_cost {
                combo_index += 1;
                continue;
            }

            let test_duration = benchmark_argon2_once(draft_m, draft_t, draft_p);

            if test_duration.as_millis() > max_ms {
                combo_index += 1;
                continue;
            }

            m_cost = draft_m;
            t_cost = draft_t;
            p_cost = draft_p;
            duration = test_duration;
        }

        m_cost = grow_then_fine_tune(
            m_cost, memory_limit, &multipliers, min_ms, max_ms, &mut duration,
            |m| benchmark_argon2_once(m, t_cost, p_cost),
        );

        t_cost = grow_then_fine_tune(
            t_cost, MAX_CALIBRATION_T_COST, &multipliers, min_ms, max_ms, &mut duration,
            |t| benchmark_argon2_once(m_cost, t, p_cost),
        );

        let mut consecutive_failures = 0;

        while duration.as_millis() < min_ms && consecutive_failures < 3 {
            let draft_p = p_cost.saturating_add(1).min(cores);

            if draft_p == p_cost {
                consecutive_failures += 1;
                continue;
            }

            let test_duration = benchmark_argon2_once(m_cost, t_cost, draft_p);

            if test_duration.as_millis() > max_ms {
                consecutive_failures += 1;
                continue;
            }

            p_cost = draft_p;
            duration = test_duration;
            consecutive_failures = 0;
        }

        let final_duration = benchmark_argon2(m_cost, t_cost, p_cost);
        build_result(m_cost, t_cost, p_cost, final_duration)
    }
}

fn grow_then_fine_tune(
    mut value: u32,
    max_value: u32,
    multipliers: &[f64; 3],
    min_ms: u128,
    max_ms: u128,
    duration: &mut Duration,
    mut benchmark: impl FnMut(u32) -> Duration,
) -> u32 {
    let mut mult_index = 0;

    while duration.as_millis() < min_ms && value < max_value && mult_index < multipliers.len() {
        let multiplier = multipliers[mult_index];
        let draft = (((value as f64) * multiplier).round() as u32).min(max_value);

        if draft <= value {
            mult_index += 1;
            continue;
        }

        let test_duration = benchmark(draft);

        if test_duration.as_millis() > max_ms {
            mult_index += 1;
            continue;
        }

        value = draft;
        *duration = test_duration;
    }

    if duration.as_millis() < min_ms && value < max_value && mult_index >= multipliers.len() {
        let linear_step = (value / 20).max(1); // ~5% do valor actual
        let mut linear_failures = 0;

        while duration.as_millis() < min_ms && value < max_value && linear_failures < 3 {
            let draft = value.saturating_add(linear_step).min(max_value);

            if draft <= value {
                break;
            }

            let test_duration = benchmark(draft);

            if test_duration.as_millis() > max_ms {
                linear_failures += 1;
                continue;
            }

            value = draft;
            *duration = test_duration;
            linear_failures = 0;
        }
    }

    value
}

fn available_memory_kib() -> u64 {
    #[cfg(not(target_family = "wasm"))]
    {
        let mut sys = sysinfo::System::new();
        sys.refresh_memory();
        let available = sys.available_memory() / 1024;
        if available > 0 {
            return available;
        }
    }

    MAX_MEMORY_CAP_BYTES / 1024
}

fn build_result(m: u32, t: u32, p: u32, d: Duration) -> CalibrationResult {
    CalibrationResult {
        m_cost_kib: m,
        t_cost: t.max(MIN_T_COST),
        p_cost: p.max(MIN_P_COST),
        duration: d,
    }
}