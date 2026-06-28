#![allow(dead_code)]

use std::sync::{Arc, RwLock};
use std::collections::HashMap;

use chrono::Utc;
use sha2::{Digest, Sha256};
use uuid::Uuid;
use zeroize::Zeroize;
use std::time::Duration;
use web_time::Instant;

use crate::errors::{
    CommonError, CoreError, CoreResult, CryptoError, DeviceError, DomainError,
    FileError, PasswordError, RestrictionError, SessionError,
    StaticPasswordError, ValidationError, XorError,
};

use crate::generator;

use crate::models::{
    build_bit_lists, canonicalize_domain, resolve_sequence,
    Argon2Params, CharacterList, CompromiseRecord, CryptoContext, Device, Domain,
    ExportEntry, ExportPrepared, ExportDevicePrepared, ExportDerivation, ExportStaticEntry, ExportOutputMeta,
    FrozenGeneratorConfig, GenerationParams, LocalState,
    StaticPasswordPlaintext,
    MaskOrLiteral, PasswordExportData, Restriction, SeedEnvelope,
    SessionFile, SessionHeader, SessionPayload, StaticFolder, StaticPassword,
};

pub use crate::models::{
    AppState, DecryptedSeed, DomainSearchResult, ExportBenchmarkReport, GeneratedPassword,
    MasterKeyInput, PasswordRequest, SecretBenchmarkReport, SessionOverview, SessionRuntime,
    SharedAppState, StaticPasswordSearchResult,
};

const RESERVED_BIT_DIGITS: u8 = 0;
const RESERVED_BIT_LOWERCASE: u8 = 1;
const RESERVED_BIT_UPPERCASE: u8 = 2;
const RESERVED_BIT_SYMBOLS: u8 = 3;
const RESERVED_BIT_EMOJIS: u8 = 4;
const RESERVED_BIT_SYMBOLS2: u8 = 5;
const RESERVED_BIT_FONT_FULL: u8 = 6;
const RESERVED_BITS_MAX: u8 = 15;
const USER_BIT_MIN: u8 = 16;
const USER_BIT_MAX: u8 = 31;

pub const USER_CHAR_LIST_BIT_MIN: u8 = USER_BIT_MIN;
pub const USER_CHAR_LIST_BIT_MAX: u8 = USER_BIT_MAX;
pub const USER_CHAR_LIST_SLOT_COUNT: u8 = USER_BIT_MAX - USER_BIT_MIN + 1;

const DEFAULT_RESTRICTION_NAME: &str = "padrão";
const DEFAULT_RESTRICTION_MASK: u32 = 7; // bits 0+1+2

const EMOJI_FONT_RANGES: &[(u32, u32)] = &[
    (0x200d, 0x200d), (0x203c, 0x203c), (0x2049, 0x2049), (0x20e3, 0x20e3), (0x2122, 0x2122), (0x2139, 0x2139), (0x2194, 0x2199), (0x21a9, 0x21aa),
    (0x231a, 0x231b), (0x2328, 0x2328), (0x23cf, 0x23cf), (0x23e9, 0x23f3), (0x23f8, 0x23fa), (0x24c2, 0x24c2), (0x25aa, 0x25ab), (0x25b6, 0x25b6),
    (0x25c0, 0x25c0), (0x25fb, 0x25fe), (0x2600, 0x2604), (0x260e, 0x260e), (0x2611, 0x2611), (0x2614, 0x2615), (0x2618, 0x2618), (0x261d, 0x261d),
    (0x2620, 0x2620), (0x2622, 0x2623), (0x2626, 0x2626), (0x262a, 0x262a), (0x262e, 0x262f), (0x2638, 0x263a), (0x2640, 0x2640), (0x2642, 0x2642),
    (0x2648, 0x2653), (0x265f, 0x2660), (0x2663, 0x2663), (0x2665, 0x2666), (0x2668, 0x2668), (0x267b, 0x267b), (0x267e, 0x267f), (0x2692, 0x2697),
    (0x2699, 0x2699), (0x269b, 0x269c), (0x26a0, 0x26a1), (0x26a7, 0x26a7), (0x26aa, 0x26ab), (0x26b0, 0x26b1), (0x26bd, 0x26be), (0x26c4, 0x26c5),
    (0x26c8, 0x26c8), (0x26ce, 0x26cf), (0x26d1, 0x26d1), (0x26d3, 0x26d4), (0x26e9, 0x26ea), (0x26f0, 0x26f5), (0x26f7, 0x26fa), (0x26fd, 0x26fd),
    (0x2702, 0x2702), (0x2705, 0x2705), (0x2708, 0x270d), (0x270f, 0x270f), (0x2712, 0x2712), (0x2714, 0x2714), (0x2716, 0x2716), (0x271d, 0x271d),
    (0x2721, 0x2721), (0x2728, 0x2728), (0x2733, 0x2734), (0x2744, 0x2744), (0x2747, 0x2747), (0x274c, 0x274c), (0x274e, 0x274e), (0x2753, 0x2755),
    (0x2757, 0x2757), (0x2763, 0x2764), (0x2795, 0x2797), (0x27a1, 0x27a1), (0x27b0, 0x27b0), (0x27bf, 0x27bf), (0x2934, 0x2935), (0x2b05, 0x2b07),
    (0x2b1b, 0x2b1c), (0x2b50, 0x2b50), (0x2b55, 0x2b55), (0x3030, 0x3030), (0x303d, 0x303d), (0x3297, 0x3297), (0x3299, 0x3299), (0xfe0e, 0xfe0f),
    (0x1f004, 0x1f004), (0x1f0cf, 0x1f0cf), (0x1f170, 0x1f171), (0x1f17e, 0x1f17f), (0x1f18e, 0x1f18e), (0x1f191, 0x1f19a), (0x1f1e6, 0x1f1ff), (0x1f201, 0x1f202),
    (0x1f21a, 0x1f21a), (0x1f22f, 0x1f22f), (0x1f232, 0x1f23a), (0x1f250, 0x1f251), (0x1f300, 0x1f321), (0x1f324, 0x1f393), (0x1f396, 0x1f397), (0x1f399, 0x1f39b),
    (0x1f39e, 0x1f3f0), (0x1f3f3, 0x1f3f5), (0x1f3f7, 0x1f4fd), (0x1f4ff, 0x1f53d), (0x1f549, 0x1f54e), (0x1f550, 0x1f567), (0x1f56f, 0x1f570), (0x1f573, 0x1f57a),
    (0x1f587, 0x1f587), (0x1f58a, 0x1f58d), (0x1f590, 0x1f590), (0x1f595, 0x1f596), (0x1f5a4, 0x1f5a5), (0x1f5a8, 0x1f5a8), (0x1f5b1, 0x1f5b2), (0x1f5bc, 0x1f5bc),
    (0x1f5c2, 0x1f5c4), (0x1f5d1, 0x1f5d3), (0x1f5dc, 0x1f5de), (0x1f5e1, 0x1f5e1), (0x1f5e3, 0x1f5e3), (0x1f5e8, 0x1f5e8), (0x1f5ef, 0x1f5ef), (0x1f5f3, 0x1f5f3),
    (0x1f5fa, 0x1f64f), (0x1f680, 0x1f6c5), (0x1f6cb, 0x1f6d2), (0x1f6d5, 0x1f6d7), (0x1f6dc, 0x1f6e5), (0x1f6e9, 0x1f6e9), (0x1f6eb, 0x1f6ec), (0x1f6f0, 0x1f6f0),
    (0x1f6f3, 0x1f6fc), (0x1f7e0, 0x1f7eb), (0x1f7f0, 0x1f7f0), (0x1f90c, 0x1f93a), (0x1f93c, 0x1f945), (0x1f947, 0x1f9ff), (0x1fa70, 0x1fa7c), (0x1fa80, 0x1fa88),
    (0x1fa90, 0x1fabd), (0x1fabf, 0x1fac5), (0x1face, 0x1fadb), (0x1fae0, 0x1fae8), (0x1faf0, 0x1faf8), (0xe0030, 0xe0039), (0xe0061, 0xe007a), (0xe007f, 0xe007f),
    (0xfe4e5, 0xfe4ee), (0xfe82c, 0xfe82c), (0xfe82e, 0xfe837),
];

const SYMBOLS_UNICODE_RANGES: &[(u32, u32)] = &[
    (0xa1, 0xac), (0xae, 0xff), (0x215b, 0x215e), (0x2212, 0x2212), (0x25cc, 0x25cc),
];

const FONT_FULL_RANGES: &[(u32, u32)] = &[
    (0x20, 0x7e), (0xa1, 0xac), (0xae, 0x17f), (0x186, 0x186), (0x18e, 0x190), (0x192, 0x192), (0x194, 0x194), (0x196, 0x196),
    (0x19a, 0x19b), (0x19d, 0x19d), (0x1a0, 0x1a1), (0x1a9, 0x1a9), (0x1af, 0x1b2), (0x1b7, 0x1b7), (0x1cd, 0x1ce), (0x1dd, 0x1dd),
    (0x1e4, 0x1e7), (0x1ea, 0x1eb), (0x1f0, 0x1f0), (0x1fa, 0x1ff), (0x218, 0x21b), (0x21e, 0x21f), (0x232, 0x233), (0x237, 0x237),
    (0x23a, 0x23b), (0x23d, 0x23e), (0x245, 0x245), (0x251, 0x251), (0x254, 0x254), (0x259, 0x259), (0x25b, 0x25b), (0x262, 0x263),
    (0x269, 0x26c), (0x272, 0x272), (0x283, 0x283), (0x28a, 0x28c), (0x292, 0x292), (0x294, 0x295), (0x29f, 0x29f), (0x2a7, 0x2a7),
    (0x2b7, 0x2b8), (0x2bb, 0x2bc), (0x2c0, 0x2c0), (0x2c6, 0x2c7), (0x2c9, 0x2c9), (0x2d0, 0x2d0), (0x2d8, 0x2dd), (0x374, 0x375),
    (0x37e, 0x37e), (0x384, 0x38a), (0x38c, 0x38c), (0x38e, 0x3a1), (0x3a3, 0x3cf), (0x3d7, 0x3d7), (0x400, 0x45f), (0x490, 0x493),
    (0x496, 0x497), (0x49a, 0x49b), (0x4a2, 0x4a3), (0x4ae, 0x4b3), (0x4b6, 0x4b7), (0x4ba, 0x4bb), (0x4c0, 0x4c0), (0x4cf, 0x4cf),
    (0x4d8, 0x4d9), (0x4e2, 0x4e3), (0x4e8, 0x4e9), (0x4ee, 0x4ef), (0x1d00, 0x1d00), (0x1dbb, 0x1dbb), (0x1dbf, 0x1dbf), (0x1e24, 0x1e25),
    (0x1e30, 0x1e30), (0x1e32, 0x1e37), (0x1e3a, 0x1e3b), (0x1e48, 0x1e49), (0x1e50, 0x1e53), (0x1e5a, 0x1e5b), (0x1e62, 0x1e63), (0x1e6e, 0x1e6e),
    (0x1e80, 0x1e85), (0x1e9e, 0x1e9e), (0x1ea0, 0x1ef9), (0x2010, 0x2010), (0x2013, 0x2015), (0x2017, 0x201e), (0x2020, 0x2022), (0x2024, 0x2024),
    (0x2026, 0x2026), (0x2030, 0x2030), (0x2032, 0x2033), (0x2039, 0x203a), (0x203c, 0x203c), (0x203e, 0x203e), (0x2044, 0x2044), (0x2070, 0x2070),
    (0x2074, 0x2079), (0x207f, 0x2089), (0x20a0, 0x20a1), (0x20a3, 0x20a4), (0x20a6, 0x20ae), (0x20b1, 0x20b2), (0x20b4, 0x20b5), (0x20b8, 0x20ba),
    (0x20bc, 0x20be), (0x2105, 0x2105), (0x2113, 0x2113), (0x2116, 0x2117), (0x2122, 0x2122), (0x2126, 0x2126), (0x212e, 0x212e), (0x215b, 0x215e),
    (0x2212, 0x2212), (0x25cc, 0x25cc), (0x2c62, 0x2c62), (0x2c6d, 0x2c6d), (0xfb01, 0xfb02),
];

fn chars_from_ranges(ranges: &[(u32, u32)]) -> Vec<String> {
    ranges
        .iter()
        .flat_map(|&(lo, hi)| (lo..=hi).filter_map(char::from_u32))
        .map(|c| c.to_string())
        .collect()
}

fn emoji_supported(s: &str) -> bool {
    if s.chars().count() != 1 {
        return false;
    }
    s.chars().all(|c| char_in_emoji_font(c))
}

pub fn char_in_emoji_font(c: char) -> bool {
    let cp = c as u32;
    EMOJI_FONT_RANGES.iter().any(|&(lo, hi)| cp >= lo && cp <= hi)
}

pub fn build_default_bit_lists() -> HashMap<u8, Vec<String>> {
    let mut map = HashMap::new();
    map.insert(0, ('0'..='9').map(|c| c.to_string()).collect());
    map.insert(1, ('a'..='z').map(|c| c.to_string()).collect());
    map.insert(2, ('A'..='Z').map(|c| c.to_string()).collect());
    map.insert(
        3,
        ('!'..='/')          // Primeiro bloco: ! " # $ % & ' ( ) * + , - . /
            .chain(':'..='@') // Segundo bloco:  : ; < = > ? @
            .chain('['..='`') // Terceiro bloco: [ \ ] ^ _ `
            .chain('{'..='~') // Quarto bloco:   { | } ~
            .map(|c| c.to_string())
            .collect(),
    );
    map.insert(
        4,
        emojis::iter()
            .map(|e| e.as_str().to_string())
            .filter(|s| emoji_supported(s))
            .collect(),
    );
    map.insert(5, chars_from_ranges(SYMBOLS_UNICODE_RANGES));
    map.insert(6, chars_from_ranges(FONT_FULL_RANGES));
    map
}

fn build_reserved_char_lists() -> Vec<CharacterList> {
    let bit_lists = build_default_bit_lists();

    vec![
        CharacterList {
            uuid: Uuid::new_v4(),
            name: "Dígitos".to_string(),
            bit: RESERVED_BIT_DIGITS,
            elements: bit_lists.get(&RESERVED_BIT_DIGITS).cloned().unwrap_or_default(),
        },
        CharacterList {
            uuid: Uuid::new_v4(),
            name: "Minúsculas".to_string(),
            bit: RESERVED_BIT_LOWERCASE,
            elements: bit_lists.get(&RESERVED_BIT_LOWERCASE).cloned().unwrap_or_default(),
        },
        CharacterList {
            uuid: Uuid::new_v4(),
            name: "Maiúsculas".to_string(),
            bit: RESERVED_BIT_UPPERCASE,
            elements: bit_lists.get(&RESERVED_BIT_UPPERCASE).cloned().unwrap_or_default(),
        },
        CharacterList {
            uuid: Uuid::new_v4(),
            name: "Símbolos".to_string(),
            bit: RESERVED_BIT_SYMBOLS,
            elements: bit_lists.get(&RESERVED_BIT_SYMBOLS).cloned().unwrap_or_default(),
        },
        CharacterList {
            uuid: Uuid::new_v4(),
            name: "Emojis".to_string(),
            bit: RESERVED_BIT_EMOJIS,
            elements: bit_lists.get(&RESERVED_BIT_EMOJIS).cloned().unwrap_or_default(),
        },
        CharacterList {
            uuid: Uuid::new_v4(),
            name: "Símbolos extendidos".to_string(),
            bit: RESERVED_BIT_SYMBOLS2,
            elements: bit_lists.get(&RESERVED_BIT_SYMBOLS2).cloned().unwrap_or_default(),
        },
        CharacterList {
            uuid: Uuid::new_v4(),
            name: "Caracteres da fonte NotoSans".to_string(),
            bit: RESERVED_BIT_FONT_FULL,
            elements: bit_lists.get(&RESERVED_BIT_FONT_FULL).cloned().unwrap_or_default(),
        },
    ]
}

fn is_reserved_bit(bit: u8) -> bool {
    bit <= RESERVED_BITS_MAX
}

pub trait CryptoService: Send + Sync {
    fn generate_random_32(&self) -> Result<[u8; 32], CryptoError>;
    fn generate_random_24(&self) -> Result<[u8; 24], CryptoError>;

    fn derive_argon2(
        &self,
        password: &[u8],
        salt: &[u8; 32],
        m_cost_kib: u32,
        t_cost: u32,
        p_cost: u32,
    ) -> Result<[u8; 32], CryptoError>;

    fn derive_kek_session(
        &self,
        k1: &str,
        k2: &str,
        salt_session: &[u8; 32],
        m_cost_kib: u32,
        t_cost: u32,
        p_cost: u32,
        k_ext: Option<&[u8; 32]>,
        salt_hkdf: Option<&[u8; 32]>,
    ) -> Result<[u8; 32], CryptoError>;

    fn encrypt_aead(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 24],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;

    fn decrypt_aead(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 24],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError>;

    fn derive_kmac256(
        &self,
        seed: &[u8; 32],
        context: &str,
        output_len: usize,
    ) -> Result<Vec<u8>, CryptoError>;

    fn hmac_sha256(
        &self,
        key: &[u8; 32],
        data: &[u8],
    ) -> Result<[u8; 32], CryptoError>;
}

pub trait GeneratorService: Send + Sync {
    fn generate_password(
        &self,
        entropy: &[u8],
        restriction: &Restriction,
        device: &Device,
    ) -> Result<GeneratedPassword, PasswordError>;
}

pub trait FileService: Send + Sync {
    fn save_session_file(&self, path: &str, session: &SessionFile) -> Result<(), FileError>;
    fn load_session_file(&self, path: &str) -> Result<SessionFile, FileError>;
    fn delete_session_file(&self, path: &str) -> Result<(), FileError>;

    fn create_xor_files(
        &self,
        k1: &str,
        k2: &str,
        path_a: &str,
        path_b: &str,
    ) -> Result<(), XorError>;

    fn read_xor_files(
        &self,
        path_a: &str,
        path_b: &str,
    ) -> Result<(String, String), XorError>;

    fn local_state_path(&self) -> Result<std::path::PathBuf, crate::errors::LocalStateError>;
    fn default_session_path(&self) -> Result<std::path::PathBuf, crate::errors::LocalStateError>;
    fn load_local_state(&self) -> Result<LocalState, crate::errors::LocalStateError>;
    fn save_local_state(&self, local_state: &LocalState) -> Result<std::path::PathBuf, crate::errors::LocalStateError>;
    fn delete_local_state(&self) -> Result<(), crate::errors::LocalStateError>;
}

#[derive(Debug, Clone, Copy)]
enum BenchmarkDistribution {
    RoundRobin,
    PerDevice,
}

const DEFAULT_BENCHMARK_DEVICE_COUNT: usize = 2;
const DEFAULT_BENCHMARK_DOMAINS_PER_DEVICE: usize = 10;
const DEFAULT_BENCHMARK_STATIC_PASSWORDS_PER_DEVICE: usize = 10;
const DEFAULT_BENCHMARK_K1_LEN: usize = 8;
const DEFAULT_BENCHMARK_K2_LEN: usize = 8;

#[derive(Clone)]
pub struct VaultCore<C, G, F>
where
    C: CryptoService,
    G: GeneratorService,
    F: FileService,
{
    state: SharedAppState,
    pub crypto: C,
    pub generator: G,
    pub files: F,
    persist_local_state: bool,
}

impl<C, G, F> VaultCore<C, G, F>
where
    C: CryptoService,
    G: GeneratorService,
    F: FileService,
{
    pub fn new(
        local_state: LocalState,
        crypto: C,
        generator: G,
        files: F,
        persist_local_state: bool,
    ) -> Self {
        let initial_local_state = if persist_local_state {
            files.load_local_state().unwrap_or(local_state)
        } else {
            local_state
        };

        if persist_local_state {
            let _ = files.save_local_state(&initial_local_state);
        }

        Self {
            state: Arc::new(RwLock::new(AppState::new(initial_local_state))),
            crypto,
            generator,
            files,
            persist_local_state,
        }
    }

    pub fn state(&self) -> SharedAppState {
        self.state.clone()
    }

    /// Recovers from a poisoned lock instead of panicking.
    pub fn read_state(&self) -> std::sync::RwLockReadGuard<'_, AppState> {
        match self.state.read() {
            Ok(g) => g,
            Err(poison) => poison.into_inner(),
        }
    }

    pub fn write_state(&self) -> std::sync::RwLockWriteGuard<'_, AppState> {
        match self.state.write() {
            Ok(g) => g,
            Err(poison) => poison.into_inner(),
        }
    }

    fn with_session<R>(
        &self,
        f: impl FnOnce(&SessionRuntime) -> CoreResult<R>,
    ) -> CoreResult<R> {
        let state = self.read_state();
        let session = state.require_session()?;
        f(session)
    }

    fn with_session_mut<R>(
        &self,
        f: impl FnOnce(&mut SessionRuntime) -> CoreResult<R>,
    ) -> CoreResult<R> {
        let mut state = self.write_state();
        let session = state.require_session_mut()?;
        f(session)
    }

    pub fn get_session_header(&self) -> CoreResult<SessionHeader> {
        self.with_session(|session| Ok(session.session_file.header.clone()))
    }

    pub fn is_session_hardware_enabled(&self) -> CoreResult<bool> {
        self.with_session(|session| Ok(session.session_file.header.hardware_enabled))
    }

    pub fn get_session_overview(&self) -> CoreResult<SessionOverview> {
        self.with_session(|session| {
            Ok(SessionOverview {
                header: session.session_file.header.clone(),
                nonce_global: session.session_file.nonce_global,
                ciphertext_global_len: session.session_file.ciphertext_global.len(),
                device_count: session.payload.devices.len(),
                restriction_count: session.payload.restrictions.len(),
                domain_count: session.payload.domains.len(),
                static_password_count: session.payload.static_passwords.len(),
            })
        })
    }

    pub fn run_fixed_benchmark(&self) -> CoreResult<Vec<SecretBenchmarkReport>> {
        let backup = self.take_session_snapshot();
        let result = (|| {
            let two_devices = self.run_benchmark_case(
                2,
                100,
                100,
                BenchmarkDistribution::RoundRobin,
                Argon2Params {
                    m_cost_kib: crate::crypto::MIN_M_COST_KIB,
                    t_cost: crate::crypto::MIN_T_COST,
                    p_cost: crate::crypto::MIN_P_COST,
                },
                DEFAULT_BENCHMARK_K1_LEN,
                DEFAULT_BENCHMARK_K2_LEN,
            )?;
            let one_device = self.run_benchmark_case(
                1,
                100,
                100,
                BenchmarkDistribution::RoundRobin,
                Argon2Params {
                    m_cost_kib: crate::crypto::MIN_M_COST_KIB,
                    t_cost: crate::crypto::MIN_T_COST,
                    p_cost: crate::crypto::MIN_P_COST,
                },
                DEFAULT_BENCHMARK_K1_LEN,
                DEFAULT_BENCHMARK_K2_LEN,
            )?;
            Ok(vec![two_devices, one_device])
        })();
        self.restore_session_snapshot(backup);
        result
    }

    pub fn run_export_benchmark(&self) -> CoreResult<ExportBenchmarkReport> {
        let backup = self.take_session_snapshot();
        let result = (|| {
            let local_state = self.get_local_state();
            let session_argon2 = Self::benchmark_argon2_params(&local_state);
            let device_count = local_state.benchmark_device_count.unwrap_or(DEFAULT_BENCHMARK_DEVICE_COUNT);
            let domains_per_device = local_state.benchmark_domains_per_device.unwrap_or(DEFAULT_BENCHMARK_DOMAINS_PER_DEVICE);
            let static_passwords_per_device = local_state.benchmark_static_passwords_per_device.unwrap_or(DEFAULT_BENCHMARK_STATIC_PASSWORDS_PER_DEVICE);
            let k1_len = local_state.benchmark_k1_len.unwrap_or(DEFAULT_BENCHMARK_K1_LEN);
            let k2_len = local_state.benchmark_k2_len.unwrap_or(DEFAULT_BENCHMARK_K2_LEN);

            let master_key = MasterKeyInput::new(
                Self::benchmark_secret(k1_len, '1'),
                Self::benchmark_secret(k2_len, '2'),
            );

            let setup_start = Instant::now();
            self.create_new_session([0x22; 32], session_argon2.clone(), false, None)?;

            for index in 0..device_count {
                let device_uuid = Uuid::from_u128(0xC0DE_0000_0000_0000_0000_0000_0000_0001u128 + index as u128,);
                let salt_device = [0x31 + index as u8; 32];
                let seed = [0x51 + index as u8; 32];
                let seed_envelope = self.encrypt_device_seed_envelope(
                    device_uuid,
                    &salt_device,
                    &session_argon2,
                    &master_key,
                    &seed,
                )?;

                self.add_device_with_details(
                    &format!("benchmark-device-{}", index + 1),
                    device_uuid,
                    salt_device,
                    session_argon2.clone(),
                    seed_envelope,
                )?;

                let restriction_uuid = self
                    .list_restrictions(device_uuid)?
                    .first()
                    .ok_or(SessionError::SessionCorrupted)?
                    .uuid;

                for domain_index in 0..domains_per_device {
                    let identifier = format!(
                        "bench-domain-device-{}-{:03}.example",
                        index + 1,
                        domain_index + 1
                    );
                    self.add_domain(&identifier, restriction_uuid)?;
                }

                let device = self.get_device(device_uuid)?;
                let decrypted = self.decrypt_device_seed_internal(&device, &master_key)?;

                for static_index in 0..static_passwords_per_device {
                    let folder = format!("/bench/device-{}/static", index + 1);
                    let label = format!("static-device-{}-{:03}", index + 1, static_index + 1);
                    let plaintext = StaticPasswordPlaintext {
                        label: label.clone(),
                        value: format!("fixed-value-device-{}-{:03}", index + 1, static_index + 1),
                        notes: "benchmark".to_string(),
                        compromised: false,
                    };

                    self.add_static_password_with_seed(
                        device_uuid,
                        &folder,
                        &label,
                        plaintext,
                        &decrypted.seed,
                    )?;
                }
            }

            let setup_duration = setup_start.elapsed();

            let prepare_start = Instant::now();
            let prepared = self.prepare_export(&[], &[], &[], &[], true, true)?;
            let prepare_duration = prepare_start.elapsed();

            let export_start = Instant::now();
            let (_export, generation_duration) = self.execute_export(&prepared, &master_key)?;
            let export_duration = export_start.elapsed();
            let total_duration = setup_duration + prepare_duration + export_duration;

            Ok(ExportBenchmarkReport {
                device_count,
                domain_count: prepared
                    .devices
                    .iter()
                    .map(|device| device.derivations.len())
                    .sum(),
                static_password_count: prepared
                    .devices
                    .iter()
                    .map(|device| device.static_entries.len())
                    .sum(),
                generation_duration,
                setup_duration,
                prepare_duration,
                export_duration,
                total_duration,
            })
        })();
        self.restore_session_snapshot(backup);
        result
    }

    pub fn run_custom_benchmark(
        &self,
        device_count: usize,
        domains_per_device: usize,
        static_passwords_per_device: usize,
    ) -> CoreResult<SecretBenchmarkReport> {
        let backup = self.take_session_snapshot();
        let result = self.run_benchmark_case(
            device_count,
            domains_per_device,
            static_passwords_per_device,
            BenchmarkDistribution::PerDevice,
            Argon2Params {
                m_cost_kib: crate::crypto::MIN_M_COST_KIB,
                t_cost: crate::crypto::MIN_T_COST,
                p_cost: crate::crypto::MIN_P_COST,
            },
            DEFAULT_BENCHMARK_K1_LEN,
            DEFAULT_BENCHMARK_K2_LEN,
        );
        self.restore_session_snapshot(backup);
        result
    }

    pub fn set_benchmark_argon2_params(
        &self,
        m_cost_kib: Option<u32>,
        t_cost: Option<u32>,
        p_cost: Option<u32>,
    ) -> CoreResult<()> {
        let mut state = self.write_state();
        state.local_state.benchmark_argon2_m_cost_kib = m_cost_kib;
        state.local_state.benchmark_argon2_t_cost = t_cost;
        state.local_state.benchmark_argon2_p_cost = p_cost;
        let snapshot = state.local_state.clone();
        drop(state);
        self.persist_local_state(snapshot)?;
        Ok(())
    }

    pub fn set_benchmark_export_settings(
        &self,
        device_count: Option<usize>,
        domains_per_device: Option<usize>,
        static_passwords_per_device: Option<usize>,
        k1_len: Option<usize>,
        k2_len: Option<usize>,
    ) -> CoreResult<()> {
        let mut state = self.write_state();
        state.local_state.benchmark_device_count = device_count;
        state.local_state.benchmark_domains_per_device = domains_per_device;
        state.local_state.benchmark_static_passwords_per_device = static_passwords_per_device;
        state.local_state.benchmark_k1_len = k1_len;
        state.local_state.benchmark_k2_len = k2_len;
        let snapshot = state.local_state.clone();
        drop(state);
        self.persist_local_state(snapshot)?;
        Ok(())
    }

    pub fn create_new_session(
        &self,
        salt_session: [u8; 32],
        argon2: Argon2Params,
        hardware_enabled: bool,
        salt_hkdf: Option<[u8; 32]>,
    ) -> CoreResult<()> {
        let mut state = self.write_state();
        if state.has_open_session() {
            return Err(SessionError::SessionAlreadyOpen.into());
        }

        let header = SessionHeader::new(salt_session, argon2, hardware_enabled, salt_hkdf);
        let nonce_global = self.crypto.generate_random_24()?;
        let payload = SessionPayload::new();

        let session_file = SessionFile {
            header,
            nonce_global,
            ciphertext_global: Vec::new(),
            session_hmac: None,
        };

        state.session = Some(SessionRuntime::new(session_file, payload));
        Ok(())
    }

    pub fn open_session(
        &self,
        session_file: SessionFile,
        master_key: &MasterKeyInput,
        k_ext: Option<&[u8; 32]>,
        verify_hmac: bool,
    ) -> CoreResult<()> {
        master_key.validate()?;

        {
            let state = self.read_state();
            if state.has_open_session() {
                return Err(SessionError::SessionAlreadyOpen.into());
            }
        }

        // Zeroizing garante limpeza da KEK em qualquer caminho (sucesso ou erro).
        let kek_session = zeroize::Zeroizing::new(
            self.build_kek_session(master_key, &session_file.header, k_ext)?,
        );

        // O payload desencriptado (JSON em claro) é limpo no Drop.
        let plaintext = zeroize::Zeroizing::new(
            self.crypto
                .decrypt_aead(
                    &kek_session,
                    &session_file.nonce_global,
                    b"SESSION_V1",
                    &session_file.ciphertext_global,
                )
                .map_err(|_| SessionError::WrongSessionKey)?,
        );

        if verify_hmac {
            if let Some(expected_hmac) = session_file.session_hmac {
                let computed_hmac = self.compute_session_hmac(&kek_session, &plaintext)?;
                if !bool::from(subtle::ConstantTimeEq::ct_eq(
                    computed_hmac.as_slice(),
                    expected_hmac.as_slice(),
                )) {
                    return Err(SessionError::SessionFileTampered.into());
                }
            }
        }
        drop(kek_session);

        let payload: SessionPayload = serde_json::from_slice(&plaintext)
            .map_err(|_| SessionError::InvalidSessionFormat("payload inválido".into()))?;

        let mut state = self.write_state();
        let mut runtime = SessionRuntime::new(session_file, payload);

        runtime.last_saved_hash = Self::hash_payload(&runtime.payload);
        state.session = Some(runtime);
        Ok(())
    }

    fn hash_payload(payload: &SessionPayload) -> Option<u64> {
        use std::collections::hash_map;
        use std::hash::{Hash, Hasher};
        let bytes = serde_json::to_vec(payload).ok()?;
        let mut hasher = hash_map::DefaultHasher::new();
        bytes.hash(&mut hasher);
        Some(hasher.finish())
    }

    /// Indica se o payload em memória mudou desde a última gravação. Usado para avisar antes de bloquear a sessão ou fechar a janela.
    pub fn has_unsaved_changes(&self) -> CoreResult<bool> {
        self.with_session(|session| {
            let current = Self::hash_payload(&session.payload);
            Ok(session.last_saved_hash != current || session.last_saved_hash.is_none())
        })
    }

    pub fn close_session(&self) -> CoreResult<()> {
        let mut state = self.write_state();
        state.session = None;
        Ok(())
    }

    /// Apaga o ficheiro de sessão em `path` (ou a entrada equivalente em localStorage, em wasm) e fecha a sessão em memória
    pub fn delete_session_file(&self, path: &str) -> CoreResult<()> {
        self.files.delete_session_file(path)?;
        self.close_session()
    }

    pub fn save_session(
        &self,
        path: &str,
        master_key: &MasterKeyInput,
        k_ext: Option<&[u8; 32]>,
        create_hmac: bool,
    ) -> CoreResult<()> {
        master_key.validate()?;

        let (header, payload_bytes) = self.with_session(|session| {
            // O JSON serializado do payload é limpo no Drop.
            let bytes = zeroize::Zeroizing::new(
                serde_json::to_vec(&session.payload)
                    .map_err(|_| SessionError::SessionCorrupted)?,
            );
            Ok((session.session_file.header.clone(), bytes))
        })?;

        // Zeroizing garante limpeza da KEK em qualquer caminho (sucesso ou erro).
        let kek_session = zeroize::Zeroizing::new(self.build_kek_session(master_key, &header, k_ext)?);
        let nonce_global = self.crypto.generate_random_24()?;

        let ciphertext = self.crypto.encrypt_aead(&kek_session, &nonce_global, b"SESSION_V1", &payload_bytes)?;

        let mut session_file = SessionFile {
            header,
            nonce_global,
            ciphertext_global: ciphertext.clone(),
            session_hmac: None,
        };

        if create_hmac {
            let session_hmac = self.compute_session_hmac(&kek_session, &payload_bytes)?;
            session_file.session_hmac = Some(session_hmac);
        }
        drop(kek_session);

        self.files.save_session_file(path, &session_file)?;

        let mut state = self.write_state();
        let session = state.require_session_mut()?;
        session.session_file.nonce_global = nonce_global;
        session.session_file.ciphertext_global = ciphertext;
        session.last_saved_hash = Self::hash_payload(&session.payload);

        let mut hasher = Sha256::new();
        hasher.update(&session_file.ciphertext_global);
        let session_hash: [u8; 32] = hasher.finalize().into();

        state.local_state.last_session_path = Some(path.to_string());
        state.local_state.session_file_hash = Some(session_hash);
        state.local_state.session_file_timestamp = Some(Utc::now());
        let snapshot = state.local_state.clone();

        drop(state);
        self.persist_local_state(snapshot)?;

        Ok(())
    }

    fn compute_session_hmac(
        &self,
        kek_session: &[u8; 32],
        plaintext_payload: &[u8],
    ) -> CoreResult<[u8; 32]> {
        let hmac_key_vec = zeroize::Zeroizing::new(crate::crypto::hkdf_extract_expand(
            kek_session,
            None,
            b"SESSION_HMAC_V1",
            32,
        ));
        let hmac_key: zeroize::Zeroizing<[u8; 32]> = zeroize::Zeroizing::new(
            hmac_key_vec
                .as_slice()
                .try_into()
                .map_err(|_| SessionError::SessionCorrupted)?,
        );
        Ok(self.crypto.hmac_sha256(&hmac_key, plaintext_payload)?)
    }

    pub fn rotate_master_key(
        &self,
        old_key: &MasterKeyInput,
        new_key: &MasterKeyInput,
        path: &str,
        k_ext: Option<&[u8; 32]>,
    ) -> CoreResult<()> {
        old_key.validate()?;
        new_key.validate()?;

        let devices: Vec<Device> = self.with_session(|session| Ok(session.payload.devices.clone()))?;

        let old_bytes = zeroize::Zeroizing::new(old_key.normalize_and_concat());
        let new_bytes = zeroize::Zeroizing::new(new_key.normalize_and_concat());

        let mut rotated: Vec<(Uuid, [u8; 32], SeedEnvelope)> = Vec::with_capacity(devices.len());

        for device in &devices {
            let aad = device.seed_aad();
            let seed_bytes = self.decrypt_seed_with_bytes(
                &old_bytes,
                &device.salt_device,
                &device.argon2,
                device.uuid,
                &device.seed_envelope,
            )?;

            let new_salt = self.crypto.generate_random_32()?;
            let new_k_user = zeroize::Zeroizing::new(self.crypto.derive_argon2(
                &new_bytes,
                &new_salt,
                device.argon2.m_cost_kib,
                device.argon2.t_cost,
                device.argon2.p_cost,
            )?);

            let new_nonce = self.crypto.generate_random_24()?;
            let new_ciphertext = self.crypto.encrypt_aead(&new_k_user, &new_nonce, &aad, seed_bytes.as_slice())?;

            rotated.push((
                device.uuid,
                new_salt,
                SeedEnvelope {
                    nonce: new_nonce,
                    ciphertext: new_ciphertext,
                },
            ));
        }

        self.with_session_mut(|session| {
            for (uuid, new_salt, envelope) in rotated {
                let device = session
                    .payload
                    .find_device_mut(uuid)
                    .ok_or(DeviceError::UuidNotFound(uuid.to_string()))?;
                device.salt_device = new_salt;
                device.seed_envelope = envelope;
            }
            Ok(())
        })?;

        self.save_session(path, new_key, k_ext, true)?;
        Ok(())
    }

    pub fn rotate_kext(
        &self,
        master_key: &MasterKeyInput,
        new_k_ext: Option<&[u8; 32]>,
        new_salt_hkdf: Option<[u8; 32]>,
        path: &str,
    ) -> CoreResult<()> {
        master_key.validate()?;

        self.with_session_mut(|session| {
            session.session_file.header.hardware_enabled = new_k_ext.is_some();
            session.session_file.header.salt_hkdf = new_salt_hkdf;
            session.session_file.header.salt_session = self.crypto.generate_random_32()?;
            Ok(())
        })?;

        self.save_session(path, master_key, new_k_ext, true)?;
        Ok(())
    }

    fn build_kek_session(
        &self,
        master_key: &MasterKeyInput,
        header: &SessionHeader,
        k_ext: Option<&[u8; 32]>,
    ) -> CoreResult<[u8; 32]> {
        if header.hardware_enabled && k_ext.is_none() {
            return Err(SessionError::HardwareRequired.into());
        }

        let salt_hkdf = if header.hardware_enabled {
            Some(
                header
                    .salt_hkdf
                    .ok_or(SessionError::HardwareNotConfigured)?,
            )
        } else {
            None
        };

        let kek = self
            .crypto
            .derive_kek_session(
                &master_key.k1,
                &master_key.k2,
                &header.salt_session,
                header.argon2.m_cost_kib,
                header.argon2.t_cost,
                header.argon2.p_cost,
                k_ext,
                salt_hkdf.as_ref(),
            )
            .map_err(|_| SessionError::WrongSessionKey)?;

        Ok(kek)
    }

    fn build_device_kek(
        &self,
        master_key: &MasterKeyInput,
        salt_device: &[u8; 32],
        argon2: &Argon2Params,
    ) -> CoreResult<[u8; 32]> {
        let k_user_bytes = zeroize::Zeroizing::new(master_key.normalize_and_concat());
        let kek_device = self.crypto.derive_argon2(
            &k_user_bytes,
            salt_device,
            argon2.m_cost_kib,
            argon2.t_cost,
            argon2.p_cost,
        )?;
        Ok(kek_device)
    }

    fn take_session_snapshot(&self) -> Option<SessionRuntime> {
        self.write_state().session.take()
    }

    fn restore_session_snapshot(&self, backup: Option<SessionRuntime>) {
        self.write_state().session = backup;
    }

    fn benchmark_argon2_params(local_state: &LocalState) -> Argon2Params {
        Argon2Params {
            m_cost_kib: local_state.benchmark_argon2_m_cost_kib.unwrap_or(crate::crypto::MIN_M_COST_KIB),
            t_cost: local_state.benchmark_argon2_t_cost.unwrap_or(crate::crypto::MIN_T_COST),
            p_cost: local_state.benchmark_argon2_p_cost.unwrap_or(crate::crypto::MIN_P_COST),
        }
    }

    fn benchmark_secret(length: usize, fill: char) -> String {
        std::iter::repeat_n(fill, length.max(1)).collect()
    }

    fn run_benchmark_case(
        &self,
        device_count: usize,
        domains_count: usize,
        static_passwords_count: usize,
        distribution: BenchmarkDistribution,
        session_argon2: Argon2Params,
        k1_len: usize,
        k2_len: usize,
    ) -> CoreResult<SecretBenchmarkReport> {
        if device_count == 0 {
            return Err(CommonError::OutOfRange(
                "Benchmark requer pelo menos 1 dispositivo".to_string(),
            )
            .into());
        }

        let total_start = Instant::now();
        let master_key = MasterKeyInput::new(
            Self::benchmark_secret(k1_len, '1'),
            Self::benchmark_secret(k2_len, '2'),
        );

        self.create_new_session([0x11; 32], session_argon2.clone(), false, None)?;

        let device_setup_start = Instant::now();
        let mut device_uuids = Vec::with_capacity(device_count);
        let mut restriction_uuids = Vec::with_capacity(device_count);

        for index in 0..device_count {
            let device_uuid = Uuid::from_u128(0xBEEF_0000_0000_0000_0000_0000_0000_0001u128 + index as u128);
            let salt_device = [0x21 + index as u8; 32];
            let seed = [0x51 + index as u8; 32];
            let kek_device = self.build_device_kek(&master_key, &salt_device, &session_argon2)?;
            let aad = CryptoContext::SeedAad { device: device_uuid }.build_bytes();
            let nonce = [0x31 + index as u8; 24];
            let ciphertext = self.crypto.encrypt_aead(&kek_device, &nonce, &aad, &seed)?;

            let seed_envelope = SeedEnvelope { nonce, ciphertext };
            self.add_device_with_details(
                &format!("benchmark-device-{}", index + 1),
                device_uuid,
                salt_device,
                session_argon2.clone(),
                seed_envelope,
            )?;

            let restriction_uuid = self
                .list_restrictions(device_uuid)?
                .first()
                .ok_or(SessionError::SessionCorrupted)?
                .uuid;

            device_uuids.push(device_uuid);
            restriction_uuids.push(restriction_uuid);
        }

        let device_setup_duration = device_setup_start.elapsed();

        let domain_start = Instant::now();
        match distribution {
            BenchmarkDistribution::RoundRobin => {
                for index in 0..domains_count {
                    let slot = index % device_count;
                    let identifier = format!("bench-domain-{index:03}.example");
                    self.add_domain(&identifier, restriction_uuids[slot])?;
                }
            }
            BenchmarkDistribution::PerDevice => {
                for (slot, restriction_uuid) in restriction_uuids.iter().enumerate() {
                    for index in 0..domains_count {
                        let identifier = format!(
                            "bench-domain-device-{}-{:03}.example",
                            slot + 1,
                            index + 1
                        );
                        self.add_domain(&identifier, *restriction_uuid)?;
                    }
                }
            }
        }
        let domain_setup_duration = domain_start.elapsed();

        let static_start = Instant::now();
        match distribution {
            BenchmarkDistribution::RoundRobin => {
                for index in 0..static_passwords_count {
                    let slot = index % device_count;
                    let device_uuid = device_uuids[slot];
                    let folder = format!("/bench/device-{}/static", slot + 1);
                    let label = format!("static-{index:03}");
                    let plaintext = StaticPasswordPlaintext {
                        label: label.clone(),
                        value: format!("fixed-value-{index:03}"),
                        notes: "benchmark".to_string(),
                        compromised: false,
                    };

                    self.add_static_password(device_uuid, &folder, &label, plaintext, &master_key)?;
                }
            }
            BenchmarkDistribution::PerDevice => {
                for (slot, device_uuid) in device_uuids.iter().enumerate() {
                    for index in 0..static_passwords_count {
                        let folder = format!("/bench/device-{}/static", slot + 1);
                        let label = format!("static-device-{}-{:03}", slot + 1, index + 1);
                        let plaintext = StaticPasswordPlaintext {
                            label: label.clone(),
                            value: format!("fixed-value-device-{}-{:03}", slot + 1, index + 1),
                            notes: "benchmark".to_string(),
                            compromised: false,
                        };

                        self.add_static_password(*device_uuid, &folder, &label, plaintext, &master_key)?;
                    }
                }
            }
        }
        let static_password_duration = static_start.elapsed();

        let total_duration = total_start.elapsed();

        self.close_session()?;

        Ok(SecretBenchmarkReport {
            device_count,
            domain_count: match distribution {
                BenchmarkDistribution::RoundRobin => domains_count,
                BenchmarkDistribution::PerDevice => domains_count.saturating_mul(device_count),
            },
            static_password_count: match distribution {
                BenchmarkDistribution::RoundRobin => static_passwords_count,
                BenchmarkDistribution::PerDevice => static_passwords_count.saturating_mul(device_count),
            },
            total_duration,
            device_setup_duration,
            domain_setup_duration,
            static_password_duration,
        })
    }

    pub fn encrypt_device_seed_envelope(
        &self,
        device_uuid: Uuid,
        salt_device: &[u8; 32],
        argon2: &Argon2Params,
        master_key: &MasterKeyInput,
        seed: &[u8; 32],
    ) -> CoreResult<SeedEnvelope> {
        let kek_device =
            zeroize::Zeroizing::new(self.build_device_kek(master_key, salt_device, argon2)?);
        let aad = CryptoContext::SeedAad { device: device_uuid }.build_bytes();
        let nonce = self.crypto.generate_random_24()?;
        let ciphertext = self
            .crypto
            .encrypt_aead(&kek_device, &nonce, &aad, seed)?;
        Ok(SeedEnvelope { nonce, ciphertext })
    }

    pub fn decrypt_device_seed_envelope(
        &self,
        device_uuid: Uuid,
        salt_device: &[u8; 32],
        argon2: &Argon2Params,
        master_key: &MasterKeyInput,
        seed_envelope: &SeedEnvelope,
    ) -> CoreResult<[u8; 32]> {
        let k_user_bytes = zeroize::Zeroizing::new(master_key.normalize_and_concat());
        let seed = self.decrypt_seed_with_bytes(
            &k_user_bytes,
            salt_device,
            argon2,
            device_uuid,
            seed_envelope,
        )?;
        Ok(*seed)
    }

    pub fn add_device(
        &self,
        name: &str,
        master_key: &MasterKeyInput,
    ) -> CoreResult<Uuid> {
        let argon2 =
            self.with_session(|session| Ok(session.session_file.header.argon2.clone()))?;
        self.add_device_with_argon2(name, master_key, argon2)
    }

    pub fn add_device_with_argon2(
        &self,
        name: &str,
        master_key: &MasterKeyInput,
        argon2: Argon2Params,
    ) -> CoreResult<Uuid> {
        master_key.validate()?;

        let salt_device = self.crypto.generate_random_32()?;

        let device_uuid = Uuid::new_v4();
        let seed_bytes = self.crypto.generate_random_32()?;
        let seed_envelope = self.encrypt_device_seed_envelope(
            device_uuid,
            &salt_device,
            &argon2,
            master_key,
            &seed_bytes,
        )?;

        self.add_device_with_details(
            name,
            device_uuid,
            salt_device,
            argon2,
            seed_envelope,
        )
    }

    pub fn add_device_with_details(
        &self,
        name: &str,
        device_uuid: Uuid,
        salt_device: [u8; 32],
        argon2: Argon2Params,
        seed_envelope: SeedEnvelope,
    ) -> CoreResult<Uuid> {
        let canonical_name = crate::models::canonicalize_name(name);
        let mut device = Device::new(name, salt_device, argon2.clone(), seed_envelope);
        device.uuid = device_uuid;

        let reserved_char_lists = build_reserved_char_lists();
        let bit_lists = build_bit_lists(&reserved_char_lists);
        let alphabet_sizes = Self::compute_alphabet_sizes_for_mask(DEFAULT_RESTRICTION_MASK, &bit_lists);
        let bytes_to_derive = GenerationParams::compute_bytes_to_derive(&alphabet_sizes);
        let max_masks = generator::build_max_masks(DEFAULT_RESTRICTION_MASK, &bit_lists, 96);

        let mut default_restriction = Restriction::new(
            DEFAULT_RESTRICTION_NAME,
            device_uuid,
            GenerationParams {
                default_mask: Some(DEFAULT_RESTRICTION_MASK),
                format_sequence: Some(max_masks),
                bytes_to_derive: Some(bytes_to_derive),
            },
        );
        default_restriction.char_lists = reserved_char_lists;

        self.with_session_mut(|session| {
            if session.payload.devices.iter()
                .any(|d| crate::models::canonicalize_name(&d.name) == canonical_name) {
                return Err(DeviceError::NameAlreadyExists(name.to_string()).into());
            }
            session.payload.devices.push(device);
            session.payload.restrictions.push(default_restriction);
            Ok(device_uuid)
        })
    }

    pub fn remove_device(&self, uuid: Uuid) -> CoreResult<()> {
        self.with_session_mut(|session| {
            if session.payload.devices.len() <= 1 {
                return Err(DeviceError::CannotDeleteLastDevice.into());
            }

            if session.payload.restrictions.iter().any(|r| r.device_uuid == uuid) {
                return Err(DeviceError::CannotDeleteDeviceWithRestrictions.into());
            }

            session.payload.devices.retain(|d| d.uuid != uuid);
            Ok(())
        })
    }

    pub fn rename_device(&self, uuid: Uuid, new_name: &str) -> CoreResult<()> {
        self.with_session_mut(|session| {
            let canonical_name = crate::models::canonicalize_name(new_name);

            if session.payload.devices.iter()
                .any(|d| d.uuid != uuid && crate::models::canonicalize_name(&d.name) == canonical_name) {
                return Err(DeviceError::NameAlreadyExists(new_name.to_string()).into());
            }

            let device = session
                .payload
                .find_device_mut(uuid)
                .ok_or(DeviceError::UuidNotFound(uuid.to_string()))?;

            device.name = canonical_name;
            Ok(())
        })
    }

    pub fn select_device(&self, uuid: Uuid) -> CoreResult<()> {
        self.with_session_mut(|session| {
            if session.payload.find_device(uuid).is_none() {
                return Err(DeviceError::UuidNotFound(uuid.to_string()).into());
            }

            session.selected_device = Some(uuid);
            session.selected_restriction = None;
            session.selected_domain = None;
            Ok(())
        })
    }

    pub fn list_devices(&self) -> CoreResult<Vec<Device>> {
        self.with_session(|session| Ok(session.payload.devices.clone()))
    }

    pub fn get_device(&self, uuid: Uuid) -> CoreResult<Device> {
        self.with_session(|session| {
            session
                .payload
                .find_device(uuid)
                .cloned()
                .ok_or_else(|| DeviceError::UuidNotFound(uuid.to_string()).into())
        })
    }

    pub fn add_char_list_to_restriction(
        &self,
        restriction_uuid: Uuid,
        name: &str,
        bit: u8,
        elements: Vec<String>,
    ) -> CoreResult<Uuid> {
        if is_reserved_bit(bit) {
            return Err(DeviceError::CharListBitOccupied(bit).into());
        }

        if !(USER_BIT_MIN..=USER_BIT_MAX).contains(&bit) {
            return Err(DeviceError::CharListBitInvalid(bit).into());
        }

        if elements.is_empty() {
            return Err(ValidationError::EmptyElementList.into());
        }

        self.with_session_mut(|session| {
            let restriction = session
                .payload
                .find_restriction_mut(restriction_uuid)
                .ok_or(RestrictionError::UuidNotFound(restriction_uuid.to_string()))?;

            if restriction.char_lists.iter().any(|cl| cl.bit == bit) {
                return Err(DeviceError::CharListBitOccupied(bit).into());
            }

            let char_list = CharacterList::new(name, bit, elements)
                .map_err(|_| DeviceError::CharListBitInvalid(bit))?;
            let uuid = char_list.uuid;
            restriction.char_lists.push(char_list);
            Self::refresh_restriction_bytes_to_derive(restriction);
            Ok(uuid)
        })
    }

    pub fn remove_char_list_from_restriction(
        &self,
        restriction_uuid: Uuid,
        char_list_uuid: Uuid,
    ) -> CoreResult<()> {
        self.with_session_mut(|session| {
            let restriction = session
                .payload
                .find_restriction_mut(restriction_uuid)
                .ok_or(RestrictionError::UuidNotFound(restriction_uuid.to_string()))?;

            let char_list = restriction
                .char_lists
                .iter()
                .find(|cl| cl.uuid == char_list_uuid)
                .ok_or(DeviceError::CharListNotFound(char_list_uuid.to_string()))?;

            if is_reserved_bit(char_list.bit) {
                return Err(DeviceError::CharListBitOccupied(char_list.bit).into());
            }

            restriction.char_lists.retain(|cl| cl.uuid != char_list_uuid);
            Self::refresh_restriction_bytes_to_derive(restriction);
            Ok(())
        })
    }

    pub fn list_char_lists(&self, restriction_uuid: Uuid) -> CoreResult<Vec<CharacterList>> {
        self.with_session(|session| {
            let restriction = session
                .payload
                .find_restriction(restriction_uuid)
                .ok_or(RestrictionError::UuidNotFound(restriction_uuid.to_string()))?;

            Ok(restriction.char_lists.clone())
        })
    }

    pub fn update_char_list_elements(
        &self,
        restriction_uuid: Uuid,
        char_list_uuid: Uuid,
        elements: Vec<String>,
    ) -> CoreResult<()> {
        if elements.is_empty() {
            return Err(ValidationError::EmptyElementList.into());
        }

        self.with_session_mut(|session| {
            let restriction = session
                .payload
                .find_restriction_mut(restriction_uuid)
                .ok_or(RestrictionError::UuidNotFound(restriction_uuid.to_string()))?;

            let char_list = restriction
                .char_lists
                .iter_mut()
                .find(|cl| cl.uuid == char_list_uuid)
                .ok_or(DeviceError::CharListNotFound(char_list_uuid.to_string()))?;

            if is_reserved_bit(char_list.bit) {
                return Err(DeviceError::CharListBitOccupied(char_list.bit).into());
            }

            char_list.elements = elements;
            Self::refresh_restriction_bytes_to_derive(restriction);
            Ok(())
        })
    }

    pub fn add_restriction(
        &self,
        name: &str,
        device_uuid: Uuid,
        generation: GenerationParams,
    ) -> CoreResult<Uuid> {
        self.with_session_mut(|session| {
            if session.payload.find_device(device_uuid).is_none() {
                return Err(DeviceError::UuidNotFound(device_uuid.to_string()).into());
            }

            let canonical_name = crate::models::canonicalize_name(name);

            if session
                .payload
                .restrictions
                .iter()
                .any(|r| r.device_uuid == device_uuid && r.name == canonical_name)
            {
                return Err(RestrictionError::NameAlreadyExists(name.to_string()).into());
            }

            let mut restriction = Restriction::new(name, device_uuid, generation);
            restriction.char_lists = build_reserved_char_lists();
            let uuid = restriction.uuid;
            session.payload.restrictions.push(restriction);
            Ok(uuid)
        })
    }

    pub fn remove_restriction(&self, uuid: Uuid) -> CoreResult<()> {
        self.with_session_mut(|session| {
            let domain_count = session
                .payload
                .domains
                .iter()
                .filter(|d| d.restriction_uuid == uuid)
                .count();

            if domain_count > 0 {
                return Err(RestrictionError::RestrictionInUse { domain_count }.into());
            }

            session.payload.restrictions.retain(|r| r.uuid != uuid);
            Ok(())
        })
    }

    pub fn rename_restriction(&self, uuid: Uuid, new_name: &str) -> CoreResult<()> {
        self.with_session_mut(|session| {
            let device_uuid = session
                .payload
                .find_restriction(uuid)
                .ok_or(RestrictionError::UuidNotFound(uuid.to_string()))?
                .device_uuid;

            let canonical_name = crate::models::canonicalize_name(new_name);

            if session
                .payload
                .restrictions
                .iter()
                .any(|r| r.uuid != uuid && r.device_uuid == device_uuid && r.name == canonical_name)
            {
                return Err(RestrictionError::NameAlreadyExists(new_name.to_string()).into());
            }

            let restriction = session
                .payload
                .find_restriction_mut(uuid)
                .ok_or(RestrictionError::UuidNotFound(uuid.to_string()))?;

            restriction.name = canonical_name;
            Ok(())
        })
    }

    pub fn update_restriction_generation(
        &self,
        uuid: Uuid,
        params: GenerationParams,
    ) -> CoreResult<()> {
        self.with_session_mut(|session| {
            let restriction = session
                .payload
                .find_restriction_mut(uuid)
                .ok_or(RestrictionError::UuidNotFound(uuid.to_string()))?;

            restriction.generation = params;
            Self::refresh_restriction_bytes_to_derive(restriction);
            Ok(())
        })
    }

    /// Define a máscara padrão global da restrição (código 0 nas posições). Afecta todas as posições `Mask(0)` já existentes
    pub fn set_default_mask(&self, restriction_uuid: Uuid, mask: u32) -> CoreResult<()> {
        let restriction = self.get_restriction(restriction_uuid)?;
        let mut params = restriction.generation.clone();
        params.default_mask = Some(mask);
        self.update_restriction_generation(restriction_uuid, params)
    }

    /// Entropia em milibits de uma única máscara (posição "padrão"/"personalizado").
    pub fn entropy_millibits_for_mask(&self, restriction_uuid: Uuid, mask: u32) -> CoreResult<u64> {
        let restriction = self.get_restriction(restriction_uuid)?;
        let bit_lists = restriction.build_bit_lists();
        let sizes = Self::compute_alphabet_sizes_for_mask(mask, &bit_lists);
        Ok(Self::entropy_millibits_for_alphabet_sizes(&sizes))
    }

    /// Entropia total em milibits de toda a sequência resolvida da restrição.
    pub fn restriction_total_entropy_millibits(&self, restriction_uuid: Uuid) -> CoreResult<u64> {
        let restriction = self.get_restriction(restriction_uuid)?;
        let bit_lists = restriction.build_bit_lists();
        let sizes = Self::compute_alphabet_sizes_for_masks(&restriction.generation, &bit_lists);
        Ok(Self::entropy_millibits_for_alphabet_sizes(&sizes))
    }

    pub fn regenerate_default_format(&self, restriction_uuid: Uuid) -> CoreResult<()> {
        let (bit_lists, existing_default_mask, effective_default_mask) = self.with_session(|session| {
            let restriction = session
                .payload
                .find_restriction(restriction_uuid)
                .ok_or(RestrictionError::UuidNotFound(restriction_uuid.to_string()))?;
            Ok((
                restriction.build_bit_lists(),
                restriction.generation.default_mask,
                restriction.generation.effective_default_mask(),
            ))
        })?;

        let alphabet_sizes = Self::compute_alphabet_sizes_for_mask(effective_default_mask, &bit_lists);
        let bytes_to_derive = GenerationParams::compute_bytes_to_derive(&alphabet_sizes);
        let max_masks = generator::build_max_masks(effective_default_mask, &bit_lists, 96);
        let format_sequence: Vec<MaskOrLiteral> =
            max_masks.into_iter().map(|_| MaskOrLiteral::Mask(0)).collect();

        let params = GenerationParams {
            default_mask:    existing_default_mask,
            format_sequence: Some(format_sequence),
            bytes_to_derive: Some(bytes_to_derive),
        };

        self.update_restriction_generation(restriction_uuid, params)
    }

    fn insert_restriction_position(
        &self,
        restriction_uuid: Uuid,
        item: MaskOrLiteral,
        insert_at: usize,
    ) -> CoreResult<()> {
        let restriction = self.get_restriction(restriction_uuid)?;

        let mut sequence = restriction
            .generation
            .sequence()
            .map(|s| s.to_vec())
            .unwrap_or_default();

        if insert_at > sequence.len() {
            return Err(CommonError::OutOfRange(format!(
                "posição {} fora do intervalo 0..={}",
                insert_at,
                sequence.len()
            ))
            .into());
        }

        sequence.insert(insert_at, item);

        let mut params = restriction.generation.clone();
        params.format_sequence = Some(sequence);
        self.update_restriction_generation(restriction_uuid, params)
    }

    pub fn update_restriction_position_mask(
        &self,
        restriction_uuid: Uuid,
        index: usize,
        mask: u32,
    ) -> CoreResult<()> {
        let restriction = self.get_restriction(restriction_uuid)?;

        let mut sequence = restriction
            .generation
            .sequence()
            .map(|s| s.to_vec())
            .unwrap_or_default();

        let Some(slot) = sequence.get_mut(index) else {
            return Err(CommonError::OutOfRange(format!(
                "posição {} fora do intervalo 0..{}",
                index,
                sequence.len()
            ))
            .into());
        };
        *slot = MaskOrLiteral::Mask(mask);

        let mut params = restriction.generation.clone();
        params.format_sequence = Some(sequence);
        self.update_restriction_generation(restriction_uuid, params)
    }

    pub fn insert_restriction_mask_position(
        &self,
        restriction_uuid: Uuid,
        mask: u32,
        insert_at: usize,
    ) -> CoreResult<()> {
        self.insert_restriction_position(restriction_uuid, MaskOrLiteral::Mask(mask), insert_at)
    }

    pub fn insert_restriction_literal_position<S: Into<String>>(
        &self,
        restriction_uuid: Uuid,
        literal: S,
        insert_at: usize,
    ) -> CoreResult<()> {
        self.insert_restriction_position(
            restriction_uuid,
            MaskOrLiteral::Literal(literal.into()),
            insert_at,
        )
    }

    pub fn extend_restriction_format_to_entropy(
        &self,
        restriction_uuid: Uuid,
        target_bits: u32,
    ) -> CoreResult<usize> {
        let restriction = self.get_restriction(restriction_uuid)?;
        let bit_lists = restriction.build_bit_lists();
        let default_mask = restriction.generation.effective_default_mask();

        let current_sizes = Self::compute_alphabet_sizes_for_masks(&restriction.generation, &bit_lists);
        let current_bits = Self::entropy_millibits_for_alphabet_sizes(&current_sizes);

        let default_sizes = Self::compute_alphabet_sizes_for_mask(default_mask, &bit_lists);
        let default_bits = Self::entropy_millibits_for_alphabet_sizes(&default_sizes);

        if default_bits == 0 {
            return Err(CommonError::OutOfRange(
                "não foi possível calcular a base padrão da restrição".to_string(),
            )
            .into());
        }

        let target_bits_millibits =
            (u64::from(target_bits) + generator::constants::ENTROPY_MARGIN_BITS) * 1000;
        let remaining_bits = target_bits_millibits.saturating_sub(current_bits);
        let extra_positions = if remaining_bits == 0 {
            0
        } else {
            remaining_bits.div_ceil(default_bits) as usize
        };

        let mut sequence = restriction
            .generation
            .sequence()
            .map(|s| s.to_vec())
            .unwrap_or_default();

        sequence.extend(std::iter::repeat_n(MaskOrLiteral::Mask(0), extra_positions));

        let mut params = restriction.generation.clone();
        params.format_sequence = Some(sequence);
        self.update_restriction_generation(restriction_uuid, params)?;

        Ok(extra_positions)
    }

    pub fn select_restriction(&self, uuid: Uuid) -> CoreResult<()> {
        self.with_session_mut(|session| {
            if session.payload.find_restriction(uuid).is_none() {
                return Err(RestrictionError::UuidNotFound(uuid.to_string()).into());
            }

            session.selected_restriction = Some(uuid);
            session.selected_domain = None;
            Ok(())
        })
    }

    pub fn list_restrictions(&self, device_uuid: Uuid) -> CoreResult<Vec<Restriction>> {
        self.with_session(|session| {
            Ok(session
                .payload
                .restrictions
                .iter()
                .filter(|r| r.device_uuid == device_uuid)
                .cloned()
                .collect())
        })
    }

    pub fn get_restriction(&self, uuid: Uuid) -> CoreResult<Restriction> {
        self.with_session(|session| {
            session
                .payload
                .find_restriction(uuid)
                .cloned()
                .ok_or_else(|| RestrictionError::UuidNotFound(uuid.to_string()).into())
        })
    }

    pub fn add_domain(&self, identifier: &str, restriction_uuid: Uuid) -> CoreResult<Uuid> {
        self.with_session_mut(|session| {
            if session.payload.find_restriction(restriction_uuid).is_none() {
                return Err(DomainError::RestrictionNotFound.into());
            }

            let domain = Domain::new(identifier, restriction_uuid);

            if session
                .payload
                .domains
                .iter()
                .any(|d| {
                    d.restriction_uuid == restriction_uuid
                        && d.identifier_canonical == domain.identifier_canonical
                })
            {
                return Err(DomainError::IdentifierAlreadyExists(identifier.to_string()).into());
            }

            let uuid = domain.uuid;
            session.payload.domains.push(domain);
            Ok(uuid)
        })
    }

    pub fn remove_domain(&self, uuid: Uuid) -> CoreResult<()> {
        self.with_session_mut(|session| {
            if session.selected_domain == Some(uuid) {
                session.selected_domain = None;
            }

            session.payload.domains.retain(|d| d.uuid != uuid);
            Ok(())
        })
    }

    pub fn select_domain(&self, uuid: Uuid) -> CoreResult<()> {
        self.with_session_mut(|session| {
            if session.payload.find_domain(uuid).is_none() {
                return Err(DomainError::UuidNotFound(uuid.to_string()).into());
            }

            session.selected_domain = Some(uuid);
            Ok(())
        })
    }

    pub fn list_domains(&self, restriction_uuid: Uuid) -> CoreResult<Vec<Domain>> {
        self.with_session(|session| {
            Ok(session
                .payload
                .domains
                .iter()
                .filter(|d| d.restriction_uuid == restriction_uuid)
                .cloned()
                .collect())
        })
    }

    pub fn get_domain(&self, uuid: Uuid) -> CoreResult<Domain> {
        self.with_session(|session| {
            session
                .payload
                .find_domain(uuid)
                .cloned()
                .ok_or_else(|| DomainError::UuidNotFound(uuid.to_string()).into())
        })
    }

    /// Pesquisa global de domínios por semelhança ao texto introduzido
    pub fn search_domains(&self, query: &str) -> CoreResult<Vec<DomainSearchResult>> {
        let query_canon = canonicalize_domain(query);

        self.with_session(|session| {
            let mut results: Vec<DomainSearchResult> = session
                .payload
                .domains
                .iter()
                .filter_map(|domain| {
                    let restriction = session
                        .payload
                        .restrictions
                        .iter()
                        .find(|r| r.uuid == domain.restriction_uuid)?;
                    let device = session
                        .payload
                        .devices
                        .iter()
                        .find(|d| d.uuid == restriction.device_uuid)?;

                    let score = fuzzy_search_score(&query_canon, &domain.identifier_canonical)?;

                    Some(DomainSearchResult {
                        domain_uuid: domain.uuid,
                        identifier: domain.identifier_canonical.clone(),
                        device_uuid: device.uuid,
                        device_name: device.name.clone(),
                        restriction_uuid: restriction.uuid,
                        restriction_name: restriction.name.clone(),
                        score,
                    })
                })
                .collect();

            results.sort_by_key(|r| r.score);
            Ok(results)
        })
    }

    /// Pesquisa global de senhas estáticas por semelhança ao texto introduzido
    pub fn search_static_passwords(&self, query: &str) -> CoreResult<Vec<StaticPasswordSearchResult>> {
        let query_lower = query.to_lowercase();

        self.with_session(|session| {
            let mut results: Vec<StaticPasswordSearchResult> = session
                .payload
                .static_passwords
                .iter()
                .filter_map(|sp| {
                    let device = session
                        .payload
                        .devices
                        .iter()
                        .find(|d| d.uuid == sp.device_uuid)?;

                    let score = fuzzy_search_score(&query_lower, &sp.label.to_lowercase())?;

                    Some(StaticPasswordSearchResult {
                        uuid: sp.uuid,
                        label: sp.label.clone(),
                        folder_path: sp.folder_path.clone(),
                        device_uuid: device.uuid,
                        device_name: device.name.clone(),
                        compromised: sp.compromised,
                        score,
                    })
                })
                .collect();

            results.sort_by_key(|r| r.score);
            Ok(results)
        })
    }

    pub fn change_domain_restriction(
        &self,
        domain_uuid: Uuid,
        new_restriction_uuid: Uuid,
    ) -> CoreResult<()> {
        self.with_session_mut(|session| {
            let domain = session
                .payload
                .find_domain(domain_uuid)
                .ok_or(DomainError::UuidNotFound(domain_uuid.to_string()))?;

            let current_device = session
                .payload
                .find_restriction(domain.restriction_uuid)
                .ok_or(DomainError::RestrictionNotFound)?
                .device_uuid;

            let new_restriction = session
                .payload
                .find_restriction(new_restriction_uuid)
                .ok_or(DomainError::RestrictionNotFound)?;

            if new_restriction.device_uuid != current_device {
                return Err(DomainError::RestrictionDeviceMismatch.into());
            }

            let domain = session
                .payload
                .find_domain_mut(domain_uuid)
                .ok_or(DomainError::UuidNotFound(domain_uuid.to_string()))?;

            domain.restriction_uuid = new_restriction_uuid;
            Ok(())
        })
    }

    pub fn mark_domain_compromised(
        &self,
        domain_uuid: Uuid,
        variation: u32,
        master_key: &MasterKeyInput,
    ) -> CoreResult<Uuid> {
        master_key.validate()?;
        let (domain, restriction, device) = self.with_session(|session| {
            let domain = session
                .payload
                .find_domain(domain_uuid)
                .ok_or(DomainError::UuidNotFound(domain_uuid.to_string()))?;

            if domain
                .compromise_history
                .iter()
                .any(|c| c.variation == variation)
            {
                return Err(DomainError::AlreadyCompromised(variation).into());
            }

            let restriction = session
                .payload
                .find_restriction(domain.restriction_uuid)
                .ok_or(DomainError::RestrictionNotFound)?;

            let device = session
                .payload
                .find_device(restriction.device_uuid)
                .ok_or(DeviceError::UuidNotFound(restriction.device_uuid.to_string()))?;

            Ok((domain.clone(), restriction.clone(), device.clone()))
        })?;

        let kmac_context = CryptoContext::DerivedPassword {
            domain_canonical: &domain.identifier_canonical,
            variation,
            device: device.uuid,
            restriction: restriction.uuid,
        }
        .build();

        let bytes_to_derive = restriction.generation.effective_bytes_to_derive();
        let decrypted = self.decrypt_device_seed_internal(&device, master_key)?;

        let entropy = zeroize::Zeroizing::new(
            self.crypto
                .derive_kmac256(&decrypted.seed, &kmac_context, bytes_to_derive)
                .map_err(|_| PasswordError::KmacContextError)?,
        );

        let mut generated = self
            .generator
            .generate_password(&entropy, &restriction, &device)?;
        drop(entropy);

        let password_hmac = self
            .crypto
            .hmac_sha256(&decrypted.seed, generated.password.as_bytes())
            .ok();
        
        generated.password.zeroize();

        let frozen_config = FrozenGeneratorConfig {
            config_version: 1,
            kmac_context,
            format_sequence_snapshot: restriction.generation.format_sequence.clone(),
            default_mask_snapshot: restriction.generation.effective_default_mask(),
            bytes_to_derive,
            char_lists_snapshot: restriction.char_lists.clone(),
            identifier_frozen: domain.identifier_canonical.clone(),
            password_hmac,
        };

        let record = CompromiseRecord::new(variation, frozen_config);
        let record_uuid = record.uuid;

        self.with_session_mut(|session| {
            let domain = session
                .payload
                .find_domain_mut(domain_uuid)
                .ok_or(DomainError::UuidNotFound(domain_uuid.to_string()))?;

            if domain
                .compromise_history
                .iter()
                .any(|c| c.variation == variation)
            {
                return Err(DomainError::AlreadyCompromised(variation).into());
            }

            domain.compromise_history.push(record);
            Ok(record_uuid)
        })
    }

    pub fn rotate_domain_password(
        &self,
        domain_uuid: Uuid,
        master_key: &MasterKeyInput,
    ) -> CoreResult<u32> {
        let current_variation = self.with_session(|session| {
            Ok(session
                .payload
                .find_domain(domain_uuid)
                .ok_or(DomainError::UuidNotFound(domain_uuid.to_string()))?
                .active_variation)
        })?;

        self.mark_domain_compromised(domain_uuid, current_variation, master_key)?;

        self.with_session_mut(|session| {
            let domain = session
                .payload
                .find_domain_mut(domain_uuid)
                .ok_or(DomainError::UuidNotFound(domain_uuid.to_string()))?;

            domain.active_variation += 1;
            Ok(domain.active_variation)
        })
    }

    pub fn get_compromise_history(
        &self,
        domain_uuid: Uuid,
    ) -> CoreResult<Vec<CompromiseRecord>> {
        self.with_session(|session| {
            Ok(session
                .payload
                .find_domain(domain_uuid)
                .ok_or(DomainError::UuidNotFound(domain_uuid.to_string()))?
                .compromise_history
                .clone())
        })
    }

    pub fn remove_compromise_record(
        &self,
        domain_uuid: Uuid,
        record_uuid: Uuid,
    ) -> CoreResult<bool> {
        self.with_session_mut(|session| {
            let domain = session
                .payload
                .find_domain_mut(domain_uuid)
                .ok_or(DomainError::UuidNotFound(domain_uuid.to_string()))?;

            let before = domain.compromise_history.len();
            domain.compromise_history.retain(|r| r.uuid != record_uuid);

            Ok(before != domain.compromise_history.len())
        })
    }

    pub fn generate_password(
        &self,
        request: PasswordRequest,
        master_key: &MasterKeyInput,
    ) -> CoreResult<GeneratedPassword> {
        master_key.validate()?;

        let (domain, restriction, device) = self.with_session(|session| {
            let (d, r, dev) = session
                .payload
                .resolve_domain_chain(request.domain_uuid)
                .map_err(SessionError::InvalidSessionFormat)?;
            Ok((d.clone(), r.clone(), dev.clone()))
        })?;

        let variation = request
            .forced_variation
            .unwrap_or(domain.active_variation);

        let kmac_context = CryptoContext::DerivedPassword {
            domain_canonical: &domain.identifier_canonical,
            variation,
            device: device.uuid,
            restriction: restriction.uuid,
        }
        .build();

        let decrypted = self.decrypt_device_seed_internal(&device, master_key)?;
        let bytes_to_derive = restriction.generation.effective_bytes_to_derive();

        let entropy = zeroize::Zeroizing::new(
            self.crypto
                .derive_kmac256(&decrypted.seed, &kmac_context, bytes_to_derive)
                .map_err(|_| PasswordError::KmacContextError)?,
        );

        let mut result = self
            .generator
            .generate_password(&entropy, &restriction, &device)?;
        drop(entropy);

        result.variation = variation;
        result.domain_uuid = domain.uuid;
        result.restriction_uuid = restriction.uuid;
        result.device_uuid = device.uuid;

        Ok(result)
    }

    pub fn generate_password_from_frozen(
        &self,
        domain_uuid: Uuid,
        variation: u32,
        master_key: &MasterKeyInput,
    ) -> CoreResult<GeneratedPassword> {
        Ok(self
            .generate_password_from_frozen_checked(domain_uuid, variation, master_key)?
            .0)
    }

    pub fn generate_password_from_frozen_checked(
        &self,
        domain_uuid: Uuid,
        variation: u32,
        master_key: &MasterKeyInput,
    ) -> CoreResult<(GeneratedPassword, Option<bool>)> {
        master_key.validate()?;

        let (record, device) = self.with_session(|session| {
            let domain = session
                .payload
                .find_domain(domain_uuid)
                .ok_or(DomainError::UuidNotFound(domain_uuid.to_string()))?;

            let record = domain
                .compromise_history
                .iter()
                .find(|c| c.variation == variation)
                .ok_or(DomainError::CompromisedVariationNotFound(variation))?
                .clone();

            let restriction = session
                .payload
                .find_restriction(domain.restriction_uuid)
                .ok_or(DomainError::RestrictionNotFound)?;

            let device = session
                .payload
                .find_device(restriction.device_uuid)
                .ok_or(DeviceError::UuidNotFound(restriction.device_uuid.to_string()))?
                .clone();

            Ok((record, device))
        })?;

        let decrypted = self.decrypt_device_seed_internal(&device, master_key)?;
        let bytes_to_derive = record.frozen_config.bytes_to_derive;

        let entropy = zeroize::Zeroizing::new(
            self.crypto
                .derive_kmac256(&decrypted.seed, &record.frozen_config.kmac_context, bytes_to_derive)
                .map_err(|_| PasswordError::KmacContextError)?,
        );

        let frozen_restriction = Restriction {
            uuid: Uuid::nil(),
            name: String::new(),
            device_uuid: device.uuid,
            generation: GenerationParams {
                default_mask: Some(record.frozen_config.default_mask_snapshot),
                format_sequence: record.frozen_config.format_sequence_snapshot.clone(),
                bytes_to_derive: Some(bytes_to_derive),
            },
            char_lists: record.frozen_config.char_lists_snapshot.clone(),
        };
        let mut result = self
            .generator
            .generate_password(&entropy, &frozen_restriction, &device)?;
        drop(entropy);

        result.variation = variation;
        result.domain_uuid = domain_uuid;

        let hmac_status = match record.frozen_config.password_hmac {
            Some(stored) => match self
                .crypto
                .hmac_sha256(&decrypted.seed, result.password.as_bytes())
            {
                Ok(computed) => Some(bool::from(subtle::ConstantTimeEq::ct_eq(
                    computed.as_slice(),
                    stored.as_slice(),
                ))),
                Err(_) => None,
            },
            None => None,
        };

        Ok((result, hmac_status))
    }

    pub fn add_static_password(
        &self,
        device_uuid: Uuid,
        folder_path: &str,
        label: &str,
        plaintext: StaticPasswordPlaintext,
        master_key: &MasterKeyInput,
    ) -> CoreResult<Uuid> {
        master_key.validate()?;

        let device = self.get_device(device_uuid)?;
        let decrypted = self.decrypt_device_seed_internal(&device, master_key)?;

        self.add_static_password_with_seed(
            device_uuid,
            folder_path,
            label,
            plaintext,
            &decrypted.seed,
        )
    }

    fn add_static_password_with_seed(
        &self,
        device_uuid: Uuid,
        folder_path: &str,
        label: &str,
        plaintext: StaticPasswordPlaintext,
        seed: &[u8; 32],
    ) -> CoreResult<Uuid> {
        let entry_uuid = Uuid::new_v4();
        let (nonce, ciphertext) = self.encrypt_static_password_payload(
            device_uuid,
            entry_uuid,
            seed,
            &plaintext,
        )?;

        let mut entry = StaticPassword::new(device_uuid, folder_path, label, nonce, ciphertext);
        entry.uuid = entry_uuid;

        self.with_session_mut(|session| {
            session.payload.static_passwords.push(entry);
            Ok(entry_uuid)
        })
    }

    pub fn get_static_password(
        &self,
        uuid: Uuid,
        master_key: &MasterKeyInput,
    ) -> CoreResult<StaticPasswordPlaintext> {
        master_key.validate()?;

        let entry = self.get_static_password_entry(uuid)?;
        let device = self.get_device(entry.device_uuid)?;
        let decrypted = self.decrypt_device_seed_internal(&device, master_key)?;

        self.decrypt_static_with_seed(&entry, &decrypted.seed)
    }

    pub fn get_static_password_entry(&self, uuid: Uuid) -> CoreResult<StaticPassword> {
        self.with_session(|session| {
            session
                .payload
                .find_static_password(uuid)
                .cloned()
                .ok_or_else(|| StaticPasswordError::UuidNotFound(uuid.to_string()).into())
        })
    }

    fn decrypt_static_with_seed(
        &self,
        entry: &StaticPassword,
        seed: &[u8; 32],
    ) -> CoreResult<StaticPasswordPlaintext> {
        let aad = entry.aad();
        let kmac_context = CryptoContext::StaticPasswordKey { entry: entry.uuid }.build();
        let key: zeroize::Zeroizing<[u8; 32]> = zeroize::Zeroizing::new(
            self.crypto
                .derive_kmac256(seed, &kmac_context, 32)
                .map_err(|_| StaticPasswordError::DecryptionFailed)?
                .try_into()
                .map_err(|_| StaticPasswordError::DecryptionFailed)?,
        );

        let plaintext_bytes = zeroize::Zeroizing::new(
            self.crypto
                .decrypt_aead(&key, &entry.nonce, aad.as_bytes(), &entry.ciphertext)
                .map_err(|_| StaticPasswordError::DecryptionFailed)?,
        );
        drop(key);

        serde_json::from_slice(&plaintext_bytes)
            .map_err(|_| StaticPasswordError::DecryptionFailed.into())
    }

    pub fn update_static_password(
        &self,
        uuid: Uuid,
        new_plaintext: StaticPasswordPlaintext,
        master_key: &MasterKeyInput,
    ) -> CoreResult<()> {
        master_key.validate()?;

        let entry = self.get_static_password_entry(uuid)?;
        let device = self.get_device(entry.device_uuid)?;
        let decrypted = self.decrypt_device_seed_internal(&device, master_key)?;

        let (nonce, ciphertext) = self.encrypt_static_password_payload(
            entry.device_uuid,
            entry.uuid,
            &decrypted.seed,
            &new_plaintext,
        )?;

        self.with_session_mut(|session| {
            let entry = session
                .payload
                .find_static_password_mut(uuid)
                .ok_or(StaticPasswordError::UuidNotFound(uuid.to_string()))?;

            entry.nonce = nonce;
            entry.ciphertext = ciphertext;
            entry.label = new_plaintext.label.clone();
            entry.compromised = new_plaintext.compromised;
            Ok(())
        })
    }

    pub fn remove_static_password(&self, uuid: Uuid) -> CoreResult<()> {
        self.with_session_mut(|session| {
            if session.payload.find_static_password(uuid).is_none() {
                return Err(StaticPasswordError::UuidNotFound(uuid.to_string()).into());
            }

            session
                .payload
                .static_passwords
                .retain(|s| s.uuid != uuid);
            Ok(())
        })
    }

    pub fn list_static_passwords(&self, device_uuid: Uuid) -> CoreResult<Vec<StaticPassword>> {
        self.with_session(|session| {
            Ok(session
                .payload
                .static_passwords
                .iter()
                .filter(|s| s.device_uuid == device_uuid)
                .cloned()
                .collect())
        })
    }

    /// Cria uma pasta de senhas estáticas vazia usando StaticFolder para que não fique só em memória 
    pub fn add_static_folder(&self, device_uuid: Uuid, name: &str) -> CoreResult<()> {
        self.with_session_mut(|session| {
            let already_exists = session
                .payload
                .static_passwords
                .iter()
                .any(|p| p.device_uuid == device_uuid && p.folder_path == name)
                || session
                    .payload
                    .static_folders
                    .iter()
                    .any(|f| f.device_uuid == device_uuid && f.name == name);

            if already_exists {
                return Err(StaticPasswordError::FolderAlreadyExists(name.to_string()).into());
            }

            session.payload.static_folders.push(StaticFolder {
                device_uuid,
                name: name.to_string(),
            });
            Ok(())
        })
    }

    /// Lista os nomes de pasta de um dispositivo - Listando tanto as pastas com StaticFolder tanto com StaticPassword
    pub fn list_static_password_folders(&self, device_uuid: Uuid) -> CoreResult<Vec<String>> {
        self.with_session(|session| {
            let mut names: Vec<String> = Vec::new();

            for password in &session.payload.static_passwords {
                if password.device_uuid == device_uuid && !names.contains(&password.folder_path) {
                    names.push(password.folder_path.clone());
                }
            }
            for folder in &session.payload.static_folders {
                if folder.device_uuid == device_uuid && !names.contains(&folder.name) {
                    names.push(folder.name.clone());
                }
            }

            Ok(names)
        })
    }

    pub fn rename_static_password_folder(
        &self,
        device_uuid: Uuid,
        old_folder: &str,
        new_folder: &str,
    ) -> CoreResult<()> {
        self.with_session_mut(|session| {
            let mut found = false;
            for password in session.payload.static_passwords.iter_mut() {
                if password.device_uuid == device_uuid && password.folder_path == old_folder {
                    password.folder_path = new_folder.to_string();
                    found = true;
                }
            }
            for folder in session.payload.static_folders.iter_mut() {
                if folder.device_uuid == device_uuid && folder.name == old_folder {
                    folder.name = new_folder.to_string();
                    found = true;
                }
            }

            if !found {
                return Err(StaticPasswordError::NotFound(old_folder.to_string()).into());
            }

            Ok(())
        })
    }

    pub fn rename_static_password(
        &self,
        uuid: Uuid,
        new_label: &str,
        master_key: &MasterKeyInput,
    ) -> CoreResult<()> {
        if new_label.trim().is_empty() {
            return Err(CommonError::OutOfRange("O nome não pode estar vazio.".to_string()).into());
        }
        master_key.validate()?;

        let entry = self.get_static_password_entry(uuid)?;
        let device = self.get_device(entry.device_uuid)?;
        let decrypted = self.decrypt_device_seed_internal(&device, master_key)?;

        let current = self.decrypt_static_with_seed(&entry, &decrypted.seed)?;
        if current.label != entry.label {
            return Err(StaticPasswordError::LabelMismatch.into());
        }

        let new_label = new_label.trim().to_string();
        let new_plaintext = StaticPasswordPlaintext {
            label:       new_label.clone(),
            value:       current.value.clone(),
            notes:       current.notes.clone(),
            compromised: current.compromised,
        };

        let (nonce, ciphertext) = self.encrypt_static_password_payload(
            entry.device_uuid,
            entry.uuid,
            &decrypted.seed,
            &new_plaintext,
        )?;

        self.with_session_mut(|session| {
            let password = session
                .payload
                .find_static_password_mut(uuid)
                .ok_or_else(|| StaticPasswordError::NotFound(uuid.to_string()))?;

            password.label      = new_label;
            password.nonce      = nonce;
            password.ciphertext = ciphertext;
            Ok(())
        })
    }

    pub fn clear_static_password_folder(
        &self,
        device_uuid: Uuid,
        folder: &str,
    ) -> CoreResult<()> {
        self.with_session_mut(|session| {
            let mut found = false;
            for password in session.payload.static_passwords.iter_mut() {
                if password.device_uuid == device_uuid && password.folder_path == folder {
                    password.folder_path.clear();
                    found = true;
                }
            }

            let before_len = session.payload.static_folders.len();
            session.payload.static_folders.retain(|f| {
                !(f.device_uuid == device_uuid && f.name == folder)
            });
            if session.payload.static_folders.len() != before_len {
                found = true;
            }

            if !found {
                return Err(StaticPasswordError::NotFound(folder.to_string()).into());
            }

            Ok(())
        })
    }

    pub fn mark_static_password_compromised(
        &self,
        uuid: Uuid,
        master_key: &MasterKeyInput,
    ) -> CoreResult<()> {
        master_key.validate()?;

        let entry = self.get_static_password_entry(uuid)?;
        let device = self.get_device(entry.device_uuid)?;
        let decrypted = self.decrypt_device_seed_internal(&device, master_key)?;

        let mut current = self.decrypt_static_with_seed(&entry, &decrypted.seed)?;
        current.compromised = true;

        let (nonce, ciphertext) = self.encrypt_static_password_payload(
            entry.device_uuid,
            entry.uuid,
            &decrypted.seed,
            &current,
        )?;

        self.with_session_mut(|session| {
            let stored = session
                .payload
                .find_static_password_mut(uuid)
                .ok_or(StaticPasswordError::UuidNotFound(uuid.to_string()))?;
            stored.nonce = nonce;
            stored.ciphertext = ciphertext;
            stored.compromised = true;
            Ok(())
        })
    }

    fn encrypt_static_password_payload(
        &self,
        device_uuid: Uuid,
        entry_uuid: Uuid,
        seed: &[u8; 32],
        plaintext: &StaticPasswordPlaintext,
    ) -> CoreResult<([u8; 24], Vec<u8>)> {
        let aad = CryptoContext::StaticPasswordAad {
            entry: entry_uuid,
            device: device_uuid,
        }
        .build();

        let kmac_context = CryptoContext::StaticPasswordKey { entry: entry_uuid }.build();
        let key: zeroize::Zeroizing<[u8; 32]> = zeroize::Zeroizing::new(
            self.crypto
                .derive_kmac256(seed, &kmac_context, 32)
                .map_err(|_| StaticPasswordError::EncryptionFailed)?
                .try_into()
                .map_err(|_| StaticPasswordError::EncryptionFailed)?,
        );

        let plaintext_bytes = zeroize::Zeroizing::new(
            serde_json::to_vec(plaintext)
                .map_err(|_| StaticPasswordError::EncryptionFailed)?,
        );

        let nonce = self.crypto.generate_random_24()?;
        let ciphertext = self.crypto
            .encrypt_aead(&key, &nonce, aad.as_bytes(), &plaintext_bytes)
            .map_err(|_| StaticPasswordError::EncryptionFailed)?;

        Ok((nonce, ciphertext))
    }

    pub fn create_xor_files(
        &self,
        k1: &str,
        k2: &str,
        path_a: &str,
        path_b: &str,
    ) -> CoreResult<()> {
        self.files
            .create_xor_files(k1, k2, path_a, path_b)
            .map_err(CoreError::Xor)
    }

    pub fn recover_keys_from_xor(
        &self,
        path_a: &str,
        path_b: &str,
    ) -> CoreResult<MasterKeyInput> {
        let (k1, k2) = self
            .files
            .read_xor_files(path_a, path_b)
            .map_err(CoreError::Xor)?;
        Ok(MasterKeyInput::new(k1, k2))
    }

    pub fn get_local_state(&self) -> LocalState {
        let state = self.read_state();
        state.local_state.clone()
    }

    fn persist_local_state(&self, local_state: LocalState) -> CoreResult<()> {
        if !self.persist_local_state {
            return Ok(());
        }

        self.files
            .save_local_state(&local_state)
            .map_err(CoreError::LocalState)?;
        Ok(())
    }

    pub fn default_session_path(&self) -> CoreResult<std::path::PathBuf> {
        self.files
            .default_session_path()
            .map_err(CoreError::LocalState)
    }

    pub fn clear_local_state(&self) -> CoreResult<()> {
        let mut state = self.write_state();
        state.local_state = LocalState::new();
        let snapshot = state.local_state.clone();
        drop(state);
        self.persist_local_state(snapshot)?;
        Ok(())
    }

    pub fn delete_local_state(&self) -> CoreResult<()> {
        self.files.delete_local_state().map_err(CoreError::LocalState)?;

        let mut state = self.write_state();
        state.local_state = LocalState::new();
        Ok(())
    }

    pub fn set_last_session_path(&self, path: Option<String>) -> CoreResult<()> {
        let mut state = self.write_state();
        state.local_state.last_session_path = path;
        let snapshot = state.local_state.clone();
        drop(state);
        self.persist_local_state(snapshot)?;
        Ok(())
    }

    pub fn update_session_file_hash(&self, hash: [u8; 32]) -> CoreResult<()> {
        let mut state = self.write_state();
        state.local_state.session_file_hash = Some(hash);
        state.local_state.session_file_timestamp = Some(Utc::now());
        let snapshot = state.local_state.clone();
        drop(state);
        self.persist_local_state(snapshot)?;
        Ok(())
    }

    pub fn set_wasm_browser_storage(&self, enabled: bool) -> CoreResult<()> {
        let mut state = self.write_state();
        state.local_state.wasm_browser_storage = enabled;
        let snapshot = state.local_state.clone();
        drop(state);
        self.persist_local_state(snapshot)?;
        Ok(())
    }

    pub fn set_calibration_targets(
        &self,
        min_target_ms: Option<u128>,
        max_target_ms: Option<u128>,
    ) -> CoreResult<()> {
        let mut state = self.write_state();
        state.local_state.calibration_min_target_ms = min_target_ms;
        state.local_state.calibration_max_target_ms = max_target_ms;
        let snapshot = state.local_state.clone();
        drop(state);
        self.persist_local_state(snapshot)?;
        Ok(())
    }

    pub fn update_session_argon2_params(&self, argon2: Argon2Params) -> CoreResult<()> {
        self.with_session_mut(|session| {
            session.session_file.header.argon2 = argon2;
            Ok(())
        })
    }

    pub fn update_device_argon2_and_regenerate_salt(
        &self,
        device_uuid: Uuid,
        master_key: &MasterKeyInput,
        argon2: Argon2Params,
    ) -> CoreResult<[u8; 32]> {
        let device = self.get_device(device_uuid)?;
        let decrypted = self.decrypt_device_seed_internal(&device, master_key)?;
        let new_salt = self.crypto.generate_random_32()?;
        let new_nonce = self.crypto.generate_random_24()?;

        let k_user_bytes = zeroize::Zeroizing::new(master_key.normalize_and_concat());
        let new_kek = zeroize::Zeroizing::new(self.crypto.derive_argon2(
            &k_user_bytes,
            &new_salt,
            argon2.m_cost_kib,
            argon2.t_cost,
            argon2.p_cost,
        )?);
        drop(k_user_bytes);

        let aad = CryptoContext::SeedAad { device: device_uuid }.build_bytes();
        let ciphertext = self.crypto.encrypt_aead(
            &new_kek,
            &new_nonce,
            &aad,
            &decrypted.seed,
        )?;
        drop(new_kek);

        self.with_session_mut(|session| {
            let target = session
                .payload
                .find_device_mut(device_uuid)
                .ok_or(DeviceError::UuidNotFound(device_uuid.to_string()))?;

            target.argon2 = argon2;
            target.salt_device = new_salt;
            target.seed_envelope.nonce = new_nonce;
            target.seed_envelope.ciphertext = ciphertext;

            Ok(new_salt)
        })
    }

    pub fn regenerate_device_salt(
        &self,
        device_uuid: Uuid,
        master_key: &MasterKeyInput,
    ) -> CoreResult<[u8; 32]> {
        let device = self.get_device(device_uuid)?;
        let argon2 = device.argon2.clone();

        let decrypted = self.decrypt_device_seed_internal(&device, master_key)?;
        let new_salt = self.crypto.generate_random_32()?;
        let new_nonce = self.crypto.generate_random_24()?;

        let k_user_bytes = zeroize::Zeroizing::new(master_key.normalize_and_concat());
        let new_kek = zeroize::Zeroizing::new(self.crypto.derive_argon2(
            &k_user_bytes,
            &new_salt,
            argon2.m_cost_kib,
            argon2.t_cost,
            argon2.p_cost,
        )?);
        drop(k_user_bytes);

        let aad = CryptoContext::SeedAad { device: device_uuid }.build_bytes();
        let ciphertext = self.crypto.encrypt_aead(
            &new_kek,
            &new_nonce,
            &aad,
            &decrypted.seed,
        )?;
        drop(new_kek);

        self.with_session_mut(|session| {
            let target = session
                .payload
                .find_device_mut(device_uuid)
                .ok_or(DeviceError::UuidNotFound(device_uuid.to_string()))?;

            target.salt_device = new_salt;
            target.seed_envelope.nonce = new_nonce;
            target.seed_envelope.ciphertext = ciphertext;

            Ok(new_salt)
        })
    }

    pub fn update_device_seed_nonce(
        &self,
        device_uuid: Uuid,
        master_key: &MasterKeyInput,
    ) -> CoreResult<[u8; 24]> {
        let new_nonce = self.crypto.generate_random_24()?;
        let device = self.get_device(device_uuid)?;
        let aad = device.seed_aad();
        let k_user_bytes = zeroize::Zeroizing::new(master_key.normalize_and_concat());
        let kek = zeroize::Zeroizing::new(self.crypto.derive_argon2(
            &k_user_bytes,
            &device.salt_device,
            device.argon2.m_cost_kib,
            device.argon2.t_cost,
            device.argon2.p_cost,
        )?);
        drop(k_user_bytes);

        let seed_bytes = zeroize::Zeroizing::new(
            self.crypto
                .decrypt_aead(
                    &kek,
                    &device.seed_envelope.nonce,
                    &aad,
                    &device.seed_envelope.ciphertext,
                )
                .map_err(|_| DeviceError::SeedDecryptionFailed)?,
        );

        if seed_bytes.len() != 32 {
            return Err(DeviceError::SeedCorrupted.into());
        }

        let ciphertext = self
            .crypto
            .encrypt_aead(&kek, &new_nonce, &aad, &seed_bytes)?;

        drop(seed_bytes);
        drop(kek);

        self.with_session_mut(|session| {
            let target = session
                .payload
                .find_device_mut(device_uuid)
                .ok_or(DeviceError::UuidNotFound(device_uuid.to_string()))?;

            target.seed_envelope.nonce = new_nonce;
            target.seed_envelope.ciphertext = ciphertext;

            Ok(new_nonce)
        })
    }

    pub fn regenerate_session_salt(&self) -> CoreResult<[u8; 32]> {
        let new_salt = self.crypto.generate_random_32().map_err(CoreError::Crypto)?;
        self.with_session_mut(|session| {
            session.session_file.header.salt_session = new_salt;
            Ok(new_salt)
        })
    }

    fn decrypt_seed_with_bytes(
        &self,
        k_user_bytes: &[u8],
        salt_device: &[u8; 32],
        argon2: &Argon2Params,
        device_uuid: Uuid,
        seed_envelope: &SeedEnvelope,
    ) -> CoreResult<zeroize::Zeroizing<[u8; 32]>> {
        let kek = zeroize::Zeroizing::new(self.crypto.derive_argon2(
            k_user_bytes,
            salt_device,
            argon2.m_cost_kib,
            argon2.t_cost,
            argon2.p_cost,
        )?);

        let aad = CryptoContext::SeedAad { device: device_uuid }.build_bytes();
        let seed_bytes = zeroize::Zeroizing::new(
            self.crypto
                .decrypt_aead(
                    &kek,
                    &seed_envelope.nonce,
                    &aad,
                    &seed_envelope.ciphertext,
                )
                .map_err(|_| DeviceError::SeedDecryptionFailed)?,
        );
        drop(kek);

        if seed_bytes.len() != 32 {
            return Err(DeviceError::SeedCorrupted.into());
        }

        let mut seed = zeroize::Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(&seed_bytes);
        Ok(seed)
    }

    pub fn decrypt_device_seed_internal(
        &self,
        device: &Device,
        master_key: &MasterKeyInput,
    ) -> CoreResult<DecryptedSeed> {
        let k_user_bytes = zeroize::Zeroizing::new(master_key.normalize_and_concat());
        let seed = self.decrypt_seed_with_bytes(
            &k_user_bytes,
            &device.salt_device,
            &device.argon2,
            device.uuid,
            &device.seed_envelope,
        )?;

        Ok(DecryptedSeed {
            device_uuid: device.uuid,
            seed: *seed,
        })
    }

    pub fn prepare_export(
        &self,
        device_uuids: &[Uuid],
        restriction_uuids: &[Uuid],
        domain_uuids: &[Uuid],
        static_uuids: &[Uuid],
        include_compromised: bool,
        include_metadata: bool,
    ) -> CoreResult<ExportPrepared> {
        let state = self.read_state();
        let session = state.require_session()?;

        let mut prepared = ExportPrepared {
            devices: Vec::new(),
            include_compromised,
            include_metadata,
        };

        let devices: Vec<_> = if device_uuids.is_empty() {
            session.payload.devices.iter().collect()
        } else {
            session
                .payload
                .devices
                .iter()
                .filter(|d| device_uuids.contains(&d.uuid))
                .collect()
        };

        for device in &devices {
            let mut dev_prepared = ExportDevicePrepared {
                device_uuid: device.uuid,
                device_name: device.name.clone(),                
                salt_device: device.salt_device,
                argon2: device.argon2.clone(),
                seed_envelope: device.seed_envelope.clone(),
                derivations: Vec::new(),
                static_entries: Vec::new(),
            };

            let restrictions: Vec<_> = if restriction_uuids.is_empty() {
                session
                    .payload
                    .restrictions
                    .iter()
                    .filter(|r| r.device_uuid == device.uuid)
                    .collect()
            } else {
                session
                    .payload
                    .restrictions
                    .iter()
                    .filter(|r| {
                        r.device_uuid == device.uuid && restriction_uuids.contains(&r.uuid)
                    })
                    .collect()
            };

            for restriction in &restrictions {
                let bit_lists = Arc::new(restriction.build_bit_lists());
                let default_mask = restriction.generation.effective_default_mask();
                let bytes_to_derive = restriction.generation.effective_bytes_to_derive();

                let resolved_masks: Arc<Vec<MaskOrLiteral>> =
                    Arc::new(match restriction.generation.resolved_sequence() {
                        Some(resolved) => resolved,
                        None => {
                            let derive_bits = (bytes_to_derive * 8) as u32;
                            generator::build_max_masks(default_mask, &bit_lists, derive_bits)
                        }
                    });

                let domains: Vec<_> = if domain_uuids.is_empty() {
                    session
                        .payload
                        .domains
                        .iter()
                        .filter(|d| d.restriction_uuid == restriction.uuid)
                        .collect()
                } else {
                    session
                        .payload
                        .domains
                        .iter()
                        .filter(|d| {
                            d.restriction_uuid == restriction.uuid
                                && domain_uuids.contains(&d.uuid)
                        })
                        .collect()
                };

                for domain in &domains {
                    let kmac_context = CryptoContext::DerivedPassword {
                        domain_canonical: &domain.identifier_canonical,
                        variation: domain.active_variation,
                        device: device.uuid,
                        restriction: restriction.uuid,
                    }
                    .build();

                    dev_prepared.derivations.push(ExportDerivation {
                        kmac_context,
                        bytes_to_derive,
                        resolved_masks: Arc::clone(&resolved_masks),
                        bit_lists: Arc::clone(&bit_lists),
                        output_meta: ExportOutputMeta {
                            entry_type: "derivada".to_string(),
                            device_name: device.name.clone(),
                            group_name: restriction.name.clone(),
                            identifier: domain.identifier_canonical.clone(),
                            variation: Some(domain.active_variation),
                            is_compromised: false,
                            compromise_date: None,
                        },
                    });

                    if include_compromised {
                        for record in &domain.compromise_history {
                            let frozen_masks: Arc<Vec<MaskOrLiteral>> = match &record
                                .frozen_config
                                .format_sequence_snapshot
                            {
                                Some(seq) => Arc::new(resolve_sequence(
                                    seq,
                                    record.frozen_config.default_mask_snapshot,
                                )),
                                None => Arc::clone(&resolved_masks),
                            };

                            let frozen_bit_lists =
                                build_bit_lists(&record.frozen_config.char_lists_snapshot);

                            dev_prepared.derivations.push(ExportDerivation {
                                kmac_context: record.frozen_config.kmac_context.clone(),
                                bytes_to_derive: record.frozen_config.bytes_to_derive,
                                resolved_masks: frozen_masks,
                                bit_lists: Arc::new(frozen_bit_lists),
                                output_meta: ExportOutputMeta {
                                    entry_type: "derivada".to_string(),
                                    device_name: device.name.clone(),
                                    group_name: restriction.name.clone(),
                                    identifier: record.frozen_config.identifier_frozen.clone(),
                                    variation: Some(record.variation),
                                    is_compromised: true,
                                    compromise_date: Some(
                                        record
                                            .timestamp
                                            .format("%Y-%m-%d %H:%M:%S")
                                            .to_string(),
                                    ),
                                },
                            });
                        }
                    }
                }
            }

            let statics: Vec<_> = session
                .payload
                .static_passwords
                .iter()
                .filter(|sp| {
                    sp.device_uuid == device.uuid
                        && (static_uuids.is_empty() || static_uuids.contains(&sp.uuid))
                        && (include_compromised || !sp.compromised)
                })
                .collect();

            for sp in &statics {
                dev_prepared.static_entries.push(ExportStaticEntry {
                    kmac_context: CryptoContext::StaticPasswordKey { entry: sp.uuid }.build(),
                    aad: sp.aad(),
                    nonce: sp.nonce,
                    ciphertext: sp.ciphertext.clone(),
                    output_meta: ExportOutputMeta {
                        entry_type: "estática".to_string(),
                        device_name: device.name.clone(),
                        group_name: sp.folder_path.clone(),
                        identifier: sp.label.clone(),
                        variation: None,
                        is_compromised: sp.compromised,
                        compromise_date: None,
                    },
                });
            }

            prepared.devices.push(dev_prepared);
        }

        Ok(prepared)
    }

    pub fn execute_export(
        &self,
        prepared: &ExportPrepared,
        master_key: &MasterKeyInput,
    ) -> CoreResult<(PasswordExportData, Duration)> {
        master_key.validate()?;

        let mut export = PasswordExportData::new(prepared.include_metadata);
        let mut generation_duration = Duration::ZERO;

        // Normalized once (not per device); zeroized on any path.
        let k_user_bytes = zeroize::Zeroizing::new(master_key.normalize_and_concat());

        for dev in &prepared.devices {
            let seed = self.decrypt_seed_with_bytes(
                &k_user_bytes,
                &dev.salt_device,
                &dev.argon2,
                dev.device_uuid,
                &dev.seed_envelope,
            )?;

            let mut derived_entropies: Vec<zeroize::Zeroizing<Vec<u8>>> =
                Vec::with_capacity(dev.derivations.len());

            for derivation in &dev.derivations {
                let entropy = self
                    .crypto
                    .derive_kmac256(&seed, &derivation.kmac_context, derivation.bytes_to_derive)
                    .map_err(|_| PasswordError::KmacContextError)?;
                derived_entropies.push(zeroize::Zeroizing::new(entropy));
            }

            let mut static_values: Vec<Option<String>> =
                Vec::with_capacity(dev.static_entries.len());

            for entry in &dev.static_entries {
                let key: Result<zeroize::Zeroizing<[u8; 32]>, _> = self
                    .crypto
                    .derive_kmac256(&seed, &entry.kmac_context, 32)
                    .map_err(|_| StaticPasswordError::DecryptionFailed)
                    .and_then(|bytes| {
                        bytes
                            .try_into()
                            .map(zeroize::Zeroizing::new)
                            .map_err(|_| StaticPasswordError::DecryptionFailed)
                    });
                let key = key?;

                let outcome = self
                    .crypto
                    .decrypt_aead(&key, &entry.nonce, entry.aad.as_bytes(), &entry.ciphertext);
                drop(key);

                match outcome {
                    Ok(pt_bytes) => {
                        let pt_bytes = zeroize::Zeroizing::new(pt_bytes);
                        if let Ok(mut pt) = serde_json::from_slice::<StaticPasswordPlaintext>(&pt_bytes) {
                            static_values.push(Some(std::mem::take(&mut pt.value)));
                        } else {
                            static_values.push(None);
                        }
                    }
                    Err(_) => static_values.push(None),
                }
            }

            drop(seed);

            for (i, derivation) in dev.derivations.iter().enumerate() {
                let entropy = &derived_entropies[i];

                let gen_start = Instant::now();
                let result = generator::generate_password(
                    entropy,
                    &derivation.resolved_masks,
                    &derivation.bit_lists,
                )?;
                generation_duration += gen_start.elapsed();

                export.entries.push(ExportEntry {
                    entry_type: derivation.output_meta.entry_type.clone(),
                    device_name: derivation.output_meta.device_name.clone(),
                    group_name: derivation.output_meta.group_name.clone(),
                    identifier: derivation.output_meta.identifier.clone(),
                    password: result.password,
                    variation: derivation.output_meta.variation,
                    is_compromised: derivation.output_meta.is_compromised,
                    compromise_date: derivation.output_meta.compromise_date.clone(),
                });
            }

            for (i, entry) in dev.static_entries.iter().enumerate() {
                if let Some(value) = &static_values[i] {
                    export.entries.push(ExportEntry {
                        entry_type: entry.output_meta.entry_type.clone(),
                        device_name: entry.output_meta.device_name.clone(),
                        group_name: entry.output_meta.group_name.clone(),
                        identifier: entry.output_meta.identifier.clone(),
                        password: value.clone(),
                        variation: entry.output_meta.variation,
                        is_compromised: entry.output_meta.is_compromised,
                        compromise_date: entry.output_meta.compromise_date.clone(),
                    });
                }
            }

            drop(derived_entropies);
        }

        Ok((export, generation_duration))
    }

    fn compute_alphabet_sizes_for_mask(
        mask: u32,
        bit_lists: &HashMap<u8, Vec<String>>,
    ) -> Vec<usize> {
        let Ok(alphabet) = crate::generator::build_alphabet_dictionary(
            bit_lists,
            &[MaskOrLiteral::Mask(mask)],
        ) else {
            return vec![];
        };
        match alphabet.get(&mask) {
            Some(chars) => vec![chars.len()],
            None => vec![],
        }
    }

    fn compute_alphabet_sizes_for_masks(
        params: &GenerationParams,
        bit_lists: &HashMap<u8, Vec<String>>,
    ) -> Vec<usize> {
        match params.resolved_sequence() {
            Some(resolved) => {
                let Ok(dict) = crate::generator::build_alphabet_dictionary(bit_lists, &resolved)
                else {
                    return vec![];
                };

                resolved
                    .iter()
                    .filter_map(|item| {
                        item.as_mask()
                            .and_then(|m| dict.get(&m))
                            .map(|chars| chars.len())
                    })
                    .collect()
            }
            None => vec![],
        }
    }

    fn entropy_millibits_for_alphabet_sizes(alphabet_sizes: &[usize]) -> u64 {
        alphabet_sizes
            .iter()
            .filter(|&&size| size > 1)
            .map(|&size| crate::generator::log2_millibits(size))
            .sum()
    }

    fn refresh_restriction_bytes_to_derive(restriction: &mut Restriction) {
        let bit_lists = restriction.build_bit_lists();
        let alphabet_sizes = Self::compute_alphabet_sizes_for_masks(&restriction.generation, &bit_lists);
        restriction.generation.calculate_and_set_bytes_to_derive(&alphabet_sizes);
    }
}

/// Quanto menor o valor devolvido, melhor a correspondência (None = sem
/// correspondência). Ordem de prioridade: vazio > igual > prefixo > contém >
/// aproximado (distância de Levenshtein), cada nível numa gama de valores
/// separada para nunca se misturarem entre si.
fn fuzzy_search_score(needle: &str, haystack: &str) -> Option<u32> {
    // Pesquisa vazia corresponde a tudo - prioriza os resultados mais curtos.
    if needle.is_empty() {
        return Some(haystack.len() as u32);
    }
    // Correspondência exacta - sempre o melhor resultado possível.
    if needle == haystack {
        return Some(0);
    }
    // Prefixo - quanto mais curto o resto do texto, melhor.
    if haystack.starts_with(needle) {
        return Some(1 + (haystack.len() - needle.len()) as u32);
    }
    // Contém a pesquisa em qualquer posição.
    if haystack.contains(needle) {
        return Some(1_000 + (haystack.len() - needle.len()) as u32);
    }

    // Sem correspondência directa - tenta por semelhança (erros de
    // digitação), mas só até metade do tamanho da pesquisa, para não
    // devolver resultados demasiado distantes.
    let distance = levenshtein_distance(needle, haystack);
    let max_distance = (needle.chars().count() as u32 / 2).max(1);
    if distance > max_distance {
        return None;
    }
    Some(2_000 + distance * 100 + haystack.len() as u32)
}

/// Número mínimo de inserções/remoções/substituições de carateres para
/// transformar `a` em `b` - algoritmo clássico de programação dinâmica,
/// guardando só a linha anterior e a actual da matriz (em vez da matriz
/// completa) para usar menos memória.
fn levenshtein_distance(a: &str, b: &str) -> u32 {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (la, lb) = (a.len(), b.len());

    // Caso base: transformar string vazia na outra é só inserir tudo.
    if la == 0 {
        return lb as u32;
    }
    if lb == 0 {
        return la as u32;
    }

    // `prev`/`curr` representam a linha anterior/actual da matriz de
    // distâncias; começa com a linha 0 (transformar "" em cada prefixo de b).
    let mut prev: Vec<u32> = (0..=lb as u32).collect();
    let mut curr: Vec<u32> = vec![0; lb + 1];

    for i in 1..=la {
        curr[0] = i as u32; // transformar prefixo de a em "" é só remover tudo
        for j in 1..=lb {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            // Melhor entre: remover, inserir, substituir.
            curr[j] = (prev[j] + 1)
                .min(curr[j - 1] + 1)
                .min(prev[j - 1] + cost);
        }
        prev.copy_from_slice(&curr);
    }

    prev[lb]
}