#![allow(dead_code)]

pub use common::{canonicalize_domain, canonicalize_name, normalize_secrets};
pub use context::CryptoContext;
pub use device::{build_bit_lists, Argon2Params, CharacterList, Device, SeedEnvelope};
pub use domain::{CompromiseRecord, Domain, FrozenGeneratorConfig};
pub use local_state::LocalState;
#[allow(unused_imports)]
pub use selection_tree::{SelectionNode, SelectionNodeType};
pub use restriction::{resolve_sequence, GenerationParams, MaskOrLiteral, Restriction};
pub use session::{SessionFile, SessionHeader, SessionPayload};
pub use static_password::{StaticFolder, StaticPassword, StaticPasswordPlaintext};
pub use password_export::{ExportEntry, ExportFormat, PasswordExportData};
pub use runtime::{
    AppState, DecryptedSeed, DomainSearchResult, ExportBenchmarkReport, GeneratedPassword,
    MasterKeyInput, PasswordRequest, SecretBenchmarkReport, SessionOverview, SessionRuntime,
    SharedAppState, StaticPasswordSearchResult,
};

mod common {
    use serde_json::Value;
    use std::collections::HashMap;
    use unicode_normalization::UnicodeNormalization;

    pub type Dict = HashMap<String, Value>;

    #[allow(dead_code)]
    pub fn canonicalize_domain(input: &str) -> String {
        let normalized = input.trim().to_lowercase();
        let without_trailing_dot = normalized.trim_end_matches('.');
        let ascii = idna::domain_to_ascii(without_trailing_dot)
            .unwrap_or_else(|_| without_trailing_dot.to_string());
        ascii.nfc().collect()
    }

    /// Canonização para nomes genéricos (dispositivos, restrições, listas): trim + lowercase + NFC.
    pub fn canonicalize_name(input: &str) -> String {
        input.trim().to_lowercase().nfc().collect()
    }

    /// Canonização para segredos humanos K1/K2: trim + NFC + ordenação lexicográfica.
    pub fn normalize_secrets(inputs: &[&str]) -> Result<Vec<u8>, String> {
        use zeroize::Zeroize;

        if inputs.is_empty() {
            return Err("normalize_secrets: requires at least one input".to_string());
        }

        let mut normalized: Vec<String> = inputs
            .iter()
            .map(|value| value.trim().nfc().collect::<String>())
            .collect();
        normalized.sort();

        let mut output = Vec::new();
        for value in &normalized {
            output.extend_from_slice(value.as_bytes());
        }

        // As cópias NFC intermédias contêm os segredos - limpa antes de sair.
        for value in normalized.iter_mut() {
            value.zeroize();
        }

        Ok(output)
    }
}

mod context {
    use uuid::Uuid;

    /// Todos os formatos "v1|…" usados na crate são construídos exclusivamente
    pub enum CryptoContext<'a> {
        DerivedPassword {
            domain_canonical: &'a str,
            variation: u32,
            device: Uuid,
            restriction: Uuid,
        },
        StaticPasswordKey { entry: Uuid },
        StaticPasswordAad { entry: Uuid, device: Uuid },
        SeedAad { device: Uuid },
        CompromiseAad { domain: Uuid, variation: u32 },
    }

    impl CryptoContext<'_> {
        pub fn build(&self) -> String {
            match self {
                Self::DerivedPassword {
                    domain_canonical,
                    variation,
                    device,
                    restriction,
                } => format!(
                    "v1|domain:{domain_canonical}|variation:{variation}|device:{device}|restriction:{restriction}"
                ),
                Self::StaticPasswordKey { entry } => format!("v1|STATIC|{entry}"),
                Self::StaticPasswordAad { entry, device } => {
                    format!("v1|STATIC|senha_estatica:{entry}|device:{device}")
                }
                Self::SeedAad { device } => format!("v1|seed|device:{device}"),
                Self::CompromiseAad { domain, variation } => {
                    format!("v1|COMP|domain:{domain}|variation:{variation}")
                }
            }
        } 

        pub fn build_bytes(&self) -> Vec<u8> {
            self.build().into_bytes()
        }
    }
}

mod device {
    use serde::{Deserialize, Serialize};
    use uuid::Uuid;

    use super::common::canonicalize_name;

    const USER_BIT_MIN: u8 = 16;
    const USER_BIT_MAX: u8 = 31;

    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct Device {
        pub uuid: Uuid,
        pub name: String,
        pub salt_device: [u8; 32],
        pub argon2: Argon2Params,
        pub seed_envelope: SeedEnvelope,
    }

    impl Device {
        pub fn new(
            name: &str,
            salt_device: [u8; 32],
            argon2: Argon2Params,
            seed_envelope: SeedEnvelope,
        ) -> Self {
            Self {
                uuid: Uuid::new_v4(),
                name: canonicalize_name(name),
                salt_device,
                argon2,
                seed_envelope,
            }
        }

        /// AAD da seed: "v1|seed|device:<uuid>"
        pub fn seed_aad(&self) -> Vec<u8> {
            super::context::CryptoContext::SeedAad { device: self.uuid }.build_bytes()
        }
    }

    /// Única implementação na crate - usada por core, services e export.
    pub fn build_bit_lists(
        char_lists: &[CharacterList],
    ) -> std::collections::HashMap<u8, Vec<String>> {
        let mut map = std::collections::HashMap::new();
        for list in char_lists {
            map.entry(list.bit)
                .or_insert_with(Vec::new)
                .extend(list.elements.iter().cloned());
        }
        map
    }

    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct Argon2Params {
        pub m_cost_kib: u32,
        pub t_cost: u32,
        pub p_cost: u32,
    }

    /// Seed encriptada com KEK_device via XChaCha20-Poly1305.
    /// O AAD é computado a partir do UUID do dispositivo, não armazenado.
    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct SeedEnvelope {
        pub nonce: [u8; 24],
        pub ciphertext: Vec<u8>,
    }

    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct CharacterList {
        pub uuid: Uuid,
        pub name: String,
        pub bit: u8,
        pub elements: Vec<String>,
    }

    impl CharacterList {
        pub fn new(name: &str, bit: u8, elements: Vec<String>) -> Result<Self, String> {
            if !(USER_BIT_MIN..=USER_BIT_MAX).contains(&bit) {
                return Err(format!(
                    "Bit de CharList inválido: {} (esperado entre {} e {})",
                    bit, USER_BIT_MIN, USER_BIT_MAX
                ));
            }

            if elements.is_empty() {
                return Err("Lista de elementos vazia".to_string());
            }

            if elements.iter().any(|element| element.is_empty()) {
                return Err("Lista de elementos contém entradas vazias".to_string());
            }

            Ok(Self {
                uuid: Uuid::new_v4(),
                name: canonicalize_name(name),
                bit,
                elements,
            })
        }
    }
}

mod domain {
    use chrono::{DateTime, Utc};
    use serde::{Deserialize, Serialize};
    use uuid::Uuid;

    use super::common::canonicalize_domain;

    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct Domain {
        pub uuid: Uuid,
        pub identifier_canonical: String,
        pub restriction_uuid: Uuid,
        pub active_variation: u32,
        pub compromise_history: Vec<CompromiseRecord>,
    }

    impl Domain {
        pub fn new(identifier: &str, restriction_uuid: Uuid) -> Self {
            Self {
                uuid: Uuid::new_v4(),
                identifier_canonical: canonicalize_domain(identifier),
                restriction_uuid,
                active_variation: 0,
                compromise_history: Vec::new(),
            }
        }
    }

    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct CompromiseRecord {
        pub uuid: Uuid,
        pub variation: u32,
        pub timestamp: DateTime<Utc>,
        pub frozen_config: FrozenGeneratorConfig,
    }

    impl CompromiseRecord {
        pub fn new(variation: u32, frozen_config: FrozenGeneratorConfig) -> Self {
            Self {
                uuid: Uuid::new_v4(),
                variation,
                timestamp: chrono::Utc::now(),
                frozen_config,
            }
        }

        /// AAD: "v1|COMP|domain:<domain_uuid>|variation:<n>"
        pub fn aad(&self, domain_uuid: Uuid) -> String {
            super::context::CryptoContext::CompromiseAad {
                domain: domain_uuid,
                variation: self.variation,
            }
            .build()
        }
    }

    /// Snapshot completo da configuração de geração no momento do comprometimento.
    /// Permite recalcular deterministicamente a senha antiga.
    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct FrozenGeneratorConfig {
        pub config_version: u8,
        /// Contexto exato KMAC256.
        pub kmac_context: String,
        pub format_sequence_snapshot: Option<Vec<super::restriction::MaskOrLiteral>>,
        pub default_mask_snapshot: u32,
        /// Quantidade de bytes derivados pelo KMAC XOF no momento da geração.
        pub bytes_to_derive: usize,
        pub char_lists_snapshot: Vec<super::device::CharacterList>,
        /// Identificador canonizado no momento do comprometimento.
        pub identifier_frozen: String,
        /// HMAC-SHA256 da senha gerada, usando a seed como chave.
        pub password_hmac: Option<[u8; 32]>,
    }
}

mod restriction {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use uuid::Uuid;

    use crate::generator::log2_millibits;

    use super::common::canonicalize_name;

    const DEFAULT_MASK_FALLBACK: u32 = 7;
    const ENTROPY_MARGIN_BITS: u64 = 64;

    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct Restriction {
        pub uuid: Uuid,
        pub name: String,
        pub device_uuid: Uuid,
        pub generation: GenerationParams,
        pub char_lists: Vec<super::device::CharacterList>,
    }

    impl Restriction {
        pub fn new(name: &str, device_uuid: Uuid, generation: GenerationParams) -> Self {
            Self {
                uuid: Uuid::new_v4(),
                name: canonicalize_name(name),
                device_uuid,
                generation,
                char_lists: Vec::new(),
            }
        }

        pub fn build_bit_lists(&self) -> std::collections::HashMap<u8, Vec<String>> {
            super::device::build_bit_lists(&self.char_lists)
        }
    }

    /// Resolve uma sequência de formato: Mask(0) -> default_mask.
    /// Única implementação na crate - usada por core e services.
    pub fn resolve_sequence(
        seq: &[MaskOrLiteral],
        default_mask: u32,
    ) -> Vec<MaskOrLiteral> {
        seq.iter()
            .map(|item| match item {
                MaskOrLiteral::Mask(0) => MaskOrLiteral::Mask(default_mask),
                other => other.clone(),
            })
            .collect()
    }

    #[derive(Debug, Serialize, Deserialize, Clone, Default)]
    pub struct GenerationParams {
        pub default_mask: Option<u32>,
        pub format_sequence: Option<Vec<MaskOrLiteral>>,
        /// Quantidade de bytes que o KMAC XOF deve derivar para esta configuração
        pub bytes_to_derive: Option<usize>,
    }

    impl GenerationParams {
        pub fn sequence(&self) -> Option<&[MaskOrLiteral]> {
            self.format_sequence.as_deref()
        }

        /// Sequência com Mask(0) já substituído pelo default efetivo.
        pub fn resolved_sequence(&self) -> Option<Vec<MaskOrLiteral>> {
            self.sequence()
                .map(|seq| resolve_sequence(seq, self.effective_default_mask()))
        }

        pub fn effective_default_mask(&self) -> u32 {
            self.default_mask
                .filter(|mask| *mask != 0)
                .unwrap_or(DEFAULT_MASK_FALLBACK)
        }

        /// Calcula bytes_to_derive a partir das bases dos alfabetos.
        /// Deve ser chamado sempre que o formato muda.
        /// `alphabet_sizes`: tamanho do alfabeto para cada posição aleatória (Mask).
        pub fn calculate_and_set_bytes_to_derive(&mut self, alphabet_sizes: &[usize]) {
            self.bytes_to_derive = Some(Self::compute_bytes_to_derive(alphabet_sizes));
        }

        /// Calcula bytes_to_derive sem modificar self.
        pub fn compute_bytes_to_derive(alphabet_sizes: &[usize]) -> usize {
            if alphabet_sizes.is_empty() {
                return 32; // mínimo
            }

            let bits_needed_millibits: u64 = alphabet_sizes
                .iter()
                .filter(|&&size| size > 1)
                .map(|&size| log2_millibits(size))
                .sum();

            let bits_needed_ceil = bits_needed_millibits.div_ceil(1000);
            let bits_to_derive = bits_needed_ceil + ENTROPY_MARGIN_BITS;

            bits_to_derive.div_ceil(8) as usize
        }

        /// Retorna bytes_to_derive, ou 32 como fallback.
        pub fn effective_bytes_to_derive(&self) -> usize {
            self.bytes_to_derive.unwrap_or(32)
        }

        /// Exemplo: "[ ][ ][ ]-[ ][ ][ ][ ]"
        /// onde [ ] = posição aleatória (padrão), [0] = posição com máscara 0
        /// e - = literal fixo.
        pub fn format_visual(&self) -> String {
            match self.sequence() {
                Some(seq) => {
                    seq.iter()
                        .map(|item| match item {
                            MaskOrLiteral::Mask(0) => "[ ]".to_string(),
                            MaskOrLiteral::Mask(m) => format!("[{}]", m),
                            MaskOrLiteral::Literal(text) => text.clone(),
                        })
                        .collect::<String>()
                }
                None => "(sem formato definido)".to_string(),
            }
        }

        pub fn random_position_count(&self) -> usize {
            match self.sequence() {
                Some(seq) => seq.iter().filter(|item| item.as_mask().is_some()).count(),
                None => 0,
            }
        }

        /// Calcula o comprimento recomendado para atingir 256 bits de entropia.
        /// Dado um tamanho de alfabeto uniforme.
        pub fn recommended_length(alphabet_size: usize) -> usize {
            if alphabet_size <= 1 {
                return 0;
            }
            let bits_per_char_milli = log2_millibits(alphabet_size);
            if bits_per_char_milli == 0 {
                return 0;
            }
            256_000_u64.div_ceil(bits_per_char_milli) as usize
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum MaskOrLiteral {
        Mask(u32),
        Literal(String),
    }

    impl MaskOrLiteral {
        pub fn from_mask(mask: u32) -> Self {
            Self::Mask(mask)
        }

        pub fn from_literal<S: Into<String>>(value: S) -> Result<Self, String> {
            let value = value.into();
            let inner = value
                .strip_prefix('/')
                .and_then(|value| value.strip_suffix('/'))
                .ok_or_else(|| {
                    format!(
                        "Literal inválido: '{}' (esperado formato '/texto/')",
                        value
                    )
                })?;

            if inner.is_empty() {
                return Err("Literal inválido: '/.../' não pode estar vazio".into());
            }

            Ok(Self::Literal(inner.to_string()))
        }

        pub fn as_literal(&self) -> Option<&str> {
            match self {
                Self::Literal(value) => Some(value),
                Self::Mask(_) => None,
            }
        }

        pub fn as_mask(&self) -> Option<u32> {
            match self {
                Self::Mask(mask) => Some(*mask),
                Self::Literal(_) => None,
            }
        }

        pub fn is_mask_valid_for_engine(&self) -> bool {
            match self {
                Self::Mask(mask) => *mask != 0 && *mask != DEFAULT_MASK_FALLBACK,
                Self::Literal(_) => true,
            }
        }
    }

    impl Serialize for MaskOrLiteral {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            match self {
                Self::Mask(mask) => serializer.serialize_u32(*mask),
                Self::Literal(text) => serializer.serialize_str(&format!("/{text}/")),
            }
        }
    }

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum MaskOrLiteralRepr {
        Mask(u32),
        Literal(String),
    }

    impl<'de> Deserialize<'de> for MaskOrLiteral {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'de>,
        {
            match MaskOrLiteralRepr::deserialize(deserializer)? {
                MaskOrLiteralRepr::Mask(mask) => Ok(Self::Mask(mask)),
                MaskOrLiteralRepr::Literal(value) => {
                    Self::from_literal(value).map_err(serde::de::Error::custom)
                }
            }
        }
    }
}

mod static_password {
    use serde::{Deserialize, Serialize};
    use uuid::Uuid;

    /// Entrada de senha estática armazenada encriptada no payload da sessão.
    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct StaticPassword {
        pub uuid: Uuid,
        pub device_uuid: Uuid,
        pub folder_path: String,
        pub label: String,
        pub nonce: [u8; 24],
        pub ciphertext: Vec<u8>,
        /// Flag em claro para separação visual sem desencriptação.
        /// Actualizada quando a senha é marcada como comprometida.
        pub compromised: bool,
    }

    impl StaticPassword {
        pub fn new(
            device_uuid: Uuid,
            folder_path: &str,
            label: &str,
            nonce: [u8; 24],
            ciphertext: Vec<u8>,
        ) -> Self {
            Self {
                uuid: Uuid::new_v4(),
                device_uuid,
                folder_path: folder_path.to_string(),
                label: label.to_string(),
                nonce,
                ciphertext,
                compromised: false,
            }
        }

        pub fn aad(&self) -> String {
            super::context::CryptoContext::StaticPasswordAad {
                entry: self.uuid,
                device: self.device_uuid,
            }
            .build()
        }
    }

    /// Pasta de senhas estáticas sem nenhuma senha
    #[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
    pub struct StaticFolder {
        pub device_uuid: Uuid,
        pub name: String,
    }

    #[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
    pub struct StaticPasswordPlaintext {
        pub label: String,
        pub value: String,
        pub notes: String,
        pub compromised: bool,
    }

    // O valor e as notas em claro são limpos da RAM quando a struct sai de âmbito
    impl Drop for StaticPasswordPlaintext {
        fn drop(&mut self) {
            use zeroize::Zeroize;
            self.value.zeroize();
            self.notes.zeroize();
        }
    }

    // Debug manual - nunca expor o valor ou as notas em logs.
    impl std::fmt::Debug for StaticPasswordPlaintext {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("StaticPasswordPlaintext")
                .field("label", &self.label)
                .field("value", &"<redacted>")
                .field("notes", &"<redacted>")
                .field("compromised", &self.compromised)
                .finish()
        }
    }
}

mod session {
    use serde::{Deserialize, Serialize};
    use uuid::Uuid;

    use super::{Device, Domain, Restriction, StaticFolder, StaticPassword};

    const SESSION_SCHEMA_VERSION: u32 = 1;

    /// Ficheiro de sessão em disco.
    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct SessionFile {
        pub header: SessionHeader,
        pub nonce_global: [u8; 24],
        pub ciphertext_global: Vec<u8>,
        pub session_hmac: Option<[u8; 32]>,
    }

    /// Cabeçalho em claro - visível sem desencriptação.
    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct SessionHeader {
        pub schema_version: u32,
        pub salt_session: [u8; 32],
        pub argon2: super::device::Argon2Params,
        pub hardware_enabled: bool,
        pub salt_hkdf: Option<[u8; 32]>,
    }

    impl SessionHeader {
        pub fn new(
            salt_session: [u8; 32],
            argon2: super::device::Argon2Params,
            hardware_enabled: bool,
            salt_hkdf: Option<[u8; 32]>,
        ) -> Self {
            Self {
                schema_version: SESSION_SCHEMA_VERSION,
                salt_session,
                argon2,
                hardware_enabled,
                salt_hkdf,
            }
        }
    }

    /// Payload desencriptado - apenas em RAM, nunca em disco em claro.
    #[derive(Debug, Serialize, Deserialize, Clone)]
    #[derive(Default)]
    pub struct SessionPayload {
        pub devices: Vec<Device>,
        pub restrictions: Vec<Restriction>,
        pub domains: Vec<Domain>,
        pub static_passwords: Vec<StaticPassword>,
        pub static_folders: Vec<StaticFolder>,
    }

    impl SessionPayload {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn find_domain(&self, uuid: Uuid) -> Option<&Domain> {
            self.domains.iter().find(|d| d.uuid == uuid)
        }

        pub fn find_restriction(&self, uuid: Uuid) -> Option<&Restriction> {
            self.restrictions.iter().find(|r| r.uuid == uuid)
        }

        pub fn find_device(&self, uuid: Uuid) -> Option<&Device> {
            self.devices.iter().find(|d| d.uuid == uuid)
        }

        pub fn find_static_password(&self, uuid: Uuid) -> Option<&StaticPassword> {
            self.static_passwords.iter().find(|s| s.uuid == uuid)
        }

        pub fn find_domain_mut(&mut self, uuid: Uuid) -> Option<&mut Domain> {
            self.domains.iter_mut().find(|d| d.uuid == uuid)
        }

        pub fn find_restriction_mut(&mut self, uuid: Uuid) -> Option<&mut Restriction> {
            self.restrictions.iter_mut().find(|r| r.uuid == uuid)
        }

        pub fn find_device_mut(&mut self, uuid: Uuid) -> Option<&mut Device> {
            self.devices.iter_mut().find(|d| d.uuid == uuid)
        }

        pub fn find_static_password_mut(&mut self, uuid: Uuid) -> Option<&mut StaticPassword> {
            self.static_passwords.iter_mut().find(|s| s.uuid == uuid)
        }

        pub fn resolve_domain_chain(
            &self,
            domain_uuid: Uuid,
        ) -> Result<(&Domain, &Restriction, &Device), String> {
            let domain = self
                .find_domain(domain_uuid)
                .ok_or_else(|| format!("Domain não encontrado: {domain_uuid}"))?;
            let restriction = self
                .find_restriction(domain.restriction_uuid)
                .ok_or_else(|| {
                    format!("Restriction não encontrada: {}", domain.restriction_uuid)
                })?;
            let device = self
                .find_device(restriction.device_uuid)
                .ok_or_else(|| {
                    format!("Device não encontrado: {}", restriction.device_uuid)
                })?;
            Ok((domain, restriction, device))
        }
    }
}

use uuid::Uuid;

mod selection_tree {
    #[derive(Debug, Clone)]
    pub struct SelectionNode {
        pub uuid: uuid::Uuid,
        pub label: String,
        pub node_type: SelectionNodeType,
        pub selected: bool,
        pub children: Vec<SelectionNode>,
    }

    #[derive(Debug, Clone, PartialEq)]
    pub enum SelectionNodeType {
        Device,
        Restriction,
        Folder,
        DerivedPassword,
        StaticPassword,
    }
}

/// Dados preparados para export - sem seeds, sem master key.
/// Organizado para pipeline rápido: seed -> derive -> limpa.
#[derive(Debug, Clone)]
pub struct ExportPrepared {
    pub devices: Vec<ExportDevicePrepared>,
    pub include_compromised: bool,
    pub include_metadata: bool,
}

/// Um dispositivo preparado para export.
/// Contém tudo necessário para derivar senhas após desencriptar a seed.
#[derive(Debug, Clone)]
pub struct ExportDevicePrepared {
    pub device_uuid: Uuid,
    pub device_name: String,
    pub salt_device: [u8; 32],
    pub argon2: Argon2Params,
    pub seed_envelope: SeedEnvelope,
    pub derivations: Vec<ExportDerivation>,
    pub static_entries: Vec<ExportStaticEntry>,
}

/// Máscaras e listas partilhadas por Arc - todos os domínios da mesma restrição apontam para os mesmos dados em vez de os clonar.
#[derive(Debug, Clone)]
pub struct ExportDerivation {
    pub kmac_context: String,
    pub bytes_to_derive: usize,
    pub resolved_masks: std::sync::Arc<Vec<MaskOrLiteral>>,
    pub bit_lists: std::sync::Arc<std::collections::HashMap<u8, Vec<String>>>,
    pub output_meta: ExportOutputMeta,
}

#[derive(Debug, Clone)]
pub struct ExportStaticEntry {
    pub kmac_context: String,
    pub aad: String,
    pub nonce: [u8; 24],
    pub ciphertext: Vec<u8>,
    pub output_meta: ExportOutputMeta,
}

#[derive(Debug, Clone)]
pub struct ExportOutputMeta {
    pub entry_type: String,
    pub device_name: String,
    pub group_name: String,
    pub identifier: String,
    pub variation: Option<u32>,
    pub is_compromised: bool,
    pub compromise_date: Option<String>,
}

mod password_export {
    use serde::Serialize;
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum ExportFormat {
        Csv,
        Json,
        Txt,
    }

    #[derive(Debug, Clone, Serialize)]
    pub struct ExportEntry {
        pub entry_type: String,
        pub device_name: String,
        pub group_name: String,
        pub identifier: String,
        pub password: String,
        pub variation: Option<u32>,
        pub is_compromised: bool,
        pub compromise_date: Option<String>,
    }

    #[derive(Debug, Clone)]
    pub struct PasswordExportData {
        pub entries: Vec<ExportEntry>,
        pub include_metadata: bool,
    }

    impl PasswordExportData {
        pub fn new(include_metadata: bool) -> Self {
            Self {
                entries: Vec::new(),
                include_metadata,
            }
        }

        pub fn to_json(&self) -> String {
            match serde_json::to_string_pretty(&self.entries) {
                Ok(s) => s,
                Err(_) => "[]".to_string(),
            }
        }

        fn escape_csv_field(s: &str) -> String {
            if s.contains(',') || s.contains('"') || s.contains('\n') {
                format!("\"{}\"", s.replace('"', "\"\""))
            } else {
                s.to_string()
            }
        }

        fn escape_csv_metadata_field(s: &str) -> String {
            if matches!(s.chars().next(), Some('=' | '+' | '-' | '@' | '\t' | '\r')) {
                Self::escape_csv_field(&format!("'{s}"))
            } else {
                Self::escape_csv_field(s)
            }
        }

        pub fn to_csv(&self) -> String {
            let mut out = String::new();
            out.push_str("entry_type,device_name,group_name,identifier,variation,is_compromised,compromise_date,password\n");
            for e in &self.entries {
                let variation = e.variation.map_or("".to_string(), |v| v.to_string());
                let compromised = if e.is_compromised { "1" } else { "0" };
                let compromise_date = e.compromise_date.clone().unwrap_or_default();
                out.push_str(&format!(
                    "{},{},{},{},{},{},{},{}\n",
                    Self::escape_csv_metadata_field(&e.entry_type),
                    Self::escape_csv_metadata_field(&e.device_name),
                    Self::escape_csv_metadata_field(&e.group_name),
                    Self::escape_csv_metadata_field(&e.identifier),
                    Self::escape_csv_metadata_field(&variation),
                    compromised,
                    Self::escape_csv_metadata_field(&compromise_date),
                    Self::escape_csv_field(&e.password),
                ));
            }
            out
        }

        pub fn to_txt(&self) -> String {
            if !self.include_metadata {
                let mut out = String::new();
                for e in &self.entries {
                    out.push_str(&format!("{}: {}\n", e.identifier, e.password));
                }
                return out;
            }

            use std::collections::BTreeMap;
            let mut map: BTreeMap<String, BTreeMap<String, Vec<&ExportEntry>>> = BTreeMap::new();
            for e in &self.entries {
                map.entry(e.device_name.clone())
                    .or_default()
                    .entry(e.group_name.clone())
                    .or_default()
                    .push(e);
            }

            let mut out = String::new();
            for (device, groups) in map {
                out.push_str(&format!("Device: {}\n", device));
                for (group, entries) in groups {
                    out.push_str(&format!("  {}\n", group));
                    for entry in entries {
                        let var_tag = entry
                            .variation
                            .map(|v| format!(" [var:{}]", v))
                            .unwrap_or_default();
                        let compromised_tag = if entry.is_compromised { " [COMPROMETIDA]" } else { "" };
                        out.push_str(&format!(
                            "    {}{}{}: {}\n",
                            entry.identifier, var_tag, compromised_tag, entry.password
                        ));
                    }
                }
                out.push('\n');
            }

            out
        }
    }
}

mod runtime {
    use std::sync::{Arc, RwLock};
    use std::time::Duration;

    use uuid::Uuid;
    use zeroize::Zeroize;

    use crate::errors::{SessionError, ValidationError};

    use super::session::{SessionFile, SessionHeader, SessionPayload};

    #[derive(Clone)]
    pub struct GeneratedPassword {
        pub password: String,
        pub entropy_millibits: u64,
        pub variation: u32,
        pub domain_uuid: Uuid,
        pub restriction_uuid: Uuid,
        pub device_uuid: Uuid,
    }

    // A senha gerada é limpa da RAM quando a struct sai de âmbito
    impl Drop for GeneratedPassword {
        fn drop(&mut self) {
            self.password.zeroize();
        }
    }

    // Debug manual - nunca expor a senha gerada em logs.
    impl std::fmt::Debug for GeneratedPassword {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("GeneratedPassword")
                .field("password", &"<redacted>")
                .field("entropy_millibits", &self.entropy_millibits)
                .field("variation", &self.variation)
                .field("domain_uuid", &self.domain_uuid)
                .finish()
        }
    }

    pub struct DecryptedSeed {
        pub device_uuid: Uuid,
        pub seed: [u8; 32],
    }

    // Debug manual - nunca expor a seed em logs.
    impl std::fmt::Debug for DecryptedSeed {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("DecryptedSeed")
                .field("device_uuid", &self.device_uuid)
                .field("seed", &"<redacted>")
                .finish()
        }
    }

    impl Drop for DecryptedSeed {
        fn drop(&mut self) {
            self.seed.zeroize();
        }
    }

    #[derive(Debug, Clone)]
    pub struct PasswordRequest {
        pub domain_uuid: Uuid,
        pub forced_variation: Option<u32>,
    }

    #[derive(Clone)]
    pub struct MasterKeyInput {
        pub k1: String,
        pub k2: String,
    }

    // Debug manual - nunca expor K1/K2 em logs ou mensagens de erro.
    impl std::fmt::Debug for MasterKeyInput {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.debug_struct("MasterKeyInput")
                .field("k1", &"<redacted>")
                .field("k2", &"<redacted>")
                .finish()
        }
    }

    impl MasterKeyInput {
        pub fn new(k1: String, k2: String) -> Self {
            Self { k1, k2 }
        }

        pub fn validate(&self) -> Result<(), ValidationError> {
            if self.k1.is_empty() && self.k2.is_empty() {
                return Err(ValidationError::InvalidName(
                    "K1 e K2 não podem estar ambos vazios".into(),
                ));
            }

            if self.k1.len() > 1024 {
                return Err(ValidationError::LengthExceeded {
                    value: self.k1.len(),
                    max: 1024,
                });
            }

            if self.k2.len() > 1024 {
                return Err(ValidationError::LengthExceeded {
                    value: self.k2.len(),
                    max: 1024,
                });
            }

            Ok(())
        }

        pub fn normalize_and_concat(&self) -> Vec<u8> {
            super::common::normalize_secrets(&[&self.k1, &self.k2])
                .expect("master key normalization failed")
        }
    }

    impl Drop for MasterKeyInput {
        fn drop(&mut self) {
            self.k1.zeroize();
            self.k2.zeroize();
        }
    }

    #[derive(Debug)]
    pub struct SessionRuntime {
        pub session_file: SessionFile,
        pub payload: SessionPayload,
        pub selected_device: Option<Uuid>,
        pub selected_restriction: Option<Uuid>,
        pub selected_domain: Option<Uuid>,
        /// Hash do payload na última gravação com sucesso (ou no momento em que uma sessão existente foi aberta). 
        /// None = nunca foi guardada (sessão nova) conta sempre como tendo alterações por guardar.
        pub last_saved_hash: Option<u64>,
    }

    impl SessionRuntime {
        pub fn new(session_file: SessionFile, payload: SessionPayload) -> Self {
            Self {
                session_file,
                payload,
                selected_device: None,
                selected_restriction: None,
                selected_domain: None,
                last_saved_hash: None,
            }
        }

        pub fn clear_selection(&mut self) {
            self.selected_device = None;
            self.selected_restriction = None;
            self.selected_domain = None;
        }
    }

    #[derive(Debug)]
    pub struct AppState {
        pub session: Option<SessionRuntime>,
        pub local_state: super::local_state::LocalState,
    }

    impl AppState {
        pub fn new(local_state: super::local_state::LocalState) -> Self {
            Self {
                session: None,
                local_state,
            }
        }

        pub fn has_open_session(&self) -> bool {
            self.session.is_some()
        }

        pub fn require_session(&self) -> Result<&SessionRuntime, SessionError> {
            self.session.as_ref().ok_or(SessionError::SessionNotOpen)
        }

        pub fn require_session_mut(&mut self) -> Result<&mut SessionRuntime, SessionError> {
            self.session.as_mut().ok_or(SessionError::SessionNotOpen)
        }
    }

    pub type SharedAppState = Arc<RwLock<AppState>>;

    #[derive(Debug, Clone)]
    pub struct SessionOverview {
        pub header: SessionHeader,
        pub nonce_global: [u8; 24],
        pub ciphertext_global_len: usize,
        pub device_count: usize,
        pub restriction_count: usize,
        pub domain_count: usize,
        pub static_password_count: usize,
    }

    /// Resultado de uma pesquisa de domínio (VaultCore::search_domains)
    #[derive(Debug, Clone)]
    pub struct DomainSearchResult {
        pub domain_uuid: Uuid,
        pub identifier: String,
        pub device_uuid: Uuid,
        pub device_name: String,
        pub restriction_uuid: Uuid,
        pub restriction_name: String,
        /// Menor = mais parecido. 0 = correspondência exacta.
        pub score: u32,
    }

    /// Resultado de uma pesquisa de senha estática (VaultCore::search_static_passwords)
    #[derive(Debug, Clone)]
    pub struct StaticPasswordSearchResult {
        pub uuid: Uuid,
        pub label: String,
        pub folder_path: String,
        pub device_uuid: Uuid,
        pub device_name: String,
        pub compromised: bool,
        /// Menor = mais parecido. 0 = correspondência exacta.
        pub score: u32,
    }

    #[derive(Debug, Clone)]
    pub struct SecretBenchmarkReport {
        pub device_count: usize,
        pub domain_count: usize,
        pub static_password_count: usize,
        pub total_duration: Duration,
        pub device_setup_duration: Duration,
        pub domain_setup_duration: Duration,
        pub static_password_duration: Duration,
    }

    #[derive(Debug, Clone)]
    pub struct ExportBenchmarkReport {
        pub device_count: usize,
        pub domain_count: usize,
        pub static_password_count: usize,
        pub setup_duration: Duration,
        pub prepare_duration: Duration,
        pub export_duration: Duration,
        /// Sub-conjunto de export_duration: só o tempo gasto no módulo de geração (generator::generate_password, bits -> senha)
        pub generation_duration: Duration,
        pub total_duration: Duration,
    }
}

mod local_state {
    use chrono::{DateTime, Utc};
    use serde::{Deserialize, Serialize};

    /// Configurações Locais da aplicação. Guardado separadamente do ficheiro de sessão. Nunca exportado.
    #[derive(Debug, Clone, Serialize, Deserialize)]
    #[serde(default)]
    #[derive(Default)]
    pub struct LocalState {
        pub last_session_path: Option<String>,
        pub session_file_timestamp: Option<DateTime<Utc>>,
        pub session_file_hash: Option<[u8; 32]>,
        pub calibration_min_target_ms: Option<u128>,
        pub calibration_max_target_ms: Option<u128>,
        pub benchmark_argon2_m_cost_kib: Option<u32>,
        pub benchmark_argon2_t_cost: Option<u32>,
        pub benchmark_argon2_p_cost: Option<u32>,
        pub benchmark_k1_len: Option<usize>,
        pub benchmark_k2_len: Option<usize>,
        pub benchmark_device_count: Option<usize>,
        pub benchmark_domains_per_device: Option<usize>,
        pub benchmark_static_passwords_per_device: Option<usize>,
        /// Apenas relevante em wasm (browser): quando true, a sessão usa localStorage ao invés de caminho editável 
        pub wasm_browser_storage: bool,
    }

    impl LocalState {
        pub fn new() -> Self {
            Self::default()
        }
    }
}