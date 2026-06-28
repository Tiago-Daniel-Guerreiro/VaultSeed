use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use crate::core::{CryptoService, FileService, MasterKeyInput, VaultCore};
use crate::errors::{CryptoError, FileError, LocalStateError, XorError};
use crate::services::generator::GeneratorServiceImpl;
use crate::models::{Argon2Params, LocalState, SessionFile};

#[derive(Clone, Copy, Debug)]
pub struct FakeCrypto;

impl FakeCrypto {
    fn mix_bytes(&self, seed: &[u8], context: &[u8], output_len: usize) -> Vec<u8> {
        let mut output = vec![0u8; output_len];

        if output_len == 0 {
            return output;
        }

        for (index, byte) in output.iter_mut().enumerate() {
            let seed_byte = seed[index % seed.len().max(1)];
            let context_byte = context[index % context.len().max(1)];
            *byte = seed_byte ^ context_byte ^ (index as u8).wrapping_mul(31);
        }

        output
    }

    fn fake_tag(&self, key: &[u8; 32], aad: &[u8]) -> [u8; 32] {
        let mut tag = [0u8; 32];

        for index in 0..32 {
            let key_byte = key[index];
            let aad_byte = aad.get(index % aad.len().max(1)).copied().unwrap_or(0);
            tag[index] = key_byte ^ aad_byte ^ (index as u8).wrapping_mul(17);
        }

        tag
    }
}

impl CryptoService for FakeCrypto {
    fn generate_random_32(&self) -> Result<[u8; 32], CryptoError> {
        Ok([0xAB; 32])
    }

    fn generate_random_24(&self) -> Result<[u8; 24], CryptoError> {
        Ok([0xCD; 24])
    }

    fn derive_argon2(
        &self,
        password: &[u8],
        salt: &[u8; 32],
        _m_cost_kib: u32,
        _t_cost: u32,
        _p_cost: u32,
    ) -> Result<[u8; 32], CryptoError> {
        let mut output = *salt;

        if password.is_empty() {
            return Ok(output);
        }

        for (index, byte) in password.iter().enumerate() {
            output[index % 32] ^= byte.wrapping_add(index as u8);
        }

        Ok(output)
    }

    fn derive_kek_session(
        &self,
        k1: &str,
        k2: &str,
        salt_session: &[u8; 32],
        _m_cost_kib: u32,
        _t_cost: u32,
        _p_cost: u32,
        k_ext: Option<&[u8; 32]>,
        salt_hkdf: Option<&[u8; 32]>,
    ) -> Result<[u8; 32], CryptoError> {
        let mut seed = *salt_session;

        for (index, byte) in k1.as_bytes().iter().chain(k2.as_bytes()).enumerate() {
            seed[index % 32] ^= byte.wrapping_add((index as u8).wrapping_mul(3));
        }

        if let Some(extra) = k_ext {
            for (index, byte) in extra.iter().enumerate() {
                seed[index % 32] ^= byte.wrapping_add(7);
            }
        }

        if let Some(extra_salt) = salt_hkdf {
            for (index, byte) in extra_salt.iter().enumerate() {
                seed[index % 32] ^= byte.wrapping_add(11);
            }
        }

        Ok(seed)
    }

    fn encrypt_aead(
        &self,
        key: &[u8; 32],
        _nonce: &[u8; 24],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let mut output = Vec::with_capacity(4 + aad.len() + 32 + plaintext.len());
        output.extend_from_slice(&(aad.len() as u32).to_le_bytes());
        output.extend_from_slice(aad);
        output.extend_from_slice(&self.fake_tag(key, aad));
        output.extend(plaintext.iter().enumerate().map(|(index, byte)| byte ^ key[index % 32]));
        Ok(output)
    }

    fn decrypt_aead(
        &self,
        key: &[u8; 32],
        _nonce: &[u8; 24],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if ciphertext.len() < 4 + 32 {
            return Err(CryptoError::AeadDecryption);
        }

        let aad_len = u32::from_le_bytes(ciphertext[0..4].try_into().unwrap()) as usize;
        let aad_start = 4;
        let aad_end = aad_start + aad_len;
        let tag_end = aad_end + 32;

        if ciphertext.len() < tag_end {
            return Err(CryptoError::AeadDecryption);
        }

        if &ciphertext[aad_start..aad_end] != aad {
            return Err(CryptoError::AeadAuthenticationFailed);
        }

        let mut expected_tag = [0u8; 32];
        expected_tag.copy_from_slice(&ciphertext[aad_end..tag_end]);

        if expected_tag != self.fake_tag(key, aad) {
            return Err(CryptoError::AeadAuthenticationFailed);
        }

        Ok(ciphertext[tag_end..]
            .iter()
            .enumerate()
            .map(|(index, byte)| byte ^ key[index % 32])
            .collect())
    }

    fn derive_kmac256(
        &self,
        seed: &[u8; 32],
        context: &str,
        output_len: usize,
    ) -> Result<Vec<u8>, CryptoError> {
        Ok(self.mix_bytes(seed, context.as_bytes(), output_len))
    }

    fn hmac_sha256(
        &self,
        key: &[u8; 32],
        data: &[u8],
    ) -> Result<[u8; 32], CryptoError> {
        let mut output = [0u8; 32];
        for index in 0..32 {
            let key_byte = key[index];
            let data_byte = data.get(index % data.len().max(1)).copied().unwrap_or(0);
            output[index] = key_byte ^ data_byte ^ (index as u8).wrapping_mul(13);
        }
        Ok(output)
    }
}

#[derive(Debug, Default)]
pub struct FakeFileService {
    sessions: Mutex<HashMap<String, SessionFile>>,
    xor_files: Mutex<HashMap<String, String>>,
    local_state: Mutex<Option<LocalState>>,
}

impl FakeFileService {
    pub fn new() -> Self {
        Self::default()
    }
}

impl FileService for FakeFileService {
    fn save_session_file(&self, path: &str, session: &SessionFile) -> Result<(), FileError> {
        self.sessions
            .lock()
            .expect("sessions mutex")
            .insert(path.to_string(), session.clone());
        Ok(())
    }

    fn load_session_file(&self, path: &str) -> Result<SessionFile, FileError> {
        self.sessions
            .lock()
            .expect("sessions mutex")
            .get(path)
            .cloned()
            .ok_or_else(|| FileError::NotFound(path.to_string()))
    }

    fn delete_session_file(&self, path: &str) -> Result<(), FileError> {
        self.sessions.lock().expect("sessions mutex").remove(path);
        Ok(())
    }

    fn create_xor_files(
        &self,
        k1: &str,
        k2: &str,
        path_a: &str,
        path_b: &str,
    ) -> Result<(), XorError> {
        let mut xor_files = self.xor_files.lock().expect("xor mutex");
        xor_files.insert(path_a.to_string(), k1.to_string());
        xor_files.insert(path_b.to_string(), k2.to_string());
        Ok(())
    }

    fn read_xor_files(
        &self,
        path_a: &str,
        path_b: &str,
    ) -> Result<(String, String), XorError> {
        let xor_files = self.xor_files.lock().expect("xor mutex");
        let k1 = xor_files
            .get(path_a)
            .cloned()
            .ok_or_else(|| XorError::InvalidFile(path_a.to_string()))?;
        let k2 = xor_files
            .get(path_b)
            .cloned()
            .ok_or_else(|| XorError::InvalidFile(path_b.to_string()))?;
        Ok((k1, k2))
    }

    fn local_state_path(&self) -> Result<PathBuf, LocalStateError> {
        Ok(std::env::temp_dir().join("vaultseed_fake_local_state.json"))
    }

    fn default_session_path(&self) -> Result<PathBuf, LocalStateError> {
        Ok(std::env::temp_dir().join("vaultseed_fake_session.vaultseed"))
    }

    fn load_local_state(&self) -> Result<LocalState, LocalStateError> {
        Ok(self
            .local_state
            .lock()
            .expect("local state mutex")
            .clone()
            .unwrap_or_else(LocalState::new))
    }

    fn save_local_state(&self, local_state: &LocalState) -> Result<PathBuf, LocalStateError> {
        let path = self.local_state_path()?;
        *self.local_state.lock().expect("local state mutex") = Some(local_state.clone());
        Ok(path)
    }

    fn delete_local_state(&self) -> Result<(), LocalStateError> {
        *self.local_state.lock().expect("local state mutex") = None;
        Ok(())
    }
}

pub fn build_default_bit_lists() -> HashMap<u8, Vec<String>> {
    crate::core::build_default_bit_lists()
}

pub fn build_test_vault() -> VaultCore<FakeCrypto, GeneratorServiceImpl, FakeFileService> {
    VaultCore::new(
        LocalState::new(),
        FakeCrypto,
        GeneratorServiceImpl::new(),
        FakeFileService::new(),
        false,
    )
}

pub fn unique_temp_session_path(label: &str) -> String {
    std::env::temp_dir()
        .join(format!("vaultseed_{}_{}.vaultseed", label, uuid::Uuid::new_v4()))
        .to_string_lossy()
        .to_string()
}

pub fn setup_basic_session(
    vault: &VaultCore<FakeCrypto, GeneratorServiceImpl, FakeFileService>,
    master_key: &MasterKeyInput,
) -> (uuid::Uuid, uuid::Uuid) {
    let argon = Argon2Params {
        m_cost_kib: 1024,
        t_cost: 2,
        p_cost: 1,
    };

    vault
        .create_new_session([7u8; 32], argon, false, None)
        .expect("create session");

    let device_uuid = vault.add_device("Device-Test", master_key).expect("add device");
    let restriction_uuid = vault
        .list_restrictions(device_uuid)
        .expect("list restrictions")
        .first()
        .expect("default restriction")
        .uuid;

    (device_uuid, restriction_uuid)
}
