use crate::crypto;
use crate::errors::CryptoError;
use crate::core::CryptoService;

#[derive(Clone, Copy)]
pub struct CryptoServiceImpl;

impl Default for CryptoServiceImpl {
    fn default() -> Self {
        Self::new()
    }
}

impl CryptoServiceImpl {
    pub fn new() -> Self {
        Self
    }
}

impl CryptoService for CryptoServiceImpl {
    fn generate_random_32(&self) -> Result<[u8; 32], CryptoError> {
        Ok(crypto::generate_salt())
    }

    fn generate_random_24(&self) -> Result<[u8; 24], CryptoError> {
        let mut nonce = [0u8; 24];
        getrandom::fill(&mut nonce).map_err(|_| CryptoError::CsprngUnavailable)?;
        Ok(nonce)
    }

    fn derive_argon2(
        &self,
        password: &[u8],
        salt: &[u8; 32],
        m_cost_kib: u32,
        t_cost: u32,
        p_cost: u32,
    ) -> Result<[u8; 32], CryptoError> {
        let result = crypto::derive_key_argon2id(password, salt, m_cost_kib, t_cost, p_cost, 32)
            .map_err(CryptoError::Argon2Derivation)?;

        let key: [u8; 32] = result
            .try_into()
            .map_err(|_| CryptoError::Argon2Derivation("output length mismatch".into()))?;

        Ok(key)
    }

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
    ) -> Result<[u8; 32], CryptoError> {
        crypto::derive_kek_session(
            k1,
            k2,
            salt_session,
            m_cost_kib,
            t_cost,
            p_cost,
            k_ext,
            salt_hkdf,
        )
        .map_err(CryptoError::HkdfDerivation)
    }

    fn encrypt_aead(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 24],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        let (_nonce, ciphertext) = crypto::xchacha20poly1305_encrypt(key, nonce, plaintext, aad);
        Ok(ciphertext)
    }

    fn decrypt_aead(
        &self,
        key: &[u8; 32],
        nonce: &[u8; 24],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        crypto::xchacha20poly1305_decrypt(key, nonce, ciphertext, aad)
            .map_err(|_| CryptoError::AeadDecryption)
    }

    fn derive_kmac256(
        &self,
        seed: &[u8; 32],
        context: &str,
        output_len: usize,
    ) -> Result<Vec<u8>, CryptoError> {
        let mut output = vec![0u8; output_len];
        crypto::kmac256_xof(seed, context.as_bytes(), &mut output);
        Ok(output)
    }

    fn hmac_sha256(
        &self,
        key: &[u8; 32],
        data: &[u8],
    ) -> Result<[u8; 32], CryptoError> {
        Ok(crypto::hmac_sha256(key, data))
    }
}