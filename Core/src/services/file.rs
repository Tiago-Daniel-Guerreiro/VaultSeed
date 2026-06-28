#[cfg(not(target_arch = "wasm32"))]
use std::env;
#[cfg(not(target_arch = "wasm32"))]
use std::fs::{self, File};
#[cfg(not(target_arch = "wasm32"))]
use std::io::{Read, Write};
#[cfg(not(target_arch = "wasm32"))]
use std::path::Path;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::core::FileService;
use crate::errors::{FileError, LocalStateError, XorError};
use crate::models::{LocalState, SessionFile};

const SESSION_SCHEMA_VERSION: u32 = 1;
// Tamanho/layout do payload XOR - puramente lógico (sem I/O), por isso
// disponível em qualquer alvo, incluindo wasm32 (ver create_xor_files_bytes/
// read_xor_files_bytes mais abaixo, usados pela GUI em browser).
const XOR_FILE_SIZE: usize = 16 * 1024;
const XOR_LENGTH_BYTES: usize = 4;
#[cfg(not(target_arch = "wasm32"))]
const LOCAL_CONFIG_DIR_NAME: &str = "vaultseed";
#[cfg(not(target_arch = "wasm32"))]
const LOCAL_CONFIG_FILE_NAME: &str = "localconfig.json";
const LOCAL_CONFIG_SCHEMA_VERSION: u32 = 1;

#[cfg(target_arch = "wasm32")]
const LOCAL_CONFIG_COOKIE_NAME: &str = "vaultseed_local_config";

/// Prefixo de chave em `localStorage` para o ficheiro de sessão - até existir GUI em wasm com seletor de ficheiros real.
#[cfg(target_arch = "wasm32")]
const SESSION_STORAGE_PREFIX: &str = "vaultseed_session:";

#[derive(Debug, Clone, Serialize, Deserialize)]
struct LocalConfigFile {
    schema_version: u32,
    local_state: LocalState,
}

#[derive(Clone, Copy)]
pub struct FileServiceImpl;

impl Default for FileServiceImpl {
    fn default() -> Self {
        Self::new()
    }
}

impl FileServiceImpl {
    pub fn new() -> Self {
        Self
    }
}

// Lógica de bytes do XOR (construir/desconstruir o payload, XOR puro) - sem
// I/O, por isso partilhada por todos os alvos. As implementações
// específicas (ficheiro real vs. download/upload no browser) ficam nos
// blocos `impl FileService` cfg-gated mais abaixo.
impl FileServiceImpl {
    fn build_xor_payload(k1: &str, k2: &str) -> Result<Vec<u8>, XorError> {
        if k1.is_empty() && k2.is_empty() {
            return Err(XorError::InvalidFile("K1 e K2 não podem estar ambas vazias".to_string()));
        }

        let k1_bytes = k1.as_bytes();
        let k2_bytes = k2.as_bytes();

        let payload_len = XOR_LENGTH_BYTES
            .saturating_add(k1_bytes.len())
            .saturating_add(XOR_LENGTH_BYTES)
            .saturating_add(k2_bytes.len());

        if payload_len > XOR_FILE_SIZE {
            return Err(XorError::InvalidFile("Payload maior do que 16 KiB".to_string()));
        }

        let padding_len = XOR_FILE_SIZE - payload_len;

        let mut payload = Vec::with_capacity(XOR_FILE_SIZE);
        payload.extend_from_slice(&(k1_bytes.len() as u32).to_le_bytes());
        payload.extend_from_slice(k1_bytes);
        payload.extend_from_slice(&(k2_bytes.len() as u32).to_le_bytes());
        payload.extend_from_slice(k2_bytes);

        let mut padding = vec![0u8; padding_len];
        getrandom::fill(&mut padding)
            .map_err(|_| XorError::InvalidFile("CSPRNG indisponível".to_string()))?;
        payload.extend_from_slice(&padding);
        padding.zeroize();

        Ok(payload)
    }

    fn xor_bytes(left: &[u8], right: &[u8]) -> Result<Vec<u8>, XorError> {
        if left.len() != right.len() {
            return Err(XorError::SizeMismatch);
        }

        Ok(left
            .iter()
            .zip(right.iter())
            .map(|(a, b)| a ^ b)
            .collect())
    }

    fn parse_xor_payload(payload: &[u8]) -> Result<(String, String), XorError> {
        if payload.len() != XOR_FILE_SIZE {
            return Err(XorError::InvalidSize { size: payload.len() as u64 });
        }

        let mut offset = 0usize;

        if payload.len() < XOR_LENGTH_BYTES {
            return Err(XorError::MalformedPayload);
        }

        let mut len_buf = [0u8; XOR_LENGTH_BYTES];
        len_buf.copy_from_slice(&payload[offset..offset + XOR_LENGTH_BYTES]);
        let k1_len = u32::from_le_bytes(len_buf) as usize;
        offset += XOR_LENGTH_BYTES;

        if offset + k1_len > payload.len() {
            return Err(XorError::MalformedPayload);
        }

        let k1 = String::from_utf8(payload[offset..offset + k1_len].to_vec())
            .map_err(|_| XorError::MalformedPayload)?;
        offset += k1_len;

        if offset + XOR_LENGTH_BYTES > payload.len() {
            return Err(XorError::MalformedPayload);
        }

        len_buf.copy_from_slice(&payload[offset..offset + XOR_LENGTH_BYTES]);
        let k2_len = u32::from_le_bytes(len_buf) as usize;
        offset += XOR_LENGTH_BYTES;

        if offset + k2_len > payload.len() {
            return Err(XorError::MalformedPayload);
        }

        let k2 = String::from_utf8(payload[offset..offset + k2_len].to_vec())
            .map_err(|_| XorError::MalformedPayload)?;

        Ok((k1, k2))
    }

    /// Gera os dois shares (aleatório A + B = A xor payload) a partir de K1/K2 -
    /// usado tanto pela escrita em disco (desktop/mobile) como pelo download
    /// no browser (wasm).
    fn build_xor_shares(k1: &str, k2: &str) -> Result<(Vec<u8>, Vec<u8>), XorError> {
        let payload = zeroize::Zeroizing::new(Self::build_xor_payload(k1, k2)?);

        let mut share_a = zeroize::Zeroizing::new(vec![0u8; XOR_FILE_SIZE]);
        getrandom::fill(share_a.as_mut_slice())
            .map_err(|_| XorError::InvalidFile("CSPRNG indisponível".to_string()))?;

        let share_b = Self::xor_bytes(&payload, &share_a)?;

        Ok((share_a.to_vec(), share_b))
    }

    /// Reconstitui K1/K2 a partir dos dois shares - usado tanto pela leitura
    /// em disco como pelo upload no browser (wasm).
    fn recover_from_xor_shares(share_a: &[u8], share_b: &[u8]) -> Result<(String, String), XorError> {
        if share_a.len() != XOR_FILE_SIZE || share_b.len() != XOR_FILE_SIZE {
            return Err(XorError::SizeMismatch);
        }

        // O payload reconstruído contém K1/K2 em claro - limpo no Drop.
        let payload = zeroize::Zeroizing::new(Self::xor_bytes(share_a, share_b)?);
        Self::parse_xor_payload(&payload)
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl FileServiceImpl {
    fn session_temp_path(path: &str) -> PathBuf {
        PathBuf::from(format!("{path}.{}.tmp", uuid::Uuid::new_v4()))
    }

    fn ensure_parent_dir(path: &Path) -> Result<(), FileError> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                fs::create_dir_all(parent)
                    .map_err(|e| FileError::DirectoryNotFound(format!("{} ({})", parent.display(), e)))?;
            }
        }

        Ok(())
    }

    fn write_atomic_bytes(path: &Path, bytes: &[u8]) -> Result<(), FileError> {
        Self::ensure_parent_dir(path)?;

        let temp_path = Self::session_temp_path(&path.display().to_string());
        if let Some(temp_parent) = temp_path.parent() {
            if !temp_parent.as_os_str().is_empty() && !temp_parent.exists() {
                fs::create_dir_all(temp_parent)
                    .map_err(|e| FileError::DirectoryNotFound(format!("{} ({})", temp_parent.display(), e)))?;
            }
        }

        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temp_path)
            .map_err(|e| FileError::CreationFailed(e.to_string()))?;
        file.write_all(bytes)
            .map_err(|e| FileError::WriteFailed(e.to_string()))?;
        file.sync_all()
            .map_err(|e| FileError::WriteFailed(e.to_string()))?;
        drop(file);

        if let Err(first_err) = fs::rename(&temp_path, path) {
            if path.exists() {
                fs::remove_file(path)
                    .map_err(|e| FileError::AtomicRenameFailed(format!("{} (remove old: {})", first_err, e)))?;
                fs::rename(&temp_path, path)
                    .map_err(|e| FileError::AtomicRenameFailed(e.to_string()))?;
            } else {
                return Err(FileError::AtomicRenameFailed(first_err.to_string()));
            }
        }
        Ok(())
    }

    fn read_bytes(path: &Path) -> Result<Vec<u8>, FileError> {
        let mut file = File::open(path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => FileError::NotFound(path.display().to_string()),
            std::io::ErrorKind::PermissionDenied => {
                FileError::PermissionDenied(path.display().to_string())
            }
            _ => FileError::ReadFailed(e.to_string()),
        })?;

        let mut bytes = Vec::new();
        file.read_to_end(&mut bytes)
            .map_err(|e| FileError::ReadFailed(e.to_string()))?;
        Ok(bytes)
    }

    fn load_session_bytes(path: &Path) -> Result<SessionFile, FileError> {
        let bytes = Self::read_bytes(path)?;
        serde_json::from_slice(&bytes).map_err(|e| FileError::DeserializationError(e.to_string()))
    }

    #[allow(dead_code)]
    pub fn verify_session_file(&self, path: &str) -> Result<bool, FileError> {
        let path = Path::new(path);
        let session = Self::load_session_bytes(path)?;
        Ok(session.header.schema_version == SESSION_SCHEMA_VERSION)
    }

    #[allow(dead_code)]
    pub fn replace_session(&self, current: &mut SessionFile, new_session: SessionFile) -> Result<(), FileError> {
        current.ciphertext_global.zeroize();
        *current = new_session;
        Ok(())
    }

    pub fn validate_xor_file(&self, path: &str) -> Result<bool, XorError> {
        let metadata = fs::metadata(path).map_err(|e| XorError::InvalidFile(e.to_string()))?;
        Ok(metadata.len() as usize == XOR_FILE_SIZE)
    }

    fn write_private_file(path: &str, bytes: &[u8]) -> std::io::Result<()> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(path)?;
        file.write_all(bytes)?;
        file.sync_all()
    }

    fn platform_config_base_dir() -> Result<PathBuf, LocalStateError> {
        #[cfg(target_os = "windows")]
        {
            if let Some(appdata) = env::var_os("APPDATA") {
                return Ok(PathBuf::from(appdata));
            }
            if let Some(localappdata) = env::var_os("LOCALAPPDATA") {
                return Ok(PathBuf::from(localappdata));
            }
            return Err(LocalStateError::LoadFailed(
                "APPDATA/LOCALAPPDATA não definido".to_string(),
            ));
        }

        #[cfg(target_os = "macos")]
        {
            let home = env::var_os("HOME")
                .ok_or_else(|| LocalStateError::LoadFailed("HOME não definido".to_string()))?;
            return Ok(std::path::Path::new(&home)
                .join("Library")
                .join("Application Support"));
        }

        #[cfg(any(target_os = "linux", target_os = "android"))]
        {
            if let Some(xdg) = env::var_os("XDG_CONFIG_HOME") {
                return Ok(PathBuf::from(xdg));
            }
            let home = env::var_os("HOME")
                .ok_or_else(|| LocalStateError::LoadFailed("HOME não definido".to_string()))?;
            return Ok(std::path::Path::new(&home).join(".config"));
        }

        #[allow(unreachable_code)]
        Err(LocalStateError::LoadFailed(
            "Plataforma não suportada para local config".to_string(),
        ))
    }

    fn local_state_dir() -> Result<PathBuf, LocalStateError> {
        let base = Self::platform_config_base_dir()?;
        Ok(base.join(LOCAL_CONFIG_DIR_NAME))
    }

    fn local_state_file_path() -> Result<PathBuf, LocalStateError> {
        Ok(Self::local_state_dir()?.join(LOCAL_CONFIG_FILE_NAME))
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl FileService for FileServiceImpl {
    fn save_session_file(&self, path: &str, session: &SessionFile) -> Result<(), FileError> {
        if path.trim().is_empty() {
            return Err(FileError::InvalidPath(path.to_string()));
        }

        let serialized = serde_json::to_vec(session)
            .map_err(|e| FileError::SerializationError(e.to_string()))?;
        Self::write_atomic_bytes(Path::new(path), &serialized)
    }

    fn load_session_file(&self, path: &str) -> Result<SessionFile, FileError> {
        if path.trim().is_empty() {
            return Err(FileError::InvalidPath(path.to_string()));
        }

        let path = Path::new(path);
        let session = Self::load_session_bytes(path)?;

        if session.header.schema_version != SESSION_SCHEMA_VERSION {
            return Err(FileError::DeserializationError(format!(
                "schema version unsupported: {}",
                session.header.schema_version
            )));
        }

        Ok(session)
    }

    fn delete_session_file(&self, path: &str) -> Result<(), FileError> {
        if path.trim().is_empty() {
            return Err(FileError::InvalidPath(path.to_string()));
        }
        let path = Path::new(path);
        if path.exists() {
            fs::remove_file(path).map_err(|e| FileError::WriteFailed(e.to_string()))?;
        }
        Ok(())
    }

    fn create_xor_files(
        &self,
        k1: &str,
        k2: &str,
        path_a: &str,
        path_b: &str,
    ) -> Result<(), XorError> {
        // Zeroizing limpa os shares em qualquer caminho, incluindo erros - já
        // contêm o payload (K1/K2 em claro) escondido pelo XOR.
        let (share_a, share_b) = Self::build_xor_shares(k1, k2)?;
        let share_a = zeroize::Zeroizing::new(share_a);
        let share_b = zeroize::Zeroizing::new(share_b);

        Self::write_private_file(path_a, &share_a)
            .map_err(|e| XorError::InvalidFile(e.to_string()))?;
        Self::write_private_file(path_b, &share_b)
            .map_err(|e| XorError::InvalidFile(e.to_string()))?;

        Ok(())
    }

    fn read_xor_files(
        &self,
        path_a: &str,
        path_b: &str,
    ) -> Result<(String, String), XorError> {
        if !self.validate_xor_file(path_a)? {
            let size = fs::metadata(path_a)
                .map_err(|e| XorError::InvalidFile(e.to_string()))?
                .len();
            return Err(XorError::InvalidSize { size });
        }

        if !self.validate_xor_file(path_b)? {
            let size = fs::metadata(path_b)
                .map_err(|e| XorError::InvalidFile(e.to_string()))?
                .len();
            return Err(XorError::InvalidSize { size });
        }

        let share_a = zeroize::Zeroizing::new(
            fs::read(path_a).map_err(|e| XorError::InvalidFile(e.to_string()))?,
        );
        let share_b = zeroize::Zeroizing::new(
            fs::read(path_b).map_err(|e| XorError::InvalidFile(e.to_string()))?,
        );

        Self::recover_from_xor_shares(&share_a, &share_b)
    }

    fn local_state_path(&self) -> Result<PathBuf, LocalStateError> {
        Self::local_state_file_path()
    }

    fn default_session_path(&self) -> Result<PathBuf, LocalStateError> {
        Ok(Self::local_state_dir()?.join("session.vaultseed"))
    }

    fn load_local_state(&self) -> Result<LocalState, LocalStateError> {
        let path = Self::local_state_file_path()?;
        let bytes = fs::read(&path).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => LocalStateError::NotFound,
            _ => LocalStateError::LoadFailed(e.to_string()),
        })?;

        let file: LocalConfigFile = serde_json::from_slice(&bytes)
            .map_err(|e| LocalStateError::Corrupted(e.to_string()))?;

        if file.schema_version != LOCAL_CONFIG_SCHEMA_VERSION {
            return Err(LocalStateError::Corrupted(format!(
                "Versão de config local não suportada: {}",
                file.schema_version
            )));
        }

        Ok(file.local_state)
    }

    fn save_local_state(&self, local_state: &LocalState) -> Result<PathBuf, LocalStateError> {
        let dir = Self::local_state_dir()?;
        fs::create_dir_all(&dir)
            .map_err(|e| LocalStateError::SaveFailed(e.to_string()))?;

        let path = dir.join(LOCAL_CONFIG_FILE_NAME);
        let temp_path = path.with_extension("json.tmp");

        let file = LocalConfigFile {
            schema_version: LOCAL_CONFIG_SCHEMA_VERSION,
            local_state: local_state.clone(),
        };

        let bytes = serde_json::to_vec_pretty(&file)
            .map_err(|e| LocalStateError::SaveFailed(e.to_string()))?;

        {
            let mut options = fs::OpenOptions::new();
            options.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut temp_file = options
                .open(&temp_path)
                .map_err(|e| LocalStateError::SaveFailed(e.to_string()))?;
            temp_file
                .write_all(&bytes)
                .map_err(|e| LocalStateError::SaveFailed(e.to_string()))?;
            temp_file
                .sync_all()
                .map_err(|e| LocalStateError::SaveFailed(e.to_string()))?;
        }

        fs::rename(&temp_path, &path)
            .map_err(|e| LocalStateError::SaveFailed(e.to_string()))?;

        Ok(path)
    }

    fn delete_local_state(&self) -> Result<(), LocalStateError> {
        // Só o ficheiro de configuração - nunca a pasta toda: o caminho por
        // omissão da sessão (default_session_path()) vive na MESMA pasta
        // (local_state_dir()), e remove_dir_all apagaria a sessão do
        // utilizador em silêncio, contradizendo o aviso mostrado na UI
        // ("As sessões e senhas NÃO são afectadas").
        let path = Self::local_state_file_path()?;
        if path.exists() {
            fs::remove_file(&path)
                .map_err(|e| LocalStateError::SaveFailed(e.to_string()))?;
        }

        // Se a pasta ficou vazia (sem sessão nem mais nada lá guardado),
        // remove-a também - não há nada a perder, só limpa o resíduo.
        if let Some(dir) = path.parent() {
            if dir.exists() {
                let is_empty = fs::read_dir(dir).map(|mut it| it.next().is_none()).unwrap_or(false);
                if is_empty {
                    let _ = fs::remove_dir(dir);
                }
            }
        }
        Ok(())
    }
}

// =============================================================================
// IMPLEMENTAÇÃO WASM32
//
// Sem sistema de ficheiros real no browser:
//  - Configuração local: guardada num cookie (`document.cookie`), em hex de
//    JSON. `LocalState` é pequena (poucos `Option<...>`), cabe sem problemas
//    no limite de ~4KB de um cookie.
//  - Sessão: interino em `localStorage`, indexado pelo `path` recebido. O
//    seletor de ficheiros real do browser (download/upload) já existe para
//    "guardar cópia"/"substituir sessão" - ver download_session_file/
//    replace_session_with_uploaded mais abaixo.
//  - Ficheiros XOR (chaves físicas/pen): create_xor_files/read_xor_files
//    (métodos da trait `FileService`, baseados em caminho) não fazem
//    sentido no browser e continuam a devolver erro - mas o mesmo fluxo
//    funciona via download/upload real (`<input type="file">` +
//    `FileReader`), só que sem "caminho": ver create_xor_files_bytes/
//    read_xor_files_bytes mais abaixo, chamados directamente pela GUI
//    (Gui/src/session.rs) em vez de passar pela trait.
// =============================================================================
#[cfg(target_arch = "wasm32")]
impl FileServiceImpl {
    fn session_storage() -> Result<web_sys::Storage, String> {
        web_sys::window()
            .ok_or_else(|| "window indisponível".to_string())?
            .local_storage()
            .map_err(|_| "localStorage indisponível".to_string())?
            .ok_or_else(|| "localStorage indisponível".to_string())
    }

    fn html_document() -> Result<web_sys::HtmlDocument, String> {
        use wasm_bindgen::JsCast;

        let document = web_sys::window()
            .ok_or_else(|| "window indisponível".to_string())?
            .document()
            .ok_or_else(|| "document indisponível".to_string())?;
        document
            .dyn_into::<web_sys::HtmlDocument>()
            .map_err(|_| "HtmlDocument indisponível".to_string())
    }

    fn read_cookie(name: &str) -> Option<String> {
        let document = Self::html_document().ok()?;
        let cookies = document.cookie().ok()?;
        cookies.split(';').find_map(|kv| {
            let (key, value) = kv.trim().split_once('=')?;
            if key == name { Some(value.to_string()) } else { None }
        })
    }

    fn write_cookie(name: &str, value: &str) -> Result<(), String> {
        let document = Self::html_document()?;
        // ~10 anos, válido em todo o site.
        document
            .set_cookie(&format!("{name}={value}; path=/; max-age=315360000"))
            .map_err(|_| "Não foi possível escrever o cookie".to_string())
    }

    fn delete_cookie(name: &str) -> Result<(), String> {
        let document = Self::html_document()?;
        document
            .set_cookie(&format!("{name}=; path=/; max-age=0"))
            .map_err(|_| "Não foi possível remover o cookie".to_string())
    }

    fn session_storage_key(path: &str) -> String {
        format!("{SESSION_STORAGE_PREFIX}{path}")
    }

    /// Lê a sessão guardada em `path` e desencadeia o download do ficheiro pelo browser (Blob + `<a download>` temporário, clicado via JS removido a seguir). É o equivalente a "Guardar cópia" num ambiente sem sistema de ficheiros real.
    pub fn download_session_file(path: &str, filename: &str) -> Result<(), String> {
        let storage = Self::session_storage()?;
        let content = storage
            .get_item(&Self::session_storage_key(path))
            .map_err(|_| "localStorage.getItem falhou".to_string())?
            .ok_or_else(|| "Sessão não encontrada no browser".to_string())?;

        Self::trigger_browser_download(filename, &content)
    }

    fn trigger_browser_download(filename: &str, content: &str) -> Result<(), String> {
        use wasm_bindgen::JsCast;

        let parts = js_sys::Array::new();
        parts.push(&wasm_bindgen::JsValue::from_str(content));

        let blob = web_sys::Blob::new_with_str_sequence(&parts)
            .map_err(|_| "Erro ao criar Blob".to_string())?;
        let url = web_sys::Url::create_object_url_with_blob(&blob)
            .map_err(|_| "Erro ao criar URL do Blob".to_string())?;

        let document = web_sys::window()
            .ok_or_else(|| "window indisponível".to_string())?
            .document()
            .ok_or_else(|| "document indisponível".to_string())?;

        let anchor = document
            .create_element("a")
            .map_err(|_| "Erro ao criar elemento <a>".to_string())?
            .dyn_into::<web_sys::HtmlAnchorElement>()
            .map_err(|_| "Erro ao converter <a>".to_string())?;

        anchor.set_href(&url);
        anchor.set_download(filename);
        anchor.click();

        let _ = web_sys::Url::revoke_object_url(&url);
        Ok(())
    }

    pub fn replace_session_with_uploaded(path: &str, content: &str) -> Result<(), String> {
        let session: SessionFile = serde_json::from_str(content)
            .map_err(|e| format!("Ficheiro de sessão inválido: {e}"))?;

        if session.header.schema_version != SESSION_SCHEMA_VERSION {
            return Err(format!(
                "Versão de sessão não suportada: {}",
                session.header.schema_version
            ));
        }

        let storage = Self::session_storage()?;
        storage
            .set_item(&Self::session_storage_key(path), content)
            .map_err(|_| "localStorage.setItem falhou".to_string())
    }

    /// Desencadeia o download de bytes arbitrários (Blob binário + `<a
    /// download>` temporário) - equivalente binário de `trigger_browser_download`,
    /// usado pelos shares XOR (ver create_xor_files_bytes).
    fn trigger_browser_download_bytes(filename: &str, bytes: &[u8]) -> Result<(), String> {
        use wasm_bindgen::JsCast;

        let array = js_sys::Uint8Array::from(bytes);
        let parts = js_sys::Array::new();
        parts.push(&array.buffer());

        let blob = web_sys::Blob::new_with_buffer_source_sequence(&parts)
            .map_err(|_| "Erro ao criar Blob".to_string())?;
        let url = web_sys::Url::create_object_url_with_blob(&blob)
            .map_err(|_| "Erro ao criar URL do Blob".to_string())?;

        let document = web_sys::window()
            .ok_or_else(|| "window indisponível".to_string())?
            .document()
            .ok_or_else(|| "document indisponível".to_string())?;

        let anchor = document
            .create_element("a")
            .map_err(|_| "Erro ao criar elemento <a>".to_string())?
            .dyn_into::<web_sys::HtmlAnchorElement>()
            .map_err(|_| "Erro ao converter <a>".to_string())?;

        anchor.set_href(&url);
        anchor.set_download(filename);
        anchor.click();

        let _ = web_sys::Url::revoke_object_url(&url);
        Ok(())
    }

    /// Equivalente browser de `create_xor_files` (desktop): em vez de
    /// escrever dois ficheiros em disco, gera os dois shares e desencadeia
    /// dois downloads (`filename_a`/`filename_b`) - usado pelo botão "Criar
    /// ficheiros XOR" em wasm (ver Gui/src/session.rs::register_create_xor).
    pub fn create_xor_files_bytes(
        k1: &str,
        k2: &str,
        filename_a: &str,
        filename_b: &str,
    ) -> Result<(), String> {
        let (share_a, share_b) = Self::build_xor_shares(k1, k2)
            .map_err(|e| e.to_string())?;
        let share_a = zeroize::Zeroizing::new(share_a);
        let share_b = zeroize::Zeroizing::new(share_b);

        Self::trigger_browser_download_bytes(filename_a, &share_a)?;
        Self::trigger_browser_download_bytes(filename_b, &share_b)
    }

    /// Equivalente browser de `read_xor_files` (desktop): em vez de ler dois
    /// caminhos do disco, recebe os bytes já lidos pelo seletor de ficheiro
    /// do browser (`<input type="file">` + `FileReader.readAsArrayBuffer`) -
    /// ver Gui/src/session.rs::register_pick_xor_file.
    pub fn read_xor_files_bytes(
        share_a: &[u8],
        share_b: &[u8],
    ) -> Result<(String, String), String> {
        Self::recover_from_xor_shares(share_a, share_b).map_err(|e| e.to_string())
    }
}

#[cfg(target_arch = "wasm32")]
impl FileService for FileServiceImpl {
    fn save_session_file(&self, path: &str, session: &SessionFile) -> Result<(), FileError> {
        if path.trim().is_empty() {
            return Err(FileError::InvalidPath(path.to_string()));
        }

        let serialized = serde_json::to_string(session)
            .map_err(|e| FileError::SerializationError(e.to_string()))?;

        let storage = Self::session_storage().map_err(FileError::WriteFailed)?;
        storage
            .set_item(&Self::session_storage_key(path), &serialized)
            .map_err(|_| FileError::WriteFailed("localStorage.setItem falhou".to_string()))
    }

    fn load_session_file(&self, path: &str) -> Result<SessionFile, FileError> {
        if path.trim().is_empty() {
            return Err(FileError::InvalidPath(path.to_string()));
        }

        let storage = Self::session_storage().map_err(FileError::ReadFailed)?;
        let item = storage
            .get_item(&Self::session_storage_key(path))
            .map_err(|_| FileError::ReadFailed("localStorage.getItem falhou".to_string()))?
            .ok_or_else(|| FileError::NotFound(path.to_string()))?;

        let session: SessionFile = serde_json::from_str(&item)
            .map_err(|e| FileError::DeserializationError(e.to_string()))?;

        if session.header.schema_version != SESSION_SCHEMA_VERSION {
            return Err(FileError::DeserializationError(format!(
                "schema version unsupported: {}",
                session.header.schema_version
            )));
        }

        Ok(session)
    }

    fn delete_session_file(&self, path: &str) -> Result<(), FileError> {
        if path.trim().is_empty() {
            return Err(FileError::InvalidPath(path.to_string()));
        }
        let storage = Self::session_storage().map_err(FileError::WriteFailed)?;
        storage
            .remove_item(&Self::session_storage_key(path))
            .map_err(|_| FileError::WriteFailed("localStorage.removeItem falhou".to_string()))
    }

    // Estes métodos da trait `FileService` são baseados em caminho de
    // ficheiro, que não existe no browser - por isso continuam a devolver
    // erro aqui. O equivalente real (download/upload) está em
    // create_xor_files_bytes/read_xor_files_bytes, mais abaixo, chamados
    // directamente pela GUI em vez de passar pela trait.
    fn create_xor_files(
        &self,
        _k1: &str,
        _k2: &str,
        _path_a: &str,
        _path_b: &str,
    ) -> Result<(), XorError> {
        Err(XorError::InvalidFile(
            "Caminhos de ficheiro não são suportados neste alvo (browser) - usa create_xor_files_bytes.".to_string(),
        ))
    }

    fn read_xor_files(
        &self,
        _path_a: &str,
        _path_b: &str,
    ) -> Result<(String, String), XorError> {
        Err(XorError::InvalidFile(
            "Caminhos de ficheiro não são suportados neste alvo (browser) - usa read_xor_files_bytes.".to_string(),
        ))
    }

    fn local_state_path(&self) -> Result<PathBuf, LocalStateError> {
        Ok(PathBuf::from(format!("cookie:{LOCAL_CONFIG_COOKIE_NAME}")))
    }

    fn default_session_path(&self) -> Result<PathBuf, LocalStateError> {
        Ok(PathBuf::from("session.vaultseed"))
    }

    fn load_local_state(&self) -> Result<LocalState, LocalStateError> {
        let encoded = Self::read_cookie(LOCAL_CONFIG_COOKIE_NAME).ok_or(LocalStateError::NotFound)?;

        let bytes = hex::decode(&encoded).map_err(|e| LocalStateError::Corrupted(e.to_string()))?;

        let file: LocalConfigFile = serde_json::from_slice(&bytes)
            .map_err(|e| LocalStateError::Corrupted(e.to_string()))?;

        if file.schema_version != LOCAL_CONFIG_SCHEMA_VERSION {
            return Err(LocalStateError::Corrupted(format!(
                "Versão de config local não suportada: {}",
                file.schema_version
            )));
        }

        Ok(file.local_state)
    }

    fn save_local_state(&self, local_state: &LocalState) -> Result<PathBuf, LocalStateError> {
        let file = LocalConfigFile {
            schema_version: LOCAL_CONFIG_SCHEMA_VERSION,
            local_state: local_state.clone(),
        };

        let bytes = serde_json::to_vec(&file).map_err(|e| LocalStateError::SaveFailed(e.to_string()))?;
        let encoded = hex::encode(bytes);

        Self::write_cookie(LOCAL_CONFIG_COOKIE_NAME, &encoded).map_err(LocalStateError::SaveFailed)?;

        self.local_state_path()
    }

    fn delete_local_state(&self) -> Result<(), LocalStateError> {
        Self::delete_cookie(LOCAL_CONFIG_COOKIE_NAME).map_err(LocalStateError::SaveFailed)
    }
}
