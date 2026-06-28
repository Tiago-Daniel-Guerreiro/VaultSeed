use thiserror::Error;

#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum CommonError {
    #[error("Valor vazio onde era esperado um valor")]
    EmptyValue,

    #[error("UUID inválido: '{0}'")]
    InvalidUuid(String),

    #[error("Codificação Unicode inválida: {0}")]
    UnicodeError(String),

    #[error("Valor fora do intervalo válido: {0}")]
    OutOfRange(String),

    #[error("Operação cancelada pelo utilizador")]
    Cancelled,
}

#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("Nome inválido: {0}")]
    InvalidName(String),

    #[error("Identificador de domínio inválido: '{0}'")]
    InvalidDomain(String),

    #[error("Máscara inválida: {0}")]
    InvalidMask(String),

    #[error("Comprimento excede o máximo permitido ({max}): {value}")]
    LengthExceeded { value: usize, max: usize },

    #[error("Elementos duplicados encontrados")]
    DuplicateElements,

    #[error("Lista de elementos vazia")]
    EmptyElementList,
}

#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Falha na derivação Argon2id: {0}")]
    Argon2Derivation(String),

    #[error("Falha na derivação HKDF: {0}")]
    HkdfDerivation(String),

    #[error("Falha no KMAC: {0}")]
    KmacError(String),

    #[error("Falha na encriptação AEAD: {0}")]
    AeadEncryption(String),

    #[error("Falha na desencriptação AEAD")]
    AeadDecryption,

    #[error("Autenticação AEAD falhou - dados adulterados")]
    AeadAuthenticationFailed,

    #[error("Nonce inválido: esperado {expected} bytes, recebido {actual}")]
    InvalidNonce { expected: usize, actual: usize },

    #[error("Salt inválido: esperado {expected} bytes, recebido {actual}")]
    InvalidSalt { expected: usize, actual: usize },

    #[error("Erro de CSPRNG: {0}")]
    RandomGenerator(String),

    #[error("Parâmetros Argon2 inválidos: m={m}, t={t}, p={p}")]
    InvalidArgonParams { m: u32, t: u32, p: u32 },

    #[error("CSPRNG não disponível")]
    CsprngUnavailable,

    #[error("Falha no HMAC: {0}")]
    HmacError(String),
}

#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum SessionError {
    #[error("Ficheiro de sessão não encontrado: {0}")]
    SessionFileNotFound(String),

    #[error("Formato de ficheiro de sessão inválido: {0}")]
    InvalidSessionFormat(String),

    #[error("Versão de schema não suportada: {0} (suportado: 1)")]
    UnsupportedSchemaVersion(u32),

    #[error("Ficheiro de sessão adulterado - hash não corresponde")]
    SessionFileTampered,

    #[error("Chave de sessão incorreta - verificar K1/K2")]
    WrongSessionKey,

    #[error("Fator físico requerido mas não disponível")]
    HardwareRequired,

    #[error("Fator físico não configurado para esta sessão")]
    HardwareNotConfigured,

    #[error("Sessão não está aberta")]
    SessionNotOpen,

    #[error("Sessão já está aberta")]
    SessionAlreadyOpen,

    #[error("Sessão corrompida em memória")]
    SessionCorrupted,

    #[error("Não foi possível criar backup da sessão anterior: {0}")]
    BackupFailed(String),

    #[error("Restauro de backup falhou: {0}")]
    RestoreFailed(String),
}

#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum DeviceError {
    #[error("Dispositivo não encontrado: {0}")]
    NotFound(String),

    #[error("Dispositivo com este UUID não existe: {0}")]
    UuidNotFound(String),

    #[error("Dispositivo com este nome já existe: '{0}'")]
    NameAlreadyExists(String),

    #[error("Não é possível eliminar o único dispositivo restante")]
    CannotDeleteLastDevice,

    #[error("Não é possível eliminar dispositivo com restrições associadas")]
    CannotDeleteDeviceWithRestrictions,

    #[error("Seed do dispositivo não pode ser desencriptada")]
    SeedDecryptionFailed,

    #[error("Seed do dispositivo corrompida")]
    SeedCorrupted,

    #[error("CharList não encontrada: {0}")]
    CharListNotFound(String),

    #[error("Não é possível adicionar CharList - bit {0} já utilizado")]
    CharListBitOccupied(u8),

    #[error("Bit de CharList inválido: {0} (máximo: 31)")]
    CharListBitInvalid(u8),
}

#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum RestrictionError {
    #[error("Restrição não encontrada: {0}")]
    NotFound(String),

    #[error("Restrição com este UUID não existe: {0}")]
    UuidNotFound(String),

    #[error("Restrição com este nome já existe: '{0}'")]
    NameAlreadyExists(String),

    #[error("Não é possível eliminar restrição em uso por {domain_count} domínio(s)")]
    RestrictionInUse { domain_count: usize },

    #[error("Máscara inválida na sequência: {0}")]
    InvalidMaskInSequence(String),

    #[error("Literal inválido na sequência: {0}")]
    InvalidLiteralInSequence(String),
}

#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum DomainError {
    #[error("Domínio não encontrado: {0}")]
    NotFound(String),

    #[error("Domínio com este UUID não existe: {0}")]
    UuidNotFound(String),

    #[error("Domínio com este identificador já existe: '{0}'")]
    IdentifierAlreadyExists(String),

    #[error("Variação comprometida não encontrada: {0}")]
    CompromisedVariationNotFound(u32),

    #[error("Restrição não existe - não foi possível criar domínio")]
    RestrictionNotFound,

    #[error("Domínio já está marcado como comprometido na variação {0}")]
    AlreadyCompromised(u32),

    #[error("Restrição de destino não pertence ao mesmo dispositivo")]
    RestrictionDeviceMismatch,
}

#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum PasswordError {
    #[error("Geração de password falhou: {0}")]
    GenerationFailed(String),

    #[error("Entropia insuficiente para o formato solicitado")]
    InsufficientEntropy,

    #[error("Alfabeto vazio após processamento")]
    EmptyAlphabet,

    #[error("Não foi possível calcular o contexto KMAC")]
    KmacContextError,

    #[error("Erro de conversão de entropia para password")]
    EntropyConversionError,

    #[error("Máscara não suportada pelo motor de geração")]
    UnsupportedMask,
}

#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum StaticPasswordError {
    #[error("Senha estática não encontrada: {0}")]
    NotFound(String),

    #[error("Senha estática com este UUID não existe: {0}")]
    UuidNotFound(String),

    #[error("Encriptação de senha estática falhou")]
    EncryptionFailed,

    #[error("Desencriptação de senha estática falhou")]
    DecryptionFailed,

    #[error("Já existe uma pasta com este nome: {0}")]
    FolderAlreadyExists(String),

    #[error("Etiqueta da senha estática não corresponde à cópia encriptada (possível adulteração)")]
    LabelMismatch,
}

#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum FileError {
    #[error("Ficheiro não encontrado: {0}")]
    NotFound(String),

    #[error("Permissão negada: {0}")]
    PermissionDenied(String),

    #[error("Não foi possível criar ficheiro: {0}")]
    CreationFailed(String),

    #[error("Não foi possível ler ficheiro: {0}")]
    ReadFailed(String),

    #[error("Não foi possível escrever ficheiro: {0}")]
    WriteFailed(String),

    #[error("Erro de serialização: {0}")]
    SerializationError(String),

    #[error("Erro de deserialização: {0}")]
    DeserializationError(String),

    #[error("Ficheiro demasiado pequeno: {size} bytes (mínimo: {min})")]
    FileTooSmall { size: u64, min: u64 },

    #[error("Ficheiro demasiado grande: {size} bytes (máximo: {max})")]
    FileTooLarge { size: u64, max: u64 },

    #[error("Ficheiro em uso por outro processo")]
    FileLocked,

    #[error("Operação de rename atómico falhou: {0}")]
    AtomicRenameFailed(String),

    #[error("Caminho inválido: {0}")]
    InvalidPath(String),

    #[error("Directoria não existe: {0}")]
    DirectoryNotFound(String),
}

#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum XorError {
    #[error("Ficheiro XOR inválido: {0}")]
    InvalidFile(String),

    #[error("Tamanho de ficheiro XOR incorreto: {size} bytes (esperado: 16384)")]
    InvalidSize { size: u64 },

    #[error("Ficheiros XOR de tamanhos diferentes")]
    SizeMismatch,

    #[error("Payload XOR malformado")]
    MalformedPayload,

    #[error("Recuperação de K1/K2 falhou - verificar ficheiros")]
    RecoveryFailed,
}

#[allow(dead_code)]
#[derive(Debug, Error)]
pub enum LocalStateError {
    #[error("Configurações Locais não encontrado")]
    NotFound,

    #[error("Não foi possível guardar Configurações Locais: {0}")]
    SaveFailed(String),

    #[error("Não foi possível carregar Configurações Locais: {0}")]
    LoadFailed(String),

    #[error("Configurações Locais corrompido: {0}")]
    Corrupted(String),

    #[error("Registo não encontrado: {0}")]
    RegistrationNotFound(String),
}

#[derive(Debug, Error)]
pub enum CoreError {
    #[error(transparent)]
    Common(#[from] CommonError),

    #[error(transparent)]
    Validation(#[from] ValidationError),

    #[error(transparent)]
    Crypto(#[from] CryptoError),

    #[error(transparent)]
    Session(#[from] SessionError),

    #[error(transparent)]
    Device(#[from] DeviceError),

    #[error(transparent)]
    Restriction(#[from] RestrictionError),

    #[error(transparent)]
    Domain(#[from] DomainError),

    #[error(transparent)]
    Password(#[from] PasswordError),

    #[error(transparent)]
    StaticPassword(#[from] StaticPasswordError),

    #[error(transparent)]
    File(#[from] FileError),

    #[error(transparent)]
    Xor(#[from] XorError),

    #[error(transparent)]
    LocalState(#[from] LocalStateError),
}

pub type CoreResult<T> = Result<T, CoreError>;