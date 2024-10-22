use thiserror::Error;

#[derive(Error, Debug)]
pub enum DIDTDWError {
    #[error("Invalid DID format")]
    InvalidDIDFormat,

    #[error("SCID generation failed")]
    SCIDGenerationFailed,

    #[error("Entry hash generation failed")]
    EntryHashGenerationFailed,

    #[error("Invalid DID Log entry")]
    InvalidLogEntry,

    #[error("DID resolution failed")]
    ResolutionFailed,

    #[error("Key management error: {0}")]
    KeyManagementError(String),

    #[error("Witness error: {0}")]
    WitnessError(String),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Multihash error: {0}")]
    MultihashError(String),

    #[error("JCS canonicalization error: {0}")]
    JCSCanonalizationError(String),

    #[error("Invalid proof")]
    InvalidProof,

    #[error("Invalid version ID")]
    InvalidVersionId,

    #[error("Invalid version number")]
    InvalidVersionNumber,

    #[error("Invalid entry hash")]
    InvalidEntryHash,

    #[error("Invalid version time")]
    InvalidVersionTime,

    #[error("Future version time")]
    FutureVersionTime,

    #[error("Missing SCID")]
    MissingSCID,

    #[error("Invalid SCID")]
    InvalidSCID,

    #[error("Version not found")]
    VersionNotFound,

    #[error("No document found")]
    NoDocumentFound,

    #[error("Pre-rotation is not active")]
    PreRotationNotActive,

    #[error("Invalid next key hashes")]
    InvalidNextKeyHashes,

    #[error("Key not pre-rotated")]
    KeyNotPreRotated,

    #[error("Cannot deactivate pre-rotation")]
    CannotDeactivatePreRotation,

    #[error("Invalid pre-rotation key")]
    InvalidPreRotationKey,

    #[error("Missing nextKeyHashes in pre-rotation update")]
    MissingNextKeyHashes,

    #[error("Askar error: {0}")]
    AskarError(#[from] aries_askar::Error),

    #[error("HTTP request error: {0}")]
    RequestError(#[from] reqwest::Error),

    #[error("Base58 decoding error")]
    Base58DecodeError(String),

    #[error("URL parse error: {0}")]
    UrlError(#[from] url::ParseError),
}