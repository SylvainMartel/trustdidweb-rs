use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use serde_with::TimestampMilliSeconds;
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DIDDocument {
    /// The context of the DID Document, typically including the base DID context.
    #[serde(rename = "@context")]
    pub context: Vec<String>,

    /// The DID itself, serving as the unique identifier for this DID Document.
    pub id: String,

    /// A list of other DIDs that are also associated with this DID Document.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "alsoKnownAs")]
    pub also_known_as: Option<Vec<String>>,

    /// A list of verification methods associated with this DID.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "verificationMethod")]
    pub verification_method: Option<Vec<VerificationMethod>>,

    /// A list of verification method references or embedded verification methods for authentication.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<Vec<String>>,

    /// A list of verification method references or embedded verification methods for assertion.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "assertionMethod")]
    pub assertion_method: Option<Vec<String>>,

    /// A list of services associated with this DID.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<Vec<Service>>,

    /// Indicates whether this DID has been deactivated.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deactivated: Option<bool>,
}

impl DIDDocument {
    pub fn new(did: &str) -> Self {
        Self {
            context: vec!["https://www.w3.org/ns/did/v1".to_string()],
            id: did.to_string(),
            verification_method: None,
            authentication: None,
            assertion_method: None,
            service: None,
            deactivated: None,
            also_known_as: None,
        }
    }
}

/// Represents a verification method in a DID Document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationMethod {
    /// The unique identifier for this verification method.
    pub id: String,

    /// The type of the verification method.
    #[serde(rename = "type")]
    pub method_type: String,

    /// The DID of the controller of this verification method.
    pub controller: String,

    /// The public key in multibase format.
    #[serde(rename = "publicKeyMultibase")]
    pub public_key_multibase: String,
}

/// Represents a single entry in the DID Log as defined in the updated DID:TDW specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DIDLogEntry {
    /// The version ID, combining the version number and the entry hash.
    /// Format: "<version_number>-<entry_hash>"
    #[serde(rename = "versionId")]
    pub version_id: String,

    /// The timestamp of when this entry was created, in ISO8601 format.
    #[serde(rename = "versionTime")]
    #[serde(with = "chrono::serde::ts_seconds")]
    pub version_time: DateTime<Utc>,

    /// Configuration parameters that control the DID generation and verification processes.
    #[serde(rename = "parameters")]
    pub parameters: DIDParameters,

    /// The full DID Document for this version.
    #[serde(rename = "state")]
    pub state: DIDDocument,

    /// A Data Integrity Proof for this log entry.
    #[serde(rename = "proof")]
    pub proof: Vec<Proof>,
}

/// Represents the parameters for a DID (Decentralized Identifier).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DIDParameters {
    /// The method used for the DID.
    pub method: String,

    /// The SCID (Service Chain Identifier) associated with the DID, if any.
    pub scid: Option<String>,

    /// A list of update keys for the DID, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update_keys: Option<Vec<String>>,

    /// Indicates whether prerotation is enabled, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prerotation: Option<bool>,

    /// A list of next key hashes for the DID, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_key_hashes: Option<Vec<String>>,

    /// Indicates whether the DID is portable, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub portable: Option<bool>,

    /// The witness configuration for the DID, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub witness: Option<WitnessConfig>,

    /// Indicates whether the DID is deactivated, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deactivated: Option<bool>,

    /// The time-to-live (TTL) for the DID, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessConfig {
    pub threshold: u32,
    pub self_weight: u32,
    pub witnesses: Vec<Witness>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Witness {
    pub id: String,
    pub weight: u32,
}


/// Represents a service endpoint in a DID Document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Service {
    /// The unique identifier for this service.
    pub id: String,

    /// The type of the service.
    #[serde(rename = "type")]
    pub service_type: String,

    /// The endpoint URL or object for this service.
    #[serde(rename = "serviceEndpoint")]
    pub service_endpoint: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proof {
    #[serde(rename = "type")]
    pub proof_type: String,

    #[serde(with = "chrono::serde::ts_seconds")]
    pub created: DateTime<Utc>,

    #[serde(rename = "verificationMethod")]
    pub verification_method: String,

    #[serde(rename = "proofPurpose")]
    pub proof_purpose: ProofPurpose,

    #[serde(rename = "proofValue")]
    pub proof_value: String,

    pub challenge: Option<String>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ProofPurpose {
    #[serde(rename = "authentication")]
    Authentication,
    #[serde(rename = "assertionMethod")]
    AssertionMethod,
    // Add other purposes as needed
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct DIDLog {
    pub entries: Vec<DIDLogEntry>,
}

