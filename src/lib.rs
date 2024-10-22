pub mod error;
pub mod types;
mod utils;
mod operations;
mod did_tdw;
mod resolution;


pub use crate::error::DIDTDWError;
pub use crate::types::{DIDDocument, DIDLogEntry, DIDLog};
pub use crate::utils::{generate_scid, verify_scid};
pub use crate::resolution::resolve_did;

use chrono::{DateTime, Utc};

pub async fn resolve_did_with_params(did: &str, version_id: Option<&str>, version_time: Option<DateTime<Utc>>) -> Result<DIDDocument, DIDTDWError> {
    resolution::resolve_did(did, version_id, version_time).await
}