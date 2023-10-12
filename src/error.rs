//! Error handling utilities for the crate
use thiserror::Error;

use reqwest::Error as ReqwestError;

/// All errors raised by this crate will be instances of VercelBlobError
#[derive(Error, Debug)]
pub enum VercelBlobError {
    #[error("No authentication token. Expected environment variable BLOB_READ_WRITE_TOKEN to contain a token")]
    NotAuthenticated(),
    #[error("Invalid request: {0}")]
    BadRequest(String),
    #[error("Access denied, please provide a valid token for this resource")]
    Forbidden(),
    #[error("The requested store does not exist")]
    StoreNotFound(),
    #[error("The requested store has been suspended")]
    StoreSuspended(),
    #[error("The requested blob does not exist")]
    BlobNotFound(),
    #[error("Internal HTTP error: {0}")]
    HttpError(#[from] ReqwestError),
    #[error("Unknown error, please visit https://vercel.com/help ({0}): {1}")]
    UnknownError(u16, String),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

impl VercelBlobError {
    pub fn unknown_error(status_code: reqwest::StatusCode) -> Self {
        VercelBlobError::UnknownError(
            status_code.as_u16(),
            status_code
                .canonical_reason()
                .unwrap_or("Unknown Error")
                .to_string(),
        )
    }

    pub fn required(field_name: &str) -> Self {
        VercelBlobError::InvalidInput(format!("{} is required", field_name))
    }
}

pub(crate) type Result<T> = std::result::Result<T, VercelBlobError>;
