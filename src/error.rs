use thiserror::Error;

use reqwest::Error as ReqwestError;

#[derive(Error, Debug)]
pub enum VercelBlobError {
    #[error("No authentication token. Expected environment variable BLOB_READ_WRITE_TOKEN to contain a token")]
    NotAuthenticated(),
    #[error("HTTP error: {0}")]
    HttpError(#[from] ReqwestError),
    #[error("HTTP Response error ({0}): {1}")]
    ResponseError(u16, String),
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

impl VercelBlobError {
    pub fn from_http(status_code: reqwest::StatusCode) -> Self {
        VercelBlobError::ResponseError(
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
