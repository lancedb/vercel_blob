//! Authentication utilities for working with the API
use std::env;

use async_trait::async_trait;

use crate::error::{Result, VercelBlobError};

/// A trait for providing a token to authenticate with the Vercel Blob Storage API.
///
/// If your code is running inside a Vercel function then you will not need this.
///
/// If your code is running outside of Vercel (e.g. a client application) then you will
/// need to obtain a token from your Vercel application.  You can create a route
/// to provide short-term tokens to authenticated users.  This trait allows you
/// to connect to that route (or use some other method to obtain a token).
///
/// The operation (e.g. list, put, download) and pathname (e.g. foo/bar.txt) are
/// provided in case fine-grained authorization is required.  For operations that
/// use the full URL (download / del) the pathname will be the URL.
#[async_trait]
pub trait TokenProvider: std::fmt::Debug + Send + Sync {
    async fn get_token(&self, operation: &str, pathname: Option<&str>) -> Result<String>;
}

pub(crate) async fn get_token(
    provider: Option<&dyn TokenProvider>,
    operation: &str,
    pathname: Option<&str>,
) -> Result<String> {
    if let Some(provider) = provider {
        provider.get_token(operation, pathname).await
    } else {
        env::var("BLOB_READ_WRITE_TOKEN").map_err(|_| VercelBlobError::NotAuthenticated())
    }
}

/// A token provider that reads the token from an environment variable.
///
/// This is useful for testing but should not be used for real applications.
pub struct EnvTokenProvider {
    token: String,
}

// Custom implementation of Debug to avoid printing the token
impl std::fmt::Debug for EnvTokenProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EnvTokenProvider")
            .field("token", &"**********")
            .finish()
    }
}

impl EnvTokenProvider {
    pub fn try_new(env_var: &str) -> Result<Self> {
        let token = env::var(env_var).map_err(|_| VercelBlobError::NotAuthenticated())?;
        Ok(Self { token })
    }
}

#[async_trait]
impl TokenProvider for EnvTokenProvider {
    async fn get_token(&self, _operation: &str, _pathname: Option<&str>) -> Result<String> {
        Ok(self.token.clone())
    }
}
