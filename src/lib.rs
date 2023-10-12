//! The [Vercel Blob API](https://vercel.com/docs/storage/vercel-blob) allows you to
//! upload and serve files in your Vercel application.
//!
//! This crate supplies a rust client to access the API functions.
//!
//! These clients can be used within Vercel functions as well as outside Vercel functions
//! in custom client applications.
//!
//! To use the client all you need to do is instantiate a [`VercelBlobClient`]:
//!
//! [`VercelBlobClient`]: crate::client::VercelBlobClient
//!
//! ```ignore
//!
//! let client = VercelBlobClient::new();
//!
//! let list_result = client.list(Default::default()).await.unwrap();
//! for blob in list_result.blobs {
//!     dbg!(blob.url);
//! }
//! ```
//!
//! To use the client externally you will need to create a token provider.  The details
//! will depend on your application.  For example, you might create a route to provide
//! short lived tokens to authenticated users.  There is an example of such a route in
//! the [quickstart guide].  Your token provider could then make requests against this
//! route:
//!
//! [quickstart guide]: https://vercel.com/docs/storage/vercel-blob/quickstart#browser-uploads
//!
//! ```ignore
//! use async_trait::async_trait;
//! use reqwest::Client;
//! use serde::Deserialize;
//! use serde::Serialize;
//!
//! #[derive(Debug, Serialize)]
//! struct UploadTokenRequestPayload {
//!     pathname: String,
//!     #[serde(rename = "callbackUrl")]
//!     callback_url: String,
//! }
//!
//! #[derive(Debug, Serialize)]
//! struct UploadTokenRequest {
//!     #[serde(rename = "type")]
//!     request_type: String,
//!     payload: UploadTokenRequestPayload,
//! }
//!
//! #[derive(Debug, Deserialize)]
//! struct UploadTokenResponse {
//!     #[serde(rename = "type")]
//!     response_type: String,
//!     #[serde(rename = "clientToken")]
//!     client_token: String,
//! }
//!
//! #[derive(Debug)]
//! struct MyAppTokenProvider {
//!     request_url: String,
//!     client: Client,
//! }
//!
//! #[async_trait]
//! impl TokenProvider for MyAppTokenProvider {
//!     async fn get_token(
//!         &self,
//!         _operation: &str,
//!         pathname: Option<&str>,
//!     ) -> Result<String, VercelBlobError> {
//!         let request = self.client.post(&self.request_url);
//!         let request = request.json(&UploadTokenRequest {
//!             request_type: "blob.generate-client-token".to_string(),
//!             payload: UploadTokenRequestPayload {
//!                 pathname: pathname.unwrap_or("").to_string(),
//!                 callback_url: self.request_url.to_string(),
//!             },
//!         });
//!
//!         // Depending on how your app handles authorization you may need to
//!         // attach a cookie or other authorization header to the request.
//!
//!         let http_response = request.send().await?;
//!         let token_rsp = http_response.json::<UploadTokenResponse>().await?;
//!         Ok(token_rsp.client_token)
//!     }
//! }
//!
//! #[tokio::main]
//! async fn main() {
//!     // ...
//!     // Some kind of login workflow should take place before using the client
//!     // ...
//!
//!     let http_client = Client::new();
//!     let provider = Arc::new(MyAppTokenProvider {
//!         request_url: "http://localhost:3000/api/upload".to_string(),
//!         client: http_client,
//!     });
//!
//!     // Now we can make authorized requests to the Vercel Blob Storage API
//!     let blob_client = VercelBlobClient::new_external(provider);
//!     for blob in blob_client.list(Default::default()).await.unwrap().blobs {
//!         println!("{:?}", blob);
//!     }
//! }
//! ```

pub mod auth;
pub mod client;
pub mod error;
