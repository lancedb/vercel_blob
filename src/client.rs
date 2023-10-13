//! A Rust definition of the API and a client to access it
use std::{env, ops::Range, sync::Arc};

use async_trait::async_trait;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use reqwest::{Body, Client, RequestBuilder, Response, StatusCode};
use serde::{Deserialize, Serialize};

use crate::{
    auth::{get_token, TokenProvider},
    error::{Result, VercelBlobError},
};

const BLOB_API_VERSION: u32 = 4;
static GLOBAL_CLIENT: Lazy<Client> = Lazy::new(Client::new);

pub struct VercelBlobClient {
    /// A token provider to use to obtain a token to authenticate with the API
    token_provider: Option<Arc<dyn TokenProvider>>,
    /// The server URL to use.  This is not normally needed but can be used
    /// for testing purposes.
    base_url: String,
    /// The API version of the client
    api_version: String,
}

#[derive(Deserialize)]
struct BlobApiErrorDetail {
    code: String,
    message: Option<String>,
}

#[derive(Deserialize)]
struct BlobApiError {
    error: BlobApiErrorDetail,
}

/// A client for interacting with the Vercel Blob Store
///
/// If your code is running in a Vercel function then you shouldn't need to
/// provide any configuration as the runtime will supply the needed information.
///
/// If your code is running externally (e.g. a client application) then you
/// will need to supply a token provider.  One way to do this is to create a
/// api route that provides a short-lived token to an authorized client.  See
/// the readme for an example.
impl VercelBlobClient {
    /// Creates a new client for use inside a Vercel function
    pub fn new() -> Self {
        Self {
            token_provider: None,
            base_url: Self::get_base_url(),
            api_version: Self::get_api_version(),
        }
    }

    /// Creates a new client for use outside of Vercel
    pub fn new_external(token_provider: Arc<dyn TokenProvider>) -> Self {
        Self {
            token_provider: Some(token_provider),
            base_url: Self::get_base_url(),
            api_version: Self::get_api_version(),
        }
    }

    fn get_base_url() -> String {
        env::var("VERCEL_BLOB_API_URL")
            .or(env::var("NEXT_PUBLIC_VERCEL_BLOB_API_URL"))
            .unwrap_or_else(|_| "https://blob.vercel-storage.com".to_string())
    }

    fn get_api_url(&self, pathname: Option<&str>) -> String {
        url_join(self.base_url.clone(), pathname.unwrap_or("").to_string())
    }

    fn get_api_version() -> String {
        env::var("VERCEL_BLOB_API_VERSION_OVERRIDE")
            .unwrap_or_else(|_| BLOB_API_VERSION.to_string())
    }

    fn add_api_version_header(&self, request: RequestBuilder) -> RequestBuilder {
        request.header("x-api-version", self.api_version.clone())
    }

    async fn add_authorization_header(
        &self,
        request: RequestBuilder,
        operation: &str,
        pathname: Option<&str>,
    ) -> Result<RequestBuilder> {
        let token = get_token(self.token_provider.as_deref(), operation, pathname).await?;
        Ok(request.header("authorization", format!("Bearer {}", token)))
    }

    async fn handle_error(response: Response) -> VercelBlobError {
        let status = response.status();
        if status.as_u16() >= 500 {
            return VercelBlobError::unknown_error(status);
        }
        let error = response.json::<BlobApiError>().await;
        if error.is_err() {
            return VercelBlobError::unknown_error(status);
        }
        let error = error.unwrap();
        match error.error.code.as_str() {
            "store_suspended" => VercelBlobError::StoreSuspended(),
            "forbidden" => VercelBlobError::Forbidden(),
            "not_found" => VercelBlobError::BlobNotFound(),
            "store_not_found" => VercelBlobError::StoreNotFound(),
            "bad_request" => VercelBlobError::BadRequest(
                error
                    .error
                    .message
                    .unwrap_or_else(|| "unknown details".to_string()),
            ),
            _ => VercelBlobError::unknown_error(status),
        }
    }
}

/// Functions defined in the Vercel Blob API
#[async_trait]
pub trait VercelBlobApi {
    /// Lists files in the blob store
    ///
    /// # Arguments
    ///
    /// * `options` - Options for the list operation
    ///
    /// # Returns
    ///
    /// The response from the list operation
    async fn list(&self, options: ListCommandOptions) -> Result<ListBlobResult>;

    /// Uploads a file to the blob store
    ///
    /// # Arguments
    ///
    /// * `pathname` - The destination pathname for the uploaded file
    /// * `body` - The contents of the file
    /// * `options` - Options for the put operation
    ///
    /// # Returns
    ///
    /// The response from the put operation.  This includes a URL that can
    /// be used to later download the blob.
    async fn put(
        &self,
        pathname: &str,
        body: impl Into<Body> + Send,
        options: PutCommandOptions,
    ) -> Result<PutBlobResult>;

    /// Gets the metadata for a file in the blob store
    ///
    /// # Arguments
    ///
    /// * `url` - The URL of the file to get metadata for.  This should be the same URL that is used
    ///           to download the file.
    /// * `options` - Options for the head operation
    ///
    /// # Returns
    ///
    /// If the file exists then the metadata for the file is returned.  If the file does not exist
    /// then None is returned.
    async fn head(&self, url: &str, options: HeadCommandOptions) -> Result<Option<HeadBlobResult>>;

    /// Deletes a blob from the blob store
    ///
    /// # Arguments
    ///
    /// * `url` - The URL of the file to delete.  This should be the same URL that is used
    ///          to download the file.
    /// * `options` - Options for the del operation
    ///
    /// # Returns
    ///
    /// None
    async fn del(&self, url: &str, options: DelCommandOptions) -> Result<()>;

    /// Downloads a blob from the blob store
    ///
    /// # Arguments
    ///
    /// * `url` - The URL of the file to download.
    /// * `options` - Options for the download operation
    ///
    /// # Returns
    ///
    /// The contents of the file
    async fn download(&self, url: &str, options: DownloadCommandOptions) -> Result<Bytes>;
}

/// Details about a blob that are returned by the list operation
#[derive(Debug, Deserialize, Serialize)]
pub struct ListBlobResultBlob {
    /// The URL to download the blob
    pub url: String,
    /// The pathname of the blob
    pub pathname: String,
    /// The size of the blob in bytes
    pub size: u64,
    /// The time the blob was uploaded
    #[serde(alias = "uploadedAt")]
    pub uploaded_at: DateTime<Utc>,
}

/// The response from the list operation
#[derive(Debug, Deserialize, Serialize)]
pub struct ListBlobResult {
    /// A list of blobs found by the operation
    pub blobs: Vec<ListBlobResultBlob>,
    /// A cursor that can be used to page results
    pub cursor: Option<String>,
    /// True if there are more results available
    #[serde(alias = "hasMore")]
    pub has_more: bool,
}

/// Options for the list operation
///
/// The limit option can be used to limit the number of results returned.
/// If the limit is reached then response will have has_more set to true
/// and the cursor can be used to get the next page of results.
#[derive(Clone, Debug, Default)]
pub struct ListCommandOptions {
    /// The maximum number of results to return
    pub limit: Option<u64>,
    /// A prefix to filter results
    pub prefix: Option<String>,
    /// A cursor (returned from a previous list call) used to page results
    pub cursor: Option<String>,
}

fn url_join(left: String, right: String) -> String {
    if left.ends_with('/') {
        if let Some(stripped) = right.strip_prefix('/') {
            left + stripped
        } else {
            left + &right
        }
    } else if right.starts_with('/') {
        left + &right
    } else {
        left + "/" + &right
    }
}

#[async_trait]
impl VercelBlobApi for VercelBlobClient {
    async fn list(&self, options: ListCommandOptions) -> Result<ListBlobResult> {
        let api_url = self.get_api_url(None);
        let mut request = GLOBAL_CLIENT.get(api_url);
        if options.limit.is_some() {
            request = request.query(&[("limit", options.limit.unwrap())]);
        }
        if options.prefix.is_some() {
            request = request.query(&[("prefix", options.prefix.unwrap())]);
        }
        if options.cursor.is_some() {
            request = request.query(&[("cursor", options.cursor.unwrap())]);
        }
        request = self.add_api_version_header(request);
        request = self.add_authorization_header(request, "list", None).await?;
        let rsp = request.send().await?;

        if rsp.status() != StatusCode::OK {
            Err(Self::handle_error(rsp).await)
        } else {
            Ok(rsp.json::<ListBlobResult>().await?)
        }
    }

    async fn put(
        &self,
        pathname: &str,
        body: impl Into<Body> + Send,
        options: PutCommandOptions,
    ) -> Result<PutBlobResult> {
        if pathname.is_empty() {
            return Err(VercelBlobError::required("pathname"));
        }

        let api_url = self.get_api_url(Some(&format!("/{pathname}")));
        let mut request = GLOBAL_CLIENT.put(api_url);

        request = self.add_api_version_header(request);
        request = self
            .add_authorization_header(request, "put", Some(pathname))
            .await?;

        if !options.add_random_suffix {
            request = request.header("x-add-random-suffix", "0");
        }

        if let Some(content_type) = options.content_type {
            request = request.header("x-content-type", content_type);
        }

        if let Some(cache_control_max_age) = options.cache_control_max_age {
            request = request.header("x-cache-control-max-age", cache_control_max_age.to_string());
        }

        request = request.body(body);

        let response = request.send().await?;
        if response.status() != StatusCode::OK {
            Err(Self::handle_error(response).await)
        } else {
            let rsp_obj = response.json::<PutBlobResult>().await?;
            Ok(rsp_obj)
        }
    }

    async fn head(
        &self,
        url: &str,
        _options: HeadCommandOptions,
    ) -> Result<Option<HeadBlobResult>> {
        let api_url = self.get_api_url(None);
        let mut request = GLOBAL_CLIENT.get(api_url);

        request = request.query(&[("url", url)]);

        request = self.add_api_version_header(request);
        request = self
            .add_authorization_header(request, "head", Some(url))
            .await?;

        let response = request.send().await?;

        if response.status() != StatusCode::OK {
            let err = Self::handle_error(response).await;
            match err {
                VercelBlobError::BlobNotFound() => Ok(None),
                _ => Err(err),
            }
        } else {
            Ok(Some(response.json::<HeadBlobResult>().await?))
        }
    }

    async fn del(&self, url: &str, _options: DelCommandOptions) -> Result<()> {
        let api_url = self.get_api_url(Some("/delete"));
        let mut request = GLOBAL_CLIENT.post(api_url);

        request = self.add_api_version_header(request);
        request = self
            .add_authorization_header(request, "del", Some(url))
            .await?;
        request = request.header("content-type", "application/json");

        request = request.json(&DelCommandBody {
            urls: vec![url.to_string()],
        });

        let response = request.send().await?;

        if response.status() != StatusCode::OK {
            Err(Self::handle_error(response).await)
        } else {
            Ok(())
        }
    }

    async fn download(&self, url: &str, options: DownloadCommandOptions) -> Result<Bytes> {
        let mut request = GLOBAL_CLIENT.get(url);

        request = self.add_api_version_header(request);
        request = self
            .add_authorization_header(request, "download", Some(url))
            .await?;

        if let Some(byte_range) = options.byte_range {
            if byte_range.start == byte_range.end {
                return Ok(Bytes::new());
            }
            // Need to subtract 1 from byte_range.end because HTTP range headers are inclusive
            // and rust ranges are not.
            request = request.header(
                "range",
                format!("bytes={}-{}", byte_range.start, byte_range.end - 1),
            );
        }

        let response = request.send().await.unwrap();

        if response.status() != StatusCode::OK && response.status() != StatusCode::PARTIAL_CONTENT {
            Err(Self::handle_error(response).await)
        } else {
            Ok(response.bytes().await.unwrap())
        }
    }
}

/// Options for the put operation
///
/// By default uploaded files are assigned a URL with a random suffix.  This
/// ensures that no put operation will overwrite an existing file.  The url
/// returned in the response can be used to later download the file.
///
/// If predictable URLs are needed then add_random_suffix can be set to false
/// to disable this behavior.  If dsiabled then sequential writes to the same
/// pathname will overwrite each other.
#[derive(Debug)]
pub struct PutCommandOptions {
    /// If true (the default) then the URL of the file will contain a random suffix
    pub add_random_suffix: bool,
    /// Specify how long (in seconds) the file should be cached.
    /// Set to 0 to disable caching.
    pub cache_control_max_age: Option<u64>,
    /// Specify the content type of the file
    /// If not specified the content type will be text/plain
    pub content_type: Option<String>,
}

impl Default for PutCommandOptions {
    fn default() -> Self {
        Self {
            add_random_suffix: true,
            cache_control_max_age: None,
            content_type: None,
        }
    }
}

/// The response from the put operation
#[derive(Debug, Deserialize, Serialize)]
pub struct PutBlobResult {
    /// The URL to download the blob
    pub url: String,
    /// The pathname of the blob
    pub pathname: String,
    /// The content type of the blob
    #[serde(alias = "contentType")]
    pub content_type: String,
    /// The content disposition of the blob
    #[serde(alias = "contentDisposition")]
    pub content_disposition: String,
}

/// Response from the head operation
#[derive(Debug, Deserialize, Serialize)]
pub struct HeadBlobResult {
    /// The URL to download the blob
    pub url: String,
    /// The size of the blob in bytes
    pub size: u64,
    #[serde(alias = "uploadedAt")]
    /// The time the blob was uploaded
    pub uploaded_at: DateTime<Utc>,
    /// The pathname of the blob
    pub pathname: String,
    #[serde(alias = "contentType")]
    /// The content type of the blob
    pub content_type: String,
    /// The content disposition of the blob
    #[serde(alias = "contentDisposition")]
    pub content_disposition: String,
    /// The cache settings for the blob
    #[serde(alias = "cacheControl")]
    pub cache_control: String,
}

/// Options for the head operation
///
/// Intentionally blank to leave room for future options
#[derive(Debug, Default)]
pub struct HeadCommandOptions {}

#[derive(Debug, Serialize)]
struct DelCommandBody {
    urls: Vec<String>,
}

/// Options for the del operation
///
/// Intentionally blank to leave room for future options
#[derive(Debug, Default)]
pub struct DelCommandOptions {}

/// Options for the download operation
#[derive(Debug, Default)]
pub struct DownloadCommandOptions {
    /// The range of bytes to download.  If not specified then the entire blob
    /// is downloaded.  The start of the range must be less than the # of bytes
    /// in the blob or an error will be returned.  The end of the range may be
    /// greater than the number of bytes in the blob.
    pub byte_range: Option<Range<usize>>,
}

/// These unit tests test against a mock server.  They will not test integration issues
/// with the blob store but they are useful for regression and testing corner cases.
#[cfg(test)]
mod tests {

    use all_asserts::{assert_false, assert_true};
    use mockito::{Matcher, Mock, ServerGuard};

    use super::*;

    const EXAMPLE_CACHE_CONTROL: &'static str = "public, max-age=31536000, s-maxage=300";

    #[derive(Debug, Serialize)]
    struct TemplateContext {
        url: String,
        files: Vec<String>,
    }

    fn mock_list_rsp(
        url: &str,
        num_files: u32,
        has_more: bool,
        cursor: Option<String>,
    ) -> ListBlobResult {
        ListBlobResult {
            blobs: (0..num_files)
                .map(|i| ListBlobResultBlob {
                    url: format!("{}/somefile-{}.txt", url, i),
                    pathname: format!("somefile-{}.txt", i),
                    size: 123,
                    uploaded_at: Utc::now(),
                })
                .collect(),
            cursor,
            has_more,
        }
    }

    fn create_client(mock_server: &ServerGuard) -> VercelBlobClient {
        let client = VercelBlobClient::new();
        VercelBlobClient {
            api_version: client.api_version,
            base_url: mock_server.url(),
            token_provider: client.token_provider,
        }
    }

    async fn setup_mock_rsp<T, O, P>(
        http_method: &str,
        http_path: P,
        response: T,
    ) -> (ServerGuard, Mock)
    where
        O: Serialize,
        T: FnOnce(&str) -> Option<O>,
        P: Into<Matcher>,
    {
        let mut server = mockito::Server::new_async().await;

        env::set_var("BLOB_READ_WRITE_TOKEN", "xyz");

        let mut mock = server
            .mock(http_method, http_path)
            .with_status(200)
            .with_header("content-type", "application/json")
            .match_header("authorization", "Bearer xyz");

        let rsp_obj = response(&server.url());
        if let Some(rsp_obj) = rsp_obj {
            let rsp_json = serde_json::to_string(&rsp_obj).unwrap();
            mock = mock.with_body(rsp_json);
        }

        (server, mock)
    }

    #[tokio::test]
    async fn can_list_no_paging() {
        let (server, mock) = setup_mock_rsp("GET", "/", |server_url| {
            Some(mock_list_rsp(server_url, 10, false, None))
        })
        .await;
        let mock = mock.create_async().await;

        let client = create_client(&server);

        let results = client
            .list(ListCommandOptions {
                ..Default::default()
            })
            .await
            .unwrap();

        assert_eq!(10, results.blobs.len());
        assert_false!(results.has_more);
        assert_true!(results.cursor.is_none());

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn can_list_paging() {
        let (server, mock) = setup_mock_rsp("GET", "/", |server_url| {
            Some(mock_list_rsp(server_url, 5, true, Some("xyz".to_string())))
        })
        .await;
        let mock = mock.create_async().await;

        let client = create_client(&server);

        let results = client
            .list(ListCommandOptions {
                ..Default::default()
            })
            .await
            .unwrap();

        assert_eq!(5, results.blobs.len());
        assert_true!(results.has_more);
        assert_eq!("xyz", results.cursor.unwrap());

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn can_put_cache_control() {
        let (server, mock) = setup_mock_rsp("PUT", "/somefile.txt", |server_url| {
            Some(PutBlobResult {
                url: format!("{}/somefile.txt", server_url),
                pathname: "somefile.txt".to_string(),
                content_type: "text/plain".to_string(),
                content_disposition: "inline".to_string(),
            })
        })
        .await;

        let mock = mock
            .match_header("x-cache-control-max-age", "100")
            .create_async()
            .await;

        let client = create_client(&server);

        let data = "here are some new contents";
        let pathname = "somefile.txt";
        let result = client
            .put(
                pathname,
                data,
                PutCommandOptions {
                    add_random_suffix: false,
                    cache_control_max_age: Some(100),
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        assert_eq!(result.pathname, "somefile.txt");
        assert_eq!(result.content_type, "text/plain");
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn can_put_no_cache_control() {
        let (server, mock) = setup_mock_rsp("PUT", "/somefile.txt", |server_url| {
            Some(PutBlobResult {
                url: format!("{}/somefile.txt", server_url),
                pathname: "somefile.txt".to_string(),
                content_type: "text/plain".to_string(),
                content_disposition: "inline".to_string(),
            })
        })
        .await;

        let mock = mock
            .match_header("x-cache-control-max-age", Matcher::Missing)
            .create_async()
            .await;

        let client = create_client(&server);

        let data = "here are some new contents";
        let pathname = "somefile.txt";
        let result = client
            .put(
                pathname,
                data,
                PutCommandOptions {
                    add_random_suffix: false,
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        assert_eq!(result.pathname, "somefile.txt");
        assert_eq!(result.content_type, "text/plain");
        mock.assert_async().await;
    }

    #[tokio::test]
    async fn can_head() {
        let (server, mock) = setup_mock_rsp("GET", Matcher::Any, |server_url| {
            Some(HeadBlobResult {
                url: format!("{}/somefile.txt", server_url),
                size: 123,
                uploaded_at: Utc::now(),
                pathname: "somefile.txt".to_string(),
                content_type: "text/plain".to_string(),
                content_disposition: "inline".to_string(),
                cache_control: EXAMPLE_CACHE_CONTROL.to_string(),
            })
        })
        .await;
        let mock = mock
            .match_query(Matcher::UrlEncoded(
                "url".to_string(),
                format!("{}/somefile.txt", server.url()),
            ))
            .create_async()
            .await;

        let client = create_client(&server);

        let maybe_result = client
            .head(
                &format!("{}/somefile.txt", server.url()),
                HeadCommandOptions {
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        assert_true!(maybe_result.is_some());

        let result = maybe_result.unwrap();
        assert_eq!(result.pathname, "somefile.txt");
        assert_eq!(result.cache_control, EXAMPLE_CACHE_CONTROL);

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn can_del() {
        let (server, mock) = setup_mock_rsp::<_, (), _>("POST", "/delete", |_| None).await;
        let mock = mock.create_async().await;

        let client = create_client(&server);

        client
            .del(
                &format!("{}/somefile.txt", server.url()),
                DelCommandOptions {
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        mock.assert_async().await;
    }

    #[derive(Debug, Deserialize, Serialize)]
    struct MockFile {
        text: String,
    }

    #[tokio::test]
    async fn can_download() {
        let (server, mock) = setup_mock_rsp("GET", "/somefile.txt", |_| {
            Some(MockFile {
                text: "hello".to_string(),
            })
        })
        .await;
        let mock = mock.create_async().await;

        let client = create_client(&server);

        let contents = client
            .download(
                &format!("{}/somefile.txt", server.url()),
                DownloadCommandOptions {
                    ..Default::default()
                },
            )
            .await
            .unwrap();

        mock.assert_async().await;

        let parsed_contents = serde_json::from_slice::<MockFile>(&contents).unwrap();
        assert_eq!(parsed_contents.text, "hello");
    }
}
