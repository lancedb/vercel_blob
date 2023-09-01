use std::{env, ops::Range, sync::Arc};

use bytes::Bytes;
use chrono::{DateTime, Utc};
use once_cell::sync::Lazy;
use reqwest::{Body, Client, RequestBuilder, StatusCode};
use serde::{Deserialize, Serialize};

use crate::{
    error::{Result, VercelBlobError},
    util::{get_token, TokenProvider},
};

const BLOB_API_VERSION: u32 = 2;
static GLOBAL_CLIENT: Lazy<Client> = Lazy::new(Client::new);

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
    /// A token provider to use to obtain a token to authenticate with the API
    pub token_provider: Option<Arc<dyn TokenProvider>>,
    /// The server URL to use.  This is not normally needed but can be used
    /// for testing purposes.
    pub api_url: Option<String>,
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

fn get_api_url(api_url: &Option<String>, pathname: Option<&str>) -> String {
    let base = api_url.clone().unwrap_or_else(|| {
        env::var("VERCEL_BLOB_API_URL")
            .or(env::var("NEXT_PUBLIC_VERCEL_BLOB_API_URL"))
            .unwrap_or_else(|_| "https://blob.vercel-storage.com".to_string())
    });
    url_join(base, pathname.unwrap_or("").to_string())
}

fn add_api_version_header(request: RequestBuilder) -> RequestBuilder {
    let api_version = env::var("VERCEL_BLOB_API_VERSION_OVERRIDE")
        .unwrap_or_else(|_| BLOB_API_VERSION.to_string());
    request.header("x-api-version", api_version)
}

async fn add_authorization_header(
    request: RequestBuilder,
    token_provider: Option<&dyn TokenProvider>,
) -> Result<RequestBuilder> {
    let token = get_token(token_provider).await?;
    Ok(request.header("authorization", format!("Bearer {}", token)))
}

/// Lists files in the blob store
///
/// # Arguments
///
/// * `options` - Options for the list operation
///
/// # Returns
///
/// The response from the list operation
pub async fn list(options: ListCommandOptions) -> Result<ListBlobResult> {
    let api_url = get_api_url(&options.api_url, None);
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
    request = add_api_version_header(request);
    request = add_authorization_header(request, options.token_provider.as_deref()).await?;
    let rsp = request.send().await?;

    if rsp.status() != StatusCode::OK {
        return Err(VercelBlobError::from_http(rsp.status()));
    }

    Ok(rsp.json::<ListBlobResult>().await?)
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
    /// A token provider to use to obtain a token to authenticate with the API
    pub token_provider: Option<Arc<dyn TokenProvider>>,
    /// The server URL to use.  This is not normally needed but can be used
    /// for testing purposes.
    pub api_url: Option<String>,
}

impl Default for PutCommandOptions {
    fn default() -> Self {
        Self {
            add_random_suffix: true,
            cache_control_max_age: None,
            content_type: None,
            token_provider: None,
            api_url: None,
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
pub async fn put(
    pathname: &str,
    body: impl Into<Body>,
    options: PutCommandOptions,
) -> Result<PutBlobResult> {
    if pathname.is_empty() {
        return Err(VercelBlobError::required("pathname"));
    }

    let api_url = get_api_url(&options.api_url, Some(&format!("/{pathname}")));
    let mut request = GLOBAL_CLIENT.put(api_url);

    request = add_api_version_header(request);
    request = add_authorization_header(request, options.token_provider.as_deref()).await?;

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
        return Err(VercelBlobError::from_http(response.status()));
    }

    let rsp_obj = response.json::<PutBlobResult>().await?;
    Ok(rsp_obj)
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
}

/// Options for the head operation
#[derive(Debug, Default)]
pub struct HeadCommandOptions {
    /// A token provider to use to obtain a token to authenticate with the API
    pub token_provider: Option<Arc<dyn TokenProvider>>,
    /// The server URL to use.  This is not normally needed but can be used
    /// for testing purposes.
    pub api_url: Option<String>,
}

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
pub async fn head(url: &str, options: HeadCommandOptions) -> Result<Option<HeadBlobResult>> {
    let api_url = get_api_url(&options.api_url, None);
    let mut request = GLOBAL_CLIENT.get(api_url);

    request = request.query(&[("url", url)]);

    request = add_api_version_header(request);
    request = add_authorization_header(request, options.token_provider.as_deref()).await?;

    let response = request.send().await?;

    if response.status() == StatusCode::NOT_FOUND {
        return Ok(None);
    }

    if response.status() == StatusCode::BAD_REQUEST {
        return Err(VercelBlobError::InvalidInput(format!(
            "{:?}",
            response.bytes().await?
        )));
    }

    if response.status() != StatusCode::OK {
        return Err(VercelBlobError::from_http(response.status()));
    }

    Ok(Some(response.json::<HeadBlobResult>().await?))
}

#[derive(Debug, Serialize)]
struct DelCommandBody {
    urls: Vec<String>,
}

/// Options for the del operation
#[derive(Debug, Default)]
pub struct DelCommandOptions {
    /// A token provider to use to obtain a token to authenticate with the API
    pub token_provider: Option<Arc<dyn TokenProvider>>,
    /// The server URL to use.  This is not normally needed but can be used
    /// for testing purposes.
    pub api_url: Option<String>,
}

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
pub async fn del(url: &str, options: DelCommandOptions) -> Result<()> {
    let api_url = get_api_url(&options.api_url, Some("/delete"));
    let mut request = GLOBAL_CLIENT.post(api_url);

    request = add_api_version_header(request);
    request = add_authorization_header(request, options.token_provider.as_deref()).await?;
    request = request.header("content-type", "application/json");

    request = request.json(&DelCommandBody {
        urls: vec![url.to_string()],
    });

    let response = request.send().await?;

    if response.status() != StatusCode::OK {
        return Err(VercelBlobError::from_http(response.status()));
    }

    Ok(())
}

/// Options for the download operation
#[derive(Debug, Default)]
pub struct DownloadCommandOptions {
    /// The range of bytes to download.  If not specified then the entire blob
    /// is downloaded.  The start of the range must be less than the # of bytes
    /// in the blob or an error will be returned.  The end of the range may be
    /// greater than the number of bytes in the blob.
    pub byte_range: Option<Range<usize>>,
    /// A token provider to use to obtain a token to authenticate with the API
    pub token_provider: Option<Arc<dyn TokenProvider>>,
    /// The server URL to use.  This is not normally needed but can be used
    /// for testing purposes.
    pub api_url: Option<String>,
}

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
pub async fn download(url: &str, options: DownloadCommandOptions) -> Result<Bytes> {
    let mut request = GLOBAL_CLIENT.get(url);

    request = add_api_version_header(request);
    request = add_authorization_header(request, options.token_provider.as_deref()).await?;

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
        return Err(VercelBlobError::from_http(response.status()));
    }

    Ok(response.bytes().await.unwrap())
}

/// These unit tests test against a mock server.  They will not test integration issues
/// with the blob store but they are useful for regression and testing corner cases.
#[cfg(test)]
mod tests {

    use all_asserts::{assert_false, assert_true};
    use mockito::{Matcher, Mock, ServerGuard};

    use super::*;

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

        let results = list(ListCommandOptions {
            api_url: Some(server.url().to_string()),
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

        let results = list(ListCommandOptions {
            api_url: Some(server.url().to_string()),
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

        let data = "here are some new contents";
        let pathname = "somefile.txt";
        let result = put(
            pathname,
            data,
            PutCommandOptions {
                api_url: Some(server.url().to_string()),
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

        let data = "here are some new contents";
        let pathname = "somefile.txt";
        let result = put(
            pathname,
            data,
            PutCommandOptions {
                api_url: Some(server.url().to_string()),
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

        let maybe_result = head(
            &format!("{}/somefile.txt", server.url()),
            HeadCommandOptions {
                api_url: Some(server.url().to_string()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        assert_true!(maybe_result.is_some());

        let result = maybe_result.unwrap();
        assert_eq!(result.pathname, "somefile.txt");

        mock.assert_async().await;
    }

    #[tokio::test]
    async fn can_del() {
        let (server, mock) = setup_mock_rsp::<_, (), _>("POST", "/delete", |_| None).await;
        let mock = mock.create_async().await;

        del(
            &format!("{}/somefile.txt", server.url()),
            DelCommandOptions {
                api_url: Some(server.url().to_string()),
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

        let contents = download(
            &format!("{}/somefile.txt", server.url()),
            DownloadCommandOptions {
                api_url: Some(server.url().to_string()),
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
