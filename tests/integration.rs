use std::collections::HashSet;
use std::env;
use std::ops::Range;
use std::sync::Arc;

use all_asserts::assert_true;
use async_trait::async_trait;
use bytes::Bytes;
use futures::stream;
use futures::stream::StreamExt;
use futures::stream::TryStreamExt;

use once_cell::sync::Lazy;
use serial_test::serial;
use vercel_blob::auth::EnvTokenProvider;
use vercel_blob::auth::TokenProvider;
use vercel_blob::client::DownloadCommandOptions;
use vercel_blob::client::HeadCommandOptions;
use vercel_blob::client::ListCommandOptions;
use vercel_blob::client::PutCommandOptions;
use vercel_blob::client::VercelBlobApi;
use vercel_blob::client::VercelBlobClient;
use vercel_blob::error::VercelBlobError;

/// These integration tests run against a real Vercel Blob Storage account.  As a result they
/// are ignored by default.  To run them, set the environment variable VERCEL_BLOB_TEST_TOKEN
/// to a token that has read/write access to a Vercel Blob Storage account.
///
/// Note that these tests will delete files (hopefully only files starting with `vercel_blob_unittest`
/// but be careful).

#[derive(Debug)]
pub struct MockTokenProvider {
    token: &'static str,
}

#[async_trait]
impl TokenProvider for MockTokenProvider {
    async fn get_token(
        &self,
        _operation: &str,
        _pathname: Option<&str>,
    ) -> std::result::Result<String, VercelBlobError> {
        Ok(self.token.to_string())
    }
}

static PROVIDER: Lazy<Arc<dyn TokenProvider>> =
    Lazy::new(|| Arc::new(EnvTokenProvider::try_new("VERCEL_BLOB_TEST_TOKEN").unwrap()));

async fn delete_all_files(client: &VercelBlobClient) {
    let all_files = client.list(Default::default()).await.unwrap();

    stream::iter(
        all_files
            .blobs
            .iter()
            .filter(|blob| blob.pathname.starts_with("vercel_blob_unittest"))
            .map(|blob| client.del(&blob.url, Default::default())),
    )
    .buffer_unordered(10)
    .try_for_each(|_| async { Ok(()) })
    .await
    .unwrap();
}

async fn count_files(client: &VercelBlobClient) -> usize {
    let all_files = client.list(Default::default()).await.unwrap();

    all_files
        .blobs
        .iter()
        .filter(|blob| blob.pathname.starts_with("vercel_blob_unittest"))
        .count()
}

async fn assert_file_contents_url(client: &VercelBlobClient, url: &str, contents: &str) {
    let file_bytes = client.download(url, Default::default()).await.unwrap();
    assert_eq!(file_bytes, contents.as_bytes());
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_delete_and_list() {
    let client = VercelBlobClient::new_external(PROVIDER.clone());

    delete_all_files(&client).await;

    assert_eq!(count_files(&client).await, 0);

    client
        .put(
            "vercel_blob_unittest/a.txt",
            "some content",
            PutCommandOptions {
                content_type: Some("text/plain".to_string()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    assert_eq!(count_files(&client).await, 1);

    delete_all_files(&client).await;

    assert_eq!(count_files(&client).await, 0);
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_paging() {
    let client = VercelBlobClient::new_external(PROVIDER.clone());

    delete_all_files(&client).await;

    for idx in 0..10 {
        client
            .put(
                &format!("vercel_blob_unittest/a{}.txt", idx),
                "some content",
                Default::default(),
            )
            .await
            .unwrap();
    }

    let first_batch = client
        .list(ListCommandOptions {
            limit: Some(6),
            prefix: Some("vercel_blob_unittest/".to_string()),
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(first_batch.blobs.len(), 6);

    let remaining_files = client
        .list(ListCommandOptions {
            limit: Some(6),
            prefix: Some("vercel_blob_unittest/".to_string()),
            cursor: first_batch.cursor.clone(),
            ..Default::default()
        })
        .await
        .unwrap();

    assert_eq!(remaining_files.blobs.len(), 4);

    let all_paths = first_batch
        .blobs
        .into_iter()
        .chain(remaining_files.blobs.into_iter())
        .map(|blob| blob.pathname)
        .collect::<HashSet<_>>();

    assert_eq!(all_paths.len(), 10);
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_put_with_random_suffix() {
    let client = VercelBlobClient::new_external(PROVIDER.clone());

    delete_all_files(&client).await;

    let file_one = client
        .put(
            "vercel_blob_unittest/a.txt",
            "some content",
            PutCommandOptions {
                content_type: Some("text/plain".to_string()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let file_two = client
        .put(
            "vercel_blob_unittest/a.txt",
            "different content",
            PutCommandOptions {
                content_type: Some("text/plain".to_string()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    // By default, two files are created
    assert_ne!(file_one.url, file_two.url);
    assert_file_contents_url(&client, &file_one.url, "some content").await;
    assert_file_contents_url(&client, &file_two.url, "different content").await;
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_put_without_random_suffix() {
    let client = VercelBlobClient::new_external(PROVIDER.clone());

    delete_all_files(&client).await;

    let file_one = client
        .put(
            "vercel_blob_unittest/a.txt",
            "some content",
            PutCommandOptions {
                content_type: Some("text/plain".to_string()),
                add_random_suffix: false,
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let file_two = client
        .put(
            "vercel_blob_unittest/a.txt",
            "different content",
            PutCommandOptions {
                content_type: Some("text/plain".to_string()),
                add_random_suffix: false,
                ..Default::default()
            },
        )
        .await
        .unwrap();

    // By default, two files are created
    assert_eq!(file_one.url, file_two.url);
    assert_file_contents_url(&client, &file_one.url, "different content").await;
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_put_cache_control() {
    let client = VercelBlobClient::new_external(PROVIDER.clone());

    delete_all_files(&client).await;

    let blob = client
        .put(
            "vercel_blob_unittest/a.json",
            vec![0_u8, 1_u8, 2_u8],
            PutCommandOptions {
                cache_control_max_age: Some(4200),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let head_result = client
        .head(&blob.url, HeadCommandOptions::default())
        .await
        .unwrap()
        .unwrap();

    assert!(head_result.cache_control.contains("max-age=4200"));
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_put_content_type() {
    let client = VercelBlobClient::new_external(PROVIDER.clone());

    delete_all_files(&client).await;

    let no_content_type = client
        .put(
            "vercel_blob_unittest/a.json",
            vec![0_u8, 1_u8, 2_u8],
            PutCommandOptions {
                content_type: Some("text/plain".to_string()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(no_content_type.content_type, "text/plain");

    let file_one = client
        .put(
            "vercel_blob_unittest/a.json",
            "{ \"a\": 1 }",
            PutCommandOptions {
                content_type: Some("text/plain".to_string()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    assert_eq!(file_one.content_type, "text/plain");

    let file_two = client
        .put(
            "vercel_blob_unittest/a.json",
            "{ \"a\": 1 }",
            PutCommandOptions {
                content_type: Some("application/json".to_string()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    assert_eq!(file_two.content_type, "application/json");
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_head() {
    let client = VercelBlobClient::new_external(PROVIDER.clone());

    delete_all_files(&client).await;

    let uploaded = client
        .put(
            "vercel_blob_unittest/a.json",
            "{ \"a\": 1 }",
            PutCommandOptions {
                content_type: Some("text/plain".to_string()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    let found = client
        .head(&uploaded.url, Default::default())
        .await
        .unwrap();

    assert_true!(found.is_some());
    assert_eq!(&found.unwrap().url, &uploaded.url);

    delete_all_files(&client).await;

    let missing = client
        .head(&uploaded.url, Default::default())
        .await
        .unwrap();

    assert_true!(missing.is_none());
}

async fn partial_get(
    client: &VercelBlobClient,
    url: &str,
    range: Range<usize>,
) -> Result<Bytes, VercelBlobError> {
    client
        .download(
            url,
            DownloadCommandOptions {
                byte_range: Some(range),
                ..Default::default()
            },
        )
        .await
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_partial_download() {
    let client = VercelBlobClient::new_external(PROVIDER.clone());

    delete_all_files(&client).await;

    let uploaded = client
        .put(
            "vercel_blob_unittest/a.json",
            "0123456789",
            PutCommandOptions {
                content_type: Some("text/plain".to_string()),
                ..Default::default()
            },
        )
        .await
        .unwrap();

    assert_file_contents_url(&client, &uploaded.url, "0123456789").await;

    let file_bytes = partial_get(&client, &uploaded.url, 0..4).await.unwrap();
    assert_eq!(std::str::from_utf8(&file_bytes).unwrap(), "0123");

    let file_bytes = partial_get(&client, &uploaded.url, 2..7).await.unwrap();
    assert_eq!(std::str::from_utf8(&file_bytes).unwrap(), "23456");

    let file_bytes = partial_get(&client, &uploaded.url, 5..5).await.unwrap();
    assert_eq!(std::str::from_utf8(&file_bytes).unwrap(), "");

    // It's ok to request past the end of the file
    let file_bytes = partial_get(&client, &uploaded.url, 5..500).await.unwrap();
    assert_eq!(std::str::from_utf8(&file_bytes).unwrap(), "56789");

    // If the start of the request is past the end of the file it's an error
    let file_bytes = partial_get(&client, &uploaded.url, 100..500).await;
    assert_true!(file_bytes.is_err());
}

#[derive(Debug)]
struct HardCodedTokenProvider {
    token: String,
}

#[async_trait]
impl TokenProvider for HardCodedTokenProvider {
    async fn get_token(
        &self,
        _operation: &str,
        _pathname: Option<&str>,
    ) -> std::result::Result<String, VercelBlobError> {
        Ok(self.token.clone())
    }
}

#[tokio::test]
#[serial]
#[ignore]
async fn test_invalid_token() {
    env::set_var("BLOB_READ_WRITE_TOKEN", "xyz");
    let bad_provider = Arc::new(HardCodedTokenProvider {
        token: "foo".to_string(),
    });
    let client = VercelBlobClient::new_external(bad_provider);
    let err = client
        .list(ListCommandOptions::default())
        .await
        .unwrap_err();
    match err {
        VercelBlobError::Forbidden() => {}
        _ => panic!("Expected Forbidden error when passed a bad token"),
    }
}
