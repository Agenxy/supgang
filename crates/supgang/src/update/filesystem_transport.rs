use std::{
    fs::OpenOptions,
    io,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

use async_trait::async_trait;
use futures_util::TryStreamExt;
use tokio_util::io::ReaderStream;
use tough::{Transport, TransportError, TransportErrorKind, TransportStream};
use url::Url;

use super::{UpdateError, valid_entry_name};

#[derive(Clone, Debug)]
struct RepositoryArea {
    url_prefix: String,
    directory: PathBuf,
    maximum_bytes: u64,
}

/// Streams only single-component files below the two already-validated bundle directories.
///
/// `tough`'s stock filesystem transport intentionally preserves URL percent encoding when it
/// turns a URL into a path. That cannot open the macOS default state directory because its
/// `Application Support` component becomes `Application%20Support`. Keeping the real directory
/// separately also gives this transport a stricter boundary: URLs select one validated filename,
/// while the URL itself never becomes a filesystem path.
#[derive(Clone, Debug)]
pub(super) struct ProtectedFilesystemTransport {
    metadata: RepositoryArea,
    targets: RepositoryArea,
}

impl ProtectedFilesystemTransport {
    pub(super) fn new(
        metadata_url: &Url,
        metadata_directory: &Path,
        maximum_metadata_bytes: u64,
        targets_url: &Url,
        targets_directory: &Path,
        maximum_target_bytes: u64,
    ) -> Result<Self, UpdateError> {
        crate::storage::validate_trusted_owner_directory(metadata_directory)?;
        crate::storage::validate_trusted_owner_directory(targets_directory)?;
        let metadata = RepositoryArea::new(metadata_url, metadata_directory, maximum_metadata_bytes)?;
        let targets = RepositoryArea::new(targets_url, targets_directory, maximum_target_bytes)?;
        Ok(Self { metadata, targets })
    }

    fn resolve<'transport, 'url>(
        &'transport self,
        url: &'url Url,
    ) -> Result<(&'transport RepositoryArea, &'url str), TransportError> {
        if url.scheme() != "file" || url.query().is_some() || url.fragment().is_some() {
            return Err(transport_error(url, TransportErrorKind::UnsupportedUrlScheme));
        }
        for area in [&self.metadata, &self.targets] {
            if let Some(name) = url.as_str().strip_prefix(&area.url_prefix)
                && valid_entry_name(name)
            {
                return Ok((area, name));
            }
        }
        Err(transport_error(url, TransportErrorKind::Other))
    }
}

impl RepositoryArea {
    fn new(url: &Url, directory: &Path, maximum_bytes: u64) -> Result<Self, UpdateError> {
        if url.scheme() != "file" || url.query().is_some() || url.fragment().is_some() || maximum_bytes == 0 {
            return Err(UpdateError::InvalidBundle);
        }
        let url_prefix = url.as_str().to_owned();
        if !url_prefix.ends_with('/') {
            return Err(UpdateError::InvalidBundle);
        }
        Ok(Self {
            url_prefix,
            directory: directory.to_path_buf(),
            maximum_bytes,
        })
    }
}

#[async_trait]
impl Transport for ProtectedFilesystemTransport {
    async fn fetch(&self, url: Url) -> Result<TransportStream, TransportError> {
        let (area, name) = self.resolve(&url)?;
        let path = area.directory.join(name);
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(super::no_follow().map_err(|error| transport_cause(&url, error))?)
            .open(path)
            .map_err(|error| io_transport_error(&url, error))?;
        crate::storage::validate_owner_file_metadata(&file).map_err(|error| transport_cause(&url, error))?;
        let length = file.metadata().map_err(|error| io_transport_error(&url, error))?.len();
        if length == 0 || length > area.maximum_bytes {
            return Err(transport_error(&url, TransportErrorKind::Other));
        }
        let stream = ReaderStream::new(tokio::io::BufReader::new(tokio::fs::File::from_std(file)));
        let error_url = url.clone();
        Ok(Box::pin(
            stream.map_err(move |error| io_transport_error(&error_url, error)),
        ))
    }
}

fn transport_error(url: &Url, kind: TransportErrorKind) -> TransportError {
    TransportError::new(kind, url.as_str())
}

fn transport_cause(url: &Url, error: impl Into<Box<dyn std::error::Error + Send + Sync>>) -> TransportError {
    TransportError::new_with_cause(TransportErrorKind::Other, url.as_str(), error)
}

fn io_transport_error(url: &Url, error: io::Error) -> TransportError {
    let kind = if error.kind() == io::ErrorKind::NotFound {
        TransportErrorKind::FileNotFound
    } else {
        TransportErrorKind::Other
    };
    TransportError::new_with_cause(kind, url.as_str(), error)
}

#[cfg(test)]
mod tests {
    use std::{fs, os::unix::fs::PermissionsExt};

    use futures_util::TryStreamExt;
    use tough::Transport;

    use super::ProtectedFilesystemTransport;

    #[test]
    fn streams_from_space_containing_paths_without_decoding_url_input() -> Result<(), Box<dyn std::error::Error>> {
        crate::transport::build_runtime()?.block_on(async {
            let temporary = tempfile::tempdir()?;
            let repository = temporary.path().join("repository with spaces");
            let metadata = repository.join("metadata");
            let targets = repository.join("targets");
            fs::create_dir(&repository)?;
            fs::create_dir(&metadata)?;
            fs::create_dir(&targets)?;
            for directory in [&repository, &metadata, &targets] {
                fs::set_permissions(directory, fs::Permissions::from_mode(0o700))?;
            }
            let timestamp = metadata.join("timestamp.json");
            fs::write(&timestamp, b"signed metadata")?;
            fs::set_permissions(&timestamp, fs::Permissions::from_mode(0o600))?;
            let metadata_url = url::Url::from_directory_path(&metadata).map_err(|()| "metadata URL")?;
            let targets_url = url::Url::from_directory_path(&targets).map_err(|()| "targets URL")?;
            let transport =
                ProtectedFilesystemTransport::new(&metadata_url, &metadata, 1024, &targets_url, &targets, 1024)?;
            let fetched = transport
                .fetch(metadata_url.join("timestamp.json")?)
                .await?
                .try_fold(Vec::new(), |mut bytes, chunk| async move {
                    bytes.extend_from_slice(&chunk);
                    Ok(bytes)
                })
                .await?;
            assert_eq!(fetched, b"signed metadata");
            Ok::<(), Box<dyn std::error::Error>>(())
        })
    }

    #[test]
    fn rejects_nested_encoded_and_symlink_names() -> Result<(), Box<dyn std::error::Error>> {
        crate::transport::build_runtime()?.block_on(async {
            let temporary = tempfile::tempdir()?;
            let metadata = temporary.path().join("metadata");
            let targets = temporary.path().join("targets");
            fs::create_dir(&metadata)?;
            fs::create_dir(&targets)?;
            fs::set_permissions(&metadata, fs::Permissions::from_mode(0o700))?;
            fs::set_permissions(&targets, fs::Permissions::from_mode(0o700))?;
            let outside = temporary.path().join("outside");
            fs::write(&outside, b"outside")?;
            fs::set_permissions(&outside, fs::Permissions::from_mode(0o600))?;
            std::os::unix::fs::symlink(&outside, metadata.join("root.json"))?;
            let metadata_url = url::Url::from_directory_path(&metadata).map_err(|()| "metadata URL")?;
            let targets_url = url::Url::from_directory_path(&targets).map_err(|()| "targets URL")?;
            let transport =
                ProtectedFilesystemTransport::new(&metadata_url, &metadata, 1024, &targets_url, &targets, 1024)?;
            assert!(transport.fetch(metadata_url.join("nested/file")?).await.is_err());
            assert!(transport.fetch(metadata_url.join("%2e%2e%2foutside")?).await.is_err());
            assert!(transport.fetch(metadata_url.join("root.json")?).await.is_err());
            Ok::<(), Box<dyn std::error::Error>>(())
        })
    }
}
