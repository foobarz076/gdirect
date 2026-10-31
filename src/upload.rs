use crate::{
    api::{Api, File},
    store::Store,
};
use anyhow::{Context, Result, bail, ensure};
use reqwest::{StatusCode, blocking::Response};
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{Read, Seek, SeekFrom},
    path::Path,
    time::{Duration, UNIX_EPOCH},
};

const CHUNK: u64 = 32 * 1024 * 1024;
const FIELDS: &str = "id,name,mimeType,size,md5Checksum";
#[derive(Serialize, Deserialize)]
struct Session {
    size: u64,
    modified: u128,
    url: String,
}

// Session URLs are credentials: keep them in the private SQLite database and
// never print them or follow a redirect with the user's bearer token.
fn session_url(raw: &str) -> Result<url::Url> {
    let url = url::Url::parse(raw).context("invalid upload session URL")?;
    ensure!(
        url.scheme() == "https"
            && url.host_str() == Some("www.googleapis.com")
            && url.port_or_known_default() == Some(443)
            && url.username().is_empty()
            && url.password().is_none()
            && url.path().starts_with("/upload/drive/v3/files"),
        "untrusted upload session URL"
    );
    Ok(url)
}
fn offset(response: &Response, size: u64) -> Result<u64> {
    let Some(range) = response.headers().get("range") else {
        return Ok(0);
    };
    acknowledged(range.to_str()?, size)
}
fn acknowledged(range: &str, size: u64) -> Result<u64> {
    let end: u64 = range
        .strip_prefix("bytes=0-")
        .context("invalid upload acknowledgement")?
        .parse()?;
    let next = end.checked_add(1).context("invalid upload offset")?;
    ensure!(next <= size, "upload acknowledgement exceeds file size");
    Ok(next)
}
fn failure(response: Response) -> anyhow::Error {
    // Do not include a response body: it can contain the secret session URI.
    anyhow::anyhow!(
        "Drive upload returned {}; rerun the same upload to resume",
        response.status()
    )
}
impl Api {
    pub fn upload(&self, path: &Path, parent: &str, name: Option<&str>) -> Result<File> {
        let path = path.canonicalize().context("cannot open upload file")?;
        let mut file = fs::File::open(&path)?;
        let metadata = file.metadata()?;
        ensure!(metadata.is_file(), "upload expects a regular file");
        let size = metadata.len();
        let modified = metadata.modified()?.duration_since(UNIX_EPOCH)?.as_nanos();
        let name = name
            .or_else(|| path.file_name().and_then(|s| s.to_str()))
            .context("file name must be UTF-8; use --name")?;
        ensure!(!name.is_empty(), "file name cannot be empty");
        ensure!(crate::drive::valid_id(parent), "invalid parent folder ID");
        ensure!(
            !matches!(parent, "drives" | "shared"),
            "open a folder or Shared Drive first"
        );
        let db = Store::open(&self.db)?;
        let key = Store::upload_key(
            self.account.as_deref().unwrap_or_default(),
            &serde_json::to_string(&(path.to_string_lossy(), parent, name))?,
        );
        let saved = db
            .setting(&key)?
            .map(|s| serde_json::from_str::<Session>(&s))
            .transpose()?;
        let mut token = self.download_token()?;
        let mut start = 0;
        let mut session = saved.filter(|s| s.size == size && s.modified == modified);
        if let Some(s) = &session {
            let url = session_url(&s.url)?;
            let response = self.deliver(|client, forged| {
                client
                    .put(crate::api::gate(forged, &url))
                    .bearer_auth(&token)
                    .header("Content-Range", format!("bytes */{size}"))
                    .header("Content-Length", 0)
            })?;
            match response.status() {
                StatusCode::OK | StatusCode::CREATED => {
                    let result = response.json()?;
                    db.unset(&key)?;
                    return Ok(result);
                }
                StatusCode::PERMANENT_REDIRECT => start = offset(&response, size)?,
                StatusCode::NOT_FOUND | StatusCode::GONE => session = None,
                _ => return Err(failure(response)),
            }
        }
        let session = match session {
            Some(s) => s,
            None => {
                let response = self.deliver(|client, forged| {
                    client
                        .post(crate::api::url_for(forged, "upload/drive/v3/files"))
                        .query(&[
                            ("uploadType", "resumable"),
                            ("supportsAllDrives", "true"),
                            ("fields", FIELDS),
                        ])
                        .bearer_auth(&token)
                        .header("X-Upload-Content-Type", "application/octet-stream")
                        .header("X-Upload-Content-Length", size)
                        .json(&serde_json::json!({"name": name, "parents": [parent]}))
                })?;
                if !response.status().is_success() {
                    return Err(failure(response));
                }
                let raw = response
                    .headers()
                    .get("location")
                    .context("missing upload session")?
                    .to_str()?;
                let s = Session {
                    size,
                    modified,
                    url: session_url(raw)?.into(),
                };
                db.set(&key, &serde_json::to_string(&s)?)?;
                s
            }
        };
        let url = session_url(&session.url)?;
        let mut failures = 0;
        let mut probe = false;
        loop {
            let current = file.metadata()?;
            ensure!(
                current.len() == size
                    && current.modified()?.duration_since(UNIX_EPOCH)?.as_nanos() == modified,
                "local file changed during upload; rerun with a stable file"
            );
            let mut body = None;
            let count = (size - start).min(CHUNK);
            if !(probe || size == 0 || start == size) {
                file.seek(SeekFrom::Start(start))?;
                let mut bytes = vec![0; count as usize];
                file.read_exact(&mut bytes)?;
                body = Some(bytes);
            }
            let response = self.deliver(|client, forged| {
                let mut request = client
                    .put(crate::api::gate(forged, &url))
                    .bearer_auth(&token)
                    .timeout(Duration::from_secs(180));
                match &body {
                    None => {
                        request = request
                            .header("Content-Range", format!("bytes */{size}"))
                            .header("Content-Length", 0);
                    }
                    Some(bytes) => {
                        request = request
                            .header("Content-Type", "application/octet-stream")
                            .header(
                                "Content-Range",
                                format!("bytes {}-{}/{size}", start, start + count - 1),
                            )
                            .body(bytes.clone());
                    }
                }
                request
            });
            match response {
                Ok(r) if r.status() == StatusCode::OK || r.status() == StatusCode::CREATED => {
                    let result: File = r.json()?;
                    ensure!(
                        result.size.as_deref() == Some(&size.to_string()),
                        "uploaded size mismatch"
                    );
                    db.unset(&key)?;
                    eprintln!("\rUploaded {size}/{size} bytes");
                    return Ok(result);
                }
                Ok(r) if r.status() == StatusCode::PERMANENT_REDIRECT => {
                    let next = offset(&r, size)?;
                    if !probe && next <= start {
                        failures += 1;
                    } else if next > start {
                        failures = 0;
                    }
                    start = next;
                    probe = false;
                    eprint!("\rUploading {start}/{size} bytes");
                }
                Ok(r) if r.status() == StatusCode::UNAUTHORIZED => {
                    token = self.download_token()?;
                    failures += 1;
                    probe = true;
                }
                Ok(r)
                    if r.status().is_server_error()
                        || r.status() == StatusCode::TOO_MANY_REQUESTS =>
                {
                    failures += 1;
                    probe = true;
                }
                Err(_) => {
                    failures += 1;
                    probe = true;
                }
                Ok(r) => return Err(failure(r)),
            }
            if failures >= 4 {
                bail!("upload interrupted; rerun the same command to resume");
            }
            if failures > 0 {
                std::thread::sleep(Duration::from_secs(1 << failures));
            }
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn acknowledgement_bounds() {
        assert_eq!(acknowledged("bytes=0-262143", 524288).unwrap(), 262144);
        for range in [
            "bytes=1-2",
            "bytes=0-524288",
            "bytes=0-18446744073709551615",
        ] {
            assert!(acknowledged(range, 524288).is_err());
        }
    }
    #[test]
    fn rejects_session_token_exfiltration() {
        for url in [
            "http://www.googleapis.com/upload/drive/v3/files",
            "https://evil.test/upload/drive/v3/files",
            "https://www.googleapis.com:444/upload/drive/v3/files",
            "https://user@www.googleapis.com/upload/drive/v3/files",
        ] {
            assert!(session_url(url).is_err());
        }
        assert!(
            session_url("https://www.googleapis.com/upload/drive/v3/files?upload_id=private")
                .is_ok()
        );
    }
}
