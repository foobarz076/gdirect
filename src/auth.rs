use crate::store::Store;
use anyhow::{Context, Result, bail, ensure};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::TcpListener,
    path::Path,
    process::Command,
    time::{Duration, Instant},
};

pub const CONFIG_GUIDE: &str =
    "https://github.com/mizorewww/gdirect/blob/main/docs/configuration/README.md";
const TOKEN_URI: &str = "https://oauth2.googleapis.com/token";
const SCOPE: &str = "https://www.googleapis.com/auth/drive";
const JWT_GRANT: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

// Only these fields are kept, so an imported token_uri or credential source is ignored.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Credentials {
    #[serde(rename = "authorized_user")]
    AuthorizedUser {
        client_id: String,
        #[serde(default)]
        client_secret: String,
        refresh_token: String,
    },
    #[serde(rename = "service_account")]
    ServiceAccount {
        client_email: String,
        private_key: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        subject: Option<String>,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Client {
    pub client_id: String,
    #[serde(default)]
    pub client_secret: String,
}
impl Credentials {
    pub fn parse(data: &[u8]) -> Result<Self> {
        let value: Value =
            serde_json::from_slice(data).context("credentials are not valid JSON")?;
        match value["type"].as_str() {
            Some("authorized_user") => {
                let credentials: Self = serde_json::from_value(value)
                    .context("credentials are missing client_id or refresh_token")?;
                if let Self::AuthorizedUser {
                    client_id,
                    refresh_token,
                    ..
                } = &credentials
                {
                    ensure!(
                        !client_id.is_empty() && !refresh_token.is_empty(),
                        "credentials are missing client_id or refresh_token"
                    );
                }
                Ok(credentials)
            }
            Some("service_account") => {
                let mut credentials: Self = serde_json::from_value(value).context(
                    "service account credentials are missing client_email or private_key",
                )?;
                if let Self::ServiceAccount {
                    client_email,
                    private_key,
                    subject,
                } = &mut credentials
                {
                    *client_email = client_email.trim().to_owned();
                    *subject = subject
                        .take()
                        .map(|s| s.trim().to_owned())
                        .filter(|s| !s.is_empty());
                    ensure!(
                        !client_email.is_empty() && !private_key.is_empty(),
                        "service account credentials are missing client_email or private_key"
                    );
                    rsa_key(private_key)?;
                }
                Ok(credentials)
            }
            _ => bail!("expected authorized_user or service_account credentials JSON"),
        }
    }
    pub fn with_subject(mut self, subject: Option<&str>) -> Result<Self> {
        let Some(subject) = subject.map(str::trim).filter(|s| !s.is_empty()) else {
            return Ok(self);
        };
        match &mut self {
            Self::ServiceAccount {
                subject: stored, ..
            } => {
                *stored = Some(subject.to_owned());
                Ok(self)
            }
            Self::AuthorizedUser { .. } => {
                bail!("--subject requires service_account credentials")
            }
        }
    }
    pub fn refresh_form(&self) -> Result<Vec<(&'static str, String)>> {
        match self {
            Self::AuthorizedUser {
                client_id,
                client_secret,
                refresh_token,
            } => Ok(vec![
                ("client_id", client_id.clone()),
                ("client_secret", client_secret.clone()),
                ("refresh_token", refresh_token.clone()),
                ("grant_type", "refresh_token".into()),
            ]),
            Self::ServiceAccount {
                client_email,
                private_key,
                subject,
            } => Ok(vec![
                ("grant_type", JWT_GRANT.into()),
                (
                    "assertion",
                    assertion(
                        client_email,
                        private_key,
                        subject.as_deref(),
                        crate::store::now(),
                    )?,
                ),
            ]),
        }
    }
    pub fn client(&self) -> Result<Client> {
        match self {
            Self::AuthorizedUser {
                client_id,
                client_secret,
                ..
            } => Ok(Client {
                client_id: client_id.clone(),
                client_secret: client_secret.clone(),
            }),
            Self::ServiceAccount { .. } => bail!(
                "browser login requires a Desktop OAuth client JSON: gdirect login --client-secret PATH\nSetup: {CONFIG_GUIDE}"
            ),
        }
    }
    pub fn is_service_account(&self) -> bool {
        matches!(self, Self::ServiceAccount { .. })
    }
    pub fn subject(&self) -> Option<&str> {
        match self {
            Self::ServiceAccount { subject, .. } => subject.as_deref(),
            Self::AuthorizedUser { .. } => None,
        }
    }
}
fn pkcs8_der(pem: &str) -> Result<Vec<u8>> {
    const BEGIN: &str = "-----BEGIN PRIVATE KEY-----";
    const END: &str = "-----END PRIVATE KEY-----";
    let body = pem
        .split_once(BEGIN)
        .and_then(|(_, rest)| rest.split_once(END))
        .map(|(body, _)| body)
        .context("service account private_key must be a PKCS#8 PEM block")?;
    let clean: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    ensure!(!clean.is_empty(), "service account private_key is empty");
    STANDARD
        .decode(clean)
        .context("service account private_key is not valid base64")
}
fn rsa_key(pem: &str) -> Result<ring::signature::RsaKeyPair> {
    let der = pkcs8_der(pem)?;
    ring::signature::RsaKeyPair::from_pkcs8(&der)
        .map_err(|_| anyhow::anyhow!("service account private_key is not a valid PKCS#8 RSA key"))
}
fn assertion(
    client_email: &str,
    private_key: &str,
    subject: Option<&str>,
    now: i64,
) -> Result<String> {
    let key = rsa_key(private_key)?;
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"RS256","typ":"JWT"}"#);
    let mut claims = serde_json::json!({
        "iss": client_email,
        "scope": SCOPE,
        "aud": TOKEN_URI,
        "iat": now,
        "exp": now + 3600,
    });
    if let Some(sub) = subject.filter(|s| !s.is_empty()) {
        claims["sub"] = Value::String(sub.into());
    }
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims)?);
    let signing_input = format!("{header}.{payload}");
    let rng = ring::rand::SystemRandom::new();
    let mut sig = vec![0; key.public().modulus_len()];
    key.sign(
        &ring::signature::RSA_PKCS1_SHA256,
        &rng,
        signing_input.as_bytes(),
        &mut sig,
    )
    .map_err(|_| anyhow::anyhow!("failed to sign service account JWT"))?;
    Ok(format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig)))
}
pub fn credentials(db: &Store, account: Option<&str>) -> Result<Credentials> {
    if let Some(raw) = account.map(|a| db.credentials(a)).transpose()?.flatten() {
        return Credentials::parse(raw.as_bytes());
    }
    bail!(
        "first login requires a Desktop OAuth client or service account JSON: gdirect login --client-secret PATH (or --credentials PATH)\nSetup: {CONFIG_GUIDE}"
    )
}
#[derive(Debug)]
pub struct Token {
    pub access_token: String,
    pub expires_in: i64,
}
fn http() -> Result<reqwest::blocking::Client> {
    Ok(crate::api::client_builder()
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(45))
        .redirect(reqwest::redirect::Policy::none())
        .build()?)
}
fn post_token<K: Serialize, V: Serialize>(
    endpoint: &str,
    form: &[(K, V)],
) -> Result<(StatusCode, Value)> {
    let response = http()?.post(endpoint).form(form).send().map_err(|e| {
        anyhow::anyhow!(
            "cannot reach Google's token endpoint ({}); check system HTTP/HTTPS proxy settings or HTTPS_PROXY and access to oauth2.googleapis.com",
            e.without_url()
        )
    })?;
    let status = response.status();
    let text = response.text().map_err(|e| e.without_url())?;
    Ok((status, serde_json::from_str(&text).unwrap_or_default()))
}
// Google's OAuth error code and description, e.g. "invalid_client: The OAuth client was deleted."
fn google_error(status: StatusCode, data: &Value) -> String {
    let code = data["error"].as_str().unwrap_or("unknown_error");
    match data["error_description"].as_str() {
        Some(description) => format!("{status} {code}: {description}"),
        None => format!("{status} {code}"),
    }
}
/// Whether a token-endpoint reply is Google's answer rather than some other page.
pub(crate) fn from_google(data: &Value) -> bool {
    data["access_token"].is_string() || data["error"].is_string()
}
pub(crate) fn refreshed(status: StatusCode, data: &Value) -> Result<Token> {
    if !status.is_success() {
        if data["error"] == "invalid_grant" {
            bail!("refresh credential expired or revoked; run gdirect login --reauth");
        }
        bail!(
            "Google token refresh failed ({}); run gdirect login --reauth",
            google_error(status, data)
        );
    }
    let access_token = data["access_token"]
        .as_str()
        .filter(|t| !t.is_empty() && t.bytes().all(|b| b.is_ascii_graphic()))
        .context("Google returned an invalid access token")?;
    Ok(Token {
        access_token: access_token.into(),
        expires_in: data["expires_in"].as_i64().unwrap_or(3600),
    })
}
pub fn refresh(credentials: &Credentials) -> Result<Token> {
    let form = credentials.refresh_form()?;
    let (status, data) = post_token(TOKEN_URI, &form)?;
    refreshed(status, &data)
}
fn oauth_client_from_accounts(db: &Store, preferred: Option<&str>) -> Result<Client> {
    let default = db.default_account()?;
    let first = preferred.or(default.as_deref());
    if let Some(account) = first
        && let Ok(cred) = credentials(db, Some(account))
        && let Ok(client) = cred.client()
    {
        return Ok(client);
    }
    for account in db.accounts()? {
        if let Ok(cred) = credentials(db, Some(&account))
            && let Ok(client) = cred.client()
        {
            return Ok(client);
        }
    }
    credentials(db, first)?.client()
}
pub fn prepare_login(
    db: &Store,
    account: Option<&str>,
    client: Option<&Path>,
    import: Option<&Path>,
    subject: Option<&str>,
    reauth: bool,
) -> Result<Credentials> {
    if let Some(path) = import {
        return Credentials::parse(&fs::read(path).context("cannot read credentials JSON")?)?
            .with_subject(subject);
    }
    if let Some(path) = client {
        let data: Value =
            serde_json::from_slice(&fs::read(path).context("cannot read OAuth client JSON")?)?;
        ensure!(
            data["installed"].is_object(),
            "download a Desktop app OAuth client JSON (web clients are not supported)"
        );
        let client = serde_json::from_value(data["installed"].clone())
            .context("OAuth client JSON is missing client_id")?;
        return browser_login(&client);
    }
    if reauth {
        // Any signed-in account's client works for adding another account.
        let client = match db.setting("oauth_client")? {
            Some(raw) => serde_json::from_str(&raw)?,
            None => oauth_client_from_accounts(db, account)?,
        };
        return browser_login(&client);
    }
    credentials(db, account)
}
fn random_string() -> Result<String> {
    let mut bytes = [0; 32];
    getrandom::fill(&mut bytes)
        .map_err(|_| anyhow::anyhow!("system random generator unavailable"))?;
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}
fn challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}
fn callback(target: &str, state: &str) -> Result<Option<String>> {
    ensure!(target.starts_with("/callback?"), "unexpected callback path");
    let url = url::Url::parse(&format!("http://127.0.0.1{target}"))?;
    let query: std::collections::HashMap<_, _> = url.query_pairs().into_owned().collect();
    ensure!(
        query.get("state").map(String::as_str) == Some(state),
        "OAuth state mismatch"
    );
    if query.contains_key("error") {
        return Ok(None);
    }
    Ok(Some(
        query
            .get("code")
            .filter(|s| !s.is_empty())
            .context("missing authorization code")?
            .clone(),
    ))
}
fn browser_login(client: &Client) -> Result<Credentials> {
    let client_id = client.client_id.as_str();
    ensure!(
        client_id.ends_with(".apps.googleusercontent.com"),
        "invalid Google OAuth client ID"
    );
    let secret = client.client_secret.as_str();
    let listener = TcpListener::bind(("127.0.0.1", 0))?;
    listener.set_nonblocking(true)?;
    let redirect = format!(
        "http://127.0.0.1:{}/callback",
        listener.local_addr()?.port()
    );
    let state = random_string()?;
    let verifier = random_string()?;
    let mut url = url::Url::parse("https://accounts.google.com/o/oauth2/v2/auth")?;
    url.query_pairs_mut().extend_pairs([
        ("client_id", client_id),
        ("redirect_uri", redirect.as_str()),
        ("response_type", "code"),
        ("scope", SCOPE),
        ("access_type", "offline"),
        ("prompt", "consent select_account"),
        ("state", state.as_str()),
        ("code_challenge", challenge(&verifier).as_str()),
        ("code_challenge_method", "S256"),
    ]);
    eprintln!("Open this URL in a browser on this computer:\n{url}");
    let mut browser = if cfg!(target_os = "macos") {
        Command::new("open")
    } else if cfg!(windows) {
        let mut c = Command::new("rundll32");
        c.arg("url.dll,FileProtocolHandler");
        c
    } else {
        Command::new("xdg-open")
    };
    let _ = browser
        .arg(url.as_str())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
    let deadline = Instant::now() + Duration::from_secs(300);
    let code = loop {
        ensure!(
            Instant::now() < deadline,
            "browser login timed out; run the login command again"
        );
        let (mut stream, _) = match listener.accept() {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(100));
                continue;
            }
            Err(e) => return Err(e.into()),
        };
        stream.set_read_timeout(Some(Duration::from_secs(3)))?;
        let mut first = String::new();
        if BufReader::new(stream.try_clone()?.take(8192))
            .read_line(&mut first)
            .is_err()
        {
            continue;
        }
        let parts: Vec<_> = first.split_whitespace().collect();
        let result = if parts.first() == Some(&"GET") && parts.len() == 3 {
            callback(parts[1], &state)
        } else {
            Err(anyhow::anyhow!("invalid callback"))
        };
        let (status, body) = if result.is_ok() {
            (
                "200 OK",
                "Authorization received. Return to the terminal to finish login.",
            )
        } else {
            (
                "400 Bad Request",
                "Invalid authorization callback. Return to the login page.",
            )
        };
        let _ = write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        if let Ok(code) = result {
            break code.context("Google authorization was declined")?;
        }
    };
    let (status, token) = post_token(
        TOKEN_URI,
        &[
            ("client_id", client_id),
            ("client_secret", secret),
            ("code", code.as_str()),
            ("code_verifier", verifier.as_str()),
            ("redirect_uri", redirect.as_str()),
            ("grant_type", "authorization_code"),
        ],
    )?;
    ensure!(
        status.is_success(),
        "Google rejected the authorization code ({}); verify the Desktop OAuth client configuration",
        google_error(status, &token)
    );
    let refresh_token = token["refresh_token"]
        .as_str()
        .filter(|s| !s.is_empty())
        .context("Google did not return a refresh token")?;
    Ok(Credentials::AuthorizedUser {
        client_id: client_id.into(),
        client_secret: secret.into(),
        refresh_token: refresh_token.into(),
    })
}
pub fn export_credentials(credentials: &Credentials, path: &Path) -> Result<()> {
    let mut options = fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    file.write_all(serde_json::to_string(credentials)?.as_bytes())?;
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::KeyPair;

    const TEST_KEY: &str = "-----BEGIN PRIVATE KEY-----\n\
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCk4IYZTitZvixg\n\
RvYHbnvw3RR2fof5JzNVzlimL3CmGww1czchukST2C6yRbxY628OxB4RWED0Ul8p\n\
Ao3Wmz+yc6alzOwH8JsLK6qTTQ50qlzIsg0whTrSDCnDRsHYRI3kfM7GNQKHtdi+\n\
opaFPmhVDLbHKZ9Bo2c/OYtSfxctcn6JTjncvVSWZpt8byQ9azPvih9fUTKXig1N\n\
lb4eZduWsVOV0Z56iiQ9b2GDEZDsha983bEKb89FzrQ8Z7n7cMYYj9vJxGyYHSii\n\
EUwOKbOKzUmkgRDnVq7RVZc0ylhhPBcQYMJV2t8PPBsYxvQm3f3gaV1Uj/+LQPGc\n\
vD9zO5q9AgMBAAECggEAFVw7M0sTxbAkGqMG28aeCwHxVTqmTgqclXjCtmD+BJ8L\n\
cV9IXLe/i7Hdtt3e/VwfCrgwtwmKfLyxNGRu0MdTNMDT7bYDPDIZPBS/qA67GTU7\n\
CQs8NzWDfdPykyh3E5gqE9hxh281sTRHbMcunfuMU7xub5X+Wmgbh67iVGE/tPTj\n\
eRbvlVYweJlkOozj8OI/bHtn1iZJmcNJgfiCxG6g6w1VqQ8ijDLBYoPXIW8I6N1t\n\
XaXrqn/siP9qsCKd2oGJBIkPmoafMmNxeX/OHF/7KUMxOPv42juM+JStlteCbj7L\n\
heU2lwx5EU9AXkrUJkEGx+er6+5EcAy5VnQZjUVc4QKBgQDdzahM+EgE1bIQL2+F\n\
RiLtf1xQVnq7G3zytd3D1gq0+hhity2eLtP5LxkIFpxnGFsxFM02cR2DbElMEQAc\n\
lUgpe8hNcd5xvQ7xBdIU0T7XYZQW5yr+PCypAySR5CifGae9nIJthAXaHqn+EH4Z\n\
jHuGHpGoUv33HGoGn83fv1AE7QKBgQC+TAuyLfWBeowWEvf6VNI5LgRXTUcPNGKD\n\
tSF4VQH3uI4gD0vGbN5yqESpQZPVAECOvwrYoNdtsmqRDZ8A0cWrXo9Rz9lDr5ps\n\
1EZX3xGO5A+HjM1ARC9mB4zIAGk9986rSu5P3e+b+XDSKk3vqUoHcgxqtctepCRp\n\
B8W+pz6DEQKBgEURna8aQZL/2IshumCODqJWXrDFvUI2tRn/eCdbp8njd2SGFjaD\n\
7o5SFEFoiRuxgfQuvhiN8NrUBZ8iTB6affYtDZrQMqzIarazUVAaOK9pO2xGYCT7\n\
KA0ZZXHo0p14p7tr2VGxIwFhOx5alGnwTSbergz0ixFAT+PwL3PVZ12hAoGAGQMZ\n\
znOn/zrCSux3V5nqf8WCoI7xthfmkvUtzwktVwgU9jXMeeo5WsyvKagK7EY6Ngj6\n\
Pfr2Fd8LjsFBkvP/jUTChbhSEEl2fLNyA364ahWjzOc+2yGbMUfwwyD6tEBsE6un\n\
oyvCoLeqkpUo5UVVC6F77FK0xl3Aw2VYInUNDGECgYBjpB4dBhQZ54ce2Pr8veNc\n\
NUKoC8ucCMSU9zNyWCQWj7sHOuBmpmf4BF9SgSX9Ao5XgJQsvsLYh9DTFNHykUjl\n\
0pUA8d8ThUcps0Y3oN2CYfQ2WYWGgTpKm0kZrha2AEN+hIE8UKXKgfKedBvY6y+k\n\
6hS1K4zEEgwHoqmDCmWrdQ==\n\
-----END PRIVATE KEY-----\n";

    #[test]
    fn token_exchange_uses_proxy() {
        crate::test_network::assert_route("auth::tests::token_exchange_uses_proxy", true, |url| {
            let (status, data) = post_token(url, &[("grant_type", "refresh_token")])?;
            ensure!(status.is_success(), "fixture token request failed");
            Ok(data)
        });
    }
    #[test]
    fn token_responses_keep_google_error_codes() {
        let token = refreshed(
            StatusCode::OK,
            &serde_json::json!({"access_token":"ya29.a","expires_in":3599}),
        )
        .unwrap();
        assert_eq!(
            (token.access_token.as_str(), token.expires_in),
            ("ya29.a", 3599)
        );
        let expired = refreshed(
            StatusCode::BAD_REQUEST,
            &serde_json::json!({"error":"invalid_grant","error_description":"Token has been expired or revoked."}),
        )
        .unwrap_err();
        assert!(
            expired
                .to_string()
                .starts_with("refresh credential expired or revoked")
        );
        let deleted = refreshed(
            StatusCode::UNAUTHORIZED,
            &serde_json::json!({"error":"deleted_client","error_description":"The OAuth client was deleted."}),
        )
        .unwrap_err();
        assert!(
            deleted
                .to_string()
                .contains("401 Unauthorized deleted_client: The OAuth client was deleted.")
        );
        assert!(
            refreshed(StatusCode::BAD_GATEWAY, &Value::Null)
                .unwrap_err()
                .to_string()
                .contains("502 Bad Gateway unknown_error")
        );
        assert!(
            refreshed(
                StatusCode::OK,
                &serde_json::json!({"access_token":"bad token"})
            )
            .is_err()
        );
    }
    #[test]
    fn only_google_token_replies_count() {
        assert!(from_google(&serde_json::json!({"access_token":"ya29.a"})));
        assert!(from_google(&serde_json::json!({"error":"invalid_client"})));
        assert!(!from_google(&serde_json::json!({"error":{"code":404}})));
        assert!(!from_google(&Value::Null));
    }
    #[test]
    fn pkce_rfc7636_vector() {
        assert_eq!(
            challenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"),
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
    }
    #[test]
    fn callback_rejects_wrong_state_and_missing_code() {
        assert!(callback("/callback?state=other&code=secret", "expected").is_err());
        assert!(callback("/callback?state=expected", "expected").is_err());
        assert_eq!(
            callback("/callback?state=expected&code=ok", "expected").unwrap(),
            Some("ok".into())
        );
        assert!(
            callback("/callback?state=expected&error=access_denied", "expected")
                .unwrap()
                .is_none()
        );
    }
    #[test]
    fn imported_credentials_cannot_redirect_tokens() {
        let credentials = Credentials::parse(br#"{"type":"authorized_user","client_id":"test","client_secret":"test","refresh_token":"test","token_uri":"https://evil.test"}"#).unwrap();
        let value = serde_json::to_value(&credentials).unwrap();
        assert!(value.get("token_uri").is_none());
        assert_eq!(value["type"], "authorized_user");
        assert!(!credentials.is_service_account());
        assert!(credentials.with_subject(Some("user@example.com")).is_err());
        assert!(
            Credentials::parse(
                br#"{"type":"service_account","client_id":"a","refresh_token":"b"}"#
            )
            .is_err()
        );
        assert!(
            Credentials::parse(br#"{"type":"authorized_user","client_id":"a","refresh_token":""}"#)
                .is_err()
        );
        assert!(Credentials::parse(br#"{"type":"unknown"}"#).is_err());
    }
    #[test]
    fn service_account_jwt_and_impersonation() {
        let raw = serde_json::json!({
            "type": "service_account",
            "client_email": "bot@test-project.iam.gserviceaccount.com",
            "private_key": TEST_KEY,
            "token_uri": "https://evil.test/token"
        });
        let sa = Credentials::parse(raw.to_string().as_bytes())
            .unwrap()
            .with_subject(Some("alice@corp.example.com"))
            .unwrap();
        assert!(sa.is_service_account());
        assert_eq!(sa.subject(), Some("alice@corp.example.com"));
        assert!(sa.client().is_err());
        let saved = serde_json::to_value(&sa).unwrap();
        assert!(saved.get("token_uri").is_none());
        assert_eq!(saved["type"], "service_account");
        assert_eq!(saved["subject"], "alice@corp.example.com");

        let form = sa.refresh_form().unwrap();
        assert_eq!(form[0], ("grant_type", JWT_GRANT.into()));
        let jwt = &form[1].1;
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        let header: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
        assert_eq!(header, serde_json::json!({"alg": "RS256", "typ": "JWT"}));
        let claims: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["iss"], "bot@test-project.iam.gserviceaccount.com");
        assert_eq!(claims["sub"], "alice@corp.example.com");
        assert_eq!(claims["scope"], SCOPE);
        assert_eq!(claims["aud"], TOKEN_URI);
        assert_eq!(
            claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
            3600
        );

        let key = rsa_key(TEST_KEY).unwrap();
        let pub_key = ring::signature::UnparsedPublicKey::new(
            &ring::signature::RSA_PKCS1_2048_8192_SHA256,
            key.public().as_ref(),
        );
        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let signature = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        pub_key
            .verify(signing_input.as_bytes(), &signature)
            .unwrap();
    }
}
