//! mTLS agent authentication (M6 hardening): per-deployment CA, signed
//! agent client certs, rustls server config for the agent listener.
//!
//! See docs/hardening-decisions.md for the design. The CA is generated on
//! first run with a loud log line; `corpusctl ca init` prints its path.

use crate::error::{Error, Result};
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub const DEFAULT_TTL_DAYS: u32 = 30;

pub struct DeploymentCa {
    /// CA certificate PEM (agents pin this as their root).
    pub cert_pem: String,
    key_pem: String,
    /// Server certificate PEM for the agent listener (signed by the CA).
    pub server_cert_pem: String,
    server_key_pem: String,
    pub dir: PathBuf,
}

fn write_0600(path: &Path, contents: &str) -> Result<()> {
    std::fs::write(path, contents)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

fn ca_params() -> Result<rcgen::CertificateParams> {
    let mut params = rcgen::CertificateParams::new(vec!["corpus-deployment-ca".to_string()])
        .map_err(|e| Error::BadRequest(e.to_string()))?;
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.distinguished_name.push(rcgen::DnType::CommonName, "Corpus Deployment CA");
    Ok(params)
}

fn expiry(ttl_days: u32) -> time::OffsetDateTime {
    time::OffsetDateTime::now_utc() + time::Duration::days(ttl_days as i64)
}

/// Load the deployment CA from `dir`, or generate it (CA + a localhost
/// server cert) on first run.
pub fn load_or_create_ca(dir: &Path, extra_sans: &[String]) -> Result<DeploymentCa> {
    let ca_cert_path = dir.join("ca.pem");
    let ca_key_path = dir.join("ca-key.pem");
    let server_cert_path = dir.join("server.pem");
    let server_key_path = dir.join("server-key.pem");
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700));
    }

    if ca_cert_path.exists() && ca_key_path.exists() && server_cert_path.exists() && server_key_path.exists() {
        return Ok(DeploymentCa {
            cert_pem: std::fs::read_to_string(&ca_cert_path)?,
            key_pem: std::fs::read_to_string(&ca_key_path)?,
            server_cert_pem: std::fs::read_to_string(&server_cert_path)?,
            server_key_pem: std::fs::read_to_string(&server_key_path)?,
            dir: dir.to_path_buf(),
        });
    }

    tracing::warn!(
        path = %dir.display(),
        "generating NEW deployment CA for mTLS agent auth; agents enrolled before a CA rotation must re-enroll"
    );
    let ca_key = rcgen::KeyPair::generate().map_err(|e| Error::BadRequest(e.to_string()))?;
    let ca_cert = ca_params()?.self_signed(&ca_key).map_err(|e| Error::BadRequest(e.to_string()))?;

    // Server certificate for the agent listener (SANs cover local dev).
    let server_key = rcgen::KeyPair::generate().map_err(|e| Error::BadRequest(e.to_string()))?;
    let mut sans = vec!["localhost".to_string(), "127.0.0.1".to_string(), "::1".to_string()];
    sans.extend(extra_sans.iter().cloned());
    let mut params = rcgen::CertificateParams::new(sans).map_err(|e| Error::BadRequest(e.to_string()))?;
    params.distinguished_name.push(rcgen::DnType::CommonName, "corpus-server");
    params.not_after = expiry(365);
    let server_cert_pem = params
        .signed_by(&server_key, &ca_cert, &ca_key)
        .map_err(|e| Error::BadRequest(e.to_string()))?
        .pem();

    let ca_pem = ca_cert.pem();
    let ca_key_pem = ca_key.serialize_pem();
    let server_key_pem = server_key.serialize_pem();
    write_0600(&ca_cert_path, &ca_pem)?;
    write_0600(&ca_key_path, &ca_key_pem)?;
    write_0600(&server_cert_path, &server_cert_pem)?;
    write_0600(&server_key_path, &server_key_pem)?;

    Ok(DeploymentCa {
        cert_pem: ca_pem,
        key_pem: ca_key_pem,
        server_cert_pem,
        server_key_pem,
        dir: dir.to_path_buf(),
    })
}

fn load_ca_cert(ca: &DeploymentCa) -> Result<rcgen::Certificate> {
    let key = rcgen::KeyPair::from_pem(&ca.key_pem).map_err(|e| Error::BadRequest(e.to_string()))?;
    let params = rcgen::CertificateParams::from_ca_cert_pem(&ca.cert_pem)
        .map_err(|e| Error::BadRequest(format!("reload CA cert: {e}")))?;
    params.self_signed(&key).map_err(|e| Error::BadRequest(e.to_string()))
}

/// Issue a short-lived client certificate for an enrolled agent.
/// Returns (cert_pem, key_pem). CN = agent UUID.
pub fn sign_client_cert(ca: &DeploymentCa, agent_id: Uuid, ttl_days: u32) -> Result<(String, String)> {
    let ca_cert = load_ca_cert(ca)?;
    let ca_key = rcgen::KeyPair::from_pem(&ca.key_pem).map_err(|e| Error::BadRequest(e.to_string()))?;
    let agent_key = rcgen::KeyPair::generate().map_err(|e| Error::BadRequest(e.to_string()))?;
    let mut params = rcgen::CertificateParams::new(vec![agent_id.to_string()]).map_err(|e| Error::BadRequest(e.to_string()))?;
    params.distinguished_name.push(rcgen::DnType::CommonName, agent_id.to_string());
    params.not_after = expiry(ttl_days);
    let pem = params
        .signed_by(&agent_key, &ca_cert, &ca_key)
        .map_err(|e| Error::BadRequest(e.to_string()))?
        .pem();
    Ok((pem, agent_key.serialize_pem()))
}

fn pem_der(pem: &str) -> Result<Vec<u8>> {
    let mut reader = std::io::BufReader::new(pem.as_bytes());
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| Error::BadRequest(format!("pem: {e}")))?;
    let first = certs.into_iter().next().ok_or_else(|| Error::BadRequest("empty pem".into()))?;
    Ok(first.to_vec())
}

fn pem_key_der(pem: &str) -> Result<rustls::pki_types::PrivatePkcs8KeyDer<'static>> {
    let mut reader = std::io::BufReader::new(pem.as_bytes());
    let keys: Vec<_> = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .collect::<std::result::Result<_, _>>()
        .map_err(|e| Error::BadRequest(format!("key pem: {e}")))?;
    keys.into_iter().next().ok_or_else(|| Error::BadRequest("no pkcs8 key in pem".into()))
}

fn cert_chain(cert_pem: &str, ca_pem: &str) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    Ok(vec![
        rustls::pki_types::CertificateDer::from(pem_der(cert_pem)?),
        rustls::pki_types::CertificateDer::from(pem_der(ca_pem)?),
    ])
}

fn ca_roots(ca_pem: &str) -> Result<rustls::RootCertStore> {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(pem_der(ca_pem)?))
        .map_err(|e| Error::BadRequest(format!("CA root: {e}")))?;
    Ok(roots)
}

/// Both aws-lc-rs and ring end up in the dependency tree (reqwest pulls
/// the other); pick ring explicitly. install_default is idempotent for
/// our purposes — a second install just returns Err, which we ignore.
pub fn install_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

/// rustls ServerConfig for the agent listener: requires a client cert
/// signed by the deployment CA.
pub fn server_config(ca: &DeploymentCa) -> Result<rustls::ServerConfig> {
    install_provider();
    let verifier = rustls::server::WebPkiClientVerifier::builder(std::sync::Arc::new(ca_roots(&ca.cert_pem)?))
        .build()
        .map_err(|e| Error::BadRequest(format!("client verifier: {e}")))?;
    let chain = cert_chain(&ca.server_cert_pem, &ca.cert_pem)?;
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(pem_key_der(&ca.server_key_pem)?);
    let config = rustls::ServerConfig::builder()
        .with_client_cert_verifier(verifier)
        .with_single_cert(chain, key)
        .map_err(|e| Error::BadRequest(format!("server cert: {e}")))?;
    Ok(config)
}

/// rustls ClientConfig for tests and the agent: pinned CA root + identity.
pub fn client_config(ca_pem: &str, cert_pem: &str, key_pem: &str) -> Result<rustls::ClientConfig> {
    install_provider();
    let chain = vec![rustls::pki_types::CertificateDer::from(pem_der(cert_pem)?)];
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(pem_key_der(key_pem)?);
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(ca_roots(ca_pem)?)
        .with_client_auth_cert(chain, key)
        .map_err(|e| Error::BadRequest(format!("client config: {e}")))?;
    Ok(config)
}

/// Extract the agent UUID from a peer certificate's CN.
pub fn agent_id_from_cert_der(der: &[u8]) -> Result<Uuid> {
    let (_, cert) = x509_parser::parse_x509_certificate(der)
        .map_err(|e| Error::Unauthorized(format!("peer cert parse: {e}")))?;
    for rdn in cert.subject().iter_common_name() {
        if let Ok(cn) = rdn.as_str() {
            if let Ok(id) = Uuid::parse_str(cn) {
                return Ok(id);
            }
        }
    }
    Err(Error::Unauthorized("peer cert has no agent UUID CN".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn one_handshake(
        server_cfg: &rustls::ServerConfig,
        client_cfg: &rustls::ClientConfig,
    ) -> (bool, bool) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(server_cfg.clone()));
        let accept = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            acceptor.accept(stream).await
        });
        let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(client_cfg.clone()));
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let client = connector
            .connect(rustls::pki_types::ServerName::try_from("localhost").unwrap(), stream)
            .await;
        let server = accept.await.unwrap();
        (client.is_ok(), server.is_ok())
    }

    #[tokio::test]
    async fn handshake_accepts_ca_signed_cert_rejects_others() {
        let dir = tempfile::tempdir().unwrap();
        let ca = load_or_create_ca(dir.path(), &[]).unwrap();
        let server_cfg = server_config(&ca).unwrap();
        let agent = Uuid::new_v4();
        let (good_pem, good_key) = sign_client_cert(&ca, agent, 1).unwrap();

        // Valid CA-signed client cert connects; CN resolves to the agent id.
        let good_cfg = client_config(&ca.cert_pem, &good_pem, &good_key).unwrap();
        let (c_ok, s_ok) = one_handshake(&server_cfg, &good_cfg).await;
        assert!(c_ok && s_ok, "valid CA-signed client cert must connect");

        // Wrong CA's cert is rejected.
        let wrong_ca = load_or_create_ca(tempfile::tempdir().unwrap().path(), &[]).unwrap();
        let (bad_pem, bad_key) = sign_client_cert(&wrong_ca, Uuid::new_v4(), 1).unwrap();
        let bad_cfg = client_config(&ca.cert_pem, &bad_pem, &bad_key).unwrap();
        let (c_ok, s_ok) = one_handshake(&server_cfg, &bad_cfg).await;
        assert!(!c_ok || !s_ok, "wrong-CA cert must be rejected");

        // No client cert at all is rejected.
        let anon_cfg = rustls::ClientConfig::builder()
            .with_root_certificates(ca_roots(&ca.cert_pem).unwrap())
            .with_no_client_auth();
        let (c_ok, s_ok) = one_handshake(&server_cfg, &anon_cfg).await;
        assert!(!c_ok || !s_ok, "certless client must be rejected");

        // CN extraction.
        let der = pem_der(&good_pem).unwrap();
        assert_eq!(agent_id_from_cert_der(&der).unwrap(), agent);
    }
}
