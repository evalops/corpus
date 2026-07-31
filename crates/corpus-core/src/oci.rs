//! OCI image ingestion (M4 vault bootstrap): registry HTTP API client
//! (no docker dependency), layer tar.gz walking, and `docker save`
//! offline import.

use crate::error::{Error, Result};
use std::io::Read;

// ---------------- image reference parsing ----------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageRef {
    pub registry: String,
    pub repository: String,
    /// Tag or digest (digest starts with "sha256:").
    pub reference: String,
}

/// Parse `alpine:3.20`, `library/alpine`, `ghcr.io/org/img:1.0`,
/// `repo@sha256:...` into registry/repository/reference.
pub fn parse_image_ref(s: &str) -> Result<ImageRef> {
    let (name_part, reference) = if let Some((n, d)) = s.split_once('@') {
        (n.to_string(), d.to_string())
    } else if let Some((n, t)) = s.rsplit_once(':') {
        if t.contains('/') {
            (s.to_string(), "latest".to_string())
        } else {
            (n.to_string(), t.to_string())
        }
    } else {
        (s.to_string(), "latest".to_string())
    };
    let mut parts = name_part.splitn(2, '/');
    let first = parts.next().unwrap_or_default();
    let rest = parts.next();
    if first.is_empty() {
        return Err(Error::BadRequest(format!("invalid image ref {s:?}")));
    }
    let (registry, repository) = match rest {
        Some(r) if first.contains('.') || first.contains(':') || first == "localhost" => {
            (first.to_string(), r.to_string())
        }
        Some(r) => ("registry-1.docker.io".to_string(), format!("{first}/{r}")),
        None => ("registry-1.docker.io".to_string(), format!("library/{first}")),
    };
    if repository.is_empty() || reference.is_empty() {
        return Err(Error::BadRequest(format!("invalid image ref {s:?}")));
    }
    Ok(ImageRef { registry, repository, reference })
}

// ---------------- registry client ----------------

const MANIFEST_ACCEPT: &str = "application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.v2+json, application/vnd.docker.distribution.manifest.list.v2+json";

/// Local registries (localhost / loopback / test mocks) speak plain HTTP.
fn registry_scheme(registry: &str) -> &'static str {
    if registry.starts_with("localhost") || registry.starts_with("127.") || registry.starts_with("[::1]") {
        "http"
    } else {
        "https"
    }
}

pub struct RegistryClient {
    http: reqwest::Client,
    registry: String,
    token: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ResolvedManifest {
    /// Digest of the manifest this config/layer list came from.
    pub image_digest: String,
    pub config_digest: String,
    pub layers: Vec<String>,
    /// `created` timestamp from the config blob, when present.
    pub created: Option<chrono::DateTime<chrono::Utc>>,
}

impl RegistryClient {
    /// Anonymous token flow (Docker Hub, ghcr public repos). Optional
    /// basic-auth credentials for private repos.
    pub async fn connect(iref: &ImageRef, creds: Option<(String, String)>) -> Result<RegistryClient> {
        let http = reqwest::Client::new();
        let realm = if iref.registry == "registry-1.docker.io" {
            "https://auth.docker.io/token".to_string()
        } else {
            format!("{}://{}/token", registry_scheme(&iref.registry), iref.registry)
        };
        let scope = format!("repository:{}:pull", iref.repository);
        let mut req = http.get(&realm).query(&[("scope", scope.as_str())]);
        if iref.registry == "registry-1.docker.io" {
            req = req.query(&[("service", "registry.docker.io")]);
        }
        if let Some((u, p)) = &creds {
            req = req.basic_auth(u, Some(p));
        }
        let token = match req.send().await {
            Ok(resp) if resp.status().is_success() => {
                let body: serde_json::Value = resp.json().await.map_err(|e| Error::BadRequest(e.to_string()))?;
                body.get("token")
                    .or_else(|| body.get("access_token"))
                    .and_then(|t| t.as_str())
                    .map(|s| s.to_string())
            }
            // Registry without a token endpoint (anonymous pulls allowed).
            _ => None,
        };
        Ok(RegistryClient { http, registry: iref.registry.clone(), token })
    }

    fn auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.token {
            Some(t) => req.bearer_auth(t),
            None => req,
        }
    }

    async fn get_manifest(&self, repo: &str, reference: &str) -> Result<(String, serde_json::Value)> {
        let scheme = registry_scheme(&self.registry);
        let url = format!("{scheme}://{}/v2/{}/manifests/{}", self.registry, repo, reference);
        let resp = self
            .auth(self.http.get(&url))
            .header("Accept", MANIFEST_ACCEPT)
            .send()
            .await
            .map_err(|e| Error::BadRequest(format!("manifest fetch: {e}")))?;
        if !resp.status().is_success() {
            return Err(Error::BadRequest(format!("manifest {repo}:{reference} -> {}", resp.status())));
        }
        let digest = resp
            .headers()
            .get("docker-content-digest")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        let body: serde_json::Value = resp.json().await.map_err(|e| Error::BadRequest(e.to_string()))?;
        Ok((digest, body))
    }

    async fn blob(&self, repo: &str, digest: &str) -> Result<Vec<u8>> {
        let scheme = registry_scheme(&self.registry);
        let url = format!("{scheme}://{}/v2/{}/blobs/{}", self.registry, repo, digest);
        let resp = self
            .auth(self.http.get(&url))
            .send()
            .await
            .map_err(|e| Error::BadRequest(format!("blob fetch: {e}")))?;
        if !resp.status().is_success() {
            return Err(Error::BadRequest(format!("blob {digest} -> {}", resp.status())));
        }
        Ok(resp.bytes().await.map_err(|e| Error::BadRequest(e.to_string()))?.to_vec())
    }

    /// Resolve tag-or-digest to a flat manifest (following an index if
    /// needed) and return config digest + ordered layer digests.
    pub async fn resolve(&self, iref: &ImageRef) -> Result<ResolvedManifest> {
        let (mut image_digest, mut manifest) = self.get_manifest(&iref.repository, &iref.reference).await?;
        let media = manifest
            .get("mediaType")
            .and_then(|m| m.as_str())
            .unwrap_or("")
            .to_string();
        if media.contains("image.index") || media.contains("manifest.list") {
            let chosen = select_platform_manifest(&manifest)?;
            let digest = chosen
                .get("digest")
                .and_then(|d| d.as_str())
                .ok_or_else(|| Error::BadRequest("manifest list entry without digest".into()))?
                .to_string();
            (image_digest, manifest) = (digest.clone(), self.get_manifest(&iref.repository, &digest).await?.1);
        }
        let config_digest = manifest
            .get("config")
            .and_then(|c| c.get("digest"))
            .and_then(|d| d.as_str())
            .ok_or_else(|| Error::BadRequest("manifest without config digest".into()))?
            .to_string();
        let layers = manifest
            .get("layers")
            .and_then(|l| l.as_array())
            .map(|ls| {
                ls.iter()
                    .filter_map(|l| l.get("digest").and_then(|d| d.as_str()).map(|s| s.to_string()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if layers.is_empty() {
            return Err(Error::BadRequest("manifest without layers".into()));
        }
        let config = self.blob(&iref.repository, &config_digest).await?;
        let created = serde_json::from_slice::<serde_json::Value>(&config)
            .ok()
            .and_then(|c| c.get("created").and_then(|t| t.as_str()).map(|s| s.to_string()))
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(&s).ok())
            .map(|t| t.with_timezone(&chrono::Utc));
        Ok(ResolvedManifest { image_digest, config_digest, layers, created })
    }

    pub async fn layer_bytes(&self, iref: &ImageRef, digest: &str) -> Result<Vec<u8>> {
        self.blob(&iref.repository, digest).await
    }
}

fn select_platform_manifest(index: &serde_json::Value) -> Result<serde_json::Value> {
    let manifests = index
        .get("manifests")
        .and_then(|m| m.as_array())
        .ok_or_else(|| Error::BadRequest("image index without manifests".into()))?;
    for m in manifests {
        let os = m.pointer("/platform/os").and_then(|v| v.as_str());
        let arch = m.pointer("/platform/architecture").and_then(|v| v.as_str());
        if os == Some("linux") && arch == Some("amd64") {
            return Ok(m.clone());
        }
    }
    manifests
        .first()
        .cloned()
        .ok_or_else(|| Error::BadRequest("image index is empty".into()))
}

// ---------------- layer walking ----------------

pub struct LayerEntry {
    pub path: String,
    pub size: u64,
    /// None when the file exceeds the size limit (TOO_LARGE gap).
    pub bytes: Option<Vec<u8>>,
}

/// Walk a (possibly gzipped) layer tar, returning regular files. Files
/// above `max_file_bytes` come back with `bytes: None`.
pub fn walk_layer(tar_bytes: &[u8], gzipped: bool, max_file_bytes: u64) -> Result<Vec<LayerEntry>> {
    let reader: Box<dyn Read> = if gzipped {
        Box::new(flate2::read::GzDecoder::new(tar_bytes))
    } else {
        Box::new(tar_bytes)
    };
    let mut archive = tar::Archive::new(reader);
    let mut out = Vec::new();
    let entries = archive.entries().map_err(|e| Error::BadRequest(format!("layer tar: {e}")))?;
    for entry in entries {
        let mut entry = entry.map_err(|e| Error::BadRequest(format!("layer tar entry: {e}")))?;
        let header = entry.header();
        if !header.entry_type().is_file() {
            continue;
        }
        let path = entry
            .path()
            .map_err(|e| Error::BadRequest(e.to_string()))?
            .to_string_lossy()
            .to_string();
        let size = header.size().unwrap_or(0);
        if size > max_file_bytes {
            out.push(LayerEntry { path, size, bytes: None });
            continue;
        }
        let mut buf = Vec::with_capacity(size as usize);
        entry.read_to_end(&mut buf).map_err(|e| Error::BadRequest(e.to_string()))?;
        out.push(LayerEntry { path, size, bytes: Some(buf) });
    }
    Ok(out)
}

/// `docker save` output: top-level tar with manifest.json and one tar per
/// layer. Returns (tags, ordered layer tar bytes).
pub fn walk_docker_save(save_tar: &[u8]) -> Result<(Vec<String>, Vec<Vec<u8>>)> {
    let mut archive = tar::Archive::new(save_tar);
    let mut manifest: Option<serde_json::Value> = None;
    let mut layer_tars: std::collections::HashMap<String, Vec<u8>> = std::collections::HashMap::new();
    for entry in archive.entries().map_err(|e| Error::BadRequest(e.to_string()))? {
        let mut entry = entry.map_err(|e| Error::BadRequest(e.to_string()))?;
        let path = entry.path().map_err(|e| Error::BadRequest(e.to_string()))?.to_string_lossy().to_string();
        if path == "manifest.json" {
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf).map_err(|e| Error::BadRequest(e.to_string()))?;
            manifest = Some(serde_json::from_slice(&buf).map_err(|e| Error::BadRequest(e.to_string()))?);
        } else if path.ends_with(".tar") {
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf).map_err(|e| Error::BadRequest(e.to_string()))?;
            layer_tars.insert(path, buf);
        }
    }
    let manifest = manifest.ok_or_else(|| Error::BadRequest("docker save tar without manifest.json".into()))?;
    let first = manifest
        .as_array()
        .and_then(|a| a.first())
        .ok_or_else(|| Error::BadRequest("empty docker save manifest".into()))?;
    let tags: Vec<String> = first
        .get("RepoTags")
        .and_then(|t| t.as_array())
        .map(|ts| ts.iter().filter_map(|t| t.as_str().map(|s| s.to_string())).collect())
        .unwrap_or_default();
    let mut layers = Vec::new();
    if let Some(list) = first.get("Layers").and_then(|l| l.as_array()) {
        for l in list {
            if let Some(name) = l.as_str() {
                if let Some(bytes) = layer_tars.remove(name) {
                    layers.push(bytes);
                }
            }
        }
    }
    Ok((tags, layers))
}

// ---------------- provenance ----------------

pub fn file_provenance(image_ref: &str, image_digest: &str, layer_digest: &str, path: &str) -> serde_json::Value {
    serde_json::json!({
        "source": "oci",
        "image_ref": image_ref,
        "image_digest": image_digest,
        "layer_digest": layer_digest,
        "path": path,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_image_refs() {
        let r = parse_image_ref("alpine:3.20").unwrap();
        assert_eq!((r.registry.as_str(), r.repository.as_str(), r.reference.as_str()), ("registry-1.docker.io", "library/alpine", "3.20"));
        let r = parse_image_ref("ghcr.io/org/img:1.0").unwrap();
        assert_eq!((r.registry.as_str(), r.repository.as_str(), r.reference.as_str()), ("ghcr.io", "org/img", "1.0"));
        let r = parse_image_ref("ubuntu").unwrap();
        assert_eq!((r.registry.as_str(), r.repository.as_str(), r.reference.as_str()), ("registry-1.docker.io", "library/ubuntu", "latest"));
        let r = parse_image_ref("localhost:5000/img:dev").unwrap();
        assert_eq!(r.registry, "localhost:5000");
        assert_eq!(r.reference, "dev");
        assert!(parse_image_ref("").is_err());
    }

    fn build_tar(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (path, bytes) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(bytes.len() as u64);
            header.set_entry_type(tar::EntryType::Regular);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append_data(&mut header, path, *bytes).unwrap();
        }
        builder.into_inner().unwrap()
    }

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        use flate2::write::GzEncoder;
        let mut enc = GzEncoder::new(Vec::new(), flate2::Compression::fast());
        std::io::Write::write_all(&mut enc, bytes).unwrap();
        enc.finish().unwrap()
    }

    #[test]
    fn walks_layer_tar_gz() {
        let tar = build_tar(&[("bin/busybox", b"\x7fELF\x02fake-elf"), ("etc/motd", b"hello")]);
        let entries = walk_layer(&gzip(&tar), true, 1 << 20).unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].path, "bin/busybox");
        assert_eq!(entries[0].bytes.as_deref().unwrap()[..4], [0x7f, b'E', b'L', b'F']);
    }

    #[test]
    fn oversized_files_become_none() {
        let big = vec![0u8; 3000];
        let tar = build_tar(&[("big.bin", &big), ("small.bin", b"tiny")]);
        let entries = walk_layer(&tar, false, 1024).unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries[0].bytes.is_none(), "big file must be TOO_LARGE-marked");
        assert_eq!(entries[1].bytes.as_deref(), Some(b"tiny".as_ref()));
    }

    #[test]
    fn walks_docker_save_tar() {
        let layer = build_tar(&[("bin/app", b"\x7fELF\x02app")]);
        let manifest = serde_json::json!([{
            "RepoTags": ["demo:latest"],
            "Layers": ["l1/layer.tar"]
        }]);
        let save = build_tar(&[
            ("manifest.json", manifest.to_string().as_bytes()),
            ("l1/layer.tar", &layer),
        ]);
        let (tags, layers) = walk_docker_save(&save).unwrap();
        assert_eq!(tags, vec!["demo:latest"]);
        assert_eq!(layers.len(), 1);
        let entries = walk_layer(&layers[0], false, 1 << 20).unwrap();
        assert_eq!(entries[0].path, "bin/app");
    }
}
