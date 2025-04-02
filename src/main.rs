use axum::{extract::Path, routing::get, Router, Json};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum_server::tls_rustls::RustlsConfig;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::{collections::HashMap, fs, net::SocketAddr, path::Path as StdPath};
use serde::Serialize;
use std::sync::{Arc, RwLock};

#[derive(Serialize, Clone)]
struct KeyPairInfo {
    name: String,
    ca: Option<String>,
    cert_path: String,
    key_path: String,
}

type KeyStore = Arc<RwLock<HashMap<String, KeyPairInfo>>>;

fn load_keypairs(cert_dir: &str) -> HashMap<String, KeyPairInfo> {
    let mut map = HashMap::new();
    fn recurse(path: &StdPath, parent_name: Option<String>, map: &mut HashMap<String, KeyPairInfo>) {
        if let Ok(entries) = fs::read_dir(path) {
            let folder_name = path.file_name().map(|s| s.to_string_lossy().to_string());
            let mut ca_present = false;
            let mut ca_cert = None;
            let mut ca_key = None;

            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    recurse(&path, path.file_name().map(|s| s.to_string_lossy().to_string()), map);
                } else if let Some(stem) = path.file_stem() {
                    let stem_str = stem.to_string_lossy();
                    let ext = path.extension().map(|e| e.to_string_lossy()).unwrap_or_default();

                    if stem_str == "ca" && ext == "cert" {
                        ca_cert = Some(path.clone());
                    } else if stem_str == "ca" && ext == "key" {
                        ca_key = Some(path.clone());
                    }
                }
            }

            if ca_cert.is_some() && ca_key.is_some() {
                ca_present = true;
            }

            for entry in fs::read_dir(path).unwrap_or_else(|_| fs::read_dir(".").unwrap()) {
                if let Ok(entry) = entry {
                    let path = entry.path();
                    if path.is_file() {
                        let stem = path.file_stem().map(|s| s.to_string_lossy()).unwrap_or_default();
                        let ext = path.extension().map(|e| e.to_string_lossy()).unwrap_or_default();
                        if ext == "cert" && stem != "ca" {
                            let key_path = path.with_extension("key");
                            if key_path.exists() {
                                map.insert(stem.to_string(), KeyPairInfo {
                                    name: stem.to_string(),
                                    ca: if ca_present { folder_name.clone() } else { parent_name.clone() },
                                    cert_path: path.to_string_lossy().to_string(),
                                    key_path: key_path.to_string_lossy().to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }
    }
    recurse(StdPath::new(cert_dir), None, &mut map);
    map
}

async fn list_keys(store: KeyStore) -> Json<Vec<KeyPairInfo>> {
    let store = store.read().unwrap();
    Json(store.values().cloned().collect())
}

async fn download_cert(Path(name): Path<String>, store: KeyStore) -> Response {
    if let Some(info) = store.read().unwrap().get(&name) {
        if let Ok(bytes) = fs::read(&info.cert_path) {
            return (
                [(header::CONTENT_TYPE, "application/x-pem-file"),
                 (header::CONTENT_DISPOSITION, &format!("attachment; filename=\"{}.cert\"", name))],
                bytes
            ).into_response();
        }
    }
    StatusCode::NOT_FOUND.into_response()
}

async fn download_key(Path(name): Path<String>, store: KeyStore) -> Response {
    if let Some(info) = store.read().unwrap().get(&name) {
        if let Ok(bytes) = fs::read(&info.key_path) {
            return (
                [(header::CONTENT_TYPE, "application/x-pem-file"),
                 (header::CONTENT_DISPOSITION, &format!("attachment; filename=\"{}.key\"", name))],
                bytes
            ).into_response();
        }
    }
    StatusCode::NOT_FOUND.into_response()
}

#[tokio::main]
async fn main() {
    let cert_dir = "./certs";
    let store = Arc::new(RwLock::new(load_keypairs(cert_dir)));

    let router = Router::new()
        .route("/list", get({
            let store = store.clone();
            move || list_keys(store)
        }))
        .route("/{name}/cert", get({
            let store = store.clone();
            move |path| download_cert(path, store)
        }))
        .route("/{name}/key", get({
            let store = store.clone();
            move |path| download_key(path, store)
        }));

    let certs = vec![CertificateDer::from_pem_file("certs/server.cert").expect("Couldn't find server TLS cert")];
    let key = PrivateKeyDer::from_pem_file("certs/server.key").expect("Couldn't find server TLS key");

    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key).unwrap();

    let tls_cfg = RustlsConfig::from_config(Arc::new(tls_config));

    let addr: SocketAddr = "127.0.0.1:6969".parse().unwrap();
    println!("Tumbler running on https://{}", addr);

    axum_server::bind_rustls(addr, tls_cfg).serve(router.into_make_service()).await.unwrap();
}

