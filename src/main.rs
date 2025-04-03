use axum::{extract::{Path, Query}, routing::get, Router, Json};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum_server::tls_rustls::RustlsConfig;
use ca::{create_and_save_ca, create_and_save_key, load_ca_from_path};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};
use std::{collections::HashMap, fs, net::SocketAddr, path::{Path as StdPath, PathBuf}};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use std::fs::create_dir_all;
use tower_http::cors::{CorsLayer, Any};


mod ca;

#[derive(Serialize, Debug, Clone)]
struct KeyPairInfo {
    name: String,
    ca: Option<String>,
    cert_path: String,
    key_path: String,
}

#[derive(Deserialize)]
struct GenerateParams {
    name: String,
    domain: String,
    folder: Option<String>,
    client: Option<bool>,
}

type KeyStore = Arc<RwLock<HashMap<String, KeyPairInfo>>>;

pub async fn load_keypairs(cert_dir: &str) -> HashMap<String, KeyPairInfo> {
    use tokio::fs;
    let mut map = HashMap::new();

    // Define a recursive closure using a pinned box
    async fn recurse<'a>(
        path: PathBuf,
        parent_name: Option<String>,
        map: &'a mut HashMap<String, KeyPairInfo>,
    ) {
        let folder_name = path.file_name().map(|s| s.to_string_lossy().to_string());
        let mut ca_cert: Option<PathBuf> = None;
        let mut ca_key: Option<PathBuf> = None;

        if let Ok(mut entries) = fs::read_dir(&path).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                let entry_path = entry.path();
                if entry_path.is_dir() {
                    let map_ref = map as *mut _;
                    let parent = entry_path.file_name().map(|s| s.to_string_lossy().to_string());
                    // SAFETY: This is safe because the future does not outlive the function call
                    let fut = recurse(entry_path.clone(), parent, unsafe { &mut *map_ref });
                    Box::pin(fut).await;
                } else if let Some(stem) = entry_path.file_stem() {
                    let stem_str = stem.to_string_lossy();
                    let ext = entry_path.extension().map(|e| e.to_string_lossy()).unwrap_or_default();

                    if stem_str == "ca" && ext == "cert" {
                        ca_cert = Some(entry_path.clone());
                    } else if stem_str == "ca" && ext == "key" {
                        ca_key = Some(entry_path.clone());
                    }
                }
            }
        }

        let ca_present = ca_cert.is_some() && ca_key.is_some();

        if let Ok(mut entries) = fs::read_dir(&path).await {
            while let Ok(Some(entry)) = entries.next_entry().await {
                let entry_path = entry.path();
                if entry_path.is_file() {

                    if entry_path.extension().map(|o| o.to_str()).flatten() == Some("cert") {
                        let stem = entry_path.file_stem().map(|s| s.to_string_lossy()).unwrap_or_default();
                        let key_path = entry_path.with_extension("key");
                        if fs::try_exists(&key_path).await.unwrap_or(false) {
                            let mut chunks = path.iter().skip(2).filter_map(|s| s.to_str()).collect::<Vec<_>>();
                            chunks.push(&stem);
                            let name = chunks.join("-");

                            map.insert(name.clone(), KeyPairInfo {
                                name,
                                ca: if ca_present { folder_name.clone() } else { parent_name.clone() },
                                cert_path: entry_path.to_string_lossy().to_string(),
                                key_path: key_path.to_string_lossy().to_string(),
                            });
                        }
                    }
                }
            }
        }
    }

    recurse(PathBuf::from(cert_dir), None, &mut map).await;
    map
}

async fn list_keys(store: KeyStore) -> Json<Vec<KeyPairInfo>> {
    let store = store.read().await;
    Json(store.values().cloned().collect())
}

async fn download_cert(Path(name): Path<String>, store: KeyStore) -> Response {
    if let Some(info) = store.read().await.get(&name) {
        if let Ok(bytes) = fs::read(&info.cert_path) {
            println!("{:?}", info);
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
    if let Some(info) = store.read().await.get(&name) {
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


async fn generate_keypair(Query(params): Query<GenerateParams>, store: KeyStore) -> Response {
    println!("Generating cert/key {} - Client: {} Domain: {} Folder: {:?}", params.name, params.client.unwrap_or_default(), params.domain, params.folder);

    let base = "./certs";
    let folder = params.folder.unwrap_or_else(|| "".into());
    let path = if folder.is_empty() {
        StdPath::new(base).to_path_buf()
    } else {
        let p = StdPath::new(base).join(&folder);
        let _ = create_dir_all(&p);
        p
    };

    let ca = if let Some(ca) = load_ca_from_path(&path).await {
        ca
    }
    else {
        match create_and_save_ca(&path).await {
            Ok(ca) => ca,
            Err(why) => {
                return Response::builder().status(StatusCode::INTERNAL_SERVER_ERROR).body(format!("Failed to create key: {}", why).into()).unwrap()
            }
        }
    };

    if let Err(why) = create_and_save_key(path, &params.name, &params.domain, params.client.unwrap_or_default(), &ca).await {
        return Response::builder().status(StatusCode::INTERNAL_SERVER_ERROR).body(format!("Failed to create key: {}", why).into()).unwrap()
    }

    let mut store = store.write().await;
    *store = load_keypairs(base).await;

    Response::builder().status(StatusCode::CREATED).body("Created".into()).unwrap()
}

async fn try_load_server_ssl_or_create<'a>() -> (Vec<CertificateDer<'a>>, PrivateKeyDer<'a>){
    let cert = CertificateDer::from_pem_file("certs/server.cert");
    let key = PrivateKeyDer::from_pem_file("certs/server.key");

    let ca_path = std::path::Path::new("./certs");

    if let (Ok(cert), Ok(key)) = (cert, key) {
        return (vec![cert], key);
    }
    else {
        let ca = if let Some(ca) = load_ca_from_path(ca_path).await {
            ca
        }
        else {
            create_and_save_ca(ca_path).await.expect("Failed to create and save new CA")
        };

        create_and_save_key(ca_path, "server", "localhost", false, &ca).await.expect("Failed to save server.key and server.cert");

        let cert = CertificateDer::from_pem_file("certs/server.cert").expect("Just created this cert");
        let key = PrivateKeyDer::from_pem_file("certs/server.key").expect("Just created this key");

        (vec![cert], key)
    }

}

#[tokio::main]
async fn main() {
    let cert_dir = "./certs";
    let store = Arc::new(RwLock::new(load_keypairs(cert_dir).await));

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
    }))
    .route("/generate", get({
        let store = store.clone();
        move |path| generate_keypair(path, store)
    }))
    .layer(
        CorsLayer::new()
        .allow_origin(Any) // or use `allow_origin([ORIGIN.parse().unwrap()])`
        .allow_methods(Any)
        .allow_headers(Any),
    );


    let (certs, key) = try_load_server_ssl_or_create().await;

    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key).unwrap();

    let tls_cfg = RustlsConfig::from_config(Arc::new(tls_config));

    let addr: SocketAddr = "127.0.0.1:6969".parse().unwrap();
    println!("Tumbler running on https://{}", addr);

    axum_server::bind_rustls(addr, tls_cfg).serve(router.into_make_service()).await.unwrap();
}

