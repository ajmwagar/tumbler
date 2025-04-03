use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, DnValue::PrintableString,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose,
};
use time::{Duration, OffsetDateTime};
use std::path::Path;

use tokio::fs;
use tokio::io::{self, AsyncWriteExt};

pub async fn load_ca_from_path(path: &Path) -> Option<(Certificate, KeyPair)> {
    let key_path = path.join("ca.key");
    let cert_path = path.join("ca.cert");

    let key_bytes = fs::read(&key_path).await.ok()?;
    let cert_string = fs::read_to_string(&cert_path).await.ok()?;

    let key_pair = KeyPair::from_pem(std::str::from_utf8(&key_bytes).ok()?).ok()?;

    let params = CertificateParams::from_ca_cert_pem(&cert_string).ok()?;

    let cert = params.self_signed(&key_pair).ok()?;

    Some((cert, key_pair))

}

pub async fn create_and_save_key<P: AsRef<Path>>(path: P, name: &str, domain: &str, client: bool, ca: &(Certificate, KeyPair)) -> io::Result<(Certificate, KeyPair)> {

    let (cert, key_pair) = new_end_entity(domain, &ca.0, &ca.1, client);

    save_key_at_path(path, name, &key_pair, &cert).await?;

    Ok((cert, key_pair))
}

pub async fn create_and_save_ca<P: AsRef<Path>>(path: P) -> io::Result<(Certificate, KeyPair)> {
    let (cert, key_pair) = new_ca();

    save_key_at_path(path, "ca", &key_pair, &cert).await?;

    Ok((cert, key_pair))
}

async fn save_key_at_path<P: AsRef<Path>>(path: P, name: &str, key_pair: &KeyPair, cert: &Certificate) -> io::Result<()> {
    let key_pem = key_pair.serialize_pem();
    let cert_pem = cert.pem();

    let key_path = path.as_ref().join(format!("{}.key", name));
    let cert_path = path.as_ref().join(format!("{}.cert", name));

    fs::create_dir_all(path.as_ref()).await?;

    let mut key_file = fs::File::create(&key_path).await?;
    key_file.write_all(key_pem.as_bytes()).await?;
    key_file.flush().await?;

    let mut cert_file = fs::File::create(&cert_path).await?;
    cert_file.write_all(cert_pem.as_bytes()).await?;
    cert_file.flush().await?;

    Ok(())
}


pub fn new_ca() -> (Certificate, KeyPair) {
    let mut params =
        CertificateParams::new(Vec::default()).expect("empty subject alt name can't produce error");
    let (yesterday, tomorrow) = validity_period();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.distinguished_name.push(
        DnType::CountryName,
        PrintableString("US".try_into().unwrap()),
    );
    params.distinguished_name.push(
        DnType::CommonName,
        PrintableString("Tumbler Generated Cert".try_into().unwrap()),
    );
    params
        .distinguished_name
        .push(DnType::OrganizationName, "Tumbler");

    params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    params.key_usages.push(KeyUsagePurpose::CrlSign);

    params.not_before = yesterday;
    params.not_after = tomorrow;

    let key_pair = KeyPair::generate().unwrap();
    (params.self_signed(&key_pair).unwrap(), key_pair)
}

pub fn new_end_entity(domain: &str, ca: &Certificate, ca_key: &KeyPair, client: bool) -> (Certificate, KeyPair) {
    println!("End Entity - {}", domain);
    let mut params = CertificateParams::new(vec![domain.into()]).expect("we know the name is valid");
    let (yesterday, tomorrow) = validity_period();

    params.is_ca = IsCa::ExplicitNoCa;
    params.distinguished_name.push(DnType::CommonName, domain);
    params.use_authority_key_identifier_extension = true;
    // params.key_usages.push(KeyUsagePurpose::DigitalSignature);

    if client {
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ClientAuth);
    }
    else {
        params
            .extended_key_usages
            .push(ExtendedKeyUsagePurpose::ServerAuth);
    }

    params.not_before = yesterday;
    params.not_after = tomorrow;

    let key_pair = KeyPair::generate().unwrap();
    let cert = params.signed_by(&key_pair, ca, ca_key).unwrap();

    (cert, key_pair)
}

fn validity_period() -> (OffsetDateTime, OffsetDateTime) {
    let days = Duration::new(86400, 0) * 10;
    let yesterday = OffsetDateTime::now_utc().checked_sub(days).unwrap();
    let tomorrow = OffsetDateTime::now_utc().checked_add(days).unwrap();
    (yesterday, tomorrow)
}

