use crate::error::Result;

#[derive(Debug)]
pub struct PrivateKey {
    pub der_data: Vec<u8>,
    pub pkcs8_pem: String,
}

#[derive(Debug)]
pub struct Certificate {
    pub cert_chain: Vec<Certificate>,
    pub x509_der_data: Vec<u8>,
    pub pem: String,
    pub private_key: Option<PrivateKey>,
}

pub trait KeyStoreImpl {
    fn certificates(&self, password: Option<&str>) -> Result<Vec<Certificate>>;
}
