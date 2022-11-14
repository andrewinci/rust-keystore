use crate::error::Result;

#[derive(Debug, Clone)]
pub struct PrivateKey {
    pub der_data: Vec<u8>,
    pub pkcs8_pem: String,
}

#[derive(Debug, Clone)]
pub struct Certificate {
    pub x509_der_data: Vec<u8>,
    pub pem: String,
    pub private_key: Option<PrivateKey>,
}

pub trait KeyStoreImpl {
    fn certificates(&self, password: Option<&str>) -> Result<Vec<Certificate>>;
    fn validate(&self, password: Option<&str>) -> bool;
}

impl Certificate {
    pub(crate) fn is_empty(&self) -> bool {
        self.x509_der_data.is_empty() && self.pem.is_empty() && self.private_key.is_none()
    }
}
