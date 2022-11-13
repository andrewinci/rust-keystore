use crate::KeyStoreImpl;

use crate::error::{Error, Result};
use crate::types::Certificate;
pub struct Jks {}

impl Jks {
    pub fn from_byte_array(_input_bytes: &[u8]) -> Result<Jks> {
        Err(Error::UnsupportedKeystoreFormat(
            "JKS not supported yet".into(),
        ))
    }
}

impl KeyStoreImpl for Jks {
    fn certificates(&self, _password: Option<&str>) -> Result<Vec<Certificate>> {
        todo!()
    }
}
