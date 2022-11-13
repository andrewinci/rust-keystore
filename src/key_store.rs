use std::{fs, io::Read};

use crate::{
    error::{Error, Result},
    pkcs12::PKCS12Store,
    KeyStoreImpl,
};

pub struct KeyStore;

impl KeyStore {

    pub fn try_load(file_path: &str) -> Result<impl KeyStoreImpl<'_>>{
        let mut f = std::fs::File::open(file_path).unwrap();
        let metadata = fs::metadata(&file_path).unwrap();
        let mut buffer = vec![0; metadata.len() as usize];
        f.read(&mut buffer).unwrap();
        KeyStore::from_byte_array(buffer)
    }

    pub fn from_byte_array<'a>(raw: Vec<u8>) -> Result<impl KeyStoreImpl<'a>> {
        PKCS12Store::from_byte_array(raw)
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::IO(format!("Load keystore error: {:?}", err))
    }
}

#[cfg(test)]
mod tests {
    use super::KeyStore;
    use super::KeyStoreImpl;

    #[test]
    fn test() {
        let sample_raw = vec![0x11];
        let key_store = KeyStore::from_byte_array(sample_raw).unwrap();
        let certs = key_store.certificates();
        println!("{:?}", certs);
    }
}
