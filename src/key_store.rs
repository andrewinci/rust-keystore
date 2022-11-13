#[cfg(feature = "p12")]
use crate::pkcs12::PKCS12Store;

use crate::{
    error::{Error, Result},
    helper::read_to_binary,
    jks::Jks,
    KeyStoreImpl,
};

pub struct KeyStore;

impl KeyStore {
    pub fn try_load(file_path: &str) -> Result<Box<dyn KeyStoreImpl>> {
        KeyStore::from_byte_array(&read_to_binary(file_path)?)
    }

    pub fn from_byte_array(raw: &[u8]) -> Result<Box<dyn KeyStoreImpl>> {
        if let Ok(jks) = Jks::from_byte_array(raw) {
            return Ok(Box::new(jks));
        };
        #[cfg(feature = "p12")]
        {
            if let Ok(p12) = PKCS12Store::from_byte_array(raw) {
                return Ok(Box::new(p12));
            }
        }

        Err(Error::UnsupportedKeystoreFormat(
            "Unable to parse the data with the supported keystores".into(),
        ))
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::IO(format!("Load keystore error: {:?}", err))
    }
}

#[cfg(test)]
mod tests {
    use crate::{error::Error, helper::read_to_binary, KeyStoreImpl};

    use super::KeyStore;

    #[test]
    fn test_parse_invalid_data() {
        let sample_raw = vec![0x11];
        let key_store = KeyStore::from_byte_array(&sample_raw);
        assert!(matches!(
            key_store.err().expect("Should not parse invalid data"),
            Error::UnsupportedKeystoreFormat { .. }
        ));
    }

    #[test]
    #[cfg(feature = "p12")]
    fn test_parse_p12() {
        let sample_message =
            read_to_binary("./test_data/p12/keyStore.p12").expect("Test file not found");
        let res = KeyStore::from_byte_array(&sample_message);
        assert!(res.is_ok());
        assert_eq!(
            res.unwrap().certificates(Some("12345678")).unwrap().len(),
            1
        );
    }
}
