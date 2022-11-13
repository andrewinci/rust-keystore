use openssl::error::ErrorStack;
use openssl::pkcs12::Pkcs12;

use crate::error::{Error, Result};
use crate::types::{Certificate, KeyStoreImpl, PrivateKey};

pub struct PKCS12Store {
    pkcs12: Pkcs12,
}

impl PKCS12Store {
    pub fn from_byte_array(input_bytes: &[u8]) -> Result<PKCS12Store> {
        let pkcs12 = Pkcs12::from_der(input_bytes).map_err(|err| {
            Error::UnsupportedKeystoreFormat(format!("Unable to parse DER Pkcs12: {:?}", err))
        })?;
        Ok(PKCS12Store { pkcs12 })
    }
}

impl KeyStoreImpl for PKCS12Store {
    fn certificates(&self, password: Option<&str>) -> Result<Vec<Certificate>> {
        if let Some(password) = password {
            let parsed = self.pkcs12.parse(password).unwrap();
            let mut cert_chain = vec![];
            if let Some(chain) = parsed.chain {
                for cert in chain {
                    cert_chain.push(Certificate {
                        cert_chain: vec![],
                        x509_der_data: cert.to_der()?,
                        pem: String::from_utf8(cert.to_pem()?)?,
                        private_key: None,
                    });
                }
            }
            Ok(vec![Certificate {
                cert_chain,
                x509_der_data: parsed.cert.to_der()?,
                pem: String::from_utf8(parsed.cert.to_pem()?)?,
                private_key: Some(PrivateKey {
                    der_data: parsed.pkey.private_key_to_der()?,
                    pkcs8_pem: String::from_utf8(parsed.pkey.private_key_to_pem_pkcs8()?)?,
                }),
            }])
        } else {
            Err(Error::RequiredPasswordNotProvided)
        }
    }

    fn validate(&self, password: Option<&str>) -> bool {
        // the validation is performed as part of the struct creation
        true
    }
}

impl From<ErrorStack> for Error {
    fn from(err: ErrorStack) -> Self {
        Error::OpenSslError(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use std::fs::read_to_string;

    use crate::{helper::read_to_binary, KeyStoreImpl};

    use super::PKCS12Store;

    #[test]
    fn test_happy_path() {
        let pk12 = read_to_binary("./test_data/p12/keyStore.p12").unwrap();
        let private_pem = read_to_string("./test_data/p12/myKey.pem").unwrap();
        let cert_pem = read_to_string("./test_data/p12/cert.pem").unwrap();

        let sut = PKCS12Store::from_byte_array(&pk12);

        assert!(sut.is_ok());
        let certs = sut.unwrap().certificates(Some("12345678"));
        assert!(certs.is_ok());
        let certs = certs.unwrap();
        assert_eq!(certs.len(), 1);
        assert_eq!(certs[0].pem, cert_pem);
        let private_key = certs[0].private_key.as_ref().unwrap();
        assert_eq!(private_key.pkcs8_pem, private_pem);
    }
}
