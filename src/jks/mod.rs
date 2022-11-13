mod helper;
mod types;

use sha1::{Digest, Sha1};

use crate::KeyStoreImpl;

use crate::error::{Error, Result};
use crate::types::Certificate;

use self::helper::{password_to_bin, read_data, read_utf, unpack_4, unpack_8};
use self::types::{CertChain, CertData, CertType, Entry};
pub struct Jks {
    check: Vec<u8>,
    raw: Vec<u8>,
    entries: Vec<Entry>,
}

impl Jks {
    pub fn from_byte_array(data: &[u8]) -> Result<Jks> {
        if data.len() < 12 {
            return Err(Error::UnsupportedKeystoreFormat(
                "JKS must be at least 12 bytes".into(),
            ));
        }
        if data[0..4] != [0xFE, 0xED, 0xFE, 0xED] {
            return Err(Error::UnsupportedKeystoreFormat(format!(
                "Unrecognized magic bytes {:02x?}",
                &data[0..4]
            )));
        }
        let version = unpack_4(data, 4)?;
        if version != 2 {
            return Err(Error::UnsupportedKeystoreFormat(format!(
                "Unsupported keystore version; expected v2, found v{}",
                version
            )));
        }
        // parse entities
        let entry_count = unpack_4(data, 8)?;
        let mut entries: Vec<Entry> = vec![];
        let mut pos = 12;
        for _ in 0..entry_count {
            let tag = unpack_4(data, pos)?;
            pos += 4;
            let alias: String;
            (alias, pos) = read_utf(data, pos)?;
            let timestamp = unpack_8(data, pos)?;
            pos += 8;

            let (cert_type, cert_data, cert_chain);
            let new_entry = match tag {
                1 => {
                    (cert_chain, cert_data, pos) = Self::read_private_key(data, pos)?;
                    Ok(Entry::PrivateKey {
                        alias,
                        timestamp,
                        cert_chain,
                        cert_data,
                    })
                }
                2 => {
                    (cert_type, cert_data, pos) = Self::read_trusted_cert(data, pos)?;
                    Ok(Entry::Cert {
                        alias,
                        timestamp,
                        cert_type,
                        cert_data: cert_data.clone(),
                    })
                }
                _ => Err(Error::UnsupportedKeystoreFormat(format!(
                    "Unrecognized entry tag {:?} parsing the keystore",
                    tag
                ))),
            }?;
            entries.push(new_entry);
        }
        Ok(Jks {
            entries,
            raw: data[..pos].to_vec(),
            check: data[pos..pos + Sha1::output_size()].to_vec(),
        })
    }

    fn read_private_key(data: &[u8], pos: usize) -> Result<(CertChain, CertData, usize)> {
        let (ber_data, mut pos) = read_data(data, pos)?;
        let chain_len = unpack_4(data, pos)?;
        pos += 4;
        let mut cert_chain = vec![];
        for _ in 0..chain_len {
            let cert_type;
            (cert_type, pos) = read_utf(data, pos)?;
            let cert_data;
            (cert_data, pos) = read_data(data, pos)?;
            cert_chain.push((cert_type, cert_data));
        }
        Ok((cert_chain, ber_data, pos))
    }

    fn read_trusted_cert(data: &[u8], pos: usize) -> Result<(CertType, CertData, usize)> {
        let (cert_type, pos) = read_utf(data, pos)?;
        let (cert_data, pos) = read_data(data, pos)?;
        Ok((cert_type, cert_data, pos))
    }
}

impl KeyStoreImpl for Jks {
    fn certificates(&self, _password: Option<&str>) -> Result<Vec<Certificate>> {
        todo!()
    }

    fn validate(&self, password: Option<&str>) -> bool {
        if let Some(password) = password {
            let mut hasher = Sha1::new();
            let pass = password_to_bin(password);
            hasher.update(pass);
            hasher.update(b"Mighty Aphrodite");
            hasher.update(&self.raw);
            let res = hasher.finalize().to_vec();
            if res.len() == Sha1::output_size() && res == self.check {
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use crate::{helper::read_to_binary, KeyStoreImpl};

    use super::Jks;

    #[test]
    fn load_empty_jks() {
        let data = read_to_binary("./test_data/jks/empty.jks").expect("Unable to read the file");
        let sut = Jks::from_byte_array(&data);
        assert!(sut.is_ok());
        let store = sut.unwrap();
        assert_eq!(store.entries.len(), 0);
    }

    #[test]
    fn test_rsa1024() {
        let data = read_to_binary("./test_data/jks/RSA1024.jks").expect("Unable to read the file");
        let sut = Jks::from_byte_array(&data);
        assert!(sut.is_ok());
        let store = sut.unwrap();
        assert_eq!(store.entries.len(), 1);
        assert!(store.validate(Some("12345678")));
    }
}
