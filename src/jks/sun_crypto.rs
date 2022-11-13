use crate::{error::Result};
use sha1::{Digest, Sha1};

use super::helper::password_to_bin;

pub(crate) fn jks_private_key_decrypt(data: &[u8], password: &str) -> Result<Vec<u8>> {
    let password: Vec<_> = password_to_bin(password);
    let (iv, data, check) = (
        &data[0..20],
        &data[20..data.len() - 20],
        &data[data.len() - 20..],
    );
    let keystream = jks_keystream(iv, &password, data.len());
    let key: Vec<_> = data
        .iter()
        .zip(keystream)
        .map(|(&x1, x2)| x1 ^ x2)
        .collect();
    let mut hasher = Sha1::new();
    hasher.update([password, key.clone()].concat());
    let computed_check: Vec<u8> = hasher.finalize().to_vec();
    if computed_check != check {
        Err(crate::error::Error::InvalidPassword)
    } else {
        Ok(key)
    }
}

fn jks_keystream(iv: &[u8], password: &[u8], result_len: usize) -> Vec<u8> {
    let mut result = Vec::new();
    let mut cur: Vec<u8> = iv.into();
    while result.len() < result_len {
        let mut hasher = Sha1::new();
        hasher.update([password, &cur].concat());
        let xhash = hasher.finalize();
        cur = xhash.to_vec();
        for b in xhash {
            if result.len() < result_len {
                result.push(b)
            }
        }
    }
    result
}
