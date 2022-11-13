use crate::error::Result;
use crate::types::{Certificate, KeyStoreImpl};

pub struct PKCS12Store<'a> {
    raw: &'a [u8],
}

impl <'a> PKCS12Store<'a> {
    pub fn from_byte_array(raw: Vec<u8>) -> Result<PKCS12Store<'a>> {
        todo!()
    }
}

impl <'a> KeyStoreImpl<'a> for PKCS12Store<'a> {
    fn certificates(&self) -> &'a [Certificate] {
        todo!()
    }
}