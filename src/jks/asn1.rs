use simple_asn1::{der_decode, oid, ASN1Block, ASN1DecodeErr, FromASN1};

pub(crate) fn get_encrypted_private_key(data: &[u8]) -> crate::error::Result<Vec<u8>> {
    let pvt_key: JKSPrivateKey = der_decode(data).map_err(|_| {
        crate::error::Error::UnsupportedKeystoreFormat(
            "Unable to decode the private key asn1".into(),
        )
    })?;
    Ok(pvt_key.encrypted_data)
}

struct JKSPrivateKey {
    encrypted_data: Vec<u8>,
}

impl FromASN1 for JKSPrivateKey {
    type Error = ASN1DecodeErr;
    fn from_asn1(
        v: &[simple_asn1::ASN1Block],
    ) -> Result<(Self, &[simple_asn1::ASN1Block]), Self::Error> {
        let mut encrypted_data: Vec<u8> = vec![];
        let recognized_alg = if let ASN1Block::Sequence(_, v) = &v[0] {
            if let (ASN1Block::Sequence(_, v), ASN1Block::OctetString(_, data)) = (&v[0], &v[1]) {
                encrypted_data = data.clone();
                if let ASN1Block::ObjectIdentifier(_, oid) = &v[0] {
                    // check that the  SUN_JKS_ALGO_ID algorithm is used
                    oid == oid!(1, 3, 6, 1, 4, 1, 42, 2, 17, 1, 1)
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        };
        if recognized_alg && !encrypted_data.is_empty() {
            Ok((JKSPrivateKey { encrypted_data }, &[]))
        } else {
            Err(ASN1DecodeErr::Incomplete)
        }
    }
}
