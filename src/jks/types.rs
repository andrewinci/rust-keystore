pub(crate) type CertType = String;
pub(crate) type CertData = Vec<u8>;
pub(crate) type CertChain = Vec<(CertType, CertData)>;

#[derive(Debug)]
pub(crate) enum Entry {
    Cert {
        _timestamp: i64,
        _alias: String,
        _cert_type: CertType,
        cert_data: CertData,
    },
    PrivateKey {
        _timestamp: i64,
        _alias: String,
        key: CertData,
        cert_chain: CertChain,
    },
}
