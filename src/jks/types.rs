pub(crate) type CertType = String;
pub(crate) type CertData = Vec<u8>;
pub(crate) type CertChain = Vec<(CertType, CertData)>;

#[derive(Debug)]
pub(crate) enum Entry {
    Cert {
        timestamp: i64,
        alias: String,
        cert_type: CertType,
        cert_data: CertData,
    },
    PrivateKey {
        timestamp: i64,
        alias: String,
        cert_data: CertData,
        cert_chain: CertChain,
    },
}
