use std::string::FromUtf8Error;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    IO(String),
    UnsupportedKeystoreFormat(String),
    RequiredPasswordNotProvided,
    Utf8Parsing,
    OpenSslError(String),
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<FromUtf8Error> for Error {
    fn from(_: FromUtf8Error) -> Self {
        Error::Utf8Parsing
    }
}
