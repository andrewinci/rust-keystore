#[derive(Debug)]
pub enum Error {
    IO(String),
}

pub type Result<T> = std::result::Result<T, Error>; 