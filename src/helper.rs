use std::{fs, io::Read};

use crate::error::Result;

pub(crate) fn read_to_binary(file_path: &str) -> Result<Vec<u8>> {
    let mut f = std::fs::File::open(file_path)?;
    let metadata = fs::metadata(&file_path)?;
    let mut buffer = vec![0; metadata.len() as usize];
    f.read_exact(&mut buffer)?;
    Ok(buffer)
}
