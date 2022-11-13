use std::array::TryFromSliceError;

use crate::error::{Error, Result};

pub(crate) fn unpack_2u(data: &[u8], offset: usize) -> Result<u16> {
    Ok(u16::from_be_bytes(data[offset..(offset + 2)].try_into()?))
}
pub(crate) fn unpack_4(data: &[u8], offset: usize) -> Result<i32> {
    Ok(i32::from_be_bytes(data[offset..(offset + 4)].try_into()?))
}
pub(crate) fn unpack_4u(data: &[u8], offset: usize) -> Result<u32> {
    Ok(u32::from_be_bytes(data[offset..(offset + 4)].try_into()?))
}
pub(crate) fn unpack_8(data: &[u8], offset: usize) -> Result<i64> {
    Ok(i64::from_be_bytes(data[offset..offset + 8].try_into()?))
}

pub(crate) fn read_utf(data: &[u8], pos: usize) -> Result<(String, usize)> {
    let size = unpack_2u(data, pos)?;
    let str = String::from_utf8(data[(pos + 2)..(2 + pos + size as usize)].into())
        .expect("Invalid UTF8 data");
    Ok((str, 2 + pos + size as usize))
}

pub(crate) fn read_data(data: &[u8], pos: usize) -> Result<(Vec<u8>, usize)> {
    let size = unpack_4u(data, pos)?;
    Ok((
        data[pos + 4..(4 + pos + size as usize)].into(),
        4 + pos + size as usize,
    ))
}

pub(crate) fn password_to_bin(password: &str) -> Vec<u8> {
    password
        .encode_utf16()
        .flat_map(|c| c.to_be_bytes())
        .collect()
}

impl From<TryFromSliceError> for Error {
    fn from(_: TryFromSliceError) -> Self {
        Error::InvalidDataLength
    }
}
