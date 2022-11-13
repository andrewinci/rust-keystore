#[derive(Debug)]
pub struct Certificate {}

pub trait KeyStoreImpl<'a> {
    fn certificates(&self) -> &'a [Certificate];
}