use anyhow::{anyhow, Result};
use extend::ext;
use std::error::Error;

#[ext]
pub impl<T, E: Error> Result<T, E> {
    fn anyhow(self) -> Result<T> {
        self.map_err(|e| anyhow!("{e}"))
    }
}

#[ext]
pub impl<T> Option<T> {
    fn ok(self, expected: &str) -> Result<T> {
        self.ok_or(anyhow!("Option was empty, expected '{expected}'"))
    }
}
