#![no_std]

extern crate alloc;

pub mod canonicalization;
pub mod dkim;
pub mod email;
pub mod string_tools;
pub mod header;

mod tests;

pub use self::dkim::Header;
pub use self::email::Email;

pub(crate) fn find_from(line: &str, ix_start: usize, key: &str) -> Option<usize> {
    line[ix_start..].find(key).map(|v| ix_start + v)
}