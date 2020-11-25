#![no_std]

extern crate alloc;

pub mod canonicalization;
pub mod dkim;
pub mod email;
pub mod string_tools;

mod tests;

pub use self::dkim::Header;
pub use self::email::Email;
