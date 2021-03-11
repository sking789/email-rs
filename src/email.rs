use crate::alloc::vec::*;
use crate::canonicalization::canonicalize_headers_simple;
use crate::{alloc::string::*, dkim::DkimParsingError};
use crate::{dkim::CanonicalizationType, Header as DkimHeader};

// use crate::header_value_parser::{create_header, EmailHeader};
/// Email represents an Email object and contains all the properties and data
/// related to an email
#[derive(Debug)]
pub struct Email<'a> {
    /// All the Headers for top level Email.
    pub headers: Vec<(&'a str, &'a str, &'a str)>,
    /// body of the email is going to be stored as a string for now since we are
    /// going to parse only simple emails.
    pub body: &'a str,

    pub dkim_header: Option<DkimHeader<'a>>,
}

/// For simplicity Email's body is now just going to be string.

impl<'a> Email<'a> {
    pub fn get_dkim_message(&self) -> String {
        match &self.dkim_header {
            Some(value) => {
                let headers = match value.canonicalization.0 {
                    CanonicalizationType::Relaxed => {
                        canonicalize_headers_simple(&self.headers, &value.signed_headers)
                    }
                    CanonicalizationType::Simple => {
                        canonicalize_headers_simple(&self.headers, &value.signed_headers)
                    }
                };

                let mut msg_str: String = headers.to_string();
                msg_str.push_str(value.original.as_ref().unwrap());
                msg_str
                // String::from("")
            }
            None => String::from(""),
        }
    }
    /// generate an Email from string object.
    pub fn from_str(s: &str) -> Result<Email, DkimParsingError> {
        let mut allheaders = Vec::new();

        let mut val: Vec<&str> = s.splitn(2, "\r\n\r\n").collect();
        if val.len() == 1 {
            val = s.splitn(2, "\n\n").collect();
        }

        // ckb_std::debug!("{:?}", val);
        let mut headers = Some(val[0]);

        while let Some(_) = headers {
            match Email::get_one_header(headers.unwrap()) {
                (Some(headerval), rest) => {
                    // ckb_std::debug!("headerval {:?}", headerval);
                    let key_val: Vec<&str> = headerval.splitn(2, ':').collect();
                    allheaders.push((
                        key_val[0],
                        ":",
                        key_val[1].trim_start().trim_end_matches(|x| x == '\r'),
                    ));
                    headers = rest;
                }
                _ => break,
            }
        }

        let dkim_header = match allheaders
            .iter()
            .find(|&x| x.0.eq_ignore_ascii_case("dkim-signature"))
        {
            Some(value) => {
                // ckb_std::debug!("dkim-signature: {:?}", value.2);
                let dkim_header = DkimHeader::parse("Dkim-Signature", value.2)?;
                Some(dkim_header)
            }
            _ => {
                return Err(DkimParsingError::NotADkimSignatureHeader);
            }
        };

        Ok(Email {
            headers: allheaders,
            dkim_header,
            body: val[1],
        })
    }

    /// get_one_header tries to parse one header line from the provided buffer
    /// and returns the rest back.
    fn get_one_header(_s: &str) -> (Option<&str>, Option<&str>) {
        let mut last = 0;
        let bytes = _s.as_bytes();
        for (i, &x) in bytes.iter().enumerate() {
            last = i;
            if x == b'\n' {
                if bytes[i + 1] == b' ' || bytes[i + 1] == b'\t' {
                    // If the next line starts with a whitespace, we continue
                    // parsing as a part of this same header.
                    continue;
                } else {
                    break;
                }
            }
        }
        let mut header_line = Some(&_s[..last]);
        let mut rest = Some(&_s[last + 1..]);
        if last + 1 == _s.len() {
            header_line = Some(&_s[..]);
            rest = None;
        }
        (header_line, rest)
    }

    pub fn get_email_timestamp(&self) -> Result<u32, i32> {
        let date = self.get_header_item("date")?;
        // debug!("date {:?}", date);

        let time = email_parser::parsing::time::date_time(date.as_bytes()).or(Err(1))?;
        let timestamp = time.1.get_timestamp().or(Err(1))?;
        // debug!("timestamp {:?}", timestamp);
        Ok(timestamp)
    }

    pub fn get_header_item(&self, key: &'a str) -> Result<&'a str, i32> {
        let value = self.headers.iter().find(|&x| x.0.eq_ignore_ascii_case(key));
        let value = value.ok_or(1)?.2;
        Ok(value)
    }

    pub fn extract_address_of_from(from: &str) -> Result<String, i32> {
        let val: Vec<&str> = from
            .trim_end()
            .rsplitn(2, |c| c == '<' || c == ' ')
            .collect();
        Ok(val[0].replace(">", ""))
    }

    // /// generate an Email from raw bytes.
    // fn from_bytes() -> Email {
    //     unimplemented!();
    // }

    // /// generate an email from a file path.
    // fn from_file() -> Email {
    //     unimplemented!();
    // }

    // /// Create a new email.
    // fn new() -> Email {
    //     unimplemented!();
    // }
}

#[test]
fn test_get_one_simple_header() {
    let headers = "From: Someone
To: Person
Date: Today";
    assert_eq!(
        Email::get_one_header(headers),
        (Some("From: Someone"), Some("To: Person\nDate: Today"))
    )
}

#[test]
fn test_get_one_multiline_header() {
    let headers = "From: acomplexheader
Subject: This is a complex header which goes to
 2nd line identified by whitespace at the
 start of each next line of header.";
    let (header, rest) = Email::get_one_header(headers);
    assert_eq!(header, Some("From: acomplexheader"));
    assert_eq!(rest.is_some(), true);
    let (header, rest) = Email::get_one_header(rest.unwrap());
    assert_eq!(
        header,
        Some(
            "Subject: This is a complex \
             header which goes to 2nd line identified by whitespace at \
             the start of each next line of header."
        )
    );
    assert_eq!(rest, None);
}
