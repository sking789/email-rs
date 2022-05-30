use crate::canonicalization::{
    canonicalize_body_relaxed, canonicalize_body_simple, canonicalize_headers_simple,
};
use crate::header::{HeaderToken, SubjectHeader};
use crate::{alloc::string::*, dkim::DkimParsingError};
use crate::{alloc::vec::*, canonicalization::canonicalize_headers_relaxed};
use crate::{dkim::CanonicalizationType, Header as DkimHeader};
// use ckb_std::debug;

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

    pub dkim_headers: Vec<DkimHeader<'a>>,

    pub subject_header: SubjectHeader<'a>,
}

/// For simplicity Email's body is now just going to be string.

impl<'a> Email<'a> {
    pub fn get_dkim_message(&self) -> Vec<String> {
        self.dkim_headers
            .iter()
            .map(|dkim_header| {
                let headers = match dkim_header.canonicalization.0 {
                    CanonicalizationType::Relaxed => {
                        canonicalize_headers_relaxed(&self.headers, &dkim_header.signed_headers)
                    }
                    CanonicalizationType::Simple => {
                        canonicalize_headers_simple(&self.headers, &dkim_header.signed_headers)
                    }
                };

                let mut msg_str: String = headers.to_string();
                msg_str.push_str(dkim_header.original.as_ref().unwrap());
                msg_str
            })
            .collect()
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
                        key_val
                            .get(1)
                            .map(|v| v.trim_start().trim_end_matches(|x| x == '\r'))
                            .unwrap_or_default(),
                    ));
                    headers = rest;
                }
                _ => break,
            }
        }

        let dkim_headers: Vec<DkimHeader> = allheaders
            .iter()
            .filter(|&x| x.0.eq_ignore_ascii_case("dkim-signature"))
            .map(|&val| DkimHeader::parse("Dkim-Signature", val.2))
            .collect::<Result<Vec<DkimHeader>, DkimParsingError>>()?;

        let subject_header = allheaders
            .iter()
            .find_map(|v| {
                if v.0.eq_ignore_ascii_case("subject") {
                    Some(SubjectHeader::tokenize_subject_header_line(v.2))
                } else {
                    None
                }
            })
            .ok_or(DkimParsingError::MissingField("subject"))?;

        Ok(Email {
            headers: allheaders,
            dkim_headers,
            body: val.get(1).unwrap_or(&""),
            subject_header,
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
                if bytes.get(i + 1) == Some(&b' ') || bytes.get(i + 1) == Some(&b'\t') {
                    // If the next line starts with a whitespace, we continue
                    // parsing as a part of this same header.
                    continue;
                } else {
                    break;
                }
            }
        }
        let header_line;
        let rest;
        if last + 1 == _s.len() {
            header_line = Some(&_s[..]);
            rest = None;
        } else {
            header_line = Some(&_s[..last]);
            rest = Some(&_s[last + 1..]);
        }

        (header_line, rest)
    }

    // pub fn get_email_timestamp(&self) -> Result<u32, i32> {
    //     let date = self.get_header_item("date")?;
    //     // debug!("date {:?}", date);

    //     let time = email_parser::parsing::time::date_time(date.as_bytes()).or(Err(1))?;
    //     let timestamp = time.1.get_timestamp().or(Err(1))?;
    //     // debug!("timestamp {:?}", timestamp);
    //     Ok(timestamp)
    // }

    pub fn get_header_item(&self, key: &'a str) -> Result<&'a str, i32> {
        let value = self.headers.iter().find(|&x| x.0.eq_ignore_ascii_case(key));
        let value = value.ok_or(1)?.2;
        Ok(value)
    }

    pub fn get_header_value(&self, key: &'a str) -> Result<String, i32> {
        let item = self.get_header_item(key)?;
        let mut res = String::new();
        for tok in crate::header::normalized_tokens(item) {
            match tok {
                HeaderToken::Text(t) => {
                    res.push_str(t);
                }
                HeaderToken::Whitespace(ws) => {
                    res.push_str(ws);
                }
                HeaderToken::Newline(Some(ws)) => {
                    res.push_str(&ws);
                }
                HeaderToken::Newline(None) => {}
                HeaderToken::DecodedWord(dw) => {
                    res.push_str(&dw);
                }
            }
        }
        Ok(res)
    }

    // pub fn get_canonicalized_body(&self) -> String {
    //     match &self.dkim_header {
    //         Some(value) => {
    //             let body = match value.canonicalization.0 {
    //                 CanonicalizationType::Relaxed => {
    //                     canonicalize_body_relaxed(String::from(self.body))
    //                 }
    //                 CanonicalizationType::Simple => {
    //                     String::from(canonicalize_body_simple(self.body))
    //                 }
    //             };

    //             body
    //             // String::from("")
    //         }
    //         None => String::from(""),
    //     }
    // }

    pub fn get_plain_body(&self) -> Result<String, i32> {
        let content_type = self.get_header_item("Content-Type")?;

        if content_type.contains(&"multipart") != true {
            let content_transfer_encoding = self.get_header_item("Content-Transfer-Encoding")?;
            if content_transfer_encoding.contains(&"base64") {
                return base64_decode_body(self.body);
            }

            return Ok(String::from(self.body));
        }

        // split body by boundary
        let vals: Vec<&str> = content_type.splitn(2, "boundary=").collect();
        let mut boundary: String = String::from("--");
        boundary.push_str(&vals[1].replace("\"", ""));

        // debug!("boundary is {}", boundary);
        let parts: Vec<&str> = self.body.split(&boundary).collect();

        // debug!("parts len is {}", parts.len());

        // process body parts
        for part in &parts[1..] {
            // debug!("part size is {}", part.len());
            if part.len() < 10 {
                continue;
            }

            // process part header
            let mut val: Vec<&str> = part.splitn(2, "\r\n\r\n").collect();
            if val.len() == 1 {
                val = part.splitn(2, "\n\n").collect();
            }
            // debug!("val len is {}", val.len());

            let content = val[1].trim_matches(|x| x == '\r' || x == '\n');

            // get Content-Type/Content-Transfer-Encoding from headers
            let mut headers: Vec<&str> = val[0].split("\r\n").collect();
            if headers.len() == 1 {
                headers = val[0].split("\n").collect();
            }
            // debug!("headers len is {}", headers.len());

            let mut content_type = "";
            let mut encoding = "";

            for header in headers {
                let items: Vec<&str> = header.splitn(2, ":").collect();

                if items[0].eq_ignore_ascii_case("content-type") {
                    let types: Vec<&str> = items[1].splitn(2, ";").collect();
                    content_type = types[0].trim();
                } else if items[0].eq_ignore_ascii_case("content-transfer-encoding") {
                    encoding = items[1].trim_start().trim_end_matches(|x| x == '\r');
                }
            }

            // debug!("encoding {}", encoding);
            // debug!("content_type {}", content_type);
            if !content_type.eq_ignore_ascii_case("text/plain") {
                continue;
            }

            if encoding.eq_ignore_ascii_case("base64") {
                return base64_decode_body(content);
            }

            return Ok(String::from(content));
        }

        Ok(String::from(self.body))
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

fn base64_decode_body(body: &str) -> Result<String, i32> {
    let canonicalized_content = body.replace("\r", "").replace("\n", "");

    let decoded_bytes =
        base64::decode_config(canonicalized_content.trim(), base64::STANDARD_NO_PAD).unwrap();

    return Ok(String::from_utf8_lossy(&decoded_bytes).into_owned());
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
