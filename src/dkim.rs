use crate::string_tools::*;
use core::num::ParseIntError;

use crate::alloc::format;
use crate::alloc::string;
use crate::alloc::string::*;
use crate::alloc::vec;
use crate::alloc::vec::Vec;

/// A struct reprensenting a DKIM-Signature header.  
/// It can be build using the builder syntax.
#[derive(Debug)]
pub struct Header<'a> {
    pub(crate) algorithm: SigningAlgorithm,
    pub signature: Vec<u8>,
    pub body_hash: Vec<u8>,
    pub(crate) canonicalization: (CanonicalizationType, CanonicalizationType),
    pub sdid: String,
    pub selector: String,
    pub(crate) signed_headers: Vec<&'a str>,
    copied_headers: Option<String>,
    auid: Option<String>,
    pub(crate) body_lenght: Option<usize>,
    signature_timestamp: Option<usize>,
    signature_expiration: Option<usize>,
    pub(crate) original: Option<String>,
}

impl<'a> Header<'a> {
    /// Initialize a new DKIM-Signature header with default fields. The first argument must be the signing domain (ex: "example.com") and the second argument must be the selector (ex: "dkim"). Making a txt lookup to "{selector}._domainkey.{sdid}" must return a DKIM record.
    ///   
    /// Uses relaxed canonicalization algorithms, Sha256 hash algorithm and signed headers will be `["mime-version", "references", "in-reply-to", "from", "date", "message-id", "subject", "to"]`. Optionnal fields are unset.  
    ///   
    /// The signature and body_hash fields can't be set manually (the `sign` method on an `Email` will do it).
    pub fn new(sdid: String, selector: String) -> Header<'a> {
        Header {
            algorithm: SigningAlgorithm::RsaSha256,
            signature: Vec::new(),
            body_hash: Vec::new(),
            canonicalization: (CanonicalizationType::Relaxed, CanonicalizationType::Relaxed),
            sdid,
            selector,
            signed_headers: vec![
                "mime-version",
                "mime-version",
                "references",
                "in-reply-to",
                "from",
                "date",
                "message-id",
                "subject",
                "to",
            ],
            copied_headers: None,
            auid: None,
            body_lenght: None,
            signature_timestamp: None,
            signature_expiration: None,
            original: None,
        }
    }

    pub fn parse(name: &'a str, value: &'a str) -> Result<Header<'a>, DkimParsingError> {
        #[derive(PartialEq)]
        enum State {
            B,
            EqualSign,
            Semicolon,
        }
        let mut state = State::B;
        let mut b_idx = 0;
        let mut b_end_idx = 0;
        for (idx, c) in value.chars().enumerate() {
            match state {
                State::B => {
                    // todo avoid 'b' that can be in other values
                    if c == 'b' {
                        state = State::EqualSign;
                    }
                }
                State::EqualSign => {
                    if c == '=' {
                        b_idx = idx + 1;
                        state = State::Semicolon;
                    } else {
                        state = State::B;
                    }
                }
                State::Semicolon => {
                    if c == ';' {
                        b_end_idx = idx;
                        break;
                    }
                }
            }
        }
        if b_end_idx == 0 && state == State::Semicolon {
            b_end_idx = value.len();
        }
        let mut save = value
            .get(..b_idx)
            .map(|v| v.to_string())
            .unwrap_or_default();
        save.push_str(match value.get(b_end_idx..) {
            Some(end) => end,
            None => "",
        });

        let mut got_v = false;
        let mut algorithm = None;
        let mut signature = None;
        let mut body_hash = None;
        let mut canonicalization = None;
        let mut sdid = None;
        let mut selector = None;
        let mut signed_headers = None;
        let mut copied_headers = None;
        let mut auid = None;
        let mut body_lenght = None;
        let mut signature_timestamp = None;
        let mut signature_expiration = None;
        let mut q = false;

        for e in value.split(';') {
            match get_all_before_strict(e, "=") {
                None => (),
                Some(name) => {
                    let value = get_all_after(&e, "=").trim();
                    match name.trim() {
                        "v" => {
                            if got_v {
                                return Err(DkimParsingError::DuplicatedField("v"));
                            } else if value != "1" {
                                return Err(DkimParsingError::UnsupportedDkimVersion(
                                    value.to_string(),
                                ));
                            } else {
                                got_v = true;
                            }
                        }
                        "a" => {
                            if algorithm.is_some() {
                                return Err(DkimParsingError::DuplicatedField("a"));
                            } else if value == "rsa-sha1" {
                                algorithm = Some(SigningAlgorithm::RsaSha1)
                            } else if value == "rsa-sha256" {
                                algorithm = Some(SigningAlgorithm::RsaSha256)
                            } else {
                                return Err(DkimParsingError::UnsupportedSigningAlgorithm(
                                    value.to_string(),
                                ));
                            }
                        }
                        "b" => {
                            if signature.is_some() {
                                return Err(DkimParsingError::DuplicatedField("b"));
                            } else {
                                // let value = if value.contains(' ') {
                                let mut new_value = String::from("");

                                for c in value.chars() {
                                    match c {
                                        '\t' | '\n' | '\r' | ' ' => {}
                                        _ => new_value.push(c),
                                    }
                                }

                                // let value: String = value.replace("\t", "");
                                // ckb_std::debug!("value is {:?}", value);
                                // } else {
                                // base64::decode(value)
                                // };

                                // debug!("value is {:?}", new_value);
                                let value = base64::decode(new_value);

                                // ckb_std::debug!("base64 is {:?}", value);

                                signature = match value {
                                    Ok(value) => Some(value), // TODO check size
                                    Err(e) => return Err(DkimParsingError::InvalidBase64Value(e)),
                                };
                                // signature = Some([1, 2, 3].to_vec());
                            }
                        }
                        "bh" => {
                            if body_hash.is_some() {
                                return Err(DkimParsingError::DuplicatedField("bh"));
                            } else {
                                let mut new_value = String::from("");
                                for c in value.chars() {
                                    match c {
                                        '\t' | '\n' | '\r' | ' ' => {}
                                        _ => new_value.push(c),
                                    }
                                }

                                let value = base64::decode(new_value);

                                body_hash = match value {
                                    Ok(value) => Some(value), // TODO check size
                                    Err(e) => return Err(DkimParsingError::InvalidBase64Value(e)),
                                };
                            }
                        }
                        "c" => {
                            if canonicalization.is_some() {
                                return Err(DkimParsingError::DuplicatedField("c"));
                            } else {
                                match value {
                                    "relaxed/relaxed" => {
                                        canonicalization = Some((
                                            CanonicalizationType::Relaxed,
                                            CanonicalizationType::Relaxed,
                                        ))
                                    }
                                    "relaxed/simple" | "relaxed" => {
                                        canonicalization = Some((
                                            CanonicalizationType::Relaxed,
                                            CanonicalizationType::Simple,
                                        ))
                                    }
                                    "simple/relaxed" => {
                                        canonicalization = Some((
                                            CanonicalizationType::Simple,
                                            CanonicalizationType::Relaxed,
                                        ))
                                    }
                                    "simple/simple" | "simple" => {
                                        canonicalization = Some((
                                            CanonicalizationType::Simple,
                                            CanonicalizationType::Simple,
                                        ))
                                    }
                                    value => {
                                        return Err(DkimParsingError::InvalidCanonicalizationType(
                                            value.to_string(),
                                        ))
                                    }
                                }
                            }
                        }
                        "d" => {
                            if sdid.is_some() {
                                return Err(DkimParsingError::DuplicatedField("d"));
                            } else {
                                sdid = Some(value.to_string());
                            }
                        }
                        "h" => {
                            if signed_headers.is_some() {
                                return Err(DkimParsingError::DuplicatedField("h"));
                            } else {
                                let mut headers = Vec::new();
                                for header in value.split(':') {
                                    headers.push(header.trim())
                                }
                                signed_headers = Some(headers);
                            }
                        }
                        "i" => {
                            if auid.is_some() {
                                return Err(DkimParsingError::DuplicatedField("i"));
                            } else {
                                auid = Some(value.to_string());
                            }
                        }
                        "l" => {
                            if body_lenght.is_some() {
                                return Err(DkimParsingError::DuplicatedField("l"));
                            } else {
                                body_lenght = match value.parse::<usize>() {
                                    Ok(value) => Some(value),
                                    Err(e) => return Err(DkimParsingError::InvalidBodyLenght(e)),
                                };
                            }
                        }
                        "q" => {
                            if q {
                                return Err(DkimParsingError::DuplicatedField("q"));
                            } else {
                                let mut methods = Vec::new();
                                for method in value.split(':') {
                                    methods.push(method)
                                }
                                if !methods.contains(&"dns/txt") {
                                    return Err(
                                        DkimParsingError::UnsupportedPublicKeyQueryMethods(
                                            format!("{:?}", methods),
                                        ),
                                    );
                                }
                                q = true;
                            }
                        }
                        "s" => {
                            if selector.is_some() {
                                return Err(DkimParsingError::DuplicatedField("s"));
                            } else {
                                selector = Some(value.to_string());
                            }
                        }
                        "t" => {
                            if signature_timestamp.is_some() {
                                return Err(DkimParsingError::DuplicatedField("t"));
                            } else {
                                signature_timestamp = match value.parse::<usize>() {
                                    Ok(value) => Some(value),
                                    Err(e) => {
                                        return Err(DkimParsingError::InvalidSignatureTimestamp(e))
                                    }
                                };
                            }
                        }
                        "x" => {
                            if signature_expiration.is_some() {
                                return Err(DkimParsingError::DuplicatedField("x"));
                            } else {
                                signature_expiration = match value.parse::<usize>() {
                                    Ok(value) => Some(value),
                                    Err(e) => {
                                        return Err(DkimParsingError::InvalidSignatureExpiration(e))
                                    }
                                };
                            }
                        }
                        "z" => {
                            if copied_headers.is_some() {
                                return Err(DkimParsingError::DuplicatedField("z"));
                            } else {
                                copied_headers = Some(value.to_string());
                            }
                        }
                        _ => (),
                    }
                }
            }
        }

        let canonicalization = canonicalization
            .unwrap_or((CanonicalizationType::Simple, CanonicalizationType::Simple));

        // ckb_std::debug!("finish canonicalization");

        match &canonicalization.0 {
            CanonicalizationType::Relaxed => {
                save = format!(
                    "dkim-signature:{}",
                    crate::canonicalization::canonicalize_header_relaxed(save)
                )
            }
            CanonicalizationType::Simple => save = format!("{}:{}", name, save),
        }

        // ckb_std::debug!("finish original");
        // Ok(Header::new("123".to_string(), "456".to_string()))

        Ok(Header {
            algorithm: algorithm.ok_or_else(|| DkimParsingError::MissingField("a"))?,
            signature: signature.ok_or_else(|| DkimParsingError::MissingField("b"))?,
            body_hash: body_hash.ok_or_else(|| DkimParsingError::MissingField("bh"))?,
            canonicalization,
            sdid: sdid.ok_or_else(|| DkimParsingError::MissingField("d"))?,
            selector: selector.ok_or_else(|| DkimParsingError::MissingField("s"))?,
            signed_headers: signed_headers.ok_or_else(|| DkimParsingError::MissingField("h"))?,
            copied_headers,
            auid,
            body_lenght,
            signature_timestamp,
            signature_expiration,
            original: Some(save),
        })
    }
}

impl<'a> string::ToString for Header<'a> {
    fn to_string(&self) -> String {
        let mut result = String::new();
        result.push_str(match self.algorithm {
            SigningAlgorithm::RsaSha1 => "v=1; a=rsa-sha1; b=",
            SigningAlgorithm::RsaSha256 => "v=1; a=rsa-sha256; b=",
        });

        result.push_str(&base64::encode(&self.signature));

        result.push_str("; bh=");
        result.push_str(&base64::encode(&self.body_hash));

        match self.canonicalization {
            (CanonicalizationType::Simple, CanonicalizationType::Simple) => (), // default value
            (CanonicalizationType::Simple, CanonicalizationType::Relaxed) => {
                result.push_str("; c=simple/relaxed")
            }
            (CanonicalizationType::Relaxed, CanonicalizationType::Simple) => {
                result.push_str("; c=relaxed")
            }
            (CanonicalizationType::Relaxed, CanonicalizationType::Relaxed) => {
                result.push_str("; c=relaxed/relaxed")
            }
        };

        result.push_str("; d=");
        result.push_str(&self.sdid);

        result.push_str("; h=");
        for (idx, signed_header) in self.signed_headers.iter().enumerate() {
            if idx > 0 {
                result.push(':');
            }
            result.push_str(signed_header);
        }

        if let Some(i) = &self.auid {
            result.push_str("; i=");
            // TODO DKIM quoted printable
            result.push_str(i);
        }

        if let Some(l) = &self.body_lenght {
            result.push_str("; l=");
            result.push_str(&l.to_string());
        }

        // q is not needed

        result.push_str("; s=");
        result.push_str(&self.selector);

        if let Some(t) = &self.signature_timestamp {
            result.push_str("; t=");
            result.push_str(&t.to_string());
        }

        if let Some(x) = &self.signature_expiration {
            result.push_str("; x=");
            result.push_str(&x.to_string());
        }

        if let Some(z) = &self.copied_headers {
            result.push_str("; z=");
            // TODO DKIM quoted printable
            result.push_str(z);
        }

        match self.canonicalization.0 {
            CanonicalizationType::Relaxed => {
                result = crate::canonicalization::canonicalize_header_relaxed(result);
                result.insert_str(0, "dkim-signature:");
                result
            }
            CanonicalizationType::Simple => {
                result.insert_str(0, "DKIM-Signature: ");
                result
            }
        }
    }
}

/// A struct reprensenting a DKIM dns record. (contains the public key and a few optional fields)
#[derive(Debug)]
pub struct PublicKey {
    sha1_supported: bool,
    sha256_supported: bool,
    subdomains_disallowed: bool,
    testing_domain: bool,
    key_type: String,
    note: Option<String>,
    pub(crate) key: Option<Vec<u8>>,
}

/// The hashing algorithm used when signing or verifying.
/// Should be sha256 but may be sha1.
#[derive(Debug)]
pub enum SigningAlgorithm {
    RsaSha1,
    RsaSha256,
}

/// The DKIM canonicalization algorithm.
#[derive(Debug, PartialEq)]
pub enum CanonicalizationType {
    /// Disallows modifications expect header addition during mail transit
    Simple,
    /// Allows space duplication and header addition during mail transit
    Relaxed,
}

#[derive(Debug)]
pub enum DkimParsingError {
    DuplicatedField(&'static str),
    MissingField(&'static str),
    NotADkimSignatureHeader,
    UnsupportedDkimVersion(String),
    UnsupportedSigningAlgorithm(String),
    UnsupportedPublicKeyQueryMethods(String),
    InvalidBase64Value(base64::DecodeError),
    InvalidCanonicalizationType(String),
    InvalidBodyLenght(ParseIntError),
    InvalidSignatureTimestamp(ParseIntError),
    InvalidSignatureExpiration(ParseIntError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_dkim_header() {
        let header = Header::parse("Dkim-Signature", " v=1; a=rsa-sha256; d=example.net; s=brisbane; c=simple; q=dns/txt; i=@eng.example.net; t=1117574938; x=1118006938; h=from:to:subject:date; z=From:foo@eng.example.net|To:joe@example.com|  Subject:demo=20run|Date:July=205,=202005=203:44:08=20PM=20-0700; bh=MTIzNDU2Nzg5MDEyMzQ1Njc4OTAxMjM0NTY3ODkwMTI=; b=dzdVyOfAKCdLXdJOc9G2q8LoXSlEniSbav+yuU4zGeeruD00lszZVoG4ZHRNiYzR").unwrap();

        // println!("{:?}", header);
        // println!("{:?}", header.to_string());
        // println!("{:?}", header.original.unwrap());
        match header.algorithm {
            SigningAlgorithm::RsaSha256 => {}
            SigningAlgorithm::RsaSha1 => panic!("Expect rsa256"),
        };

        assert_eq!(header.signature_timestamp.unwrap(), 1117574938);
    }
}
