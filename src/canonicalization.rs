use crate::alloc::string::String;
use crate::alloc::string::ToString;
use crate::alloc::vec::Vec;
// Canonicalize headers using the simple canonicalization algorithm.
pub fn canonicalize_headers_simple(
    headers: &[(&str, &str, &str)],
    signed_headers: &[&str],
) -> String {
    let mut canonicalized_headers = String::new();
    let mut already_used = Vec::new();

    for signed_header in signed_headers {
        for (idx, (name, separator, value)) in headers
            .iter()
            .enumerate()
            .filter(|(idx, _)| !already_used.contains(idx))
        {
            if signed_header.eq_ignore_ascii_case(name) {
                canonicalized_headers.push_str(&name.to_lowercase());
                canonicalized_headers.push_str(separator);
                canonicalized_headers.push_str(value.replace("\r\n", "").as_ref());
                canonicalized_headers.push_str("\r\n");
                already_used.push(idx);
                break;
            }
        }
    }
    canonicalized_headers
}

/// Canonicalize body using the simple canonicalization algorithm.  
///   
/// The first argument **must** be the body of the mail.
pub fn canonicalize_body_simple(mut body: &str) -> &str {
    if body.is_empty() {
        return "\r\n";
    }

    while body.ends_with("\r\n\r\n") {
        body = &body[..body.len() - 2];
    }

    body
}

/// Canonicalize a single header using the relaxed canonicalization algorithm.  
///   
/// Note: There is no corresponding function for the simple canonicalization algorithm because the simple canonicalization algorithm does not change a single header.
pub fn canonicalize_header_relaxed(mut value: String) -> String {
    value = value.replace('\t', " ");
    // value = value.replace("\r\n", "");
    value = value.replace("\n", "");
    value = value.replace("\r", "");

    while value.ends_with(' ') {
        value.remove(value.len() - 1);
    }
    while value.starts_with(' ') {
        value.remove(0);
    }
    let mut previous = false;
    value.retain(|c| {
        if c == ' ' {
            if previous {
                false
            } else {
                previous = true;
                true
            }
        } else {
            previous = false;
            true
        }
    });

    value
}

// Canonicalize headers using the relaxed canonicalization algorithm.
pub fn canonicalize_headers_relaxed(
    headers: &[(&str, &str, &str)],
    signed_headers: &[&str],
) -> String {
    let mut canonicalized_headers = String::new();
    let mut already_used = Vec::new();

    for signed_header in signed_headers {
        for (idx, (name, _separator, value)) in headers
            .iter()
            .enumerate()
            .filter(|(idx, _)| !already_used.contains(idx))
        {
            if signed_header.eq_ignore_ascii_case(name) {
                canonicalized_headers.push_str(&name.to_lowercase());
                canonicalized_headers.push_str(":");
                canonicalized_headers.push_str(&canonicalize_header_relaxed(value.to_string()));
                canonicalized_headers.push_str("\r\n");

                already_used.push(idx);
                break;
            }
        }
    }
    canonicalized_headers
}

/// Canonicalize body using the relaxed canonicalization algorithm.  
///   
/// The first argument **must** be the body of the mail.
pub fn canonicalize_body_relaxed(mut body: String) -> String {
    // See https://tools.ietf.org/html/rfc6376#section-3.4.4 for implementation details

    // Reduce all sequences of WSP within a line to a single SP character.
    body = body.replace('\t', " ");
    let mut previous = false;
    body.retain(|c| {
        if c == ' ' {
            if previous {
                false
            } else {
                previous = true;
                true
            }
        } else {
            previous = false;
            true
        }
    });

    // Ignore all whitespace at the end of lines. Implementations MUST NOT remove the CRLF at the end of the line.
    while let Some(idx) = body.find(" \r\n") {
        body.remove(idx);
    }

    // Ignore all empty lines at the end of the message body. "Empty line" is defined in Section 3.4.3.
    while body.ends_with("\r\n\r\n") {
        body.remove(body.len() - 1);
        body.remove(body.len() - 1);
    }

    // If the body is non-empty but does not end with a CRLF, a CRLF is added. (For email, this is only possible when using extensions to SMTP or non-SMTP transport mechanisms.)
    if !body.is_empty() && !body.ends_with("\r\n") {
        body.push_str("\r\n");
    }

    body
}
