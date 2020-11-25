/// Return the part of a str which is before an occurence or return None if there is no occurence.
///
/// ```
/// use string_tools::get_all_before_strict;
///
/// assert_eq!(get_all_before_strict("azertyuiopqsdfghjklmwxcvbn", "sdf"), Some("azertyuiopq"));
/// assert_eq!(get_all_before_strict("azertyuiopqsdfghjklmwxcvbn", "123"), None);
/// ```
pub fn get_all_before_strict<'a>(text: &'a str, begin: &str) -> Option<&'a str> {
    let begin = text.find(begin)?;
    Some(&text[..begin])
}

/// Return the part of a str which is after an occurence or return None if there is no occurence.
///
/// ```
/// use string_tools::get_all_after_strict;
///
/// assert_eq!(get_all_after_strict("azertyuiopqsdfghjklmwxcvbn", "sdf"), Some("ghjklmwxcvbn"));
/// assert_eq!(get_all_after_strict("azertyuiopqsdfghjklmwxcvbn", "123"), None);
/// ```
pub fn get_all_after_strict<'a>(text: &'a str, end: &str) -> Option<&'a str> {
    let end = text.find(end)? + end.len();
    Some(&text[end..])
}

/// Alias for the str find method.
///
/// ```
/// use string_tools::get_idx_before_strict;
///
/// assert_eq!(get_idx_before_strict("azertyuiopqsdfghjklmwxcvbn", "sdf"), Some(11));
/// assert_eq!(get_idx_before_strict("azertyuiopqsdfghjklmwxcvbn", "123"), None);
/// ```
pub fn get_idx_before_strict<'a>(text: &'a str, begin: &str) -> Option<usize> {
    text.find(begin)
}

/// Return the index of an occurence. If there is no occurence, the index is the len of the text.
///
/// ```
/// use string_tools::get_idx_before;
///
/// assert_eq!(get_idx_before("azertyuiopqsdfghjklmwxcvbn", "sdf"), 11);
/// assert_eq!(get_idx_before("azertyuiopqsdfghjklmwxcvbn", "123"), 26);
/// ```
pub fn get_idx_before(text: &str, begin: &str) -> usize {
    if let Some(idx) = text.find(begin) {
        return idx;
    } else {
        return text.len();
    }
}

/// Return the index of the end of an occurence. Return None if there is no occurence.
///
/// ```
/// use string_tools::get_idx_after_strict;
///
/// assert_eq!(get_idx_after_strict("azertyuiopqsdfghjklmwxcvbn", "sdf"), Some(14));
/// assert_eq!(get_idx_after_strict("azertyuiopqsdfghjklmwxcvbn", "123"), None);
/// ```
pub fn get_idx_after_strict<'a>(text: &'a str, end: &str) -> Option<usize> {
    let end = text.find(end)? + end.len();
    Some(end)
}

/// Return the part of a str which is between two str or return None if this is not possible.
///
/// ```
/// use string_tools::get_all_between_strict;
///
/// assert_eq!(get_all_between_strict("azertyuiopqsdfghjklmwxcvbn", "tyu", "klm"), Some("iopqsdfghj"));
/// assert_eq!(get_all_between_strict("azertyuiopqsdfghjklmwxcvbn", "klm", "tyu"), None);
/// ```
pub fn get_all_between_strict<'a>(text: &'a str, begin: &str, end: &str) -> Option<&'a str> {
    let text = get_all_after_strict(text, begin)?;
    let text = get_all_before_strict(text, end)?;
    Some(text)
}

pub fn get_idx_between_strict<'a>(text: &'a str, begin: &str, end: &str) -> Option<(usize, usize)> {
    let after = get_idx_after_strict(text, begin)?;
    let before = get_idx_before_strict(&text[after..], end)?;
    Some((after, after + before))
}

pub fn get_all_before<'a>(text: &'a str, begin: &str) -> &'a str {
    let begin = text.find(begin).unwrap_or(text.len());
    &text[..begin]
}

pub fn get_all_after<'a>(text: &'a str, end: &str) -> &'a str {
    if let Some(mut end_index) = text.find(end) {
        end_index += end.len();
        return &text[end_index..];
    } else {
        return "";
    }
}

pub fn get_all_between<'a>(text: &'a str, begin: &str, end: &str) -> &'a str {
    let text = get_all_after(text, begin);
    let text = get_all_before(text, end);
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn string_tools_test() {
        assert_eq!(Some("test"), get_all_before_strict("testlol", "lol"));
        assert_eq!(Some("test"), get_all_before_strict("testloltestlol", "lol"));
        assert_eq!(Some("lol"), get_all_after_strict("testlol", "test"));
        assert_eq!(
            Some("testlol"),
            get_all_after_strict("testloltestlol", "lol")
        );
        assert_eq!(
            Some("str3str4"),
            get_all_between_strict("str1str2str3str4str5", "str2", "str5")
        );
        assert_eq!(
            Some("str3str4"),
            get_all_between_strict("str5str1str2str3str4str5str2str3str5", "str2", "str5")
        );
        assert_eq!(None, get_all_before_strict("str1str2", "str3"));
        assert_eq!("str1str2", get_all_before("str1str2", "str3"));
        assert_eq!(None, get_all_after_strict("str1str2", "str3"));
        assert_eq!("", get_all_after("str1str2", "str3"));
        assert_eq!(
            "str2str3",
            get_all_between("str1str2str3str4", "str1", "str4")
        );
        assert_eq!("", get_all_between("str1str2str3str4", "str0", "str4"));
        assert_eq!(
            "str2str3str4",
            get_all_between("str1str2str3str4", "str1", "str6")
        );
    }
}
