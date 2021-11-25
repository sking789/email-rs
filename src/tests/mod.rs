use crate::Email;

#[cfg(test)]
#[test]
fn test_parse_google_mail() {
    let emailstr: &str = include_str!("./gmail_cn.eml");
    // let emailstr = std::fs::read_to_string("src/tests/gmail_cn.eml").unwrap();

    let email = Email::from_str(emailstr).unwrap();
    match email
        .headers
        .iter()
        .find(|&x| x.0.eq_ignore_ascii_case("from"))
    {
        Some(value) => {
            assert_eq!(
                value.2.trim_start(),
                "Zhang Huaqiang <zhanghuaqiang@gmail.com>"
            );
        }
        val => panic!("Expected from header found: {:?}", val),
    }
    // match email.headers.get("subject") {
    match email
        .headers
        .iter()
        .find(|&x| x.0.eq_ignore_ascii_case("subject"))
    {
        Some(value) => {
            assert_eq!(
                value.2.trim_start(),
                "=?UTF-8?B?5rWL6K+V5pWw5o2u5Lit5paH5aW95LiN5aW95L2/?="
            );
        }
        val => panic!("Expected subject header found: {:?}", val),
    }

    // match email
    //     .headers
    //     .iter()
    //     .find(|&x| x.0.eq_ignore_ascii_case("date"))
    // {
    //     Some(value) => {
    //         let date = date_time(value.2.as_bytes()).unwrap();
    //         assert_eq!(
    //             date.1,
    //             DateTime {
    //                 day_name: Some(Day::Friday),
    //                 date: Date {
    //                     day: 20,
    //                     month: Month::November,
    //                     year: 2020
    //                 },
    //                 time: TimeWithZone {
    //                     time: Time {
    //                         hour: 13,
    //                         minute: 19,
    //                         second: 57
    //                     },
    //                     zone: Zone {
    //                         sign: true,
    //                         hour_offset: 8,
    //                         minute_offset: 0
    //                     }
    //                 }
    //             }
    //         );

    //         assert_eq!(date.1.get_timestamp().unwrap(), 1605849597);
    //     }
    //     // val => panic!("Expected subject header found: {:?}", val),
    //     // None => {}
    //     None => {}
    // }

    let msg = email.get_dkim_message();
    panic!("dkim_msg: {:?}", msg);
}
// #[test]
// fn test_email_parser() {
// let email_bytes: &[u8] = include_bytes!("./gmail_cn.eml");
// println!("{:?}", email_bytes);
// let emailstr = std::fs::read_to_string("src/tests/gmail_cn.eml").unwrap();
// let email = Email::parse(email_bytes).unwrap();

// let from = email.unknown_fields.iter().last();

// println!("{:?}", from);
// }

#[test]
fn test_header_decode() {
    {
        let emailstr: &str = include_str!("./test_email.eml");
        let email = Email::from_str(emailstr).unwrap();
        let subject = email.get_header_value("subject").unwrap();
        assert_eq!(
            subject,
            "转发 长长长长长0xba069a60f5b6e6ad758b877a79bad51731d6ca6b456fa93255c028939bd9b552"
        );
    }
    {
        let emailstr: &str =
            include_str!("./how to include the sender's email address in the email body_.eml");
        let email = Email::from_str(emailstr).unwrap();
        let subject = email.get_header_value("subject").unwrap();
        assert_eq!(
            subject,
            "转发：how to include the sender's email address in the email body?"
        );
    }
    {
        let emailstr: &str =
            include_str!("./how to include the sender's email address in the email body_ (1).eml");
        let email = Email::from_str(emailstr).unwrap();
        let subject = email.get_header_value("subject").unwrap();
        assert_eq!(
            subject,
            "转发：how to include the sender's email address in the email body?"
        );
    }
}
