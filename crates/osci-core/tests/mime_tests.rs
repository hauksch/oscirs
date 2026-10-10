//! Port of `de.osci.helper.TestMIMEParser`, strengthened with the golden
//! corpus fixtures.

mod common;

use std::io::Read;

use osci_core::helper::mime::MimeParser;

/// Port of `testMimeParser`: files with LF and CRLF formats parse.
#[test]
fn constructor_accepts_lf_and_crlf_files() {
    for name in ["StoreDeliveryLF.osci", "StoreDeliveryCRLF.osci"] {
        let bytes = std::fs::read(common::message(name)).unwrap();
        let parser = MimeParser::new(&bytes[..]).unwrap();
        assert_eq!(parser.boundary(), "MIME_boundary", "{name}");
    }
}

/// Full part walk over the CRLF golden fixture `StoreDelivery.osci`.
#[test]
fn parses_store_delivery_parts() {
    let bytes = std::fs::read(common::message("StoreDelivery.osci")).unwrap();
    let mut parser = MimeParser::new(&bytes[..]).unwrap();

    let mut part = parser.next_part().unwrap().expect("part 1");
    assert_eq!(part.content_type(), "text/xml");
    assert_eq!(part.content_id(), "osci@message");
    assert_eq!(part.encoding(), Some("8bit"));
    assert_eq!(part.length(), -1);
    let mut xml = Vec::new();
    part.read_to_end(&mut xml).unwrap();
    let xml = String::from_utf8(xml).unwrap();
    assert!(
        xml.starts_with("<?xml"),
        "part 1 content starts with the XML"
    );
    assert!(
        xml.trim_end().ends_with("</soap:Envelope>")
            || xml.trim_end().ends_with("</pups:Envelope>"),
        "part 1 content ends with the closing envelope tag"
    );
    assert!(
        !xml.contains("--MIME_boundary"),
        "boundary leaked into content"
    );
    drop(part);

    let mut part = parser.next_part().unwrap().expect("part 2");
    assert_eq!(part.content_type(), "application/octet-stream");
    assert_eq!(part.content_id(), "test.txt");
    assert_eq!(part.encoding(), Some("base64"));
    assert_eq!(part.length(), 8);
    let mut content = String::new();
    part.read_to_string(&mut content).unwrap();
    assert_eq!(content.trim_end(), "dGVzdA==");
    drop(part);

    assert!(parser.next_part().unwrap().is_none(), "closing boundary");
}

/// Java behavior: after the end of the multipart body, another
/// `getNextStream()` raises a format error.
#[test]
fn second_next_part_after_end_is_an_error() {
    let bytes = std::fs::read(common::message("StoreDelivery.osci")).unwrap();
    let mut parser = MimeParser::new(&bytes[..]).unwrap();
    while parser.next_part().unwrap().is_some() {
        // drain parts
    }
    assert!(parser.next_part().is_err());
}

/// Quirk port: LF-only files parse their headers, but part content cannot
/// be delimited (the marker starts with CRLF), yielding "EOS before marker".
#[test]
fn lf_only_parts_hit_eos_before_marker() {
    let bytes = std::fs::read(common::message("test.mime")).unwrap();
    let mut parser = MimeParser::new(&bytes[..]).unwrap();
    assert_eq!(parser.boundary(), "MIME_boundary");

    let mut part = parser.next_part().unwrap().expect("part 1 headers");
    assert_eq!(part.content_id(), "osci@message");
    let mut sink = Vec::new();
    let err = part
        .read_to_end(&mut sink)
        .expect_err("LF-only part must hit EOS before marker");
    assert!(err.to_string().contains("EOS before marker"), "{err}");
}

/// `mailapi.mime`: quoted boundary parameter, header folding in the outer
/// header block, part Content-IDs without angle brackets.
#[test]
fn folded_headers_and_quoted_boundary() {
    let bytes = std::fs::read(common::message("mailapi.mime")).unwrap();
    let mut parser = MimeParser::new(&bytes[..]).unwrap();
    assert_eq!(parser.boundary(), "----=_Part_0_12122157.1169810284484");

    let part = parser.next_part().unwrap().expect("part 1");
    assert_eq!(part.content_id(), "bumms");
    assert_eq!(part.content_type(), "text/plain");
    assert_eq!(part.encoding(), Some("7bit"));
    assert!(
        part.finish().is_err(),
        "LF-only part cannot be drained to a marker"
    );
}

/// Synthetic CRLF multipart covering folding, quoted values, charset and
/// content-length, with a byte-exact expected part content.
#[test]
fn synthetic_multipart_roundtrip() {
    let mime = concat!(
        "MIME-Version: 1.0\r\n",
        "Content-Type: multipart/mixed; boundary=\"BB\"\r\n",
        "\r\n",
        "--BB\r\n",
        "Content-Type: text/xml;\r\n",
        " charset=UTF-8\r\n",
        "Content-ID: <a@b>\r\n",
        "\r\n",
        "hello\r\n",
        "world\r\n",
        "--BB\r\n",
        "Content-Type: application/pdf\r\n",
        "Content-ID: <c>\r\n",
        "Content-Length: 3\r\n",
        "\r\n",
        "abc\r\n",
        "--BB--\r\n",
        "epilogue junk",
    );
    let mut parser = MimeParser::new(mime.as_bytes()).unwrap();
    assert_eq!(parser.boundary(), "BB");

    let mut part = parser.next_part().unwrap().expect("part 1");
    assert_eq!(part.content_type(), "text/xml");
    assert_eq!(part.content_id(), "a@b");
    let mut content = Vec::new();
    part.read_to_end(&mut content).unwrap();
    assert_eq!(content, b"hello\r\nworld");
    drop(part);

    let mut part = parser.next_part().unwrap().expect("part 2");
    assert_eq!(part.content_type(), "application/pdf");
    assert_eq!(part.content_id(), "c");
    assert_eq!(part.length(), 3);
    let mut content = Vec::new();
    part.read_to_end(&mut content).unwrap();
    assert_eq!(content, b"abc");
    drop(part);

    assert!(parser.next_part().unwrap().is_none());
}

#[test]
fn missing_boundary_is_format_error() {
    let mime = "Content-Type: text/xml\r\n\r\n";
    assert!(MimeParser::new(mime.as_bytes()).is_err());
}

#[test]
fn wrong_mime_version_rejected() {
    let mime = "MIME-Version: 2.0\r\nContent-Type: multipart/mixed; boundary=B\r\n\r\n";
    assert!(MimeParser::new(mime.as_bytes()).is_err());
}

#[test]
fn empty_input_rejected() {
    assert!(MimeParser::new("".as_bytes()).is_err());
}

#[test]
fn part_without_content_type_rejected() {
    let mime = "Content-Type: multipart/mixed; boundary=B\r\n\r\n--B\r\nContent-ID: <x>\r\n\r\n";
    let mut parser = MimeParser::new(mime.as_bytes()).unwrap();
    assert!(parser.next_part().is_err());
}

#[test]
fn part_with_wrong_charset_rejected() {
    let mime = concat!(
        "Content-Type: multipart/mixed; boundary=B\r\n\r\n",
        "--B\r\nContent-Type: text/xml; charset=iso-8859-1\r\nContent-ID: <x>\r\n\r\n",
        "x\r\n--B--\r\n"
    );
    let mut parser = MimeParser::new(mime.as_bytes()).unwrap();
    let err = parser.next_part().expect_err("charset must be rejected");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn missing_content_id_rejected() {
    let mime = concat!(
        "Content-Type: multipart/mixed; boundary=B\r\n\r\n",
        "--B\r\nContent-Type: text/xml\r\n\r\n",
        "x\r\n--B--\r\n"
    );
    let mut parser = MimeParser::new(mime.as_bytes()).unwrap();
    assert!(parser.next_part().is_err());
}

/// A part boundary split across refill boundaries still delimits correctly
/// (each read returns only a few bytes).
#[test]
fn marker_split_across_reads() {
    let mime = concat!(
        "Content-Type: multipart/mixed; boundary=BOUND\r\n\r\n",
        "--BOUND\r\nContent-Type: text/xml\r\nContent-ID: <x>\r\n\r\n",
        "0123456789\r\n--BOUND--\r\n"
    );
    let mut parser = MimeParser::new(mime.as_bytes()).unwrap();
    let mut part = parser.next_part().unwrap().expect("part");
    let mut content = Vec::new();
    // read in tiny slices to force the marker across refills
    let mut buf = [0u8; 3];
    loop {
        let n = part.read(&mut buf).unwrap();
        if n == 0 {
            break;
        }
        content.extend_from_slice(&buf[..n]);
    }
    assert_eq!(content, b"0123456789");
}

/// Content that legitimately contains the boundary string without the
/// preceding CRLF does not terminate the part.
#[test]
fn boundary_text_without_crlf_is_content() {
    let mime = concat!(
        "Content-Type: multipart/mixed; boundary=B\r\n\r\n",
        "--B\r\nContent-Type: text/xml\r\nContent-ID: <x>\r\n\r\n",
        "xx--B yy\n--B zz\r\n--B--\r\n"
    );
    let mut parser = MimeParser::new(mime.as_bytes()).unwrap();
    let mut part = parser.next_part().unwrap().expect("part");
    let mut content = Vec::new();
    part.read_to_end(&mut content).unwrap();
    assert_eq!(content, b"xx--B yy\n--B zz");
}
