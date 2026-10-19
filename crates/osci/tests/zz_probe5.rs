//! Replicates the legacy-dialect framing search exactly.

#[test]
fn probe_legacy_search() {
    let inner_signed = b"MIME-Version: 1.0\r\nContent-Type: text/xml\r\n\r\n<xml/>";
    let recipient =
        osci_crypto::Certificate::from_der(&cert_der_fn("osci_manager_cipher_4096.pem")).unwrap();
    let outer = osci::security::encrypt_message_for(
        inner_signed,
        &recipient,
        &osci::security::EncryptConfig::default(),
        "MIME_boundary",
    )
    .unwrap();

    println!("outer len: {}", outer.len());
    let marker = b"Content-ID: <osci_enc>\r\n\r\n";
    let content_start = outer
        .windows(marker.len())
        .position(|w| w == marker)
        .unwrap()
        + marker.len();
    println!("content_start: {content_start}");

    let end_search = outer[content_start..]
        .windows(5)
        .position(|w| w == b"\r\n--");
    println!("content_end search: {end_search:?}");

    // print every \r\n-- occurrence in the whole outer
    let mut i = 0;
    while i + 5 <= outer.len() {
        if &outer[i..i + 5] == b"\r\n--" {
            println!(
                "crlf-dashdash at {i}: {:?}",
                &outer[i..(i + 30).min(outer.len())]
            );
        }
        i += 1;
    }

    // and the search over the FULL slice for comparison
    println!(
        "full-slice search: {:?}",
        outer.windows(5).position(|w| w == b"\r\n--")
    );
    println!("last 30 bytes: {:?}", &outer[outer.len() - 30..]);
    // where is the closing boundary really?
    let close = outer.windows(17).position(|w| w == b"--MIME_boundary--");
    println!("closing marker at: {close:?} (outer len {})", outer.len());
    if let Some(c) = close {
        println!("bytes [{}..{}]: {:?}", c - 5, c + 17, &outer[c - 5..c + 17]);
    }
    // where does the XML part really end?
    let xml_part_end = outer
        .windows(24)
        .position(|w| w == b"</soap:Body></soap:Envelope>");
    println!("xml part end marker at: {xml_part_end:?}");
}

fn cert_der_fn(pem: &str) -> Vec<u8> {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap()
        .to_path_buf();
    let dump = std::fs::read_to_string(root.join("testcorpus/certs").join(pem)).unwrap();
    let start = dump.find("-----BEGIN CERTIFICATE-----").unwrap();
    let after = &dump[start + 27..];
    let end = after.find("-----END CERTIFICATE-----").unwrap();
    let b64: String = after[..end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    osci_core::helper::base64::decode(&b64).unwrap()
}
