# osci-rust-rewrite

A from-scratch Rust implementation of the **OSCI-Transport 1.2** client
library, developed test-first against the Java reference implementation
[governikus/osci-bib-java](https://gitlab.opencode.de/governikus/osci/osci-bib-java)
(pinned to tag **2.6.1**, commit `f2e4a6a`).

Status: **all milestones complete (M0–M9)** — helpers, XML/C14N, crypto,
headers, all 24 message types (parse + compose + stored re-parse +
chunking), signature/encryption integration, dialog state machine, HTTP
transport, samples, and hardening. 131+ tests green against the golden
corpus; the Java reference verifies the output of every layer.

## Layout

| Path | Purpose |
|---|---|
| `crates/osci-core` | Message model, MIME, ISO dates, swap buffer, SOAP/XML codec, **restricted C14N 1.0 canonicalizer**, message types |
| `crates/osci-crypto` | `Signer`/`Decrypter` SPI, algorithm registry, streaming AES-GCM/CBC/3DES, weak-key policy |
| `crates/osci-transport` | `Transport` SPI, loopback mock, HTTP (ureq) |
| `crates/osci` | Facade: `Dialog` state machine, `security` (verify/decrypt), `sign` |
| `crates/osci-samples` | Ported sample programs (`cargo run -p osci-samples --example one_way_message`) |
| `testcorpus/` | Golden fixtures, certs, XSDs (see `testcorpus/ORIGIN.md`) |
| `oracle/` | Java CLI harness (canonize/validate/verify/spike) |
| `fuzz/` | libFuzzer targets for the four parsers |
| `reference/` | Pinned Java reference clone (not committed) |
| `tools/` | Local JDK 11 + Maven (not committed) |

## Getting started

```sh
make corpus            # reference clone + fixture extraction
make oracle            # compile the Java oracle (needs bcprov in ~/.m2)
make test              # cargo test --workspace (oracle tests skip if oracle absent)
make lint              # fmt --check + clippy -D warnings
cargo run -p osci-samples --example one_way_message   # end-to-end sample
```

## Verification model

Every layer is gated against the pinned reference:

1. **Unit ports** — the JUnit suites of the reference (`TestBase64*`,
   `TestMIMEParser`, `TestIsoDateParsing`, `TestSwapBuffer`,
   `TestCanonizer`, `TestCrypto`, `TestSymCipher*`, `TestSwapBuffer`)
   ported byte-for-byte.
2. **Golden corpus** — ~50 `.osci` wire fixtures must parse, round-trip
   and (signed) verify; every `ds:Reference` digest checked against the
   recorded `DigestValue`s; every `xenc:EncryptedData` decrypts with the
   corpus keys.
3. **Attack corpus** — XXE, signature-wrapping 2–4, CBC/GCM tamper and
   corrupt-signature fixtures must be *detected*.
4. **Java oracle differential testing** — canonical bytes, digest maps,
   `SignedInfo` captures and XSD verdicts compared byte-for-byte /
   verdict-for-verdict; our signed messages must pass the reference
   library's own `loadMessageCheckingSignature`, tampered ones must be
   rejected by it.

## Parity checklist (vs the 2.6.1 reference)

- [x] Streaming Base64 (76-char LF layout incl. trailing break at boundaries)
- [x] MIME multipart parser (lenient headers, CRLF boundary markers, 1 MB line cap)
- [x] ISO-8601 dates (2.4.7 millisecond-trimming semantics)
- [x] SwapBuffer (RAM → AES-GCM-encrypted temp file, repeatable reads)
- [x] XXE-safe XML tree parser (DOCTYPE rejected, Xerces normalization)
- [x] Restricted C14N 1.0 canonicalizer with inline digesting (byte-exact vs reference)
- [x] Signer/Decrypter SPI + software RSA (PSS/v1.5); ECDSA raw r‖s sign primitives only (not wired into message verification)
- [x] Algorithm registry (all digests incl. SHA-3/RIPEMD-160, AES-GCM/CBC, 3DES, OAEP/v1.5)
- [x] Weak-key policy (all `TestCrypto` dates)
- [x] Streaming symmetric ciphers (`[IV][ct]` wire format, tag verification)
- [x] SOAP headers (ControlBlock, certificate headers, QualityOfTimestamp, DesiredLanguages, FeatureDescription, custom)
- [x] All 24 message types: recognition, parse, compose (XSD-VALID)
- [x] StoredMessage load/store, passive-recipient DialogFinder
- [x] Chunking (partial store/fetch, both wire shapes)
- [x] MessageMetaData extension header
- [x] Transport + content signature composition (two-pass) and verification
- [x] EncryptedData decryption pipelines
- [x] Dialog state machine (challenge/response, conversation; sequence is echo-compared only)
- [x] Loopback + HTTP transports
- [x] Sample program
- [ ] RSA-PSS P-384 ECDSA signing path (P-256 verified; P-384 sign trait ready)
- [ ] Real-intermediary smoke test against gov.test.osci.de (needs network/live system)

## Known deviations

- Default SwapBuffer limit is a fixed 4 MiB (no JVM free-heap equivalent).
- `DialogHandler` mutable statics became an owned `Dialog` context.
- Legacy-certificate keystores are consumed as openssl PEM dumps; PKCS#12
  parsing is intentionally out of scope (test-only conversion in
  `scripts/extract-testcorpus.sh`).
- Pure-Rust `rsa` inherits RUSTSEC-2023-0071 (Marvin) on v1.5 unwrap —
  the same exposure class as BouncyCastle; document for legacy interop.

## Notes

- **License**: MIT OR Apache-2.0 (upstream is EUPL-1.2 OR MIT).
- **Ecosystem**: FITKO's `osci-transport-rs` (EUPL, Matrix G2X) exists —
  watch/coordinate.
