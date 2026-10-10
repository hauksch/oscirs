# osci-rust-rewrite

A from-scratch Rust implementation of the **OSCI-Transport 1.2** client
library, currently being developed test-first against the Java reference
implementation [governikus/osci-bib-java](https://gitlab.opencode.de/governikus/osci/osci-bib-java)
(pinned to tag **2.6.1**, commit `f2e4a6a`).

Status: **Milestone M0 (groundwork) complete.**

- Java reference builds green (`mvn verify`) and serves as the
  differential-testing oracle.
- The golden test corpus (wire-format fixtures, attack corpus, test
  certificates/keystores, XSD schemas) is extracted into `testcorpus/`.
- The crypto foundation is proven interoperable in both directions:
  BouncyCastle RSA-PSS (`SHA256withRSAandMGF1`) signatures verify with
  RustCrypto `rsa::pss`, BouncyCastle RSA-OAEP wraps open with `rsa::Oaep`,
  and the reverse directions pass through the Java oracle
  (`crates/osci-crypto/tests/spike_cross_verify.rs`).

## Layout

| Path | Purpose |
|---|---|
| `crates/osci-core` | Message model, SOAP/XML codec, C14N, MIME, helpers |
| `crates/osci-crypto` | `Signer`/`Decrypter` SPI + software implementation |
| `crates/osci-transport` | `Transport` SPI + HTTP implementation |
| `crates/osci` | Facade: DialogHandler, roles, dialogs, messages |
| `crates/osci-samples` | Ported sample programs |
| `testcorpus/` | Extracted fixtures, certs, XSDs (see `testcorpus/ORIGIN.md`) |
| `oracle/` | Java CLI harness for differential testing |
| `reference/` | Pinned Java reference clone (not committed) |
| `tools/` | Local JDK 11 + Maven (not committed) |
| `scripts/` | fetch-reference, extract-testcorpus, build-oracle |

## Getting started

```sh
# one-time: local JDK 11 + Maven (skip if you have them on PATH/JAVA_HOME)
#   see tools/env.sh for the expected layout
make corpus            # reference clone + fixture extraction
make oracle            # compile the Java oracle harness (needs bcprov in ~/.m2)
make test              # cargo test --workspace (includes Java cross-verification)
make lint              # fmt --check + clippy -D warnings
```

The Java oracle is invoked from Rust tests via `$OSCI_JAVA` or
`tools/jdk11/bin/java`; the corpus is found via `$OSCI_CORPUS` or
`./testcorpus`.

## Method

Test-driven, milestone-by-milestone (see the plan in the project history):

1. Port the JUnit tests of the reference as the unit-level spec.
2. Golden `.osci` wire fixtures must parse, re-serialize and (where signed or
   encrypted) verify/decrypt with the shipped test keys.
3. The attack corpus (XXE, signature wrapping, CBC attack, corrupt
   signatures) must be rejected.
4. The Java oracle provides a second opinion on newly composed output;
   comparisons are structural, never byte-wise.

## Notes

- **License**: MIT OR Apache-2.0. The upstream Java library is EUPL-1.2 OR
  MIT, so this licensing is unambiguous even for a faithful port. Extracted
  fixtures inherit the upstream licensing (see `testcorpus/ORIGIN.md`).
- **Ecosystem**: FITKO has scaffolded an empty `osci-transport-rs` repository
  (EUPL-1.2) under the Matrix G2X initiative; worth watching/coordinating.
- Known accepted risk: pure-Rust `rsa` is subject to RUSTSEC-2023-0071
  (Marvin attack) on PKCS#1 v1.5 decryption — the same exposure class the
  Java library has with BouncyCastle; documented for the legacy interop
  paths only.
