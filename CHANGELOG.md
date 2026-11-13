# Changelog

Loose Keep-a-Changelog style; dates ISO-8601. History before 0.1.0 lives
in the milestone series (M0–M9) and `git log`.

## [Unreleased]

### Changed
- **CI moves to GitHub Actions** (the GitLab mirror keeps its config for
  now): `ci.yml` runs fmt/clippy/tests with the XSD gate against the
  vendored 2.6.1 schemas; `audit.yml` runs cargo-deny plus a CycloneDX
  SBOM artifact on a weekly schedule so RustSec advisories surface
  without commit activity. Dependabot handles cargo (workspace + fuzz)
  and github-actions updates in grouped weekly PRs.
- `rust-toolchain.toml` declares rustfmt/clippy components so fresh
  clones can run every gate.
- README: badge row, security & supply chain section, ecosystem links
  (rosci, safedir).

## [0.1.0] — 2026-10-18 — milestone series complete

M0–M9 as listed in the README parity checklist: all 24 message types
(parse + compose + stored re-parse + chunking), crypto integration,
dialog state machine, HTTP transport, samples, hardening, the Java
differential oracle, and the golden corpus. See `git log` for the
milestone commits.
