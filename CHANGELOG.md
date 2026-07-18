# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.3.1](https://github.com/dantech2000/digg/compare/v0.3.0...v0.3.1) (2026-07-18)


### Bug Fixes

* clear quarantine for Homebrew cask ([#23](https://github.com/dantech2000/digg/issues/23)) ([#24](https://github.com/dantech2000/digg/issues/24)) ([fe8e6c9](https://github.com/dantech2000/digg/commit/fe8e6c9dc6583078958af2a9df660e043b5a9e75))
* connect UDP socket and stop truncating large responses ([#28](https://github.com/dantech2000/digg/issues/28)) ([1d4f382](https://github.com/dantech2000/digg/commit/1d4f3820e2391766979cf6fc1e2f779cf77137fc))
* follow IPv6 glue in +trace and surface extended EDNS RCODEs ([#27](https://github.com/dantech2000/digg/issues/27)) ([e8b00ae](https://github.com/dantech2000/digg/commit/e8b00aeb7ce69a1d36c0a8aa533ad9a10c8fc216))
* harden DNS response parsing and resolve hostname server args ([#26](https://github.com/dantech2000/digg/issues/26)) ([e86557f](https://github.com/dantech2000/digg/commit/e86557fe256bbd0ce0a2c2ed85160b0e939cd2e8))
* NaN-safe bench sort, non-panicking serde output, document Quad9 DoH ([#29](https://github.com/dantech2000/digg/issues/29)) ([df29b13](https://github.com/dantech2000/digg/commit/df29b135a516c5ce06de2422a29cfcf9c1ed07cd))

## [Unreleased]

## [0.3.0] - 2026-07-10

### Added

- Deterministic DNS wire-format protocol tests, including compressed-name,
  EDNS, malformed-message, and `~/.diggrc` end-to-end coverage.
- `+color` and `+nocolor` display options, plus support for the `NO_COLOR`
  convention.
- GitHub Actions CI and tag-based release automation that publishes macOS
  archives and updates the Homebrew Cask.

### Changed

- Development checks now enforce formatting and Clippy warnings.

## [0.2.0]

### Added

- Standard DNS queries with IPv4 and IPv6 UDP/TCP transport, automatic reverse
  lookups, EDNS(0), and DNSSEC DO-bit support.
- DNS-over-HTTPS, DNS-over-TLS, delegation tracing, zone transfer, resolver
  comparison, propagation checks, benchmarking, batch input, and watch mode.
- Human-readable, terse, JSON, and YAML output for common and DNSSEC record
  types.
