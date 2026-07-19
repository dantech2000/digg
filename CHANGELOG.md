# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [0.4.0](https://github.com/dantech2000/digg/compare/v0.3.1...v0.4.0) (2026-07-19)


### Features

* accept TYPE&lt;N&gt; query syntax for arbitrary record types (RFC 3597) ([#55](https://github.com/dantech2000/digg/issues/55)) ([be380b0](https://github.com/dantech2000/digg/commit/be380b03234b76e91cd2d391ac6c56514ae7ce79)), closes [#37](https://github.com/dantech2000/digg/issues/37)
* add +compat flag for classic dig-style output ([#64](https://github.com/dantech2000/digg/issues/64)) ([0b8c613](https://github.com/dantech2000/digg/commit/0b8c613383bd3d725e4ca8f3ef0da9e86e3adf58)), closes [#33](https://github.com/dantech2000/digg/issues/33)
* add +nsid to request and display the server identifier (RFC 5001) ([#60](https://github.com/dantech2000/digg/issues/60)) ([027060a](https://github.com/dantech2000/digg/commit/027060a035581ae9b11da7e6a44858f72b2ae4b9)), closes [#36](https://github.com/dantech2000/digg/issues/36)
* add +qr and +stats/+nostats output toggles ([#62](https://github.com/dantech2000/digg/issues/62)) ([a0648e0](https://github.com/dantech2000/digg/commit/a0648e0d303ab4ca043251f3a23608c0667b30a0)), closes [#42](https://github.com/dantech2000/digg/issues/42)
* add +retry=N for UDP query retries ([#61](https://github.com/dantech2000/digg/issues/61)) ([78055a7](https://github.com/dantech2000/digg/commit/78055a71c7cbbdd28bd9e9f582f2e877f33bba99)), closes [#41](https://github.com/dantech2000/digg/issues/41)
* add +tsv machine-readable tabular output ([#63](https://github.com/dantech2000/digg/issues/63)) ([c6f67be](https://github.com/dantech2000/digg/commit/c6f67bef047522b258edc202319f44797ae448fa)), closes [#32](https://github.com/dantech2000/digg/issues/32)
* add +validate for local DNSSEC chain-of-trust validation ([#70](https://github.com/dantech2000/digg/issues/70)) ([681bb43](https://github.com/dantech2000/digg/commit/681bb43e275b13b579d97522289177be00662e3e)), closes [#39](https://github.com/dantech2000/digg/issues/39)
* add shell completions (bash/zsh/fish) ([#69](https://github.com/dantech2000/digg/issues/69)) ([cbf4850](https://github.com/dantech2000/digg/commit/cbf48503c6d441872d180f30840695ad44959ff0)), closes [#11](https://github.com/dantech2000/digg/issues/11)
* IDN support — punycode-encode Unicode domain names ([#65](https://github.com/dantech2000/digg/issues/65)) ([be658f1](https://github.com/dantech2000/digg/commit/be658f16294384b541719c28b1bee0c9d5899186)), closes [#38](https://github.com/dantech2000/digg/issues/38)
* support EDNS Client Subnet via +subnet=ADDR[/PREFIX] (RFC 7871) ([#59](https://github.com/dantech2000/digg/issues/59)) ([c4d8592](https://github.com/dantech2000/digg/commit/c4d8592b4d7b425752d598c4595e55ca31681f11)), closes [#34](https://github.com/dantech2000/digg/issues/34)
* support query classes beyond IN (CH/HS/ANY, -c flag) ([#57](https://github.com/dantech2000/digg/issues/57)) ([d305a46](https://github.com/dantech2000/digg/commit/d305a46cb3a771e167dd219fa4de1d77f061252c)), closes [#35](https://github.com/dantech2000/digg/issues/35)


### Bug Fixes

* gate unused Question::new constructor to test builds ([#58](https://github.com/dantech2000/digg/issues/58)) ([a3053a0](https://github.com/dantech2000/digg/commit/a3053a07f0a85718bc059ed3bdd61e30da5a76ed))

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
