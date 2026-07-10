# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

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
