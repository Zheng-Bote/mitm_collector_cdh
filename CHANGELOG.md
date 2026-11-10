# Changelog

All notable changes to the `mitm_collector_cdh` component will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The version is taken from the Git tag at build time (`git describe --tags`).

## [v0.2.0] - 2026-11-10

### Fixed
- Fatal errors are now sent with their actual message (instead of a generic text) as `failed` status event and as audit event (`ERROR: <message>`) to the scheduler, so they appear in `job_audit_logs`.
- Invalid job arguments are now also reported to the scheduler.

## [v0.1.0] - 2026-10-20

### Added
- **CDH Collector**: Initial implementation in Go 1.27 to retrieve a CDH dataset snapshot via the CNX OAuth2 machine-to-machine flow, encrypt it with the source DEK (AES-GCM) and write it atomically together with its SHA-256 snapshot cursor to `raw_ingestion` / `ingestion_cursors`.
