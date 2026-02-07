# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-02-07

### Added

#### Security Features
- **Tool Allowlist**: Only explicitly permitted tools can be called by the AI
- **Resource Allowlist**: Prefix-based filtering for MCP resource URIs
- **Path Scoping**: Symlink-safe file path validation with URL encoding protection
- **Command Blocklist**: Blocks dangerous shell operators (`&&`, `|`, `;`, `rm`, `sudo`, `$()`)
- **PII Redaction**: Automatic detection and redaction of 15+ sensitive data patterns
  - SSN, Credit Card, Bank Account
  - API Keys, AWS Keys, Passwords, Private Keys
  - JWT Tokens, Connection Strings
  - Email, Phone, IP Address
  - IBAN, SWIFT codes, Internal URLs

#### Infrastructure
- Transparent stdio-based MCP proxy
- Structured JSON logging with pino
- Graceful shutdown with process cleanup
- Zod-based configuration validation

#### Testing
- 30 unit tests covering security-critical code
- Integration test suite with 7 attack simulations
- GitHub Actions CI pipeline

### Security
- Fail-safe defaults (deny all by default)
- No information disclosure in error messages
- Audit logging for all security decisions
