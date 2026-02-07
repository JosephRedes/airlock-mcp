# Airlock-MCP

[![CI](https://github.com/JosephRedes/airlock-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/JosephRedes/airlock-mcp/actions/workflows/ci.yml)
[![npm version](https://badge.fury.io/js/airlock-mcp.svg)](https://badge.fury.io/js/airlock-mcp)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

> Security-first pass-through proxy for Model Context Protocol

**Status**: ✅ All Phases Complete

---

## What It Does

Airlock-MCP sits between your AI (VS Code, Claude Desktop) and any MCP server, acting as a security guard that:

1. ✅ **Forwards messages** transparently
2. ✅ **Blocks unauthorized tools** via allowlist
3. ✅ **Restricts resource access** via URI prefix matching
4. ✅ **Blocks command injection** (`&&`, `|`, `;`, `rm`, `sudo`)
5. ✅ **Scopes file paths** to allowed directories
6. ✅ **Redacts PII** from responses (SSN, credit cards, API keys)

---

## Quick Start

### 1. Install dependencies
```bash
npm install
```

### 2. Build the project
```bash
npm run build
```

### 3. Create a configuration file

Example `airlock.config.json`:
```json
{
  "targetCommand": "npx",
  "targetArgs": [
    "-y",
    "@modelcontextprotocol/server-filesystem",
    "/absolute/path/to/secure/folder"
  ],
  "allowedTools": ["read_file", "list_directory"],
  "allowedResources": ["mcp://public/"],
  "allowedPaths": ["/absolute/path/to/secure/folder"],
  "blockDangerousCommands": true,
  "logging": {
    "level": "info",
    "destination": "stdout"
  }
}
```

### 4. Run the proxy
```bash
node dist/index.js --config airlock.config.json
```

---

## Using with VS Code

Add to `.vscode/mcp.json`:
```json
{
  "mcpServers": {
    "secure-filesystem": {
      "command": "node",
      "args": [
        "C:\\Users\\josep\\OneDrive\\Documents\\pancake\\dist\\index.js",
        "--config",
        "C:\\Users\\josep\\OneDrive\\Documents\\pancake\\airlock.config.json"
      ]
    }
  }
}
```

---

## Security Features

| Feature | Status | Description |
|---------|--------|-------------|
| **Tool Allowlist** | ✅ Implemented | Only explicitly allowed tools can be called |
| **Resource Allowlist** | ✅ Implemented | Prefix matching for `mcp://` URIs |
| **Path Scoping** | ✅ Implemented | Validates paths stay in allowed directories (symlink-safe) |
| **Command Blocklist** | ✅ Implemented | Blocks `&&`, `|`, `;`, `rm`, `sudo`, `$()` |
| **PII Redaction** | ✅ Implemented | Auto-redact SSN, credit cards, API keys from responses |
| **Audit Logging** | ✅ Implemented | All requests/decisions logged in structured JSON |
| **Fail-Safe Defaults** | ✅ Implemented | Empty allowlists = deny all |

---

## Configuration Reference

```json
{
  "targetCommand": "npx",           // Command to spawn target server
  "targetArgs": [],                 // Arguments for target command
  "targetEnv": {},                  // Optional environment variables
  "allowedTools": [],               // SECURITY: Tools allowed to execute
  "allowedResources": [],           // SECURITY: Resource URI prefixes allowed
  "allowedPaths": [],               // SECURITY: Filesystem paths allowed (empty = no restriction)
  "blockDangerousCommands": true,   // SECURITY: Block shell operators
  "piiRedaction": {
    "enabled": true,                // Enable PII scanning on responses
    "patterns": [                   // Optional: specify patterns (defaults to all)
      "ssn", "credit_card", "api_key", "email", "phone"
    ]
  },
  "logging": {
    "level": "info | debug | warn | error",
    "destination": "stdout | file",
    "filePath": "./logs/airlock.log"
  }
}
```

---

## Threat Mapping

This project addresses threats documented in the [CSA MCP Security TTPs](https://modelcontextprotocol-security.io/ttps/) framework.

| Airlock Control | CSA TTP Category | Status |
|-----------------|------------------|--------|
| `blockDangerousCommands` | Command & Code Injection | ✅ Addressed |
| `allowedTools` + `allowedPaths` | Privilege & Access Control | ✅ Addressed |
| `piiRedaction` | Data Exfiltration & Credential Theft | ✅ Addressed |
| Structured logging | Monitoring & Operational Security | ✅ Addressed |

📄 **[Full Threat Mapping →](./THREAT_MAPPING.md)**

---

## Documentation

- **[CODE_GUIDE.md](./CODE_GUIDE.md)** - Detailed explanation of how the code works
- **[SPECIFICATION.md](./SPECIFICATION.md)** - Full specification including future phases
- **[THREAT_MAPPING.md](./THREAT_MAPPING.md)** - CSA TTP mapping for security teams

---

## Security Best Practices Used

1. **Fail-Safe Defaults** - Deny by default (empty allowlist blocks all)
2. **Least Privilege** - Allowlist instead of blocklist
3. **Input Validation** - Zod schema validation at startup
4. **Audit Logging** - Every decision logged with structured data
5. **No Information Disclosure** - Errors don't leak allowlist
6. **Process Isolation** - Clean shutdown prevents orphans

---

## Development

### Run in development mode
```bash
npm run dev -- --config airlock.config.json
```

### Build
```bash
npm run build
```

### Run integration tests
```bash
npx tsx src/test/integration.ts
```

---

## License

MIT
