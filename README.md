# Airlock-MCP

A security-first pass-through proxy for the [Model Context Protocol](https://modelcontextprotocol.io/). Airlock sits between your AI host (VS Code, Claude Desktop) and any MCP server, enforcing configurable security policies before forwarding requests.

```
AI Host (VS Code / Claude Desktop)
        |
        v
  [ Airlock-MCP ]  <-- security checks run here
        |
        v
  Target MCP Server (filesystem, database, API, etc.)
```

## Why

MCP servers can expose powerful tools - file system access, shell execution, database queries. Airlock lets you run them without handing the AI unrestricted access:

- **Allowlist tools** by name - deny everything else by default
- **Block dangerous shell patterns** before they reach the server
- **Scope filesystem access** to specific directories
- **Rate-limit** tool calls globally or per tool
- **Reject oversized payloads** before they hit the target
- **Redact PII** from responses before they reach the model

All checks run in order, fail-safe, and every decision is logged.

---

## Install

```bash
npm install -g airlock-mcp
```

Or run without installing:

```bash
npx airlock-mcp --config airlock.config.json
```

---

## Quick start

**1. Create `airlock.config.json`:**

```json
{
  "targetCommand": "npx",
  "targetArgs": ["-y", "@modelcontextprotocol/server-filesystem", "/home/user/projects"],
  "allowedTools": ["read_file", "list_directory", "search_files"],
  "allowedPaths": ["/home/user/projects"],
  "blockDangerousCommands": true,
  "logging": { "level": "info", "destination": "stdout" }
}
```

**2. Point your AI host at Airlock** (see [Host integration](#host-integration) below).

---

## Host integration

### VS Code (Copilot / MCP extension)

In `.vscode/mcp.json` or user `settings.json`:

```json
{
  "mcpServers": {
    "secure-filesystem": {
      "command": "npx",
      "args": ["airlock-mcp", "--config", "/absolute/path/to/airlock.config.json"]
    }
  }
}
```

### Claude Desktop

In `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "secure-filesystem": {
      "command": "npx",
      "args": ["airlock-mcp", "--config", "/absolute/path/to/airlock.config.json"]
    }
  }
}
```

---

## Security checks

Every `tools/call` request passes through these checks in order. A failure at any step returns an error and the request is never forwarded.

| # | Check | Config field | Default |
|---|-------|-------------|---------|
| 1 | Tool allowlist | `allowedTools` | deny all |
| 2 | Dangerous command patterns | `blockDangerousCommands` | enabled |
| 3 | Path scoping | `allowedPaths` | allow all |
| 4 | Rate limiting | `rateLimiting` | disabled |
| 5 | Request size | `sizeLimits` | disabled |
| 6 | Response size | `sizeLimits` | disabled |
| 7 | PII redaction | `piiRedaction` | disabled |

`resources/read` requests are checked against `allowedResources` (URI prefix allowlist).

---

## Configuration reference

### Target server

Exactly one of `targetCommand` or `targetUrl` is required.

```jsonc
{
  // Spawn a local MCP server over stdio
  "targetCommand": "npx",
  "targetArgs": ["-y", "@modelcontextprotocol/server-filesystem", "/tmp"],
  "targetEnv": { "MY_VAR": "value" },  // optional env vars for the child process

  // OR connect to a remote HTTP MCP server
  "targetUrl": "https://my-mcp-server.example.com"
}
```

---

### Tool allowlist

```jsonc
{
  // Only these tools are forwarded. Everything else is blocked.
  // Empty array (the default) blocks all tools.
  "allowedTools": ["read_file", "list_directory", "search_files"]
}
```

---

### Resource allowlist

```jsonc
{
  // resources/read URIs must start with one of these prefixes.
  // Empty array (the default) blocks all resources.
  "allowedResources": ["mcp://public/", "mcp://logs/"]
}
```

---

### Path scoping

```jsonc
{
  // Tool arguments containing filesystem paths must resolve inside one
  // of these directories. URL-encoding is decoded and symlinks are
  // followed before checking, so traversal tricks don't work.
  // Empty array (the default) skips path checking entirely.
  "allowedPaths": ["/home/user/projects", "/tmp/workspace"]
}
```

---

### Dangerous command blocking

```jsonc
{
  // Scan tool arguments for shell operators and dangerous commands:
  // &&, pipes, semicolons before rm/sudo/curl/etc., backticks, $().
  // Default: true
  "blockDangerousCommands": true
}
```

---

### Rate limiting

Disabled by default. Uses a sliding window - timestamps older than `windowMs` are pruned on each check. Blocked requests do not consume quota.

```jsonc
{
  "rateLimiting": {
    "enabled": true,
    "windowMs": 60000,       // sliding window in ms (default: 60 000)
    "maxRequests": 100,      // max allowed calls per window, globally

    // Per-tool overrides - inherits global windowMs/maxRequests if omitted
    "perTool": {
      "write_file": { "maxRequests": 10 },
      "execute_command": { "windowMs": 10000, "maxRequests": 3 }
    }
  }
}
```

---

### Payload size limits

Disabled by default. Request size is measured as the UTF-8 byte length of the JSON-serialised arguments. Response size is the sum of all `text` content items.

```jsonc
{
  "sizeLimits": {
    "enabled": true,
    "maxRequestBytes": 1048576,    // 1 MB  (default)
    "maxResponseBytes": 10485760   // 10 MB (default)
  }
}
```

---

### PII redaction

Disabled by default. Scans tool and resource response text and replaces matches with typed placeholders like `[SSN:REDACTED]`.

```jsonc
{
  "piiRedaction": {
    "enabled": true,

    // Optional: list specific patterns to apply.
    // Omit to use the default set (marked below).
    "patterns": ["ssn", "credit_card", "api_key", "email"]
  }
}
```

**Available patterns:**

| Pattern | Detects | On by default |
|---------|---------|:---:|
| `ssn` | US Social Security Numbers | yes |
| `credit_card` | Credit/debit card numbers | yes |
| `bank_account` | Bank account numbers (near keywords) | no |
| `api_key` | API keys and tokens (`sk-`, `pk-`, etc.) | yes |
| `aws_key` | AWS access key IDs (`AKIA...`) | yes |
| `password` | Passwords in config/log format | yes |
| `private_key` | PEM private key blocks | yes |
| `jwt` | JSON Web Tokens | yes |
| `connection_string` | Database connection strings | yes |
| `email` | Email addresses | yes |
| `phone` | Phone numbers | no |
| `ip_address` | IPv4 addresses | no |
| `iban` | International bank account numbers | no |
| `swift` | SWIFT/BIC codes | no |
| `internal_url` | Internal/corp/staging URLs | no |

---

### Logging

```jsonc
{
  "logging": {
    "level": "info",           // "debug" | "info" | "warn" | "error"
    "destination": "stdout",   // "stdout" | "file"
    "filePath": "/var/log/airlock.log"  // required when destination is "file"
  }
}
```

Logs are structured JSON ([pino](https://getpino.io/)). Security decisions (allow/deny) are logged at `info` or `warn` level for audit.

---

## Full example config

```json
{
  "targetCommand": "npx",
  "targetArgs": ["-y", "@modelcontextprotocol/server-filesystem", "/home/user/projects"],
  "allowedTools": [
    "read_file",
    "write_file",
    "list_directory",
    "search_files"
  ],
  "allowedResources": ["mcp://public/"],
  "allowedPaths": ["/home/user/projects"],
  "blockDangerousCommands": true,
  "rateLimiting": {
    "enabled": true,
    "windowMs": 60000,
    "maxRequests": 200,
    "perTool": {
      "write_file": { "maxRequests": 20 }
    }
  },
  "sizeLimits": {
    "enabled": true,
    "maxRequestBytes": 1048576,
    "maxResponseBytes": 10485760
  },
  "piiRedaction": {
    "enabled": true,
    "patterns": ["api_key", "password", "private_key", "jwt", "connection_string"]
  },
  "logging": {
    "level": "info",
    "destination": "stdout"
  }
}
```

---

## Security design principles

- **Deny by default** - empty `allowedTools` or `allowedResources` blocks everything
- **No information disclosure** - blocked-tool errors do not reveal the allowlist
- **Fail-safe** - any validation error blocks the request; nothing falls through
- **No quota consumption on blocked requests** - rate-limit budget is only spent on forwarded calls
- **Config validated at startup** via Zod - the proxy won't start with an invalid config

---

## Development

```bash
npm install
npm run dev -- --config airlock.config.json   # run with ts-node (no build needed)
npm run build                                  # compile TypeScript -> dist/
npm test                                       # unit tests (vitest)
npm run test:watch                             # watch mode
npm run test:integration                       # integration tests (spawns processes)
npm run typecheck                              # type check without emitting
```

To run a single test file:

```bash
npx vitest run src/test/guard.test.ts
```

---

## License

MIT
