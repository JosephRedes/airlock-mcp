# Airlock-MCP Code Guide

This document explains how the code works, the security practices used, and how everything fits together.

## Project Structure

```
pancake/
├── src/
│   ├── index.ts      # Entry point - CLI parsing, starts proxy
│   ├── config.ts     # Configuration loading & validation (zod)
│   ├── logger.ts     # Structured logging setup (pino)
│   ├── guard.ts      # Security guard (Tools, Resources, Paths, Commands)
│   ├── redactor.ts   # PII detection & redaction (15+ patterns)
│   └── proxy.ts      # Core proxy logic (Server + Client)
├── src/test/
│   ├── integration.ts  # Automated integration tests
│   └── mock-server.ts  # Mock MCP server for testing
├── airlock.config.json       # Example configuration
├── package.json
└── tsconfig.json
```

## How It Works: The Flow

```
┌──────────┐         1. tools/call          ┌────────────┐
│ VS Code  │ ───────────────────────────▶   │  Airlock   │
│  (Host)  │                                 │            │
│          │                                 │  ┌──────┐  │
│          │                                 │  │Guard │  │
│          │                                 │  └───┬──┘  │
│          │                                 │      │     │
│          │                                 │   allowed? │
│          │   2a. Blocked (error)           │      │     │
│          │ ◀───────────────────────────────│      NO    │
│          │                                 │            │
│          │   2b. Forwarded                 │      YES   │
│          │                                 │      │     │
└──────────┘                                 │      ▼     │
                                             │  ┌──────┐  │
                3. Forward to target         │  │Client│  │
                 ◀───────────────────────────│  └──────┘  │
                                             └────────────┘
                                                    │
                4. Execute tool                     ▼
                 ───────────────────────▶   ┌──────────────┐
                                            │Target Server │
                5. Return result            │ (filesystem) │
                 ◀───────────────────────   └──────────────┘
```

## Security Practices Implemented

### 1. Fail-Safe Defaults

**Location**: `src/config.ts`

```typescript
allowedTools: z.array(z.string()).default([])
allowedResources: z.array(z.string()).default([])
allowedPaths: z.array(z.string()).default([])
blockDangerousCommands: z.boolean().default(true)
```

**Why**: All security features default to deny-all or enabled. No tools, resources, or paths are allowed unless explicitly configured.

---

### 2. Input Validation (Defense in Depth)

**Location**: `src/config.ts`

```typescript
export const ConfigSchema = z.object({
  targetCommand: z.string().min(1),  // Must not be empty
  allowedTools: z.array(z.string()).default([]),
  // ...
});
```

**Why**: Configuration is validated at startup using zod. Invalid config fails fast before any proxy logic runs.

---

### 3. Least Privilege (Allowlist, Not Blocklist)

**Location**: `src/guard.ts`

```typescript
isToolAllowed(toolName: string): boolean {
  return this.allowedTools.has(toolName);  // Only explicitly allowed tools pass
}

isResourceAllowed(uri: string): boolean {
  return this.allowedResources.some(prefix => uri.startsWith(prefix));
}

isPathAllowed(filepath: string): boolean {
  // Decodes URL encoding, follows symlinks, validates directory boundary
  return this.allowedPaths.some(root => realPath.startsWith(root + sep));
}
```

**Why**: Blocklists can be bypassed (new tools, typos). Allowlists enforce "only what you explicitly permit".

---

### 4. Audit Logging (Complete Visibility)

**Location**: `src/guard.ts` and `src/proxy.ts`

```typescript
this.logger[allowed ? "info" : "warn"]({
  msg: "Tool access check",
  tool: toolName,
  allowed,
  decision: allowed ? "permit" : "deny",
});
```

**Why**: Every security decision is logged. You can review:
- What tools were requested
- Which were blocked
- When and why

---

### 5. No Information Disclosure

**Location**: `src/guard.ts`

```typescript
getBlockedToolError(toolName: string) {
  // Security: Don't leak allowlist in error message
  return {
    code: -32000,
    message: "Security policy violation: Tool not allowed",
    data: { type: "tool_blocked", tool: toolName },
  };
}
```

**Why**: Error messages don't reveal what tools ARE allowed, preventing attackers from probing the allowlist.

---

### 6. Command Injection Protection

**Location**: `src/guard.ts`

```typescript
const DANGEROUS_PATTERNS = [
  /&&/,           // Command chaining
  /\|\s*\w/,      // Pipe to command
  /;/,            // Command separator
  /\brm\b/,       // Remove command
  /\bsudo\b/,     // Privilege escalation
  /`.*`/,         // Backtick execution
  /\$\(/,         // Command substitution
];

isCommandSafe(args: Record<string, unknown>): boolean {
  const argsString = JSON.stringify(args);
  return !DANGEROUS_PATTERNS.some(p => p.test(argsString));
}
```

**Why**: Prevents shell command injection attacks by blocking dangerous operators before they reach the target server.

---

### 7. Path Scoping (Symlink-Safe)

**Location**: `src/guard.ts`

```typescript
isPathAllowed(filepath: string): boolean {
  // 1. Decode URL encoding (%2e%2e = ..)
  const decoded = decodeURIComponent(filepath);
  
  // 2. Resolve to absolute path
  const resolved = path.resolve(decoded);
  
  // 3. Follow symlinks to get real path
  const realPath = fs.realpathSync(resolved);
  
  // 4. Check boundary with path separator
  return this.allowedPaths.some(root => 
    realPath.startsWith(path.resolve(root) + path.sep)
  );
}
```

**Why**: Prevents path traversal attacks (`../../etc/passwd`) and symlink escapes.

---

### 8. Process Isolation & Graceful Shutdown

**Location**: `src/proxy.ts`

```typescript
const shutdown = async (signal: string) => {
  // 1. Close client connection
  if (this.client) await this.client.close();
  
  // 2. Close transport (kills child process)
  if (this.clientTransport) await this.clientTransport.close();
  
  // 3. Close server
  await this.server.close();
  
  process.exit(0);
};

["SIGTERM", "SIGINT", "SIGHUP"].forEach((signal) => {
  process.on(signal, () => shutdown(signal));
});
```

**Why**: Prevents orphan processes that:
- Leak memory
- Hold file handles open
- Keep database connections alive

---

### 9. PII Redaction (Response Security)

**Location**: `src/redactor.ts`

```typescript
const PII_PATTERNS = {
  ssn: { regex: /\b\d{3}-\d{2}-\d{4}\b/g, replacement: "[SSN:REDACTED]" },
  credit_card: { regex: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g, replacement: "[CREDIT_CARD:REDACTED]" },
  api_key: { regex: /\b(?:sk|api|key)[_-]?[a-zA-Z0-9]{20,}\b/gi, replacement: "[API_KEY:REDACTED]" },
  // ... 12 more patterns
};

redact(content: string): { redacted: string; counts: Record<string, number> } {
  for (const pattern of this.enabledPatterns) {
    result = result.replace(pattern.regex, pattern.replacement);
  }
  return { redacted: result, counts };
}
```

**Integration in proxy.ts:**
```typescript
// After receiving tool response
const { redacted } = this.redactor.redact(result.content[0].text);
result.content[0].text = redacted;
```

**Why**: Prevents sensitive data from reaching the AI model, closing the response-side security gap.

---

## 10x Engineering Techniques

### 1. TypeScript Strict Mode

**Location**: `tsconfig.json`

```json
{
  "strict": true,
  "noUnusedLocals": true,
  "noImplicitReturns": true,
  // ...
}
```

**Benefit**: Catches bugs at compile time, not runtime.

---

### 2. Single Responsibility Principle

| File | Responsibility |
|------|----------------|
| `config.ts` | Configuration loading & validation |
| `logger.ts` | Logging setup |
| `guard.ts` | Tool, Resource, Path & Command security |
| `proxy.ts` | MCP protocol handling |
| `index.ts` | CLI & startup |

**Benefit**: Easy to test, maintain, and understand each piece.

---

### 3. Pure Functions (Where Possible)

**Location**: `src/guard.ts`

```typescript
isToolAllowed(toolName: string): boolean {
  return this.allowedTools.has(toolName);  // No side effects
}
```

**Benefit**: Predictable, testable, no hidden state changes.

---

### 4. Clear Error Messages

**Location**: `src/index.ts`

```typescript
if (configIndex === -1 || !args[configIndex + 1]) {
  console.error("Usage: airlock-mcp --config <config-file>");
  process.exit(1);
}
```

**Benefit**: Users know exactly what's wrong and how to fix it.

---

### 5. Structured Logging (Not Console.log)

**Location**: `src/logger.ts`

```typescript
export function createLogger(config: AirlockConfig["logging"]) {
  return pino({
    level: config.level,
    timestamp: pino.stdTimeFunctions.isoTime,
  });
}
```

**Benefit**: Logs are machine-parseable JSON, easy to search/filter.

---

## How to Test

### 1. Build the code
```bash
npm run build
```

### 2. Run with the example config
```bash
node dist/index.js --config airlock.config.json
```

### 3. Test in VS Code
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

### 4. Try calling a tool:
- **Allowed tool** (`read_file`): Should work
- **Blocked tool** (`write_file`): Should return security error

---

## Configuration Explained

```json
{
  "targetCommand": "npx",  // Command to spawn target server
  "targetArgs": [          // Arguments for that command
    "-y",
    "@modelcontextprotocol/server-filesystem",
    "C:\\Users\\yourname\\project"
  ],
  "allowedTools": [        // SECURITY: Only these tools can be called
    "read_file",
    "list_directory"
  ],
  "allowedResources": [    // SECURITY: Only these URI prefixes allowed
    "mcp://public/"
  ],
  "allowedPaths": [        // SECURITY: Only files in these directories
    "C:\\Users\\yourname\\project"
  ],
  "blockDangerousCommands": true,  // SECURITY: Block shell operators
  "logging": {
    "level": "info",       // debug | info | warn | error
    "destination": "stdout" // stdout | file
  }
}
```

### Security Note on Tool Names

Tool names must match **exactly** what the target server exposes. To see what tools a server provides, run:
```bash
npx @modelcontextprotocol/inspector npx -y @modelcontextprotocol/server-filesystem .
```

---

## Common Issues & Solutions

### Issue: "Cannot find module '@modelcontextprotocol/sdk'"

**Solution**: Run `npm install` to install dependencies.

---

### Issue: TypeScript errors about missing types

**Solution**: Ensure `npm install` completed. If still broken, try:
```bash
rm -rf node_modules package-lock.json
npm install
```

---

### Issue: Proxy blocks all tools

**Check**:
1. Is `allowedTools` empty in your config?
2. Do tool names match exactly (case-sensitive)?
3. Check logs for "Tool access check" messages

---

## Running Integration Tests

Run the full security test suite:
```bash
npx tsx src/test/integration.ts
```

This tests:
- ✅ Allowed tools pass through
- ✅ Blocked tools are intercepted
- ✅ Allowed resources are readable
- ✅ Blocked resources return errors
- ✅ Command injection is blocked
- ✅ Path handling works correctly
- ✅ PII is redacted from responses

---

## Next Steps (Not Yet Implemented)

All core security phases are complete! Future enhancements:

- [ ] NER-based name/address detection (ML models)
- [ ] HTTP transport support
- [ ] Gateway mode (multiple target servers)

This MVP focuses on **proving the security architecture works** with minimal complexity.
