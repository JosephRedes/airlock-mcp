# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**Airlock-MCP** is a security-first pass-through proxy for the Model Context Protocol (MCP). It sits between an AI host (VS Code, Claude Desktop) and any MCP server, enforcing security policies before forwarding requests.

## Commands

```bash
npm install          # Install dependencies
npm run build        # Compile TypeScript → dist/
npm run dev -- --config airlock.config.json  # Run with ts-node (no build needed)
npm test             # Run unit tests (vitest)
npm run test:watch   # Run unit tests in watch mode
npm run test:integration  # Run integration tests (requires process spawning)
npm run typecheck    # TypeScript type check without emitting
```

To run a single test file:
```bash
npx vitest run src/test/guard.test.ts
```

After building, run the proxy with:
```bash
node dist/index.js --config airlock.config.json
```

## Architecture

The proxy is a **dual-transport bridge**: it presents itself as an MCP Server to the upstream host and connects as an MCP Client to the downstream target server. All MCP messages pass through security checks before forwarding.

```
AI Host (VS Code/Claude) ←→ [AirlockProxy as Server] → [Security Checks] → [AirlockProxy as Client] ←→ Target MCP Server
```

### Core modules (`src/`)

| File | Role |
|------|------|
| `index.ts` | Entry point — parses `--config` arg, wires config → logger → proxy |
| `config.ts` | Zod schema validation for `airlock.config.json`; loaded once at startup |
| `proxy.ts` | `AirlockProxy` class — MCP server/client setup, request handlers, lifecycle |
| `guard.ts` | `ToolGuard` — enforces tool allowlist, command blocklist, path scoping |
| `redactor.ts` | `PIIRedactor` — regex-based redaction of sensitive data from responses |
| `logger.ts` | `pino`-based structured JSON logger factory |

### Security check order in `proxy.ts`

For every `tools/call` request:
1. **Tool allowlist** (`ToolGuard.isToolAllowed`) — deny-by-default; empty allowlist blocks everything
2. **Dangerous command patterns** (`ToolGuard.isCommandSafe`) — blocks `&&`, `|`, `;`, `rm`, `sudo`, backticks, `$()`
3. **Path scoping** (`ToolGuard.isPathAllowed`) — decodes URL encoding, resolves symlinks, checks against `allowedPaths`
4. **Forward to target**, then run `PIIRedactor.redact()` on the response text

For `resources/read`: resource URI must match a prefix in `allowedResources`.

### Key design decisions

- **Fail-safe defaults**: empty `allowedTools` or `allowedResources` = deny all. `allowedPaths: []` = allow all paths (backwards compatibility exception).
- **No information disclosure**: blocked-tool errors do not reveal the allowlist contents.
- **Config validated at startup** via Zod — the proxy won't start with invalid config.
- TypeScript strict mode with `noUnusedLocals`, `noUnusedParameters`, `noImplicitReturns` enforced. All imports use `.js` extensions (Node16 module resolution).

## Testing

Unit tests use **vitest** and live in `src/test/`. The `guard.test.ts` and `redactor.test.ts` files use a mock logger object. Integration tests in `src/test/integration.ts` spawn real processes and are run separately.

## TypeScript Notes

- Module system: `"type": "module"` (ESM). Import paths must end in `.js` even for `.ts` source files.
- Target: Node 18+ (ES2022, Node16 module resolution).
- Build output goes to `dist/` with source maps and declaration files.
