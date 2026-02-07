# Airlock-MCP Threat Mitigation Mapping

> Maps Airlock-MCP security controls to threats documented in the [CSA MCP Security TTPs](https://modelcontextprotocol-security.io/ttps/) framework

---

## Summary

| Status | Count |
|--------|-------|
| **Fully Addressed** | 4 |
| **Partially Addressed** | 3 |
| **Not Addressed** | 5 |

---

## TTP Categories Mapping

### ✅ FULLY ADDRESSED

| TTP Category | Airlock Control | How It Mitigates |
|--------------|-----------------|------------------|
| **Command & Code Injection** | `blockDangerousCommands` | Blocks `&&`, `\|`, `;`, `rm`, `sudo`, `$()`, backticks in tool arguments |
| **Privilege & Access Control** | `allowedTools` + `allowedPaths` | Allowlist restricts which tools can execute; path scoping prevents traversal |
| **Data Exfiltration & Credential Theft** | `piiRedaction` + `allowedResources` | PII redaction removes credentials from responses; resource allowlist blocks sensitive data access |
| **Monitoring & Operational Security** | Structured logging (pino) | Full audit trail of all tool calls, blocks, and redactions |

---

### ⚠️ PARTIALLY ADDRESSED

| TTP Category | Airlock Control | Coverage | Gap |
|--------------|-----------------|----------|-----|
| **Tool Poisoning & Metadata Attacks** | `allowedTools` | Limits which tools can be called | Does not validate tool descriptions or metadata |
| **Context Manipulation** | `allowedResources` | Restricts which resources AI can read | Does not validate resource content for manipulation |
| **Protocol Vulnerabilities** | Transparent proxy design | No modification of MCP protocol | Does not add authentication layer |

---

### ❌ NOT ADDRESSED (Out of Scope)

| TTP Category | Why Not Addressed | Recommended Control |
|--------------|-------------------|---------------------|
| **Prompt Injection & Manipulation** | Operates below the LLM layer | Requires LLM-level guardrails |
| **Authentication & Authorization** | MCP uses stdio (no network auth) | Add OAuth/mTLS at gateway layer |
| **Supply Chain & Dependencies** | Trust in target server assumed | Use `npm audit`, code review |
| **Economic & Infrastructure Abuse** | No rate limiting in proxy | Add rate limiting, cost tracking |
| **AI-Specific Vulnerabilities** | Model behavior not in scope | Requires model-level controls |

---

## Control-to-Hardening Mapping

Maps Airlock controls to [CSA Hardening Guide](https://modelcontextprotocol-security.io/hardening/):

| Hardening Domain | Airlock Feature | Notes |
|------------------|-----------------|-------|
| **Traffic Mediation** | Transparent proxy | All MCP traffic flows through Airlock |
| **Policy & Guardrails** | Tool/Resource/Path allowlists | Configurable policy enforcement |
| **Observability & Logging** | Pino structured logging | JSON audit logs for SIEM |
| **Secrets & Credential Management** | PII Redaction | Prevents credential leakage to AI |

---

## Demo Scenarios

Use these for security demos:

### 1. Tool Allowlist Demo
```json
{ "allowedTools": ["read_file"] }
```
AI tries `write_file` → **BLOCKED**

### 2. Command Injection Demo
AI calls tool with argument: `file.txt && rm -rf /`
→ **BLOCKED** (dangerous command detected)

### 3. Path Traversal Demo
AI tries to read: `../../etc/passwd`
→ **BLOCKED** (outside allowed path)

### 4. PII Redaction Demo
Tool returns: `Customer SSN: 123-45-6789`
AI receives: `Customer SSN: [SSN:REDACTED]`

---

## References

- [CSA MCP Security TTPs](https://modelcontextprotocol-security.io/ttps/)
- [CSA Hardening Guide](https://modelcontextprotocol-security.io/hardening/)
- [MCP Security GitHub](https://github.com/ModelContextProtocol-Security/modelcontextprotocol-security.io)
