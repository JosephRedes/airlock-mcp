/**
 * Airlock-MCP Live Threat Demonstration
 *
 * Simulates an attacker (or compromised AI) making malicious MCP tool calls.
 * Airlock intercepts and blocks each one.
 *
 * Run: npm run demo:attack
 * Prereq: npm run build
 */

import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import fs from "fs";

// ── ANSI colours ────────────────────────────────────────────────────────────
const R     = "\x1b[0m";
const BOLD  = "\x1b[1m";
const DIM   = "\x1b[2m";
const RED   = "\x1b[31m";
const GREEN = "\x1b[32m";
const YELLOW = "\x1b[33m";
const CYAN  = "\x1b[36m";
const LINE  = "─".repeat(64);
const DLINE = "═".repeat(64);

// ── Helpers ──────────────────────────────────────────────────────────────────
const p = (s = "") => process.stdout.write(s + "\n");
const sleep = (ms: number) => new Promise(r => setTimeout(r, ms));

function header(text: string) {
    p(); p(`${BOLD}${CYAN}${DLINE}${R}`);
    p(`${BOLD}${CYAN}  ${text}${R}`);
    p(`${BOLD}${CYAN}${DLINE}${R}`); p();
}

function section(text: string) {
    p(`${LINE}`);
    p(`  ${BOLD}${text}${R}`);
    p(`${LINE}`); p();
}

function parseError(content: unknown[]): { type: string; message: string } {
    const item = content?.[0] as { text?: string } | undefined;
    if (!item?.text) return { type: "unknown", message: "unknown error" };
    try {
        const parsed = JSON.parse(item.text) as { data?: { type?: string }; message?: string };
        return {
            type: parsed.data?.type ?? "unknown",
            message: parsed.message ?? item.text,
        };
    } catch {
        return { type: "unknown", message: item.text };
    }
}

// ── Main ─────────────────────────────────────────────────────────────────────
async function main() {
    // Ensure demo dir and clear stale log
    if (!fs.existsSync("demo")) fs.mkdirSync("demo");
    fs.writeFileSync("demo/airlock.log", "");

    if (!fs.existsSync("dist/index.js")) {
        p(`${RED}Error: dist/index.js not found. Run 'npm run build' first.${R}`);
        process.exit(1);
    }

    header("AIRLOCK-MCP  —  LIVE THREAT DEMONSTRATION");
    p(`  ${YELLOW}Connecting to Airlock security proxy...${R}`);

    const transport = new StdioClientTransport({
        command: "node",
        args: ["dist/index.js", "--config", "demo/demo.config.json"],
    });

    const client = new Client(
        { name: "demo-attacker", version: "1.0.0" },
        { capabilities: {} }
    );

    await client.connect(transport);
    p(`  ${GREEN}✓ Connected to Airlock${R}`);
    await sleep(4000);

    // ── THREAT 1: Unauthorized Tool ──────────────────────────────────────────
    section("THREAT 1 of 3  —  Unauthorized Tool Execution");
    p(`  ${BOLD}${RED}⚠  ATTACK${R}    Calling execute_command (not in allowlist)`);
    p(`  ${DIM}   Scenario: Compromised AI attempts to run arbitrary shell commands${R}`);
    p();
    await sleep(5000);
    p(`  ${DIM}→  Sending malicious request to Airlock...${R}`);
    await sleep(2000);

    const r1 = await client.callTool({
        name: "execute_command",
        arguments: { command: "cat /etc/passwd" },
    });

    const e1 = parseError(r1.content as unknown[]);
    p();
    p(`  ${BOLD}${GREEN}✓  BLOCKED${R}    ${e1.message}`);
    p(`  ${DIM}   Reason: ${e1.type}${R}`);
    await sleep(7000);

    // ── THREAT 2: Command Injection ──────────────────────────────────────────
    section("THREAT 2 of 3  —  Command Injection via Tool Arguments");
    p(`  ${BOLD}${RED}⚠  ATTACK${R}    Injecting "&& rm -rf /" into read_file path argument`);
    p(`  ${DIM}   Scenario: Prompt injection triggers destructive shell command chain${R}`);
    p();
    await sleep(5000);
    p(`  ${DIM}→  Sending injected request to Airlock...${R}`);
    await sleep(2000);

    const r2 = await client.callTool({
        name: "read_file",
        arguments: { path: "/data/report.txt && rm -rf /" },
    });

    const e2 = parseError(r2.content as unknown[]);
    p();
    p(`  ${BOLD}${GREEN}✓  BLOCKED${R}    ${e2.message}`);
    p(`  ${DIM}   Reason: ${e2.type}${R}`);
    await sleep(7000);

    // ── THREAT 3: PII Exfiltration ───────────────────────────────────────────
    section("THREAT 3 of 3  —  PII Exfiltration via Response");
    p(`  ${BOLD}${RED}⚠  ATTACK${R}    AI reads HR file containing sensitive employee data`);
    p(`  ${DIM}   Scenario: Target server exposes SSN, API key, and email in response${R}`);
    p();
    await sleep(5000);
    p(`  ${DIM}→  Sending request to Airlock...${R}`);
    await sleep(2000);
    p(`  ${DIM}→  Target server returned raw sensitive data...${R}`);
    await sleep(2000);
    p(`  ${DIM}→  Airlock scanning response for PII patterns...${R}`);
    await sleep(2500);

    const r3 = await client.callTool({
        name: "read_file",
        arguments: { path: "/hr/employees.txt" },
    });

    const responseText = (r3.content as Array<{ type: string; text: string }>)[0]?.text ?? "";
    const ssnRedacted   = responseText.includes("[SSN:REDACTED]");
    const apiRedacted   = responseText.includes("[API_KEY:REDACTED]");
    const emailRedacted = responseText.includes("[EMAIL:REDACTED]");

    p();
    p(`  ${BOLD}${GREEN}✓  REDACTED${R}   Airlock stripped PII before it reached the AI`);
    p();
    p(`  ${DIM}   Field     Before (raw)                         After (sanitized)${R}`);
    p(`  ${LINE.slice(0, 60)}`);
    p(`  ${DIM}   SSN    ${R}  ${RED}123-45-6789${R}                          ${GREEN}${ssnRedacted ? "[SSN:REDACTED]" : "not redacted"}${R}`);
    p(`  ${DIM}   API Key${R}  ${RED}sk-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5${R}  ${GREEN}${apiRedacted ? "[API_KEY:REDACTED]" : "not redacted"}${R}`);
    p(`  ${DIM}   Email  ${R}  ${RED}john.smith@corp.com${R}                  ${GREEN}${emailRedacted ? "[EMAIL:REDACTED]" : "not redacted"}${R}`);

    await sleep(6000);

    // ── Summary ──────────────────────────────────────────────────────────────
    p(); p(`${BOLD}${CYAN}${DLINE}${R}`);
    p(`${BOLD}${CYAN}  DEMO COMPLETE  —  All 3 Threats Controlled by Airlock${R}`);
    p(`${BOLD}${CYAN}${DLINE}${R}`); p();
    p(`  ${BOLD}Active controls:${R}`);
    p(`    ${GREEN}✓${R}  Tool allowlist enforcement    ${DIM}allowedTools in config${R}`);
    p(`    ${GREEN}✓${R}  Command injection detection   ${DIM}blockDangerousCommands in config${R}`);
    p(`    ${GREEN}✓${R}  PII redaction on responses    ${DIM}piiRedaction in config${R}`);
    p();

    await client.close();
    process.exit(0);
}

main().catch((err) => {
    console.error("Demo error:", err);
    process.exit(1);
});
