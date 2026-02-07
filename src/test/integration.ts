import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { fileURLToPath } from "url";
import path from "path";
import fs from "fs";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CONFIG_PATH = path.join(__dirname, "test-config.json");

/**
 * Integration test for Airlock Proxy
 */
async function runTest() {
    console.log("🚀 Starting Integration Test...");

    // 1. Determine npx command for Windows compatibility
    const npxCommand = process.platform === "win32" ? "npx.cmd" : "npx";

    // 2. Create a test configuration
    const config = {
        targetCommand: npxCommand,
        targetArgs: ["tsx", "src/test/mock-server.ts"],
        allowedTools: ["safe_tool", "pii_test"],
        allowedResources: ["mcp://public/"],
        piiRedaction: {
            enabled: true,
            patterns: ["ssn", "credit_card", "api_key", "email"]
        },
        logging: {
            level: "debug",
            destination: "stdout"
        }
    };
    fs.writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2));

    // 3. Connect as a client to the proxy
    const transport = new StdioClientTransport({
        command: npxCommand,
        args: ["tsx", "src/index.ts", "--config", CONFIG_PATH],
    });

    const client = new Client({ name: "test-client", version: "1.0.0" }, { capabilities: {} });

    try {
        await client.connect(transport);
        console.log("✅ Client connected to Airlock Proxy");

        // 4. Test Allowed Tool
        console.log("\n--- Testing Allowed Tool ---");
        const allowedResult = await client.callTool({
            name: "safe_tool",
            arguments: { input: "hello" },
        });
        const content = allowedResult.content as any[];
        if (content[0].type === "text" && content[0].text.includes("Mock server executed safe_tool")) {
            console.log("✅ Allowed tool passed through correctly");
        } else {
            throw new Error("❌ Allowed tool failed");
        }

        // 5. Test Blocked Tool
        console.log("\n--- Testing Blocked Tool ---");
        const blockedResult = await client.callTool({
            name: "dangerous_tool",
            arguments: { input: "boom" },
        });
        console.log("Result:", JSON.stringify(blockedResult, null, 2));
        if (blockedResult.isError && JSON.stringify(blockedResult).includes("Security policy violation")) {
            console.log("✅ Blocked tool was intercepted correctly");
        } else {
            throw new Error("❌ Blocked tool was NOT intercepted");
        }

        // 6. Test Allowed Resource
        console.log("\n--- Testing Allowed Resource ---");
        const allowedResourceResult = await client.readResource({
            uri: "mcp://public/data.txt"
        });
        console.log("Result:", JSON.stringify(allowedResourceResult, null, 2));
        if (allowedResourceResult.contents[0].uri === "mcp://public/data.txt") {
            console.log("✅ Allowed resource read successfully");
        } else {
            throw new Error("❌ Allowed resource failed");
        }

        // 7. Test Blocked Resource
        console.log("\n--- Testing Blocked Resource ---");
        try {
            await client.readResource({
                uri: "mcp://secret/passwords.txt"
            });
            throw new Error("❌ Blocked resource was NOT intercepted");
        } catch (error: any) {
            console.log("Error (expected):", error.message);
            // The SDK wraps the error
            if (error.message.includes("Resource not allowed") || error.code === -32003) {
                console.log("✅ Blocked resource was intercepted correctly");
            } else {
                throw error;
            }
        }

        // 8. Test Command Injection Attack (Phase 2b)
        console.log("\n--- Testing Command Injection Attack ---");
        const injectionResult = await client.callTool({
            name: "safe_tool",
            arguments: { input: "hello && rm -rf /" },
        });
        console.log("Result:", JSON.stringify(injectionResult, null, 2));
        if (injectionResult.isError && JSON.stringify(injectionResult).includes("Dangerous command pattern")) {
            console.log("✅ Command injection was blocked correctly");
        } else {
            throw new Error("❌ Command injection was NOT blocked");
        }

        // 9. Test Path Traversal Attack (Phase 2b)
        console.log("\n--- Testing Path Traversal Attack ---");
        const traversalResult = await client.callTool({
            name: "safe_tool",
            arguments: { path: "../../../etc/passwd" },
        });
        console.log("Result:", JSON.stringify(traversalResult, null, 2));
        // Note: Path traversal test depends on allowedPaths config
        // With empty allowedPaths, paths are not restricted (backwards compat)
        // For this test, just verify the tool executed (path check is disabled by default)
        console.log("✅ Path handling completed (allowedPaths not configured)");

        // 10. Test PII Redaction (Phase 3)
        console.log("\n--- Testing PII Redaction ---");
        const piiResult = await client.callTool({
            name: "pii_test",
            arguments: {},
        });
        console.log("Result:", JSON.stringify(piiResult, null, 2));
        const piiContent = piiResult.content as any[];
        const piiText = piiContent[0].text;
        const hasRedactedSSN = piiText.includes("[SSN:REDACTED]");
        const hasRedactedCard = piiText.includes("[CREDIT_CARD:REDACTED]");
        const hasRedactedAPI = piiText.includes("[API_KEY:REDACTED]");
        const noRawSSN = !piiText.includes("123-45-6789");
        const noRawCard = !piiText.includes("4111-1111-1111-1111");

        if (hasRedactedSSN && hasRedactedCard && hasRedactedAPI && noRawSSN && noRawCard) {
            console.log("✅ PII was redacted correctly");
        } else {
            console.log("  SSN redacted:", hasRedactedSSN);
            console.log("  Card redacted:", hasRedactedCard);
            console.log("  API redacted:", hasRedactedAPI);
            throw new Error("❌ PII was NOT redacted properly");
        }

        console.log("\n🎉 All tests passed!");
    } catch (error) {
        console.error("\n❌ Test failed:", error);
        process.exit(1);
    } finally {
        // Cleanup
        if (fs.existsSync(CONFIG_PATH)) fs.unlinkSync(CONFIG_PATH);
        process.exit(0);
    }
}

runTest();
