import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
    CallToolRequestSchema,
    ListResourcesRequestSchema,
    ReadResourceRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { z } from "zod";

/**
 * A simple mock MCP server for testing the Airlock Proxy
 */
const server = new Server(
    { name: "mock-server", version: "1.0.0" },
    { capabilities: { tools: {}, resources: {} } }
);

server.setRequestHandler(ListResourcesRequestSchema, async () => {
    return {
        resources: [
            {
                uri: "mcp://public/data.txt",
                name: "Public Data",
                mimeType: "text/plain",
            },
            {
                uri: "mcp://secret/passwords.txt",
                name: "Secret Passwords",
                mimeType: "text/plain",
            },
        ],
    };
});

server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
    const { uri } = request.params;
    return {
        contents: [
            {
                uri,
                mimeType: "text/plain",
                text: `Content of ${uri}`,
            },
        ],
    };
});

server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    // Special tool for testing PII redaction
    if (name === "pii_test") {
        return {
            content: [
                {
                    type: "text",
                    text: `Customer SSN: 123-45-6789\nCard: 4111-1111-1111-1111\nAPI Key: sk-test1234567890abcdef\nEmail: john.doe@company.com`,
                },
            ],
        };
    }

    return {
        content: [
            {
                type: "text",
                text: `Mock server executed ${name} with args: ${JSON.stringify(args)}`,
            },
        ],
    };
});

async function main() {
    const transport = new StdioServerTransport();
    await server.connect(transport);
    console.error("Mock server running on stdio");
}

main().catch((error) => {
    console.error("Mock server error:", error);
    process.exit(1);
});
