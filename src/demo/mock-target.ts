import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
    CallToolRequestSchema,
    ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";

/**
 * Demo target MCP server — simulates a real server with sensitive data.
 * Used by the Airlock-MCP threat demonstration.
 */
const server = new Server(
    { name: "demo-target", version: "1.0.0" },
    { capabilities: { tools: {} } }
);

server.setRequestHandler(ListToolsRequestSchema, async () => ({
    tools: [
        {
            name: "read_file",
            description: "Read the contents of a file",
            inputSchema: {
                type: "object",
                properties: {
                    path: { type: "string", description: "Path to the file" },
                },
                required: ["path"],
            },
        },
        {
            name: "execute_command",
            description: "Execute a shell command on the server",
            inputSchema: {
                type: "object",
                properties: {
                    command: { type: "string", description: "Shell command to run" },
                },
                required: ["command"],
            },
        },
        {
            name: "list_files",
            description: "List files in a directory",
            inputSchema: {
                type: "object",
                properties: {
                    directory: { type: "string", description: "Directory path" },
                },
                required: ["directory"],
            },
        },
    ],
}));

server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    if (name === "read_file") {
        // Simulates a real server returning a file with PII — Airlock will redact this
        return {
            content: [{
                type: "text" as const,
                text: [
                    `=== HR Record: ${String(args?.path ?? "unknown")} ===`,
                    `Name:    John Smith`,
                    `SSN:     123-45-6789`,
                    `Email:   john.smith@corp.com`,
                    `API Key: sk-a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5`,
                    `Salary:  $95,000`,
                ].join("\n"),
            }],
        };
    }

    if (name === "execute_command") {
        return {
            content: [{
                type: "text" as const,
                text: `Executed: ${String(args?.command ?? "")}`,
            }],
        };
    }

    if (name === "list_files") {
        return {
            content: [{
                type: "text" as const,
                text: `Files in ${String(args?.directory ?? "")}:\n- report.txt\n- config.json\n- employees.csv`,
            }],
        };
    }

    throw new Error(`Unknown tool: ${name}`);
});

async function main() {
    const transport = new StdioServerTransport();
    await server.connect(transport);
}

main().catch((error) => {
    process.stderr.write(`Demo target error: ${String(error)}\n`);
    process.exit(1);
});
