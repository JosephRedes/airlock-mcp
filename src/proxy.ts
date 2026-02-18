import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import type { Transport } from "@modelcontextprotocol/sdk/shared/transport.js";
import {
    CallToolRequestSchema,
    ListToolsRequestSchema,
    ListResourcesRequestSchema,
    ReadResourceRequestSchema,
    type CallToolResult,
    McpError,
    ErrorCode,
} from "@modelcontextprotocol/sdk/types.js";
import type { Logger } from "./logger.js";
import type { AirlockConfig } from "./config.js";
import { ToolGuard } from "./guard.js";
import { PIIRedactor } from "./redactor.js";
import { RateLimiter } from "./limiter.js";

/**
 * AirlockProxy: Security-first MCP proxy
 * 
 * Architecture:
 * - Acts as MCP Server to the host (VS Code, Claude)
 * - Acts as MCP Client to the target server
 * - Intercepts and validates all tool calls
 * 
 * Security Principles:
 * 1. Separation of concerns: validation separate from forwarding
 * 2. Fail-safe: errors block execution, don't fall through
 * 3. Audit trail: all requests/responses logged
 * 4. Process isolation: clean shutdown prevents orphans
 */
export class AirlockProxy {
    private server: Server;
    private client: Client | null = null;
    private clientTransport: Transport | null = null;
    private guard: ToolGuard;
    private redactor: PIIRedactor;
    private limiter: RateLimiter;
    private logger: Logger;
    private config: AirlockConfig;

    constructor(config: AirlockConfig, logger: Logger) {
        this.config = config;
        this.logger = logger;
        this.guard = new ToolGuard(config, logger);
        this.redactor = new PIIRedactor(config, logger);
        this.limiter = new RateLimiter(config, logger);

        // Initialize MCP Server (upstream facing)
        this.server = new Server(
            {
                name: "airlock-mcp",
                version: "1.0.0",
            },
            {
                capabilities: {
                    tools: {},
                    resources: {},
                },
            }
        );

        this.setupHandlers();
        this.setupLifecycle();
    }

    /**
     * Set up MCP protocol handlers
     * 
     * Security: Each handler validates before forwarding
     */
    private setupHandlers(): void {
        // List tools: forward from target server, filtered to allowlist
        this.server.setRequestHandler(ListToolsRequestSchema, async () => {
            if (!this.client) {
                throw new Error("Target server not connected");
            }

            this.logger.debug({ msg: "Forwarding tools/list" });
            const result = await this.client.listTools();
            return { tools: this.guard.filterToolList(result.tools) };
        });

        // Call tool: SECURITY INTERCEPTION POINT
        this.server.setRequestHandler(CallToolRequestSchema, async (request) => {
            const toolName = request.params.name;
            const toolArgs = request.params.arguments ?? {};

            this.logger.info({
                msg: "Tool call request",
                tool: toolName,
                argsCount: Object.keys(toolArgs).length,
            });

            // SECURITY CHECK 1: Tool allowlist
            if (!this.guard.isToolAllowed(toolName)) {
                const error = this.guard.getBlockedToolError(toolName);

                // Security: Return error, don't execute
                return {
                    content: [{
                        type: "text" as const,
                        text: JSON.stringify(error, null, 2),
                    }],
                    isError: true,
                } satisfies CallToolResult;
            }

            // SECURITY CHECK 2: Dangerous command patterns
            if (!this.guard.isCommandSafe(toolArgs as Record<string, unknown>)) {
                const error = this.guard.getDangerousCommandError();

                return {
                    content: [{
                        type: "text" as const,
                        text: JSON.stringify(error, null, 2),
                    }],
                    isError: true,
                } satisfies CallToolResult;
            }

            // SECURITY CHECK 3: Path scoping
            // Extract and validate any path-like arguments
            const pathArgs = this.extractPathArguments(toolArgs as Record<string, unknown>);
            for (const filepath of pathArgs) {
                if (!this.guard.isPathAllowed(filepath)) {
                    const error = this.guard.getPathViolationError(filepath);

                    return {
                        content: [{
                            type: "text" as const,
                            text: JSON.stringify(error, null, 2),
                        }],
                        isError: true,
                    } satisfies CallToolResult;
                }
            }

            // SECURITY CHECK 4: Rate limiting
            if (this.limiter.isToolRateLimited(toolName)) {
                return {
                    content: [{
                        type: "text" as const,
                        text: JSON.stringify(this.limiter.getRateLimitError(toolName), null, 2),
                    }],
                    isError: true,
                } satisfies CallToolResult;
            }

            // SECURITY CHECK 5: Request size
            if (this.limiter.isRequestTooLarge(toolArgs as Record<string, unknown>)) {
                return {
                    content: [{
                        type: "text" as const,
                        text: JSON.stringify(this.limiter.getSizeLimitError("request"), null, 2),
                    }],
                    isError: true,
                } satisfies CallToolResult;
            }

            // Tool is allowed, forward to target server
            if (!this.client) {
                throw new Error("Target server not connected");
            }

            this.logger.debug({ msg: "Forwarding to target server", tool: toolName });
            const result = await this.client.callTool({
                name: toolName,
                arguments: request.params.arguments,
            });

            // SECURITY CHECK 6: Response size
            if (result.content && Array.isArray(result.content) && this.limiter.isResponseTooLarge(result.content)) {
                return {
                    content: [{
                        type: "text" as const,
                        text: JSON.stringify(this.limiter.getSizeLimitError("response"), null, 2),
                    }],
                    isError: true,
                } satisfies CallToolResult;
            }

            // SECURITY: Redact PII from response
            if (result.content && Array.isArray(result.content)) {
                for (const item of result.content) {
                    if (item.type === "text" && "text" in item && typeof item.text === "string") {
                        const { redacted } = this.redactor.redact(item.text);
                        item.text = redacted;
                    }
                }
            }

            this.logger.info({
                msg: "Tool call completed",
                tool: toolName,
                isError: result.isError ?? false,
            });

            return result;
        });

        // List resources: forward from target server
        this.server.setRequestHandler(ListResourcesRequestSchema, async () => {
            if (!this.client) {
                throw new Error("Target server not connected");
            }

            this.logger.debug({ msg: "Forwarding resources/list" });
            return await this.client.listResources();
        });

        // Read resource: SECURITY INTERCEPTION POINT
        this.server.setRequestHandler(ReadResourceRequestSchema, async (request) => {
            const uri = request.params.uri;

            this.logger.info({
                msg: "Resource read request",
                uri,
            });

            // SECURITY: Check allowlist before forwarding
            if (!this.guard.isResourceAllowed(uri)) {
                this.guard.getBlockedResourceError(uri); // Logs the error

                // Security: Throw standard MCP error
                throw new McpError(
                    -32003 as ErrorCode, // Using -32003 for resource_blocked
                    "Security policy violation: Resource not allowed"
                );
            }

            // Resource is allowed, forward to target server
            if (!this.client) {
                throw new Error("Target server not connected");
            }

            this.logger.debug({ msg: "Forwarding to target server", uri });
            const result = await this.client.readResource({
                uri,
            });

            // SECURITY: Redact PII from resource content
            if (result.contents && Array.isArray(result.contents)) {
                for (const item of result.contents) {
                    if ("text" in item && typeof item.text === "string") {
                        const { redacted } = this.redactor.redact(item.text);
                        item.text = redacted;
                    }
                }
            }

            this.logger.info({
                msg: "Resource read completed",
                uri,
            });

            return result;
        });
    }

    /**
     * Extract path-like arguments from tool arguments.
     *
     * Catches paths regardless of argument key name by checking whether the
     * value itself looks like a filesystem path (absolute or traversal).
     * Key-name heuristics are kept as an additional signal for relative paths.
     */
    private extractPathArguments(args: Record<string, unknown>): string[] {
        const paths: string[] = [];
        const pathKeyPatterns = /^(path|file|filepath|filename|directory|dir|src|dest|target|source)$/i;

        // Returns true for strings that look like filesystem paths regardless of key name.
        // Matches Unix absolute (/), home (~), Windows absolute (C:\ or C:/), and traversal (..)
        const looksLikeAbsolutePath = (v: string): boolean =>
            v.startsWith("/") ||
            v.startsWith("~") ||
            v.startsWith("..") ||
            /^[A-Za-z]:[/\\]/.test(v);

        const extractFromValue = (value: unknown, key?: string): void => {
            if (typeof value === "string") {
                // Always extract absolute/traversal paths regardless of key name.
                // Also extract when the key name signals a path argument.
                if (looksLikeAbsolutePath(value) || (key && pathKeyPatterns.test(key))) {
                    paths.push(value);
                }
            } else if (Array.isArray(value)) {
                for (const item of value) {
                    extractFromValue(item);
                }
            } else if (value && typeof value === "object") {
                for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
                    extractFromValue(v, k);
                }
            }
        };

        for (const [key, value] of Object.entries(args)) {
            extractFromValue(value, key);
        }

        return paths;
    }

    /**
   * Setup process lifecycle management
     * 
     * Security: Prevent orphan processes that leak resources
     * 10x Engineering: Graceful shutdown, clear error messages
     */
    private setupLifecycle(): void {
        const shutdown = async (signal: string) => {
            this.logger.info({ msg: "Shutdown initiated", signal });

            try {
                // 1. Close client connection gracefully
                if (this.client) {
                    await this.client.close();
                    this.logger.debug({ msg: "Client connection closed" });
                }

                // 2. Close client transport (kills child process)
                if (this.clientTransport) {
                    await this.clientTransport.close();
                    this.logger.debug({ msg: "Client transport closed" });
                }

                // 3. Close server
                await this.server.close();
                this.logger.info({ msg: "Airlock shutdown complete" });

                process.exit(0);
            } catch (error) {
                this.logger.error({ msg: "Error during shutdown", error });
                process.exit(1);
            }
        };

        // Handle all termination signals
        ["SIGTERM", "SIGINT", "SIGHUP"].forEach((signal) => {
            process.on(signal, () => shutdown(signal));
        });

        // Handle uncaught errors
        process.on("uncaughtException", (error) => {
            this.logger.fatal({ msg: "Uncaught exception", error });
            process.exit(1);
        });

        process.on("unhandledRejection", (reason) => {
            this.logger.fatal({ msg: "Unhandled rejection", reason });
            process.exit(1);
        });
    }

    /**
     * Start the proxy
     * 
     * 1. Connect to target MCP server
     * 2. Start listening for host connections
     */
    async start(): Promise<void> {
        this.logger.info({ msg: "Starting Airlock-MCP" });

        // Phase 1: Connect to target server (downstream)
        if (this.config.targetUrl) {
            this.logger.info({
                msg: "Connecting to remote target server",
                url: this.config.targetUrl,
            });
            this.clientTransport = new StreamableHTTPClientTransport(
                new URL(this.config.targetUrl)
            );
        } else {
            this.logger.info({
                msg: "Connecting to target server",
                command: this.config.targetCommand,
                args: this.config.targetArgs,
            });
            this.clientTransport = new StdioClientTransport({
                command: this.config.targetCommand!,
                args: this.config.targetArgs,
                env: this.config.targetEnv,
            });
        }

        this.client = new Client(
            {
                name: "airlock-client",
                version: "1.0.0",
            },
            {
                capabilities: {},
            }
        );

        await this.client.connect(this.clientTransport);
        this.logger.info({ msg: "Connected to target server" });

        // Phase 2: Start server for host (upstream)
        const serverTransport = new StdioServerTransport();
        await this.server.connect(serverTransport);

        this.logger.info({ msg: "Airlock-MCP ready", status: "operational" });
    }
}
