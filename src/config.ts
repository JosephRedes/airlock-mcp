import { z } from "zod";

/**
 * Configuration schema for Airlock-MCP
 * 
 * Security Best Practices:
 * - Fail-safe defaults: allowedTools is required (no implicit "allow all")
 * - Explicit is better than implicit
 * - Validated at startup, not runtime
 */
export const ConfigSchema = z.object({
    /** Command to spawn a local target MCP server (mutually exclusive with targetUrl) */
    targetCommand: z.string().min(1).optional(),

    /** URL of a remote HTTP MCP server (mutually exclusive with targetCommand) */
    targetUrl: z.string().url().optional(),

    /** Arguments to pass to the target command (only used with targetCommand) */
    targetArgs: z.array(z.string()).default([]),

    /** Environment variables for the target server (only used with targetCommand) */
    targetEnv: z.record(z.string()).optional(),

    /** 
     * SECURITY: Allowlist of permitted tool names
     * If a tool is not in this list, it will be blocked
     * Default: empty array (deny all)
     */
    allowedTools: z.array(z.string()).default([]),

    /**
     * SECURITY: Allowlist of permitted resource URI prefixes
     * If a resource URI does not start with one of these, it will be blocked
     * Default: empty array (deny all)
     */
    allowedResources: z.array(z.string()).default([]),

    /**
     * SECURITY: Allowlist of permitted filesystem paths
     * Tool arguments containing paths must resolve within one of these directories.
     * Default: empty array means NO path restriction (all paths permitted).
     * To restrict access, list one or more allowed root directories.
     * A warning is logged at startup when this is empty.
     */
    allowedPaths: z.array(z.string()).default([]),

    /**
     * SECURITY: Block dangerous shell operators in tool arguments
     * Blocks: &&, |, ;, rm, sudo, backticks, $()
     * Default: true (enabled)
     */
    blockDangerousCommands: z.boolean().default(true),

    /**
     * SECURITY: PII Redaction for response content
     * Scans tool and resource outputs for sensitive data
     * Default: disabled (opt-in)
     */
    piiRedaction: z.object({
        /** Enable PII scanning on responses */
        enabled: z.boolean().default(false),
        /**
         * Patterns to detect and redact
         * Available: ssn, credit_card, bank_account, api_key, aws_key,
         *            password, private_key, jwt, connection_string,
         *            email, phone, ip_address, iban, swift, internal_url
         */
        patterns: z.array(z.string()).optional(),
    }).default({ enabled: false }),

    /**
     * SECURITY: Rate limiting for tool calls
     * Sliding-window counters (global + per-tool) reject requests once a
     * threshold is exceeded. Default: disabled (opt-in).
     */
    rateLimiting: z.object({
        /** Enable rate limiting */
        enabled: z.boolean().default(false),
        /** Sliding window duration in milliseconds */
        windowMs: z.number().int().positive().default(60_000),
        /** Maximum requests allowed within windowMs (global, across all tools) */
        maxRequests: z.number().int().positive().default(100),
        /** Per-tool overrides; omitted tools use the global windowMs/maxRequests */
        perTool: z.record(z.object({
            windowMs: z.number().int().positive().optional(),
            maxRequests: z.number().int().positive().optional(),
        })).optional(),
    }).optional(),

    /**
     * SECURITY: Request and response size limits
     * Rejects payloads that exceed configured byte thresholds.
     * Default: disabled (opt-in).
     */
    sizeLimits: z.object({
        /** Enable size limit enforcement */
        enabled: z.boolean().default(false),
        /** Maximum allowed request argument size in bytes */
        maxRequestBytes: z.number().int().positive().default(1_048_576),
        /** Maximum allowed response content size in bytes */
        maxResponseBytes: z.number().int().positive().default(10_485_760),
    }).optional(),

    /** Logging configuration */
    logging: z.object({
        level: z.enum(["debug", "info", "warn", "error"]).default("info"),
        destination: z.enum(["stdout", "file"]).default("stdout"),
        filePath: z.string().optional(),
    }).default({}),
}).refine(
    data => Boolean(data.targetCommand) !== Boolean(data.targetUrl),
    { message: "Exactly one of targetCommand or targetUrl must be set, not both or neither" }
);

export type AirlockConfig = z.infer<typeof ConfigSchema>;

/**
 * Load and validate configuration from a file
 * 
 * @param configPath - Path to configuration JSON file
 * @returns Validated configuration object
 * @throws {Error} If configuration is invalid
 */
export async function loadConfig(configPath: string): Promise<AirlockConfig> {
    const fs = await import("fs/promises");

    try {
        const content = await fs.readFile(configPath, "utf-8");
        const parsed = JSON.parse(content);
        return ConfigSchema.parse(parsed);
    } catch (error) {
        if (error instanceof z.ZodError) {
            throw new Error(
                `Invalid configuration: ${error.errors.map(e => `${e.path.join(".")}: ${e.message}`).join(", ")}`
            );
        }
        throw error;
    }
}
