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
    /** Command to spawn the target MCP server */
    targetCommand: z.string().min(1),

    /** Arguments to pass to the target command */
    targetArgs: z.array(z.string()).default([]),

    /** Environment variables for the target server */
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
     * Tool arguments containing paths must resolve within one of these directories
     * Default: empty array (no path restriction - for backwards compatibility)
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

    /** Logging configuration */
    logging: z.object({
        level: z.enum(["debug", "info", "warn", "error"]).default("info"),
        destination: z.enum(["stdout", "file"]).default("stdout"),
        filePath: z.string().optional(),
    }).default({}),
});

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
