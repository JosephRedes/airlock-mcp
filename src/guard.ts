import type { Logger } from "./logger.js";
import type { AirlockConfig } from "./config.js";
import fs from "fs";
import path from "path";

/**
 * Dangerous shell patterns that could lead to command injection
 */
const DANGEROUS_PATTERNS = [
    /&&/,           // Command chaining
    /\|\s*\w/,      // Pipe to command
    /;/,            // Command separator
    /\brm\b/,       // Remove command
    /\bsudo\b/,     // Privilege escalation
    /`.*`/,         // Backtick execution
    /\$\(/,         // Command substitution
];

/**
 * Security guard for tool execution requests
 * 
 * Security Principles Applied:
 * 1. Fail-safe defaults: Deny by default
 * 2. Least privilege: Only explicitly allowed tools pass
 * 3. Defense in depth: Separate validation from execution
 * 4. Audit logging: All decisions are logged
 */
export class ToolGuard {
    private allowedTools: Set<string>;
    private allowedResources: string[];
    private allowedPaths: string[];
    private blockDangerousCommands: boolean;
    private logger: Logger;

    constructor(config: AirlockConfig, logger: Logger) {
        // Security: Use Set for O(1) lookup and immutability
        this.allowedTools = new Set(config.allowedTools);
        this.allowedResources = config.allowedResources;
        this.allowedPaths = config.allowedPaths;
        this.blockDangerousCommands = config.blockDangerousCommands;
        this.logger = logger;

        this.logger.info({
            msg: "ToolGuard initialized",
            allowedToolCount: this.allowedTools.size,
            allowedResourceCount: this.allowedResources.length,
            allowedPathCount: this.allowedPaths.length,
            blockDangerousCommands: this.blockDangerousCommands,
            allowedTools: Array.from(this.allowedTools),
            allowedResources: this.allowedResources,
            allowedPaths: this.allowedPaths,
        });

        if (this.allowedPaths.length === 0) {
            this.logger.warn({
                msg: "allowedPaths is empty - all filesystem paths are permitted. Set allowedPaths in your config to restrict access.",
                severity: "high",
            });
        }
    }

    /**
     * Validate if a tool is allowed to be called
     * 
     * @param toolName - Name of the tool being invoked
     * @returns true if allowed, false otherwise
     * 
     * Security: Pure function, no side effects, easy to test
     */
    isToolAllowed(toolName: string): boolean {
        const allowed = this.allowedTools.has(toolName);

        // Security: Audit log every decision
        this.logger[allowed ? "info" : "warn"]({
            msg: "Tool access check",
            tool: toolName,
            allowed,
            decision: allowed ? "permit" : "deny",
        });

        return allowed;
    }

    /**
     * Validate if a resource URI is allowed to be read
     * 
     * @param uri - URI of the resource being accessed
     * @returns true if allowed, false otherwise
     * 
     * Security: Prefix-based matching for mcp:// URIs
     */
    isResourceAllowed(uri: string): boolean {
        const allowed = this.allowedResources.some(prefix => uri.startsWith(prefix));

        this.logger[allowed ? "info" : "warn"]({
            msg: "Resource access check",
            uri,
            allowed,
            decision: allowed ? "permit" : "deny",
        });

        return allowed;
    }

    /**
     * Validate if a filepath is within allowed directories
     * 
     * Security Hardening:
     * - Decodes URL encoding (%2e%2e = ..)
     * - Follows symlinks to get real path
     * - Checks boundary with path separator
     * 
     * @param filepath - Path to validate
     * @returns true if allowed, false otherwise
     */
    isPathAllowed(filepath: string): boolean {
        // If no path restrictions configured, allow all (backwards compatibility)
        if (this.allowedPaths.length === 0) {
            return true;
        }

        try {
            // 1. Decode URL encoding (handles %2e%2e attacks)
            const decoded = decodeURIComponent(filepath);

            // 2. Resolve to absolute path
            const resolved = path.resolve(decoded);

            // 3. Check if path exists and follow symlinks
            let realPath: string;
            try {
                realPath = fs.realpathSync(resolved);
            } catch {
                // Path doesn't exist yet (e.g., creating new file)
                // Validate the parent directory instead
                const parentDir = path.dirname(resolved);
                try {
                    realPath = fs.realpathSync(parentDir);
                } catch {
                    // Parent doesn't exist either, deny
                    this.logger.warn({
                        msg: "Path validation failed",
                        filepath,
                        reason: "path_not_found",
                    });
                    return false;
                }
            }

            // 4. Check if real path is within any allowed root
            const allowed = this.allowedPaths.some(allowedRoot => {
                const resolvedRoot = path.resolve(allowedRoot);
                // Boundary check: path must be exactly root or start with root + separator
                return realPath === resolvedRoot || realPath.startsWith(resolvedRoot + path.sep);
            });

            this.logger[allowed ? "info" : "warn"]({
                msg: "Path access check",
                filepath,
                realPath,
                allowed,
                decision: allowed ? "permit" : "deny",
            });

            return allowed;
        } catch (error) {
            this.logger.warn({
                msg: "Path validation error",
                filepath,
                error: String(error),
            });
            return false;
        }
    }

    /**
     * Check if tool arguments contain dangerous shell operators
     * 
     * @param args - Tool arguments object
     * @returns true if safe, false if dangerous patterns found
     */
    isCommandSafe(args: Record<string, unknown>): boolean {
        if (!this.blockDangerousCommands) {
            return true;
        }

        const argsString = JSON.stringify(args);

        for (const pattern of DANGEROUS_PATTERNS) {
            if (pattern.test(argsString)) {
                this.logger.warn({
                    msg: "Dangerous command pattern detected",
                    pattern: pattern.toString(),
                    severity: "high",
                });
                return false;
            }
        }

        this.logger.debug({
            msg: "Command safety check passed",
        });

        return true;
    }

    /**
     * Filter a tool list to only include tools in the allowlist.
     * If allowedTools is empty, returns an empty list (deny-by-default).
     *
     * @param tools - Array of tool objects with at least a `name` field
     * @returns Filtered array containing only permitted tools
     */
    filterToolList<T extends { name: string }>(tools: T[]): T[] {
        if (this.allowedTools.size === 0) return [];
        return tools.filter(t => this.allowedTools.has(t.name));
    }

    /**
     * Get error for path violation
     */
    getPathViolationError(filepath: string): {
        code: number;
        message: string;
        data: { type: string; path: string };
    } {
        this.logger.warn({
            msg: "Security policy violation",
            type: "path_violation",
            path: filepath,
            severity: "high",
        });

        return {
            code: -32001,
            message: "Security policy violation: Path outside allowed directory",
            data: {
                type: "path_violation",
                path: filepath,
            },
        };
    }

    /**
     * Get error for dangerous command
     */
    getDangerousCommandError(): {
        code: number;
        message: string;
        data: { type: string };
    } {
        this.logger.warn({
            msg: "Security policy violation",
            type: "command_blocked",
            severity: "critical",
        });

        return {
            code: -32000,
            message: "Security policy violation: Dangerous command pattern detected",
            data: {
                type: "command_blocked",
            },
        };
    }

    /**
     * Get a security error for a blocked resource
     */
    getBlockedResourceError(uri: string): {
        code: number;
        message: string;
        data: { type: string; uri: string };
    } {
        this.logger.warn({
            msg: "Security policy violation",
            type: "resource_blocked",
            uri: uri,
            severity: "medium",
        });

        return {
            code: -32003,
            message: "Security policy violation: Resource not allowed",
            data: {
                type: "resource_blocked",
                uri: uri,
            },
        };
    }

    /**
     * Get a security error for a blocked tool
     * 
     * Security: Don't leak allowlist in error message (information disclosure)
     * 10x Engineering: Clear, actionable error messages for legitimate users
     */
    getBlockedToolError(toolName: string): {
        code: number;
        message: string;
        data: { type: string; tool: string };
    } {
        // Security event: Log attempted access to blocked tool
        this.logger.warn({
            msg: "Security policy violation",
            type: "tool_blocked",
            tool: toolName,
            severity: "medium",
        });

        return {
            code: -32000,
            message: "Security policy violation: Tool not allowed",
            data: {
                type: "tool_blocked",
                tool: toolName,
            },
        };
    }
}

