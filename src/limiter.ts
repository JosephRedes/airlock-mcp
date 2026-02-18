import type { Logger } from "./logger.js";
import type { AirlockConfig } from "./config.js";

/**
 * RateLimiter: sliding-window rate limiting and payload size enforcement
 *
 * Security Principles Applied:
 * 1. Fail-safe defaults: disabled by default (opt-in)
 * 2. Defense in depth: separate global and per-tool budgets
 * 3. No budget consumption on blocked requests
 * 4. Audit logging: all violations are logged
 */
export class RateLimiter {
    private readonly enabled: boolean;
    private readonly windowMs: number;
    private readonly maxRequests: number;
    private readonly perTool: Record<string, { windowMs?: number; maxRequests?: number }>;

    private readonly sizeLimitsEnabled: boolean;
    private readonly maxRequestBytes: number;
    private readonly maxResponseBytes: number;

    /** Sliding-window timestamp buckets keyed by tool name or "__global__" */
    private readonly buckets: Map<string, number[]> = new Map();

    private readonly logger: Logger;

    constructor(config: AirlockConfig, logger: Logger) {
        const rl = config.rateLimiting;
        this.enabled = rl?.enabled ?? false;
        this.windowMs = rl?.windowMs ?? 60_000;
        this.maxRequests = rl?.maxRequests ?? 100;
        this.perTool = rl?.perTool ?? {};

        const sl = config.sizeLimits;
        this.sizeLimitsEnabled = sl?.enabled ?? false;
        this.maxRequestBytes = sl?.maxRequestBytes ?? 1_048_576;
        this.maxResponseBytes = sl?.maxResponseBytes ?? 10_485_760;

        this.logger = logger;

        this.logger.info({
            msg: "RateLimiter initialized",
            rateLimitingEnabled: this.enabled,
            sizeLimitsEnabled: this.sizeLimitsEnabled,
        });
    }

    /**
     * Check whether a tool call should be rate-limited.
     *
     * Both the global budget and any per-tool budget are evaluated before
     * consuming either, so blocked requests never spend quota.
     *
     * @param toolName - Name of the tool being called
     * @returns true if the request should be blocked, false if allowed
     */
    isToolRateLimited(toolName: string): boolean {
        if (!this.enabled) return false;

        const now = Date.now();

        // Evaluate both buckets before mutating either
        const globalOver = this.isOverLimit("__global__", now, this.windowMs, this.maxRequests);

        const toolConfig = this.perTool[toolName];
        const toolOver = toolConfig
            ? this.isOverLimit(
                toolName,
                now,
                toolConfig.windowMs ?? this.windowMs,
                toolConfig.maxRequests ?? this.maxRequests,
            )
            : false;

        if (globalOver || toolOver) {
            return true;
        }

        // Under both limits - consume quota
        this.addToHistory("__global__", now);
        if (toolConfig) {
            this.addToHistory(toolName, now);
        }

        return false;
    }

    /**
     * Prune stale timestamps and check whether the bucket is at or over the
     * limit. Does NOT add the current timestamp (read-only operation).
     */
    private isOverLimit(key: string, now: number, windowMs: number, maxRequests: number): boolean {
        let timestamps = this.buckets.get(key) ?? [];
        timestamps = timestamps.filter(t => now - t < windowMs);
        this.buckets.set(key, timestamps); // persist pruned list
        return timestamps.length >= maxRequests;
    }

    /** Append the current timestamp to a bucket. */
    private addToHistory(key: string, now: number): void {
        const timestamps = this.buckets.get(key) ?? [];
        timestamps.push(now);
        this.buckets.set(key, timestamps);
    }

    /**
     * Build a rate-limit error object (MCP-compatible).
     *
     * @param toolName - Tool that triggered the limit (used for audit logging)
     */
    getRateLimitError(toolName: string): { code: number; message: string; data: { type: string } } {
        this.logger.warn({
            msg: "Security policy violation",
            type: "rate_limit_exceeded",
            tool: toolName,
            severity: "high",
        });

        return {
            code: -32029,
            message: "Security policy violation: Rate limit exceeded",
            data: { type: "rate_limit_exceeded" },
        };
    }

    /**
     * Check whether the serialised request arguments exceed the configured
     * byte limit.
     *
     * @param args - Tool argument map (will be JSON-serialised for measurement)
     * @returns true if the payload is too large
     */
    isRequestTooLarge(args: Record<string, unknown>): boolean {
        if (!this.sizeLimitsEnabled) return false;

        const bytes = Buffer.byteLength(JSON.stringify(args), "utf8");
        const tooLarge = bytes > this.maxRequestBytes;

        if (tooLarge) {
            this.logger.warn({
                msg: "Request size limit exceeded",
                bytes,
                maxBytes: this.maxRequestBytes,
                severity: "medium",
            });
        }

        return tooLarge;
    }

    /**
     * Check whether the total byte length of text content items in a response
     * exceeds the configured limit.
     *
     * @param content - Array of MCP content items
     * @returns true if the combined text size is too large
     */
    isResponseTooLarge(content: unknown[]): boolean {
        if (!this.sizeLimitsEnabled) return false;

        let totalBytes = 0;
        for (const item of content) {
            if (
                item !== null &&
                typeof item === "object" &&
                "text" in item &&
                typeof (item as { text: unknown }).text === "string"
            ) {
                totalBytes += Buffer.byteLength((item as { text: string }).text, "utf8");
            }
        }

        const tooLarge = totalBytes > this.maxResponseBytes;

        if (tooLarge) {
            this.logger.warn({
                msg: "Response size limit exceeded",
                bytes: totalBytes,
                maxBytes: this.maxResponseBytes,
                severity: "medium",
            });
        }

        return tooLarge;
    }

    /**
     * Build a size-limit error object (MCP-compatible).
     *
     * @param direction - Whether the oversized payload is a "request" or "response"
     */
    getSizeLimitError(direction: "request" | "response"): { code: number; message: string; data: { type: string } } {
        return {
            code: -32030,
            message: `Security policy violation: ${direction === "request" ? "Request" : "Response"} exceeds size limit`,
            data: { type: `${direction}_too_large` },
        };
    }
}
