import { describe, it, expect, vi, afterEach } from "vitest";
import { RateLimiter } from "../limiter.js";
import type { AirlockConfig } from "../config.js";

// Mock logger - same pattern as guard.test.ts
const mockLogger = {
    info: () => { },
    warn: () => { },
    debug: () => { },
    error: () => { },
} as any;

/** Minimal valid config with sensible defaults; override individual fields as needed */
function makeConfig(overrides: Partial<AirlockConfig> = {}): AirlockConfig {
    return {
        targetCommand: "test",
        targetArgs: [],
        allowedTools: [],
        allowedResources: [],
        allowedPaths: [],
        blockDangerousCommands: true,
        piiRedaction: { enabled: false },
        logging: { level: "info", destination: "stdout" },
        ...overrides,
    };
}

describe("RateLimiter", () => {
    afterEach(() => {
        vi.restoreAllMocks();
    });

    // -------------------------------------------------------------------------
    // Disabled
    // -------------------------------------------------------------------------
    describe("when disabled", () => {
        it("isToolRateLimited always returns false regardless of call volume", () => {
            const limiter = new RateLimiter(
                makeConfig({ rateLimiting: { enabled: false, windowMs: 60_000, maxRequests: 1 } }),
                mockLogger,
            );

            for (let i = 0; i < 200; i++) {
                expect(limiter.isToolRateLimited("any_tool")).toBe(false);
            }
        });
    });

    // -------------------------------------------------------------------------
    // Global rate limiting
    // -------------------------------------------------------------------------
    describe("global rate limiting", () => {
        it("does not limit requests under the global threshold", () => {
            const limiter = new RateLimiter(
                makeConfig({ rateLimiting: { enabled: true, windowMs: 60_000, maxRequests: 3 } }),
                mockLogger,
            );

            expect(limiter.isToolRateLimited("tool_a")).toBe(false);
            expect(limiter.isToolRateLimited("tool_b")).toBe(false);
        });

        it("allows the maxRequests-th request (equal to limit, not over)", () => {
            const limiter = new RateLimiter(
                makeConfig({ rateLimiting: { enabled: true, windowMs: 60_000, maxRequests: 3 } }),
                mockLogger,
            );

            expect(limiter.isToolRateLimited("tool")).toBe(false); // 1
            expect(limiter.isToolRateLimited("tool")).toBe(false); // 2
            expect(limiter.isToolRateLimited("tool")).toBe(false); // 3 - exactly at limit
        });

        it("blocks the request after global limit is exceeded", () => {
            const limiter = new RateLimiter(
                makeConfig({ rateLimiting: { enabled: true, windowMs: 60_000, maxRequests: 3 } }),
                mockLogger,
            );

            limiter.isToolRateLimited("tool"); // 1
            limiter.isToolRateLimited("tool"); // 2
            limiter.isToolRateLimited("tool"); // 3

            expect(limiter.isToolRateLimited("tool")).toBe(true); // 4 - over limit
        });

        it("blocked requests do not consume global quota", () => {
            const limiter = new RateLimiter(
                makeConfig({ rateLimiting: { enabled: true, windowMs: 60_000, maxRequests: 2 } }),
                mockLogger,
            );

            limiter.isToolRateLimited("tool"); // 1
            limiter.isToolRateLimited("tool"); // 2

            // These are all blocked - quota stays at 2, not growing further
            expect(limiter.isToolRateLimited("tool")).toBe(true);
            expect(limiter.isToolRateLimited("tool")).toBe(true);
            expect(limiter.isToolRateLimited("tool")).toBe(true);
        });
    });

    // -------------------------------------------------------------------------
    // Per-tool rate limiting
    // -------------------------------------------------------------------------
    describe("per-tool rate limiting", () => {
        it("limits a specific tool before the global limit is reached", () => {
            const limiter = new RateLimiter(
                makeConfig({
                    rateLimiting: {
                        enabled: true,
                        windowMs: 60_000,
                        maxRequests: 100,
                        perTool: {
                            restricted_tool: { maxRequests: 2 },
                        },
                    },
                }),
                mockLogger,
            );

            expect(limiter.isToolRateLimited("restricted_tool")).toBe(false); // 1
            expect(limiter.isToolRateLimited("restricted_tool")).toBe(false); // 2
            expect(limiter.isToolRateLimited("restricted_tool")).toBe(true);  // 3 - per-tool limit
        });

        it("does not affect other tools when one tool is limited", () => {
            const limiter = new RateLimiter(
                makeConfig({
                    rateLimiting: {
                        enabled: true,
                        windowMs: 60_000,
                        maxRequests: 100,
                        perTool: {
                            restricted_tool: { maxRequests: 1 },
                        },
                    },
                }),
                mockLogger,
            );

            limiter.isToolRateLimited("restricted_tool"); // 1
            expect(limiter.isToolRateLimited("restricted_tool")).toBe(true); // blocked

            // Different tool should still be allowed
            expect(limiter.isToolRateLimited("other_tool")).toBe(false);
        });
    });

    // -------------------------------------------------------------------------
    // Sliding-window expiry
    // -------------------------------------------------------------------------
    describe("sliding window expiry", () => {
        it("timestamps older than windowMs are pruned and do not count", () => {
            let currentTime = 1_000_000;
            vi.spyOn(Date, "now").mockImplementation(() => currentTime);

            const limiter = new RateLimiter(
                makeConfig({ rateLimiting: { enabled: true, windowMs: 60_000, maxRequests: 3 } }),
                mockLogger,
            );

            limiter.isToolRateLimited("tool"); // 1
            limiter.isToolRateLimited("tool"); // 2
            limiter.isToolRateLimited("tool"); // 3

            expect(limiter.isToolRateLimited("tool")).toBe(true); // over limit

            // Advance past the window
            currentTime += 60_001;

            expect(limiter.isToolRateLimited("tool")).toBe(false); // window reset
        });

        it("only requests within the window count toward the limit", () => {
            let currentTime = 1_000_000;
            vi.spyOn(Date, "now").mockImplementation(() => currentTime);

            const limiter = new RateLimiter(
                makeConfig({ rateLimiting: { enabled: true, windowMs: 60_000, maxRequests: 3 } }),
                mockLogger,
            );

            limiter.isToolRateLimited("tool"); // at t=0 (inside window)
            limiter.isToolRateLimited("tool"); // at t=0

            // Advance so the two above will expire
            currentTime += 60_001;

            // These two are now inside the new window
            expect(limiter.isToolRateLimited("tool")).toBe(false);
            expect(limiter.isToolRateLimited("tool")).toBe(false);
            // Third is still allowed (old two are gone)
            expect(limiter.isToolRateLimited("tool")).toBe(false);
            // Fourth is blocked
            expect(limiter.isToolRateLimited("tool")).toBe(true);
        });
    });

    // -------------------------------------------------------------------------
    // Request size limits
    // -------------------------------------------------------------------------
    describe("isRequestTooLarge", () => {
        it("returns false when size limits are disabled", () => {
            const limiter = new RateLimiter(
                makeConfig({ sizeLimits: { enabled: false, maxRequestBytes: 10, maxResponseBytes: 10_000 } }),
                mockLogger,
            );

            expect(limiter.isRequestTooLarge({ big: "x".repeat(10_000) })).toBe(false);
        });

        it("returns false for a payload under the limit", () => {
            const limiter = new RateLimiter(
                makeConfig({ sizeLimits: { enabled: true, maxRequestBytes: 1_000, maxResponseBytes: 10_000 } }),
                mockLogger,
            );

            expect(limiter.isRequestTooLarge({ key: "small" })).toBe(false);
        });

        it("returns true when the payload exceeds the limit", () => {
            const limiter = new RateLimiter(
                makeConfig({ sizeLimits: { enabled: true, maxRequestBytes: 100, maxResponseBytes: 10_000 } }),
                mockLogger,
            );

            expect(limiter.isRequestTooLarge({ key: "x".repeat(200) })).toBe(true);
        });
    });

    // -------------------------------------------------------------------------
    // Response size limits
    // -------------------------------------------------------------------------
    describe("isResponseTooLarge", () => {
        it("returns false when size limits are disabled", () => {
            const limiter = new RateLimiter(
                makeConfig({ sizeLimits: { enabled: false, maxRequestBytes: 1_000, maxResponseBytes: 10 } }),
                mockLogger,
            );

            const content = [{ type: "text", text: "x".repeat(20_000_000) }];
            expect(limiter.isResponseTooLarge(content)).toBe(false);
        });

        it("returns false for a small response", () => {
            const limiter = new RateLimiter(
                makeConfig({ sizeLimits: { enabled: true, maxRequestBytes: 1_000, maxResponseBytes: 10_000 } }),
                mockLogger,
            );

            const content = [{ type: "text", text: "small response" }];
            expect(limiter.isResponseTooLarge(content)).toBe(false);
        });

        it("returns true when the response exceeds the limit", () => {
            const limiter = new RateLimiter(
                makeConfig({ sizeLimits: { enabled: true, maxRequestBytes: 1_000, maxResponseBytes: 1_000 } }),
                mockLogger,
            );

            const content = [{ type: "text", text: "x".repeat(2_000) }];
            expect(limiter.isResponseTooLarge(content)).toBe(true);
        });

        it("sums all text content items to compute total size", () => {
            const limiter = new RateLimiter(
                makeConfig({ sizeLimits: { enabled: true, maxRequestBytes: 1_000, maxResponseBytes: 1_000 } }),
                mockLogger,
            );

            // Each item is 600 bytes; combined 1200 bytes > 1000
            const content = [
                { type: "text", text: "x".repeat(600) },
                { type: "text", text: "x".repeat(600) },
            ];
            expect(limiter.isResponseTooLarge(content)).toBe(true);
        });

        it("ignores non-text content items when computing size", () => {
            const limiter = new RateLimiter(
                makeConfig({ sizeLimits: { enabled: true, maxRequestBytes: 1_000, maxResponseBytes: 1_000 } }),
                mockLogger,
            );

            const content = [
                { type: "image", data: "x".repeat(2_000) }, // should not count
                { type: "text", text: "small" },
            ];
            expect(limiter.isResponseTooLarge(content)).toBe(false);
        });
    });

    // -------------------------------------------------------------------------
    // Error object shapes
    // -------------------------------------------------------------------------
    describe("error objects", () => {
        it("getRateLimitError returns the expected structure", () => {
            const limiter = new RateLimiter(makeConfig(), mockLogger);
            const error = limiter.getRateLimitError("some_tool");

            expect(typeof error.code).toBe("number");
            expect(error.message).toContain("Rate limit");
            expect(error.data.type).toBe("rate_limit_exceeded");
        });

        it("getSizeLimitError for request direction contains 'Request'", () => {
            const limiter = new RateLimiter(makeConfig(), mockLogger);
            const error = limiter.getSizeLimitError("request");

            expect(typeof error.code).toBe("number");
            expect(error.message).toContain("Request");
            expect(error.data.type).toBe("request_too_large");
        });

        it("getSizeLimitError for response direction contains 'Response'", () => {
            const limiter = new RateLimiter(makeConfig(), mockLogger);
            const error = limiter.getSizeLimitError("response");

            expect(typeof error.code).toBe("number");
            expect(error.message).toContain("Response");
            expect(error.data.type).toBe("response_too_large");
        });
    });
});
