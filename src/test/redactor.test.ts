import { describe, it, expect } from "vitest";
import { PIIRedactor } from "../redactor.js";
import type { AirlockConfig } from "../config.js";

// Mock logger
const mockLogger = {
    info: () => { },
    warn: () => { },
    debug: () => { },
    error: () => { },
} as any;

describe("PIIRedactor", () => {
    describe("when disabled", () => {
        it("should return content unchanged", () => {
            const config: AirlockConfig = {
                targetCommand: "test",
                targetArgs: [],
                allowedTools: [],
                allowedResources: [],
                allowedPaths: [],
                blockDangerousCommands: true,
                piiRedaction: { enabled: false },
                logging: { level: "info", destination: "stdout" },
            };
            const redactor = new PIIRedactor(config, mockLogger);

            const input = "SSN: 123-45-6789, Card: 4111-1111-1111-1111";
            const { redacted, counts } = redactor.redact(input);

            expect(redacted).toBe(input);
            expect(Object.keys(counts)).toHaveLength(0);
        });
    });

    describe("SSN detection", () => {
        it("should redact US Social Security Numbers", () => {
            const config: AirlockConfig = {
                targetCommand: "test",
                targetArgs: [],
                allowedTools: [],
                allowedResources: [],
                allowedPaths: [],
                blockDangerousCommands: true,
                piiRedaction: { enabled: true, patterns: ["ssn"] },
                logging: { level: "info", destination: "stdout" },
            };
            const redactor = new PIIRedactor(config, mockLogger);

            const input = "Customer SSN is 123-45-6789";
            const { redacted, counts } = redactor.redact(input);

            expect(redacted).toBe("Customer SSN is [SSN:REDACTED]");
            expect(counts.ssn).toBe(1);
        });

        it("should redact multiple SSNs", () => {
            const config: AirlockConfig = {
                targetCommand: "test",
                targetArgs: [],
                allowedTools: [],
                allowedResources: [],
                allowedPaths: [],
                blockDangerousCommands: true,
                piiRedaction: { enabled: true, patterns: ["ssn"] },
                logging: { level: "info", destination: "stdout" },
            };
            const redactor = new PIIRedactor(config, mockLogger);

            const input = "SSN1: 123-45-6789, SSN2: 987-65-4321";
            const { redacted, counts } = redactor.redact(input);

            expect(redacted).toBe("SSN1: [SSN:REDACTED], SSN2: [SSN:REDACTED]");
            expect(counts.ssn).toBe(2);
        });
    });

    describe("Credit Card detection", () => {
        it("should redact credit card numbers", () => {
            const config: AirlockConfig = {
                targetCommand: "test",
                targetArgs: [],
                allowedTools: [],
                allowedResources: [],
                allowedPaths: [],
                blockDangerousCommands: true,
                piiRedaction: { enabled: true, patterns: ["credit_card"] },
                logging: { level: "info", destination: "stdout" },
            };
            const redactor = new PIIRedactor(config, mockLogger);

            const input = "Card: 4111-1111-1111-1111";
            const { redacted } = redactor.redact(input);

            expect(redacted).toBe("Card: [CREDIT_CARD:REDACTED]");
        });

        it("should redact cards with spaces", () => {
            const config: AirlockConfig = {
                targetCommand: "test",
                targetArgs: [],
                allowedTools: [],
                allowedResources: [],
                allowedPaths: [],
                blockDangerousCommands: true,
                piiRedaction: { enabled: true, patterns: ["credit_card"] },
                logging: { level: "info", destination: "stdout" },
            };
            const redactor = new PIIRedactor(config, mockLogger);

            const input = "Card: 4111 1111 1111 1111";
            const { redacted } = redactor.redact(input);

            expect(redacted).toBe("Card: [CREDIT_CARD:REDACTED]");
        });
    });

    describe("API Key detection", () => {
        it("should redact API keys", () => {
            const config: AirlockConfig = {
                targetCommand: "test",
                targetArgs: [],
                allowedTools: [],
                allowedResources: [],
                allowedPaths: [],
                blockDangerousCommands: true,
                piiRedaction: { enabled: true, patterns: ["api_key"] },
                logging: { level: "info", destination: "stdout" },
            };
            const redactor = new PIIRedactor(config, mockLogger);

            const input = "API key: sk-abc123456789abcdef1234567890";
            const { redacted } = redactor.redact(input);

            expect(redacted).toBe("API key: [API_KEY:REDACTED]");
        });
    });

    describe("Email detection", () => {
        it("should redact email addresses", () => {
            const config: AirlockConfig = {
                targetCommand: "test",
                targetArgs: [],
                allowedTools: [],
                allowedResources: [],
                allowedPaths: [],
                blockDangerousCommands: true,
                piiRedaction: { enabled: true, patterns: ["email"] },
                logging: { level: "info", destination: "stdout" },
            };
            const redactor = new PIIRedactor(config, mockLogger);

            const input = "Contact: john.doe@company.com";
            const { redacted } = redactor.redact(input);

            expect(redacted).toBe("Contact: [EMAIL:REDACTED]");
        });
    });

    describe("JWT detection", () => {
        it("should redact JWT tokens", () => {
            const config: AirlockConfig = {
                targetCommand: "test",
                targetArgs: [],
                allowedTools: [],
                allowedResources: [],
                allowedPaths: [],
                blockDangerousCommands: true,
                piiRedaction: { enabled: true, patterns: ["jwt"] },
                logging: { level: "info", destination: "stdout" },
            };
            const redactor = new PIIRedactor(config, mockLogger);

            const input = "Token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
            const { redacted } = redactor.redact(input);

            expect(redacted).toBe("Token: [JWT:REDACTED]");
        });
    });

    describe("Multiple pattern detection", () => {
        it("should redact multiple pattern types", () => {
            const config: AirlockConfig = {
                targetCommand: "test",
                targetArgs: [],
                allowedTools: [],
                allowedResources: [],
                allowedPaths: [],
                blockDangerousCommands: true,
                piiRedaction: { enabled: true, patterns: ["ssn", "email", "api_key"] },
                logging: { level: "info", destination: "stdout" },
            };
            const redactor = new PIIRedactor(config, mockLogger);

            const input = "SSN: 123-45-6789, Email: test@example.com, Key: sk-test12345678901234567890";
            const { redacted, counts } = redactor.redact(input);

            expect(redacted).toContain("[SSN:REDACTED]");
            expect(redacted).toContain("[EMAIL:REDACTED]");
            expect(redacted).toContain("[API_KEY:REDACTED]");
            expect(counts.ssn).toBe(1);
            expect(counts.email).toBe(1);
        });
    });

    describe("SWIFT code handling", () => {
        it("should NOT redact SWIFT codes with default patterns", () => {
            const config: AirlockConfig = {
                targetCommand: "test",
                targetArgs: [],
                allowedTools: [],
                allowedResources: [],
                allowedPaths: [],
                blockDangerousCommands: true,
                piiRedaction: { enabled: true },
                logging: { level: "info", destination: "stdout" },
            };
            const redactor = new PIIRedactor(config, mockLogger);

            const input = "Bank SWIFT code: DEUTDEDB";
            const { redacted } = redactor.redact(input);

            expect(redacted).toBe(input);
        });

        it("should redact SWIFT codes when explicitly opted in", () => {
            const config: AirlockConfig = {
                targetCommand: "test",
                targetArgs: [],
                allowedTools: [],
                allowedResources: [],
                allowedPaths: [],
                blockDangerousCommands: true,
                piiRedaction: { enabled: true, patterns: ["swift"] },
                logging: { level: "info", destination: "stdout" },
            };
            const redactor = new PIIRedactor(config, mockLogger);

            const input = "Bank SWIFT code: DEUTDEDB";
            const { redacted } = redactor.redact(input);

            expect(redacted).toBe("Bank SWIFT code: [SWIFT:REDACTED]");
        });
    });

    describe("isEnabled", () => {
        it("should return false when disabled", () => {
            const config: AirlockConfig = {
                targetCommand: "test",
                targetArgs: [],
                allowedTools: [],
                allowedResources: [],
                allowedPaths: [],
                blockDangerousCommands: true,
                piiRedaction: { enabled: false },
                logging: { level: "info", destination: "stdout" },
            };
            const redactor = new PIIRedactor(config, mockLogger);

            expect(redactor.isEnabled()).toBe(false);
        });

        it("should return true when enabled", () => {
            const config: AirlockConfig = {
                targetCommand: "test",
                targetArgs: [],
                allowedTools: [],
                allowedResources: [],
                allowedPaths: [],
                blockDangerousCommands: true,
                piiRedaction: { enabled: true },
                logging: { level: "info", destination: "stdout" },
            };
            const redactor = new PIIRedactor(config, mockLogger);

            expect(redactor.isEnabled()).toBe(true);
        });
    });
});
