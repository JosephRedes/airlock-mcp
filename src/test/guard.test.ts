import { describe, it, expect, beforeEach } from "vitest";
import { ToolGuard } from "../guard.js";
import type { AirlockConfig } from "../config.js";

// Mock logger
const mockLogger = {
    info: () => { },
    warn: () => { },
    debug: () => { },
    error: () => { },
} as any;

describe("ToolGuard", () => {
    describe("isToolAllowed", () => {
        it("should allow tools in the allowlist", () => {
            const config: AirlockConfig = {
                targetCommand: "test",
                allowedTools: ["read_file", "write_file"],
                allowedResources: [],
                allowedPaths: [],
                blockDangerousCommands: true,
                piiRedaction: { enabled: false },
                logging: { level: "info", destination: "stdout" },
            };
            const guard = new ToolGuard(config, mockLogger);

            expect(guard.isToolAllowed("read_file")).toBe(true);
            expect(guard.isToolAllowed("write_file")).toBe(true);
        });

        it("should block tools not in the allowlist", () => {
            const config: AirlockConfig = {
                targetCommand: "test",
                allowedTools: ["read_file"],
                allowedResources: [],
                allowedPaths: [],
                blockDangerousCommands: true,
                piiRedaction: { enabled: false },
                logging: { level: "info", destination: "stdout" },
            };
            const guard = new ToolGuard(config, mockLogger);

            expect(guard.isToolAllowed("delete_file")).toBe(false);
            expect(guard.isToolAllowed("execute_command")).toBe(false);
        });

        it("should be case-sensitive", () => {
            const config: AirlockConfig = {
                targetCommand: "test",
                allowedTools: ["read_file"],
                allowedResources: [],
                allowedPaths: [],
                blockDangerousCommands: true,
                piiRedaction: { enabled: false },
                logging: { level: "info", destination: "stdout" },
            };
            const guard = new ToolGuard(config, mockLogger);

            expect(guard.isToolAllowed("read_file")).toBe(true);
            expect(guard.isToolAllowed("READ_FILE")).toBe(false);
            expect(guard.isToolAllowed("Read_File")).toBe(false);
        });

        it("should block all tools when allowlist is empty", () => {
            const config: AirlockConfig = {
                targetCommand: "test",
                allowedTools: [],
                allowedResources: [],
                allowedPaths: [],
                blockDangerousCommands: true,
                piiRedaction: { enabled: false },
                logging: { level: "info", destination: "stdout" },
            };
            const guard = new ToolGuard(config, mockLogger);

            expect(guard.isToolAllowed("any_tool")).toBe(false);
        });
    });

    describe("isResourceAllowed", () => {
        it("should allow resources matching prefix", () => {
            const config: AirlockConfig = {
                targetCommand: "test",
                allowedTools: [],
                allowedResources: ["mcp://public/", "mcp://logs/"],
                allowedPaths: [],
                blockDangerousCommands: true,
                piiRedaction: { enabled: false },
                logging: { level: "info", destination: "stdout" },
            };
            const guard = new ToolGuard(config, mockLogger);

            expect(guard.isResourceAllowed("mcp://public/data.txt")).toBe(true);
            expect(guard.isResourceAllowed("mcp://logs/app.log")).toBe(true);
        });

        it("should block resources not matching any prefix", () => {
            const config: AirlockConfig = {
                targetCommand: "test",
                allowedTools: [],
                allowedResources: ["mcp://public/"],
                allowedPaths: [],
                blockDangerousCommands: true,
                piiRedaction: { enabled: false },
                logging: { level: "info", destination: "stdout" },
            };
            const guard = new ToolGuard(config, mockLogger);

            expect(guard.isResourceAllowed("mcp://secret/passwords.txt")).toBe(false);
            expect(guard.isResourceAllowed("mcp://private/keys")).toBe(false);
        });

        it("should block all resources when allowlist is empty", () => {
            const config: AirlockConfig = {
                targetCommand: "test",
                allowedTools: [],
                allowedResources: [],
                allowedPaths: [],
                blockDangerousCommands: true,
                piiRedaction: { enabled: false },
                logging: { level: "info", destination: "stdout" },
            };
            const guard = new ToolGuard(config, mockLogger);

            expect(guard.isResourceAllowed("mcp://anything")).toBe(false);
        });
    });

    describe("isCommandSafe", () => {
        let guard: ToolGuard;

        beforeEach(() => {
            const config: AirlockConfig = {
                targetCommand: "test",
                allowedTools: [],
                allowedResources: [],
                allowedPaths: [],
                blockDangerousCommands: true,
                piiRedaction: { enabled: false },
                logging: { level: "info", destination: "stdout" },
            };
            guard = new ToolGuard(config, mockLogger);
        });

        it("should allow safe commands", () => {
            expect(guard.isCommandSafe({ input: "hello world" })).toBe(true);
            expect(guard.isCommandSafe({ path: "/home/user/file.txt" })).toBe(true);
        });

        it("should block command chaining (&&)", () => {
            expect(guard.isCommandSafe({ input: "echo hello && rm -rf /" })).toBe(false);
        });

        it("should block pipes (|)", () => {
            expect(guard.isCommandSafe({ input: "cat file | grep secret" })).toBe(false);
        });

        it("should block semicolons (;)", () => {
            expect(guard.isCommandSafe({ input: "echo hello; rm file" })).toBe(false);
        });

        it("should block rm command", () => {
            expect(guard.isCommandSafe({ input: "rm -rf /important" })).toBe(false);
        });

        it("should block sudo", () => {
            expect(guard.isCommandSafe({ input: "sudo apt install malware" })).toBe(false);
        });

        it("should block backticks", () => {
            expect(guard.isCommandSafe({ input: "echo `whoami`" })).toBe(false);
        });

        it("should block command substitution $()", () => {
            expect(guard.isCommandSafe({ input: "echo $(cat /etc/passwd)" })).toBe(false);
        });

        it("should allow commands when blocking is disabled", () => {
            const config: AirlockConfig = {
                targetCommand: "test",
                allowedTools: [],
                allowedResources: [],
                allowedPaths: [],
                blockDangerousCommands: false,
                piiRedaction: { enabled: false },
                logging: { level: "info", destination: "stdout" },
            };
            const permissiveGuard = new ToolGuard(config, mockLogger);

            expect(permissiveGuard.isCommandSafe({ input: "rm -rf /" })).toBe(true);
        });
    });

    describe("isPathAllowed", () => {
        it("should allow all paths when allowedPaths is empty (backwards compat)", () => {
            const config: AirlockConfig = {
                targetCommand: "test",
                allowedTools: [],
                allowedResources: [],
                allowedPaths: [],
                blockDangerousCommands: true,
                piiRedaction: { enabled: false },
                logging: { level: "info", destination: "stdout" },
            };
            const guard = new ToolGuard(config, mockLogger);

            expect(guard.isPathAllowed("/any/path")).toBe(true);
            expect(guard.isPathAllowed("../traversal")).toBe(true);
        });

        it("should block paths outside allowed directories", () => {
            const config: AirlockConfig = {
                targetCommand: "test",
                allowedTools: [],
                allowedResources: [],
                allowedPaths: ["C:\\Users\\test\\project"],
                blockDangerousCommands: true,
                piiRedaction: { enabled: false },
                logging: { level: "info", destination: "stdout" },
            };
            const guard = new ToolGuard(config, mockLogger);

            // This should be blocked - outside allowed path
            expect(guard.isPathAllowed("C:\\Windows\\System32")).toBe(false);
        });

        it("should block URL-encoded traversal attempts", () => {
            const config: AirlockConfig = {
                targetCommand: "test",
                allowedTools: [],
                allowedResources: [],
                allowedPaths: ["C:\\Users\\test\\project"],
                blockDangerousCommands: true,
                piiRedaction: { enabled: false },
                logging: { level: "info", destination: "stdout" },
            };
            const guard = new ToolGuard(config, mockLogger);

            // %2e%2e = ..
            expect(guard.isPathAllowed("%2e%2e%2f%2e%2e%2fetc%2fpasswd")).toBe(false);
        });
    });
});
