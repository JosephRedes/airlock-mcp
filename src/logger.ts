import pino from "pino";
import type { AirlockConfig } from "./config.js";

/**
 * Create a logger instance based on configuration
 * 
 * Security: Structured logging for audit trail
 * 10x Engineering: Single source of truth for logging
 */
export function createLogger(config: AirlockConfig["logging"]) {
    return pino({
        level: config.level,
        transport: config.destination === "file" && config.filePath
            ? { target: "pino/file", options: { destination: config.filePath } }
            : undefined,
        timestamp: pino.stdTimeFunctions.isoTime,
        formatters: {
            level: (label) => ({ level: label }),
        },
    });
}

export type Logger = ReturnType<typeof createLogger>;
