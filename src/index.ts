#!/usr/bin/env node

/**
 * Airlock-MCP Entry Point
 * 
 * Usage:
 *   airlock-mcp --config airlock.config.json
 * 
 * Security: Validates config before starting
 * 10x Engineering: Clear error messages, fast failure
 */

import { loadConfig } from "./config.js";
import { createLogger } from "./logger.js";
import { AirlockProxy } from "./proxy.js";

async function main() {
    // Parse command line arguments
    const args = process.argv.slice(2);
    const configIndex = args.indexOf("--config");

    if (configIndex === -1 || !args[configIndex + 1]) {
        console.error("Usage: airlock-mcp --config <config-file>");
        process.exit(1);
    }

    const configPath = args[configIndex + 1];

    try {
        // 1. Load and validate configuration
        const config = await loadConfig(configPath);

        // 2. Create logger
        const logger = createLogger(config.logging);
        logger.info({ msg: "Airlock-MCP starting", configPath });

        // Security: Log configuration (excluding sensitive data)
        logger.info({
            msg: "Configuration loaded",
            targetCommand: config.targetCommand,
            allowedToolCount: config.allowedTools.length,
        });

        // 3. Create and start proxy
        const proxy = new AirlockProxy(config, logger);
        await proxy.start();

    } catch (error) {
        // 10x Engineering: Clear error messages for operational issues
        console.error("Failed to start Airlock-MCP:");
        console.error(error instanceof Error ? error.message : String(error));
        process.exit(1);
    }
}

main();
