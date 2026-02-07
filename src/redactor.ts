import type { Logger } from "./logger.js";
import type { AirlockConfig } from "./config.js";

/**
 * PII pattern definitions with regex and replacement templates
 * 
 * Organized by risk level for enterprise security teams
 */
const PII_PATTERNS: Record<string, { regex: RegExp; replacement: string; description: string }> = {
    // HIGH RISK - Identity & Financial
    ssn: {
        regex: /\b\d{3}-\d{2}-\d{4}\b/g,
        replacement: "[SSN:REDACTED]",
        description: "US Social Security Number",
    },
    credit_card: {
        regex: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g,
        replacement: "[CREDIT_CARD:REDACTED]",
        description: "Credit card number",
    },
    bank_account: {
        regex: /\b\d{8,17}\b(?=.*(?:account|routing|iban|swift))/gi,
        replacement: "[BANK_ACCOUNT:REDACTED]",
        description: "Bank account number",
    },

    // HIGH RISK - Secrets & Credentials
    api_key: {
        regex: /\b(?:sk|pk|api|key|token|secret|auth)[_-]?[a-zA-Z0-9]{20,}\b/gi,
        replacement: "[API_KEY:REDACTED]",
        description: "API keys and tokens",
    },
    aws_key: {
        regex: /\b(?:AKIA|ABIA|ACCA|ASIA)[A-Z0-9]{16}\b/g,
        replacement: "[AWS_KEY:REDACTED]",
        description: "AWS access key ID",
    },
    password: {
        regex: /(?:password|passwd|pwd|secret)\s*[:=]\s*["']?[^\s"']{4,}["']?/gi,
        replacement: "[PASSWORD:REDACTED]",
        description: "Password in config/logs",
    },
    private_key: {
        regex: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
        replacement: "[PRIVATE_KEY:REDACTED]",
        description: "Private key block",
    },
    jwt: {
        regex: /\beyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\b/g,
        replacement: "[JWT:REDACTED]",
        description: "JSON Web Token",
    },
    connection_string: {
        regex: /(?:mongodb|postgresql|mysql|redis|amqp):\/\/[^\s"']+/gi,
        replacement: "[CONNECTION_STRING:REDACTED]",
        description: "Database connection string",
    },

    // MEDIUM RISK - PII
    email: {
        regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
        replacement: "[EMAIL:REDACTED]",
        description: "Email address",
    },
    phone: {
        regex: /\b(?:\+?1[-.\s]?)?(?:\(?[0-9]{3}\)?[-.\s]?)?[0-9]{3}[-.\s]?[0-9]{4}\b/g,
        replacement: "[PHONE:REDACTED]",
        description: "Phone number",
    },
    ip_address: {
        regex: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
        replacement: "[IP_ADDRESS:REDACTED]",
        description: "IPv4 address",
    },

    // FINANCE-SPECIFIC
    iban: {
        regex: /\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}(?:[A-Z0-9]?){0,16}\b/g,
        replacement: "[IBAN:REDACTED]",
        description: "International Bank Account Number",
    },
    swift: {
        regex: /\b[A-Z]{4}[A-Z]{2}[A-Z0-9]{2}(?:[A-Z0-9]{3})?\b/g,
        replacement: "[SWIFT:REDACTED]",
        description: "SWIFT/BIC code",
    },

    // INFRASTRUCTURE
    internal_url: {
        regex: /https?:\/\/(?:[a-z0-9-]+\.)*(?:internal|corp|local|dev|staging|prod)[a-z0-9.-]*(?::\d+)?(?:\/[^\s]*)?/gi,
        replacement: "[INTERNAL_URL:REDACTED]",
        description: "Internal URL",
    },
};

/**
 * Default patterns to enable when piiRedaction.enabled = true
 */
const DEFAULT_PATTERNS = [
    "ssn",
    "credit_card",
    "api_key",
    "aws_key",
    "password",
    "private_key",
    "jwt",
    "connection_string",
    "email",
] as const;

export type PIIPatternName = keyof typeof PII_PATTERNS;

/**
 * PII Redactor - Response-side security for sensitive data
 * 
 * Scans tool and resource outputs for sensitive patterns and
 * replaces them with typed placeholders.
 */
export class PIIRedactor {
    private enabled: boolean;
    private enabledPatterns: Set<PIIPatternName>;
    private logger: Logger;

    constructor(config: AirlockConfig, logger: Logger) {
        const piiConfig = config.piiRedaction ?? { enabled: false };
        this.enabled = piiConfig.enabled;
        this.enabledPatterns = new Set(
            piiConfig.patterns?.length
                ? piiConfig.patterns
                : DEFAULT_PATTERNS
        );
        this.logger = logger;

        if (this.enabled) {
            this.logger.info({
                msg: "PIIRedactor initialized",
                enabledPatterns: Array.from(this.enabledPatterns),
                patternCount: this.enabledPatterns.size,
            });
        }
    }

    /**
     * Redact sensitive data from content
     * 
     * @param content - Text content to scan and redact
     * @returns Redacted content with pattern counts
     */
    redact(content: string): { redacted: string; counts: Record<string, number> } {
        if (!this.enabled) {
            return { redacted: content, counts: {} };
        }

        let result = content;
        const counts: Record<string, number> = {};

        for (const patternName of this.enabledPatterns) {
            const pattern = PII_PATTERNS[patternName];
            if (!pattern) continue;

            // Reset regex lastIndex for global patterns
            pattern.regex.lastIndex = 0;

            const matches = result.match(pattern.regex);
            if (matches && matches.length > 0) {
                counts[patternName] = matches.length;
                result = result.replace(pattern.regex, pattern.replacement);
            }
        }

        // Log redaction summary if anything was redacted
        const totalRedacted = Object.values(counts).reduce((a, b) => a + b, 0);
        if (totalRedacted > 0) {
            this.logger.warn({
                msg: "PII redacted from response",
                redactionCounts: counts,
                totalRedacted,
                severity: "high",
            });
        }

        return { redacted: result, counts };
    }

    /**
     * Check if redaction is enabled
     */
    isEnabled(): boolean {
        return this.enabled;
    }

    /**
     * Get list of available patterns
     */
    static getAvailablePatterns(): Array<{ name: string; description: string }> {
        return Object.entries(PII_PATTERNS).map(([name, pattern]) => ({
            name,
            description: pattern.description,
        }));
    }
}
