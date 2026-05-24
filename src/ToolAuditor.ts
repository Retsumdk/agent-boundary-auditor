/**
 * ToolAuditor - Audits agent tool usage against policies
 */

export interface ToolCall {
  tool: string;
  args: Record<string, any>;
  timestamp: string;
  agentId: string;
}

export interface AuditResult {
  allowed: boolean;
  reason?: string;
  severity: "none" | "low" | "medium" | "high" | "critical";
  violations: string[];
}

export interface Policy {
  whitelist: string[];
  restrictedArgs: Record<string, string[]>; // tool -> [argNames]
  forbiddenPatterns: string[];
}

export class ToolAuditor {
  constructor(private policy: Policy) {}

  /**
   * Audit a single tool call
   */
  public audit(call: ToolCall): AuditResult {
    const violations: string[] = [];
    let severity: AuditResult["severity"] = "none";

    // Check whitelist
    if (!this.policy.whitelist.includes(call.tool)) {
      violations.push(`Tool '${call.tool}' is not in the whitelist.`);
      severity = "high";
    }

    // Check restricted arguments
    const restricted = this.policy.restrictedArgs[call.tool];
    if (restricted) {
      for (const arg of restricted) {
        if (call.args[arg]) {
          const value = JSON.stringify(call.args[arg]);
          if (this.containsForbiddenPattern(value)) {
            violations.push(`Restricted argument '${arg}' in tool '${call.tool}' contains forbidden patterns.`);
            severity = "critical";
          }
        }
      }
    }

    // Check all arguments for sensitive patterns
    for (const [arg, value] of Object.entries(call.args)) {
      const stringValue = typeof value === "string" ? value : JSON.stringify(value);
      if (this.containsForbiddenPattern(stringValue)) {
        violations.push(`Argument '${arg}' contains forbidden patterns.`);
        if (severity !== "critical") severity = "medium";
      }
    }

    return {
      allowed: violations.length === 0,
      reason: violations.length > 0 ? violations.join(" ") : undefined,
      severity,
      violations,
    };
  }

  /**
   * Check if a string contains forbidden patterns (e.g., shell injection, etc.)
   */
  private containsForbiddenPattern(text: string): boolean {
    const forbidden = [
      /\brm\s+-rf\b/i,
      /\bchmod\s+777\b/i,
      /\bcurl\s+.*\s+\|\s*bash\b/i,
      /\b>\s*\/etc\/\b/i,
      /\bpasswd\b/i,
      /\bshadow\b/i,
      /\.bash_history/i,
      /\bexec\s+\(\b/i,
      /\beval\s*\(\b/i,
    ];

    return forbidden.some(pattern => pattern.test(text));
  }
}
