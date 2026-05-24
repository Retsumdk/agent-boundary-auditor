import { BoundaryViolation } from "./PolicyEnforcer";

export class Reporter {
  /**
   * Print a summary of violations
   */
  public static summarize(violations: BoundaryViolation[]): string {
    if (violations.length === 0) {
      return "✅ No boundary violations detected.";
    }

    const counts = this.getCounts(violations);
    const severityColor = this.getOverallSeverityColor(violations);

    let output = `⚠️  Detection Summary: ${violations.length} violations found.\n`;
    output += `--------------------------------------------------\n`;
    output += `PII Leaks: ${counts.PII_LEAK || 0}\n`;
    output += `Unauthorized Tools: ${counts.UNAUTHORIZED_TOOL || 0}\n`;
    output += `Policy Violations: ${counts.POLICY_VIOLATION || 0}\n`;
    output += `--------------------------------------------------\n`;
    output += `Overall Severity: ${severityColor}${this.getOverallSeverity(violations)}\x1b[0m\n\n`;

    output += `Details:\n`;
    violations.forEach((v, i) => {
      output += `${i + 1}. [${v.severity.toUpperCase()}] ${v.type}: ${v.description}\n`;
      if (v.context && v.type === "PII_LEAK") {
        output += `   Findings: ${v.context.findings.map((f: any) => `${f.type}(${f.value})`).join(", ")}\n`;
      }
    });

    return output;
  }

  /**
   * Export violations to a JSON file format
   */
  public static exportJson(violations: BoundaryViolation[]): string {
    return JSON.stringify({
      generatedAt: new Date().toISOString(),
      violationCount: violations.length,
      violations,
    }, null, 2);
  }

  private static getCounts(violations: BoundaryViolation[]): Record<string, number> {
    return violations.reduce((acc, v) => {
      acc[v.type] = (acc[v.type] || 0) + 1;
      return acc;
    }, {} as Record<string, number>);
  }

  private static getOverallSeverity(violations: BoundaryViolation[]): string {
    const severities = ["critical", "high", "medium", "low", "none"];
    for (const s of severities) {
      if (violations.some(v => v.severity === s)) return s.toUpperCase();
    }
    return "NONE";
  }

  private static getOverallSeverityColor(violations: BoundaryViolation[]): string {
    const highest = violations.reduce((prev, v) => {
      const levels: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, none: 0 };
      return levels[v.severity] > levels[prev] ? v.severity : prev;
    }, "none" as BoundaryViolation["severity"]);

    switch (highest) {
      case "critical": return "\x1b[31;1m"; // Bold Red
      case "high": return "\x1b[31m";    // Red
      case "medium": return "\x1b[33m";  // Yellow
      case "low": return "\x1b[34m";     // Blue
      default: return "\x1b[32m";        // Green
    }
  }
}
