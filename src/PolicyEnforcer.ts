import { PIIDetector, PIIFinding } from "./PIIDetector";
import { ToolAuditor, ToolCall, AuditResult, Policy } from "./ToolAuditor";

export interface BoundaryViolation {
  timestamp: string;
  type: "PII_LEAK" | "UNAUTHORIZED_TOOL" | "POLICY_VIOLATION";
  description: string;
  severity: AuditResult["severity"];
  context: any;
}

export class PolicyEnforcer {
  private piiDetector: PIIDetector;
  private toolAuditor: ToolAuditor;

  constructor(policy: Policy) {
    this.piiDetector = new PIIDetector();
    this.toolAuditor = new ToolAuditor(policy);
  }

  /**
   * Process an agent event (log entry or tool call)
   */
  public processEvent(event: any): BoundaryViolation[] {
    const violations: BoundaryViolation[] = [];
    const timestamp = event.timestamp || new Date().toISOString();

    // 1. Audit Tool Usage
    if (event.type === "tool_call") {
      const toolCall: ToolCall = {
        tool: event.tool,
        args: event.args || {},
        timestamp,
        agentId: event.agentId || "unknown",
      };

      const audit = this.toolAuditor.audit(toolCall);
      if (!audit.allowed) {
        violations.push({
          timestamp,
          type: "UNAUTHORIZED_TOOL",
          description: audit.reason || "Unauthorized tool usage detected",
          severity: audit.severity,
          context: { tool: event.tool, violations: audit.violations },
        });
      }
    }

    // 2. Detect PII in any string content
    const contentToScan = this.extractStringContent(event);
    for (const text of contentToScan) {
      const piiFindings = this.piiDetector.scan(text);
      if (piiFindings.length > 0) {
        violations.push({
          timestamp,
          type: "PII_LEAK",
          description: `Detected ${piiFindings.length} PII occurrences: ${piiFindings.map(f => f.type).join(", ")}`,
          severity: this.mapPIISeverity(piiFindings),
          context: { findings: piiFindings },
        });
      }
    }

    return violations;
  }

  /**
   * Extract all strings from an object recursively
   */
  private extractStringContent(obj: any): string[] {
    const strings: string[] = [];
    
    const walk = (item: any) => {
      if (typeof item === "string") {
        strings.push(item);
      } else if (Array.isArray(item)) {
        item.forEach(walk);
      } else if (item !== null && typeof item === "object") {
        Object.values(item).forEach(walk);
      }
    };

    walk(obj);
    return strings;
  }

  /**
   * Map PII findings to a severity level
   */
  private mapPIISeverity(findings: PIIFinding[]): BoundaryViolation["severity"] {
    const highRisk = ["credit_card", "ssn", "api_key"];
    const containsHighRisk = findings.some(f => highRisk.includes(f.type));
    
    if (containsHighRisk) return "critical";
    if (findings.length > 5) return "high";
    if (findings.length > 1) return "medium";
    return "low";
  }
}
