import { describe, test, expect } from "bun:test";
import { PolicyEnforcer } from "../src/PolicyEnforcer";
import { ToolAuditor } from "../src/ToolAuditor";
import { PIIDetector } from "../src/PIIDetector";
import type { Policy, ToolCall } from "../src/ToolAuditor";

const policy: Policy = {
  whitelist: ["read_file", "run_bash_command"],
  restrictedArgs: { run_bash_command: ["cmd"] },
  forbiddenPatterns: [],
};

const call = (tool: string, args: Record<string, unknown>): ToolCall => ({
  tool,
  args,
  timestamp: new Date().toISOString(),
  agentId: "test-agent",
});

describe("ToolAuditor", () => {
  test("allows whitelisted tools with clean arguments", () => {
    const auditor = new ToolAuditor(policy);
    const verdict = auditor.audit(call("read_file", { path: "notes.txt" }));
    expect(verdict.allowed).toBe(true);
    expect(verdict.severity).toBe("none");
  });

  test("flags tools outside the whitelist as high severity", () => {
    const auditor = new ToolAuditor(policy);
    const verdict = auditor.audit(call("send_email", { to: "a@b.com" }));
    expect(verdict.allowed).toBe(false);
    expect(verdict.severity).toBe("high");
    expect(verdict.reason).toContain("not in the whitelist");
  });

  test("flags forbidden shell patterns in restricted arguments as critical", () => {
    const auditor = new ToolAuditor(policy);
    const verdict = auditor.audit(call("run_bash_command", { cmd: "ls && rm -rf /" }));
    expect(verdict.allowed).toBe(false);
    expect(verdict.severity).toBe("critical");
  });
});

describe("PIIDetector", () => {
  const detector = new PIIDetector();

  test("detects email addresses", () => {
    const findings = detector.scan("contact me at jane.doe@example.com please");
    expect(findings.some(f => f.type === "email")).toBe(true);
  });

  test("detects valid credit card numbers", () => {
    const findings = detector.scan("card: 4111 1111 1111 1111");
    expect(findings.some(f => f.type === "credit_card")).toBe(true);
  });

  test("returns no findings for ordinary text", () => {
    expect(detector.scan("nothing sensitive in this sentence")).toHaveLength(0);
  });
});

describe("PolicyEnforcer", () => {
  test("raises an UNAUTHORIZED_TOOL violation for non-whitelisted tool calls", () => {
    const enforcer = new PolicyEnforcer(policy);
    const violations = enforcer.processEvent({
      type: "tool_call",
      tool: "send_email",
      args: {},
    });
    expect(violations.some(v => v.type === "UNAUTHORIZED_TOOL")).toBe(true);
  });

  test("raises a PII_LEAK violation when message content contains PII", () => {
    const enforcer = new PolicyEnforcer(policy);
    const violations = enforcer.processEvent({
      type: "message",
      content: "the user email is bob@acme.com",
    });
    expect(violations.some(v => v.type === "PII_LEAK")).toBe(true);
  });

  test("returns no violations for clean events", () => {
    const enforcer = new PolicyEnforcer(policy);
    const violations = enforcer.processEvent({
      type: "tool_call",
      tool: "read_file",
      args: { path: "notes.txt" },
    });
    expect(violations).toHaveLength(0);
  });
});
