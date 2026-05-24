#!/usr/bin/env bun
/**
 * agent-boundary-auditor - System for monitoring and auditing agent boundary violations
 */

import { Command } from "commander";
import { readFileSync, writeFileSync, existsSync } from "fs";
import { PolicyEnforcer } from "./PolicyEnforcer";
import { Reporter } from "./Reporter";
import { Policy } from "./ToolAuditor";

const DEFAULT_POLICY: Policy = {
  whitelist: ["read_file", "list_files", "grep_search", "web_search", "run_bash_command"],
  restrictedArgs: {
    run_bash_command: ["cmd", "command"],
  },
  forbiddenPatterns: [
    "rm -rf",
    "chmod 777",
    "passwd",
    "shadow",
  ],
};

async function main() {
  const program = new Command();

  program
    .name("agent-boundary-auditor")
    .description("Audit agent logs for PII leaks and unauthorized tool usage")
    .version("1.0.0");

  program
    .command("audit <file>")
    .description("Audit a log file for violations")
    .option("-p, --policy <path>", "Path to custom policy JSON")
    .option("-o, --output <path>", "Path to save JSON report")
    .action(async (file, options) => {
      if (!existsSync(file)) {
        console.error(`Error: Log file not found at ${file}`);
        process.exit(1);
      }

      let policy = DEFAULT_POLICY;
      if (options.policy && existsSync(options.policy)) {
        policy = JSON.parse(readFileSync(options.policy, "utf-8"));
      }

      const enforcer = new PolicyEnforcer(policy);
      const logs = JSON.parse(readFileSync(file, "utf-8"));
      const events = Array.isArray(logs) ? logs : [logs];
      
      const allViolations = events.flatMap(event => enforcer.processEvent(event));

      console.log(Reporter.summarize(allViolations));

      if (options.output) {
        writeFileSync(options.output, Reporter.exportJson(allViolations));
        console.log(`Report saved to ${options.output}`);
      }
    });

  program
    .command("scan <text>")
    .description("Scan a raw string for PII")
    .action((text) => {
      const enforcer = new PolicyEnforcer(DEFAULT_POLICY);
      const violations = enforcer.processEvent({ type: "text", content: text });
      console.log(Reporter.summarize(violations));
    });

  program
    .command("init-policy")
    .description("Generate a default policy file")
    .action(() => {
      writeFileSync("policy.json", JSON.stringify(DEFAULT_POLICY, null, 2));
      console.log("Default policy written to policy.json");
    });

  await program.parseAsync(process.argv);
}

main().catch(err => {
  console.error(err);
  process.exit(1);
});
