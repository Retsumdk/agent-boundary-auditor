# Agent Boundary Auditor

A robust system for monitoring and auditing AI agent boundary violations. This tool helps ensure that autonomous agents operate within security constraints by detecting Personally Identifiable Information (PII) leaks and auditing tool usage against defined security policies.

## Features

- **PII Detection**: Scans agent logs and communications for sensitive data including:
  - Email addresses
  - Phone numbers
  - Social Security Numbers (SSN)
  - Credit Card numbers (with Luhn validation)
  - API Keys and Auth Tokens
  - IP and MAC addresses
- **Tool Auditing**: Validates agent tool calls against:
  - Whitelists of allowed tools
  - Restricted arguments
  - Forbidden patterns (e.g., shell injection attempts like `rm -rf`)
- **Policy Enforcement**: Configurable security policies to define what is "unauthorized".
- **Structured Reporting**: Generates human-readable summaries and machine-readable JSON reports.

## Installation

```bash
# Clone the repository
git clone https://github.com/Retsumdk/agent-boundary-auditor.git
cd agent-boundary-auditor

# Install dependencies
bun install
```

## Usage

### Audit a log file
```bash
bun run src/index.ts audit logs.json
```

### Scan a raw string for PII
```bash
bun run src/index.ts scan "My email is test@example.com"
```

### Initialize a default policy
```bash
bun run src/index.ts init-policy
```

## Architecture

- **PIIDetector**: Uses high-performance regex and validation logic to identify sensitive data.
- **ToolAuditor**: Compares tool calls and arguments against a security policy.
- **PolicyEnforcer**: Orchestrates the audit process across multiple data types.
- **Reporter**: Provides structured, color-coded feedback on audit results.

## Configuration

Custom policies can be defined in a `policy.json` file:

```json
{
  "whitelist": ["read_file", "list_files"],
  "restrictedArgs": {
    "run_bash_command": ["cmd"]
  },
  "forbiddenPatterns": ["rm -rf", "passwd"]
}
```

## License

MIT
