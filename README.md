# iam-advisor

Discover what AWS IAM permissions are actually being used — then generate a least-privilege policy from real CloudTrail data, with LLM-powered risk analysis on top.

Stop guessing at permissions. Let your CloudTrail logs tell you what's needed.

## How It Works

1. **Collect** — queries CloudTrail LookupEvents for a principal, service, and time window
2. **Analyze** — maps `principal → action → resource` from real API calls
3. **Generate** — produces a valid least-privilege IAM policy JSON
4. **Explain** — optional MCP server wraps the CLI with Claude for risk scoring and recommendations

## Features

- CloudTrail event ingestion via AWS SDK v2
- AWS Organizations support — scan all accounts with cross-account assume-role
- Filter by principal (IAM role/user ARN), service (e.g. `s3`, `ec2`), and time window
- Outputs clean IAM policy JSON or human-readable text
- MCP server with 3 tools for AI-powered analysis via Claude

## Installation

### Prerequisites
- Go 1.22+
- AWS credentials configured (`aws configure` or environment variables)
- For org-wide scans: permissions to call `organizations:ListAccounts` and assume `OrganizationAccountAccessRole` in member accounts

### Build

```bash
git clone https://github.com/nelssec/iam-advisor.git
cd iam-advisor
go build -o iam-advisor .
```

### MCP Server (optional)

```bash
pip install mcp anthropic
```

## Usage

### Basic — analyze a single principal

```bash
./iam-advisor analyze \
  --principal arn:aws:iam::123456789012:role/MyAppRole \
  --days 30 \
  --output json
```

### Filter by service

```bash
./iam-advisor analyze \
  --principal arn:aws:iam::123456789012:role/MyAppRole \
  --service s3 \
  --days 14 \
  --output json
```

### Org-wide scan across all accounts

```bash
./iam-advisor analyze \
  --principal arn:aws:iam::123456789012:role/MyAppRole \
  --org \
  --role-name OrganizationAccountAccessRole \
  --days 30 \
  --output json
```

### Text output

```bash
./iam-advisor analyze \
  --principal arn:aws:iam::123456789012:role/MyAppRole \
  --output text
```

### Example output (JSON)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "Stmt1",
      "Effect": "Allow",
      "Action": [
        "s3:GetObject",
        "s3:ListBucket"
      ],
      "Resource": [
        "arn:aws:s3:::my-app-bucket",
        "arn:aws:s3:::my-app-bucket/*"
      ]
    }
  ]
}
```

## CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--principal` | — | IAM principal ARN to analyze |
| `--service` | all | AWS service filter (e.g. `s3`, `ec2`, `sts`) |
| `--days` | `30` | Days of CloudTrail history to analyze |
| `--account` | current | AWS account ID |
| `--org` | `false` | Scan all accounts in AWS Organization |
| `--role-name` | `OrganizationAccountAccessRole` | Role to assume in org accounts |
| `--output` | `text` | Output format: `json` or `text` |

## MCP Server

The included `mcp_server.py` exposes three tools for use with Claude or any MCP-compatible client:

### `analyze_iam_permissions`
Runs the CLI against CloudTrail and returns the generated policy plus an AI risk analysis.

```json
{
  "principal": "arn:aws:iam::123:role/MyRole",
  "service": "s3",
  "days": 30
}
```

### `explain_permission`
Explains what an IAM action allows, its blast radius, and how to tighten the resource scope.

```json
{
  "action": "s3:DeleteObject",
  "resource": "*"
}
```

### `suggest_improvements`
Reviews an IAM policy and returns a rewritten least-privilege version with inline explanations.

```json
{
  "policy_json": "{\"Version\":\"2012-10-17\",\"Statement\":[...]}"
}
```

### Running the MCP server

```bash
python mcp_server.py
```

Add to your MCP client config:

```json
{
  "mcpServers": {
    "iam-advisor": {
      "command": "python",
      "args": ["/path/to/iam-advisor/mcp_server.py"],
      "env": {
        "ANTHROPIC_API_KEY": "your-key"
      }
    }
  }
}
```

## Risk Scoring

The LLM layer scores policies on a 1–5 scale:

| Score | Meaning |
|-------|---------|
| 1 | Read-only on specific resources — low risk |
| 2 | Write on specific resources |
| 3 | Write on wildcards OR sensitive reads |
| 4 | Destructive actions (`Delete*`, `Terminate*`) on wildcards |
| 5 | Privilege escalation: `iam:*`, `sts:AssumeRole*`, `kms:*`, `PassRole` on `*` |

## IAM Permissions Required

To run `iam-advisor` your principal needs:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cloudtrail:LookupEvents"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "organizations:ListAccounts"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": "sts:AssumeRole",
      "Resource": "arn:aws:iam::*:role/OrganizationAccountAccessRole"
    }
  ]
}
```

The last two statements are only needed for `--org` scans.

## Architecture

See [DESIGN.md](DESIGN.md) for the full architecture, MCP tool specs, LLM prompt design, and risk scoring rubric.

## License

MIT
