# iam-advisor — Design

A least-privilege IAM policy advisor that mines CloudTrail to discover what permissions are actually used, then applies LLM analysis to explain risks and suggest improvements.

## Architecture

```
CloudTrail API / S3
       │
       ▼
  Go CLI (iam-advisor)
  ├── internal/cloudtrail  — event collection + parsing
  └── internal/policy      — policy document generation
       │
       ▼ JSON policy output
  MCP Server (mcp_server.py)
  ├── analyze_iam_permissions  — runs CLI, returns policy + AI analysis
  ├── explain_permission       — explains why a permission is needed + flags risks
  └── suggest_improvements     — reviews a policy and tightens it
       │
       ▼
   Claude (via MCP)
```

## MCP Tool Definitions

### `analyze_iam_permissions`
**Input:** `principal` (ARN), `service` (e.g. s3), `days` (int, default 30)
**What it does:** Runs `iam-advisor analyze` against CloudTrail, returns the generated policy JSON plus an LLM-generated summary explaining what was found, why each permission exists, and any risk flags.

### `explain_permission`
**Input:** `action` (e.g. s3:DeleteObject), `resource` (ARN or *)
**What it does:** Explains what the permission allows, what blast radius looks like if misused, and whether a tighter resource scope is possible.

### `suggest_improvements`
**Input:** `policy_json` (raw IAM policy JSON string)
**What it does:** Reviews the policy for wildcard resources, sensitive actions, and over-broad scopes. Returns a rewritten policy with inline annotations explaining each change.

## LLM Prompts

### System Prompt (all tools)
```
You are an AWS IAM security expert. Your job is to help engineers apply least-privilege principles.
When analyzing permissions, always:
1. Explain what each permission allows in plain English
2. Flag any high-risk permissions with a risk score (1-5)
3. Suggest specific resource ARNs instead of wildcards where possible
4. Call out sensitive action prefixes: iam:*, s3:Delete*, ec2:Terminate*, kms:*, sts:AssumeRole*
5. Be concise — engineers are reading on-screen, not writing essays
```

### User Prompt — analyze_iam_permissions
```
Here is a least-privilege IAM policy generated from {days} days of CloudTrail events for principal {principal}:

{policy_json}

Summarize:
- What this principal is doing (in plain English)
- Any permissions that look risky or overly broad
- Risk score for the overall policy (1-5)
- Top 3 recommendations to tighten it
```

### User Prompt — explain_permission
```
Explain this AWS IAM permission:
Action: {action}
Resource: {resource}

Cover: what it allows, real-world use cases, blast radius if abused, and whether the resource scope can be tightened.
```

### User Prompt — suggest_improvements
```
Review this IAM policy and rewrite it with least-privilege improvements:

{policy_json}

For each change, add a comment explaining why. Return the improved policy JSON followed by a bullet list of changes made.
```

## Risk Scoring Rubric

| Score | Criteria |
|-------|----------|
| 1 | Read-only actions on specific resources |
| 2 | Write actions on specific resources |
| 3 | Write actions on wildcard resources OR sensitive reads (e.g. s3:GetObject on *) |
| 4 | Destructive actions (Delete*, Terminate*) on wildcard resources |
| 5 | Privilege escalation risk: iam:*, sts:AssumeRole*, kms:*, PassRole on * |

## Integration Flow

1. Engineer runs: `iam-advisor analyze --principal arn:aws:iam::123:role/MyRole --service s3 --output json`
2. CLI queries CloudTrail, generates policy JSON
3. MCP server wraps CLI call, feeds output to Claude with analysis prompt
4. Claude returns: plain-English summary, risk score, improvement suggestions
5. Engineer gets actionable least-privilege policy with full context
