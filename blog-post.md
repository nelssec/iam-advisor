# Stop Guessing at IAM Permissions — Let CloudTrail Tell You

Every team I've worked with has the same problem: IAM roles that are way too permissive. Not because engineers don't care about least-privilege — they do. It's because figuring out the exact permissions a workload needs is tedious, and when you're trying to ship, `s3:*` gets the job done.

The result is a permission sprawl that nobody fully understands. Auditors flag it. Security reviews ding it. But nothing changes because trimming those policies means risking a production breakage.

There's a better way.

## CloudTrail Already Has the Answer

CloudTrail logs every API call made in your AWS account. Every `s3:GetObject`, every `ec2:DescribeInstances`, every `sts:AssumeRole` — it's all there. Instead of guessing what permissions a role needs, you can look at what it's actually called over the last 30 days and build the policy from that.

That's what `iam-advisor` does.

## How It Works

`iam-advisor` is a Go CLI that queries CloudTrail for a given principal, extracts the `action → resource` mappings from real events, and generates a least-privilege IAM policy JSON.

```bash
./iam-advisor analyze \
  --principal arn:aws:iam::123456789012:role/MyAppRole \
  --service s3 \
  --days 30 \
  --output json
```

Output:

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

Not `s3:*` on `*`. Exactly what was used, on exactly the buckets that were touched.

## Org-Wide Scans

If you're running AWS Organizations, you can scan across all member accounts in one shot:

```bash
./iam-advisor analyze \
  --principal arn:aws:iam::123456789012:role/MyAppRole \
  --org \
  --days 30 \
  --output json
```

It assumes `OrganizationAccountAccessRole` in each account, collects events, merges the results, and generates a unified policy. One command, full org coverage.

## LLM Analysis on Top

The CLI gets you the policy. But sometimes you want to understand *why* a permission is there, or whether a wildcard resource is actually risky.

I added an MCP server that wraps the CLI and connects it to Claude. Three tools:

- **`analyze_iam_permissions`** — runs the CLI, returns the policy plus an AI-generated risk summary with a 1–5 risk score
- **`explain_permission`** — tell it `s3:DeleteObject` on `*` and it explains the blast radius and suggests tighter scoping
- **`suggest_improvements`** — feed it any policy JSON and it rewrites it with least-privilege improvements and inline explanations

The risk scoring is simple but useful:

| Score | What it means |
|-------|--------------|
| 1–2 | Read/write on specific resources — you're fine |
| 3 | Wildcards or sensitive reads — worth reviewing |
| 4 | Destructive actions on wildcards — tighten this |
| 5 | `iam:*`, `sts:AssumeRole*`, `kms:*` on `*` — fix immediately |

## Getting Started

```bash
git clone https://github.com/nelssec/iam-advisor.git
cd iam-advisor
go build -o iam-advisor .

# Analyze a role
./iam-advisor analyze --principal arn:aws:iam::123:role/MyRole --days 30 --output json
```

You need `cloudtrail:LookupEvents` at minimum. For org scans, add `organizations:ListAccounts` and the ability to assume the cross-account role.

## What's Next

CloudTrail LookupEvents covers the last 90 days and has rate limits — for high-volume accounts, S3 log parsing is faster. That's next on the list, along with a `diff` mode that compares your current policy against what was actually used and flags the gap.

If you're doing security work on AWS, stop writing IAM policies by hand. Let the logs tell you what's needed.

Repo: [github.com/nelssec/iam-advisor](https://github.com/nelssec/iam-advisor)
