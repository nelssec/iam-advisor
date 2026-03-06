#!/usr/bin/env python3
"""
iam-advisor MCP Server
Wraps the iam-advisor Go CLI with LLM-powered analysis via Claude.
"""

import json
import subprocess
import sys
from pathlib import Path

import anthropic
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import TextContent, Tool

# Path to the iam-advisor binary (assumes it's in PATH or same directory)
IAM_ADVISOR_BIN = "iam-advisor"

SYSTEM_PROMPT = """You are an AWS IAM security expert. Your job is to help engineers apply least-privilege principles.
When analyzing permissions, always:
1. Explain what each permission allows in plain English
2. Flag any high-risk permissions with a risk score (1-5)
3. Suggest specific resource ARNs instead of wildcards where possible
4. Call out sensitive action prefixes: iam:*, s3:Delete*, ec2:Terminate*, kms:*, sts:AssumeRole*
5. Be concise — engineers are reading on-screen, not writing essays

Risk score rubric:
1 = Read-only on specific resources
2 = Write on specific resources
3 = Write on wildcard resources OR sensitive reads
4 = Destructive actions (Delete*, Terminate*) on wildcard resources
5 = Privilege escalation risk: iam:*, sts:AssumeRole*, kms:*, PassRole on *"""

app = Server("iam-advisor")
claude = anthropic.Anthropic()


def run_cli(*args: str) -> dict:
    """Run iam-advisor CLI and return parsed JSON output."""
    cmd = [IAM_ADVISOR_BIN, *args, "--output", "json"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    if result.returncode != 0:
        raise RuntimeError(f"iam-advisor failed: {result.stderr}")
    return json.loads(result.stdout)


def llm_analyze(user_prompt: str) -> str:
    """Send a prompt to Claude and return the response text."""
    response = claude.messages.create(
        model="claude-opus-4-5",
        max_tokens=1024,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_prompt}],
    )
    return response.content[0].text


@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="analyze_iam_permissions",
            description=(
                "Analyze CloudTrail events for a principal and generate a least-privilege "
                "IAM policy with AI-powered risk analysis and recommendations."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "principal": {
                        "type": "string",
                        "description": "IAM principal ARN to analyze (e.g. arn:aws:iam::123:role/MyRole)",
                    },
                    "service": {
                        "type": "string",
                        "description": "AWS service to filter (e.g. s3, ec2). Leave empty for all services.",
                    },
                    "days": {
                        "type": "integer",
                        "description": "Days of CloudTrail history to analyze (default 30)",
                        "default": 30,
                    },
                    "org": {
                        "type": "boolean",
                        "description": "Scan all accounts in the AWS Organization",
                        "default": False,
                    },
                },
                "required": ["principal"],
            },
        ),
        Tool(
            name="explain_permission",
            description="Explain what an AWS IAM permission allows, its blast radius, and how to tighten it.",
            inputSchema={
                "type": "object",
                "properties": {
                    "action": {
                        "type": "string",
                        "description": "IAM action (e.g. s3:DeleteObject)",
                    },
                    "resource": {
                        "type": "string",
                        "description": "Resource ARN or wildcard (e.g. arn:aws:s3:::my-bucket/* or *)",
                    },
                },
                "required": ["action", "resource"],
            },
        ),
        Tool(
            name="suggest_improvements",
            description="Review an IAM policy JSON and return a tightened least-privilege version with explanations.",
            inputSchema={
                "type": "object",
                "properties": {
                    "policy_json": {
                        "type": "string",
                        "description": "IAM policy document as a JSON string",
                    },
                },
                "required": ["policy_json"],
            },
        ),
    ]


@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    if name == "analyze_iam_permissions":
        principal = arguments["principal"]
        service = arguments.get("service", "")
        days = arguments.get("days", 30)
        org = arguments.get("org", False)

        cli_args = ["analyze", "--principal", principal, "--days", str(days)]
        if service:
            cli_args += ["--service", service]
        if org:
            cli_args.append("--org")

        policy = run_cli(*cli_args)
        policy_str = json.dumps(policy, indent=2)

        prompt = f"""Here is a least-privilege IAM policy generated from {days} days of CloudTrail events for principal {principal}:

{policy_str}

Summarize:
- What this principal is doing (in plain English)
- Any permissions that look risky or overly broad
- Risk score for the overall policy (1-5)
- Top 3 recommendations to tighten it"""

        analysis = llm_analyze(prompt)
        output = f"## Generated Policy\n\n```json\n{policy_str}\n```\n\n## AI Analysis\n\n{analysis}"
        return [TextContent(type="text", text=output)]

    elif name == "explain_permission":
        action = arguments["action"]
        resource = arguments["resource"]

        prompt = f"""Explain this AWS IAM permission:
Action: {action}
Resource: {resource}

Cover: what it allows, real-world use cases, blast radius if abused, and whether the resource scope can be tightened."""

        explanation = llm_analyze(prompt)
        return [TextContent(type="text", text=explanation)]

    elif name == "suggest_improvements":
        policy_json = arguments["policy_json"]

        prompt = f"""Review this IAM policy and rewrite it with least-privilege improvements:

{policy_json}

For each change, add a comment explaining why. Return the improved policy JSON followed by a bullet list of changes made."""

        improved = llm_analyze(prompt)
        return [TextContent(type="text", text=improved)]

    else:
        raise ValueError(f"Unknown tool: {name}")


async def main():
    async with stdio_server() as streams:
        await app.run(*streams, app.create_initialization_options())


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
