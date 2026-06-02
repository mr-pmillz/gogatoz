---
title: Use Cases
description: Common use cases for GoGatoZ in GitLab security assessments
---

This section provides an overview of common use cases for GoGatoZ (GitLab).

## Available Use Cases

- [Scanning for Vulnerabilities](/user-guide/use-cases/scanning/) - How to effectively scan GitLab projects for CI/CD risks
- [Self-Hosted Runner Takeover](/user-guide/use-cases/runner-takeover/) - Techniques for exploiting GitLab Runner misconfigurations
- [Post-Compromise Enumeration](/user-guide/use-cases/post-compromise/) - How to enumerate resources after obtaining a GitLab PAT
- [Generating Reports](/user-guide/use-cases/reporting/) - Generate HTML reports and send findings to Discord
- [MCP Capstone Lab](/user-guide/use-cases/mcp-lab/) - Use GoGatoZ as an MCP server with Claude Code for AI-assisted scanning

## Choosing the Right Approach

The approach you take depends on your specific goals:

1. **Security Research**: Use the search and enumerate commands to identify vulnerabilities in public GitLab projects, then report them responsibly.

2. **Red Team Operations**: Use GoGatoZ to simulate attacks against your organization's GitLab CI/CD infrastructure (attack features require explicit authorization).

3. **Security Assessment**: Use GoGatoZ to assess the CI/CD posture via static analysis of `.gitlab-ci.yml` and includes.

## Ethical Considerations

Always ensure you have proper authorization before using attack features. The search and enumerate features are safe to use on public GitLab projects, but attack features should only be used with explicit permission.
