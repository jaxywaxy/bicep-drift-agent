# Contributing

Thank you for contributing to this example drift agent.

This example demonstrates drift detection for enterprise Azure environments and focuses on reliable, accurate, and explainable drift detection for Bicep-managed infrastructure. Use it as a reference implementation or a starting point for your own, organisation-specific deployment.

Before contributing, please review the project documentation:

- `README.md`
- `ARCHITECTURE.md`
- `CAPABILITIES.md`
- `SECURITY_MODEL.md`
- `LANDING_ZONE_OPERATIONS.md`

---

# Development Workflow

The project follows a **branch and pull request model**.

Contributors should create feature branches from the main branch in their fork or organization and submit pull requests for review against the central example or their own repository as appropriate.

## Workflow

```text
main
  │
  ├── feature/new-capability
  ├── feature/rbac-improvements
  ├── fix/activity-log-bug
  └── docs/update-runbook
```

---

# Creating a Branch

Create a branch from the latest version of `main`.

```bash
git checkout main
git pull origin main

git checkout -b feature/my-change
```

Branch naming recommendations:

```text
feature/<description>
fix/<description>
docs/<description>
refactor/<description>
test/<description>
```

Examples:

```text
feature/policy-drift-detection
fix/resource-graph-query
docs/security-model
```

---

# Development Environment

## Prerequisites

- Python 3.11+
- Azure CLI
- GitHub CLI
- Bicep CLI

## Clone Example

```bash
git clone <repository-url>

# Change to the directory you cloned (example name shown)
cd bicep-drift-agent
```

## Create Virtual Environment

```bash
python -m venv .venv
```

Linux/macOS:

```bash
source .venv/bin/activate
```

Windows:

```powershell
.venv\Scripts\activate
```

## Install Dependencies

```bash
pip install -r requirements.txt
```

---

# Testing

Contributions should include testing where practical.

Run the test suite before submitting a pull request.

```bash
python -m unittest discover -s tests
```

## Expected Behaviour

Changes should:

- Pass existing tests
- Not introduce new drift noise
- Maintain backwards compatibility where possible
- Follow documented ownership classification rules
- Produce deterministic drift results

---

# Documentation Requirements

Documentation is considered a feature.

Update documentation whenever:

- New capabilities are added
- Configuration changes
- Authentication changes
- Notification behaviour changes
- Scan behaviour changes
- Ownership classification changes

Typical documentation updates include:

| Change | Documentation |
|----------|--------------|
| New capability | `CAPABILITIES.md` |
| New architecture component | `ARCHITECTURE.md` |
| Security change | `SECURITY_MODEL.md` |
| New configuration option | `CONFIG_REFERENCE.md` |
| New operating procedure | `OPERATIONS_RUNBOOK.md` |

---

# Pull Requests

## Before Opening a Pull Request

Confirm:

- [ ] Branch is up to date with main
- [ ] Tests pass
- [ ] Documentation has been updated
- [ ] Change has been manually validated where appropriate
- [ ] No secrets or credentials have been committed
- [ ] Pull request description explains why the change is needed

## Pull Request Template

Recommended structure:

```text
Summary

What problem does this solve?

Changes

- Change 1
- Change 2
- Change 3

Testing

- Unit tests
- Manual validation

Documentation

Updated:
- ARCHITECTURE.md
- CAPABILITIES.md

Related Issue

#123
```

---

# Coding Standards

## General Principles

Prioritise:

- Readability
- Maintainability
- Deterministic behaviour
- Explainable results
- Least surprise

Avoid:

- Hard-coded tenant-specific values
- Organisation-specific assumptions
- Unclear matching logic
- Silent error handling

---

# Security Requirements

This project operates against enterprise Azure environments.

Contributors must:

- Never commit secrets
- Never commit webhook URLs
- Never commit access tokens
- Use GitHub OIDC authentication
- Maintain least-privilege principles
- Preserve read-only behaviour

Changes that increase permissions should be reviewed carefully.

See:

```text
SECURITY_MODEL.md
```

---

# New Drift Detection Capabilities

When introducing support for a new Azure resource type:

## Requirements

1. Live state collection implemented.
2. Property comparison implemented.
3. False-positive behaviour considered.
4. Unit tests added.
5. Documentation updated.

## Recommended Process

```text
Collect live state
        ↓
Normalise resource
        ↓
Compare desired vs actual
        ↓
Classify ownership
        ↓
Generate report output
        ↓
Add tests
        ↓
Update documentation
```

---

# Reporting Issues

When reporting bugs, include:

- Expected behaviour
- Actual behaviour
- Resource type(s)
- Example drift output
- Relevant configuration
- Logs or screenshots if available

Avoid including:

- Secrets
- Access tokens
- Subscription identifiers
- Internal URLs

---

# Code of Conduct

Be respectful, constructive, and collaborative.

Focus feedback on:

- Technical correctness
- Accuracy
- Maintainability
- Usability

The goal of the project is to provide reliable and actionable drift detection for Azure environments managed with Infrastructure as Code.

---

# Questions

If you are unsure whether a change is appropriate:

1. Open an issue or discussion.
2. Describe the scenario.
3. Describe the proposed approach.
4. Seek feedback before significant implementation work begins.

Thank you for helping improve Bicep Drift Agent.
