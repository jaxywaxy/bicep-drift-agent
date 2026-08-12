# Migrating this repo to another GitHub organisation

What actually breaks when `jaxywaxy/bicep-drift-agent` becomes
`<neworg>/bicep-drift-agent`, in the order it bites.

GitHub keeps the git history, issues, PRs, Actions workflows, repo secrets and
repo variables across a transfer, and leaves a redirect from the old path. It
does **not** update anything keyed to the repo's *identity* — which is where
every item below comes from.

## 1. OIDC federated credentials — the one that breaks everything

**Symptom if missed:** every workflow fails at `Azure Login (OIDC)` with
`AADSTS700213: No matching federated identity record found for presented
assertion subject 'repo:<neworg>/bicep-drift-agent:ref:refs/heads/main'`.

Azure trusts a *subject string* that embeds the owner. Transferring the repo
changes the subject; the federated credential still names the old one, so the
token is refused. Nothing in GitHub warns you.

Current credential, on app `github-oidc-terraform`
(`bcfc3973-f472-4b19-b850-749af958b7a9`):

| Name | Subject |
| --- | --- |
| `github-oidc-bicepdrift` | `repo:jaxywaxy/bicep-drift-agent:ref:refs/heads/main` |

Add the replacement **before** the transfer (an app can hold both; they do not
conflict), then delete the old one once the new path is proven:

```bash
az ad app federated-credential create --id bcfc3973-f472-4b19-b850-749af958b7a9 \
  --parameters '{
    "name": "github-oidc-bicepdrift-neworg",
    "issuer": "https://token.actions.githubusercontent.com",
    "subject": "repo:<neworg>/bicep-drift-agent:ref:refs/heads/main",
    "audiences": ["api://AzureADTokenExchange"]
  }'
```

**This is not hypothetical.** `azure-landingzone-bicep/.github/workflows/dev.yml`
had no credential for its `environment:dev` subject and therefore failed every
run from 2026-05-07 until it was discovered on 2026-08-11 — three months of a
red workflow nobody read as "misconfigured trust".

While you are in there, consider also adding
`repo:<neworg>/bicep-drift-agent:pull_request`. Its absence is why a fix cannot
be verified against real Azure from a branch, even though
`docs/LANDING_ZONES_OPERATIONS.md` and `CLAUDE.md` describe
`drift-lz-verify.yml` as doing exactly that.

## 2. Secrets and variables

Transferred with the repo, but verify — and if you are re-creating by hand,
note that **the OpenAI settings are variables, not secrets** (three dead
secrets shadowing them were removed on 2026-08-12).

Secrets (6):
`ANTHROPIC_API_KEY`, `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `BICEP_REPO_TOKEN`,
`PLATFORM_SLACK_WEBHOOK`, `WORKLOAD_SLACK_WEBHOOK`.

Variables (5):
`AZURE_OPENAI_DEPLOYMENT`, `AZURE_OPENAI_ENDPOINT`, `DRIFT_AUTHORIZED_DEPLOYERS`,
`DRIFT_LLM_PROVIDER`, `DRIFT_MODEL_PRICING`.

`BICEP_REPO_TOKEN` is a PAT that reads the external Bicep repos. If those repos
do **not** move with this one, the token's owner must still have access to them
from the new org. If the token belongs to a personal account being wound down,
re-issue it.

## 3. `.github/lz-index.yml` — 7 owner-qualified repo paths

Only needs editing **if the Bicep repos move too**. The index points outward:

```
landingzone, landingzone-prod, spoke-drifttest  ->  jaxywaxy/azure-landingzone-bicep
test-resources, vhub-test,
test-stack-resources, database-testing          ->  jaxywaxy/drift-test-resources
```

If those two repos stay under `jaxywaxy`, leave the index alone — the agent
clones them by full path and does not care where it lives itself.

## 4. What does NOT need changing

Checked on 2026-08-12, so you can skip re-deriving it:

- **No inbound cross-repo references.** No workflow in
  `azure-landingzone-bicep`, `drift-test-resources` or `azure-alz-avm` calls
  `jaxywaxy/bicep-drift-agent`. The agent pulls them; they never call it. So a
  transfer cannot break the LZ repos.
- **No owner references in code.** `jaxywaxy` appears in exactly one tracked
  file, `.github/lz-index.yml`. Nothing in `tools/`, `agent/`, `orchestration/`
  or the workflows hardcodes the owner.
- **No tenant identity or personal data in production code.** Every `jacqui*`
  string under `tools/`, `agent/` and `orchestration/` is a *comment* recording
  a real live-round incident; the tenant GUIDs live only in `tests/` and
  `evals/` fixtures.
- **No GitHub environments** are configured on this repo, so there are no
  environment protection rules or environment-scoped secrets to recreate.
  (The LZ repos are different — `azure-landingzone-bicep` has a `dev`
  environment whose branch policy allows only the `dev` branch to deploy.)

## 5. Order of operations

1. Add the new federated credential (old one still in place).
2. Transfer the repo.
3. Confirm secrets and variables survived; recreate any that did not.
4. Run a scan against a landing zone you *do* own — it exercises OIDC, the
   external-repo clone, the LLM provider and notifications in one pass, and a
   green run proves the whole chain. The verification fixtures were not
   migrated (see `TEST_ESTATE.md`), so use a real LZ or stand up a fixture
   first.
5. Update `.github/lz-index.yml` only if the Bicep repos moved.
6. Delete the old federated credential.

## 6. Tenant or subscription move

Out of scope above, and a bigger job: `DRIFT_AUTHORIZED_DEPLOYERS` is a tenant
principal GUID, the OIDC app registrations are tenant objects, and the LZ
configs in the external repos carry subscription IDs. Treat that as a separate
migration, not a step in this one.
