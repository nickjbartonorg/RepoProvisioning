# RepoProvisioning

Provisions GitHub repositories with Terraform and enforces compliance guardrails before any change applies.

## How it works

1. Add `repos/<repo-name>.yaml` (see `repos/example-repo.yaml.example`) and open a PR.
2. `terraform-plan.yml` runs fmt, validate, policy unit tests, a plan, then Conftest against the plan JSON. A failing guardrail blocks the PR.
3. Merge to `main`. `terraform-apply.yml` runs the same plan and policy gate, pauses at the `repo-provisioning-prod` environment for approval, then applies the saved plan.

Each YAML file becomes one set of resources in `terraform/main.tf`, created with `for_each`:

| Resource | Setting |
|---|---|
| `github_repository` | Name, description, visibility, topics. Delete branch on merge on. Secret scanning and push protection on. |
| `github_repository_vulnerability_alerts` | Enabled |
| `github_repository_dependabot_security_updates` | Enabled |
| `github_repository_ruleset` | Default branch: no deletion, no force-push, linear history, PR required, approvals required, code-owner review, stale reviews dismissed |
| `github_repository_file` | `.github/CODEOWNERS` with `* <codeowners>` |

## Repo file format

One file per repo, named `<repo-name>.yaml`. The file name must match the repo name.

| Key | Required | Default | Notes |
|---|---|---|---|
| `description` | Yes | None | Shown on the repo |
| `codeowners` | Yes | None | Written as the `*` owner in CODEOWNERS, for example `@org/team` |
| `visibility` | No | `default_visibility` (private) | Must be in `allowed_visibility` |
| `topics` | No | `[]` | |
| `required_reviews` | No | `default_required_reviews` (1) | Must be at least `min_required_reviews` |
| `owner` | No | None | Backstage catalog entity ref, for example `user:default/nick`. Must be a string. Read by the Backstage entity provider. |
| `template_ref` | No | None | Backstage template ref, for example `template:default/repo-service-request`. Must be a string. Read by the Backstage entity provider. |
| `type` | No | `service` | Backstage Component type, for example `documentation`. Must be a string. Read by the Backstage entity provider. |
| `techdocs_ref` | No | None | TechDocs source, for example `url:https://github.com/org/repo`. Written to `backstage.io/techdocs-ref`. Must be a string. Read by the Backstage entity provider. |
| `guardrails` | No | None | Turns `enforce_*` flags on for this repo only. See [Per-repo guardrails](#per-repo-guardrails). |
| `risk` | No | `standard` | `standard` or `high`. A `high` repo that is `public` needs approval before apply (see [Approval](#approval)). |

## Guardrails

Every guardrail setting lives in `policy/guardrails.yaml`. Terraform reads it to configure repos, and the policy reads it to check the plan. To change a guardrail, edit that one file.

### Settings

| Key | Type | Effect |
|---|---|---|
| `name_pattern` | Regex | Repo names must match |
| `allowed_visibility` | List | Visibility must be one of these values |
| `default_visibility` | Text | Visibility used when a repo YAML does not set one |
| `default_required_reviews` | Number | Approvals used when a repo YAML does not set one |
| `min_required_reviews` | Number | Minimum approvals a ruleset may require |
| `enforce_branch_protection` | `true`/`false` | A ruleset on the default branch is created |
| `enforce_delete_branch_on_merge` | `true`/`false` | Delete head branches on merge |
| `enforce_vulnerability_alerts` | `true`/`false` | Vulnerability alerts on |
| `enforce_dependabot_security_updates` | `true`/`false` | Dependabot security updates on |
| `enforce_secret_scanning` | `true`/`false` | Secret scanning on |
| `enforce_push_protection` | `true`/`false` | Secret scanning push protection on |
| `enforce_ruleset_block_deletion` | `true`/`false` | Ruleset blocks branch deletion |
| `enforce_ruleset_block_force_push` | `true`/`false` | Ruleset blocks force-push |
| `enforce_ruleset_linear_history` | `true`/`false` | Ruleset requires linear history |

A `true` flag means Terraform sets the setting and the policy requires it. A `false` flag means neither does. A missing key, or a value of the wrong type, fails the plan with a message naming the key.

### Change a guardrail

No code is needed for these changes.

1. Create a branch and edit `policy/guardrails.yaml`.
2. Change a value, or flip a flag.
3. Open a PR. The plan job checks every repo against the new settings. A failure names the key that caused it.
4. Merge. The apply job re-runs the same check before applying.

Examples:

- Require two approvals: set `min_required_reviews: 2`.
- Allow internal repos: set `allowed_visibility: [public, private, internal]`.
- Stop requiring linear history: set `enforce_ruleset_linear_history: false`.

Changes apply to every repo in `repos/` on the next plan. Turning a flag off also stops Terraform from setting that option on existing repos at the next apply.

### Add a new guardrail

A new guardrail needs a Rego change. Steps:

1. Add the key to `policy/guardrails.yaml` with a value.
2. Use it in `terraform/main.tf` as `local.guardrails.<key>` for the setting it controls.
3. Add a `deny` rule to `policy/guardrails.rego` that runs only when the key is true:

   ```rego
   deny contains msg if {
   	data.enforce_wiki_disabled
   	some r in repos
   	r.values.has_wiki == true
   	msg := sprintf("%s: wiki must be disabled (enforce_wiki_disabled)", [r.address])
   }
   ```

4. Add a passing test and a failing test to `policy/guardrails_test.rego`. Pin the key in each test with `with data.<key> as <value>`, so the tests do not depend on the shipped file.
5. Add a config check for the new key. Copy an existing one, such as `deny contains msg if { not is_boolean(data.enforce_secret_scanning) ... }`, so a missing key fails the plan.
6. Run the local checks below, then open a PR.

### Visibility profiles

Settings can differ by repo visibility. The `visibility_profiles` section of `policy/guardrails.yaml` holds one block per visibility:

```yaml
visibility_profiles:
  public:
    enforce_push_protection: true
    min_required_reviews: 2
  private: {}
```

Rules:

- A profile can turn an `enforce_*` flag on, or raise `min_required_reviews`. It cannot turn a flag off or lower the minimum. Terraform stops the plan if it does.
- A profile only lists the settings it changes. Everything else comes from the global values.
- The profile is picked from the repo's `visibility`, which defaults to `default_visibility`.
- Effective setting = global value, OR the profile for the repo's visibility, OR the repo's own `guardrails:` override.

Example: `public` repos get push protection and two approvals. `private` repos get the global settings unless their own YAML changes them.

### Per-repo guardrails

A repo can turn guardrails on for itself. This supports a risk-based approach: keep the global settings lenient, and enforce stricter controls on the repos that need them.

```yaml
# repos/payments-api.yaml
description: "Payments API"
codeowners: "@org/payments"
guardrails:
  enforce_branch_protection: true
  enforce_ruleset_linear_history: true
```

Rules:

- A repo can set any `enforce_*` flag to `true`. This turns the guardrail on for that repo only.
- A repo cannot set a flag to `false` when it is `true` in `guardrails.yaml`. Terraform stops the plan with a message naming the repo.
- Unknown keys in `guardrails:` also stop the plan.
- Name pattern, allowed visibility and default visibility are global. A repo can raise its own `required_reviews`, but not below its effective minimum, which is `min_required_reviews` raised by the visibility profile if that is higher.

The policy checks each repo against its effective settings: the global value, or on if the repo turns it on. Terraform records those settings in a `terraform_data.effective_guardrails` resource per repo, and the policy reads them from the plan.

Example: keep `enforce_branch_protection: false` globally, so most repos get no ruleset. Repos that need branch protection add `enforce_branch_protection: true` in their YAML.

### Files

| File | Purpose |
|---|---|
| `policy/guardrails.yaml` | Global settings. Edit this to change a guardrail for all repos. |
| `policy/guardrails.rego` | Rule logic. One rule per guardrail. |
| `policy/guardrails_test.rego` | Unit tests for the rules. |
| `terraform/main.tf` | Reads the settings and configures repos. |

### What is checked

The policy checks the planned state of every repo in `repos/`, including repos that are not changing. Each plan re-evaluates all repos against the current settings. Raising `min_required_reviews` therefore fails the plan for any existing repo below the new minimum.

## Setup (one time)

**Terraform Cloud**
- Create organisation and workspace `repo-provisioning`.
- Set workspace **Execution Mode** to **Local**. Plans and applies then run on the Actions runner with its GitHub credentials. State stays in TF Cloud.
- Create a team API token.

**GitHub App** (owned by the account or organisation that will hold the repos)
- Permissions: Administration (read and write), Contents (read and write), Metadata (read), Dependabot alerts (read and write).
- Install on the target account for all repositories or selected repositories.
- Generate a private key (`.pem`).

**GitHub repo settings for this repository**

| Type | Name | Value |
|---|---|---|
| Variable | `TF_CLOUD_ORGANIZATION` | Your TF Cloud org |
| Variable | `REPO_OWNER` | Owner of the target repos |
| Variable | `APP_ID` | App ID |
| Variable | `APP_INSTALLATION_ID` | Installation ID |
| Secret | `TF_API_TOKEN` | TF Cloud token |
| Secret | `APP_PRIVATE_KEY` | Full contents of the `.pem` file |

Create environment `repo-provisioning-prod` with required reviewers.

## Limits on a Free personal account or organisation

- Rulesets and branch protection do not apply to **private** repos on Free. Use public repos for testing, or upgrade.
- Secret scanning push protection on **private** repos requires GitHub Advanced Security. Public repos are covered.
- Dependabot security updates and vulnerability alerts apply on Free for both public and private repos.

Tighten `allowed_visibility` to `["private"]` once the account has GitHub Pro, Team or Enterprise.

## Test plan

1. Open a PR adding `repos/guardrail-test-public.yaml` with `visibility: public`. Confirm plan and policy pass.
2. Open a PR with an uppercase name or `visibility: internal`. Confirm the policy gate fails.
3. Merge test 1, approve the environment, then confirm in the GitHub UI: ruleset active, CODEOWNERS present, secret scanning enabled.
4. Remove the test file in a PR, merge, approve. Confirm the repo is destroyed.

## Local checks

```bash
cd terraform && terraform fmt -check -recursive && terraform init -backend=false && terraform validate
cd .. && conftest verify --policy policy --data policy/guardrails.yaml
```

`conftest verify` runs the unit tests. To test a real plan locally, run `terraform show -json tfplan > plan.json` and then `conftest test plan.json --policy policy --data policy/guardrails.yaml`.

## Known gaps

- The policy checks planned state from Terraform, so it only sees what the provider reads. Settings that the provider does not read, or that Terraform does not manage, are not checked.
- A new key is only validated if a config check is added for it in `policy/guardrails.rego`. Add one when you add a key.
- Repo overrides are checked by Terraform's precondition, which runs during plan. The policy only sees the effective result.
- The checks rely on the attribute names in the Terraform provider. A provider upgrade can rename an attribute, so the tests should be run after upgrading `integrations/github`.

## Approval

Apply runs in two jobs. The plan job runs the policy gate on the saved plan and decides whether a person must approve. If it decides yes, apply waits on the `repo-provisioning-approval` environment.

Approval is needed when the plan:

- deletes a repo, or
- creates or changes a repo with `risk: high` and `visibility: public`. The pair is set in `approval_gate` in `policy/guardrails.yaml`.

Any other change applies without approval, using the `repo-provisioning-prod` environment.

Setup (once, in GitHub settings for this repo): create the environment `repo-provisioning-approval` with required reviewers. Leave "Prevent self-review" off while you are the only reviewer. Without required reviewers the environment has no gate.

## Delete protection

Set `enforce_delete_protection: true` in a repo file's `guardrails:` section to block deletion of that repo. The policy rejects any plan that removes the repo while the flag is on.

To delete a protected repo: open a PR that turns the flag off, merge it, then open a PR that removes the repo file. The delete still needs approval at apply.
