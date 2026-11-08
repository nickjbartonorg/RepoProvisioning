provider "github" {
  # Auth and owner come from env, set in the workflow:
  #   GITHUB_OWNER, GITHUB_APP_ID, GITHUB_APP_INSTALLATION_ID, GITHUB_APP_PEM_FILE

  # Space out write calls and retry 403 rate-limit responses (GitHub secondary limits).
  parallel_requests = false
  write_delay_ms    = 3000
  max_retries       = 5
}

locals {
  # Shared with the policy. Edit policy/guardrails.yaml, not this file, to change guardrails.
  guardrails = yamldecode(file("${path.module}/../policy/guardrails.yaml"))

  # Flags a repo may turn on in its own YAML under `guardrails:`.
  override_flags = [for k in keys(local.guardrails) : k if substr(k, 0, 8) == "enforce_"]

  # Keys a visibility profile may set: the flags above, plus the approval minimum.
  profile_keys = concat(local.override_flags, ["min_required_reviews"])

  profiles = local.guardrails.visibility_profiles

  repo_files = fileset("${path.module}/../repos", "*.yaml")

  repositories = {
    for f in local.repo_files :
    trimsuffix(f, ".yaml") => merge(
      {
        visibility       = local.guardrails.default_visibility
        risk             = "standard"
        topics           = []
        default_branch   = "main"
        required_reviews = local.guardrails.default_required_reviews
        guardrails       = {}
        owner            = null
        template_ref     = null
      },
      yamldecode(file("${path.module}/../repos/${f}"))
    )
  }

  # Effective settings per repo: global, OR the profile for its visibility, OR its own override.
  # A profile or repo cannot turn a flag off (see the preconditions).
  effective = {
    for name, r in local.repositories : name => merge(
      {
        for f in local.override_flags : f => local.guardrails[f] || lookup(lookup(local.profiles, r.visibility, {}), f, false) || lookup(r.guardrails, f, false)
      },
      {
        min_required_reviews = max(local.guardrails.min_required_reviews, lookup(lookup(local.profiles, r.visibility, {}), "min_required_reviews", 0))
      }
    )
  }
}

resource "github_repository" "this" {
  for_each = local.repositories

  lifecycle {
    precondition {
      condition = alltrue([
        for f, v in each.value.guardrails :
        contains(local.override_flags, f) && (v == true || lookup(local.guardrails, f, false) == false)
      ])
      error_message = "${each.key}: guardrails in the repo file can only turn a guardrail on. Remove unknown keys and any false value for a guardrail that is on in policy/guardrails.yaml."
    }

    precondition {
      condition     = try(tostring(each.value.owner) == each.value.owner, each.value.owner == null)
      error_message = "${each.key}: owner must be a string, for example user:default/nick."
    }

    precondition {
      condition     = contains(["standard", "high"], each.value.risk)
      error_message = "${each.key}: risk must be \"standard\" or \"high\"."
    }

    precondition {
      condition     = try(tostring(each.value.template_ref) == each.value.template_ref, each.value.template_ref == null)
      error_message = "${each.key}: template_ref must be a string, for example template:default/repo-service-request."
    }
  }

  name                   = each.key
  description            = each.value.description
  visibility             = each.value.visibility
  topics                 = each.value.topics
  auto_init              = true
  has_issues             = true
  delete_branch_on_merge = local.effective[each.key].enforce_delete_branch_on_merge

  security_and_analysis {
    secret_scanning {
      status = local.effective[each.key].enforce_secret_scanning ? "enabled" : "disabled"
    }
    secret_scanning_push_protection {
      status = local.effective[each.key].enforce_push_protection ? "enabled" : "disabled"
    }
  }
}

# Fails the plan if a visibility profile would loosen the global settings.
resource "terraform_data" "profile_validation" {
  input = true

  lifecycle {
    precondition {
      condition = alltrue(flatten([
        for vis, p in local.profiles : [
          for k, v in p : contains(local.profile_keys, k) && (
            k == "min_required_reviews" ? v >= local.guardrails.min_required_reviews : (v == true || lookup(local.guardrails, k, false) == false)
          )
        ]
      ]))
      error_message = "guardrails.yaml visibility_profiles can only tighten: turn enforce_* flags on, or raise min_required_reviews. Unknown keys are not allowed."
    }
  }
}

# Carries each repo's effective guardrails into the plan so the policy can check them.
resource "terraform_data" "effective_guardrails" {
  for_each = local.repositories

  input = merge(
    {
      name              = each.key
      owner             = each.value.owner
      template_ref      = each.value.template_ref
      visibility        = each.value.visibility
      risk              = each.value.risk
      approval_required = each.value.risk == local.guardrails.approval_gate.risk && each.value.visibility == local.guardrails.approval_gate.visibility
    },
    local.effective[each.key]
  )
}

resource "github_repository_vulnerability_alerts" "this" {
  for_each = local.repositories

  repository = github_repository.this[each.key].name
  enabled    = local.effective[each.key].enforce_vulnerability_alerts
}

resource "github_repository_dependabot_security_updates" "this" {
  for_each = local.repositories

  # Dependabot security updates need vulnerability alerts enabled first. Disabling them
  # also calls an endpoint that fails when alerts are off.
  depends_on = [github_repository_vulnerability_alerts.this]

  lifecycle {
    precondition {
      condition     = !local.effective[each.key].enforce_dependabot_security_updates || local.effective[each.key].enforce_vulnerability_alerts
      error_message = "${each.key}: enforce_dependabot_security_updates requires enforce_vulnerability_alerts. Turn alerts on too."
    }
  }

  repository = github_repository.this[each.key].name
  enabled    = local.effective[each.key].enforce_dependabot_security_updates
}

resource "github_repository_ruleset" "default_branch" {
  for_each = { for k, r in local.repositories : k => r if local.effective[k].enforce_branch_protection }

  # CODEOWNERS must land before the ruleset blocks direct pushes to the default branch.
  depends_on = [github_repository_file.codeowners]

  name        = "default-branch-protection"
  repository  = github_repository.this[each.key].name
  target      = "branch"
  enforcement = "active"

  conditions {
    ref_name {
      include = ["~DEFAULT_BRANCH"]
      exclude = []
    }
  }

  rules {
    deletion                = local.effective[each.key].enforce_ruleset_block_deletion
    non_fast_forward        = local.effective[each.key].enforce_ruleset_block_force_push
    required_linear_history = local.effective[each.key].enforce_ruleset_linear_history

    pull_request {
      required_approving_review_count   = max(each.value.required_reviews, local.effective[each.key].min_required_reviews)
      dismiss_stale_reviews_on_push     = true
      require_code_owner_review         = true
      require_last_push_approval        = true
      required_review_thread_resolution = true
    }
  }
}

resource "github_repository_file" "codeowners" {
  for_each = local.repositories

  repository          = github_repository.this[each.key].name
  branch              = github_repository.this[each.key].default_branch
  file                = ".github/CODEOWNERS"
  content             = "* ${each.value.codeowners}\n"
  commit_message      = "Add CODEOWNERS (managed by Terraform)"
  commit_author       = "repo-provisioning"
  commit_email        = "repo-provisioning@users.noreply.github.com"
  overwrite_on_create = true
}

# Drops catalog-info.yaml from state only. The file stays in each repo and no commit is made,
# so default-branch rulesets that require a PR do not block the apply.
removed {
  from = github_repository_file.catalog_info

  lifecycle {
    destroy = false
  }
}
