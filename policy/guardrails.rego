package main

import rego.v1

# Rule logic only. Global settings come from policy/guardrails.yaml (loaded as `data`).
# Each repo's effective flags come from terraform_data.effective_guardrails in main.tf:
# the global value, or true if the repo turns the flag on in its own YAML.
# Evaluated against planned_values, so every repo in the configuration is checked on every plan.

effective := {name: g |
	some t in input.planned_values.root_module.resources
	t.type == "terraform_data"
	g := t.values.input
	name := g.name
}

repos contains r if {
	some r in input.planned_values.root_module.resources
	r.type == "github_repository"
}

alerts contains r if {
	some r in input.planned_values.root_module.resources
	r.type == "github_repository_vulnerability_alerts"
}

dependabot contains r if {
	some r in input.planned_values.root_module.resources
	r.type == "github_repository_dependabot_security_updates"
}

rulesets contains r if {
	some r in input.planned_values.root_module.resources
	r.type == "github_repository_ruleset"
}

ruleset_repos contains name if {
	some rs in rulesets
	name := rs.values.repository
}

# Config checks: a missing key would otherwise silently turn a rule off.
deny contains msg if {
	not data.name_pattern
	msg := "guardrails.yaml: 'name_pattern' is missing or has the wrong type"
}

deny contains msg if {
	not data.allowed_visibility
	msg := "guardrails.yaml: 'allowed_visibility' is missing or has the wrong type"
}

deny contains msg if {
	not data.default_visibility
	msg := "guardrails.yaml: 'default_visibility' is missing or has the wrong type"
}

deny contains msg if {
	not is_number(data.min_required_reviews)
	msg := "guardrails.yaml: 'min_required_reviews' is missing or has the wrong type"
}

deny contains msg if {
	not is_number(data.default_required_reviews)
	msg := "guardrails.yaml: 'default_required_reviews' is missing or has the wrong type"
}

deny contains msg if {
	not is_boolean(data.enforce_branch_protection)
	msg := "guardrails.yaml: 'enforce_branch_protection' is missing or has the wrong type"
}

deny contains msg if {
	not is_boolean(data.enforce_delete_branch_on_merge)
	msg := "guardrails.yaml: 'enforce_delete_branch_on_merge' is missing or has the wrong type"
}

deny contains msg if {
	not is_boolean(data.enforce_vulnerability_alerts)
	msg := "guardrails.yaml: 'enforce_vulnerability_alerts' is missing or has the wrong type"
}

deny contains msg if {
	not is_boolean(data.enforce_dependabot_security_updates)
	msg := "guardrails.yaml: 'enforce_dependabot_security_updates' is missing or has the wrong type"
}

deny contains msg if {
	not is_boolean(data.enforce_secret_scanning)
	msg := "guardrails.yaml: 'enforce_secret_scanning' is missing or has the wrong type"
}

deny contains msg if {
	not is_boolean(data.enforce_push_protection)
	msg := "guardrails.yaml: 'enforce_push_protection' is missing or has the wrong type"
}

deny contains msg if {
	not is_boolean(data.enforce_ruleset_block_deletion)
	msg := "guardrails.yaml: 'enforce_ruleset_block_deletion' is missing or has the wrong type"
}

deny contains msg if {
	not is_boolean(data.enforce_ruleset_block_force_push)
	msg := "guardrails.yaml: 'enforce_ruleset_block_force_push' is missing or has the wrong type"
}

deny contains msg if {
	not is_boolean(data.enforce_ruleset_linear_history)
	msg := "guardrails.yaml: 'enforce_ruleset_linear_history' is missing or has the wrong type"
}

deny contains msg if {
	not is_boolean(data.enforce_delete_protection)
	msg := "guardrails.yaml: 'enforce_delete_protection' is missing or has the wrong type"
}

deny contains msg if {
	not is_string(data.approval_gate.risk)
	msg := "guardrails.yaml: 'approval_gate.risk' is missing or has the wrong type"
}

deny contains msg if {
	not is_string(data.approval_gate.visibility)
	msg := "guardrails.yaml: 'approval_gate.visibility' is missing or has the wrong type"
}

# Delete protection. Checks what the plan removes, so it covers repos that leave repos/ as well.
# terraform_data.effective_guardrails carries the flag in its before-state when the repo is removed.
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "terraform_data"
	some action in rc.change.actions
	action == "delete"
	rc.change.before.input.enforce_delete_protection == true
	msg := sprintf("%s: delete is blocked by enforce_delete_protection. Turn the flag off in its own PR, merge it, then remove the repo file.", [rc.address])
}

# Every repo must have effective flags in the plan.
deny contains msg if {
	some r in repos
	not effective[r.values.name]
	msg := sprintf("%s: no effective guardrails for this repo", [r.address])
}

deny contains msg if {
	some r in repos
	not r.values.visibility in data.allowed_visibility
	msg := sprintf("%s: visibility '%s' not in allowed_visibility %v", [r.address, r.values.visibility, data.allowed_visibility])
}

deny contains msg if {
	some r in repos
	not regex.match(data.name_pattern, r.values.name)
	msg := sprintf("%s: name must match name_pattern (%s)", [r.address, data.name_pattern])
}

deny contains msg if {
	some r in repos
	effective[r.values.name].enforce_branch_protection == true
	not ruleset_repos[r.values.name]
	msg := sprintf("%s: enforce_branch_protection is on but no default-branch ruleset is planned", [r.address])
}

deny contains msg if {
	some r in repos
	effective[r.values.name].enforce_delete_branch_on_merge == true
	not r.values.delete_branch_on_merge == true
	msg := sprintf("%s: delete_branch_on_merge must be true (enforce_delete_branch_on_merge)", [r.address])
}

deny contains msg if {
	some r in repos
	effective[r.values.name].enforce_secret_scanning == true
	some saa in r.values.security_and_analysis
	not secret_scanning_enabled(saa)
	msg := sprintf("%s: secret scanning must be enabled (enforce_secret_scanning)", [r.address])
}

deny contains msg if {
	some r in repos
	effective[r.values.name].enforce_push_protection == true
	some saa in r.values.security_and_analysis
	not push_protection_enabled(saa)
	msg := sprintf("%s: push protection must be enabled (enforce_push_protection)", [r.address])
}

deny contains msg if {
	some a in alerts
	effective[a.values.repository].enforce_vulnerability_alerts == true
	not a.values.enabled == true
	msg := sprintf("%s: vulnerability alerts must be enabled (enforce_vulnerability_alerts)", [a.address])
}

deny contains msg if {
	some d in dependabot
	effective[d.values.repository].enforce_dependabot_security_updates == true
	not d.values.enabled == true
	msg := sprintf("%s: Dependabot security updates must be enabled (enforce_dependabot_security_updates)", [d.address])
}

deny contains msg if {
	some rs in rulesets
	effective[rs.values.repository].enforce_ruleset_block_deletion == true
	some rule in rs.values.rules
	not rule.deletion == true
	msg := sprintf("%s: ruleset must block branch deletion (enforce_ruleset_block_deletion)", [rs.address])
}

deny contains msg if {
	some rs in rulesets
	effective[rs.values.repository].enforce_ruleset_block_force_push == true
	some rule in rs.values.rules
	not rule.non_fast_forward == true
	msg := sprintf("%s: ruleset must block force-push (enforce_ruleset_block_force_push)", [rs.address])
}

deny contains msg if {
	some rs in rulesets
	effective[rs.values.repository].enforce_ruleset_linear_history == true
	some rule in rs.values.rules
	not rule.required_linear_history == true
	msg := sprintf("%s: ruleset must require linear history (enforce_ruleset_linear_history)", [rs.address])
}

# Approval minimum is per repo: global, raised by the visibility profile or the repo.
deny contains msg if {
	some rs in rulesets
	some rule in rs.values.rules
	some pr in rule.pull_request
	g := effective[rs.values.repository]
	pr.required_approving_review_count < g.min_required_reviews
	msg := sprintf("%s: requires at least %d approving review(s) (min_required_reviews for this repo)", [rs.address, g.min_required_reviews])
}

deny contains msg if {
	some rs in rulesets
	count(object.get(rs.values, "rules", [])) == 0
	msg := sprintf("%s: ruleset has no rules", [rs.address])
}

# Optional repo keys: owner and template_ref must be strings when set.
deny contains msg if {
	some name, g in effective
	g.owner != null
	not is_string(g.owner)
	msg := sprintf("%s: owner must be a string (catalog entity ref)", [name])
}

deny contains msg if {
	some name, g in effective
	g.template_ref != null
	not is_string(g.template_ref)
	msg := sprintf("%s: template_ref must be a string (catalog template ref)", [name])
}

secret_scanning_enabled(saa) if {
	some ss in saa.secret_scanning
	ss.status == "enabled"
}

push_protection_enabled(saa) if {
	some pp in saa.secret_scanning_push_protection
	pp.status == "enabled"
}
