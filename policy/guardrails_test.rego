package main

import rego.v1

# Tests pin the global settings they depend on, so they do not change when an admin edits guardrails.yaml.
# Effective flags for each repo are supplied as terraform_data fixtures, as Terraform produces them.

plan(resources) := {"planned_values": {"root_module": {"resources": resources}}}

flags_on := {
	"enforce_branch_protection": true,
	"enforce_delete_branch_on_merge": true,
	"enforce_vulnerability_alerts": true,
	"enforce_dependabot_security_updates": true,
	"enforce_secret_scanning": true,
	"enforce_push_protection": true,
	"enforce_ruleset_block_deletion": true,
	"enforce_ruleset_block_force_push": true,
	"enforce_ruleset_linear_history": true,
	"min_required_reviews": 1,
}

with_flag(k, v) := object.union(flags_on, {k: v})

effective_for(name, flags) := {
	"address": sprintf("terraform_data.effective_guardrails[\"%s\"]", [name]),
	"type": "terraform_data",
	"values": {"input": object.union({"name": name}, flags)},
}

on := effective_for("demo-app", flags_on)

compliant_repo := {
	"address": "github_repository.this[\"demo-app\"]",
	"type": "github_repository",
	"values": {
		"name": "demo-app",
		"visibility": "private",
		"delete_branch_on_merge": true,
		"security_and_analysis": [{
			"secret_scanning": [{"status": "enabled"}],
			"secret_scanning_push_protection": [{"status": "enabled"}],
		}],
	},
}

compliant_alerts := {
	"address": "github_repository_vulnerability_alerts.this[\"demo-app\"]",
	"type": "github_repository_vulnerability_alerts",
	"values": {"repository": "demo-app", "enabled": true},
}

compliant_dependabot := {
	"address": "github_repository_dependabot_security_updates.this[\"demo-app\"]",
	"type": "github_repository_dependabot_security_updates",
	"values": {"repository": "demo-app", "enabled": true},
}

compliant_ruleset := {
	"address": "github_repository_ruleset.default_branch[\"demo-app\"]",
	"type": "github_repository_ruleset",
	"values": {
		"repository": "demo-app",
		"rules": [{
			"deletion": true,
			"non_fast_forward": true,
			"required_linear_history": true,
			"pull_request": [{"required_approving_review_count": 1}],
		}],
	},
}

compliant_resources := [compliant_repo, compliant_alerts, compliant_dependabot, compliant_ruleset]

# Compliant companions for the repo under test: everything except the repo itself.
rest := [compliant_alerts, compliant_dependabot, compliant_ruleset, on]

rest_with(eff) := [compliant_alerts, compliant_dependabot, compliant_ruleset, eff]

with_values(resource, changes) := object.union(resource, {"values": object.union(resource.values, changes)})

with_rules(rules) := with_values(compliant_ruleset, {"rules": [rules]})

test_compliant_plan_passes if {
	count(deny) == 0
		with input as plan(array.concat(compliant_resources, [on]))
		with data.name_pattern as "^[a-z][a-z0-9-]{2,49}$"
		with data.allowed_visibility as ["public", "private"]
}

test_bad_name_denied if {
	bad := with_values(compliant_repo, {"name": "Bad_Name"})
	count(deny) == 1 with input as plan(array.concat([bad], rest_with(effective_for("Bad_Name", with_flag("enforce_branch_protection", false))))) with data.name_pattern as "^[a-z][a-z0-9-]{2,49}$"
}

test_visibility_not_allowed_denied if {
	bad := with_values(compliant_repo, {"visibility": "internal"})
	count(deny) == 1 with input as plan(array.concat([bad], rest)) with data.allowed_visibility as ["public", "private"]
}

test_visibility_allowed_when_listed if {
	ok := with_values(compliant_repo, {"visibility": "internal"})
	count(deny) == 0 with input as plan(array.concat([ok], rest)) with data.allowed_visibility as ["public", "private", "internal"]
}

test_missing_effective_flags_denied if {
	count(deny) == 1 with input as plan([compliant_repo]) with data.allowed_visibility as ["public", "private"]
}

test_delete_branch_on_merge_off_denied if {
	bad := with_values(compliant_repo, {"delete_branch_on_merge": false})
	count(deny) == 1 with input as plan(array.concat([bad], rest))
}

test_delete_branch_check_skipped_when_flag_off if {
	bad := with_values(compliant_repo, {"delete_branch_on_merge": false})
	count(deny) == 0 with input as plan(array.concat([bad], rest_with(effective_for("demo-app", with_flag("enforce_delete_branch_on_merge", false)))))
}

test_secret_scanning_disabled_denied if {
	bad := with_values(compliant_repo, {"security_and_analysis": [{
		"secret_scanning": [{"status": "disabled"}],
		"secret_scanning_push_protection": [{"status": "enabled"}],
	}]})
	count(deny) == 1 with input as plan(array.concat([bad], rest))
}

test_secret_scanning_off_allows_disabled if {
	bad := with_values(compliant_repo, {"security_and_analysis": [{
		"secret_scanning": [{"status": "disabled"}],
		"secret_scanning_push_protection": [{"status": "enabled"}],
	}]})
	count(deny) == 0 with input as plan(array.concat([bad], rest_with(effective_for("demo-app", with_flag("enforce_secret_scanning", false)))))
}

test_push_protection_disabled_denied if {
	bad := with_values(compliant_repo, {"security_and_analysis": [{
		"secret_scanning": [{"status": "enabled"}],
		"secret_scanning_push_protection": [{"status": "disabled"}],
	}]})
	count(deny) == 1 with input as plan(array.concat([bad], rest))
}

test_alerts_disabled_denied if {
	bad := with_values(compliant_alerts, {"enabled": false})
	count(deny) == 1 with input as plan([compliant_repo, bad, compliant_dependabot, compliant_ruleset, on])
}

test_dependabot_disabled_denied if {
	bad := with_values(compliant_dependabot, {"enabled": false})
	count(deny) == 1 with input as plan([compliant_repo, compliant_alerts, bad, compliant_ruleset, on])
}

test_ruleset_without_deletion_block_denied if {
	bad := with_rules({"deletion": false, "non_fast_forward": true, "required_linear_history": true, "pull_request": [{"required_approving_review_count": 1}]})
	count(deny) == 1 with input as plan([compliant_repo, compliant_alerts, compliant_dependabot, bad, on])
}

test_ruleset_without_force_push_block_denied if {
	bad := with_rules({"deletion": true, "non_fast_forward": false, "required_linear_history": true, "pull_request": [{"required_approving_review_count": 1}]})
	count(deny) == 1 with input as plan([compliant_repo, compliant_alerts, compliant_dependabot, bad, on])
}

test_ruleset_without_linear_history_denied if {
	bad := with_rules({"deletion": true, "non_fast_forward": true, "required_linear_history": false, "pull_request": [{"required_approving_review_count": 1}]})
	count(deny) == 1 with input as plan([compliant_repo, compliant_alerts, compliant_dependabot, bad, on])
}

test_ruleset_below_min_reviews_denied if {
	bad := with_rules({"deletion": true, "non_fast_forward": true, "required_linear_history": true, "pull_request": [{"required_approving_review_count": 0}]})
	count(deny) == 1 with input as plan([compliant_repo, compliant_alerts, compliant_dependabot, bad, on])
}

test_ruleset_meets_raised_min_reviews if {
	ok := with_rules({"deletion": true, "non_fast_forward": true, "required_linear_history": true, "pull_request": [{"required_approving_review_count": 2}]})
	count(deny) == 0 with input as plan([compliant_repo, compliant_alerts, compliant_dependabot, ok, effective_for("demo-app", with_flag("min_required_reviews", 2))])
}

test_branch_protection_on_without_ruleset_denied if {
	count(deny) == 1 with input as plan([compliant_repo, compliant_alerts, compliant_dependabot, on])
}

test_branch_protection_off_without_ruleset_passes if {
	off := effective_for("demo-app", with_flag("enforce_branch_protection", false))
	count(deny) == 0 with input as plan([compliant_repo, compliant_alerts, compliant_dependabot, off])
}

test_repo_turns_branch_protection_on_when_global_off if {
	# Global off, repo override on: the ruleset is planned and checked.
	repo_on := effective_for("demo-app", with_flag("enforce_branch_protection", true))
	count(deny) == 0 with input as plan(array.concat(compliant_resources, [repo_on]))
}

test_profile_raises_min_reviews_denied if {
	# Public profile sets min 2: a ruleset requiring 1 approval fails for that repo.
	public := effective_for("demo-app", with_flag("min_required_reviews", 2))
	count(deny) == 1 with input as plan([compliant_repo, compliant_alerts, compliant_dependabot, compliant_ruleset, public])
}

test_missing_setting_denied if {
	count(deny) == 1 with input as plan([]) with data.enforce_push_protection as null
}

test_owner_string_passes if {
	owned := effective_for("demo-app", object.union(flags_on, {"owner": "user:default/nick", "template_ref": "template:default/repo-service-request"}))
	count(deny) == 0 with input as plan(array.concat(compliant_resources, [owned]))
		with data.name_pattern as "^[a-z][a-z0-9-]{2,49}$"
		with data.allowed_visibility as ["public", "private"]
}

test_owner_absent_passes if {
	count(deny) == 0 with input as plan(array.concat(compliant_resources, [on]))
		with data.name_pattern as "^[a-z][a-z0-9-]{2,49}$"
		with data.allowed_visibility as ["public", "private"]
}

test_owner_not_string_denied if {
	bad := effective_for("demo-app", object.union(flags_on, {"owner": 42}))
	count(deny) == 1 with input as plan(array.concat(compliant_resources, [bad]))
		with data.name_pattern as "^[a-z][a-z0-9-]{2,49}$"
		with data.allowed_visibility as ["public", "private"]
}

test_template_ref_not_string_denied if {
	bad := effective_for("demo-app", object.union(flags_on, {"template_ref": ["template:default/x"]}))
	count(deny) == 1 with input as plan(array.concat(compliant_resources, [bad]))
		with data.name_pattern as "^[a-z][a-z0-9-]{2,49}$"
		with data.allowed_visibility as ["public", "private"]
}

deleted_effective_for(name, flag) := {
	"address": sprintf("terraform_data.effective_guardrails[\"%s\"]", [name]),
	"type": "terraform_data",
	"change": {
		"actions": ["delete"],
		"before": {"input": object.union({"name": name}, with_flag("enforce_delete_protection", flag))},
	},
}

test_delete_blocked_when_protected if {
	count(deny) == 1 with input as {"resource_changes": [deleted_effective_for("demo-app", true)]}
}

test_delete_allowed_when_not_protected if {
	count(deny) == 0 with input as {"resource_changes": [deleted_effective_for("demo-app", false)]}
}
