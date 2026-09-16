package guarded_refunds

import rego.v1

# The manifest binds one query per intervention point, so each point has
# its own entrypoint. `verdict` stays as the policy-level default so the
# bundle is still usable through a single query.
default verdict := {"decision": "allow"}

default input_verdict := {"decision": "allow"}

default pre_tool_call_verdict := {"decision": "allow"}

default output_verdict := {"decision": "allow"}

verdict := input_verdict if input.intervention_point == "input"

verdict := pre_tool_call_verdict if input.intervention_point == "pre_tool_call"

verdict := output_verdict if input.intervention_point == "output"

# A user turn that tries to talk past the guardrails never reaches the model.
input_verdict := {
	"decision": "deny",
	"reason": "prompt_injection",
	"message": "The request tried to override the agent's instructions.",
} if {
	input.annotations.injection_risk.label == "prompt_injection"
}

# Refund rules, most severe first. `else` makes the ordering explicit
# rather than relying on rule evaluation order.
pre_tool_call_verdict := {
	"decision": "deny",
	"reason": "fraud_suspected",
	"message": "The refund reason matches a known fraud pattern.",
} if {
	input.tool.name == "issue_refund"
	input.annotations.refund_risk.label == "fraudulent"
} else := {
	"decision": "escalate",
	"reason": "high_value_refund",
	"message": "Refunds above 200 need a human decision.",
} if {
	input.tool.name == "issue_refund"
	input.policy_target.value.amount > 200
} else := {
	"decision": "transform",
	"reason": "refund_capped",
	"message": "Refund reduced to the unattended limit of 100.",
	"transform": {"path": "$target.amount", "value": 100},
} if {
	input.tool.name == "issue_refund"
	input.policy_target.value.amount > 100
}

# The annotator returns both a label and the redacted text, so the policy
# can name a concrete replacement value instead of describing one.
output_verdict := {
	"decision": "transform",
	"reason": "pii_redacted",
	"message": "Customer contact details removed from the reply.",
	"transform": {
		"path": "$target.content",
		"value": input.annotations.pii_scan.redacted,
	},
} if {
	input.annotations.pii_scan.label == "pii_present"
}
