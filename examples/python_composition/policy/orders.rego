package refund_orders

import rego.v1

default verdict := {"decision": "deny", "reason": "order_not_permitted"}

verdict := {"decision": "allow"} if {
    input.policy_target.value.order_id in {"A-1001", "A-1003"}
    is_number(input.policy_target.value.amount)
    input.policy_target.value.amount > 0
    input.policy_target.value.amount <= 100
}
