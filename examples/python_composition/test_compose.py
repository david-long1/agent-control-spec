# Copyright (c) Microsoft Corporation.
# Licensed under the MIT License.
"""Run with python -m unittest discover -s examples/python_composition -v."""

from __future__ import annotations

import contextlib
import copy
import io
import re
import subprocess
import sys
import unittest

from agent_control_spec import AcsInterceptor, ActivatedPolicy
from agent_hooks import (
    AgentContextBuilder,
    ApprovalOutcome,
    ApprovalResolution,
    CompositionConfig,
    Decision,
    EnforcementMode,
    InterceptionEmitter,
    OnApproval,
    Verdict,
)
from compose import EXAMPLE, make_emitter, refund

ROOT = EXAMPLE.parents[1]


def context(order_id="A-1001", amount=40):
    return AgentContextBuilder(
        agent_id="refund-assistant", framework="test", session_id="test"
    ).pre_tool_call(
        call_id="c1", name="issue_refund", args={"order_id": order_id, "amount": amount}
    )


class SdkTests(unittest.TestCase):
    def test_activation_reuse_and_unbound_point(self):
        policy = ActivatedPolicy(str(EXAMPLE / "limits.yaml"))
        self.assertEqual(policy.intervention_points, ("pre_tool_call",))
        self.assertTrue(policy.governs("pre_tool_call"))
        self.assertFalse(policy.governs("input"))
        for amount, decision in ((40, Decision.ALLOW), (150, Decision.TRANSFORM)):
            with self.subTest(amount=amount):
                ctx = context(amount=amount)
                original = copy.deepcopy(ctx)
                verdict = policy.evaluate("pre_tool_call", ctx)
                self.assertEqual(verdict.decision, decision)
                self.assertEqual(ctx, original)
        self.assertEqual(
            policy.evaluate("input", context()).reason,
            "runtime_error:intervention_point_unknown",
        )
        with self.assertRaises(ValueError):
            policy.evaluate("typo", context())

    def test_loading_and_serialization_errors_propagate(self):
        with self.assertRaises(ValueError):
            ActivatedPolicy(str(EXAMPLE / "missing.yaml"))
        policy = ActivatedPolicy(str(EXAMPLE / "limits.yaml"))
        with self.assertRaises(TypeError):
            policy.evaluate("pre_tool_call", {"not_json": object()})

    def test_sdk_readme_python_blocks(self):
        readme = (ROOT / "sdk/python/README.md").read_text()
        blocks = re.findall(r"```python\n(.*?)\n```", readme, re.DOTALL)
        self.assertEqual(len(blocks), 5)
        result = subprocess.run(
            [
                sys.executable,
                "-c",
                "\n\n".join(blocks)
                + "\nassert policy.evaluate('pre_tool_call', context).transform.value == 100\n",
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertIn("'decision': 'allow'", result.stdout)
        self.assertIn("'decision': 'transform'", result.stdout)
        self.assertIn("'value': 100", result.stdout)

    def test_documentation_links(self):
        for relative in ("sdk/python/README.md", "docs/ACS-AND-AGENT-HOOKS.md"):
            path = ROOT / relative
            for target in re.findall(r"\]\(([^)#]+)\)", path.read_text()):
                if not target.startswith("https://"):
                    self.assertTrue((path.parent / target).resolve().exists(), target)


class CompositionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.emitter = make_emitter()
        self.ledger = []

    async def test_both_allow(self):
        record = await refund(self.emitter, context(), self.ledger)
        self.assertTrue(record.proceeds)
        self.assertEqual(record.verdict.decision, Decision.ALLOW)
        self.assertEqual(
            [(v.name, v.decision) for v in record.verdicts],
            [("limits", Decision.ALLOW), ("orders", Decision.ALLOW)],
        )
        self.assertEqual(self.ledger, [{"order_id": "A-1001", "amount": 40}])
        self.assertEqual(
            record.composition.to_wire(), {"profile": "sequential/run_all"}
        )

    async def test_second_control_deny_prevents_invocation(self):
        record = await refund(
            self.emitter, context(order_id="blocked-order"), self.ledger
        )
        self.assertFalse(record.proceeds)
        self.assertEqual(record.verdict.reason, "order_not_permitted")
        self.assertEqual(
            [v.decision for v in record.verdicts], [Decision.ALLOW, Decision.DENY]
        )
        self.assertEqual(self.ledger, [])

    async def test_transform_folds_into_second_evaluation_and_operation(self):
        ctx = context(order_id="A-1003", amount=150)
        original_args = ctx["tool_call"]["args"]
        record = await refund(self.emitter, ctx, self.ledger)
        self.assertTrue(record.proceeds)
        self.assertEqual(record.verdict.decision, Decision.TRANSFORM)
        self.assertEqual(
            [v.decision for v in record.verdicts], [Decision.TRANSFORM, Decision.ALLOW]
        )
        self.assertEqual(original_args["amount"], 150)
        self.assertEqual(ctx["tool_call"]["args"]["amount"], 100)
        self.assertEqual(self.ledger, [{"order_id": "A-1003", "amount": 100}])

    async def test_transform_then_deny_still_prevents_invocation(self):
        record = await refund(
            self.emitter, context(order_id="blocked-order", amount=150), self.ledger
        )
        self.assertFalse(record.proceeds)
        self.assertEqual(
            [v.decision for v in record.verdicts], [Decision.TRANSFORM, Decision.DENY]
        )
        self.assertEqual(self.ledger, [])

    async def test_parallel_profile_does_not_fold_transform(self):
        self.emitter.set_composition(CompositionConfig.strictest())
        record = await refund(self.emitter, context(amount=150), self.ledger)
        self.assertFalse(record.proceeds)
        self.assertEqual(record.verdict.reason, "order_not_permitted")
        self.assertEqual(self.ledger, [])

    async def test_invalid_amounts_fail_closed(self):
        for amount in (-1, 0, True, "40", None):
            with self.subTest(amount=amount):
                record = await refund(self.emitter, context(amount=amount), self.ledger)
                self.assertFalse(record.proceeds)
                self.assertEqual(record.verdict.reason, "amount_invalid")
                self.assertEqual(len(record.verdicts), 2)
        self.assertEqual(self.ledger, [])

    async def test_evaluation_error_denies_and_other_control_still_runs(self):
        def broken_policy(_invocation):
            raise RuntimeError("deterministic test failure")

        emitter = InterceptionEmitter(composition=CompositionConfig.run_all())
        emitter.register(
            AcsInterceptor(
                str(EXAMPLE / "limits.yaml"), policy_dispatcher=broken_policy
            ),
            "broken",
        )
        emitter.register(AcsInterceptor(str(EXAMPLE / "orders.yaml")), "orders")
        record = await refund(emitter, context(), self.ledger)
        self.assertFalse(record.proceeds)
        self.assertEqual(
            record.verdict.reason, "runtime_error:policy_invocation_failed"
        )
        self.assertEqual([v.name for v in record.verdicts], ["broken", "orders"])
        self.assertEqual(record.verdicts[1].decision, Decision.ALLOW)
        self.assertEqual(self.ledger, [])

    async def test_unbound_point_never_reaches_operation(self):
        ctx = AgentContextBuilder(
            agent_id="a", framework="test", session_id="unbound"
        ).input(content="hello")
        record = await refund(self.emitter, ctx, self.ledger)
        self.assertFalse(record.proceeds)
        self.assertEqual(
            record.verdict.reason, "runtime_error:intervention_point_unknown"
        )
        self.assertEqual(len(record.verdicts), 2)
        self.assertEqual(self.ledger, [])

    async def test_approval_profiles(self):
        class Approver:
            calls = 0

            def resolve(self, request):
                self.calls += 1
                return ApprovalResolution(
                    ApprovalOutcome.APPROVE,
                    request.context_identity,
                    verdict=Verdict.allow(),
                )

        # Override only the first ACS policy output to exercise the approval seam.
        def needs_review(_invocation):
            return {"decision": "escalate", "reason": "review_required"}

        for profile, permitted, controls, resolver_calls in (
            (CompositionConfig.run_all(), False, 2, 0),
            (CompositionConfig.first_deny(OnApproval.STOP), True, 1, 1),
            (CompositionConfig.first_deny(OnApproval.RESUME), False, 2, 1),
        ):
            with self.subTest(profile=profile.to_wire()):
                approver = Approver()
                emitter = InterceptionEmitter(composition=profile, resolver=approver)
                emitter.register(
                    AcsInterceptor(
                        str(EXAMPLE / "limits.yaml"), policy_dispatcher=needs_review
                    ),
                    "review",
                )
                emitter.register(AcsInterceptor(str(EXAMPLE / "orders.yaml")), "orders")
                # Inspect the fold without executing an intentionally unsafe combination.
                record = await emitter.emit_unchecked(context(order_id="blocked-order"))
                self.assertEqual(record.proceeds, permitted)
                self.assertEqual(len(record.verdicts), controls)
                self.assertEqual(approver.calls, resolver_calls)

        no_resolver = InterceptionEmitter(composition=CompositionConfig.run_all())
        no_resolver.register(
            AcsInterceptor(
                str(EXAMPLE / "limits.yaml"), policy_dispatcher=needs_review
            ),
            "review",
        )
        no_resolver.register(AcsInterceptor(str(EXAMPLE / "orders.yaml")), "orders")
        blocked = await refund(no_resolver, context(), self.ledger)
        self.assertFalse(blocked.proceeds)
        self.assertTrue(blocked.verdict.is_liftable)
        self.assertEqual(self.ledger, [])

    async def test_invalid_transform_stops_run_all(self):
        def invalid_transform(_invocation):
            return {
                "decision": "transform",
                "transform": {"path": "$target.missing", "value": 1},
            }

        emitter = InterceptionEmitter(composition=CompositionConfig.run_all())
        emitter.register(
            AcsInterceptor(
                str(EXAMPLE / "limits.yaml"), policy_dispatcher=invalid_transform
            ),
            "invalid",
        )
        emitter.register(AcsInterceptor(str(EXAMPLE / "orders.yaml")), "orders")
        record = await refund(emitter, context(), self.ledger)
        self.assertFalse(record.proceeds)
        self.assertEqual(record.verdict.reason, "host_error:transform_invalid")
        self.assertEqual(len(record.verdicts), 1)
        self.assertEqual(self.ledger, [])

    async def test_evaluate_only_does_not_enforce(self):
        emitter = InterceptionEmitter(
            mode=EnforcementMode.EVALUATE_ONLY, composition=CompositionConfig.run_all()
        )
        emitter.register(AcsInterceptor(str(EXAMPLE / "limits.yaml")), "limits")
        emitter.register(AcsInterceptor(str(EXAMPLE / "orders.yaml")), "orders")
        record = await refund(emitter, context(order_id="blocked-order"), self.ledger)
        self.assertTrue(record.proceeds)
        self.assertEqual(record.verdict.decision, Decision.DENY)
        self.assertEqual(self.ledger, [{"order_id": "blocked-order", "amount": 40}])

    async def test_full_example(self):
        from compose import main

        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            await main(self.emitter)
        self.assertIn("deny: combined=deny, proceeds=False", output.getvalue())
        self.assertIn("transform: combined=transform, proceeds=True", output.getvalue())


if __name__ == "__main__":
    unittest.main()
