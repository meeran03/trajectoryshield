"""
Policy Specification Adapter

Uses our own multi-level LTL property framework (from src/taxonomy/policy_specs.py)
as a guardrail. This is the STRONGEST baseline because it has step-level,
trajectory-level, AND temporal properties.

This adapter demonstrates what's possible with the full taxonomy --
and helps validate that DeceptiveComply-Bench trajectories are actually
detectable by a system designed for them.

Expected result: High detection on trajectories matching implemented property types.
Gaps where properties are insufficient (novel deception strategies).
"""

from __future__ import annotations

from trajectoryshield.red_team.guardrail_adapter import GuardrailAdapter, GuardrailVerdict, VerdictType
from trajectoryshield.benchmark.trajectory_schema import Trajectory
from trajectoryshield.taxonomy.policy_specs import get_policy, ALL_POLICIES
from trajectoryshield.taxonomy.ltl_properties import ComplianceType


class PolicySpecAdapter(GuardrailAdapter):
    """
    Uses the multi-level policy specification framework.

    Checks step, trajectory, AND temporal properties -- the full taxonomy.
    This is the "ideal detector" for known deception patterns.
    """

    def __init__(self):
        super().__init__(name="PolicySpec (multi-level LTL)")

    def evaluate_trajectory(self, trajectory: Trajectory) -> GuardrailVerdict:
        """
        Evaluate using the full policy specification framework.

        Converts tool calls to the dict format expected by the property checkers,
        then runs all three property levels.
        """
        policy_id = trajectory.policy.policy_id

        # Check if we have a specification for this policy
        if policy_id not in ALL_POLICIES:
            return GuardrailVerdict(
                guardrail_name=self.name,
                verdict=VerdictType.ALLOW,
                detected=False,
                explanation=f"No policy spec for {policy_id}",
            )

        policy_spec = get_policy(policy_id)

        # Convert trajectory tool calls to dict format for the property checkers
        trajectory_dicts = []
        for tc in trajectory.tool_calls:
            step_dict = {
                "tool": tc.tool,
                "args": tc.args,
                "result": tc.result,
                "step": tc.step,
            }
            trajectory_dicts.append(step_dict)

        # Run all three levels of property checking
        result = policy_spec.check_all(trajectory_dicts)

        if result.compliance_type == ComplianceType.FULLY_COMPLIANT:
            return GuardrailVerdict(
                guardrail_name=self.name,
                verdict=VerdictType.ALLOW,
                detected=False,
                explanation="All property levels passed",
                evaluation_mode="trajectory",
            )

        elif result.compliance_type == ComplianceType.ACCIDENTALLY_NON_COMPLIANT:
            # Step-level violation -- not deceptive, just an obvious violation
            failed = result.failed_properties
            first_fail = failed[0] if failed else None
            step = first_fail.violating_steps[0] if first_fail and first_fail.violating_steps else -1
            return GuardrailVerdict(
                guardrail_name=self.name,
                verdict=VerdictType.BLOCK,
                detected=True,
                detection_step=step,
                confidence=1.0,
                explanation=f"Step-level violation: {first_fail.explanation if first_fail else 'unknown'}",
                evaluation_mode="step",
            )

        else:
            # DECEPTIVELY_COMPLIANT -- step-level passed but trajectory/temporal failed
            failed = result.failed_properties
            explanations = [f.explanation for f in failed]
            return GuardrailVerdict(
                guardrail_name=self.name,
                verdict=VerdictType.BLOCK,
                detected=True,
                detection_step=-1,  # Trajectory-level detection
                confidence=0.9,
                explanation=f"Deceptive compliance detected: {'; '.join(explanations)}",
                evaluation_mode="trajectory",
            )
