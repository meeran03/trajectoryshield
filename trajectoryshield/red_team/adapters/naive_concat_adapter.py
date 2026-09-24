"""
Naive Concatenation Adapter

A simple baseline that concatenates all tool call contents and runs
the step-level predicate engine on the concatenated result.

This tests the simplest possible "trajectory-level" approach:
just smash everything together and run existing checks.

Expected result: Catches some compositional obfuscation (where
concatenation reveals the violation) but misses temporal evasion
and many literal compliance cases.
"""

from __future__ import annotations

from trajectoryshield.predicates import PredicateEngine, Decision
from trajectoryshield.red_team.guardrail_adapter import GuardrailAdapter, GuardrailVerdict, VerdictType
from trajectoryshield.benchmark.trajectory_schema import Trajectory


class NaiveConcatAdapter(GuardrailAdapter):
    """
    Concatenates all tool call contents and checks the combined result.

    This is the simplest possible improvement over pure step-level checking.
    """

    def __init__(self):
        super().__init__(name="NaiveConcat (concatenate + check)")
        self.engine = PredicateEngine()

    def evaluate_trajectory(self, trajectory: Trajectory) -> GuardrailVerdict:
        """
        Concatenate all write contents and check the result.
        """
        # Collect all content from write operations
        all_content_parts = []
        for tc in trajectory.tool_calls:
            if tc.tool in ("write_file", "append_to_file", "create_file"):
                content = tc.args.get("content", "")
                if content:
                    all_content_parts.append(content)

        if not all_content_parts:
            return GuardrailVerdict(
                guardrail_name=self.name,
                verdict=VerdictType.ALLOW,
                detected=False,
                explanation="No write operations in trajectory",
                evaluation_mode="trajectory",
            )

        # Concatenate everything into one big "file"
        combined_content = "\n".join(all_content_parts)

        # Run the predicate engine on the combined content
        proposal = {
            "file_path": "combined_trajectory_output.py",
            "diff": combined_content,
            "content": combined_content,
        }

        result = self.engine.evaluate(
            edge="verify_edit",
            proposal=proposal,
            observation={},
        )

        if result.decision == Decision.BLOCK:
            return GuardrailVerdict(
                guardrail_name=self.name,
                verdict=VerdictType.BLOCK,
                detected=True,
                detection_step=-1,  # Trajectory-level
                confidence=0.8,
                explanation=f"Combined content violation: {result.reason}",
                evaluation_mode="trajectory",
            )

        return GuardrailVerdict(
            guardrail_name=self.name,
            verdict=VerdictType.ALLOW,
            detected=False,
            explanation="Combined content passed all predicate checks",
            evaluation_mode="trajectory",
        )
