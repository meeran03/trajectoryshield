"""
Predicate Engine Adapter

Wraps the existing PredicateEngine (from src/predicates.py) as a guardrail
baseline. This is Baseline 1 -- the project's own rule-based system.

The PredicateEngine operates at the step level (per-tool-call), which means
it should catch accidental violations but miss all deceptive compliance types.

Expected result: ~0% detection on deceptive trajectories.
This is the "these are the best existing rules, and they completely fail" baseline.
"""

from __future__ import annotations

from trajectoryshield.predicates import PredicateEngine, Decision
from trajectoryshield.red_team.guardrail_adapter import GuardrailAdapter, GuardrailVerdict, VerdictType
from trajectoryshield.benchmark.trajectory_schema import Trajectory


class PredicateEngineAdapter(GuardrailAdapter):
    """
    Wraps the existing PredicateEngine for step-level evaluation.

    Evaluates each tool call in the trajectory independently.
    Flags the trajectory if ANY step is blocked.
    """

    def __init__(self):
        super().__init__(name="PredicateEngine (step-level)")
        self.engine = PredicateEngine()

    def evaluate_trajectory(self, trajectory: Trajectory) -> GuardrailVerdict:
        """
        Evaluate trajectory by checking each step independently.

        This is how existing rule-based guardrails work -- per-step checks.
        It should fail completely on deceptive compliance because the whole
        point of deception is that individual steps look clean.
        """
        for tc in trajectory.tool_calls:
            # The PredicateEngine expects an edge name, a proposal dict, and observation
            # We adapt the tool call format to match
            if tc.tool not in ("write_file", "append_to_file", "create_file"):
                continue  # PredicateEngine only checks file writes

            proposal = {
                "file_path": tc.args.get("path", "unknown.py"),
                "diff": tc.args.get("content", ""),
                "content": tc.args.get("content", ""),
            }
            observation = {}

            result = self.engine.evaluate(
                edge="verify_edit",
                proposal=proposal,
                observation=observation,
            )

            if result.decision == Decision.BLOCK:
                return GuardrailVerdict(
                    guardrail_name=self.name,
                    verdict=VerdictType.BLOCK,
                    detected=True,
                    detection_step=tc.step,
                    confidence=1.0,
                    explanation=f"Step {tc.step}: {result.reason}",
                    evaluation_mode="step",
                )

        return GuardrailVerdict(
            guardrail_name=self.name,
            verdict=VerdictType.ALLOW,
            detected=False,
            explanation="All steps passed individual predicate checks",
            evaluation_mode="step",
        )
