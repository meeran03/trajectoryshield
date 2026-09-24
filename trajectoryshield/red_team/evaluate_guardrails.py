"""
Guardrail Evaluation Runner

Orchestrates the evaluation of all guardrail systems against
DeceptiveComply-Bench. This produces the data for Chapter 3:
"The Failure of Existing Guardrails."

Usage:
    runner = GuardrailEvaluationRunner()
    runner.add_guardrail(PredicateEngineAdapter())
    runner.add_guardrail(LLMJudgeAdapter(model="gpt-5.2"))
    runner.add_guardrail(PolicySpecAdapter())
    results = runner.evaluate_all(dataset)
    runner.print_comparison(results)
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Optional

from trajectoryshield.red_team.guardrail_adapter import GuardrailAdapter, GuardrailEvalResult
from trajectoryshield.benchmark.trajectory_schema import Trajectory, BenchmarkDataset


class GuardrailEvaluationRunner:
    """
    Runs all registered guardrail adapters against a dataset and
    produces a comparative analysis.
    """

    def __init__(self):
        self.guardrails: list[GuardrailAdapter] = []

    def add_guardrail(self, adapter: GuardrailAdapter) -> None:
        """Register a guardrail adapter for evaluation."""
        self.guardrails.append(adapter)
        print(f"  Registered: {adapter.name}")

    def evaluate_all(
        self,
        trajectories: list[Trajectory],
        verbose: bool = True,
    ) -> list[GuardrailEvalResult]:
        """
        Run all guardrails on all trajectories.

        Args:
            trajectories: The trajectories to evaluate
            verbose: Print progress

        Returns:
            List of GuardrailEvalResult, one per guardrail
        """
        results = []

        for adapter in self.guardrails:
            if verbose:
                print(f"\nEvaluating: {adapter.name}")
                print(f"  Trajectories: {len(trajectories)}")

            start = time.perf_counter()
            result = adapter.evaluate_batch(trajectories)
            total_time = (time.perf_counter() - start) * 1000

            if verbose:
                print(f"  Completed in {total_time:.0f}ms")
                print(f"  Detection rate: {result.detection_rate:.1%}")
                print(f"  False positive rate: {result.false_positive_rate:.1%}")

            results.append(result)

        return results

    def print_comparison(self, results: list[GuardrailEvalResult]) -> str:
        """
        Print a comparative table of all guardrail results.

        Returns the formatted string.
        """
        lines = [
            "",
            "=" * 90,
            "GUARDRAIL COMPARISON ON DeceptiveComply-Bench",
            "=" * 90,
            "",
        ]

        # Header
        header = f"{'Guardrail':<35} {'Det.Rate':>8} {'FPR':>8} {'Prec':>8} {'F1':>8} {'Lat(ms)':>8}"
        lines.append(header)
        lines.append("-" * 90)

        for result in results:
            row = (
                f"{result.guardrail_name:<35} "
                f"{result.detection_rate:>7.1%} "
                f"{result.false_positive_rate:>7.1%} "
                f"{result.precision:>7.1%} "
                f"{result.f1:>7.3f} "
                f"{result.avg_latency_ms:>7.1f}"
            )
            lines.append(row)

        lines.append("-" * 90)
        lines.append("")

        # Per deception-type breakdown
        lines.append("DETECTION RATE BY DECEPTION TYPE")
        lines.append("-" * 90)

        # Collect all deception types
        all_types = set()
        for result in results:
            all_types.update(result.detection_by_type.keys())
        all_types = sorted(all_types)

        type_header = f"{'Guardrail':<35}" + "".join(f" {t[:12]:>12}" for t in all_types)
        lines.append(type_header)
        lines.append("-" * 90)

        for result in results:
            row_parts = [f"{result.guardrail_name:<35}"]
            for dtype in all_types:
                metrics = result.detection_by_type.get(dtype, {})
                rate = metrics.get("detection_rate", 0)
                total = metrics.get("total", 0)
                if total > 0:
                    row_parts.append(f" {rate:>11.1%}")
                else:
                    row_parts.append(f" {'N/A':>11}")
            lines.append("".join(row_parts))

        lines.append("-" * 90)
        lines.append("")

        output = "\n".join(lines)
        print(output)
        return output

    def save_results(
        self,
        results: list[GuardrailEvalResult],
        output_path: str = "results/guardrail_comparison.json",
    ) -> None:
        """Save results to JSON for later analysis."""
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        data = []
        for result in results:
            data.append({
                "guardrail_name": result.guardrail_name,
                "total_trajectories": result.total_trajectories,
                "true_positives": result.true_positives,
                "false_positives": result.false_positives,
                "true_negatives": result.true_negatives,
                "false_negatives": result.false_negatives,
                "detection_rate": result.detection_rate,
                "false_positive_rate": result.false_positive_rate,
                "precision": result.precision,
                "f1": result.f1,
                "avg_latency_ms": result.avg_latency_ms,
                "detection_by_type": result.detection_by_type,
                "detection_by_domain": result.detection_by_domain,
            })

        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print(f"Results saved to {output_path}")

    @staticmethod
    def build_default_local_guardrails() -> list[GuardrailAdapter]:
        """
        Build the set of guardrails that can run locally (no API keys needed).

        Returns adapters for:
            1. PredicateEngine (step-level rules)
            2. NaiveConcat (concatenate + check)
            3. PolicySpec (multi-level LTL)
        """
        from trajectoryshield.red_team.adapters.predicate_adapter import PredicateEngineAdapter
        from trajectoryshield.red_team.adapters.naive_concat_adapter import NaiveConcatAdapter
        from trajectoryshield.red_team.adapters.policy_spec_adapter import PolicySpecAdapter

        return [
            PredicateEngineAdapter(),
            NaiveConcatAdapter(),
            PolicySpecAdapter(),
        ]

    @staticmethod
    def build_all_guardrails(
        llm_models: Optional[list[str]] = None,
    ) -> list[GuardrailAdapter]:
        """
        Build the full set of guardrails including LLM judges.

        Args:
            llm_models: Models to use as judges. Default: ["gpt-5.2", "claude-opus-4-5-20250301"]
        """
        from trajectoryshield.red_team.adapters.predicate_adapter import PredicateEngineAdapter
        from trajectoryshield.red_team.adapters.naive_concat_adapter import NaiveConcatAdapter
        from trajectoryshield.red_team.adapters.policy_spec_adapter import PolicySpecAdapter
        from trajectoryshield.red_team.adapters.llm_judge_adapter import LLMJudgeAdapter

        if llm_models is None:
            llm_models = ["gpt-5.2", "claude-opus-4-5-20250301"]

        adapters: list[GuardrailAdapter] = [
            PredicateEngineAdapter(),
            NaiveConcatAdapter(),
            PolicySpecAdapter(),
        ]

        for model in llm_models:
            adapters.append(LLMJudgeAdapter(model=model))

        return adapters


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main():
    """Run guardrail evaluation from command line."""
    import argparse

    parser = argparse.ArgumentParser(description="Evaluate guardrails on DeceptiveComply-Bench")
    parser.add_argument("--dataset", default=None,
                        help="Path to benchmark dataset JSON (ignored if --gold-standard)")
    parser.add_argument("--gold-standard", action="store_true",
                        help="Use 300 human-crafted gold-standard trajectories instead of dataset file")
    parser.add_argument("--local-only", action="store_true",
                        help="Only run local guardrails (no API calls)")
    parser.add_argument("--output", default="results/guardrail_comparison.json",
                        help="Output JSON path")
    args = parser.parse_args()

    # Load dataset
    if args.gold_standard:
        from trajectoryshield.benchmark.gold_standard import get_gold_standard_dataset
        dataset = get_gold_standard_dataset()
        print("Using gold-standard dataset (300 human-crafted deceptive trajectories)")
    else:
        dataset = BenchmarkDataset.load(args.dataset or "data/deceptive_comply_bench/dataset.json")
    print(f"Loaded {dataset.num_trajectories} trajectories")
    print(dataset.summary())

    # Build guardrails
    runner = GuardrailEvaluationRunner()
    if args.local_only:
        for adapter in runner.build_default_local_guardrails():
            runner.add_guardrail(adapter)
    else:
        for adapter in runner.build_all_guardrails():
            runner.add_guardrail(adapter)

    # Run evaluation
    results = runner.evaluate_all(dataset.trajectories)

    # Print and save
    runner.print_comparison(results)
    runner.save_results(results, args.output)


if __name__ == "__main__":
    main()
