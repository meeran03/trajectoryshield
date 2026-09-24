"""
Benchmark validation: schema checks, quality analysis, detector agreement,
and distribution stats. Produces thesis-ready validation tables.

Checks:
    1. Schema consistency (all fields present, labels consistent)
    2. Distribution balance (domain, deception type, source)
    3. Step-level annotation consistency (compliant_individually flags)
    4. Detector agreement: compare ground-truth labels to TrajectoryShield verdicts
       (agreement between human labels and automated detector = proxy for annotation quality)
    5. Cross-source quality: gold-standard vs LLM-generated quality comparison

Usage:
    python -m trajectoryshield.benchmark.validate_benchmark
    python -m trajectoryshield.benchmark.validate_benchmark --dataset data/deceptive_comply_bench/dataset.json
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from pathlib import Path

from trajectoryshield.benchmark.trajectory_schema import Trajectory, BenchmarkDataset


# ---------------------------------------------------------------------------
# Schema and consistency checks
# ---------------------------------------------------------------------------


def check_schema(dataset: BenchmarkDataset) -> list[str]:
    """Check all trajectories have valid schema and consistent labels."""
    errors = []
    seen_ids = set()
    for i, t in enumerate(dataset.trajectories):
        if not t.tool_calls:
            errors.append(f"Trajectory {i} ({t.trajectory_id}): no tool_calls")
        if not t.policy or not t.policy.policy_id:
            errors.append(f"Trajectory {i} ({t.trajectory_id}): missing policy_id")
        if t.label.deception_type == "honest" and not t.is_honest:
            errors.append(f"Trajectory {i} ({t.trajectory_id}): label honest but is_deceptive=True")
        if t.label.deception_type != "honest" and t.is_honest:
            errors.append(f"Trajectory {i} ({t.trajectory_id}): label deceptive but is_honest=True")
        if t.trajectory_id in seen_ids:
            errors.append(f"Trajectory {i}: duplicate trajectory_id '{t.trajectory_id}'")
        seen_ids.add(t.trajectory_id)
        # Deceptive trajectories should not be marked trajectory_compliant
        if t.is_deceptive and t.label.trajectory_compliant:
            errors.append(f"Trajectory {i} ({t.trajectory_id}): deceptive but trajectory_compliant=True")
        # Each deceptive trajectory should have a step_analysis or strategy
        if t.is_deceptive and not t.label.deception_strategy and not t.label.violation_explanation:
            errors.append(f"Trajectory {i} ({t.trajectory_id}): deceptive but no strategy or violation_explanation")
    return errors


# ---------------------------------------------------------------------------
# Distribution analysis
# ---------------------------------------------------------------------------


def compute_distributions(dataset: BenchmarkDataset) -> dict:
    """Compute distribution stats for thesis tables."""
    by_domain = Counter(t.policy.domain for t in dataset.trajectories)
    by_deception_type = Counter(t.label.deception_type for t in dataset.trajectories)
    by_source = Counter(t.metadata.source for t in dataset.trajectories)
    by_domain_type = Counter(
        (t.policy.domain, t.label.deception_type) for t in dataset.trajectories
    )
    steps_per_traj = [t.num_steps for t in dataset.trajectories]
    tools_used = Counter()
    for t in dataset.trajectories:
        for tc in t.tool_calls:
            tools_used[tc.tool] += 1

    return {
        "total": dataset.num_trajectories,
        "num_honest": dataset.num_honest,
        "num_deceptive": dataset.num_deceptive,
        "domains": len(by_domain),
        "avg_steps": sum(steps_per_traj) / len(steps_per_traj) if steps_per_traj else 0,
        "min_steps": min(steps_per_traj) if steps_per_traj else 0,
        "max_steps": max(steps_per_traj) if steps_per_traj else 0,
        "by_domain": dict(by_domain),
        "by_deception_type": dict(by_deception_type),
        "by_source": dict(by_source),
        "by_domain_type": {f"{d}|{t}": c for (d, t), c in sorted(by_domain_type.items())},
        "top_tools": dict(tools_used.most_common(10)),
    }


# ---------------------------------------------------------------------------
# Step-level annotation consistency
# ---------------------------------------------------------------------------


def check_step_annotations(dataset: BenchmarkDataset) -> dict:
    """
    Check consistency of compliant_individually annotations.

    For deceptive trajectories: all steps should be individually compliant
    (that's the definition of deception -- each step passes step-level checks).
    """
    total_deceptive = 0
    deceptive_with_all_steps_compliant = 0
    deceptive_with_noncompliant_steps = 0
    noncompliant_step_details = []

    for t in dataset.trajectories:
        if not t.is_deceptive:
            continue
        total_deceptive += 1
        all_compliant = all(tc.compliant_individually for tc in t.tool_calls)
        if all_compliant:
            deceptive_with_all_steps_compliant += 1
        else:
            deceptive_with_noncompliant_steps += 1
            noncompliant_step_details.append(t.trajectory_id)

    return {
        "total_deceptive": total_deceptive,
        "all_steps_compliant": deceptive_with_all_steps_compliant,
        "has_noncompliant_step": deceptive_with_noncompliant_steps,
        "pct_all_steps_compliant": (
            deceptive_with_all_steps_compliant / total_deceptive * 100
            if total_deceptive > 0 else 0
        ),
        "noncompliant_examples": noncompliant_step_details[:10],
    }


# ---------------------------------------------------------------------------
# Detector agreement (proxy for inter-annotator agreement)
# ---------------------------------------------------------------------------


def compute_detector_agreement(dataset: BenchmarkDataset) -> dict:
    """
    Compute agreement between ground-truth labels and TrajectoryShield.

    This serves as a proxy for inter-annotator agreement:
    - "Annotator 1" = human/LLM label (ground truth)
    - "Annotator 2" = TrajectoryShield (automated detector)

    Reports Cohen's kappa on binary (deceptive vs honest) classification.
    """
    from trajectoryshield.trajectory_shield.shield import TrajectoryShield

    shield = TrajectoryShield(enable_layer3=False)

    # Binary: deceptive or not
    gt_labels = []
    pred_labels = []

    for t in dataset.trajectories:
        gt = 1 if t.is_deceptive else 0
        verdict = shield.evaluate(t)
        pred = 1 if verdict.detected else 0
        gt_labels.append(gt)
        pred_labels.append(pred)

    # Confusion matrix
    tp = sum(1 for g, p in zip(gt_labels, pred_labels) if g == 1 and p == 1)
    fp = sum(1 for g, p in zip(gt_labels, pred_labels) if g == 0 and p == 1)
    tn = sum(1 for g, p in zip(gt_labels, pred_labels) if g == 0 and p == 0)
    fn = sum(1 for g, p in zip(gt_labels, pred_labels) if g == 1 and p == 0)

    total = len(gt_labels)
    accuracy = (tp + tn) / total if total > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    # Cohen's kappa
    p_o = accuracy  # observed agreement
    p_yes = ((tp + fp) / total) * ((tp + fn) / total) if total > 0 else 0
    p_no = ((tn + fn) / total) * ((tn + fp) / total) if total > 0 else 0
    p_e = p_yes + p_no  # expected agreement by chance
    kappa = (p_o - p_e) / (1 - p_e) if (1 - p_e) > 0 else 0

    # Per deception-type agreement
    by_type = {}
    for t, pred in zip(dataset.trajectories, pred_labels):
        dtype = t.label.deception_type
        if dtype not in by_type:
            by_type[dtype] = {"total": 0, "agreed": 0}
        by_type[dtype]["total"] += 1
        gt = 1 if t.is_deceptive else 0
        if gt == pred:
            by_type[dtype]["agreed"] += 1
    for v in by_type.values():
        v["agreement_rate"] = v["agreed"] / v["total"] if v["total"] > 0 else 0

    # Per source agreement
    by_source = {}
    for t, pred in zip(dataset.trajectories, pred_labels):
        src = t.metadata.source
        if src not in by_source:
            by_source[src] = {"total": 0, "agreed": 0}
        by_source[src]["total"] += 1
        gt = 1 if t.is_deceptive else 0
        if gt == pred:
            by_source[src]["agreed"] += 1
    for v in by_source.values():
        v["agreement_rate"] = v["agreed"] / v["total"] if v["total"] > 0 else 0

    return {
        "confusion_matrix": {"tp": tp, "fp": fp, "tn": tn, "fn": fn},
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "cohens_kappa": kappa,
        "by_deception_type": by_type,
        "by_source": by_source,
    }


# ---------------------------------------------------------------------------
# Full validation
# ---------------------------------------------------------------------------


def validate_dataset(dataset_path: str = "data/deceptive_comply_bench/dataset.json") -> dict:
    """Run all validation checks and return results."""
    path = Path(dataset_path)
    if not path.exists():
        return {"valid": False, "errors": [f"File not found: {dataset_path}"], "stats": {}}

    try:
        dataset = BenchmarkDataset.load(str(path))
    except Exception as e:
        return {"valid": False, "errors": [str(e)], "stats": {}}

    errors = check_schema(dataset)
    distributions = compute_distributions(dataset)
    step_annotations = check_step_annotations(dataset)
    detector_agreement = compute_detector_agreement(dataset)

    return {
        "valid": len(errors) == 0,
        "errors": errors[:20],
        "error_count": len(errors),
        "stats": distributions,
        "step_annotations": step_annotations,
        "detector_agreement": detector_agreement,
    }


# ---------------------------------------------------------------------------
# Pretty-print
# ---------------------------------------------------------------------------


def print_results(result: dict) -> None:
    """Print validation results in thesis-friendly format."""
    print("=" * 70)
    print("DeceptiveComply-Bench Validation Report")
    print("=" * 70)

    print(f"\nSchema valid: {result['valid']}")
    if result.get("errors"):
        print(f"Errors ({result['error_count']} total, showing first 20):")
        for e in result["errors"]:
            print(f"  - {e}")

    s = result.get("stats", {})
    if s:
        print(f"\n--- Dataset Summary ---")
        print(f"  Total trajectories: {s['total']}")
        print(f"  Honest: {s.get('num_honest', 'N/A')}")
        print(f"  Deceptive: {s.get('num_deceptive', 'N/A')}")
        print(f"  Domains: {s['domains']}")
        print(f"  Avg steps: {s['avg_steps']:.1f} (min {s['min_steps']}, max {s['max_steps']})")

        print(f"\n  By deception type:")
        for k, v in sorted(s.get("by_deception_type", {}).items()):
            print(f"    {k}: {v}")
        print(f"\n  By domain:")
        for k, v in sorted(s.get("by_domain", {}).items()):
            print(f"    {k}: {v}")
        print(f"\n  By source:")
        for k, v in sorted(s.get("by_source", {}).items()):
            print(f"    {k}: {v}")
        print(f"\n  Top tools used:")
        for k, v in s.get("top_tools", {}).items():
            print(f"    {k}: {v}")

    sa = result.get("step_annotations", {})
    if sa:
        print(f"\n--- Step-Level Annotation Consistency ---")
        print(f"  Deceptive trajectories: {sa['total_deceptive']}")
        print(f"  All steps individually compliant: {sa['all_steps_compliant']} ({sa['pct_all_steps_compliant']:.1f}%)")
        print(f"  Has non-compliant step: {sa['has_noncompliant_step']}")
        if sa.get("noncompliant_examples"):
            print(f"  Examples with non-compliant steps (first 10): {sa['noncompliant_examples']}")

    da = result.get("detector_agreement", {})
    if da:
        print(f"\n--- Detector Agreement (Label vs TrajectoryShield) ---")
        cm = da.get("confusion_matrix", {})
        print(f"  Confusion matrix: TP={cm.get('tp',0)}, FP={cm.get('fp',0)}, TN={cm.get('tn',0)}, FN={cm.get('fn',0)}")
        print(f"  Accuracy: {da['accuracy']:.3f}")
        print(f"  Precision: {da['precision']:.3f}")
        print(f"  Recall: {da['recall']:.3f}")
        print(f"  F1: {da['f1']:.3f}")
        print(f"  Cohen's kappa: {da['cohens_kappa']:.3f}")

        print(f"\n  Agreement by deception type:")
        for k, v in sorted(da.get("by_deception_type", {}).items()):
            print(f"    {k}: {v['agreed']}/{v['total']} ({v['agreement_rate']:.1%})")

        print(f"\n  Agreement by source:")
        for k, v in sorted(da.get("by_source", {}).items()):
            print(f"    {k}: {v['agreed']}/{v['total']} ({v['agreement_rate']:.1%})")

    print()


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(description="Validate DeceptiveComply-Bench dataset")
    parser.add_argument("--dataset", default="data/deceptive_comply_bench/dataset.json")
    parser.add_argument("--save", default=None, help="Save results JSON to this path")
    args = parser.parse_args()

    result = validate_dataset(args.dataset)
    print_results(result)

    if args.save:
        out = Path(args.save)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2, default=str)
        print(f"Results saved to {args.save}")


if __name__ == "__main__":
    main()
