"""
Gold-standard deceptive trajectories for DeceptiveComply-Bench.

300 hand-crafted trajectories: 20 per deception type per domain.
- code_security: 60 (CS-001, CS-002, CS-003)
- healthcare_privacy: 60 (HP-001)
- business_compliance: 60 (BC-001)
- content_moderation: 60 (CM-001)
- legal_contracts: 60 (LC-001)

Usage:
    from trajectoryshield.benchmark.gold_standard import get_all_gold_standard, get_gold_standard_by_domain

    all_trajectories = get_all_gold_standard()
    code_sec = get_gold_standard_by_domain("code_security")
"""

from __future__ import annotations

from trajectoryshield.benchmark.trajectory_schema import Trajectory, BenchmarkDataset, STANDARD_TOOLS
from trajectoryshield.benchmark.gold_standard.code_security import get_all_code_security
from trajectoryshield.benchmark.gold_standard.healthcare_privacy import get_all_healthcare
from trajectoryshield.benchmark.gold_standard.business_compliance import get_all_business
from trajectoryshield.benchmark.gold_standard.content_moderation import get_all_content
from trajectoryshield.benchmark.gold_standard.legal_contracts import get_all_legal


def get_all_gold_standard() -> list[Trajectory]:
    """Return all 300 gold-standard deceptive trajectories."""
    return (
        get_all_code_security()
        + get_all_healthcare()
        + get_all_business()
        + get_all_content()
        + get_all_legal()
    )


def get_gold_standard_by_domain(domain: str) -> list[Trajectory]:
    """Return gold-standard trajectories for a single domain."""
    if domain == "code_security":
        return get_all_code_security()
    if domain == "healthcare_privacy":
        return get_all_healthcare()
    if domain == "business_compliance":
        return get_all_business()
    if domain == "content_moderation":
        return get_all_content()
    if domain == "legal_contracts":
        return get_all_legal()
    raise ValueError(f"Unknown domain: {domain}")


def get_gold_standard_dataset() -> BenchmarkDataset:
    """Return a BenchmarkDataset containing all 300 gold-standard trajectories."""
    trajectories = get_all_gold_standard()
    return BenchmarkDataset(
        name="DeceptiveComply-Bench Gold Standard",
        version="1.0.0",
        description="300 human-crafted gold-standard deceptive trajectories (20 per type per domain)",
        trajectories=trajectories,
    )


__all__ = [
    "get_all_gold_standard",
    "get_gold_standard_by_domain",
    "get_gold_standard_dataset",
]
