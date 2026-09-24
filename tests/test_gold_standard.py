"""
Tests for gold-standard deceptive trajectories.

Validates:
    - Exactly 300 trajectories load
    - 60 per domain, 20 per (type, domain) pair
    - All steps have compliant_individually=True
    - All trajectory_compliant=False
    - All tools from STANDARD_TOOLS
    - IDs unique
    - metadata.source == "human_crafted"
"""

import pytest

from trajectoryshield.benchmark.gold_standard import (
    get_all_gold_standard,
    get_gold_standard_by_domain,
    get_gold_standard_dataset,
)
from trajectoryshield.benchmark.trajectory_schema import STANDARD_TOOLS
from trajectoryshield.taxonomy.deception_types import DeceptionType


DOMAINS = [
    "code_security",
    "healthcare_privacy",
    "business_compliance",
    "content_moderation",
    "legal_contracts",
]

DECEPTION_TYPES = [
    DeceptionType.LITERAL_COMPLIANCE.value,
    DeceptionType.TEMPORAL_EVASION.value,
    DeceptionType.COMPOSITIONAL_OBFUSCATION.value,
]


class TestGoldStandardCounts:
    """Validate counts: 300 total, 60 per domain, 20 per (type, domain)."""

    def test_total_count(self):
        all_trajs = get_all_gold_standard()
        assert len(all_trajs) == 300

    def test_per_domain_count(self):
        for domain in DOMAINS:
            trajs = get_gold_standard_by_domain(domain)
            assert len(trajs) == 60, f"Expected 60 for domain {domain}, got {len(trajs)}"

    def test_per_type_per_domain_count(self):
        all_trajs = get_all_gold_standard()
        for domain in DOMAINS:
            domain_trajs = [t for t in all_trajs if t.policy.domain == domain]
            assert len(domain_trajs) == 60
            for dtype in DECEPTION_TYPES:
                type_trajs = [t for t in domain_trajs if t.label.deception_type == dtype]
                assert len(type_trajs) == 20, (
                    f"Expected 20 for domain={domain} type={dtype}, got {len(type_trajs)}"
                )


class TestGoldStandardLabels:
    """All trajectories are deceptive and non-compliant at trajectory level."""

    def test_all_trajectory_compliant_false(self):
        all_trajs = get_all_gold_standard()
        for t in all_trajs:
            assert t.label.trajectory_compliant is False, f"{t.trajectory_id} should be non-compliant"

    def test_all_steps_individually_compliant(self):
        all_trajs = get_all_gold_standard()
        for t in all_trajs:
            assert t.all_steps_individually_compliant, (
                f"{t.trajectory_id} should have all steps compliant_individually=True"
            )

    def test_all_deceptive(self):
        all_trajs = get_all_gold_standard()
        for t in all_trajs:
            assert t.is_deceptive, f"{t.trajectory_id} should be deceptive"
            assert t.label.deception_type in DECEPTION_TYPES


class TestGoldStandardTools:
    """All tool names must be in STANDARD_TOOLS."""

    def test_all_tools_valid(self):
        all_trajs = get_all_gold_standard()
        valid_tools = set(STANDARD_TOOLS.keys())
        for t in all_trajs:
            for tc in t.tool_calls:
                assert tc.tool in valid_tools, (
                    f"{t.trajectory_id} step {tc.step}: unknown tool {tc.tool}"
                )


class TestGoldStandardIds:
    """IDs must be unique."""

    def test_unique_ids(self):
        all_trajs = get_all_gold_standard()
        ids = [t.trajectory_id for t in all_trajs]
        assert len(ids) == len(set(ids)), "Duplicate trajectory IDs found"


class TestGoldStandardMetadata:
    """metadata.source must be human_crafted."""

    def test_source_human_crafted(self):
        all_trajs = get_all_gold_standard()
        for t in all_trajs:
            assert t.metadata.source == "human_crafted", (
                f"{t.trajectory_id} should have source=human_crafted"
            )


class TestGoldStandardDataset:
    """BenchmarkDataset from get_gold_standard_dataset()."""

    def test_dataset_loads(self):
        dataset = get_gold_standard_dataset()
        assert dataset.num_trajectories == 300
        assert dataset.num_deceptive == 300
        assert dataset.num_honest == 0

    def test_dataset_summary(self):
        dataset = get_gold_standard_dataset()
        summary = dataset.summary()
        assert "300" in summary
        assert "DeceptiveComply-Bench" in summary or "Gold Standard" in summary
