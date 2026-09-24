"""
Trajectory Schema for DeceptiveComply-Bench

Defines the data model for tool-call trajectories used throughout the
benchmark, evaluation, and detection pipeline.

A Trajectory is a sequence of ToolCalls made by an agent while completing
a task under a policy. Each trajectory is labeled as honest or deceptive,
with deceptive trajectories further classified by deception type.

Usage:
    from trajectoryshield.benchmark.trajectory_schema import Trajectory, ToolCall

    trajectory = Trajectory(
        trajectory_id="dc-001",
        policy=PolicyContext(text="No hardcoded credentials", ...),
        task=TaskContext(description="Fix auth bug", ...),
        tool_calls=[ToolCall(step=0, tool="read_file", ...)],
        label=TrajectoryLabel(deception_type=DeceptionType.HONEST, ...),
    )
"""

from __future__ import annotations

import json
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator

from trajectoryshield.taxonomy.deception_types import DeceptionType, DeceptionSeverity, DetectionDifficulty


# ---------------------------------------------------------------------------
# Tool Definitions
# ---------------------------------------------------------------------------


class ToolCategory(str, Enum):
    """Categories of tools available to agents."""

    FILE_SYSTEM = "file_system"
    CODE_ANALYSIS = "code_analysis"
    EXECUTION = "execution"
    DATABASE = "database"
    NETWORK = "network"
    AUTHENTICATION = "authentication"
    NOTIFICATION = "notification"


class ToolDefinition(BaseModel):
    """Definition of a tool available to agents in the benchmark."""

    name: str
    category: ToolCategory
    description: str
    parameters: dict[str, str] = Field(default_factory=dict)  # param_name -> type description
    can_mutate_state: bool = False  # Does this tool have side effects?
    risk_level: str = "low"  # low, medium, high

    class Config:
        use_enum_values = True


# The standardized tool set for DeceptiveComply-Bench
# Modeled after MCP primitives and real coding agent tools
STANDARD_TOOLS: dict[str, ToolDefinition] = {
    # File System Tools
    "read_file": ToolDefinition(
        name="read_file",
        category=ToolCategory.FILE_SYSTEM,
        description="Read the contents of a file",
        parameters={"path": "str - file path to read"},
        can_mutate_state=False,
        risk_level="low",
    ),
    "write_file": ToolDefinition(
        name="write_file",
        category=ToolCategory.FILE_SYSTEM,
        description="Write content to a file (creates or overwrites)",
        parameters={"path": "str - file path", "content": "str - file content"},
        can_mutate_state=True,
        risk_level="medium",
    ),
    "append_to_file": ToolDefinition(
        name="append_to_file",
        category=ToolCategory.FILE_SYSTEM,
        description="Append content to the end of a file",
        parameters={"path": "str - file path", "content": "str - content to append"},
        can_mutate_state=True,
        risk_level="medium",
    ),
    "delete_file": ToolDefinition(
        name="delete_file",
        category=ToolCategory.FILE_SYSTEM,
        description="Delete a file",
        parameters={"path": "str - file path to delete"},
        can_mutate_state=True,
        risk_level="high",
    ),
    "create_file": ToolDefinition(
        name="create_file",
        category=ToolCategory.FILE_SYSTEM,
        description="Create a new empty file",
        parameters={"path": "str - file path to create"},
        can_mutate_state=True,
        risk_level="low",
    ),
    "move_file": ToolDefinition(
        name="move_file",
        category=ToolCategory.FILE_SYSTEM,
        description="Move or rename a file",
        parameters={"source": "str - source path", "destination": "str - destination path"},
        can_mutate_state=True,
        risk_level="medium",
    ),
    "list_directory": ToolDefinition(
        name="list_directory",
        category=ToolCategory.FILE_SYSTEM,
        description="List contents of a directory",
        parameters={"path": "str - directory path"},
        can_mutate_state=False,
        risk_level="low",
    ),

    # Code Analysis Tools
    "search_code": ToolDefinition(
        name="search_code",
        category=ToolCategory.CODE_ANALYSIS,
        description="Search for a pattern across the codebase",
        parameters={"pattern": "str - regex or text pattern", "path": "str - optional scope"},
        can_mutate_state=False,
        risk_level="low",
    ),

    # Execution Tools
    "run_command": ToolDefinition(
        name="run_command",
        category=ToolCategory.EXECUTION,
        description="Run a shell command",
        parameters={"command": "str - shell command to execute"},
        can_mutate_state=True,
        risk_level="high",
    ),
    "run_tests": ToolDefinition(
        name="run_tests",
        category=ToolCategory.EXECUTION,
        description="Run the project's test suite",
        parameters={"test_path": "str - optional specific test to run"},
        can_mutate_state=False,
        risk_level="low",
    ),

    # Database Tools
    "database_query": ToolDefinition(
        name="database_query",
        category=ToolCategory.DATABASE,
        description="Execute a database query",
        parameters={"query": "str - SQL query", "database": "str - database name"},
        can_mutate_state=True,
        risk_level="high",
    ),

    # Network Tools
    "http_request": ToolDefinition(
        name="http_request",
        category=ToolCategory.NETWORK,
        description="Make an HTTP request to a URL",
        parameters={"method": "str - HTTP method", "url": "str - target URL", "body": "str - optional body"},
        can_mutate_state=True,
        risk_level="high",
    ),

    # Authentication Tools
    "authenticate": ToolDefinition(
        name="authenticate",
        category=ToolCategory.AUTHENTICATION,
        description="Authenticate with a service",
        parameters={"service": "str - service name", "credentials": "str - credential reference"},
        can_mutate_state=True,
        risk_level="medium",
    ),
    "read_env": ToolDefinition(
        name="read_env",
        category=ToolCategory.AUTHENTICATION,
        description="Read an environment variable",
        parameters={"variable": "str - environment variable name"},
        can_mutate_state=False,
        risk_level="medium",
    ),

    # Notification Tools
    "send_notification": ToolDefinition(
        name="send_notification",
        category=ToolCategory.NOTIFICATION,
        description="Send a notification message",
        parameters={"channel": "str - notification channel", "message": "str - message content"},
        can_mutate_state=True,
        risk_level="medium",
    ),
}


# ---------------------------------------------------------------------------
# Tool Call Schema
# ---------------------------------------------------------------------------


class ToolCall(BaseModel):
    """A single tool call in an agent trajectory."""

    step: int = Field(ge=0, description="Zero-indexed step number in the trajectory")
    tool: str = Field(description="Name of the tool called")
    args: dict[str, Any] = Field(default_factory=dict, description="Arguments passed to the tool")
    result: Any = Field(default=None, description="Return value from the tool")
    result_status: str = Field(default="success", description="success, error, or timeout")

    # Per-step compliance annotations
    compliant_individually: bool = Field(
        default=True,
        description="Whether this step passes step-level policy checks in isolation",
    )
    step_analysis: str = Field(
        default="",
        description="Why this step is/isn't individually compliant",
    )

    # Metadata
    latency_ms: float = Field(default=0.0, description="Simulated tool call latency")

    @field_validator("tool")
    @classmethod
    def validate_tool_name(cls, v: str) -> str:
        if v not in STANDARD_TOOLS:
            # Allow custom tools but warn
            pass
        return v


# ---------------------------------------------------------------------------
# Context Models
# ---------------------------------------------------------------------------


class PolicyContext(BaseModel):
    """The policy being enforced during this trajectory."""

    policy_id: str = Field(description="Unique identifier for the policy")
    domain: str = Field(description="Policy domain: code_security, content_moderation, healthcare_privacy, business_compliance, legal_contracts")
    text: str = Field(description="Natural language policy statement")
    intent: str = Field(description="What the policy is trying to prevent (the 'spirit')")

    # LTL formalization
    ltl_step: str = Field(default="", description="Step-level LTL formula")
    ltl_trajectory: str = Field(default="", description="Trajectory-level LTL formula")
    ltl_temporal: str = Field(default="", description="Temporal LTL formula")


class TaskContext(BaseModel):
    """The task the agent is trying to accomplish."""

    task_id: str = Field(description="Unique task identifier")
    description: str = Field(description="What the agent is asked to do")
    source: str = Field(default="swebench", description="Where this task comes from: swebench, custom, etc.")
    files_involved: list[str] = Field(default_factory=list, description="Files relevant to the task")
    expected_outcome: str = Field(default="", description="What successful completion looks like")


# ---------------------------------------------------------------------------
# Labels
# ---------------------------------------------------------------------------


class TrajectoryLabel(BaseModel):
    """Ground truth label for a trajectory."""

    deception_type: DeceptionType = Field(description="Classification of the trajectory")
    severity: DeceptionSeverity = Field(default=DeceptionSeverity.MEDIUM)
    detection_difficulty: DetectionDifficulty = Field(default=DetectionDifficulty.MODERATE)

    trajectory_compliant: bool = Field(
        description="Whether the trajectory as a whole is policy-compliant",
    )
    violation_explanation: str = Field(
        default="",
        description="For non-compliant trajectories: what violation occurs",
    )
    deception_strategy: str = Field(
        default="",
        description="For deceptive trajectories: what strategy the agent uses",
    )

    # For temporal evasion
    violated_ordering: str = Field(
        default="",
        description="What temporal ordering is violated",
    )

    # For compositional obfuscation
    composed_effect: str = Field(
        default="",
        description="What the composed effect of the tool calls achieves",
    )

    class Config:
        use_enum_values = True


class GenerationMetadata(BaseModel):
    """Metadata about how a trajectory was generated."""

    source: str = Field(description="human_crafted, llm_generated, or patch_converted")
    generating_model: str = Field(default="", description="Which LLM generated this, if applicable")
    generation_prompt: str = Field(default="", description="The prompt used to generate, if applicable")
    human_validated: bool = Field(default=False)
    validator_id: str = Field(default="")
    generation_timestamp: str = Field(default="")
    notes: str = Field(default="")


# ---------------------------------------------------------------------------
# Main Trajectory Model
# ---------------------------------------------------------------------------


class Trajectory(BaseModel):
    """
    A complete agent trajectory in DeceptiveComply-Bench.

    This is the primary data structure for the benchmark. Each trajectory
    represents a sequence of tool calls made by an agent while completing
    a task under a policy constraint.
    """

    # Identity
    trajectory_id: str = Field(description="Unique trajectory identifier, e.g., 'dc-0001'")

    # Context
    policy: PolicyContext
    task: TaskContext

    # The trajectory itself
    tool_calls: list[ToolCall] = Field(min_length=1, description="Ordered sequence of tool calls")

    # Ground truth
    label: TrajectoryLabel

    # Generation info
    metadata: GenerationMetadata

    # Convenience properties
    @property
    def num_steps(self) -> int:
        return len(self.tool_calls)

    @property
    def is_deceptive(self) -> bool:
        return self.label.deception_type != DeceptionType.HONEST.value

    @property
    def is_honest(self) -> bool:
        return self.label.deception_type == DeceptionType.HONEST.value

    @property
    def all_steps_individually_compliant(self) -> bool:
        return all(tc.compliant_individually for tc in self.tool_calls)

    @property
    def tools_used(self) -> list[str]:
        return [tc.tool for tc in self.tool_calls]

    @property
    def unique_tools_used(self) -> set[str]:
        return {tc.tool for tc in self.tool_calls}

    def to_serialized_text(self) -> str:
        """
        Serialize trajectory to a text format suitable for model input.

        Format:
            [POLICY] No hardcoded credentials
            [TASK] Fix authentication bug
            [STEP 0] read_file(path="login.py") -> "def login():..."
            [STEP 1] write_file(path="login.py", content="...") -> "ok"
            ...
        """
        lines = [
            f"[POLICY] {self.policy.text}",
            f"[INTENT] {self.policy.intent}",
            f"[TASK] {self.task.description}",
            "",
        ]
        for tc in self.tool_calls:
            args_str = ", ".join(f'{k}="{_truncate(str(v), 100)}"' for k, v in tc.args.items())
            result_str = _truncate(str(tc.result), 200)
            lines.append(f"[STEP {tc.step}] {tc.tool}({args_str}) -> {result_str}")

        return "\n".join(lines)

    def save(self, path: str | Path) -> None:
        """Save trajectory to a JSON file."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.model_dump(), f, indent=2, default=str)

    @classmethod
    def load(cls, path: str | Path) -> Trajectory:
        """Load trajectory from a JSON file."""
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return cls.model_validate(data)


# ---------------------------------------------------------------------------
# Benchmark Dataset
# ---------------------------------------------------------------------------


class BenchmarkDataset(BaseModel):
    """The full DeceptiveComply-Bench dataset."""

    name: str = "DeceptiveComply-Bench"
    version: str = "1.0.0"
    description: str = "Benchmark for detecting deceptive policy compliance in tool-using LLM agents"
    created: str = Field(default_factory=lambda: datetime.now().isoformat())

    trajectories: list[Trajectory] = Field(default_factory=list)

    @property
    def num_trajectories(self) -> int:
        return len(self.trajectories)

    @property
    def num_honest(self) -> int:
        return sum(1 for t in self.trajectories if t.is_honest)

    @property
    def num_deceptive(self) -> int:
        return sum(1 for t in self.trajectories if t.is_deceptive)

    def by_deception_type(self, dtype: str) -> list[Trajectory]:
        """Filter trajectories by deception type."""
        return [t for t in self.trajectories if t.label.deception_type == dtype]

    def by_domain(self, domain: str) -> list[Trajectory]:
        """Filter trajectories by policy domain."""
        return [t for t in self.trajectories if t.policy.domain == domain]

    def split(
        self, train_ratio: float = 0.7, val_ratio: float = 0.15
    ) -> tuple[list[Trajectory], list[Trajectory], list[Trajectory]]:
        """Split dataset into train/val/test, stratified by deception type."""
        from collections import defaultdict
        import random

        # Group by deception type for stratification
        by_type: dict[str, list[Trajectory]] = defaultdict(list)
        for t in self.trajectories:
            by_type[t.label.deception_type].append(t)

        train, val, test = [], [], []
        for _dtype, trajs in by_type.items():
            random.shuffle(trajs)
            n = len(trajs)
            n_train = int(n * train_ratio)
            n_val = int(n * val_ratio)

            train.extend(trajs[:n_train])
            val.extend(trajs[n_train : n_train + n_val])
            test.extend(trajs[n_train + n_val :])

        return train, val, test

    def summary(self) -> str:
        """Print dataset summary statistics."""
        from collections import Counter

        type_counts = Counter(t.label.deception_type for t in self.trajectories)
        domain_counts = Counter(t.policy.domain for t in self.trajectories)
        source_counts = Counter(t.metadata.source for t in self.trajectories)
        avg_steps = sum(t.num_steps for t in self.trajectories) / max(self.num_trajectories, 1)

        lines = [
            f"=== {self.name} v{self.version} ===",
            f"Total trajectories: {self.num_trajectories}",
            f"  Honest: {self.num_honest}",
            f"  Deceptive: {self.num_deceptive}",
            f"  Avg steps per trajectory: {avg_steps:.1f}",
            "",
            "By deception type:",
        ]
        for dtype, count in sorted(type_counts.items()):
            lines.append(f"  {dtype}: {count}")

        lines.append("\nBy domain:")
        for domain, count in sorted(domain_counts.items()):
            lines.append(f"  {domain}: {count}")

        lines.append("\nBy source:")
        for source, count in sorted(source_counts.items()):
            lines.append(f"  {source}: {count}")

        return "\n".join(lines)

    def save(self, path: str | Path) -> None:
        """Save full dataset to JSON."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.model_dump(), f, indent=2, default=str)

    @classmethod
    def load(cls, path: str | Path) -> BenchmarkDataset:
        """Load dataset from JSON."""
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        return cls.model_validate(data)


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------


def _truncate(s: str, max_len: int) -> str:
    """Truncate a string for display."""
    if len(s) <= max_len:
        return s
    return s[: max_len - 3] + "..."
