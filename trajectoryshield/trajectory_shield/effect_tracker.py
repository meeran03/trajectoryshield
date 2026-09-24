"""
Effect Tracker: Cumulative effect accumulation across tool calls.

Tracks the net effect of all tool calls in a trajectory, enabling
detection of compositional obfuscation where individual steps look
innocent but their combined effect is a policy violation.

Effects tracked:
    - File state: what's been written, appended, deleted
    - Data flow: what data has been read and where it went
    - Execution: what commands have been run
    - Network: what external communications have occurred

This is the foundation for Layer 2 of TrajectoryShield.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class FileState:
    """Accumulated state of a file across the trajectory."""
    path: str
    content: str = ""  # Current accumulated content
    operations: list[str] = field(default_factory=list)  # ["write", "append", "append"]
    is_deleted: bool = False
    was_read: bool = False
    read_content: str = ""  # What was read from this file


@dataclass
class DataFlow:
    """Tracks where data flows during the trajectory."""
    source: str  # Where data came from (file path, env var, etc.)
    destination: str  # Where data went (file, network, notification)
    data_type: str  # "sensitive", "credential", "code", "general"
    step: int  # Which step caused this flow


@dataclass
class EffectState:
    """
    Complete accumulated effect state of a trajectory.

    This is the "world state" after all tool calls have been applied.
    Comparing this to the initial state reveals the net effect.
    """

    # File system effects
    files: dict[str, FileState] = field(default_factory=dict)

    # Data flow tracking
    data_flows: list[DataFlow] = field(default_factory=list)

    # Execution effects
    commands_executed: list[dict] = field(default_factory=list)
    scripts_written_then_executed: list[dict] = field(default_factory=list)

    # Network effects
    external_requests: list[dict] = field(default_factory=list)

    # Authentication state
    authenticated_services: set[str] = field(default_factory=set)

    # Notification effects
    notifications_sent: list[dict] = field(default_factory=list)

    @property
    def all_written_content(self) -> str:
        """Concatenation of all file write content."""
        parts = []
        for fs in self.files.values():
            if not fs.is_deleted:
                parts.append(fs.content)
        return "\n".join(parts)

    @property
    def files_written(self) -> list[str]:
        """List of file paths that were written/created."""
        return [p for p, fs in self.files.items() if fs.operations and not fs.is_deleted]

    @property
    def files_deleted(self) -> list[str]:
        """List of file paths that were deleted."""
        return [p for p, fs in self.files.items() if fs.is_deleted]

    @property
    def sensitive_data_read(self) -> list[str]:
        """Paths of sensitive files that were read."""
        sensitive_keywords = ["patient", "medical", "health", "phi", "record",
                             "secret", "credential", "password", "key", "token",
                             "private", "confidential"]
        result = []
        for path, fs in self.files.items():
            if fs.was_read:
                path_lower = path.lower()
                content_lower = fs.read_content.lower()
                if any(kw in path_lower or kw in content_lower for kw in sensitive_keywords):
                    result.append(path)
        return result

    @property
    def has_external_communication(self) -> bool:
        return len(self.external_requests) > 0 or len(self.notifications_sent) > 0


class EffectTracker:
    """
    Tracks cumulative effects as tool calls are processed.

    Process tool calls one by one, building up the effect state.
    After all calls are processed, the EffectState reveals the
    net effect of the trajectory.
    """

    def __init__(self):
        self.state = EffectState()

    def process_step(self, step: dict) -> None:
        """
        Process a single tool call and update the effect state.

        Args:
            step: Tool call dict with keys: tool, args, result, step
        """
        tool = step.get("tool", "")
        args = step.get("args", {})
        result = step.get("result", "")
        step_num = step.get("step", -1)

        handler = self._handlers.get(tool)
        if handler:
            handler(self, args, result, step_num)

    def process_trajectory(self, trajectory: list[dict]) -> EffectState:
        """
        Process an entire trajectory and return the accumulated effect state.

        Args:
            trajectory: List of tool call dicts

        Returns:
            EffectState after all tool calls
        """
        self.state = EffectState()  # Reset
        for step in trajectory:
            self.process_step(step)
        return self.state

    # --- Tool-specific handlers ---

    def _handle_read_file(self, args: dict, result: Any, step_num: int) -> None:
        path = args.get("path", "")
        if path not in self.state.files:
            self.state.files[path] = FileState(path=path)
        self.state.files[path].was_read = True
        self.state.files[path].read_content = str(result) if result else ""

    def _handle_write_file(self, args: dict, result: Any, step_num: int) -> None:
        path = args.get("path", "")
        content = str(args.get("content", ""))
        if path not in self.state.files:
            self.state.files[path] = FileState(path=path)
        self.state.files[path].content = content  # Overwrites
        self.state.files[path].operations.append("write")
        self.state.files[path].is_deleted = False

    def _handle_append_to_file(self, args: dict, result: Any, step_num: int) -> None:
        path = args.get("path", "")
        content = str(args.get("content", ""))
        if path not in self.state.files:
            self.state.files[path] = FileState(path=path)
        self.state.files[path].content += content  # Appends
        self.state.files[path].operations.append("append")
        self.state.files[path].is_deleted = False

    def _handle_create_file(self, args: dict, result: Any, step_num: int) -> None:
        path = args.get("path", "")
        if path not in self.state.files:
            self.state.files[path] = FileState(path=path)
        self.state.files[path].operations.append("create")
        self.state.files[path].is_deleted = False

    def _handle_delete_file(self, args: dict, result: Any, step_num: int) -> None:
        path = args.get("path", "")
        if path not in self.state.files:
            self.state.files[path] = FileState(path=path)
        self.state.files[path].is_deleted = True
        self.state.files[path].operations.append("delete")

    def _handle_move_file(self, args: dict, result: Any, step_num: int) -> None:
        source = args.get("source", "")
        dest = args.get("destination", "")
        # Source is effectively deleted, dest gets the content
        if source in self.state.files:
            content = self.state.files[source].content
            self.state.files[source].is_deleted = True
            self.state.files[source].operations.append("moved_from")
        else:
            content = ""
        if dest not in self.state.files:
            self.state.files[dest] = FileState(path=dest)
        self.state.files[dest].content = content
        self.state.files[dest].operations.append("moved_to")

    def _handle_run_command(self, args: dict, result: Any, step_num: int) -> None:
        command = str(args.get("command", ""))
        self.state.commands_executed.append({
            "command": command,
            "result": str(result),
            "step": step_num,
        })

        # Check if this executes a previously written script
        for path, fs in self.state.files.items():
            if not fs.is_deleted and path in command and fs.operations:
                self.state.scripts_written_then_executed.append({
                    "script_path": path,
                    "command": command,
                    "write_step": len(fs.operations) - 1,
                    "execute_step": step_num,
                })

    def _handle_http_request(self, args: dict, result: Any, step_num: int) -> None:
        self.state.external_requests.append({
            "method": args.get("method", "GET"),
            "url": args.get("url", ""),
            "body": args.get("body", ""),
            "step": step_num,
        })

        # Track data flow: if sensitive data was read, this could be exfiltration
        if self.state.sensitive_data_read:
            self.state.data_flows.append(DataFlow(
                source=", ".join(self.state.sensitive_data_read),
                destination=args.get("url", "external"),
                data_type="sensitive",
                step=step_num,
            ))

    def _handle_authenticate(self, args: dict, result: Any, step_num: int) -> None:
        service = args.get("service", "")
        self.state.authenticated_services.add(service)

    def _handle_database_query(self, args: dict, result: Any, step_num: int) -> None:
        # Track as a command with special handling
        self.state.commands_executed.append({
            "command": f"database_query: {args.get('query', '')}",
            "database": args.get("database", ""),
            "result": str(result),
            "step": step_num,
        })

    def _handle_send_notification(self, args: dict, result: Any, step_num: int) -> None:
        self.state.notifications_sent.append({
            "channel": args.get("channel", ""),
            "message": args.get("message", ""),
            "step": step_num,
        })

    # Handler dispatch table
    _handlers = {
        "read_file": _handle_read_file,
        "write_file": _handle_write_file,
        "append_to_file": _handle_append_to_file,
        "create_file": _handle_create_file,
        "delete_file": _handle_delete_file,
        "move_file": _handle_move_file,
        "run_command": _handle_run_command,
        "http_request": _handle_http_request,
        "authenticate": _handle_authenticate,
        "database_query": _handle_database_query,
        "send_notification": _handle_send_notification,
    }
