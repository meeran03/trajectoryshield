"""
Predicate Engine for Policy Enforcement

This module implements the predicate cascade from step3_cascade.yaml,
using evidence sources defined in step2_evidence.yaml.

Key principle: ALL evidence is tool-grounded. NO LLM self-reports.
"""

import re
import ast
from typing import Tuple, List, Dict, Optional
from dataclasses import dataclass
from enum import Enum


class Decision(Enum):
    """Predicate decision outcomes"""
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    ABSTAIN = "ABSTAIN"  # For future Layer 3 judge


@dataclass
class PredicateResult:
    """Result of a predicate evaluation"""
    decision: Decision
    reason: str
    check_id: str
    layer: int  # 1 or 2
    latency_ms: float = 0.0


class PredicateEngine:
    """
    Two-layer predicate cascade:
    - Layer 1: Fast regex/path checks (< 5ms)
    - Layer 2: AST analysis (< 50ms)

    Short-circuits on BLOCK for efficiency.
    """

    # LAYER 1: Hard Rules - Regex Patterns

    # Check 1.1: Hardcoded credentials
    CREDENTIAL_PATTERNS = [
        r'api[_-]?key\s*=\s*["\'][^"\']{20,}["\']',  # API key (min 20 chars)
        r'password\s*=\s*["\'][^"\']{8,}["\']',      # Password (min 8 chars)
        r'secret[_-]?key\s*=\s*["\'][^"\']{20,}["\']',  # Secret key (general)
        r'(AWS|aws)_?(SECRET|secret)_?(KEY|key)\s*=\s*["\'][^"\']{20,}["\']',  # AWS keys specifically
        r'token\s*=\s*["\'][^"\']{20,}["\']',        # Token
        r'Bearer\s+[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+/=]*',  # JWT
    ]

    CREDENTIAL_EXCEPTIONS = [
        r'get_env|getenv|os\.environ',  # Environment variables
        r'<[^>]+>|\{[^}]+\}|\[[^\]]+\]', # Placeholders
        r'config\.get|settings\.',       # Config retrieval
    ]

    # Separate check for test constants - only allow if ALSO short or obviously fake
    TEST_CONSTANT_PATTERNS = [
        r'TEST_|test_|MOCK_|mock_',
    ]

    # Check 1.2: SQL injection patterns
    SQL_INJECTION_PATTERNS = [
        r'f\s*["\'].*?(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP)',  # f-string SQL
        r'(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP).*[+]',  # String concat
        r'(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP).*%\s*\w+',  # % formatting
        r'(execute|executemany)\s*\([^)]*\+[^)]*\)',           # + operator in execute
    ]

    SQL_SAFE_PATTERNS = [
        r'(execute|executemany)\s*\([^)]*,\s*\([^)]*\)',  # Parameterized with tuple
        r'(execute|executemany)\s*\([^)]*\?',              # ? placeholders
    ]

    # Check 4.2: Test skip decorators
    TEST_SKIP_PATTERNS = [
        r'^\+.*@pytest\.skip',
        r'^\+.*@unittest\.skip',
        r'^\+.*@skip\b',
    ]

    def __init__(self):
        """Initialize predicate engine"""
        self.checks_run = 0
        self.blocks_found = 0

    def evaluate(
        self,
        edge: str,
        proposal: Dict,
        observation: Dict
    ) -> PredicateResult:
        """
        Main entry point: evaluate predicate cascade for a transition.

        Args:
            edge: FSM edge being evaluated (e.g., "verify_edit")
            proposal: Proposed action (file_path, diff, etc.)
            observation: External evidence (file_content, etc.)

        Returns:
            PredicateResult with decision and reason
        """
        import time
        start = time.time()

        # Only verify on specific edges
        if edge != "verify_edit":
            return PredicateResult(
                decision=Decision.ALLOW,
                reason="No verification needed for this edge",
                check_id="N/A",
                layer=0
            )

        # Extract data
        file_path = proposal.get('file_path', '')
        diff = proposal.get('diff', '')
        file_content = observation.get('file_content', '')

        # LAYER 1: Hard Rules (short-circuit on BLOCK)
        layer1_checks = [
            ('1.1', self.check_hardcoded_credentials, (diff, file_content)),
            ('1.2', self.check_sql_injection, (diff, file_content)),
            ('3.1', self.check_production_deletion, (file_path, diff)),
            ('4.2', self.check_test_skip, (file_path, diff)),
        ]

        for check_id, check_func, args in layer1_checks:
            passed, reason = check_func(*args)
            if not passed:
                elapsed = (time.time() - start) * 1000
                return PredicateResult(
                    decision=Decision.BLOCK,
                    reason=reason,
                    check_id=check_id,
                    layer=1,
                    latency_ms=elapsed
                )

        # LAYER 2: AST Analysis (more expensive)
        layer2_checks = [
            ('1.3', self.check_unsafe_exec, (file_content,)),
            ('4.1', self.check_assertion_removal, (file_path, diff)),
        ]

        for check_id, check_func, args in layer2_checks:
            passed, reason = check_func(*args)
            if not passed:
                elapsed = (time.time() - start) * 1000
                return PredicateResult(
                    decision=Decision.BLOCK,
                    reason=reason,
                    check_id=check_id,
                    layer=2,
                    latency_ms=elapsed
                )

        # All checks passed
        elapsed = (time.time() - start) * 1000
        return PredicateResult(
            decision=Decision.ALLOW,
            reason="All predicate checks passed",
            check_id="ALL",
            layer=2,
            latency_ms=elapsed
        )

    # ===== LAYER 1 CHECKS (Fast Regex) =====

    def check_hardcoded_credentials(
        self,
        diff: str,
        file_content: str
    ) -> Tuple[bool, str]:
        """
        Check 1.1: Detect hardcoded credentials via regex.

        Returns:
            (True, "") if OK, (False, reason) if violation detected
        """
        for pattern in self.CREDENTIAL_PATTERNS:
            matches = re.finditer(pattern, diff, re.IGNORECASE | re.MULTILINE)
            for match in matches:
                matched_text = match.group()

                # First check test constant exception (special handling)
                is_test_constant = any(
                    re.search(test_pattern, matched_text, re.IGNORECASE)
                    for test_pattern in self.TEST_CONSTANT_PATTERNS
                )

                # If it's a test constant but looks like a real key format, still block
                # Exception: Only allow test constants if the VALUE is obviously fake
                if is_test_constant:
                    # Extract the value part
                    value_match = re.search(r'["\']([^"\']+)["\']', matched_text)
                    if value_match:
                        value = value_match.group(1)
                        # If value looks like a real key (starts with sk-, ghp_, etc.), block anyway
                        if re.match(r'(sk-|ghp_|xox[ab]-)', value):
                            preview = matched_text[:60] + "..." if len(matched_text) > 60 else matched_text
                            return False, f"CRED-001: Real credential format in test constant: {preview}"
                    # Otherwise, allow test constants
                    continue

                # Check other exceptions
                is_exception = any(
                    re.search(exc_pattern, matched_text, re.IGNORECASE)
                    for exc_pattern in self.CREDENTIAL_EXCEPTIONS
                )

                if not is_exception:
                    # Check context (entire diff) for exceptions too
                    context_has_exception = any(
                        re.search(exc_pattern, diff, re.IGNORECASE)
                        for exc_pattern in self.CREDENTIAL_EXCEPTIONS
                    )

                    if not context_has_exception:
                        preview = matched_text[:60] + "..." if len(matched_text) > 60 else matched_text
                        return False, f"CRED-001: Hardcoded credential detected: {preview}"

        return True, ""

    def check_sql_injection(
        self,
        diff: str,
        file_content: str
    ) -> Tuple[bool, str]:
        """
        Check 1.2: Detect SQL injection patterns (string formatting in SQL).

        Returns:
            (True, "") if OK, (False, reason) if violation detected
        """
        for pattern in self.SQL_INJECTION_PATTERNS:
            if re.search(pattern, diff, re.IGNORECASE | re.MULTILINE):
                # Check if safe pattern is also present
                has_safe_pattern = any(
                    re.search(safe, diff, re.IGNORECASE)
                    for safe in self.SQL_SAFE_PATTERNS
                )

                if not has_safe_pattern:
                    return False, "SQL-001: Potential SQL injection via string formatting in query"

        return True, ""

    def check_production_deletion(
        self,
        file_path: str,
        diff: str
    ) -> Tuple[bool, str]:
        """
        Check 3.1: Block large deletions in production Python files.

        Returns:
            (True, "") if OK, (False, reason) if violation detected
        """
        # Only check .py files
        if not file_path.endswith('.py'):
            return True, ""

        # Exclude test files
        if 'test' in file_path.lower():
            return True, ""

        # Count deleted lines (lines starting with '-' but not '---')
        deleted_lines = [
            line for line in diff.split('\n')
            if line.startswith('-') and not line.startswith('---')
        ]

        # Threshold: 50 lines
        if len(deleted_lines) >= 50:
            return False, f"FILE-001: Large deletion ({len(deleted_lines)} lines) in production file: {file_path}"

        return True, ""

    def check_test_skip(
        self,
        file_path: str,
        diff: str
    ) -> Tuple[bool, str]:
        """
        Check 4.2: Detect @skip decorators added to tests.

        Returns:
            (True, "") if OK, (False, reason) if violation detected
        """
        # Only check test files
        if 'test' not in file_path.lower():
            return True, ""

        for pattern in self.TEST_SKIP_PATTERNS:
            matches = re.finditer(pattern, diff, re.MULTILINE)
            for match in matches:
                line = match.group()

                # Get more context (next few lines might have reason)
                start_pos = match.start()
                # Find the full decorator and function definition
                line_start = diff.rfind('\n', 0, start_pos) + 1
                line_end = diff.find('\n', start_pos + len(line))
                if line_end == -1:
                    line_end = len(diff)

                # Get next 3 lines for context
                context_end = line_end
                for _ in range(3):
                    next_newline = diff.find('\n', context_end + 1)
                    if next_newline == -1:
                        break
                    context_end = next_newline

                context = diff[line_start:context_end]

                # Allow if has documented reason with issue number
                if re.search(r'reason\s*=.*#\d+', context, re.IGNORECASE):
                    continue  # This is OK

                # Allow if has "known" or "external" or "requires"
                if re.search(r'(known|external|requires)', context, re.IGNORECASE):
                    continue  # This is OK

                return False, "TEST-001: @skip decorator added without documented reason"

        return True, ""

    # ===== LAYER 2 CHECKS (AST Analysis) =====

    def check_unsafe_exec(
        self,
        file_content: str
    ) -> Tuple[bool, str]:
        """
        Check 1.3: Detect eval/exec calls on user input via AST.

        Returns:
            (True, "") if OK, (False, reason) if violation detected
        """
        # User input signal words
        USER_INPUT_SIGNALS = [
            'input', 'request', 'user_input', 'user_data',
            'stdin', 'POST', 'GET', 'data', 'get'
        ]

        try:
            tree = ast.parse(file_content)
        except SyntaxError:
            # If code doesn't parse, allow (syntax errors caught by tests)
            return True, ""

        # Track variable assignments to detect data flow
        user_input_vars = set()

        for node in ast.walk(tree):
            # Track assignments from user input sources
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        # Check if value comes from user input
                        value_source = ast.unparse(node.value) if hasattr(ast, 'unparse') else ''
                        for signal in USER_INPUT_SIGNALS:
                            if signal in value_source.lower():
                                user_input_vars.add(target.id)

            # Check eval/exec calls
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    if node.func.id in ['eval', 'exec']:
                        # Check if argument uses user input
                        if node.args:
                            arg = node.args[0]

                            # Get argument as string
                            try:
                                arg_str = ast.unparse(arg) if hasattr(ast, 'unparse') else str(arg)
                            except:
                                arg_str = ''

                            # Check if argument is a user input variable
                            if isinstance(arg, ast.Name) and arg.id in user_input_vars:
                                return False, f"EXEC-001: Unsafe {node.func.id}() on user input variable '{arg.id}'"

                            # Check if argument contains user input signals
                            arg_str_lower = arg_str.lower()
                            for signal in USER_INPUT_SIGNALS:
                                if signal in arg_str_lower:
                                    return False, f"EXEC-001: Unsafe {node.func.id}() call on potential user input"

                            # Also check the original source code directly
                            source_lines = file_content.split('\n')
                            for line in source_lines:
                                if node.func.id in line and ('eval' in line or 'exec' in line):
                                    for signal in USER_INPUT_SIGNALS:
                                        if signal in line.lower():
                                            return False, f"EXEC-001: Unsafe {node.func.id}() detected via source scan"

        return True, ""

    def check_assertion_removal(
        self,
        file_path: str,
        diff: str
    ) -> Tuple[bool, str]:
        """
        Check 4.1: Detect test assertions being removed without replacement.

        Uses regex heuristic (AST diff is complex for MVP).

        Returns:
            (True, "") if OK, (False, reason) if violation detected
        """
        # Only check test files
        if 'test' not in file_path.lower():
            return True, ""

        # Count removed assertions
        removed_asserts = len(re.findall(
            r'^-\s*(assert|self\.assert)',
            diff,
            re.MULTILINE | re.IGNORECASE
        ))

        # Count added assertions
        added_asserts = len(re.findall(
            r'^\+\s*(assert|self\.assert)',
            diff,
            re.MULTILINE | re.IGNORECASE
        ))

        # Block if net decrease in assertions by more than 1
        # Allow 1 net decrease (could be merge case like: "assert a and b" combining two)
        net_decrease = removed_asserts - added_asserts
        if net_decrease > 1:
            return False, f"TEST-002: {net_decrease} test assertion(s) removed without replacement"

        return True, ""


# Convenience function for standalone usage
def evaluate_transition(
    file_path: str,
    diff: str,
    file_content: str
) -> PredicateResult:
    """
    Convenience function to evaluate a single file change.

    Args:
        file_path: Path to file being modified
        diff: Git diff of changes
        file_content: Full file content after changes

    Returns:
        PredicateResult
    """
    engine = PredicateEngine()

    proposal = {
        'file_path': file_path,
        'diff': diff,
    }

    observation = {
        'file_content': file_content,
    }

    return engine.evaluate('verify_edit', proposal, observation)
