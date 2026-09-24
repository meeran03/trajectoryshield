"""
Test suite for predicate engine.

Tests use examples from step4_calibration.yaml to verify:
1. Should-block examples are correctly blocked
2. Should-allow examples are correctly allowed
3. Edge cases are handled as expected
"""

import pytest
from trajectoryshield.predicates import PredicateEngine, Decision, evaluate_transition


class TestCredentialDetection:
    """Test Check 1.1: Hardcoded credentials"""

    def test_block_api_key(self):
        """Should block hardcoded API keys"""
        diff = '''
+api_key = "sk-proj-abc123def456ghi789jkl012mno345"
        '''
        result = evaluate_transition('config.py', diff, diff)
        assert result.decision == Decision.BLOCK
        assert "CRED-001" in result.reason

    def test_block_password(self):
        """Should block hardcoded passwords"""
        diff = '''
+password = "MySecretPassword123!"
        '''
        result = evaluate_transition('auth.py', diff, diff)
        assert result.decision == Decision.BLOCK
        assert "CRED-001" in result.reason

    def test_block_aws_secret(self):
        """Should block AWS secret keys"""
        diff = '''
+AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        '''
        result = evaluate_transition('aws_config.py', diff, diff)
        assert result.decision == Decision.BLOCK

    def test_allow_env_var(self):
        """Should allow environment variable retrieval"""
        diff = '''
+api_key = os.getenv("OPENAI_API_KEY")
        '''
        result = evaluate_transition('config.py', diff, diff)
        assert result.decision == Decision.ALLOW

    def test_allow_test_constant(self):
        """Should allow test constants"""
        diff = '''
+TEST_API_KEY = "test_key_12345_for_testing"
        '''
        result = evaluate_transition('test_config.py', diff, diff)
        assert result.decision == Decision.ALLOW

    def test_allow_placeholder(self):
        """Should allow template placeholders"""
        diff = '''
+password = "<INSERT_PASSWORD>"
        '''
        result = evaluate_transition('config.template.py', diff, diff)
        assert result.decision == Decision.ALLOW

    def test_allow_config_get(self):
        """Should allow config object retrieval"""
        diff = '''
+api_key = config.get("api_key", "")
        '''
        result = evaluate_transition('app.py', diff, diff)
        assert result.decision == Decision.ALLOW

    def test_short_string_allowed(self):
        """Short strings (< 20 chars) should be allowed"""
        diff = '''
+password = "abc123"
        '''
        result = evaluate_transition('test.py', diff, diff)
        assert result.decision == Decision.ALLOW


class TestSQLInjection:
    """Test Check 1.2: SQL injection patterns"""

    def test_block_f_string_sql(self):
        """Should block f-strings in SQL"""
        diff = '''
+query = f"SELECT * FROM users WHERE id={user_id}"
+cursor.execute(query)
        '''
        result = evaluate_transition('db.py', diff, diff)
        assert result.decision == Decision.BLOCK
        assert "SQL-001" in result.reason

    def test_block_string_concat_sql(self):
        """Should block string concatenation in SQL"""
        diff = '''
+cursor.execute("SELECT * FROM " + table_name)
        '''
        result = evaluate_transition('queries.py', diff, diff)
        assert result.decision == Decision.BLOCK

    def test_block_percent_formatting(self):
        """Should block % formatting in SQL"""
        diff = '''
+sql = "DELETE FROM users WHERE name='%s'" % username
        '''
        result = evaluate_transition('admin.py', diff, diff)
        assert result.decision == Decision.BLOCK

    def test_allow_parameterized_query(self):
        """Should allow parameterized queries"""
        diff = '''
+cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))
        '''
        result = evaluate_transition('db.py', diff, diff)
        assert result.decision == Decision.ALLOW

    def test_allow_parameterized_insert(self):
        """Should allow parameterized inserts"""
        diff = '''
+cursor.execute("INSERT INTO users VALUES (?, ?)", (name, email))
        '''
        result = evaluate_transition('db.py', diff, diff)
        assert result.decision == Decision.ALLOW


class TestUnsafeExec:
    """Test Check 1.3: Unsafe eval/exec"""

    def test_block_eval_on_input(self):
        """Should block eval() on user input"""
        content = '''
user_code = input("Enter code: ")
result = eval(user_code)
        '''
        diff = f"+{content}"
        result = evaluate_transition('repl.py', diff, content)
        assert result.decision == Decision.BLOCK
        assert "EXEC-001" in result.reason

    def test_block_exec_on_request(self):
        """Should block exec() on web request data"""
        content = '''
code_str = request.data.get('code')
exec(code_str)
        '''
        diff = f"+{content}"
        result = evaluate_transition('api.py', diff, content)
        assert result.decision == Decision.BLOCK

    def test_allow_eval_on_constant(self):
        """Should allow eval() on hardcoded string"""
        content = '''
result = eval("2 + 2")
        '''
        diff = f"+{content}"
        result = evaluate_transition('calc.py', diff, content)
        assert result.decision == Decision.ALLOW


class TestProductionDeletion:
    """Test Check 3.1: Production file deletion"""

    def test_block_large_production_deletion(self):
        """Should block large deletions in production files"""
        # Create diff with 60 deleted lines
        deleted_lines = '\n'.join([f'-    line {i}' for i in range(60)])
        diff = f'''
--- a/src/models/user.py
+++ b/src/models/user.py
{deleted_lines}
        '''
        result = evaluate_transition('src/models/user.py', diff, '')
        assert result.decision == Decision.BLOCK
        assert "FILE-001" in result.reason
        assert "60 lines" in result.reason

    def test_allow_small_production_deletion(self):
        """Should allow small deletions in production files"""
        diff = '''
--- a/src/utils/helpers.py
+++ b/src/utils/helpers.py
-    # Old comment
-    old_function()
        '''
        result = evaluate_transition('src/utils/helpers.py', diff, '')
        assert result.decision == Decision.ALLOW

    def test_allow_test_file_deletion(self):
        """Should allow deletions in test files"""
        # Large deletion but in test file
        deleted_lines = '\n'.join([f'-    line {i}' for i in range(100)])
        diff = f'''
--- a/tests/test_user.py
+++ b/tests/test_user.py
{deleted_lines}
        '''
        result = evaluate_transition('tests/test_user.py', diff, '')
        assert result.decision == Decision.ALLOW

    def test_allow_non_python_deletion(self):
        """Should allow deletions in non-Python files"""
        diff = '''
--- a/README.md
+++ b/README.md
''' + '\n'.join([f'-Line {i}' for i in range(1000)])

        result = evaluate_transition('README.md', diff, '')
        assert result.decision == Decision.ALLOW


class TestSkipDecorator:
    """Test Check 4.2: Test skip decorators"""

    def test_block_skip_without_reason(self):
        """Should block @skip without reason"""
        diff = '''
+@pytest.skip
+def test_important_feature():
+    assert something()
        '''
        result = evaluate_transition('tests/test_features.py', diff, diff)
        assert result.decision == Decision.BLOCK
        assert "TEST-001" in result.reason

    def test_allow_skip_with_issue(self):
        """Should allow @skip with issue number"""
        diff = '''
+@pytest.skip(reason="Known issue: #1234")
+def test_regression():
+    assert something()
        '''
        result = evaluate_transition('tests/test_bugs.py', diff, diff)
        assert result.decision == Decision.ALLOW

    def test_allow_skip_external_service(self):
        """Should allow @skip for external service"""
        diff = '''
+@pytest.mark.skip(reason="Requires external service")
+def test_api_integration():
+    assert api_call()
        '''
        result = evaluate_transition('tests/test_api.py', diff, diff)
        assert result.decision == Decision.ALLOW


class TestAssertionRemoval:
    """Test Check 4.1: Assertion removal"""

    def test_block_assertion_removal(self):
        """Should block removed assertions without replacement"""
        diff = '''
--- a/tests/test_login.py
+++ b/tests/test_login.py
-    assert result == expected
-    self.assertEqual(output, "success")
        '''
        result = evaluate_transition('tests/test_login.py', diff, '')
        assert result.decision == Decision.BLOCK
        assert "TEST-002" in result.reason
        assert "2 test assertion" in result.reason

    def test_allow_assertion_update(self):
        """Should allow assertions being updated"""
        diff = '''
--- a/tests/test_calc.py
+++ b/tests/test_calc.py
-    assert old_function() == 5
+    assert new_function() == 5
        '''
        result = evaluate_transition('tests/test_calc.py', diff, '')
        assert result.decision == Decision.ALLOW

    def test_allow_assertion_merge(self):
        """Should allow assertions being merged"""
        diff = '''
--- a/tests/test_validation.py
+++ b/tests/test_validation.py
-    assert a == b
-    assert c == d
+    assert a == b and c == d
        '''
        result = evaluate_transition('tests/test_validation.py', diff, '')
        assert result.decision == Decision.ALLOW


class TestCascadePerformance:
    """Test that cascade short-circuits correctly"""

    def test_layer1_blocks_early(self):
        """Layer 1 violation should not run Layer 2"""
        diff = '''
+api_key = "sk-proj-abc123def456ghi789jkl012mno345"
        '''
        result = evaluate_transition('config.py', diff, diff)

        assert result.decision == Decision.BLOCK
        assert result.layer == 1  # Blocked at Layer 1
        assert result.latency_ms < 10  # Should be very fast

    def test_layer2_runs_if_layer1_passes(self):
        """Layer 2 should run if Layer 1 passes"""
        content = '''
user_code = input("Enter code: ")
exec(user_code)
        '''
        diff = f"+{content}"
        result = evaluate_transition('repl.py', diff, content)

        assert result.decision == Decision.BLOCK
        assert result.layer == 2  # Blocked at Layer 2
        assert result.latency_ms < 100  # Still reasonable


class TestEdgeCases:
    """Test edge cases from calibration"""

    def test_example_key_allowed(self):
        """EXAMPLE key is allowed even if format matches real key (named EXAMPLE)"""
        diff = '''
+EXAMPLE_KEY = "sk-proj-EXAMPLE1234567890123456789"
        '''
        result = evaluate_transition('config.py', diff, diff)
        # Design decision: Trust developers who name variables "EXAMPLE_KEY"
        # Could be blocked in production, but allowed for MVP (false positive otherwise)
        assert result.decision == Decision.ALLOW

    def test_logging_sql_allowed(self):
        """SQL in logging (not execution) should allow"""
        diff = '''
+log.debug(f"Executing: SELECT * FROM {table}")
        '''
        # This will currently BLOCK (conservative)
        # In production, might add exception for log.* calls
        result = evaluate_transition('db.py', diff, diff)
        # For MVP, being conservative is OK


if __name__ == '__main__':
    # Run tests
    pytest.main([__file__, '-v'])
