import unittest
from fastapi.testclient import TestClient

import os
os.environ.setdefault("SKIP_LLM_GUARD_INIT", "1")

import shield_api


class ExecGuardTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(shield_api.app)
        self.orig_mode = shield_api.EXEC_GUARD_MODE
        self.orig_fail_mode = shield_api.EXEC_GUARD_FAIL_MODE
        self.orig_shadow = shield_api.shadow_exec_risk_check
        self.orig_policy = shield_api._EXEC_POLICY

        shield_api.EXEC_GUARD_MODE = "enforce"
        shield_api.EXEC_GUARD_FAIL_MODE = "approval"
        shield_api._EXEC_POLICY = {
            "deny_commands": ["rm"],
            "deny_patterns": [r"\brm\s+-rf\s+/(?:\s|$)"],
            "allow_patterns": [r"^ls(\s|$)", r"^echo\s+"],
            "blocked_cwd_prefixes": ["/etc"],
            "allowed_cwd_prefixes": [],
            "max_command_length": 1024,
            "elevated": {"deny_patterns": [r"\bssh\b"]},
        }

    def tearDown(self):
        shield_api.EXEC_GUARD_MODE = self.orig_mode
        shield_api.EXEC_GUARD_FAIL_MODE = self.orig_fail_mode
        shield_api.shadow_exec_risk_check = self.orig_shadow
        shield_api._EXEC_POLICY = self.orig_policy

    def test_safe_command_allow(self):
        shield_api.shadow_exec_risk_check = lambda *_: {
            "ok": True,
            "label": "SAFE",
            "risk_score": 0.1,
            "reason": "safe",
        }
        res = self.client.post(
            "/scan_exec",
            json={"command": "ls -la", "args": [], "cwd": "/tmp", "elevated": False},
        )
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(body["decision"], "allow")

    def test_deny_destructive_pattern(self):
        res = self.client.post(
            "/scan_exec",
            json={"command": "rm -rf /", "cwd": "/tmp", "elevated": False},
        )
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(body["decision"], "deny")
        self.assertIsNone(body["llm_label"])

    def test_ambiguous_requires_approval(self):
        shield_api.shadow_exec_risk_check = lambda *_: {
            "ok": True,
            "label": "SUSPICIOUS",
            "risk_score": 0.7,
            "reason": "ambiguous",
        }
        res = self.client.post(
            "/scan_exec",
            json={"command": "python script.py", "cwd": "/tmp", "elevated": False},
        )
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(body["decision"], "require_approval")

    def test_timeout_fail_closed_to_approval(self):
        shield_api.shadow_exec_risk_check = lambda *_: {
            "ok": False,
            "label": "UNKNOWN",
            "risk_score": 0.9,
            "reason": "timeout",
        }
        res = self.client.post(
            "/scan_exec",
            json={"command": "echo hello", "cwd": "/tmp", "elevated": False},
        )
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(body["decision"], "require_approval")

    def test_timeout_fail_closed_to_deny(self):
        shield_api.EXEC_GUARD_FAIL_MODE = "closed"
        shield_api.shadow_exec_risk_check = lambda *_: {
            "ok": False,
            "label": "UNKNOWN",
            "risk_score": 0.9,
            "reason": "timeout",
        }
        res = self.client.post(
            "/scan_exec",
            json={"command": "echo hello", "cwd": "/tmp", "elevated": False},
        )
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(body["decision"], "deny")

    def test_deny_pattern_stops_after_first_match(self):
        shield_api._EXEC_POLICY = {
            "deny_commands": [],
            "deny_patterns": [r"\becho\b", r"\becho\s+hello\b"],
            "allow_patterns": [],
            "blocked_cwd_prefixes": [],
            "allowed_cwd_prefixes": [],
            "max_command_length": 1024,
            "elevated": {"deny_patterns": []},
        }
        res = self.client.post(
            "/scan_exec",
            json={"command": "echo hello", "cwd": "/tmp", "elevated": False},
        )
        self.assertEqual(res.status_code, 200)
        body = res.json()
        deny_matches = [m for m in body["policy_matches"] if m.startswith("deny_pattern:")]
        self.assertEqual(len(deny_matches), 1)

    def test_elevated_deny_pattern_stops_after_first_match(self):
        shield_api._EXEC_POLICY = {
            "deny_commands": [],
            "deny_patterns": [],
            "allow_patterns": [],
            "blocked_cwd_prefixes": [],
            "allowed_cwd_prefixes": [],
            "max_command_length": 1024,
            "elevated": {"deny_patterns": [r"\bssh\b", r"\bssh\s+-i\b"]},
        }
        res = self.client.post(
            "/scan_exec",
            json={"command": "ssh -i key.pem host", "cwd": "/tmp", "elevated": True},
        )
        self.assertEqual(res.status_code, 200)
        body = res.json()
        elevated_matches = [m for m in body["policy_matches"] if m.startswith("elevated_deny_pattern:")]
        self.assertEqual(len(elevated_matches), 1)


if __name__ == "__main__":
    unittest.main()
