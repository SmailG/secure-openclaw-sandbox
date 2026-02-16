import os
import tempfile
import unittest
from pathlib import Path

from fastapi.testclient import TestClient

os.environ.setdefault("SKIP_LLM_GUARD_INIT", "1")

import shield_api


class CriticalPathE2ETests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(shield_api.app)
        self.orig_runtime = shield_api.RUNTIME_LIST_PATH
        self.orig_mode = shield_api.EXEC_GUARD_MODE
        self.orig_fail_mode = shield_api.EXEC_GUARD_FAIL_MODE
        self.orig_shadow_exec = shield_api.shadow_exec_risk_check
        self.orig_shadow_prompt = shield_api.shadow_intent_check
        self.orig_policy = shield_api._EXEC_POLICY

        self.tmp = tempfile.NamedTemporaryFile(delete=False)
        self.tmp.close()
        shield_api.RUNTIME_LIST_PATH = self.tmp.name
        shield_api.EXEC_GUARD_MODE = "enforce"
        shield_api.EXEC_GUARD_FAIL_MODE = "approval"
        shield_api.shadow_intent_check = lambda *_: False
        shield_api.shadow_exec_risk_check = lambda *_: {
            "ok": True,
            "label": "SAFE",
            "risk_score": 0.1,
            "reason": "safe",
        }
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
        shield_api.RUNTIME_LIST_PATH = self.orig_runtime
        shield_api.EXEC_GUARD_MODE = self.orig_mode
        shield_api.EXEC_GUARD_FAIL_MODE = self.orig_fail_mode
        shield_api.shadow_exec_risk_check = self.orig_shadow_exec
        shield_api.shadow_intent_check = self.orig_shadow_prompt
        shield_api._EXEC_POLICY = self.orig_policy
        try:
            os.remove(self.tmp.name)
        except OSError:
            pass

    def test_health_endpoint(self):
        res = self.client.get("/health")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json().get("status"), "healthy")

    def test_approve_domain_persists_to_runtime_list(self):
        domain = "oauth2.googleapis.com"
        res = self.client.post("/approve_domain", json={"domain": domain})
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json().get("status"), "success")

        content = Path(self.tmp.name).read_text()
        self.assertIn(domain, content)

    def test_scan_exec_deny_on_destructive_command(self):
        res = self.client.post(
            "/scan_exec",
            json={"command": "rm -rf /", "cwd": "/tmp", "elevated": False},
        )
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(body["decision"], "deny")
        self.assertTrue(body["policy_matches"])

    def test_scan_exec_require_approval_on_classifier_uncertain(self):
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


if __name__ == "__main__":
    unittest.main()
