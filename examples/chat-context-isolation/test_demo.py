from __future__ import annotations

import importlib.util
import json
import sys
import threading
import unittest
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import urlopen


MODULE_PATH = Path(__file__).with_name("server.py")
SPEC = importlib.util.spec_from_file_location("synthetic_isolation_demo", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
DEMO = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = DEMO
SPEC.loader.exec_module(DEMO)


class SyntheticModelTests(unittest.TestCase):
    def test_resource_families_are_exact_and_context_scoped(self) -> None:
        model = DEMO.SyntheticControlPlane()
        self.assertEqual(DEMO.RESOURCE_FAMILIES, ("CommandSession", "Monitoring", "FileChange"))
        for context, suffix in (("context-a", "a"), ("context-b", "b")):
            resources = model.resources_for(context)
            self.assertEqual(tuple(resources), DEMO.RESOURCE_FAMILIES)
            self.assertEqual(resources["CommandSession"][0]["id"], f"session-{suffix}")
            self.assertEqual(resources["Monitoring"][0]["id"], f"monitor-{suffix}")
            self.assertEqual(resources["FileChange"][0]["id"], f"change-{suffix}")
            serialized = json.dumps(resources, sort_keys=True)
            other = "b" if suffix == "a" else "a"
            self.assertNotIn(f"session-{other}", serialized)
            self.assertNotIn(f"monitor-{other}", serialized)
            self.assertNotIn(f"change-{other}", serialized)

    def test_cross_context_command_session_lookup_fails_closed(self) -> None:
        model = DEMO.SyntheticControlPlane()
        with self.assertRaisesRegex(KeyError, "Command session not found"):
            model.get_command_session("context-a", "session-b")
        with self.assertRaisesRegex(KeyError, "Command session not found"):
            model.get_command_session("context-b", "session-a")

    def test_snapshot_is_explicitly_synthetic(self) -> None:
        snapshot = DEMO.SyntheticControlPlane().snapshot()
        self.assertEqual(snapshot["demo"], "synthetic")
        self.assertFalse(snapshot["production_evidence"])
        self.assertEqual(snapshot["contexts"]["context-a"]["cross_lookup"]["status"], 404)
        self.assertEqual(snapshot["contexts"]["context-b"]["cross_lookup"]["status"], 404)


class SyntheticHttpTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.server = DEMO.DemoServer(("127.0.0.1", 0))
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        host, port = cls.server.server_address
        cls.base_url = f"http://{host}:{port}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=5)

    def test_html_contains_result_and_synthetic_boundary(self) -> None:
        with urlopen(self.base_url + "/", timeout=5) as response:  # noqa: S310 - loopback fixture
            self.assertEqual(response.status, 200)
            body = response.read().decode("utf-8")
        self.assertIn("SYNTHETIC DEMO · NOT PRODUCTION EVIDENCE", body)
        self.assertIn("GET session-b → 404", body)
        self.assertIn("GET session-a → 404", body)
        self.assertIn("CommandSession", body)
        self.assertIn("Monitoring", body)
        self.assertIn("FileChange", body)

    def test_demo_api_and_owned_lookup(self) -> None:
        with urlopen(self.base_url + "/api/demo", timeout=5) as response:  # noqa: S310 - loopback fixture
            payload = json.load(response)
        self.assertFalse(payload["production_evidence"])
        self.assertEqual(payload["shared_infrastructure"]["backend"], "synthetic-backend")

        with urlopen(self.base_url + "/api/contexts/context-a/sessions/session-a", timeout=5) as response:  # noqa: S310
            owned = json.load(response)
        self.assertEqual(owned["id"], "session-a")

    def test_cross_context_http_lookup_is_404(self) -> None:
        for context, foreign_session in (("context-a", "session-b"), ("context-b", "session-a")):
            with self.subTest(context=context):
                with self.assertRaises(HTTPError) as raised:
                    urlopen(  # noqa: S310 - loopback fixture
                        f"{self.base_url}/api/contexts/{context}/sessions/{foreign_session}",
                        timeout=5,
                    )
                self.assertEqual(raised.exception.code, 404)
                payload = json.loads(raised.exception.read().decode("utf-8"))
                self.assertEqual(payload, {"detail": "Command session not found"})


if __name__ == "__main__":
    unittest.main()
