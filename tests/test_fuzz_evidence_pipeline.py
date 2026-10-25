import json
import tempfile
import unittest
from pathlib import Path

from bugbounty_toolkit.cli import _integrate_fuzz_evidence
from bugbounty_toolkit.core.records import ProgramPaths, RecordStore
from bugbounty_toolkit.fuzzing.results_parser import build_authorization_followups, classify_ffuf_results
from bugbounty_toolkit.reporting.evidence import write_evidence_json


class FuzzEvidencePipelineTests(unittest.TestCase):
    def test_discovery_flows_into_workflow_graph_memory_and_nonexecuting_skill_plan(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = ProgramPaths(Path(directory), "local-lab")
            store = RecordStore(paths)
            try:
                raw_path = paths.raw_dir / "ffuf.json"
                raw_path.write_text(
                    json.dumps(
                        {
                            "results": [
                                {
                                    "url": "http://127.0.0.1:8099/api/orders/123",
                                    "status": 200,
                                    "length": 180,
                                    "words": 16,
                                    "lines": 5,
                                }
                            ]
                        }
                    ),
                    encoding="utf-8",
                )
                classified = classify_ffuf_results(
                    [
                        {
                            "url": "http://127.0.0.1:8099/api/orders/123",
                            "status": 200,
                            "length": 180,
                            "words": 16,
                            "lines": 5,
                        }
                    ],
                    {"status": 404, "length": 20, "words": 3, "lines": 1},
                )
                fuzz_evidence = write_evidence_json(
                    paths.evidence_dir / "fuzzing",
                    {
                        "type": "ffuf",
                        "raw_output": str(raw_path),
                        "followup_candidates": build_authorization_followups(classified),
                    },
                    "ffuf",
                )

                result = _integrate_fuzz_evidence(store, "local-lab", fuzz_evidence, raw_path, 20)

                self.assertEqual(result["network_requests_sent"], 0)
                self.assertEqual(result["ollama_calls"], 0)
                self.assertFalse(result["plan_executed"])
                self.assertTrue(Path(str(result["bundle"])).exists())
                self.assertTrue(Path(str(result["workflow"])).exists())
                route_path = Path(str(result["route_plan"]))
                route = json.loads(route_path.read_text(encoding="utf-8"))
                self.assertEqual(route["selected"][0]["skill"], "bugbounty-access-control")
                self.assertTrue(any("private case.json" in item for item in route["missing_inputs"]))
                self.assertIn("access-check", route["plan"][0]["command"])
                self.assertRegex(str(result["investigation_id"]), r"^fuzz-[a-f0-9]{24}$")
                graph_nodes = store.connection.execute("select count(*) as total from graph_nodes").fetchone()
                self.assertGreater(graph_nodes["total"], 0)
                memory = store.connection.execute("select status from investigation_memory").fetchone()
                self.assertEqual(memory["status"], "active")
            finally:
                store.close()


if __name__ == "__main__":
    unittest.main()
