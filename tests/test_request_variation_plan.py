from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import secrets
import socket
import tempfile
import unittest
from typing import Any
from unittest.mock import patch

from bugbounty_toolkit.analysis.request_variation_plan import (
    _replace_target,
    build_plan,
    load_declaration,
    save_plan,
    summary,
    validate_plan,
)
from labs.request_variation_eval.evaluate import evaluate
from labs.request_variation_eval.example import create_example
from labs.request_variation_eval.fixtures import declaration, request


class RequestVariationPlanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.capture = self.root / "capture.http"
        self.config = self.root / "declaration.json"
        self.scope = self.root / "scope.txt"
        self.scope.write_text("https://lab.test\n")
        self.inputs()
        for target in ((socket.socket, "connect"), (socket, "getaddrinfo")):
            guard = patch.object(*target, side_effect=AssertionError("Network prohibited"))
            guard.start()
            self.addCleanup(guard.stop)

    def inputs(self, raw: str | None = None, config: dict[str, Any] | None = None) -> None:
        self.capture.write_text(request() if raw is None else raw, newline="")
        self.config.write_text(json.dumps(declaration() if config is None else config))

    def plan(self) -> dict[str, Any]:
        return build_plan(self.capture, self.config, self.scope)

    def test_lab_metrics(self) -> None:
        result = evaluate()
        self.assertEqual(result["scenarios"], 21)
        metrics = result["metrics"]
        self.assertEqual(metrics["structurally_correct_variations"], 5)
        self.assertEqual(metrics["correctly_rejected_cases"], 16)
        self.assertEqual(metrics["duplicates_skipped"], 1)
        self.assertEqual(metrics["types_preserved"], 5)
        for key in (
            "accidental_field_changes",
            "duplicates_generated",
            "unauthorized_variations",
            "network_requests_sent",
            "secrets_in_plans",
            "origin_rewrites",
            "unexpected_results",
        ):
            self.assertEqual(metrics[key], 0, key)

    def test_private_diff_and_unchanged_capture(self) -> None:
        value = secrets.token_hex(24)
        self.inputs(request(extra="Authorization: [REDACTED]\r\n").replace("[REDACTED]", value))
        before = self.capture.read_bytes()
        plan = self.plan()
        self.assertEqual(self.capture.read_bytes(), before)
        self.assertTrue(value not in json.dumps(plan), "Plan must not contain captured secrets.")
        self.assertNotIn("Authorization", json.dumps(plan))
        self.assertNotIn("lab.test", json.dumps(plan))
        self.assertEqual(plan["variants"][0]["diff"], {"selector": {"path_segment": 1}, "before": 101, "after": 202})
        self.assertEqual(type(plan["variants"][0]["diff"]["after"]), int)
        self.assertFalse(plan["execution_allowed"])
        self.assertFalse(plan["case_eligible"])
        self.assertFalse(plan["finding_confirmed"])
        self.assertFalse(plan["confirmed"])
        self.assertTrue(validate_plan(plan, self.capture, self.config, self.scope))
        self.assertNotIn("diff", json.dumps(summary(plan)))
        plan["duplicates_skipped"] = value
        with self.assertRaises(ValueError):
            summary(plan)

    def test_replacement_preserves_every_unrelated_url_byte(self) -> None:
        for target, selector, expected in (
            ("/objects/101?x=a%20b&blank=&encoded=%2F", {"path_segment": 1}, "/objects/202?x=a%20b&blank=&encoded=%2F"),
            (
                "https://lab.test/objects/%31%30%31?view=small",
                {"path_segment": 1},
                "https://lab.test/objects/202?view=small",
            ),
            ("/objects?view=a+b&id=%31%30%31&empty=", {"query_parameter": "id"}, "/objects?view=a+b&id=202&empty="),
            ("/objects/101?id=101", {"path_segment": 1}, "/objects/202?id=101"),
        ):
            with self.subTest(target=target):
                self.assertEqual(_replace_target(target, selector, "101", "202"), expected)

    def test_publication_and_tampering(self) -> None:
        output = self.root / "private" / "plan.json"
        result = save_plan(self.capture, self.config, self.scope, output)
        self.assertEqual(result["variants"], 1)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        self.assertEqual(output.parent.stat().st_mode & 0o777, 0o700)
        with self.assertRaises(ValueError):
            save_plan(self.capture, self.config, self.scope, output)
        original = json.loads(output.read_text())
        for field in ("execution_allowed", "case_eligible", "confirmed", "finding_confirmed"):
            changed = copy.deepcopy(original)
            changed[field] = True
            self.assertFalse(validate_plan(changed, self.capture, self.config, self.scope))
        changed = copy.deepcopy(original)
        changed["variants"][0]["diff"]["after"] = 999
        self.assertFalse(validate_plan(changed, self.capture, self.config, self.scope))
        self.capture.write_text(request("/objects/202"))
        self.assertFalse(validate_plan(original, self.capture, self.config, self.scope))

    def test_private_example_is_reproducible(self) -> None:
        directory = self.root / "example"
        self.assertEqual(create_example(directory)["variants"], 1)
        self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
        self.assertTrue(all(item.stat().st_mode & 0o777 == 0o600 for item in directory.iterdir()))
        plan = json.loads((directory / "plan.json").read_text())
        self.assertTrue(
            validate_plan(plan, directory / "capture.http", directory / "resources.json", directory / "scope.txt")
        )
        with self.assertRaises(FileExistsError):
            create_example(directory)

    def test_input_paths_and_overwrite_rejected(self) -> None:
        for path in (self.capture, self.config, self.scope):
            with self.assertRaises(ValueError):
                save_plan(self.capture, self.config, self.scope, path)
        link = self.root / "link.http"
        link.symlink_to(self.capture)
        with self.assertRaises(ValueError):
            build_plan(link, self.config, self.scope)
        with self.assertRaises(ValueError):
            save_plan(self.capture, self.config, self.scope, link)
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        with self.assertRaises(ValueError):
            build_plan(fifo, self.config, self.scope)
        self.assertFalse(build_plan(self.capture, self.config, fifo)["variants"])

    def test_invalid_declarations_fail_closed(self) -> None:
        modifications: list[dict[str, Any]] = [
            {"lab_authorized": False},
            {"lab_authorized": 1},
            {"schema_version": "unknown"},
            {"origin": "https://example.com"},
            {"origin": "https://lab.test/path"},
            {"origin": "https://alice:secret@lab.test"},
            {"targets": list(range(65))},
            {"source": "unknown"},
            {"accounts": []},
            {"resources": []},
            {"selector": {"path_segment": True}},
            {"selector": {"json_body_pointer": "/bad~escape"}},
            {"selector": {"cookie": "id"}},
            {"extra": True},
        ]
        for changes in modifications:
            with self.subTest(changes=changes):
                config = declaration()
                config.update(changes)
                self.inputs(config=config)
                with self.assertRaises(ValueError):
                    self.plan()
        for value in (True, 202.0, None, {"id": 202}, [202], "../202", "202%2fpath", "a&csrf=b"):
            config = declaration()
            config["resources"][1]["value"] = value
            self.inputs(config=config)
            with self.assertRaises(ValueError):
                self.plan()

    def test_no_identity_inference_or_undeclared_ownership(self) -> None:
        for collection, field, value in (
            ("accounts", "authorized", False),
            ("resources", "synthetic", False),
            ("resources", "account", "unknown"),
        ):
            config = declaration()
            config[collection][1][field] = value
            self.inputs(config=config)
            with self.assertRaises(ValueError):
                self.plan()
        self.inputs(request().replace("Cookie: [REDACTED]\r\n", ""))
        self.assertEqual(len(self.plan()["variants"]), 1)

    def test_duplicates_and_no_op(self) -> None:
        config = declaration()
        config["resources"].append({"name": "alias", "account": "bob", "value": 202, "synthetic": True})
        config["targets"] = ["other", "alias", "other", "own"]
        self.inputs(config=config)
        plan = self.plan()
        self.assertEqual(len(plan["variants"]), 1)
        self.assertEqual(plan["duplicates_skipped"], 2)
        self.assertEqual(plan["incompatible"], [{"resource_ref": "own", "code": "NO_CHANGE"}])

    def test_scope_exclusions_apply_to_variant(self) -> None:
        self.scope.write_text("https://lab.test\n!https://lab.test/objects/202\n")
        plan = self.plan()
        self.assertFalse(plan["variants"])
        self.assertEqual(plan["incompatible"][0]["code"], "VARIANT_OR_SCOPE_INCOMPATIBLE")
        self.scope.write_text("")
        self.assertFalse(self.plan()["variants"])

    def test_ambiguous_json_and_unsafe_capture(self) -> None:
        self.config.write_text('{"schema_version":1,"schema_version":2}')
        with self.assertRaises(ValueError):
            load_declaration(self.config)
        for raw in (
            request().replace("Host: lab.test", "Host: lab.test\r\nHost: other.test"),
            request("https://other.test/objects/101"),
            request("/objects/101#fragment"),
            request(extra="Transfer-Encoding: chunked\r\n"),
        ):
            self.inputs(raw)
            self.assertFalse(self.plan()["variants"])


if __name__ == "__main__":
    unittest.main()
