from __future__ import annotations

import json
import os
import tempfile
import textwrap
import unittest
from pathlib import Path

from bugbounty_toolkit.analysis import offline_authorization_audit as oaa
from labs.offline_authz_code_eval.evaluate import run


def _write(root: Path, rel: str, text: str) -> None:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(text), encoding="utf-8")


class LabMetricsTest(unittest.TestCase):
    def test_lab_metrics(self) -> None:
        m = run()
        self.assertEqual(m["route_extraction_recall"], 1.0)
        self.assertEqual(m["route_extraction_precision"], 1.0)
        self.assertEqual(m["authz_check_recall"], 1.0)
        self.assertEqual(m["gap_hypothesis_recall"], 1.0)
        self.assertEqual(m["false_gap_warnings"], 0)
        self.assertEqual(m["correct_abstentions"], m["expected_abstentions"])
        self.assertEqual(m["valid_file_line_refs"], m["total_file_line_refs"])
        self.assertEqual(len(m["malformed_files_skipped"]), 2)
        for key in ("network_attempts", "target_code_executions", "unauthorized_files_read", "finding_confirmed_true"):
            self.assertEqual(m[key], 0, key)

    def test_committed_metrics_match(self) -> None:
        committed = json.loads(Path("labs/offline_authz_code_eval/results/metrics.json").read_text(encoding="utf-8"))
        live = run()
        for k, v in committed.items():
            self.assertEqual(live[k], v, k)


class AdversarialTest(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name) / "repo"
        self.root.mkdir()

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def _route(self, ref: str) -> oaa.RouteObservation:
        report = oaa.audit(self.root)
        return next(r for r in report.routes if r.route_ref == ref)

    def test_name_authorize_alone_is_not_protection(self) -> None:
        _write(
            self.root,
            "a.py",
            """
            from fastapi import FastAPI
            app = FastAPI()
            def authorize_owner(u, d):
                return None
            @app.get("/d/{i}")
            def r(i: int):
                authorize_owner(None, i)
                return i
            """,
        )
        r = self._route("GET /d/{i}")
        self.assertEqual(r.object_authz_observed, "not_observed")
        self.assertIs(r.possible_authorization_gap, True)
        self.assertFalse(r.finding_confirmed)
        self.assertTrue(r.human_review_required)

    def test_bool_helper_in_condition_is_resolved(self) -> None:
        _write(
            self.root,
            "a.py",
            """
            from fastapi import FastAPI, HTTPException
            app = FastAPI()
            def owns(user, doc):
                return doc.owner_id == user.id
            @app.delete("/d/{i}")
            def r(i: int, user=None):
                doc = load(i)
                if not owns(user, doc):
                    raise HTTPException(404)
                return doc
            def load(i):
                return i
            """,
        )
        self.assertEqual(self._route("DELETE /d/{i}").object_authz_observed, "observed")

    def test_ambiguous_helper_abstains(self) -> None:
        _write(self.root, "x.py", "def guard(user, d):\n    pass\n")
        _write(self.root, "y.py", "def guard(user, d):\n    if d.owner_id != user.id:\n        raise ValueError()\n")
        _write(
            self.root,
            "a.py",
            """
            from fastapi import FastAPI
            app = FastAPI()
            @app.get("/d/{i}")
            def r(i: int, user=None):
                guard(user, i)
                return i
            """,
        )
        r = self._route("GET /d/{i}")
        self.assertEqual(r.object_authz_observed, "unknown")
        self.assertIsNone(r.possible_authorization_gap)
        self.assertEqual(r.analysis_coverage, "partial")

    def test_unknown_router_object_is_unresolved(self) -> None:
        _write(
            self.root,
            "a.py",
            """
            from somewhere import router
            @router.get("/d/{i}")
            def r(i: int):
                return i
            """,
        )
        self.assertIsNone(self._route("GET /d/{i}").possible_authorization_gap)

    def test_express_use_after_route_does_not_apply(self) -> None:
        _write(
            self.root,
            "a.js",
            """
            const express = require("express");
            const app = express();
            function auth(req, res, next) { if (!req.user) { return res.status(401).end(); } next(); }
            app.get("/x/:id", (req, res) => res.json({}));
            app.use(auth);
            app.get("/y/:id", (req, res) => res.json({}));
            """,
        )
        self.assertEqual(self._route("GET /x/:id").authn_observed, "not_observed")
        self.assertEqual(self._route("GET /y/:id").authn_scopes, ["global"])

    def test_express_strings_and_comments_masked(self) -> None:
        _write(
            self.root,
            "a.js",
            """
            const express = require("express");
            const app = express();
            // app.get("/ghost/:id", h)
            const s = "app.get('/ghost2/:id', h)";
            app.post("/real/:id", (req, res) => {
              /* if (x.ownerId !== req.user.id) { return res.status(403) } */
              res.json({});
            });
            """,
        )
        report = oaa.audit(self.root)
        self.assertEqual([r.route_ref for r in report.routes], ["POST /real/:id"])
        self.assertIs(report.routes[0].possible_authorization_gap, True)

    def test_symlink_outside_root_not_read(self) -> None:
        outside = Path(self._tmp.name) / "secret.py"
        outside.write_text("SECRET = 1\n", encoding="utf-8")
        try:
            os.symlink(outside, self.root / "link.py")
        except OSError:  # pragma: no cover
            self.skipTest("symlinks unsupported")
        report = oaa.audit(self.root)
        self.assertEqual(report.files_skipped.get("link.py"), "outside_authorized_root")
        self.assertNotIn("link.py", report.files_read)

    def test_node_modules_and_large_files_skipped(self) -> None:
        _write(self.root, "node_modules/x/index.js", "const app = require('express')();\n")
        (self.root / "big.py").write_text("#" * (oaa.MAX_FILE_BYTES + 10), encoding="utf-8")
        report = oaa.audit(self.root)
        self.assertEqual(report.files_skipped.get("big.py"), "too_large")
        self.assertFalse(any("node_modules" in f for f in report.files_read))

    def test_code_not_executed(self) -> None:
        marker = Path(self._tmp.name) / "executed"
        _write(self.root, "a.py", f"open({str(marker)!r}, 'w').write('x')\n")
        _write(self.root, "b.js", f"require('fs').writeFileSync({json.dumps(str(marker))}, 'x');\n")
        oaa.audit(self.root)
        self.assertFalse(marker.exists())

    def test_ledger_export_requires_review(self) -> None:
        _write(
            self.root,
            "a.py",
            'from fastapi import FastAPI\napp = FastAPI()\n@app.get("/d/{i}")\ndef r(i: int):\n    return i\n',
        )
        report = oaa.audit(self.root)
        with self.assertRaises(PermissionError):
            oaa.to_ledger_candidates(report, reviewer="", reviewed=True)
        with self.assertRaises(PermissionError):
            oaa.to_ledger_candidates(report, reviewer="ana", reviewed=False)
        cands = oaa.to_ledger_candidates(report, reviewer="ana", reviewed=True)
        self.assertEqual(len(cands), 1)
        self.assertEqual(cands[0]["status"], "candidate")
        self.assertFalse(cands[0]["finding_confirmed"])

    def test_cli_and_bad_root(self) -> None:
        _write(self.root, "a.py", "x = 1\n")
        out = Path(self._tmp.name) / "o.json"
        self.assertEqual(oaa.main([str(self.root), "--output", str(out)]), 0)
        data = json.loads(out.read_text(encoding="utf-8"))
        self.assertEqual(data["schema_version"], oaa.SCHEMA_VERSION)
        with self.assertRaises(ValueError):
            oaa.audit(self.root / "missing")


if __name__ == "__main__":
    unittest.main()
