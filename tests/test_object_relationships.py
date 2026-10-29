from __future__ import annotations

import base64
from contextlib import ExitStack, redirect_stdout, redirect_stderr
from io import StringIO
import json
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest.mock import patch

from bugbounty_toolkit import cli
from bugbounty_toolkit.analysis.object_relationships import (
    MAX_CAPTURES,
    MAX_FILES,
    MAX_OCCURRENCES,
    RANKING_VERSION,
    build_object_graph,
    discover_to_file,
    indexed_capture_sources,
    load_object_key,
    object_candidates,
    read_object_graph,
    save_object_json,
    verify_object_sources,
)
from bugbounty_toolkit.core.private_files import atomic_private_write, read_private_input
from bugbounty_toolkit.idor_discovery import discover_idor, discovery_summary


class ObjectRelationshipTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.input = self.root / "capture-secret-filename.har"
        self.key = b"k" * 32
        self.key_path = self.root / "private" / "key.bin"
        self.graph_path = self.root / "private" / "graph.json"

    @staticmethod
    def entry(
        target="/api/orders/987",
        body=None,
        session="owner",
        method="GET",
        request_body=None,
        origin="http://127.0.0.1:8099",
    ):
        request = {
            "method": method,
            "url": origin + target,
            "headers": [
                {"name": "Authorization", "value": "Bearer synthetic-" + session},
                {"name": "Cookie", "value": "session=" + session},
            ],
        }
        if request_body is not None:
            request["postData"] = {"mimeType": "application/json", "text": json.dumps(request_body)}
        return {
            "request": request,
            "response": {"status": 200, "content": {"mimeType": "application/json", "text": json.dumps(body or {})}},
        }

    def write_har(self, entries, path=None):
        path = path or self.input
        path.write_text(json.dumps({"log": {"entries": entries}}))
        return path

    def graph(self, entries=None, paths=None, **options):
        if entries is not None:
            self.write_har(entries)
        with ExitStack() as stack:
            for target in ("socket.socket", "socket.getaddrinfo", "urllib.request.urlopen", "subprocess.Popen"):
                stack.enter_context(
                    patch(target, side_effect=AssertionError("Offline discovery attempted external I/O"))
                )
            return build_object_graph(
                "lab", paths or [self.input], options.pop("key", self.key), authorized=True, **options
            )

    @staticmethod
    def objects(graph, kind=None):
        return [
            node
            for node in graph["nodes"]
            if node["type"] == "Object" and (kind is None or node["resource_type"] == kind)
        ]

    def candidates(self, graph, **options):
        return object_candidates(graph, "lab", self.key, **options)["candidates"]

    def test_windowed_import_recovers_valid_entries_after_many_rejected_entries(self):
        damaged = [{"request": {"method": "GET"}, "response": {}} for _ in range(300)]
        pair = [
            self.entry("/orders/987", {"order_id": 987}, "owner"),
            self.entry("/orders/988", {"order_id": 988}, "actor"),
        ]
        graph = self.graph(damaged + pair, independent_windows=True)
        summary = graph["capture_import"]
        self.assertEqual(summary["accepted"], 2)
        self.assertEqual(summary["rejected"], 300)
        locators = {p["locator"] for o in graph["observations"] for p in o["provenance"]}
        self.assertEqual(locators, {"/log/entries[300]", "/log/entries[301]"})
        self.assertTrue(self.candidates(graph))
        index = indexed_capture_sources("lab", [self.input], self.key, independent_windows=True)
        self.assertEqual({locator for _, locator in index}, locators)
        verify_object_sources(graph, [self.input], self.key)

    def test_windowed_import_still_enforces_accepted_observation_budget(self):
        entries = [self.entry(f"/orders/{1000 + i}", {"order_id": 1000 + i}) for i in range(MAX_CAPTURES + 1)]
        with self.assertRaisesRegex(ValueError, "exceed discovery limits"):
            self.graph(entries, independent_windows=True)
        with self.assertRaisesRegex(ValueError, "exceed discovery limits"):
            indexed_capture_sources("lab", [self.input], self.key, independent_windows=True)

    def test_windowed_recovery_does_not_relax_default_or_strict_import(self):
        entries = [{"request": {"method": "GET"}, "response": {}} for _ in range(300)]
        entries.append(self.entry("/orders/987", {"order_id": 987}))
        with self.assertRaisesRegex(ValueError, "entries_over_limit"):
            self.graph(entries)
        with self.assertRaisesRegex(ValueError, "strict_entry_rejected"):
            self.graph(entries, independent_windows=True, strict=True)

    def call_cli(self, *arguments):
        output, errors = StringIO(), StringIO()
        with patch.object(cli, "RECORDS_ROOT", self.root / "records"), redirect_stdout(output), redirect_stderr(errors):
            args = cli.build_parser().parse_args(list(arguments))
            args.func(args)
        return output.getvalue()

    def test_correlates_path_query_and_json_with_provenance(self):
        graph = self.graph(
            [
                self.entry(body={"data": {"id": 987, "user_id": 123}}),
                self.entry("/api/orders/987/items", {"items": [{"id": 456, "order_id": 987}]}),
                self.entry("/api/invoices?order_id=987", {"data": {"id": 654, "order_id": 987}}),
            ]
        )
        self.assertEqual(len(self.objects(graph, "order")), 1)
        row = next(r for r in self.candidates(graph) if r["resource_type"] == "order")
        self.assertEqual(row["score"], 70)
        self.assertEqual(len(row["endpoint_refs"]), 3)
        self.assertFalse(row["confirmed"])
        self.assertFalse(row["case_executable"])
        self.assertEqual(row["ownership"], "unknown")
        self.assertTrue(
            all(o["provenance"][0]["source_ref"] == graph["sources"][0]["id"] for o in graph["observations"])
        )
        self.assertTrue(all(r["evidence_refs"] and r["provenance"] for r in graph["relations"]))
        verify_object_sources(graph, [self.input], self.key)

    def test_different_ids_with_same_parameter_are_not_merged(self):
        graph = self.graph([self.entry("/api/invoices?order_id=987"), self.entry("/api/invoices?order_id=988")])
        self.assertEqual(len(self.objects(graph, "order")), 2)
        self.assertEqual([len(row["observation_refs"]) for row in self.candidates(graph)], [1, 1])
        self.assertEqual(len({row["object_ref"] for row in self.candidates(graph)}), 2)

    def test_different_namespaces_origins_and_leading_zeros_are_separate(self):
        graph = self.graph(
            [
                self.entry("/api/users/987"),
                self.entry(),
                self.entry("/api/orders/0987"),
                self.entry(origin="http://127.0.0.1:8100"),
                self.entry(origin="https://127.0.0.1:8099"),
            ]
        )
        self.assertEqual(len(self.objects(graph)), 5)

    def test_same_resource_two_sessions_does_not_imply_two_owners(self):
        graph = self.graph([self.entry(), self.entry(session="actor")])
        self.assertEqual(len(self.objects(graph)), 1)
        row = self.candidates(graph)[0]
        self.assertEqual(row["session_context_count"], 2)
        # Leaf object seen in two sessions: request + path_leaf + multi_session_leaf (not ownership).
        self.assertEqual(row["score"], 50)
        self.assertTrue(all(node.get("ownership", "unknown") == "unknown" for node in graph["nodes"]))
        self.assertNotIn("OWNS", {r["relation"] for r in graph["relations"]})

    def test_direct_cooccurrence_and_inferred_path_are_distinct(self):
        graph = self.graph([self.entry("/api/users/123/orders/987", {"data": {"id": 987, "user_id": 123}})])
        self.assertEqual({r["state"] for r in graph["relations"] if r["relation"] == "PATH_CONTEXT"}, {"inferred"})
        self.assertEqual({r["state"] for r in graph["relations"] if r["relation"] == "CO_OCCURS"}, {"observed"})
        self.assertTrue(all("ownership" in r["limitations"] for r in graph["relations"]))

    def test_json_array_entries_are_not_cross_linked(self):
        graph = self.graph(
            [self.entry("/api/orders", {"data": [{"id": 987, "user_id": 123}, {"id": 988, "user_id": 124}]})]
        )
        co = [r for r in graph["relations"] if r["relation"] == "CO_OCCURS"]
        self.assertEqual(len(co), 2)
        self.assertEqual(len(self.objects(graph)), 4)

    def test_json_post_bodies_are_analyzed_but_never_executed(self):
        graph = self.graph([self.entry("/api/invoices", method="POST", request_body={"orderId": 987, "user_id": 123})])
        self.assertEqual({node["resource_type"] for node in self.objects(graph)}, {"order", "user"})
        self.assertEqual(graph["network_requests_sent"], 0)
        self.assertTrue(all(f["location"] == "request_json" for o in graph["observations"] for f in o["references"]))

    def test_non_identifier_values_and_booleans_are_not_objects(self):
        graph = self.graph(
            [
                self.entry(
                    "/api/orders?page=3&limit=9&valid=987", {"status": 200, "id": True, "grid": 987, "cost": 987.5}
                )
            ]
        )
        self.assertEqual(self.objects(graph), [])
        self.assertEqual(self.candidates(graph), [])

    def test_unknown_types_are_conservative_and_names_are_hashed(self):
        graph = self.graph(
            [
                self.entry("/confidential-customer-name?custom_id=987"),
                self.entry("/another-private-route?custom_id=987"),
            ]
        )
        self.assertEqual(len(self.objects(graph)), 2)
        text = json.dumps(graph)
        for secret in ("confidential-customer-name", "another-private-route", "custom_id"):
            self.assertNotIn(secret, text)

    def test_redaction_of_credentials_pii_filenames_and_ids(self):
        entry = self.entry(
            "/api/orders/987?token=query-secret&order_id=987",
            {
                "data": {
                    "id": 987,
                    "email": "private@example.test",
                    "password": "body-password",
                    "token": "json-token",
                    "user_id": "json-token",
                },
                "private-key": {"user_id": "hidden-id"},
            },
        )
        entry["response"]["headers"] = [{"name": "Set-Cookie", "value": "session=response-cookie"}]
        graph = self.graph([entry])
        text = json.dumps(graph) + json.dumps(self.candidates(graph))
        for secret in (
            "synthetic-owner",
            "response-cookie",
            "query-secret",
            "body-password",
            "json-token",
            "hidden-id",
            "private@example.test",
            '"987"',
            self.input.name,
            "127.0.0.1",
            "Authorization",
            "Cookie",
        ):
            self.assertNotIn(secret, text)
        self.assertEqual(len(self.objects(graph)), 1)
        self.assertNotIn("body", graph)

    def test_jwt_and_copied_header_credential_are_not_objects(self):
        entry = self.entry(
            "/api/orders?order_id=synthetic-owner", {"id": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.signature"}
        )
        self.assertEqual(self.objects(self.graph([entry])), [])

    def test_determinism_input_order_and_key_separation(self):
        one, two = self.root / "one.har", self.root / "two.har"
        self.write_har([self.entry(body={"id": 987})], one)
        self.write_har([self.entry("/api/invoices?order_id=987")], two)
        graph = self.graph(paths=[one, two])
        self.assertEqual(graph, self.graph(paths=[two, one]))
        self.assertEqual(self.candidates(graph), self.candidates(self.graph(paths=[one, two])))
        rotated = self.graph(paths=[one, two], key=b"r" * 32)
        self.assertNotEqual(self.objects(graph)[0]["id"], self.objects(rotated)[0]["id"])

    def test_duplicate_capture_does_not_inflate_score_or_graph(self):
        self.write_har([self.entry(body={"id": 987})])
        graph = self.graph()
        self.assertEqual(graph, self.graph(paths=[self.input, self.input]))
        duplicate_entries = self.graph([self.entry(body={"id": 987}), self.entry(body={"id": 987})])
        self.assertEqual(self.candidates(graph), self.candidates(duplicate_entries))
        self.assertEqual(len(duplicate_entries["observations"]), 1)

    def test_query_order_is_normalized_but_path_case_is_preserved(self):
        graph = self.graph(
            [
                self.entry("/api/invoices?order_id=987&user_id=123"),
                self.entry("/api/invoices?user_id=123&order_id=987"),
            ]
        )
        self.assertEqual(len(graph["observations"]), 1)
        self.assertEqual(len(graph["observations"][0]["provenance"]), 2)
        case_graph = self.graph([self.entry(), self.entry("/api/Orders/987")])
        self.assertEqual(len([node for node in case_graph["nodes"] if node["type"] == "Endpoint"]), 2)

    def test_valid_base64_har_response_is_reused(self):
        entry = self.entry()
        entry["response"]["content"].update(encoding="base64", text=base64.b64encode(b'{"id":987}').decode())
        graph = self.graph([entry])
        self.assertEqual(self.candidates(graph)[0]["score"], 45)

    def test_ranking_is_bounded_explainable_and_filterable(self):
        graph = self.graph(
            [
                self.entry("/api/users/123/orders/987", {"id": 987, "user_id": 123}),
                self.entry("/api/invoices?order_id=987", {"order_id": 987}, session="actor"),
            ]
        )
        row = next(r for r in self.candidates(graph) if r["resource_type"] == "order")
        self.assertEqual(RANKING_VERSION, "2.0")
        self.assertEqual(row["score"], 90)
        self.assertEqual(sum(part["points"] for part in row["score_breakdown"]), row["score_raw"])
        self.assertLessEqual(row["score"], 100)
        self.assertTrue(all(part["observation_refs"] for part in row["score_breakdown"]))
        self.assertTrue(any(part.get("polarity") == "positive" for part in row["score_breakdown"]))
        self.assertIn("order_reason", row)
        self.assertIn("uncertainty", row)
        self.assertFalse(row["confirmed"])
        self.assertEqual(row["evidence_class"], "observation")
        # Shared path-parent demotion keeps the parent candidate but lowers it vs leaf order.
        user = next(r for r in self.candidates(graph) if r["resource_type"] == "user")
        self.assertLessEqual(user["score"], row["score"])
        # Dedicated shared-parent demotion: same parent id under two sessions with distinct children.
        shared = self.graph(
            [
                self.entry("/api/users/1/orders/10", session="owner"),
                self.entry("/api/users/1/orders/11", session="actor"),
            ]
        )
        parent = next(r for r in self.candidates(shared) if r["resource_type"] == "user")
        child = next(r for r in self.candidates(shared) if r["resource_type"] == "order")
        self.assertTrue(any(p["rule"] == "shared_path_parent_across_sessions" for p in parent["score_breakdown"]))
        self.assertGreater(child["score"], parent["score"])
        self.assertEqual(len(self.candidates(graph, min_score=90, limit=1)), 1)
        for options in ({"limit": 0}, {"limit": 101}, {"min_score": -1}, {"min_score": 101}):
            with self.assertRaises(ValueError):
                self.candidates(graph, **options)

    def test_hmac_integrity_wrong_key_program_and_source_tampering(self):
        graph = self.graph([self.entry()])
        save_object_json(self.graph_path, graph)
        self.assertEqual(read_object_graph(self.graph_path, "lab", self.key), graph)
        for program, key in (("other", self.key), ("lab", b"x" * 32)):
            with self.assertRaises(ValueError):
                read_object_graph(self.graph_path, program, key)
        graph["nodes"][0]["secret"] = "do-not-print"
        with self.assertRaises(ValueError):
            self.candidates(graph)
        original = read_object_graph(self.graph_path, "lab", self.key)
        self.input.write_text("changed")
        with self.assertRaises(ValueError):
            verify_object_sources(original, [self.input], self.key)
        with self.assertRaises(ValueError):
            verify_object_sources(original, [], self.key)

    def test_rejects_missing_authorization_bad_program_and_input_counts(self):
        self.write_har([self.entry()])
        for options in (
            {"authorized": False},
            {"key": b"bad"},
            {"inputs": []},
            {"inputs": [self.input] * (MAX_FILES + 1)},
            {"program": "../bad"},
        ):
            arguments = {"program": "lab", "inputs": [self.input], "key": self.key, "authorized": True, **options}
            with self.assertRaises(ValueError):
                build_object_graph(**arguments)

    def test_rejects_malformed_and_incomplete_captures_without_echo(self):
        payloads = [
            b"{bad-secret",
            b"{}",
            b'{"log":[]}',
            b'{"log":{"entries":[{}]}}',
            b"<items><item/>",
            b"GET /secret HTTP/1.1\r\n",
            b"\xff",
            b'<!DOCTYPE items [<!ENTITY x "secret">]><items/>',
        ]
        for data in payloads:
            with self.subTest(data=data):
                self.input.write_bytes(data)
                with self.assertRaisesRegex(ValueError, "Offline captures are invalid") as caught:
                    self.graph()
                self.assertNotIn("secret", str(caught.exception))

    def test_rejects_ambiguous_json_bad_encoding_and_excessive_structure(self):
        bad_entries = []
        for text in ('{"id":1,"id":2}', '{"data":' * 18 + "0" + "}" * 18, "{bad-secret"):
            entry = self.entry()
            entry["response"]["content"]["text"] = text
            bad_entries.append(entry)
        entry = self.entry()
        entry["response"]["content"].update(encoding="base64", text="invalid!")
        bad_entries.append(entry)
        entry = self.entry()
        entry["response"]["content"]["encoding"] = "gzip"
        bad_entries.append(entry)
        for entry in bad_entries:
            with self.subTest(entry=entry), self.assertRaises(ValueError):
                self.graph([entry])

    def test_byte_file_capture_occurrence_and_graph_limits(self):
        self.write_har([self.entry()])
        for constant, value in (
            ("MAX_ITEM_BYTES", 1),
            ("MAX_TOTAL_BYTES", 1),
            ("MAX_CAPTURES", 0),
            ("MAX_GRAPH_NODES", 1),
            ("MAX_GRAPH_EDGES", 1),
            ("MAX_GRAPH_INPUT_BYTES", 1),
        ):
            with (
                patch("bugbounty_toolkit.analysis.object_relationships." + constant, value),
                self.assertRaises(ValueError),
            ):
                self.graph()
        with self.assertRaises(ValueError):
            self.graph([self.entry(body={"data": [{"id": n} for n in range(MAX_OCCURRENCES + 1)]})])
        with self.assertRaises(ValueError):
            self.graph([self.entry()] * 33)
        with (
            patch("bugbounty_toolkit.analysis.object_relationships.MAX_EXCHANGES", MAX_CAPTURES + 1),
            self.assertRaises(ValueError),
        ):
            self.graph([self.entry()] * (MAX_CAPTURES + 1))

    def test_safe_paths_reject_links_traversal_directories_and_fifos(self):
        self.write_har([self.entry()])
        link = self.root / "link.har"
        link.symlink_to(self.input)
        directory_link = self.root / "linked"
        directory_link.symlink_to(self.root, target_is_directory=True)
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        for path in (
            link,
            directory_link / self.input.name,
            self.root,
            fifo,
            self.root / ".." / self.root.name / self.input.name,
            Path("//server/export"),
        ):
            with self.subTest(path=path), self.assertRaises(ValueError):
                self.graph(paths=[path])
        with self.assertRaises(ValueError):
            read_private_input(self.input, 1)
        with patch("bugbounty_toolkit.core.private_files.os.name", "nt"), self.assertRaises(ValueError):
            read_private_input(self.input, 99999)

    def test_private_atomic_writes_exclusive_force_and_cleanup(self):
        atomic_private_write(self.key_path, self.key)
        self.assertEqual(stat.S_IMODE(self.key_path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.key_path.parent.stat().st_mode), 0o700)
        self.assertEqual(load_object_key(self.key_path), self.key)
        with self.assertRaises(ValueError):
            atomic_private_write(self.key_path, b"overwrite")
        atomic_private_write(self.key_path, b"x" * 32, force=True)
        self.assertEqual(load_object_key(self.key_path), b"x" * 32)
        with (
            patch("bugbounty_toolkit.core.private_files.os.link", side_effect=OSError("failure")),
            self.assertRaises(ValueError),
        ):
            atomic_private_write(self.graph_path, b"new")
        self.assertFalse(self.graph_path.exists())
        self.assertEqual(list(self.key_path.parent.iterdir()), [self.key_path])
        self.graph_path.symlink_to(self.key_path)
        with self.assertRaises(ValueError):
            atomic_private_write(self.graph_path, b"bad", force=True)
        self.assertEqual(load_object_key(self.key_path), b"x" * 32)

    def test_insecure_and_invalid_keys_are_rejected(self):
        atomic_private_write(self.key_path, self.key)
        self.key_path.chmod(0o644)
        with self.assertRaises(ValueError):
            load_object_key(self.key_path)
        self.key_path.chmod(0o600)
        self.key_path.write_bytes(b"short")
        with self.assertRaises(ValueError):
            load_object_key(self.key_path)

    def test_cli_dry_runs_have_no_side_effects_even_with_log_option(self):
        self.write_har([self.entry()])
        arguments = [
            "--records-root",
            str(self.root / "records"),
            "--log-file",
            str(self.root / "do-not-create.log"),
            "object-discover",
            "lab",
            "--input",
            str(self.input),
            "--attest-authorized-captures",
            "--dry-run",
        ]
        before = sorted(self.root.rglob("*"))
        with patch("sys.argv", ["bbtk", *arguments]), redirect_stdout(StringIO()):
            cli.main()
        self.assertEqual(before, sorted(self.root.rglob("*")))
        discover_to_file("lab", [self.input], self.key_path, self.graph_path, authorized=True)
        before = {p: p.read_bytes() for p in self.root.rglob("*") if p.is_file()}
        text = self.call_cli(
            "object-candidates",
            "lab",
            "--graph",
            str(self.graph_path),
            "--key-file",
            str(self.key_path),
            "--output",
            str(self.root / "no-output.json"),
            "--dry-run",
        )
        self.assertIn('"dry_run": true', text)
        self.assertEqual(before, {p: p.read_bytes() for p in self.root.rglob("*") if p.is_file()})

    def test_cli_round_trip_and_secret_free_summaries(self):
        self.write_har([self.entry(body={"id": 987})])
        with patch("socket.socket", side_effect=AssertionError("No network")):
            text = self.call_cli(
                "object-discover",
                "lab",
                "--input",
                str(self.input),
                "--key-file",
                str(self.key_path),
                "--output",
                str(self.graph_path),
                "--attest-authorized-captures",
            )
            output = self.root / "candidates.json"
            text += self.call_cli(
                "object-candidates",
                "lab",
                "--graph",
                str(self.graph_path),
                "--key-file",
                str(self.key_path),
                "--verify-input",
                str(self.input),
                "--output",
                str(output),
            )
        self.assertEqual(json.loads(output.read_text())["total_candidates"], 1)
        self.assertFalse((self.root / "records").exists())
        for secret in ('"987"', "/987", "synthetic-owner", self.input.name):
            self.assertNotIn(secret, text)

    def test_numeric_json_dictionary_keys_are_pseudonymized(self):
        graph = self.graph([self.entry(body={"orders": {"987": {"id": 987, "user_id": 123}}})])
        self.assertEqual(len(self.objects(graph)), 2)
        for node in graph["nodes"]:
            if node["type"] == "Field":
                self.assertNotIn("/987", node["pointer_template"])
        self.assertNotIn('"987"', json.dumps(graph))
        for destination in (self.input, self.key_path, self.graph_path):
            with self.assertRaises(ValueError):
                self.call_cli(
                    "object-candidates",
                    "lab",
                    "--graph",
                    str(self.graph_path),
                    "--key-file",
                    str(self.key_path),
                    "--verify-input",
                    str(self.input),
                    "--output",
                    str(destination),
                    "--force",
                )

    def test_outputs_cannot_replace_sources_or_keys(self):
        self.write_har([self.entry()])
        for output, key_path in (
            (self.input, self.key_path),
            (self.graph_path, self.input),
            (self.key_path, self.key_path),
        ):
            with self.assertRaises(ValueError):
                discover_to_file("lab", [self.input], key_path, output, authorized=True, force=True)
        self.assertFalse(self.key_path.exists())
        discover_to_file("lab", [self.input], self.key_path, self.graph_path, authorized=True)
        with self.assertRaises(ValueError):
            discover_to_file("lab", [self.input], self.key_path, self.graph_path, authorized=True)
        discover_to_file("lab", [self.input], self.key_path, self.graph_path, authorized=True, force=True)

    def test_burp_xml_raw_http_and_existing_idor_discovery_remain_compatible(self):
        inputs = []
        for account, identifier in (("owner", 1001), ("actor", 1002)):
            request = f"GET /api/orders/{identifier} HTTP/1.1\r\nHost: 127.0.0.1:8099\r\nAuthorization: Bearer lab-{account}\r\n\r\n"
            response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n" + json.dumps(
                {"success": True, "data": {"id": identifier, "marker": f"{account}-private-proof-{identifier}"}}
            )
            path = self.root / (account + ".xml")
            path.write_text(
                "<items><item><url>http://127.0.0.1:8099/api/orders/"
                + str(identifier)
                + '</url><request base64="true">'
                + base64.b64encode(request.encode()).decode()
                + '</request><response base64="true">'
                + base64.b64encode(response.encode()).decode()
                + "</response></item></items>"
            )
            inputs.append(path)
        graph = self.graph(paths=inputs)
        self.assertEqual(len(self.objects(graph, "order")), 2)
        proposal = discover_idor("lab", inputs[0], inputs[1])
        self.assertEqual(len(proposal.proposal["candidates"]), 1)
        self.assertFalse(discovery_summary(proposal)["confirmed"])
        raw = self.root / "request.http"
        raw.write_text("GET /api/orders/1001 HTTP/1.1\r\nHost: 127.0.0.1:8099\r\n\r\n")
        self.assertEqual(len(self.objects(self.graph(paths=[raw]))), 1)

    def test_synthetic_repository_example_is_offline_and_reviewable(self):
        path = Path(__file__).resolve().parents[1] / "examples/object-discovery/captures.har"
        graph = self.graph(paths=[path])
        self.assertEqual(len(self.objects(graph, "order")), 2)
        self.assertEqual(graph["summary"]["observations"], 5)
        rows = self.candidates(graph)
        self.assertTrue(rows[0]["researcher_review_required"])
        self.assertEqual(rows[0]["resource_type"], "order")


if __name__ == "__main__":
    unittest.main()
