from __future__ import annotations

import contextlib
import io
import tempfile
import unittest
from pathlib import Path

from bugbounty_toolkit.cli import build_parser, cmd_wordlists
from bugbounty_toolkit.fuzzing.wordlist_manager import (
    MAX_ENTRY_BYTES,
    WordlistCollection,
    default_prepared_root,
    default_registry_path,
    detect_local_collections,
    inspect_wordlist,
    list_wordlists,
    load_collections,
    prepare_wordlist,
    preview_wordlist,
    recommend_wordlists,
    register_collection,
    scan_collections,
)


class WordlistManagerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.registry = self.root / "config" / "wordlists.json"
        self.collection_path = self.root / "seclists"
        (self.collection_path / "Discovery" / "Web-Content" / "api").mkdir(parents=True)
        (self.collection_path / "Discovery" / "Web-Content" / "routes").mkdir(parents=True)
        (self.collection_path / "Fuzzing" / "XSS").mkdir(parents=True)
        (self.collection_path / "Fuzzing" / "SQLi").mkdir(parents=True)
        (self.collection_path / "Discovery" / "Web-Content").joinpath("api", "api-endpoints.txt").write_text(
            "users\norders\nusers\n", encoding="utf-8"
        )
        (self.collection_path / "Discovery" / "Web-Content" / "routes" / "routes.txt").write_text(
            "health\norders\n", encoding="utf-8"
        )
        (self.collection_path / "Fuzzing" / "XSS" / "xss-payloads.txt").write_text("marker-xss\n", encoding="utf-8")
        (self.collection_path / "Fuzzing" / "SQLi" / "sql.txt").write_text("marker-sql\n", encoding="utf-8")
        self.collection = register_collection(self.registry, "seclists", self.collection_path)

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_registry_round_trip_and_duplicate_rejection(self) -> None:
        items = load_collections(self.registry)
        self.assertEqual(items, [self.collection])
        with self.assertRaisesRegex(ValueError, "already registered"):
            register_collection(self.registry, "SECLISTS", self.collection_path)
        with self.assertRaisesRegex(ValueError, "already registered"):
            register_collection(self.registry, "other", self.collection_path)

    def test_malformed_registry_is_reported(self) -> None:
        self.registry.write_text("{broken", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "Cannot read wordlist registry"):
            load_collections(self.registry)

    def test_category_inference_and_recommendation(self) -> None:
        files = list_wordlists([self.collection])
        categories = {item.path.name: item.category for item in files}
        self.assertEqual(categories["api-endpoints.txt"], "api")
        self.assertEqual(categories["routes.txt"], "endpoints")
        self.assertEqual(categories["xss-payloads.txt"], "xss")
        self.assertEqual(categories["sql.txt"], "sqli")
        recommended = recommend_wordlists([self.collection], "endpoints")
        self.assertEqual({item.path.name for item in recommended}, {"api-endpoints.txt", "routes.txt"})
        with self.assertRaisesRegex(ValueError, "specific category"):
            recommend_wordlists([self.collection], "other")

    def test_explicit_collection_category_overrides_path_inference(self) -> None:
        categorized = WordlistCollection("custom-api", self.collection_path, "custom")
        self.assertTrue(all(item.category == "custom" for item in list_wordlists([categorized])))
        self.assertEqual(len(recommend_wordlists([categorized], "custom")), 4)

    def test_collection_walk_skips_hidden_directories(self) -> None:
        hidden = self.collection_path / ".git"
        hidden.mkdir()
        (hidden / "secret.txt").write_text("ignored\n", encoding="utf-8")
        self.assertNotIn("secret.txt", {item.path.name for item in list_wordlists([self.collection])})

    def test_collection_walk_does_not_follow_symlinked_directories(self) -> None:
        link = self.collection_path / "linked"
        try:
            link.symlink_to(self.collection_path / "Fuzzing", target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("Directory symlinks are unavailable in this environment")
        self.assertEqual(sum(item.path.name == "xss-payloads.txt" for item in list_wordlists([self.collection])), 1)

    def test_scan_dry_run_does_not_write_and_scan_registers_unique_paths(self) -> None:
        scan_registry = self.root / "scan.json"
        candidates = [("seclists", self.collection_path), ("seclists", self.collection_path)]
        preview = scan_collections(scan_registry, candidates, dry_run=True)
        self.assertEqual(len(preview), 1)
        self.assertFalse(scan_registry.exists())
        added = scan_collections(scan_registry, candidates)
        self.assertEqual(len(added), 1)
        self.assertEqual(load_collections(scan_registry), added)

    def test_scan_detect_uses_environment_roots_without_network_or_walk(self) -> None:
        detected = detect_local_collections({"SECLISTS_DIR": str(self.collection_path)}, home=self.root / "home")
        self.assertIn(("seclists", self.collection_path.resolve()), detected)

    def test_inspect_stream_counts_unique_duplicates_invalid_and_format_lines(self) -> None:
        path = self.root / "mixed.txt"
        path.write_bytes(
            b"\xef\xbb\xbfalpha\n# comment\n\nalpha\nbeta\n\xff\nnull\x00byte\n" + b"x" * (MAX_ENTRY_BYTES + 1) + b"\n"
        )
        result = inspect_wordlist(path, rate=2, large_file_warning_bytes=1, preview_limit=2)
        self.assertEqual(result.entry_count, 3)
        self.assertEqual(result.unique_entries, 2)
        self.assertEqual(result.duplicate_entries, 1)
        self.assertEqual(result.blank_lines, 1)
        self.assertEqual(result.comment_lines, 1)
        self.assertEqual(result.invalid_lines, 3)
        self.assertEqual(result.preview, ("alpha", "beta"))
        self.assertEqual(result.requests_estimate, 2)
        self.assertEqual(result.minimum_seconds, 1)
        self.assertTrue(result.large_file_warning)

    def test_inspect_rejects_invalid_limits(self) -> None:
        path = self.root / "valid.txt"
        path.write_text("one\n", encoding="utf-8")
        for kwargs in ({"rate": 0}, {"large_file_warning_bytes": 0}, {"preview_limit": -1}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                inspect_wordlist(path, **kwargs)

    def test_preview_is_bounded_and_skips_blank_comments(self) -> None:
        path = self.root / "preview.txt"
        path.write_text("# comment\n\nfirst\nsecond\nthird\n", encoding="utf-8")
        self.assertEqual(preview_wordlist(path, 2), ["first", "second"])
        self.assertEqual(preview_wordlist(path, 0), [])
        with self.assertRaises(ValueError):
            preview_wordlist(path, -1)

    def test_prepare_combines_matching_lists_deduplicates_and_estimates(self) -> None:
        output = self.root / "prepared" / "endpoints.txt"
        result = prepare_wordlist([self.collection], "endpoints", output, max_entries=10, rate=2)
        self.assertEqual(output.read_text(encoding="utf-8"), "users\norders\nhealth\n")
        self.assertEqual(result.unique_entries, 3)
        self.assertEqual(result.duplicate_entries, 2)
        self.assertEqual(result.requests_estimate, 3)
        self.assertEqual(result.minimum_seconds, 1.5)
        self.assertFalse(result.limit_reached)

    def test_prepare_cap_only_reports_reached_when_more_unique_entries_exist(self) -> None:
        exact = self.root / "exact.txt"
        exact_result = prepare_wordlist([self.collection], "xss", exact, max_entries=1)
        self.assertFalse(exact_result.limit_reached)
        capped = self.root / "capped.txt"
        result = prepare_wordlist([self.collection], "endpoints", capped, max_entries=2)
        self.assertTrue(result.limit_reached)
        self.assertEqual(result.unique_entries, 2)
        self.assertEqual(capped.read_text(encoding="utf-8"), "users\norders\n")

    def test_prepare_dry_run_does_not_create_output_or_parent(self) -> None:
        output = self.root / "not-created" / "prepared.txt"
        result = prepare_wordlist([self.collection], "endpoints", output, max_entries=2, dry_run=True)
        self.assertTrue(result.limit_reached)
        self.assertFalse(output.parent.exists())
        self.assertFalse(output.exists())

    def test_prepare_never_overwrites_without_force_and_force_replaces(self) -> None:
        output = self.root / "existing.txt"
        output.write_text("original\n", encoding="utf-8")
        with self.assertRaisesRegex(FileExistsError, "use --force"):
            prepare_wordlist([self.collection], "xss", output, max_entries=2)
        self.assertEqual(output.read_text(encoding="utf-8"), "original\n")
        prepare_wordlist([self.collection], "xss", output, max_entries=2, force=True)
        self.assertEqual(output.read_text(encoding="utf-8"), "marker-xss\n")

    def test_prepare_rejects_output_inside_source_collection(self) -> None:
        output = self.collection_path / "prepared.txt"
        with self.assertRaisesRegex(ValueError, "outside registered source"):
            prepare_wordlist([self.collection], "endpoints", output, max_entries=10)

    def test_prepare_rejects_bad_category_cap_rate_and_no_match(self) -> None:
        for kwargs in ({"max_entries": 0}, {"max_entries": 1_000_001}, {"max_entries": 1, "rate": 0}):
            options = {"max_entries": 1, **kwargs}
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                prepare_wordlist([self.collection], "endpoints", self.root / "x", **options)
        with self.assertRaisesRegex(ValueError, "No local wordlists"):
            prepare_wordlist([self.collection], "parameters", self.root / "x", max_entries=10)

    def test_wordlists_cli_prepare_dry_run_and_parser(self) -> None:
        parser = build_parser()
        args = parser.parse_args(
            [
                "wordlists",
                "prepare",
                "--category",
                "endpoints",
                "--max-entries",
                "2",
                "--output",
                str(self.root / "cli-output.txt"),
                "--dry-run",
                "--registry",
                str(self.registry),
            ]
        )
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            cmd_wordlists(args)
        self.assertIn("Would prepare 2 unique entries", output.getvalue())
        self.assertIn("duplicates removed: 1", output.getvalue())
        self.assertIn("not written", output.getvalue())
        self.assertFalse((self.root / "cli-output.txt").exists())

    def test_wordlists_cli_inspect_works_without_registry_argument(self) -> None:
        path = self.root / "inspect.txt"
        path.write_text("one\none\ntwo\n", encoding="utf-8")
        args = build_parser().parse_args(["wordlists", "inspect", str(path), "--rate", "2"])
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            cmd_wordlists(args)
        self.assertIn("unique: 2", output.getvalue())
        self.assertIn("minimum at 2/s: 1.0s", output.getvalue())

    def test_registry_path_helpers_are_user_local(self) -> None:
        registry = default_registry_path({"LOCALAPPDATA": str(self.root / "local")}, self.root / "home")
        prepared = default_prepared_root({"LOCALAPPDATA": str(self.root / "local")}, self.root / "home")
        self.assertIn("wordlists.json", str(registry))
        self.assertIn("prepared", str(prepared))
        self.assertNotEqual(registry.parent, self.root)


if __name__ == "__main__":
    unittest.main()
