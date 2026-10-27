from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
from pathlib import Path
import secrets
import socket
import sys
import tempfile
import types
import unittest
from unittest.mock import patch

from bugbounty_toolkit import burp_passive_bridge as bridge
from bugbounty_toolkit.burp_import import captured_response
from labs.burp_passive_bridge_eval.corpus import ORIGIN, TIME, capture, corpus


def repack(raw, change):
    document = json.loads(raw)
    change(document["payload"])
    document["sha256"] = hashlib.sha256(bridge._canonical(document["payload"])).hexdigest()
    return bridge._canonical(document)


class PassiveBridgeTests(unittest.TestCase):
    def inspect(self, entries):
        return bridge.inspect_bytes(bridge.envelope("lab", entries), project="lab", origins=[ORIGIN])

    def test_final_pairing_metadata_and_existing_evidence_importer(self):
        with patch.object(socket.socket, "connect", side_effect=AssertionError("Network forbidden")):
            preview = self.inspect(corpus())
            self.assertEqual(len(preview.captures), 50)
            for index, item in enumerate(preview.captures):
                self.assertEqual(item.timestamp, TIME)
                self.assertEqual(item.exchange.request.method, "GET")
                self.assertEqual(item.exchange.request.url, f"{ORIGIN}/items/{index}")
                self.assertEqual(captured_response(item.exchange).body_text, '{"item":' + str(index) + "}")
            bundle = bridge.evidence_bundle(preview)
            self.assertEqual(len(bundle["records"]), 50)
            self.assertEqual(bundle["bundle_id"], hashlib.sha256(bridge._canonical(bundle["records"])).hexdigest()[:24])
            self.assertTrue(
                all(row["provenance"][0]["locator"].startswith("burp-passive:") for row in bundle["records"])
            )
            self.assertEqual(bundle["vulnerabilities_confirmed"], 0)

    def test_missing_response_two_accounts_duplicates_and_stable_locators(self):
        entries = [capture(1), capture(1, account=2), capture(1), capture(2, missing=True)]
        preview = self.inspect(entries)
        self.assertEqual((len(preview.captures), preview.duplicates, preview.rejected), (3, 1, 0))
        self.assertIsNone(preview.captures[-1].exchange.raw_response)
        self.assertEqual(preview.captures[0].locator, self.inspect(entries).captures[0].locator)
        self.assertTrue(preview.captures[-1].locator.endswith("/3"))

    def test_private_file_no_overwrite_no_duplicate_storage(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "capture.json"
            preview = bridge.export_selected(path, "lab", [ORIGIN], [capture(1), capture(1)], authorized=True)
            self.assertEqual(preview.duplicates, 1)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(len(json.loads(path.read_bytes())["payload"]["entries"]), 1)
            result = bridge.import_private(path, project="lab", origins=[ORIGIN], authorized=True)
            self.assertEqual(len(result.captures), 1)
            before = path.read_bytes()
            with self.assertRaises(ValueError):
                bridge.export_selected(path, "lab", [ORIGIN], [capture(2)], authorized=True)
            self.assertEqual(path.read_bytes(), before)
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                bridge.import_private(path, project="lab", origins=[ORIGIN], authorized=True)

    def test_scope_host_absolute_target_and_encoding_rejections(self):
        entries = [
            capture(0),
            bridge.Selection("https://other.invalid", capture(1).request),
            bridge.Selection(ORIGIN, b"GET / HTTP/1.1\r\nHost: other.invalid\r\n\r\n"),
            bridge.Selection(ORIGIN, b"GET https://other.invalid/ HTTP/1.1\r\nHost: other.invalid\r\n\r\n"),
            bridge.Selection(ORIGIN, b"GET / HTTP/1.1\r\nHost: lab.invalid\r\n\r\n\xff"),
        ]
        preview = self.inspect(entries)
        self.assertEqual((len(preview.captures), preview.rejected), (1, 4))

    def test_corruption_interruption_version_project_duplicate_keys(self):
        raw = bridge.envelope("lab", [capture(1)])
        cases = [
            raw[:40],
            b"\xff",
            raw.replace(b'"lab"', b'"bad"'),
            repack(raw, lambda p: p.update(schema="bbtk.burp-passive/2")),
            repack(raw, lambda p: p.update(project="different")),
            b'{"payload":{},"payload":{},"sha256":"x"}',
            b"[" * 3000,
        ]
        for value in cases:
            with self.subTest(size=len(value)), self.assertRaisesRegex(ValueError, "Bridge file refused"):
                bridge.inspect_bytes(value, project="lab", origins=[ORIGIN])

    def test_canary_never_in_summary_or_errors(self):
        secret = secrets.token_urlsafe(32)
        preview = self.inspect([capture(1, secret=secret)])
        public = json.dumps(preview.summary())
        self.assertNotIn(secret, public)
        self.assertNotIn("lab.invalid", public)
        self.assertNotIn("Cookie", public)
        raw = bridge.envelope("lab", [capture(1, secret=secret)])
        with self.assertRaises(ValueError) as error:
            bridge.inspect_bytes(raw, project=secret, origins=[ORIGIN])
        self.assertNotIn(secret, str(error.exception))
        self.assertIsNone(error.exception.__cause__)

    def test_hard_limits_bad_framing_and_base64(self):
        with self.assertRaises(ValueError):
            bridge.envelope("lab", [capture(1)] * 101)
        with self.assertRaises(ValueError):
            bridge.envelope("lab", [bridge.Selection(ORIGIN, b"a" * (bridge.MAX_MESSAGE_BYTES + 1))])
        raw = bridge.envelope("lab", [capture(1)])
        bad = repack(
            raw,
            lambda p: p["entries"][0].update(
                response=base64.b64encode(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nx").decode()
            ),
        )
        self.assertEqual(bridge.inspect_bytes(bad, project="lab", origins=[ORIGIN]).rejected, 1)
        bad = repack(raw, lambda p: p["entries"][0].update(request="!"))
        self.assertEqual(bridge.inspect_bytes(bad, project="lab", origins=[ORIGIN]).rejected, 1)
        with patch.object(bridge, "MAX_FILE_BYTES", 5), self.assertRaises(ValueError):
            bridge.inspect_bytes(raw, project="lab", origins=[ORIGIN])

    def test_attestation_symlink_and_atomic_interruption(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private.json"
            with self.assertRaises(ValueError):
                bridge.export_selected(path, "lab", [ORIGIN], [capture(1)])
            with self.assertRaises(ValueError):
                bridge.import_private(path, project="lab", origins=[ORIGIN])
            with patch("os.link", side_effect=OSError("interrupted")), self.assertRaises(ValueError):
                bridge.export_selected(path, "lab", [ORIGIN], [capture(1)], authorized=True)
            self.assertFalse(path.exists())
            self.assertEqual(list(Path(directory).iterdir()), [])
            target = Path(directory) / "target"
            target.write_bytes(b"untouched")
            path.symlink_to(target)
            with self.assertRaises(ValueError):
                bridge.export_selected(path, "lab", [ORIGIN], [capture(1)], authorized=True)
            self.assertEqual(target.read_bytes(), b"untouched")

    def test_legacy_extension_wire_compatible_and_no_active_registration(self):
        modules = {}
        for name in (
            "burp",
            "java",
            "java.util",
            "java.nio",
            "java.nio.file",
            "java.nio.file.attribute",
            "javax",
            "javax.swing",
        ):
            modules[name] = types.ModuleType(name)
        modules["burp"].IBurpExtender = type("IBurpExtender", (), {})
        modules["burp"].IContextMenuFactory = type("IContextMenuFactory", (), {})
        for module, names in (
            ("java.util", ["ArrayList"]),
            ("java.nio.file", ["Files", "Paths", "StandardCopyOption"]),
            ("java.nio.file.attribute", ["PosixFilePermissions"]),
            ("javax.swing", ["JMenuItem", "JOptionPane"]),
        ):
            for name in names:
                setattr(modules[module], name, object())
        path = Path(__file__).resolve().parents[1] / "labs/burp_passive_bridge_eval/extension/BurpExtender.py"
        with patch.dict(sys.modules, modules):
            spec = importlib.util.spec_from_file_location("passive_extension", path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            callbacks = unittest.mock.Mock()
            module.BurpExtender().registerExtenderCallbacks(callbacks)
            self.assertEqual(
                [call[0] for call in callbacks.method_calls], ["setExtensionName", "registerContextMenuFactory"]
            )
            entries = json.loads(bridge.envelope("lab", [capture(1)]))["payload"]["entries"]
            raw = module.build_transfer("lab", entries)
            self.assertEqual(len(bridge.inspect_bytes(raw, project="lab", origins=[ORIGIN]).captures), 1)

        # Execute the real extension export method against a mocked Java/Burp surface.
        class JavaPath:
            def __init__(self, value):
                self.path = Path(value)

            def isAbsolute(self):
                return self.path.is_absolute()

            def normalize(self):
                return self

            def getParent(self):
                return None if self.path == self.path.parent else JavaPath(self.path.parent)

            def resolve(self, name):
                return JavaPath(self.path / name)

            def __eq__(self, other):
                return isinstance(other, JavaPath) and self.path == other.path

        import os

        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "extension.json"
            temporary = Path(directory) / "pending"
            ui = unittest.mock.Mock()
            ui.YES_NO_OPTION = 0
            ui.YES_OPTION = 0
            ui.showInputDialog.side_effect = ["lab", ORIGIN, str(destination)]
            ui.showConfirmDialog.return_value = 0
            module.JOptionPane = ui
            module.Paths = types.SimpleNamespace(get=JavaPath)
            module.java_home = lambda: directory
            module.PosixFilePermissions = types.SimpleNamespace(
                toString=lambda value: "rwx------", asFileAttribute=lambda value: value, fromString=lambda value: value
            )

            def write_private(path, value):
                path.path.touch(mode=0o600)
                path.path.write_bytes(value)

            module.Files = types.SimpleNamespace(
                exists=lambda path: path.path.name != ".git" and path.path.exists(),
                isSymbolicLink=lambda path: path.path.is_symlink(),
                getPosixFilePermissions=lambda path: None,
                getOwner=lambda path: "mock-user",
                createTempFile=lambda *args: JavaPath(temporary),
                write=write_private,
                createLink=lambda path, source: os.link(source.path, path.path),
                deleteIfExists=lambda path: path.path.unlink(missing_ok=True),
            )
            module.base64 = types.SimpleNamespace(b64encode=lambda value: base64.b64encode(value).decode())
            service = types.SimpleNamespace(
                getProtocol=lambda: "https", getHost=lambda: "lab.invalid", getPort=lambda: 443
            )
            selected = capture(9)
            message = types.SimpleNamespace(
                getHttpService=lambda: service,
                getRequest=lambda: selected.request,
                getResponse=lambda: selected.response,
            )
            callbacks = unittest.mock.Mock()
            callbacks.getHelpers.return_value = types.SimpleNamespace(
                bytesToString=lambda value: value.decode("iso-8859-1"),
                stringToBytes=lambda value: value.encode("iso-8859-1"),
                analyzeRequest=lambda value: types.SimpleNamespace(getUrl=lambda: ORIGIN + "/items/9"),
            )
            callbacks.isInScope.return_value = True
            extension = module.BurpExtender()
            extension.registerExtenderCallbacks(callbacks)
            with patch.object(socket.socket, "connect", side_effect=AssertionError("Network forbidden")):
                extension.export([message, message])
            self.assertTrue(destination.exists(), ui.showMessageDialog.call_args)
            preview = bridge.import_private(destination, project="lab", origins=[ORIGIN], authorized=True)
            self.assertEqual(len(preview.captures), 1)
            self.assertIsNone(preview.captures[0].timestamp)
            self.assertFalse(temporary.exists())
            self.assertIn("duplicates: 1", ui.showConfirmDialog.call_args.args[1])

    def test_cli_preview_private_bundle_and_content_free_error(self):
        from contextlib import redirect_stdout, redirect_stderr
        from io import StringIO

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            source = path / "transfer.json"
            bridge.export_selected(source, "lab", [ORIGIN], [capture(1)], authorized=True)
            args = [
                "bridge",
                str(source),
                "--project",
                "lab",
                "--origin",
                ORIGIN,
                "--attest-authorized-captures",
                "--report",
                str(path / "review.json"),
                "--private-bundle",
                str(path / "bundle.json"),
            ]
            output = StringIO()
            with patch.object(sys, "argv", args), redirect_stdout(output):
                bridge.main()
            self.assertEqual(json.loads(output.getvalue())["accepted"], 1)
            self.assertNotIn(ORIGIN, output.getvalue())
            self.assertEqual((path / "bundle.json").stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads((path / "bundle.json").read_bytes())["records"][0]["method"], "GET")
            with (
                patch.object(sys, "argv", args),
                redirect_stderr(StringIO()) as errors,
                self.assertRaises(SystemExit) as exit_code,
            ):
                bridge.main()
            self.assertEqual(exit_code.exception.code, 2)
            self.assertNotIn(str(source), errors.getvalue())

    def test_private_storage_refuses_git_and_permissive_parent(self):
        with tempfile.TemporaryDirectory() as directory:
            parent = Path(directory)
            git = parent / ".git"
            git.mkdir()
            (git / "HEAD").write_text("ref: refs/heads/example")
            with self.assertRaises(ValueError):
                bridge.export_selected(parent / "x", "lab", [ORIGIN], [capture(1)], authorized=True)
            (git / "HEAD").unlink()
            git.rmdir()
            parent.chmod(0o755)
            with self.assertRaises(ValueError):
                bridge.export_selected(parent / "x", "lab", [ORIGIN], [capture(1)], authorized=True)
