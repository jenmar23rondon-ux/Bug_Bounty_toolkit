import base64
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import patch

from bugbounty_toolkit import cli
from bugbounty_toolkit.burp_import import extract_item_artifacts, normalize_raw_request, parse_sitemap


class BurpImportTests(unittest.TestCase):
    def test_sitemap_deduplicates_routes_parameters_and_ignores_static_assets(self):
        xml = b"""<items>
          <item><url>https://target.example/api/items?id=7&amp;view=full</url></item>
          <item><url>https://target.example/api/items?id=8&amp;view=compact</url></item>
          <item><url>https://target.example/assets/app.js?v=1</url></item>
          <item><url>https://target.example/assets/site.css</url></item>
          <item><url>not-a-url</url></item>
        </items>"""
        result = parse_sitemap(xml, "https://target.example")
        self.assertEqual(result.routes, ["/api/items?id=7&view=full", "/api/items?id=8&view=compact"])
        self.assertEqual(result.parameters, ["id", "view"])
        self.assertEqual(result.ignored_static, 2)
        self.assertEqual(result.ignored_items, 1)

    def test_sitemap_extracts_form_names_and_redacts_sensitive_query_values(self):
        request = (
            "POST /search HTTP/1.1\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nq=term&csrf_token=private"  # noqa: E501
        )
        encoded = base64.b64encode(request.encode()).decode()
        xml = f'<items><item><url>https://target.example/search?q=term&amp;session=private</url><request base64="true">{encoded}</request></item></items>'.encode()  # noqa: E501
        result = parse_sitemap(xml, "https://target.example")
        self.assertEqual(result.routes, ["/search?q=term&session=%5Bredacted%5D"])
        self.assertEqual(result.parameters, ["q", "session", "csrf_token"])

    def test_raw_post_body_is_preserved_and_sensitive_values_are_redacted(self):
        request = (
            b"POST /api/items?access_token=query-secret HTTP/1.1\r\n"
            b"Host: target.example\r\nAuthorization: Bearer header-secret\r\n"
            b"Cookie: sessionid=cookie-secret\r\nContent-Type: application/json\r\n"
            b"Content-Length: 71\r\n\r\n"
            b'{"name":"keep-this","token":"body-secret","description":"full body"}'
        )
        normalized = normalize_raw_request(request)
        self.assertIn("POST /api/items?access_token=%5Bredacted%5D HTTP/1.1", normalized)
        self.assertIn('"name": "keep-this"', normalized)
        self.assertIn('"description": "full body"', normalized)
        for secret in ("header-secret", "cookie-secret", "query-secret", "body-secret", "Content-Length"):
            self.assertNotIn(secret, normalized)
        self.assertIn("Authorization: [redacted]", normalized)
        self.assertIn("Cookie: [redacted]", normalized)

    def test_saved_item_extracts_html_and_jwt_without_putting_header_into_html(self):
        token = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.signature"
        response = (
            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
            f"Set-Cookie: access_token={token}; HttpOnly; Secure\r\n\r\n"
            "<!doctype html><html><body><h1>Captured page</h1></body></html>"
        )
        request = f"GET / HTTP/1.1\r\nAuthorization: Bearer {token}\r\n\r\n"
        xml = (
            "<items><item>"
            f'<request base64="true">{base64.b64encode(request.encode()).decode()}</request>'
            f'<response base64="true">{base64.b64encode(response.encode()).decode()}</response>'
            "</item></items>"
        ).encode()
        item = extract_item_artifacts(xml)
        self.assertIn("Captured page", item.html or "")
        self.assertNotIn(token, item.html or "")
        self.assertEqual(item.jwts, [token])

    def test_malformed_sitemap_has_clear_error(self):
        with self.assertRaisesRegex(ValueError, "sitemap XML is malformed"):
            parse_sitemap(b"<items><item>")

    def test_cli_dry_run_does_not_create_output_directories_or_send_network(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sitemap = root / "sitemap.xml"
            sitemap.write_text("<items><item><url>https://target.example/a</url></item></items>", encoding="utf-8")
            args = cli.build_parser().parse_args(
                [
                    "import",
                    "burp",
                    "sample",
                    "--sitemap",
                    str(sitemap),
                    "--base-url",
                    "https://target.example",
                    "--dry-run",
                ]
            )
            output = StringIO()
            with (
                patch.object(cli, "RECORDS_ROOT", root / "records"),
                patch("socket.create_connection", side_effect=AssertionError("Burp import must stay offline")),
                redirect_stdout(output),
            ):
                args.func(args)
            self.assertFalse((root / "records" / "sample" / "inputs").exists())
            self.assertIn("would create", output.getvalue())
            self.assertIn("no network requests sent", output.getvalue())

    def test_cli_refuses_overwrite_without_force(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sitemap = root / "sitemap.xml"
            sitemap.write_text("<items><item><url>https://target.example/a</url></item></items>", encoding="utf-8")
            target = root / "records" / "sample" / "inputs" / "routes.txt"
            target.parent.mkdir(parents=True)
            target.write_text("existing route\n", encoding="utf-8")
            args = cli.build_parser().parse_args(
                ["import", "burp", "sample", "--sitemap", str(sitemap), "--base-url", "https://target.example"]
            )
            with patch.object(cli, "RECORDS_ROOT", root / "records"), self.assertRaisesRegex(ValueError, "--force"):
                args.func(args)
            self.assertEqual(target.read_text(encoding="utf-8"), "existing route\n")

    def test_cli_force_overwrites_and_reports_changed_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sitemap = root / "sitemap.xml"
            sitemap.write_text("<items><item><url>https://target.example/a</url></item></items>", encoding="utf-8")
            target = root / "records" / "sample" / "inputs" / "routes.txt"
            target.parent.mkdir(parents=True)
            target.write_text("old\n", encoding="utf-8")
            args = cli.build_parser().parse_args(
                [
                    "import",
                    "burp",
                    "sample",
                    "--sitemap",
                    str(sitemap),
                    "--base-url",
                    "https://target.example",
                    "--force",
                ]
            )
            output = StringIO()
            with patch.object(cli, "RECORDS_ROOT", root / "records"), redirect_stdout(output):
                args.func(args)
            self.assertEqual(target.read_text(encoding="utf-8"), "/a\n")
            self.assertIn("Imported:", output.getvalue())


if __name__ == "__main__":
    unittest.main()
