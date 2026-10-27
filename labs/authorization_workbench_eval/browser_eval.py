"""Optional local-browser QA; all page requests are fulfilled by ASGI, never sent."""

from __future__ import annotations

import json
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit
from fastapi.testclient import TestClient
from playwright.sync_api import Route, sync_playwright
from labs.authorization_workbench_eval.fixtures import populate
from bugbounty_toolkit.dashboard import create_app


def evaluate_browser(executable: str, screenshot: str | None = None) -> None:
    with tempfile.TemporaryDirectory() as tmp:
        paths = populate(Path(tmp))
        with (
            TestClient(
                create_app(paths.root, paths.program), base_url="http://127.0.0.1", client=("127.0.0.1", 1234)
            ) as client,
            sync_playwright() as p,
        ):
            browser = p.chromium.launch(
                executable_path=executable, headless=True, args=["--no-sandbox", "--disable-background-networking"]
            )
            page = browser.new_page(viewport={"width": 1440, "height": 1100})
            unexpected = []

            def route(request_route: Route) -> None:
                u = urlsplit(request_route.request.url)
                if u.hostname != "127.0.0.1":
                    unexpected.append(u.hostname)
                    request_route.abort()
                    return
                response = client.get(u.path + ("?" + u.query if u.query else ""))
                request_route.fulfill(
                    status=response.status_code, headers=dict(response.headers), body=response.content
                )

            page.route("**/*", route)
            errors = []
            page.on("pageerror", lambda e: errors.append(str(e)))
            page.goto("http://127.0.0.1/authorization-workbench")
            page.locator("#a option").nth(1).wait_for(state="attached")
            page.select_option("#a", "ev-lab@0")
            page.select_option("#b", "ev-lab@1")
            page.select_option("#c", "ev-lab@5")
            start = time.perf_counter()
            page.get_by_role("button", name="Comparar capturas").click()
            page.locator("#fields tr").nth(9).wait_for()
            elapsed = (time.perf_counter() - start) * 1000
            assert page.locator("#columns article").count() == 3
            assert page.locator("#fields tr").count() == 10
            assert page.locator(".difference").count() > 0
            page.locator("#highlight").uncheck()
            assert page.locator(".difference").count() == 0
            page.locator("#highlight").check()
            # Optional screenshot is a local artifact, never captured HTTP content.
            if screenshot:
                page.screenshot(path=screenshot, full_page=True)
            print(
                json.dumps(
                    {
                        "browser_dom_render_ms": round(elapsed, 3),
                        "render_method": "headless Chrome; Playwright requests fulfilled by local ASGI TestClient; includes click and automation overhead",
                        "browser_errors": errors,
                        "external_requests": unexpected,
                    }
                )
            )
            assert not errors and not unexpected
            page.set_viewport_size({"width": 390, "height": 844})
            assert page.locator("#columns article").count() == 3
            browser.close()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--executable", required=True)
    parser.add_argument("--screenshot")
    args = parser.parse_args()
    evaluate_browser(args.executable, args.screenshot)
