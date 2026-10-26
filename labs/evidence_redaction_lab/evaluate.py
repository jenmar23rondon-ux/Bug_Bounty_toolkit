"""Offline canary + performance evaluation for destination-aware redaction."""

from __future__ import annotations

import json
import socket
import time
import tracemalloc
from typing import Any

from bugbounty_toolkit.core.redaction import (
    RESIDUAL_RISKS,
    UNRECOGNIZED_FORMATS,
    RedactionDestination,
    detect_truncation,
    provenance_digest,
    pseudonymize_identifier,
    redact_for,
    scrub_model_output,
)
from labs.evidence_redaction_lab.canaries import (
    ALL_CANARIES,
    adversarial_text,
    large_body,
    private_payload,
    shareable_payload,
)


def _count_leaks(text: str) -> list[str]:
    return [canary for canary in ALL_CANARIES if canary in text]


def evaluate() -> dict[str, Any]:
    network: list[str] = []
    real_connect = socket.socket.connect

    def guard(self: socket.socket, address: Any) -> None:  # noqa: ANN001
        network.append(str(address))
        raise OSError("network disabled in evidence redaction lab")

    socket.socket.connect = guard  # type: ignore[method-assign]
    try:
        payload = shareable_payload()
        # Baseline-style minimized redaction (legacy default destination).
        before = redact_for(RedactionDestination.MINIMIZED_ARTIFACT, payload)
        before_text = json.dumps(before.value, ensure_ascii=True)
        before_leaks = _count_leaks(before_text)

        shareable = redact_for(RedactionDestination.SHAREABLE_REPORT, payload)
        shareable_text = json.dumps(shareable.value, ensure_ascii=True)
        shareable_leaks = _count_leaks(shareable_text)

        console = redact_for(RedactionDestination.CONSOLE_SUMMARY, payload)
        console_leaks = _count_leaks(json.dumps(console.value, ensure_ascii=True))

        model = redact_for(RedactionDestination.MODEL_INPUT, payload)
        model_leaks = _count_leaks(json.dumps(model.value, ensure_ascii=True))

        private = redact_for(RedactionDestination.PRIVATE_EVIDENCE, private_payload())
        private_text = json.dumps(private.value, ensure_ascii=True)
        # Private destination may retain session markers for authorized validation.
        private_usable = "private-marker-owner" in private_text and ("b" * 64) in private_text

        ai_raw = adversarial_text()
        scrubbed, changed = scrub_model_output(ai_raw)
        ai_leaks = _count_leaks(scrubbed)

        # Performance on large body
        body = large_body(200_000)
        tracemalloc.start()
        t0 = time.perf_counter()
        large_result = redact_for(RedactionDestination.SHAREABLE_REPORT, body, max_chars=2_000_000)
        large_ms = round((time.perf_counter() - t0) * 1000, 3)
        _current, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        large_leaks = _count_leaks(str(large_result.value))

        # Bounds / truncation
        over = redact_for(RedactionDestination.SHAREABLE_REPORT, "y" * 1000, max_chars=100)
        trunc = detect_truncation(1000, 100, claimed_complete=True)

        digest = provenance_digest("secret-preimage-should-not-appear")
        pseudo = pseudonymize_identifier("account-99")

        false_positives = 0
        benign = "The status token count is five and the report is ready."
        scrubbed_benign = redact_for(RedactionDestination.SHAREABLE_REPORT, benign).value
        if scrubbed_benign != benign and "token count" not in str(scrubbed_benign):
            # Only count if the sentence meaning was destroyed incorrectly.
            false_positives += 1

        return {
            "network_attempts": len(network),
            "canaries_total": len(ALL_CANARIES),
            "before_shareable_policy": {
                "destination": "minimized_artifact",
                "leaked_canaries": len(before_leaks),
                "leaked_values": before_leaks,
                "chars_out": before.chars_out,
                "elapsed_ms": before.elapsed_ms,
            },
            "after_shareable_policy": {
                "destination": "shareable_report",
                "leaked_canaries": len(shareable_leaks),
                "leaked_values": shareable_leaks,
                "chars_out": shareable.chars_out,
                "elapsed_ms": shareable.elapsed_ms,
                "truncated": shareable.truncated,
            },
            "console_leaks": len(console_leaks),
            "model_input_leaks": len(model_leaks),
            "ai_output_scrub": {
                "changed": changed,
                "leaks": len(ai_leaks),
                "leaked_values": ai_leaks,
            },
            "private_evidence_usable": private_usable,
            "large_body": {
                "chars_in": large_result.chars_in,
                "elapsed_ms": large_ms,
                "peak_memory_kib": round(peak / 1024, 1),
                "leaks": len(large_leaks),
            },
            "bounds": {
                "oversize_truncated": over.truncated,
                "truncation_validity": trunc,
            },
            "provenance_digest_is_hash_only": len(digest) == 64 and "secret-preimage" not in digest,
            "pseudonym_distinct": pseudo.startswith("bbtk-id-") and "account-99" not in pseudo,
            "false_positive_probe": false_positives,
            "unrecognized_formats": list(UNRECOGNIZED_FORMATS),
            "residual_risks": list(RESIDUAL_RISKS),
            "absolute_privacy_claimed": False,
        }
    finally:
        socket.socket.connect = real_connect  # type: ignore[method-assign]


def main() -> None:
    print(json.dumps(evaluate(), indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
