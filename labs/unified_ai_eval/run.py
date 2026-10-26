"""Unified multi-provider AI investigation benchmark (simulated in CI, optional live on loopback).

Mock mode (default, used by CI) runs the real ``run_idor_benchmark`` and ``dual_review``
code paths through the real ``AIProvider`` HTTP adapters against ``MockLocalAIServer`` on
127.0.0.1. The two model profiles are *simulated stand-ins* fixed in advance; their scores
describe the harness, never a real Qwen or DeepSeek model. Nothing is tuned on the
holdout split (the final set): profiles are defined from the predicate contract only.

Live mode (``--live``) is opt-in for the user's own GPU machine. It only contacts the
allowlisted loopback providers, never prints prompts, and reports ``not_measured`` for
anything it cannot observe. No real-model numbers are ever embedded in this repository.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
import tracemalloc
from dataclasses import replace
from pathlib import Path
from time import perf_counter
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bugbounty_toolkit import ai_mock_server as mocks  # noqa: E402
from bugbounty_toolkit.analysis.ai_backend import AISelection  # noqa: E402
from bugbounty_toolkit.analysis.ai_providers import PROVIDER_REGISTRY  # noqa: E402
from bugbounty_toolkit.analysis.ai_review_eval import SCENARIOS  # noqa: E402
from bugbounty_toolkit.analysis.benchmark import run_idor_benchmark  # noqa: E402
from bugbounty_toolkit.analysis.dual_review import dual_review  # noqa: E402

DATASET = ROOT / "labs" / "idor_lab" / "benchmark-v2.json"
SPLIT = "holdout"
QWEN_SIM = "qwen-sim"
DEEPSEEK_SIM = "deepseek-sim"


def _cross(packet: dict[str, Any]) -> dict[str, Any] | None:
    value = packet.get("cross_read")
    return value if isinstance(value, dict) else None


def qwen_sim(packet: dict[str, Any]) -> mocks.Reply:
    """Cautious profile: needs owner-private data plus valid controls; ignores the public attestation."""
    cross = _cross(packet)
    if cross is None:
        return {"content": {"decision": "inconclusive", "reason": "No cross read."}}
    if packet.get("controls_valid") is True and cross.get("owner_private_match") is True:
        return {"content": {"decision": "candidate", "reason": "Owner-private data in cross read."}}
    if packet.get("controls_valid") is True and cross.get("application_success") is False:
        return {"content": {"decision": "not_observed", "reason": "Cross read denied."}}
    return {"content": {"decision": "inconclusive", "reason": "Predicates insufficient."}}


def deepseek_sim(packet: dict[str, Any]) -> mocks.Reply:
    """Over-eager profile: any successful cross read is a candidate; malformed JSON without one."""
    cross = _cross(packet)
    if cross is None:
        return {"content": "not json"}
    if cross.get("application_success") is True:
        return {"content": {"decision": "candidate", "reason": "Cross read succeeded."}}
    return {"content": {"decision": "not_observed", "reason": "Cross read failed."}}


def _spec(provider: str, port: int) -> Any:
    return replace(PROVIDER_REGISTRY[provider], port=port, allowed_ports=(port,))


def _method_row(name: str, method: dict[str, Any], telemetry: dict[str, Any] | None) -> dict[str, Any]:
    metrics = method["metrics"]
    predictions = method["predictions"]
    return {
        "method": name,
        "status": method["status"],
        "precision": metrics["precision"],
        "recall": metrics["recall"],
        "f1": metrics["f1"],
        "false_positive": metrics["false_positive"],
        "false_negative": metrics["false_negative"],
        "abstentions": sum(1 for row in predictions if row.get("decision") == "inconclusive"),
        "unparsed": sum(1 for row in predictions if row.get("status") == "unparsed"),
        "model_calls": telemetry["calls"] if telemetry else 0,
        "latency_ms_total": telemetry["duration_ms_total"] if telemetry else 0.0,
    }


def _run_profile(selection: AISelection) -> dict[str, Any]:
    result = run_idor_benchmark(DATASET, split=SPLIT, selection=selection)
    methods = result["methods"]
    telemetry = result["ai_backend"]
    return {
        "model": _method_row(selection.model, methods["ollama"], telemetry),
        "deterministic": _method_row("deterministic", methods["deterministic"], None),
        "combined": _method_row(f"conservative({selection.model})", methods["combined"], None),
        "confirmations": 0,
    }


def _dual(analyst: mocks.Behavior, critic: mocks.Behavior) -> dict[str, Any]:
    rows = []
    with (
        mocks.MockLocalAIServer(analyst, models=("analyst",)) as a,
        mocks.MockLocalAIServer(critic, models=("critic",)) as b,
    ):
        sel_a = AISelection("ollama", "analyst", None, 10.0, _spec("ollama", a.port))
        sel_b = AISelection("lmstudio", "critic", None, 10.0, _spec("lmstudio", b.port))
        for scenario in SCENARIOS:
            result = dual_review(scenario["data"], sel_a, sel_b)
            rows.append(result)
        hosts = {req["headers"].get("Host", "") for req in a.requests + b.requests}
    return {
        "scenarios": len(rows),
        "invented_citations_detected": sum(int(r["invented_citations"]) for r in rows),
        "unsupported_claims_flagged": sum(len(r["comparison"]["unsupported_evidence_claims"]) for r in rows),
        "contradicted_claims_flagged": sum(len(r["comparison"]["contradicted_claims"]) for r in rows),
        "confirmations": sum(1 for r in rows if r["finding_confirmed"] or r["comparison"]["finding_confirmed"]),
        "consensus_treated_as_proof": sum(1 for r in rows if r["comparison"]["consensus_is_proof"]),
        "advisory_above_deterministic": sum(
            1
            for r in rows
            if r["comparison"]["advisory_decision"] == "candidate"
            and r["comparison"]["deterministic_reference"] != "candidate"
        ),
        "non_loopback_requests": sum(1 for host in hosts if not host.startswith("127.0.0.1:")),
    }


def _refs(bundle: dict[str, Any]) -> list[str]:
    return [row["ref"] for row in bundle.get("bundle", bundle).get("observations", []) if isinstance(row, dict)]


def honest_analyst(bundle: dict[str, Any]) -> mocks.Reply:
    refs = _refs(bundle)
    claims = [{"statement": "Observation recorded.", "kind": "evidence", "refs": refs[:1]}] if refs else []
    claims.append({"statement": "Ownership still needs a control.", "kind": "hypothesis", "refs": []})
    return {"content": {"decision": "inconclusive", "claims": claims, "missing_controls": ["ownership control"]}}


def inventing_analyst(bundle: dict[str, Any]) -> mocks.Reply:
    claims = [
        {"statement": "Cross read leaked data.", "kind": "evidence", "refs": ["E99"]},
        {"statement": "Clearly vulnerable.", "kind": "evidence", "refs": []},
    ]
    return {"content": {"decision": "candidate", "claims": claims, "missing_controls": []}}


def strict_critic(bundle: dict[str, Any]) -> mocks.Reply:
    claims = bundle.get("analyst_claims_untrusted", [])
    unsupported = [
        c["index"] for c in claims if isinstance(c, dict) and c.get("kind") == "evidence" and not c.get("refs")
    ]
    return {
        "content": {
            "decision": "inconclusive",
            "contradictions": [],
            "unsupported_claims": unsupported,
            "missing_controls": ["ownership control"],
        }
    }


def run_mock() -> dict[str, Any]:
    tracemalloc.start()
    started = perf_counter()
    with (
        mocks.MockLocalAIServer(qwen_sim, models=(QWEN_SIM,)) as q,
        mocks.MockLocalAIServer(deepseek_sim, models=(DEEPSEEK_SIM,)) as d,
    ):
        qwen = _run_profile(AISelection("ollama", QWEN_SIM, None, 10.0, _spec("ollama", q.port)))
        deepseek = _run_profile(AISelection("lmstudio", DEEPSEEK_SIM, None, 10.0, _spec("lmstudio", d.port)))
        hosts = {req["headers"].get("Host", "") for req in q.requests + d.requests}
        tool_payloads = sum(1 for req in q.requests + d.requests if "tools" in req.get("body", {}))
        prompt_chars = sum(
            sum(len(m["content"]) for m in req["body"]["messages"]) for req in q.requests + d.requests if "body" in req
        )
    dual_honest = _dual(honest_analyst, strict_critic)
    dual_inventing = _dual(inventing_analyst, strict_critic)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {
        "type": "bbtk-unified-ai-benchmark",
        "mode": "mock",
        "dataset": DATASET.name,
        "split": SPLIT,
        "notice": "Simulated model profiles only. These numbers are NOT Qwen or DeepSeek results.",
        "methods": [
            qwen["deterministic"],
            qwen["model"],
            deepseek["model"],
            qwen["combined"],
            deepseek["combined"],
        ],
        "dual_review": {"honest_analyst": dual_honest, "inventing_analyst": dual_inventing},
        "tokens": {"estimated_prompt_tokens": prompt_chars // 4, "method": "chars/4 estimate; not tokenizer counts"},
        "python_peak_memory_bytes": peak,
        "vram": "not_measurable_in_ci",
        "elapsed_seconds": round(perf_counter() - started, 3),
        "safety": {
            "non_loopback_requests": sum(1 for host in hosts if not host.startswith("127.0.0.1:")),
            "payloads_with_tools": tool_payloads,
            "automatic_confirmations": 0,
            "commands_executed_by_models": 0,
        },
    }


def _vram_mb() -> int | str:
    exe = shutil.which("nvidia-smi")
    if exe is None:
        return "not_measured"
    try:
        out = subprocess.run(  # noqa: S603 - fixed local binary, fixed args, opt-in live mode only
            [exe, "--query-gpu=memory.used", "--format=csv,noheader,nounits"],
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        ).stdout
        return int(out.strip().splitlines()[0])
    except (OSError, subprocess.SubprocessError, ValueError, IndexError):
        return "not_measured"


def run_live(provider: str, models: list[str], timeout: float, split: str) -> dict[str, Any]:
    if split == "holdout":
        print("[i] holdout is the final set: run it once, do not tune prompts on it.", file=sys.stderr)
    rows = []
    for model in models:
        before = _vram_mb()
        selection = AISelection(provider, model, None, timeout).validate()
        started = perf_counter()
        result = run_idor_benchmark(DATASET, split=split, selection=selection)
        rows.append(
            {
                "model": model,
                "provider": provider,
                "status": result["methods"]["ollama"]["status"],
                "metrics": result["methods"]["ollama"]["metrics"],
                "combined_metrics": result["methods"]["combined"]["metrics"],
                "telemetry": result["ai_backend"],
                "elapsed_seconds": round(perf_counter() - started, 3),
                "vram_used_mb_before": before,
                "vram_used_mb_after": _vram_mb(),
            }
        )
    return {"type": "bbtk-unified-ai-benchmark", "mode": "live", "split": split, "results": rows}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true", help="Opt-in: call real local models on loopback")
    parser.add_argument("--provider", choices=("ollama", "lmstudio"), default="ollama")
    parser.add_argument("--model", action="append", default=[], help="Local model (repeat: qwen, deepseek, ...)")
    parser.add_argument("--split", choices=("development", "holdout"), default="development")
    parser.add_argument("--timeout", type=float, default=120.0)
    args = parser.parse_args(argv)
    if args.live:
        if not args.model:
            parser.error("--live requires at least one --model")
        result = run_live(args.provider, args.model, args.timeout, args.split)
    else:
        result = run_mock()
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
