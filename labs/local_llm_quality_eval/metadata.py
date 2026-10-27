"""Reproducibility metadata for a real local Qwen / DeepSeek run.

Live numbers that were not executed are ``NOT_MEASURED`` with a reason.
Prompt/schema identity and minimized packet hashes describe this commit and
the frozen corpus; they are not model scores. Simulated mock-final numbers are
copied only as a labelled historical reference.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from bugbounty_toolkit import __version__
from bugbounty_toolkit.analysis.dual_review import (
    ANALYST_PROMPT,
    ANALYST_SCHEMA,
    CRITIC_PROMPT,
    CRITIC_SCHEMA,
    SCHEMA_VERSION as DUAL_SCHEMA_VERSION,
)
from bugbounty_toolkit.analysis.multi_review import (
    BUNDLE_SCHEMA_VERSION,
    MODEL_OUTPUT_SCHEMA,
    RESULT_SCHEMA_VERSION,
    _SYSTEM_PROMPT,
    build_evidence_bundle,
)

from . import corpus, discovery

METADATA_SCHEMA = "bbtk.local-llm-rtx3060-metadata.v1"
EVAL_SCHEMA = "bbtk.local-llm-rtx3060-eval.v1"
NOT_MEASURED = "NOT_MEASURED"
LAB_ROOT = Path(__file__).resolve().parent
MOCK_FINAL = LAB_ROOT / "results" / "mock-final.json"
CONFIGS = {
    "A": "deterministic only (no AI)",
    "B": "Qwen alone",
    "C": "DeepSeek alone",
    "D": "Qwen analyst + DeepSeek critic",
    "E": "DeepSeek analyst + Qwen critic",
}
LIVE_METRICS = (
    "accuracy",
    "precision",
    "recall",
    "f1",
    "false_positive_rate",
    "false_negative_rate",
    "abstention_rate",
    "valid_structured_output_rate",
    "invented_citations",
    "missing_control_recall",
    "contradictions_handled",
    "candidates_without_support",
    "automatic_confirmations",
    "decision_stability_across_repeats",
    "latency_ms_median",
    "latency_ms_p95",
    "tokens_in",
    "tokens_out",
    "tokens_per_second",
    "wall_time_s",
    "vram_used_mb",
)
AUTHORITY: dict[str, Any] = {
    "finding_confirmed": False,
    "ai_classification_authority": False,
    "tools_enabled": False,
    "tool_calling_enabled": False,
    "model_output_executed": False,
    "evidence_ledger_modified": False,
    "final_labels_modified": False,
    "classification_primary": "deterministic",
}


def _sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _sha256_json(value: Any) -> str:
    blob = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    return _sha256_text(blob)


def not_measured(reason: str) -> dict[str, str]:
    return {"value": NOT_MEASURED, "reason": reason}


def measured_value(value: Any, reason: str) -> dict[str, Any]:
    if value is None or value in {NOT_MEASURED, "not_measured"}:
        return not_measured(reason)
    return {"value": value, "reason": None}


def prompt_schema_identity() -> dict[str, Any]:
    """Identity of the prompts and schemas shipped in this commit. No model is called."""
    return {
        "measured": True,
        "requires_model": False,
        "single_review_schema": RESULT_SCHEMA_VERSION,
        "bundle_schema": BUNDLE_SCHEMA_VERSION,
        "dual_review_schema": DUAL_SCHEMA_VERSION,
        "single_prompt_sha256": _sha256_text(_SYSTEM_PROMPT),
        "analyst_prompt_sha256": _sha256_text(ANALYST_PROMPT),
        "critic_prompt_sha256": _sha256_text(CRITIC_PROMPT),
        "single_output_schema_sha256": _sha256_json(MODEL_OUTPUT_SCHEMA),
        "analyst_schema_sha256": _sha256_json(ANALYST_SCHEMA),
        "critic_schema_sha256": _sha256_json(CRITIC_SCHEMA),
    }


def packet_manifest(split: str) -> dict[str, Any]:
    """Hash the minimized model view of each frozen scenario. Labels are not hashed."""
    scenarios, labels = corpus.load(split)
    packets: list[dict[str, str]] = []
    leaks = 0
    for scenario in scenarios:
        bundle = build_evidence_bundle(scenario["data"])
        model_view = {
            "evidence_bundle_id": bundle["evidence_bundle_id"],
            "topic": bundle["topic"],
            "observations": bundle["observations"],
        }
        blob = json.dumps(model_view, sort_keys=True, ensure_ascii=True)
        label = labels[scenario["id"]]
        if any(canary in blob for canary in corpus.CANARIES) or "SYSTEM OVERRIDE" in blob:
            leaks += 1
        if label["family"] in blob or "expected_decision" in blob:
            leaks += 1
        packets.append({"id": scenario["id"], "sha256": _sha256_text(blob)})
    aggregate = _sha256_text("\n".join(row["sha256"] for row in packets))
    return {
        "split": split,
        "count": len(packets),
        "packet_sha256": aggregate,
        "packets": packets,
        "labels_included": False,
        "secret_leaks_in_packets": leaks,
        "measured": True,
        "requires_model": False,
    }


def corpus_status() -> dict[str, Any]:
    problems = corpus.verify()
    manifest = (corpus.CORPUS_DIR / corpus.MANIFEST).read_text(encoding="utf-8")
    return {
        "verified": not problems,
        "problems": problems,
        "manifest_sha256": _sha256_text(manifest),
        "labels_modified": False,
        "manifest": manifest.splitlines(),
    }


def _model_field(models: dict[str, Any] | None, slot: str, key: str, reason: str) -> dict[str, Any]:
    if not models or slot not in models:
        return not_measured(reason)
    raw = models[slot].get(key)
    if raw in (None, "", "not_exposed"):
        return {"value": "not_exposed", "reason": "provider_does_not_expose_" + key}
    return {"value": raw, "reason": None}


def reproducibility(
    *,
    measured: bool,
    reason: str,
    inventory: dict[str, Any],
    temperature: float,
    seed: int | None,
    models: dict[str, Any] | None,
    elapsed_s: float | None,
    tokens_in: int | None,
    tokens_out: int | None,
    vram_used_mb_before: int | str | None = None,
    vram_used_mb_after: int | str | None = None,
) -> dict[str, Any]:
    """Metadata block. Model, timing and token fields stay ``NOT_MEASURED`` until a live run."""
    raw_gpu = inventory.get("gpu")
    gpu: dict[str, Any] = raw_gpu if isinstance(raw_gpu, dict) else {}
    gpu_reason = str(gpu.get("reason") or "no_gpu")
    if gpu.get("present"):
        gpu_name: dict[str, Any] = {"value": gpu.get("name"), "reason": None}
        vram_total: dict[str, Any] = {"value": gpu.get("vram_total_mib"), "reason": None}
        driver: dict[str, Any] = {"value": gpu.get("driver"), "reason": None}
    else:
        gpu_name = not_measured(gpu_reason)
        vram_total = not_measured(gpu_reason)
        driver = not_measured(gpu_reason)
    if measured:
        temperature_field: dict[str, Any] = {
            "value": float(temperature),
            "applied": True,
            "reason": None,
            "source": "GenerationLimits.temperature forwarded by the existing loopback adapter",
        }
    else:
        temperature_field = {
            "value": NOT_MEASURED,
            "configured_default": float(temperature),
            "applied": False,
            "reason": reason,
        }
    seed_field: dict[str, Any] = {
        "value": NOT_MEASURED,
        "applied": False,
        "requested_seed": seed,
        "reason": "ai_provider_adapter_has_no_seed_parameter",
    }
    metric_reason = reason if not measured else "not_exposed"
    return {
        "schema_version": METADATA_SCHEMA,
        "model_digest": {
            "B": _model_field(models, "B", "digest", reason),
            "C": _model_field(models, "C", "digest", reason),
        },
        "quantization": {
            "B": _model_field(models, "B", "quantization", reason),
            "C": _model_field(models, "C", "quantization", reason),
        },
        "gpu": gpu_name,
        "vram": {
            "total_mib": vram_total,
            "used_mb_before": measured_value(vram_used_mb_before, metric_reason),
            "used_mb_after": measured_value(vram_used_mb_after, metric_reason),
        },
        "driver": driver,
        "temperature": temperature_field,
        "seed": seed_field,
        "prompt_schema": prompt_schema_identity(),
        "packet_hash": {"dev": packet_manifest("dev"), "final": packet_manifest("final")},
        "wall_time_s": measured_value(elapsed_s, reason),
        "tokens_in": measured_value(tokens_in, reason if not measured else "token_counts_not_exposed"),
        "tokens_out": measured_value(tokens_out, reason if not measured else "token_counts_not_exposed"),
        "token_method": "chars/4 estimate inside the harness when a live response exists; not tokenizer counts",
    }


def live_metric_block(reason: str) -> dict[str, dict[str, str]]:
    return {metric: not_measured(reason) for metric in LIVE_METRICS}


def frozen_mock_reference() -> dict[str, Any]:
    """Historical mock-final numbers, verbatim. B–E are simulated profiles."""
    document = json.loads(MOCK_FINAL.read_text(encoding="utf-8"))
    configs: dict[str, Any] = {}
    for key, cfg in document["configs"].items():
        quality = cfg["quality"]
        configs[key] = {
            "name": cfg["name"],
            "kind": "deterministic_no_model" if key == "A" else "SIMULATED_not_a_real_model",
            "real_model": False,
            "accuracy": quality["accuracy"],
            "precision": quality["precision"],
            "recall": quality["recall"],
            "f1": quality["f1"],
            "false_positive_rate": quality["false_positive_rate"],
            "abstention_rate": quality["abstention_rate"],
            "valid_structured_output_rate": quality["valid_structured_output_rate"],
            "invented_citations": quality["invented_citations"],
            "missing_control_recall": quality["missing_control_recall"],
            "automatic_confirmations": quality["automatic_confirmations"],
            "latency_kind": cfg["performance"]["latency_kind"],
        }
    return {
        "source": "labs/local_llm_quality_eval/results/mock-final.json",
        "schema_version": document["schema_version"],
        "mode": document["mode"],
        "split": document["split"],
        "repeats": document["repeats"],
        "notice": document["notice"],
        "configs": configs,
    }


def _quality_ready(configs: dict[str, Any]) -> bool:
    return all(isinstance(configs.get(key), dict) and isinstance(configs[key].get("quality"), dict) for key in "ABCDE")


def _ci_strictly_above(higher: Any, lower: Any) -> bool:
    if not isinstance(higher, list) or not isinstance(lower, list) or len(higher) != 2 or len(lower) != 2:
        return False
    try:
        return float(higher[0]) > float(lower[1])
    except (TypeError, ValueError):
        return False


def compare_to_baseline(result: dict[str, Any]) -> dict[str, Any]:
    """Compare already-measured scores. Does not retune rules or confirm a finding.

    A single model can be named as a second opinion when its false-positive rate
    is lower at recall at least the deterministic recall. Dual review is
    recommended for classification only when its consensus interval sits strictly
    above that single model and the production advisory rule did not merely
    abstain. Classification authority stays with the deterministic engine.
    """
    base: dict[str, Any] = {
        **AUTHORITY,
        "deterministic_remains_primary": True,
        "dual_review_recommended_for_classification": False,
        "dual_review_may_confirm": False,
        "preferred_second_opinion": None,
        "reason": "scores_absent",
    }
    configs = result.get("configs")
    if not isinstance(configs, dict) or not _quality_ready(configs):
        return base
    if any(configs[key]["quality"].get("automatic_confirmations") for key in "ABCDE"):
        base["reason"] = "automatic_confirmations_present_recommendation_withheld"
        return base
    deterministic = configs["A"]["quality"]
    det_recall = deterministic.get("recall")
    det_fpr = deterministic.get("false_positive_rate")
    eligible: list[tuple[str, float, float]] = []
    if isinstance(det_recall, (int, float)) and isinstance(det_fpr, (int, float)):
        for key in ("B", "C"):
            quality = configs[key]["quality"]
            recall = quality.get("recall")
            fpr = quality.get("false_positive_rate")
            if isinstance(recall, (int, float)) and isinstance(fpr, (int, float)) and recall >= det_recall:
                eligible.append((key, float(fpr), float(recall)))
    preferred: str | None = None
    if eligible:
        eligible.sort(key=lambda item: (item[1], -item[2]))
        best_key, best_fpr, _recall = eligible[0]
        if best_fpr < float(det_fpr):
            preferred = best_key
    dual_ok = False
    dual_reason = "dual_review_not_shown_to_beat_best_single"
    if preferred is not None:
        single_ci = configs[preferred]["quality"].get("accuracy_ci95")
        for key in ("D", "E"):
            production = configs[key]["quality"]
            if production.get("abstention_rate") == 1.0 or production.get("recall") == 0:
                if not dual_ok:
                    dual_reason = "production_advisory_rule_abstains"
                continue
            consensus = configs[key].get("quality_consensus_rule")
            if not isinstance(consensus, dict):
                continue
            delta = configs[key].get("dual_vs_analyst_single_consensus_rule")
            extra = delta.get("extra_calls_per_net_improvement") if isinstance(delta, dict) else None
            extra_ok = isinstance(extra, (int, float)) and not isinstance(extra, bool)
            if _ci_strictly_above(consensus.get("accuracy_ci95"), single_ci) and extra_ok:
                dual_ok = True
                dual_reason = f"{key}_consensus_separates_from_{preferred}"
    if preferred is None:
        lead = "no_single_model_improved_fpr_at_recall_at_least_the_deterministic_baseline"
    else:
        lead = f"second_opinion_candidate_{preferred}_has_lower_fpr"
    base["preferred_second_opinion"] = preferred
    base["dual_review_recommended_for_classification"] = dual_ok
    base["reason"] = lead + "; " + dual_reason
    return base


def _secret_leak_count(document: dict[str, Any]) -> int:
    blob = json.dumps(document, ensure_ascii=True)
    leaks = sum(blob.count(canary) for canary in corpus.CANARIES)
    if "SYSTEM OVERRIDE" in blob:
        leaks += 1
    return leaks


def recommendation_text(reasons: list[str]) -> str:
    joined = ", ".join(reasons) if reasons else "not_executed"
    return (
        "Deterministic engine remains the classification primary. "
        f"Live Qwen and DeepSeek metrics are NOT_MEASURED ({joined}). "
        "Dual review is not recommended for classification: no real-model measurement exists, "
        "and on simulated profiles the production advisory rule only abstains. "
        "AI has no tools and no final classification authority. "
        "Simulated mock scores are not real-model results."
    )


def build_not_measured_report(*, temperature: float = 0.0, seed: int | None = None) -> dict[str, Any]:
    """Documentary report. Every live metric is ``NOT_MEASURED``. No model is called."""
    inventory = discovery.discover()
    reasons = [str(item) for item in inventory.get("reasons", [])]
    if "no_gpu" in reasons:
        metric_reason = "no_gpu"
    elif "model_absent" in reasons:
        metric_reason = "model_absent"
    elif reasons:
        metric_reason = reasons[0]
    else:
        metric_reason = "not_executed"
    report: dict[str, Any] = {
        "schema_version": EVAL_SCHEMA,
        "metadata_schema": METADATA_SCHEMA,
        "mode": "not_measured",
        "measurement_status": NOT_MEASURED,
        "primary_reason": metric_reason,
        "reasons": reasons,
        "version": __version__,
        **AUTHORITY,
        "deterministic_remains_primary": True,
        "dual_review_recommended_for_classification": False,
        "dual_review_may_confirm": False,
        "preferred_second_opinion": NOT_MEASURED,
        "recommendation": recommendation_text(reasons),
        "model_download_attempted": False,
        "external_requests": inventory["external_requests"],
        "network_attempts": inventory["network_attempts"],
        "loopback_probes": inventory["loopback_probes"],
        "corpus": corpus_status(),
        "reproducibility": reproducibility(
            measured=False,
            reason=metric_reason,
            inventory=inventory,
            temperature=temperature,
            seed=seed,
            models=None,
            elapsed_s=None,
            tokens_in=None,
            tokens_out=None,
        ),
        "matrix": {
            key: {"name": name, "real_model": False, "live": live_metric_block(metric_reason)}
            for key, name in CONFIGS.items()
        },
        "frozen_historical_reference": frozen_mock_reference(),
        "discovery": inventory,
        "notice": (
            "Live Qwen/DeepSeek metrics are NOT_MEASURED. "
            "frozen_historical_reference configs B-E are SIMULATED profiles, not Qwen or DeepSeek scores. "
            "Config A in that file is the deterministic engine on the frozen FINAL split, not a new FINAL run."
        ),
    }
    packet_leaks = sum(
        int(report["reproducibility"]["packet_hash"][split]["secret_leaks_in_packets"]) for split in ("dev", "final")
    )
    report["secret_leaks"] = _secret_leak_count(report) + packet_leaks
    return report


def token_total(result: dict[str, Any], field: str) -> int | None:
    """Sum integer token estimates. A missing or non-integer estimate yields None."""
    configs = result.get("configs")
    if not isinstance(configs, dict) or not configs:
        return None
    total = 0
    for cfg in configs.values():
        if not isinstance(cfg, dict):
            return None
        performance = cfg.get("performance")
        if not isinstance(performance, dict):
            return None
        value = performance.get(field)
        if isinstance(value, bool) or not isinstance(value, int):
            return None
        total += value
    return total
