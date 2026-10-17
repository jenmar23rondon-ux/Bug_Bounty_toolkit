from __future__ import annotations


def deduplicate_results(results: list[dict[str, object]]) -> list[dict[str, object]]:
    seen: set[tuple[object, object, object, object, object]] = set()
    unique: list[dict[str, object]] = []
    for item in results:
        key = (
            item.get("url"),
            item.get("status"),
            item.get("length"),
            item.get("words"),
            item.get("lines"),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(item)
    return unique
