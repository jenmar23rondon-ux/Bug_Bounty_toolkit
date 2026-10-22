from __future__ import annotations

from typing import Any


def parse_html_document(document: str, parser: str = "html.parser") -> Any:
    if parser not in {"html.parser", "lxml", "html5lib"}:
        raise ValueError("Unsupported HTML parser.")
    try:
        from bs4 import BeautifulSoup, FeatureNotFound
    except ImportError as exc:
        raise ValueError('Install HTML analysis with: python -m pip install ".[csrf]" or ".[xss]"') from exc
    try:
        soup = BeautifulSoup(document, parser)
    except FeatureNotFound as exc:
        raise ValueError("The selected parser is not installed; install the xss extra.") from exc
    return soup


def analyze_html(document: str, marker: str, parser: str = "html.parser") -> dict:
    if not marker or len(marker) > 256:
        raise ValueError("A nonempty marker of at most 256 characters is required.")
    source_reflected = marker in document
    soup = parse_html_document(document, parser)
    from bs4 import Comment

    contexts = set()
    for text in soup.find_all(string=lambda value: value and marker in value):
        parent = text.parent.name if text.parent else ""
        context = "comment" if isinstance(text, Comment) else parent if parent in {"script", "style"} else "html_text"
        contexts.add((context, parent, ""))
    for tag in soup.find_all(True):
        if source_reflected and marker.lower() in tag.name.lower():
            contexts.add(("tag_name", tag.name, ""))
        for attribute, value in tag.attrs.items():
            if source_reflected and marker.lower() in attribute.lower():
                contexts.add(("attribute_name", tag.name, attribute))
            values = value if isinstance(value, list) else [value]
            if not any(marker in str(item) for item in values) and marker not in " ".join(map(str, values)):
                continue
            kind = (
                "event_attribute"
                if attribute.lower().startswith("on")
                else "url_attribute"
                if attribute.lower() in {"href", "src", "action", "formaction"}
                else "attribute"
            )
            contexts.add((kind, tag.name, attribute))
    return {
        "parser": parser,
        "reflected": source_reflected or bool(contexts),
        "source_reflected": source_reflected,
        "confirmed": False,
        "contexts": [
            {"context": kind, "tag": tag, "attribute": attribute} for kind, tag, attribute in sorted(contexts)
        ],
        "note": "Parsing locates a marker; it does not execute JavaScript or confirm XSS.",
    }
