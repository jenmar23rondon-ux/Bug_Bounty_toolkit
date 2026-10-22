from __future__ import annotations


def analyze_sql(query: str) -> dict:
    try:
        import sqlparse
    except ImportError as exc:
        raise ValueError('Install SQL analysis with: python -m pip install ".[sqli]"') from exc
    statements = sqlparse.parse(query)
    return {
        "statement_count": len(statements),
        "statement_types": [statement.get_type() for statement in statements],
        "executed": False,
        "confirmed_vulnerability": False,
        "note": "SQL syntax analysis does not prove SQL injection; no database connection is opened.",
    }
