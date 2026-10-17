from __future__ import annotations


ALGORITHMS = ("HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA")


def inspect_jwt(token: str, key: bytes | None = None, algorithm: str | None = None,
                issuer: str | None = None, audience: str | None = None) -> dict:
    if not token or len(token) > 65536 or token.count(".") != 2:
        raise ValueError("Expected one compact JWS token (maximum 64 KiB), not a cookie or request.")
    if (key is None) != (algorithm is None) or (algorithm is not None and algorithm not in ALGORITHMS):
        raise ValueError("Verification requires a local key and one explicitly allowed algorithm.")
    if key is None and (issuer is not None or audience is not None):
        raise ValueError("Issuer/audience checks require signature verification.")
    try:
        import jwt
    except ImportError as exc:
        raise ValueError('Install JWT analysis with: python -m pip install ".[jwt]"') from exc
    try:
        header = jwt.get_unverified_header(token)
        raw_algorithm = header.get("alg")
        if not isinstance(raw_algorithm, str) or not raw_algorithm or len(raw_algorithm) > 32:
            raise ValueError("Invalid algorithm header.")
        claims = jwt.decode(token, options={"verify_signature": False})
        if key is not None:
            claims = jwt.decode(token, key, algorithms=[algorithm], issuer=issuer, audience=audience,
                                options={"require": ["exp"], "verify_aud": audience is not None})
    except (jwt.PyJWTError, ValueError, TypeError) as exc:
        raise ValueError("JWT parsing or verification failed; token/key content is not logged.") from exc
    warnings = []
    safe_algorithm = raw_algorithm if raw_algorithm in ALGORITHMS or raw_algorithm == "none" else "unsupported"
    if safe_algorithm == "unsupported":
        warnings.append("unsupported_algorithm")
    if header.get("alg") == "none":
        warnings.append("unsigned_algorithm")
    if "jku" in header or "x5u" in header:
        warnings.append("untrusted_key_url_present_not_fetched")
    if key is None:
        warnings.append("decoded_claims_are_untrusted")
    if audience is None:
        warnings.append("audience_not_checked")
    if issuer is None:
        warnings.append("issuer_not_checked")
    return {"algorithm": safe_algorithm, "claim_names": sorted(claims),
            "has_kid": "kid" in header, "has_jku": "jku" in header, "has_x5u": "x5u" in header,
            "signature_verified": key is not None, "expiration_checked": key is not None,
            "issuer_checked": issuer is not None, "audience_checked": audience is not None,
            "warnings": warnings, "confirmed_vulnerability": False}
