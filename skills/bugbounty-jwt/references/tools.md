# JWT Tools

Install `python -m pip install -e ".[jwt]"` for PyJWT, python-jose, cryptography and jwcrypto. The built-in analyzer uses PyJWT; the other libraries are available for separately reviewed cryptographic workflows.

```bash
bugbounty analyze jwt --input registros/my-program/token.private.txt
bugbounty analyze jwt --input registros/my-program/token.private.txt --key-file registros/my-program/public-key.pem --algorithm RS256 --issuer https://issuer.example --audience own-test-app
```

The output excludes tokens, keys and claim values. Unverified decoding reports claim names and key-reference presence. Verification requires/checks `exp` and separately records issuer/audience checks; do not describe an unchecked field as validated.

| Tool | Role | Official source |
| --- | --- | --- |
| PyJWT | Offline inspection and explicit verification | [API and algorithm warning](https://pyjwt.readthedocs.io/en/stable/api.html) |
| python-jose | Optional JOSE library | [Project](https://github.com/mpdavis/python-jose) |
| cryptography | Optional cryptographic primitives | [Docs](https://cryptography.io/) |
| jwcrypto | Optional JWK/JWE handling | [Docs](https://jwcrypto.readthedocs.io/) |
| jwt_tool | Manual, no execution adapter | [Project](https://github.com/ticarpi/jwt_tool) |
| JWT Editor | Separate Burp extension | [Project](https://github.com/PortSwigger/jwt-editor) |
| hashcat / John | Separate offline review of specifically authorized material | [hashcat](https://hashcat.net/hashcat/), [John](https://www.openwall.com/john/) |
| jwt.io | Reference only, never upload live tokens | [Site](https://jwt.io/) |

Do not mix RSA public keys into HMAC verification or trust token-supplied algorithms/key locations. Token editing, weak-secret testing and forged-token acceptance need explicit separate test material and authorization. Libraries and tool availability do not authorize live account changes or privilege escalation.
