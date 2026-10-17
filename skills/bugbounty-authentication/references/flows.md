# Authentication Flow Review

Choose the user's requested category; these are not an automatic execution queue.

| Category | Necessary controls and boundaries |
| --- | --- |
| Login/default credentials | Known own accounts and explicit attempt cap/lockout policy; no credential spraying or automatic wordlist |
| Session cookies/fixation | Compare own pre/post-login session rotation and invalidation; preserve CSRF/session pairing and do not expose session values |
| Password reset | Own account and inbox; bound reset deliveries, verify actual trusted reset destination, no third-party emails |
| MFA | Own enrolled test factors and recovery path; no automatic disabling, exhaustion or account locking |
| OAuth | Own client/test accounts and reviewed redirect origins; no token delivery to unapproved destinations |
| Cookie/parameter tampering | Exact reviewed field and expected behavior; do not infer success from reflected input or change permissions silently |

`SecLists/Passwords/Common-Credentials/best1050.txt` is a password collection, not an access-control wordlist. See the [official Common-Credentials directory](https://github.com/danielmiessler/SecLists/tree/master/Passwords/Common-Credentials) and verify the local checkout's filename. Its inclusion as a reference does not enable guessing; this toolkit has no password-guessing adapter. Offline secret testing is also separate from online authentication.

`requests`, `aiohttp` and `httpx` are available via the `http` extra, but direct clients do not inherit the toolkit's scope, no-redirect policy, rate limiter or evidence redaction. Prefer the scoped request executor for live replays. Beautiful Soup/lxml (`xss` extra) can inspect saved login forms offline; parsing a page does not establish a bypass. PyJWT (`jwt` extra) does not establish a session or authorize server-side claim changes.

Read the [OWASP authentication testing guide](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/04-Authentication_Testing/README) for the selected flow. Burp [Intruder](https://portswigger.net/burp/documentation/desktop/tools/intruder) is a separate manual tool, not something the skill starts. No alternative client or scanner should be used to evade a failed control, rate limit or scope restriction.
