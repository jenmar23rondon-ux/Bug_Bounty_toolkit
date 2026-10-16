# SQLi Resources

| Resource | Actual role | Official source |
| --- | --- | --- |
| PayloadsAllTheThings | Reference, no automatic payload expansion | [SQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection) |
| SecLists | Reviewed local subsets | [Fuzzing/Databases](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/Databases) |
| sqlmap | Detection argv drafts only, no execution adapter | [Usage](https://github.com/sqlmapproject/sqlmap/wiki/Usage) |
| sqlparse | Offline syntax parsing via the `sqli` extra | [Docs](https://sqlparse.readthedocs.io/) |
| sqlite3 | Python standard library, no connection by the analyzer | [Docs](https://docs.python.org/3/library/sqlite3.html) |
| PyMySQL / psycopg2 | Optional `databases` extra for separately authorized DB work | [PyMySQL](https://pymysql.readthedocs.io/), [psycopg2](https://www.psycopg.org/docs/) |

SecLists Linux paths are case-sensitive: `Fuzzing/Databases`, not an assumed lowercase path. Do not assume `Fuzzing/SQLi` exists. `blind-sqli` is an ambiguous package name, not an installed dependency.

```bash
python -m pip install -e ".[sqli]"
bugbounty sqli my-program --routes inputs/routes.txt --parameters inputs/parameters.txt --rate 0.1 --max-tests 6 --dry-run
bugbounty analyze sql --input registros/my-program/own-query.sql
bugbounty tool-plan my-program --tool sqlmap --url "http://localhost:3000/search?q=1" --parameter q --dry-run
```

Error-based changes need reproducible baseline controls. Boolean comparisons need stable content and true/false controls; timing needs repeated matched controls to distinguish jitter and must not create load; OOB needs explicitly authorized callback destinations. These are methodology topics, not features of the built-in quote probes. Never turn a finding into `--dbs`, `--tables`, `--dump`, an OS/SQL shell or credential retrieval by default. Read the shared [external-plan limitations](../../bugbounty-executor/references/security-tools.md) before reviewing a separate sqlmap run.
