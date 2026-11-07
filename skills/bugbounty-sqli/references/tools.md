# SQLi Resources

| Resource | Actual role | Official source |
| --- | --- | --- |
| PayloadsAllTheThings | Reference, no automatic payload expansion | [SQL Injection](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection) |
| SecLists | Reviewed local subsets | [Fuzzing/Databases](https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/Databases) |
| sqlmap | Detection argv drafts only, no execution adapter | [Usage](https://github.com/sqlmapproject/sqlmap/wiki/Usage) |
| sqlparse | Offline syntax parsing via the `sqli` extra | [Docs](https://sqlparse.readthedocs.io/) |
| sqlite3 | Python standard library, no connection by the analyzer | [Docs](https://docs.python.org/3/library/sqlite3.html) |
| PyMySQL / psycopg2 | Optional `databases` extra for separately authorized DB work | [PyMySQL](https://pymysql.readthedocs.io/), [psycopg2](https://www.psycopg.org/docs/) |

The opt-in delay syntax is based on the DBMS documentation for [PostgreSQL `pg_sleep`](https://www.postgresql.org/docs/current/functions-datetime.html#FUNCTIONS-DATETIME-DELAY), [MySQL `SLEEP`](https://dev.mysql.com/doc/refman/8.0/en/miscellaneous-functions.html#function_sleep), and [SQL Server `WAITFOR`](https://learn.microsoft.com/en-us/sql/t-sql/language-elements/waitfor-transact-sql). Application query shape and driver settings still determine whether a probe is syntactically applicable.

SecLists Linux paths are case-sensitive: `Fuzzing/Databases`, not an assumed lowercase path. Do not assume `Fuzzing/SQLi` exists. `blind-sqli` is an ambiguous package name, not an installed dependency.

```bash
python -m pip install -e ".[sqli]"
bugbounty sqli my-program --routes inputs/routes.txt --parameters inputs/parameters.txt --rate 0.1 --max-tests 6 --dry-run
bugbounty sqli my-program --routes inputs/routes.txt --parameters inputs/parameters.txt --deep --max-tests 8 --dry-run
bugbounty analyze sql --input registros/my-program/own-query.sql
bugbounty tool-plan my-program --tool sqlmap --url "http://localhost:3000/search?q=1" --parameter q --dry-run
```

The bounded `--deep` mode issues exactly three 3-second delay variants (MySQL, PostgreSQL, MSSQL) and two boolean true/false pairs separated by a second baseline, after the baseline/quote probes. Each complete parameter group costs eleven requests. The comparison threshold is a 2500ms increase above the measured baseline, not an absolute response duration. Timing remains a candidate. A boolean body delta confirms only when the second pair matches the first and the intervening baseline matches the first baseline; otherwise the boolean rows are inconclusive. Dynamic content and jitter are not execution proof. DBMS error text is a fingerprint, not a promotion. `--bypass` adds at most 15 packaged payloads and cannot confirm. OOB needs explicitly authorized callback destinations and is not implemented. Never turn a finding into `--dbs`, `--tables`, `--dump`, an OS/SQL shell or credential retrieval by default. Read the shared [external-plan limitations](../../bugbounty-executor/references/security-tools.md) before reviewing a separate sqlmap run.
