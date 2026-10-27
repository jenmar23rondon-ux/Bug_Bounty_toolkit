# Manual vs bbtk on the disposable investigator lab

Fixture results only. Human timing is NOT_MEASURED.

| Split | Arm | Cases | Correct | Valid found | FP accepted | FN | Conservative abstain | Over-reject | Actions | Tool switches | External | Secret leaks | finding_confirmed true | Checklist mean |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| dev | manual | 9 | 9 | 4 | 0 | 0 | 0 | 0 | 63 | 36 | 0 | 0 | 0 | 5.0 |
| dev | bbtk | 9 | 9 | 4 | 0 | 0 | 0 | 0 | 81 | 72 | 0 | 0 | 0 | 5.0 |
| final | manual | 12 | 12 | 3 | 0 | 0 | 0 | 0 | 84 | 48 | 0 | 0 | 0 | 5.0 |
| final | bbtk | 12 | 9 | 3 | 0 | 0 | 2 | 1 | 108 | 96 | 0 | 0 | 0 | 5.0 |
| stress | manual | 10 | 10 | 3 | 0 | 0 | 0 | 0 | 70 | 40 | 0 | 0 | 0 | 5.0 |
| stress | bbtk | 10 | 9 | 3 | 1 | 0 | 0 | 0 | 90 | 80 | 0 | 0 | 0 | 5.0 |

## NOT_MEASURED

| Item | Reason |
| --- | --- |
| human_minutes | No human investigator was timed. Scripted wall-clock is not researcher time. |
| human_manual_actions | Scripted action counts are a checklist replay, not observed human clicks. |
| human_researcher_errors | No human reviewer participated. |
| human_dossier_quality | The checklist score is paperwork completeness, not a human quality judgment. |
| human_time_to_first_reviewable | No human clock was started. |
| human_time_to_complete_report | No human clock was started. |
| field_bug_bounty_efficacy | Disposable fixture only. Do not cite these rows as program results. |
| browser_dom_execution | Chromium was not launched. DOM rows use static source text only. |
| real_world_program | The opt-in real-world protocol was not executed. |
