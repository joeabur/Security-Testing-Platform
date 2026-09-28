"""Queueing an assessment run — the one code path every caller shares.

`app/api/v1/routers/runs.py`, `remediation.py`, `repositories.py`, and the
native agent's `start_scan` tool all queue a run through `service.queue_run`
rather than each writing their own `AssessmentRun` row and Celery dispatch.
"""
