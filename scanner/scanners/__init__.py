from scanner.models import Verdict

VERDICT_PRIORITY = {Verdict.allow: 0, Verdict.warn: 1, Verdict.block: 2}


def aggregate_verdict(*verdicts: Verdict) -> Verdict:
    return max(verdicts, key=lambda v: VERDICT_PRIORITY[v])
