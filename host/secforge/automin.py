"""Minimize a QNX security policy over a shortlist of candidate permissions.

Everything not on the shortlist is kept fixed. A candidate is removed only if a
rebuilt image still boots, the legitimate checks pass and the attack checks are
still denied.

    set PYTHONPATH=host
    python -m secforge.automin --policy evidence\\policies\\policy-merged.txt ^
        --candidates candidates.txt --workdir C:\\qnxwork\\run1
"""
import argparse
import json
import os
import sys
import time
from typing import Callable, Dict, List

from secforge.minimize import ddmin
from secforge.policy import Policy


def select_candidates(policy: Policy, labels: List[str]) -> List[int]:
    """Map 'type ability[:arg]' labels to unit indexes; unknown labels are an error."""
    by_label = {policy.atoms[i].label(): i for i in policy.unique_indexes}
    missing = [l for l in labels if l not in by_label]
    if missing:
        raise ValueError("candidate labels not found in policy: " + "; ".join(missing))
    return [by_label[l] for l in labels]


def minimize_policy(policy: Policy, candidates: List[int],
                    passes: Callable[[str], bool],
                    on_trial: Callable[[List[int], bool], None] = lambda s, ok: None) -> List[int]:
    """Return the candidate units that must stay. `passes(policy_text)` runs one trial."""
    cand = set(candidates)
    fixed = [i for i in policy.unique_indexes if i not in cand]
    cache: Dict[frozenset, bool] = {}

    def oracle(subset: List[int]) -> bool:
        key = frozenset(subset)
        if key not in cache:
            cache[key] = passes(policy.render(fixed + list(subset)))
            on_trial(list(subset), cache[key])
        return cache[key]

    return ddmin(candidates, oracle)


def main(argv=None) -> int:
    from secforge.runner import run_trial, sha256   # imported late: needs QNX tooling only here
    ap = argparse.ArgumentParser()
    ap.add_argument("--policy", required=True)
    ap.add_argument("--candidates", required=True, help="text file, one label per line")
    ap.add_argument("--workdir", required=True)
    args = ap.parse_args(argv)

    policy = Policy(open(args.policy, encoding="utf-8", errors="replace").read())
    labels = [l.strip() for l in open(args.candidates, encoding="utf-8")
              if l.strip() and not l.lstrip().startswith("#")]
    candidates = select_candidates(policy, labels)
    os.makedirs(args.workdir, exist_ok=True)
    log_path = os.path.join(args.workdir, "trials.jsonl")

    seen: Dict[str, dict] = {}                       # resume support: results by policy hash
    if os.path.exists(log_path):
        for line in open(log_path, encoding="utf-8"):
            rec = json.loads(line)
            seen[rec["policy_sha256"]] = rec

    counter = {"n": len(seen), "ran": 0}
    t_all = time.time()

    def passes(text: str) -> bool:
        digest = sha256(text)
        if digest in seen:
            print(f"[cached] {digest[:8]} -> {'PASS' if seen[digest]['passed'] else 'FAIL'}")
            return seen[digest]["passed"]
        counter["n"] += 1
        counter["ran"] += 1
        res = run_trial(text, args.workdir, f"trial-{counter['n']:03d}").to_dict()
        seen[digest] = res
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(res) + "\n")
        print(f"[trial {counter['n']}] {'PASS' if res['passed'] else 'FAIL'} "
              f"({res['total_seconds']} s) {res['detail']}")
        return res["passed"]

    def on_trial(subset, ok):
        print(f"   tested {len(subset)} of {len(candidates)} candidates kept -> {'ok' if ok else 'broke'}")

    keep = minimize_policy(policy, candidates, passes, on_trial)
    removed = [policy.atoms[i].label() for i in candidates if i not in set(keep)]
    kept = [policy.atoms[i].label() for i in keep]
    cand_set = set(candidates)
    fixed = [i for i in policy.unique_indexes if i not in cand_set]
    final_text = policy.render(fixed + keep)
    with open(os.path.join(args.workdir, "policy-minimized.txt"), "w", encoding="utf-8", newline="\n") as f:
        f.write(final_text)
    summary = {"candidates": len(candidates), "removed": removed, "kept_candidates": kept,
               "trials_run_this_session": counter["ran"], "seconds_this_session": round(time.time() - t_all, 1)}
    with open(os.path.join(args.workdir, "result.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)
    print(json.dumps(summary, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
