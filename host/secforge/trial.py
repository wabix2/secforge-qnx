"""Run ONE trial for a given policy file (no minimizing): build, boot, check.

    set PYTHONPATH=host
    python -m secforge.trial --policy C:\\qnxvm-secpol\\policy-min1.txt --workdir C:\\qnxwork\\t1
"""
import argparse
import json
import sys

from secforge.runner import run_trial


def main(argv=None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--policy", required=True)
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--name", default="single")
    args = ap.parse_args(argv)
    text = open(args.policy, encoding="utf-8", errors="replace").read()
    res = run_trial(text, args.workdir, args.name)
    print(json.dumps(res.to_dict(), indent=2))
    return 0 if res.passed else 1


if __name__ == "__main__":
    sys.exit(main())
