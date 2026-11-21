"""Small command line helper. Usage (from the repo root):
    set PYTHONPATH=host
    python -m secforge.cli atoms evidence\\policies\\policy-merged.txt
"""
import sys
from collections import Counter

from secforge.policy import Policy


def main(argv):
    if len(argv) != 3 or argv[1] != "atoms":
        print("usage: python -m secforge.cli atoms <policy.txt>")
        return 2
    with open(argv[2], encoding="utf-8", errors="replace") as f:
        policy = Policy(f.read())
    print(f"blocks: {len({a.block for a in policy.atoms})}")
    print(f"removable atoms: {len(policy.atoms)}")
    for type_name, n in Counter(a.type_name for a in policy.atoms).most_common():
        print(f"  {type_name}: {n}")
    print("--- atoms ---")
    for a in policy.atoms:
        print(f"{a.index:4d}  {a.label()}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
