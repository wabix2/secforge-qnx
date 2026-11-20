"""Delta-debugging (ddmin) minimizer for policy rules.

Pure Python, no QNX needed. The `oracle` is the only QNX-specific part:
it receives a candidate list of rules and returns True if the workload
still PASSES under a policy built from them (boot the image, run the demo,
check the attacker is blocked). Everything else here is testable offline.
"""
from typing import Callable, List, Sequence, TypeVar

T = TypeVar("T")


def ddmin(items: Sequence[T], oracle: Callable[[List[T]], bool]) -> List[T]:
    """Return a 1-minimal subset of `items` for which oracle(subset) is True.

    Precondition: oracle(list(items)) is True (the full policy works).
    Deterministic: same inputs and oracle -> same output.
    """
    current = list(items)
    if not oracle(current):
        raise ValueError("full rule set does not pass; nothing to minimize")
    n = 2
    while len(current) >= 2:
        size = max(1, len(current) // n)
        chunks = [current[i:i + size] for i in range(0, len(current), size)]
        reduced = False
        for i in range(len(chunks)):
            complement = [x for j, c in enumerate(chunks) if j != i for x in c]
            if complement and oracle(complement):
                current, n, reduced = complement, max(n - 1, 2), True
                break
        if not reduced:
            if n >= len(current):
                break
            n = min(len(current), n * 2)
    i = 0
    while i < len(current):
        candidate = current[:i] + current[i + 1:]
        if candidate and oracle(candidate):
            current = candidate
        else:
            i += 1
    return current
