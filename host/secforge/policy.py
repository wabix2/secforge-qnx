"""Parse a QNX security policy text into removable 'atoms' and render it back.

An atom is one permission granted inside an `allow <type> self:ability { ... };`
block: either a bare ability (`spawn`) or one argument of an ability with a
list (`channel_connect:devb_t`). Everything outside those blocks (type
declarations, allow_attach, ability definitions, comments) is kept unchanged.

Pure Python, no QNX needed. Verified only against the rule shapes seen in the
QNX 8.0 docs and in our own generated policy; run `python -m secforge.cli atoms
<policy>` on a real file and check the counts before trusting it.
"""
import re
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Set

# Abilities whose comma list we split into one atom per item. Others (for
# example xprocess_query:20-22,24-25) are kept as one atom, to stay conservative.
SPLIT_ABILITIES = {"channel_connect", "settypeid"}

_BLOCK_RE = re.compile(
    r"allow\s+(?P<type>[^\s{}]+)\s+self\s*:\s*ability\s*\{(?P<body>[^{}]*)\}\s*;",
    re.DOTALL,
)


@dataclass(frozen=True)
class Atom:
    index: int           # position in Policy.atoms
    block: int           # index of the block it belongs to
    type_name: str       # e.g. console_t
    ability: str         # e.g. channel_connect
    arg: Optional[str]   # e.g. devb_t, or None for a bare ability
    canon: int           # index of the first atom with the same (type, ability, arg)

    def label(self) -> str:
        tail = f":{self.arg}" if self.arg is not None else ""
        return f"{self.type_name} {self.ability}{tail}"


@dataclass
class _Block:
    start: int
    end: int
    type_name: str
    atom_indexes: List[int]


class Policy:
    def __init__(self, text: str):
        self.text = text
        self.atoms: List[Atom] = []
        self._blocks: List[_Block] = []
        seen: Dict[tuple, int] = {}
        for m in _BLOCK_RE.finditer(text):
            block_no = len(self._blocks)
            idxs: List[int] = []
            for ability, arg in _tokens(m.group("body")):
                key = (m.group("type"), ability, arg)
                canon = seen.setdefault(key, len(self.atoms))
                atom = Atom(len(self.atoms), block_no, m.group("type"), ability, arg, canon)
                self.atoms.append(atom)
                idxs.append(atom.index)
            self._blocks.append(_Block(m.start(), m.end(), m.group("type"), idxs))

    @property
    def unique_indexes(self) -> List[int]:
        """Indexes of atoms to minimize over: one per distinct (type, ability, arg).
        A permission that appears twice (for example in the baseline and in the
        generated update) is one unit: keeping it keeps every copy."""
        return [a.index for a in self.atoms if a.canon == a.index]

    def render(self, keep: Optional[Iterable[int]] = None) -> str:
        """Return policy text containing only the kept units (None = all).
        `keep` holds indexes from unique_indexes."""
        keep_set = set(self.unique_indexes) if keep is None else set(keep)
        kept: Set[int] = {a.index for a in self.atoms if a.canon in keep_set}
        out = self.text
        for block in reversed(self._blocks):
            body = _render_block(block.type_name,
                                 [self.atoms[i] for i in block.atom_indexes if i in kept])
            out = out[:block.start] + body + out[block.end:]
        return out


def _tokens(body: str):
    """Yield (ability, arg) pairs from the inside of a block; comments ignored."""
    for line in body.splitlines():
        line = line.split("#", 1)[0]
        for token in line.split():
            name, sep, rest = token.partition(":")
            if sep and name in SPLIT_ABILITIES:
                for item in rest.split(","):
                    if item:
                        yield name, item
            elif sep:
                yield name, rest          # keep the whole range as one atom
            else:
                yield name, None


def _render_block(type_name: str, atoms: List[Atom]) -> str:
    if not atoms:
        return ""                          # drop empty blocks entirely
    order: List[str] = []
    grouped: Dict[str, List[str]] = {}
    for a in atoms:
        if a.ability not in grouped:
            grouped[a.ability] = []
            order.append(a.ability)
        if a.arg is not None:
            grouped[a.ability].append(a.arg)
    lines = []
    for ability in order:
        args = grouped[ability]
        lines.append(f"    {ability}:{','.join(args)}" if args else f"    {ability}")
    return f"allow {type_name} self:ability {{\n" + "\n".join(lines) + "\n};"
