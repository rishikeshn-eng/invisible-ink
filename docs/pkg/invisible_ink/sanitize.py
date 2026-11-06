"""Neutralise Unicode smuggling while preserving legitimate international text.

``sanitize`` returns cleaned text plus a report of what was changed. The policy is
configurable, but the defaults are chosen to be safe for real multilingual content:
invisible smuggling vectors are removed, confusable spoofs are optionally mapped to
their Latin prototype, and legitimate zero-width joiners inside complex scripts are
kept unless ``aggressive`` is set.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import _tables as T
from .scan import (
    scan, script_of, _ZERO_WIDTH, _BIDI_OVERRIDE, _BIDI_MARKS, _DECEPTIVE_SPACE,
    _TAG_LO, _TAG_HI, _VS_LO1, _VS_HI1, _VS_LO2, _VS_HI2, _zw_is_benign,
)

__all__ = ["Policy", "SanitizeResult", "sanitize"]


@dataclass
class Policy:
    remove_tag_chars: bool = True          # U+E0000 block — never legitimate
    remove_bidi_overrides: bool = True     # RLO/LRO/embeddings/isolates
    remove_variation_payloads: bool = True  # VS runs used as data carriers
    remove_zero_width: bool = True         # zero-width smuggling...
    keep_script_zero_width: bool = True    # ...but keep ZWJ/ZWNJ legit for the surrounding script
    remove_noncharacters: bool = True
    remove_private_use: bool = True
    normalize_spaces: bool = False         # map exotic spaces to U+0020 (off: can change meaning)
    map_confusables: bool = False          # fold Latin look-alikes to ASCII (off by default: lossy)


@dataclass
class SanitizeResult:
    original: str
    cleaned: str
    removed: int = 0
    replaced: int = 0
    notes: list = field(default_factory=list)

    @property
    def changed(self) -> bool:
        return self.cleaned != self.original

    def to_json(self):
        return {"cleaned": self.cleaned, "removed": self.removed, "replaced": self.replaced,
                "changed": self.changed, "notes": self.notes}


def _is_vs(cp):
    return _VS_LO1 <= cp <= _VS_HI1 or _VS_LO2 <= cp <= _VS_HI2


def sanitize(text: str, policy: Policy = None) -> SanitizeResult:
    policy = policy or Policy()
    cps = [ord(c) for c in text]
    out = []
    removed = replaced = 0
    seen = set()

    # precompute VS runs so single legitimate selectors can be kept
    for i, cp in enumerate(cps):
        # tag chars
        if policy.remove_tag_chars and _TAG_LO <= cp <= _TAG_HI:
            removed += 1
            seen.add("tag characters")
            continue
        # bidi overrides (keep harmless marks)
        if policy.remove_bidi_overrides and cp in _BIDI_OVERRIDE:
            removed += 1
            seen.add("bidi override controls")
            continue
        # variation selectors used as payload
        if policy.remove_variation_payloads and _is_vs(cp):
            if _vs_is_legit(cps, i):
                out.append(chr(cp))
            else:
                removed += 1
                seen.add("variation-selector payloads")
            continue
        # zero-width
        if policy.remove_zero_width and cp in _ZERO_WIDTH:
            if policy.keep_script_zero_width and _zw_is_benign(cps, i):
                out.append(chr(cp))
            else:
                removed += 1
                seen.add("zero-width characters")
            continue
        # noncharacters
        if policy.remove_noncharacters and (0xFDD0 <= cp <= 0xFDEF or (cp & 0xFFFE) == 0xFFFE):
            removed += 1
            seen.add("noncharacters")
            continue
        # private use
        if policy.remove_private_use and ((0xE000 <= cp <= 0xF8FF) or (0xF0000 <= cp <= 0xFFFFD)
                                          or (0x100000 <= cp <= 0x10FFFD)):
            removed += 1
            seen.add("private-use characters")
            continue
        # exotic spaces
        if policy.normalize_spaces and cp in _DECEPTIVE_SPACE and cp not in (0x2028, 0x2029):
            out.append(" ")
            replaced += 1
            seen.add("non-standard spaces")
            continue
        # confusables
        if policy.map_confusables and cp in T.LATIN_CONFUSABLES:
            out.append(T.LATIN_CONFUSABLES[cp])
            replaced += 1
            seen.add("confusable look-alikes")
            continue
        out.append(chr(cp))

    res = SanitizeResult(original=text, cleaned="".join(out), removed=removed, replaced=replaced)
    res.notes = sorted(seen)
    return res


def _vs_is_legit(cps, i) -> bool:
    """A single variation selector right after an emoji or CJK base is legitimate."""
    cp = cps[i]
    # part of a run of length >= 2 -> payload
    if (i + 1 < len(cps) and _is_vs(cps[i + 1])) or (i > 0 and _is_vs(cps[i - 1])):
        return False
    if i == 0:
        return False
    base = cps[i - 1]
    from .scan import _is_emoji_base
    bs = script_of(base)
    return bs in ("Han", "Hiragana", "Katakana") or _is_emoji_base(base) or cp in (0xFE0E, 0xFE0F)
