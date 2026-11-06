"""Detect Unicode smuggling in text an AI model or person is about to trust.

Modern prompt-injection and spoofing attacks hide instructions or data in text that
looks innocent to a human reviewer:

  * ASCII smuggling via Unicode **tag characters** (U+E0000–E007F) — an invisible
    copy of an instruction rendered as nothing.
  * **Bidi overrides** (Trojan Source, CVE-2021-42574) — reorder what the eye reads
    versus what the machine parses.
  * **Variation-selector payloads** — arbitrary bytes encoded in the 256 variation
    selectors, hidden behind one carrier glyph.
  * **Zero-width smuggling** — data encoded in runs of zero-width joiners/spaces.
  * **Homoglyph / confusable** spoofing — Cyrillic/Greek letters that look Latin.

The hard part is doing this without mangling legitimate international text: Thai and
Khmer use zero-width spaces, Arabic and Indic scripts use zero-width joiners, French
uses non-breaking spaces, CJK uses ideographic variation selectors. This scanner is
calibrated against 204 languages of real text (FLORES-200) to keep those benign.
"""

from __future__ import annotations

import bisect
import unicodedata
from dataclasses import dataclass, field
from typing import Optional

from . import _tables as T

__all__ = ["Finding", "ScanResult", "scan", "decode_tag_chars", "decode_variation_payload"]

# severity
CRITICAL, WARNING, INFO = "critical", "warning", "info"
_SEV_RANK = {INFO: 0, WARNING: 1, CRITICAL: 2}

# ---- fast range membership ------------------------------------------------- #
_RANGE_STARTS = {name: [a for a, _ in getattr(T, name)]
                 for name in ("DEFAULT_IGNORABLE", "BIDI_CONTROL", "JOIN_CONTROL",
                              "NONCHARACTER", "VARIATION_SELECTOR", "WHITE_SPACE", "DEPRECATED")}


def _in(name: str, cp: int) -> bool:
    ranges = getattr(T, name)
    starts = _RANGE_STARTS[name]
    i = bisect.bisect_right(starts, cp) - 1
    return 0 <= i < len(ranges) and ranges[i][0] <= cp <= ranges[i][1]


_SCRIPT_STARTS = [s for s, _, _ in T.SCRIPTS]


def script_of(cp: int) -> str:
    i = bisect.bisect_right(_SCRIPT_STARTS, cp) - 1
    if 0 <= i < len(T.SCRIPTS):
        a, b, name = T.SCRIPTS[i]
        if a <= cp <= b:
            return name
    return "Unknown"


# scripts that legitimately use zero-width joiners / non-joiners / spaces
_ZW_SCRIPTS = {
    "Arabic", "Syriac", "Thaana", "Nko", "Mongolian",
    "Devanagari", "Bengali", "Gurmukhi", "Gujarati", "Oriya", "Tamil", "Telugu",
    "Kannada", "Malayalam", "Sinhala", "Tibetan", "Myanmar", "Khmer", "Thai", "Lao",
    "Hangul", "Manichaean", "Meetei_Mayek", "Tirhuta", "Chakma", "Javanese", "Balinese",
    "Kaithi", "Sharada", "Grantha", "Khudawadi", "Modi", "Takri",
}
# code points that are the real "invisible" smuggling vectors
_TAG_LO, _TAG_HI = 0xE0000, 0xE007F
_BIDI_OVERRIDE = {0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069}
_BIDI_MARKS = {0x200E, 0x200F, 0x061C}          # harmless directional marks
_ZERO_WIDTH = {0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x180E, 0x00AD, 0x034F, 0x2061,
               0x2062, 0x2063, 0x2064}
_DECEPTIVE_SPACE = {0x00A0, 0x2007, 0x202F, 0x205F, 0x2028, 0x2029, 0x1680,
                    *range(0x2000, 0x200B), 0x3000, 0x3164, 0xFFA0}
_VS_LO1, _VS_HI1 = 0xFE00, 0xFE0F
_VS_LO2, _VS_HI2 = 0xE0100, 0xE01EF
# scripts whose letters are classically used to imitate Latin (homoglyph spoofing)
_SPOOF_SCRIPTS = {"Cyrillic", "Greek", "Armenian", "Coptic", "Cherokee"}


# --------------------------------------------------------------------------- #
# model
# --------------------------------------------------------------------------- #

@dataclass
class Finding:
    code: str
    severity: str
    message: str
    index: int                      # position in the input string
    char: str = ""
    codepoint: int = 0
    count: int = 1
    decoded: Optional[str] = None   # recovered hidden payload, if any

    def to_json(self):
        return {"code": self.code, "severity": self.severity, "message": self.message,
                "index": self.index, "codepoint": f"U+{self.codepoint:04X}" if self.codepoint else None,
                "count": self.count, "decoded": self.decoded}


@dataclass
class ScanResult:
    text: str
    findings: list = field(default_factory=list)
    verdict: str = "clean"          # clean | suspicious | dangerous
    stats: dict = field(default_factory=dict)

    def add(self, f: Finding):
        self.findings.append(f)

    @property
    def hidden_text(self) -> str:
        """Concatenation of every decoded hidden payload found."""
        return "".join(f.decoded for f in self.findings if f.decoded)

    def finalize(self):
        sev = max((_SEV_RANK[f.severity] for f in self.findings), default=0)
        self.verdict = {0: "clean", 1: "suspicious", 2: "dangerous"}[sev]
        self.findings.sort(key=lambda f: (-_SEV_RANK[f.severity], f.index))
        return self

    def to_json(self):
        return {"verdict": self.verdict, "stats": self.stats,
                "hidden_text": self.hidden_text,
                "findings": [f.to_json() for f in self.findings]}


# --------------------------------------------------------------------------- #
# decoders
# --------------------------------------------------------------------------- #

def decode_tag_chars(text: str) -> str:
    """Map Unicode tag characters (U+E0000 block) back to their ASCII meaning."""
    out = []
    for ch in text:
        cp = ord(ch)
        if 0xE0020 <= cp <= 0xE007E:       # tag space .. tag tilde
            out.append(chr(cp - 0xE0000))
        elif cp == 0xE0001 or cp == 0xE007F:
            continue                        # language-tag begin / cancel tag
    return "".join(out)


def decode_variation_payload(text: str) -> bytes:
    """Decode a run of variation selectors into bytes (Paul Butler's emoji-smuggling scheme).

    VS1..VS16  (U+FE00..FE0F)   -> byte 0..15
    VS17..VS256 (U+E0100..E01EF) -> byte 16..255
    """
    out = bytearray()
    for ch in text:
        cp = ord(ch)
        if _VS_LO1 <= cp <= _VS_HI1:
            out.append(cp - _VS_LO1)
        elif _VS_LO2 <= cp <= _VS_HI2:
            out.append(cp - _VS_LO2 + 16)
    return bytes(out)


# --------------------------------------------------------------------------- #
# scanner
# --------------------------------------------------------------------------- #

def scan(text: str) -> ScanResult:
    r = ScanResult(text=text)
    if not text:
        return r.finalize()

    cps = [ord(c) for c in text]
    n = len(cps)

    _scan_tag_chars(text, cps, r)
    _scan_bidi(text, cps, r)
    _scan_variation_selectors(text, cps, r)
    _scan_zero_width(text, cps, r)
    _scan_confusables(text, cps, r)
    _scan_misc(text, cps, r)

    visible = sum(1 for cp in cps if not (_in("DEFAULT_IGNORABLE", cp) or cp in _ZERO_WIDTH
                                          or _TAG_LO <= cp <= _TAG_HI))
    r.stats = {
        "length": n, "visible": visible,
        "invisible": n - visible,
        "scripts": sorted(_scripts_present(cps)),
        "n_findings": len(r.findings),
    }
    return r.finalize()


def _scripts_present(cps):
    s = set()
    for cp in cps:
        if cp < 0x80:
            continue
        sc = script_of(cp)
        if sc not in ("Common", "Inherited", "Unknown"):
            s.add(sc)
    return s


def _scan_tag_chars(text, cps, r: ScanResult):
    idxs = [i for i, cp in enumerate(cps) if _TAG_LO <= cp <= _TAG_HI]
    if not idxs:
        return
    payload = decode_tag_chars(text)
    r.add(Finding("tag-chars", CRITICAL,
                  f"{len(idxs)} Unicode tag character(s) (U+E0000 block) — an invisible, machine-readable "
                  f"message hidden in the text. This is the classic ASCII-smuggling prompt-injection vector.",
                  index=idxs[0], count=len(idxs), codepoint=cps[idxs[0]],
                  decoded=payload or None))


def _scan_bidi(text, cps, r: ScanResult):
    overrides = [i for i, cp in enumerate(cps) if cp in _BIDI_OVERRIDE]
    if not overrides:
        return
    # unbalanced / override controls can visually reorder text vs. its logical order
    opens = sum(1 for i in overrides if cps[i] in (0x202A, 0x202B, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068))
    closes = sum(1 for i in overrides if cps[i] in (0x202C, 0x2069))
    has_hard_override = any(cps[i] in (0x202D, 0x202E) for i in overrides)
    msg = (f"{len(overrides)} bidirectional control character(s) that can reorder how the text is displayed "
           f"versus how it is parsed (Trojan-Source style).")
    if has_hard_override:
        msg += " Includes a hard left/right override (RLO/LRO)."
    if opens != closes:
        msg += f" The embeddings/isolates are unbalanced ({opens} open, {closes} close)."
    r.add(Finding("bidi-override", CRITICAL, msg, index=overrides[0],
                  count=len(overrides), codepoint=cps[overrides[0]]))


def _scan_variation_selectors(text, cps, r: ScanResult):
    def is_vs(cp):
        return _VS_LO1 <= cp <= _VS_HI1 or _VS_LO2 <= cp <= _VS_HI2
    # find runs of variation selectors
    i = 0
    runs = []
    while i < len(cps):
        if is_vs(cps[i]):
            j = i
            while j < len(cps) and is_vs(cps[j]):
                j += 1
            runs.append((i, j))
            i = j
        else:
            i += 1
    for start, end in runs:
        run_len = end - start
        base = cps[start - 1] if start > 0 else None
        base_script = script_of(base) if base else ""
        # legitimate: a SINGLE emoji VS16 after an emoji, or a single IVS after a CJK ideograph
        legit_single = run_len == 1 and base is not None and (
            base_script in ("Han", "Hiragana", "Katakana") or _is_emoji_base(base) or cps[start] == 0xFE0F
            or cps[start] == 0xFE0E)
        if legit_single:
            continue
        payload = decode_variation_payload(text[start:end])
        try:
            decoded = payload.decode("utf-8")
        except UnicodeDecodeError:
            decoded = payload.hex()
        r.add(Finding("vs-payload", CRITICAL,
                      f"A run of {run_len} variation selector(s) encodes hidden data behind one visible "
                      f"character — arbitrary bytes smuggled through invisible code points.",
                      index=start, count=run_len, codepoint=cps[start],
                      decoded=decoded or None))


def _is_emoji_base(cp: int) -> bool:
    return (0x1F000 <= cp <= 0x1FAFF) or (0x2600 <= cp <= 0x27BF) or cp in (0x2122, 0x2139) \
        or (0x1F1E6 <= cp <= 0x1F1FF)


# a run of this many consecutive zero-width chars carries enough bits to be a payload;
# shorter runs occur in legitimate complex-script typography (Khmer/Myanmar word breaks)
_ZW_RUN_PAYLOAD = 4


def _scan_zero_width(text, cps, r: ScanResult):
    zw_idx = [i for i, cp in enumerate(cps) if cp in _ZERO_WIDTH]
    if not zw_idx:
        return
    runs = _consecutive(zw_idx)
    payload_runs = [run for run in runs if len(run) >= _ZW_RUN_PAYLOAD]
    short_runs = [run for run in runs if 2 <= len(run) < _ZW_RUN_PAYLOAD]
    in_run = {i for run in runs if len(run) >= 2 for i in run}
    singles = [i for i in zw_idx if i not in in_run]

    # a run in a complex-script context (Khmer/Myanmar/Devanagari) is typography, not a payload
    hot_runs = [run for run in payload_runs if not _run_in_script_context(cps, run)]
    soft_runs = [run for run in payload_runs if run not in hot_runs]
    if hot_runs:
        total = sum(len(run) for run in hot_runs)
        r.add(Finding("zero-width-run", CRITICAL,
                      f"{len(hot_runs)} run(s) of consecutive zero-width characters ({total} in total) in text "
                      f"with no complex-script context — the signature of data encoded in invisible code points.",
                      index=hot_runs[0][0], count=total, codepoint=cps[hot_runs[0][0]]))

    # a single zero-width char is smuggling when it splits a word (both neighbours are letters)
    suspicious = [i for i in singles if _between_letters(cps, i) and not _zw_is_benign(cps, i)]
    benign = len(singles) - len(suspicious)
    if suspicious:
        r.add(Finding("zero-width-embed", WARNING,
                      f"{len(suspicious)} zero-width character(s) inserted between letters where they serve no "
                      f"typographic purpose — often used to break up keywords and evade filters.",
                      index=suspicious[0], count=len(suspicious), codepoint=cps[suspicious[0]]))
    if short_runs or soft_runs:
        short_runs = short_runs + soft_runs
        r.add(Finding("zero-width-anomaly", INFO,
                      f"{len(short_runs)} short run(s) of repeated zero-width characters — unusual but seen "
                      f"in some complex-script typography.", index=short_runs[0][0],
                      count=sum(len(x) for x in short_runs), codepoint=cps[short_runs[0][0]]))
    if benign and not suspicious and not payload_runs:
        r.add(Finding("zero-width-benign", INFO,
                      f"{benign} zero-width joiner/non-joiner/space character(s) consistent with the "
                      f"surrounding script (e.g. Indic, Arabic or Thai typography).",
                      index=zw_idx[0], count=benign, codepoint=cps[zw_idx[0]]))


def _zw_is_benign(cps, i) -> bool:
    cp = cps[i]
    prev_cp = _nearest(cps, i, -1)
    next_cp = _nearest(cps, i, +1)
    # emoji ZWJ sequence
    if cp == 0x200D and prev_cp and next_cp and (_is_emoji_base(prev_cp) or _is_emoji_base(next_cp)):
        return True
    # benign when a complex script that uses zero-width chars is nearby (within a small window —
    # legitimate uses sit inside a word, which may include adjacent punctuation or spaces)
    for nb in _window_scripts(cps, i, radius=3):
        if nb in _ZW_SCRIPTS:
            return True
    return False


def _run_in_script_context(cps, run) -> bool:
    """True if a complex (zero-width-using) script sits next to this run of invisibles."""
    for anchor in (run[0], run[-1]):
        for sc in _window_scripts(cps, anchor, radius=3):
            if sc in _ZW_SCRIPTS:
                return True
    return False


def _between_letters(cps, i) -> bool:
    prev_cp = _nearest(cps, i, -1)
    next_cp = _nearest(cps, i, +1)
    return bool(prev_cp and next_cp and chr(prev_cp).isalpha() and chr(next_cp).isalpha())


def _window_scripts(cps, i, radius):
    for j in range(max(0, i - radius), min(len(cps), i + radius + 1)):
        if j == i:
            continue
        cp = cps[j]
        if cp in _ZERO_WIDTH or _TAG_LO <= cp <= _TAG_HI or cp < 0x80:
            continue
        yield script_of(cp)


def _nearest(cps, i, step):
    j = i + step
    while 0 <= j < len(cps):
        if cps[j] not in _ZERO_WIDTH and not (_TAG_LO <= cps[j] <= _TAG_HI):
            return cps[j]
        j += step
    return None


def _consecutive(idxs):
    runs, cur = [], []
    for i in idxs:
        if cur and i == cur[-1] + 1:
            cur.append(i)
        else:
            if cur:
                runs.append(cur)
            cur = [i]
    if cur:
        runs.append(cur)
    return runs


def _scan_confusables(text, cps, r: ScanResult):
    """Mixed-script tokens where a non-Latin glyph imitates a Latin letter (homoglyph spoof)."""
    conf = T.LATIN_CONFUSABLES
    hits = []
    for token, start in _tokens(text):
        ascii_latin = sum(1 for c in token if ord(c) < 0x80 and c.isalpha())
        # only count look-alikes that are LETTERS from a classic spoofing script
        token_conf = [(k, c) for k, c in enumerate(token)
                      if ord(c) in conf and c.isalpha() and script_of(ord(c)) in _SPOOF_SCRIPTS]
        other = sum(1 for c in token if ord(c) >= 0x80 and ord(c) not in conf and c.isalpha())
        # a homoglyph spoof is a predominantly-Latin word with non-Latin look-alikes swapped in —
        # NOT a word of another script that merely contains a Latin letter or acronym.
        if token_conf and ascii_latin >= 2 and other == 0 and (ascii_latin + len(token_conf)) >= 3:
            k, c = token_conf[0]
            skeleton = "".join(conf.get(ord(ch), ch) for ch in token)
            hits.append((start + k, c, token, skeleton))
    if hits:
        idx, c, token, skel = hits[0]
        r.add(Finding("confusable-latin", WARNING,
                      f"{len(hits)} token(s) mix ASCII letters with non-Latin look-alikes "
                      f"(e.g. “{token}” looks like “{skel}”) — a homoglyph spoof used to impersonate "
                      f"trusted names or slip past keyword filters.",
                      index=idx, count=len(hits), codepoint=ord(c)))


def _tokens(text):
    tok, start = [], 0
    i = 0
    for i, ch in enumerate(text):
        if ch.isspace() or (ch in ".,;:!?()[]{}\"'/\\|<>@#"):
            if tok:
                yield "".join(tok), start
                tok = []
        else:
            if not tok:
                start = i
            tok.append(ch)
    if tok:
        yield "".join(tok), start


def _scan_misc(text, cps, r: ScanResult):
    nonchar = [i for i, cp in enumerate(cps) if _in("NONCHARACTER", cp)]
    if nonchar:
        r.add(Finding("noncharacter", WARNING,
                      f"{len(nonchar)} Unicode noncharacter(s) — code points permanently reserved as invalid, "
                      f"sometimes used to corrupt or confuse parsers.", index=nonchar[0],
                      count=len(nonchar), codepoint=cps[nonchar[0]]))
    pua = [i for i, cp in enumerate(cps) if (0xE000 <= cp <= 0xF8FF) or (0xF0000 <= cp <= 0xFFFFD)
           or (0x100000 <= cp <= 0x10FFFD)]
    if pua:
        r.add(Finding("private-use", WARNING,
                      f"{len(pua)} private-use character(s) with no standard meaning — their rendering and "
                      f"interpretation depend on a private agreement and can hide content.",
                      index=pua[0], count=len(pua), codepoint=cps[pua[0]]))
    # deceptive whitespace: non-ASCII spaces masquerading as a normal space
    dspace = [i for i, cp in enumerate(cps) if cp in _DECEPTIVE_SPACE]
    if dspace:
        r.add(Finding("deceptive-space", INFO,
                      f"{len(dspace)} non-ASCII space character(s) (e.g. non-breaking or ideographic space). "
                      f"Usually legitimate, but can disguise token boundaries.",
                      index=dspace[0], count=len(dspace), codepoint=cps[dspace[0]]))
    # Zalgo: combining-mark floods
    _scan_combining_flood(cps, r)


def _scan_combining_flood(cps, r: ScanResult):
    run = 0
    worst = 0
    worst_idx = 0
    for i, cp in enumerate(cps):
        if unicodedata.combining(chr(cp)):
            run += 1
            if run > worst:
                worst, worst_idx = run, i - run + 1
        else:
            run = 0
    if worst >= 5:
        r.add(Finding("combining-flood", WARNING,
                      f"Up to {worst} combining marks stacked on a single base character (“Zalgo” text) — "
                      f"can break rendering and hide or distort content.",
                      index=worst_idx, count=worst, codepoint=cps[worst_idx]))
