# Benchmarks

| test | corpus | n |
|---|---|---|
| **false positives** (precision) | FLORES-200 real sentences, 204 languages | 206,448 |
| **attack recall** | crafted samples of each smuggling vector | 18 |

## Reproduce

```bash
# FLORES-200 (one-time download)
curl -L -o /tmp/flores.tar.gz https://dl.fbaipublicfiles.com/nllb/flores200_dataset.tar.gz
tar xzf /tmp/flores.tar.gz -C /tmp
python bench/run_bench.py /tmp/flores200_dataset/devtest bench/out
```

The Unicode character tables are regenerated from the UCD with:

```bash
python build_tables.py <path-to-ucd> invisible_ink/_tables.py
```

## Headline results (`bench/out/report.json`)

- **0 critical false positives** across 206,448 sentences in 204 languages.
- Overall flag rate 0.02% — all warnings, and all genuine mixed-script tokens
  (a Cyrillic letter inside a Latin word in transliterated text).
- The default sanitiser alters 0.06% of legitimate sentences (benign normalisation).
- **100% attack recall** (18/18) across every documented vector.
- **100% payload decode** (7/7) — the hidden ASCII / byte payload is recovered,
  not just flagged.
- ~0.1 ms per scan.
