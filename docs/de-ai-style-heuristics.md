# German AI-style heuristics

This project primarily detects verifiable artifacts: Unicode controls, hidden characters, payload candidates, URL tracking parameters, and related signals. The German AI-style heuristics added here are deliberately weaker and are reported as `HINT` only.

They should not be used as proof that a text was written by AI.

## Files

- `api/de_ai_style_analyze.php` exposes a standalone PHP endpoint for German prose style metrics.
- `data/de_ai_text_indicators.json` contains the same indicator families in a machine-readable form.

## Endpoint

`POST /api/de_ai_style_analyze.php`

```json
{
  "text": "Deutscher Fließtext...",
  "settings": {
    "include_catalog": true
  }
}
```

## Main output fields

- `style.metrics`: numeric metrics such as word count, sentence count, average sentence length, burstiness, type-token ratio, Yule's K, hapax ratio, n-gram repetition and phrase counts.
- `style.findings`: conservative hint-only findings with thresholds and matched phrases where applicable.
- `style.matches`: extracted matches for formulaic transitions, disclaimer-like phrases, parallel structures, triplets and informal markers.
- `indicator_catalog`: optional machine-readable indicator metadata when `settings.include_catalog` is true.

## Indicator families

- Low sentence-length variation (`de_low_burstiness`)
- Low lexical diversity (`de_low_lexical_diversity`)
- Dense formal transition phrases (`de_formulaic_transition_density`)
- Assistant-like caveat phrases (`de_disclaimer_phrase_density`)
- Parallel structures and triplets (`de_parallel_or_triplet_style`)
- Informal German markers as context data (`de_low_informality_in_informal_text`)
- En dash / em dash density (`de_punctuation_uniformity`)
- Repeated 3-grams and 4-grams (`de_repeated_ngram_uniformity`)

## Interpretation

Treat these metrics as triage data. They can be useful for comparison across texts or corpora, but they are genre-sensitive. Governmental, academic, legal, SEO, help-center and corporate texts can legitimately look formulaic and uniform.

Recommended wording for reports:

> The text shows several weak style hints that are compatible with formulaic or generated prose. These hints do not prove AI authorship.

Avoid wording such as:

> The text is AI-generated.
