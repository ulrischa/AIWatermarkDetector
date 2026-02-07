# AIWatermarkDetector
## Detect AI Watermarks in text or code

A small self-hostable web app that scans **text and code** for **detectable watermark/stego patterns** and common “hidden signal” techniques: Unicode invisibles, Bidi controls (Trojan Source), homoglyphs/confusables, normalization tricks, whitespace channels, encoded payloads (Base64/hex/percent-encoding), high-entropy blobs, URL tracking tokens, acrostics, and repetition/uniformity hints.

It runs **client-only** (vanilla JS, single `index.html`) and can optionally use a **PHP API** to improve Unicode/confusable detection using ICU (`ext-intl`).

> Important: Many modern “model-side” watermarking schemes are **not reliably detectable from text alone** (they rely on secret keys, model telemetry, or statistical tests requiring the generator). This tool focuses on **observable output artifacts**.

---

## Contents

- [Features](#features)
- [Methods / Checks](#methods--checks)
- [Install](#install)
- [Usage](#usage)
- [Examples](#examples)
- [False Positive Strategy](#false-positive-strategy)
- [PHP API details](#php-api-details)
- [Security notes](#security-notes)
- [Limitations](#limitations)
- [Troubleshooting](#troubleshooting)

---

## Features

- **Single-file web app** (`index.html`) using **vanilla JS**.
- **Selective checks**: enable/disable each method.
- **Run analysis** only enabled when input contains text.
- **URL masking** to avoid payload false positives from URLs.
- **Strict Base64 mode**: decodes and validates bytes to avoid noise hits.
- Optional **PHP API** (`api/analyze.php`) for:
  - richer Unicode scanning via ICU (`IntlChar`)
  - **ICU Spoofchecker** for confusable/mixed-script detection
  - server-side strict Base64 verification

---

## Methods / Checks

Below are the checks implemented. Each item links to a relevant reference / background.

### 1) Unicode invisibles / format / control characters
Detects common hidden characters that can carry signals or break comparisons:
- Zero-width chars, word-joiner, BOM, NBSP variants
- control characters (excluding tab/newline/carriage return)

References:
- Unicode **General Category** overview: https://www.unicode.org/reports/tr44/#General_Category_Values  
- Zero-width / formatting characters discussion: https://www.unicode.org/faq/utf_bom.html

### 2) Bidi / direction controls (Trojan Source)
Detects directionality overrides and isolates (RLO/LRO, RLI/LRI/FSI, PDF/PDI, LRM/RLM), plus simple pairing heuristics.

References:
- Trojan Source paper: https://trojansource.codes/  
- Unicode Bidirectional Algorithm: https://www.unicode.org/reports/tr9/

### 3) Unicode normalization tricks (NFKC differences)
Compares original text vs `NFKC` normalization; differences can indicate compatibility glyphs, ligatures, fullwidth forms, etc.

References:
- Unicode Normalization Forms: https://www.unicode.org/reports/tr15/  
- NFKC compatibility mapping rationale: https://www.unicode.org/reports/tr15/#Compatibility_Equivalence

### 4) Homoglyphs / mixed scripts (confusables)
Client: a small baseline confusable set (Greek/Cyrillic lookalikes).  
Server (optional): ICU **Spoofchecker** detects mixed-script and confusable identifiers.

References:
- Unicode confusables data: https://www.unicode.org/reports/tr39/  
- ICU Spoofchecker docs: https://unicode-org.github.io/icu-docs/apidoc/released/icu4c/uspoof_8h.html

### 5) Whitespace channel signals
Detects:
- trailing spaces/tabs on lines
- mixed indentation (tabs + spaces)
These can carry a hidden binary channel or act as a watermark in code.

References:
- General concept (text steganography): https://en.wikipedia.org/wiki/Text_steganography

### 6) Base64 / Base64URL payloads (strict mode)
Detects long Base64-like runs.
In **Strict** mode, it only reports a hit if:
- decoding succeeds **and**
- decoded bytes are mostly printable UTF-8 **or**
- decoded bytes match known “magic bytes” (gzip/zlib/zip/pdf)

References:
- RFC 4648 (Base64/Base64url): https://www.rfc-editor.org/rfc/rfc4648

### 7) Hex / escape payloads
Detects:
- `0x...` long hex literals
- common escape sequences: `\xNN`, `\uNNNN`, `\u{...}`

References:
- JavaScript escape sequences: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String

### 8) Percent-encoding payloads
Detects `%xx` sequences. With **URL masking enabled**, URL text is blanked to avoid noisy hits.

References:
- URL percent-encoding: https://url.spec.whatwg.org/#percent-encoded-bytes

### 9) High-entropy runs (encoded/compressed blobs)
Detects long alnum-like runs with high Shannon entropy (heuristic), often indicating encoded/compressed payloads.

References:
- Shannon entropy: https://en.wikipedia.org/wiki/Entropy_(information_theory)

### 10) URL tracking-like tokens
Detects common tracking keys and high-entropy query values:
- `srsltid`, `utm_*`, `gclid`, `fbclid`, `msclkid`, etc.

References:
- UTM parameters: https://en.wikipedia.org/wiki/UTM_parameters

### 11) Acrostics (sentences/lines/comments)
Collects first letters of sentences and lines/comments and looks for a small set of obvious “hint words” (configurable).

Reference:
- Acrostic concept: https://en.wikipedia.org/wiki/Acrostic

### 12) Repetition / uniformity heuristics
Computes:
- token count, unique count, TTR
- token distribution entropy
- repeated bigrams/trigrams (informational hints)
This is **not** a watermark detector; it’s a structure hint.

References:
- Type–token ratio: https://en.wikipedia.org/wiki/Type%E2%80%93token_ratio

### 13) Code identifier anomalies (mixed scripts/confusables)
**Important behavior**:
- Runs **only on code** (code-like input or fenced code blocks ```...```).
- Does **not** flag German umlauts in prose.
It flags identifiers that contain:
- mixed scripts (Latin + Cyrillic/Greek/etc.)
- known confusable characters
- non-Latin letters inside identifiers

References:
- Unicode TR39 confusables: https://www.unicode.org/reports/tr39/  
- Trojan Source + Bidi pitfalls: https://trojansource.codes/

---

## Install

### Option A: Client-only (recommended baseline)
1. Put `index.html` on any static web host.
2. Open it in a browser.

### Option B: With PHP API (enhanced)
Directory layout:
````

/your-webroot
index.html
/api
analyze.php

```

Requirements:
- PHP 8+ recommended
- Optional but recommended: `ext-intl` enabled (for Spoofchecker/IntlChar/Normalizer)

---

## Usage

1. Open the page.
2. Paste text or code into the textarea.
3. Select checks (chips).
4. Click **Run analysis** (enabled only when text is non-empty).
5. Optionally enable **Use PHP API**:
   - If the API is reachable, it improves Unicode/confusable checks.

Toggles:
- **Mask URLs for payload checks** (default ON): reduces false positives for Base64/percent/entropy checks.
- **Strict Base64 mode** (default ON): prevents Base64 false positives on random words.
- **Analyze URLs for tracking tokens** (default ON): extracts query tokens like `srsltid`, `utm_*`.

---

## Examples

### Example 1: Detect Bidi controls
Input:
```

Bidi example: ABC ‮123‬ DEF

```
Expected:
- **Bidi / direction controls**: hits for `RLO` / `PDF` (or isolates)

### Example 2: Detect invisible Unicode
Input:
```

This has a hidden marker: Testcase

````
(contains ZWSP U+200B)
Expected:
- **Unicode invisibles**: finding showing `U+200B ZERO WIDTH SPACE`

### Example 3: Detect confusables in identifiers (code only)
Input:
```js
const paylоad = "x"; // the 'o' is Cyrillic U+043E
````

Expected:

* **Code identifier anomalies**: `paylоad` flagged (mixed scripts/confusable)

### Example 4: Strict Base64 hit

Input:

```
SGVsbG8sIFVsaSE=
```

Expected:

* **Base64 payloads (strict)**: 1 hit, decoded preview “Hello, Uli!”

### Example 5: URL tracking tokens

Input:

```
https://example.com/?utm_source=newsletter&gclid=abc123
```

Expected:

* **URL tracking-like tokens**: hits for `utm_source`, `gclid`

---

## False Positive Strategy

This project is designed to avoid “everything looks suspicious” outputs.

Key measures:

* **Strict Base64 mode** only reports decodable + printable/known-signature payloads.
* **URL masking** prevents:

  * percent-encoding hits from URLs
  * entropy hits from long tracking tokens
* **Code identifier anomalies**:

  * only scans **code contexts**
  * does **not** treat Latin diacritics (äöüß) as suspicious
  * flags only mixed scripts / confusables / non-Latin letters

---

## PHP API details

Endpoint: `POST /api/analyze.php`
Body:

```json
{
  "text": "…",
  "selected": ["unicode_homoglyph","unicode_bidi","payload_base64"],
  "settings": { "maskUrls": true }
}
```

Response:

```json
{
  "ok": true,
  "meta": { "intl_available": true, "spoofchecker_available": true, ... },
  "server": {
    "unicode_scan": [...],
    "bidi_pairing": { "issues": [...] },
    "spoof_tokens": { "available": true, "suspicious": [...] },
    "normalization": { "available": true, "differs": false },
    "base64": [...]
  }
}
```

Notes:

* If `ext-intl` is missing, the API still returns JSON but with reduced capability.
* If PHP emits warnings/notices to output, it can break JSON. Keep `display_errors=Off` in production and check logs.

---

## Security notes

* The app does **not** execute pasted code.
* If you deploy the PHP API publicly:

  * consider rate limiting
  * restrict origin if needed (CORS is permissive by default)
  * log errors to file, not to response

---

## Limitations

* “True” AI watermark detection for modern schemes often requires:

  * knowledge of the generator/model
  * secret keys or telemetry
  * statistical tests not possible on a single sample
* This tool detects **observable artifacts** and **likely stego channels**, not “proof of AI generation”.




