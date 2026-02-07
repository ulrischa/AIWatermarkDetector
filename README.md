# AIWatermarkDetector
## Detect AI Watermarks in text or code

A self-hostable web app that scans **text and code** for **detectable watermark/steganography artifacts** and “hidden signal” techniques: Unicode invisibles, BiDi controls (Trojan Source), homoglyph/confusables, normalization tricks, whitespace channels, encoded payloads (Base64/hex/percent-encoding), high-entropy blobs, URL tracking tokens, acrostics, and repetition/uniformity hints.

Runs **client-only** (vanilla JS, single `index.html`). Optionally use a **PHP API** for higher-fidelity Unicode/confusable detection using ICU (`ext-intl`).

---

## Research snapshot

### A) LLM watermarking (token-level / statistical)
These are **model-side watermarking schemes**. They usually require a **secret key** or a detection procedure; detection from arbitrary text alone is often not reliable unless you know the watermark family and parameters.

- **A Watermark for Large Language Models** (Kirchenbauer et al., 2023)  
  https://arxiv.org/abs/2301.10226  
  https://proceedings.mlr.press/v202/kirchenbauer23a.html  
  *Key idea:* “greenlist” token bias + statistical test.

- **On the Reliability of Watermarks for Large Language Models** (Kirchenbauer et al.)  
  https://openreview.net/forum?id=DEJIDCmWOz  
  *Focus:* detectability under paraphrasing / mixing.

- **Watermark under Fire: A Robustness Evaluation of LLM Watermarking (WaterPark)**  
  https://arxiv.org/html/2411.13425v3  
  *Focus:* unified evaluation + attacks and robustness.

- **A Robustness Evaluation of LLM Watermarking** (Findings of EMNLP 2025)  
  https://aclanthology.org/2025.findings-emnlp.1148.pdf  
  *Focus:* systematic robustness study across watermarkers.

- **A Survey of Text Watermarking in the Era of Large Language Models** (Liu et al., 2024 / 2023 preprint)  
  https://dl.acm.org/doi/full/10.1145/3691626  
  https://arxiv.org/pdf/2312.07913  
  *Focus:* taxonomy, evaluation, attacks, and design space.

**How this app relates:**  
This app does **not** claim to detect greenlist/token-bias watermarks generically. It focuses on **observable artifacts** in the final text (Unicode/format/payload channels). It also provides **structure heuristics** (repetition, uniformity) as hints—not proof.

---

### B) Text steganography / format-based text watermarking (detectable in plain text)
These methods often embed data using **Unicode spaces**, **zero-width characters**, or similar “invisible” substitutions, which *can* be detected by scanning the output.

- **Trojan Source: Invisible Vulnerabilities** (Boucher & Anderson et al., 2021)  
  https://arxiv.org/pdf/2111.00169  
  https://trojansource.codes/  
  *BiDi control characters* can visually reorder code.

- **Unicode Security Mechanisms (UTS #39)**  
  https://www.unicode.org/reports/tr39/  
  *Confusables* and mixed-script identifier detection.

- **Innamark: A Whitespace Replacement Information-Hiding Technique…**  
  https://arxiv.org/html/2502.12710v3  
  *Idea:* encode by swapping “visually similar” Unicode whitespace.

- **A Hidden Digital Text Watermarking Method Using Unicode Whitespace Replacement** (2025)  
  https://scholarspace.manoa.hawaii.edu/server/api/core/bitstreams/0f11e4d3-625e-4840-971c-24808e9499a8/content  
  *Idea:* replace conventional spaces with a set of Unicode spaces.

- **Hybrid text steganography using Unicode space + zero-width characters** (2017)  
  https://www.researchgate.net/publication/314449134_A_HYBRID_TEXT_STEGANOGRAPHY_APPROACH_UTILIZING_UNICODE_SPACE_CHARACTERS_AND_ZERO-WIDTH_CHARACTER

- **Fraunhofer ISST “Innamark” repo (implementation)**  
  https://github.com/FraunhoferISST/Innamark

**How this app relates:**  
These map directly to the app’s **Unicode invisibles**, **Unicode whitespace variants**, **BiDi controls**, and **confusables** checks.

---

### C) Watermarking for code / software watermarking (semantics-preserving)
Code watermarking often uses transformations such as **reordering**, **identifier changes**, **dead code**, **format/whitespace**, etc. Some are detectable heuristically; many require a key/detector.

- **Who Wrote this Code? Watermarking for Code Generation** (ACL 2024)  
  https://aclanthology.org/2024.acl-long.268.pdf  
  *Focus:* watermarking machine-generated code; robustness.

- **Practical and Effective Code Watermarking for Large Language Models** (OpenReview, 2025)  
  https://openreview.net/pdf/e28031c958fa8b0115bf14d0fcd0a2c33c8d8826.pdf

- **A Survey of Software Watermarking by Code Re-Ordering** (Hamilton)  
  https://jameshamilton.eu/sites/default/files/CodeReOrderingWatermarks.pdf

**How this app relates:**  
The app provides **Trojan Source / UTS #39 identifier checks**, **whitespace channel checks**, and **encoded payload checks** that matter especially for code review.

---

### D) PHP ICU tooling references (for the optional API)
- PHP `Spoofchecker` (ICU): https://www.php.net/manual/en/class.spoofchecker.php  
- PHP `IntlChar`: https://www.php.net/manual/en/class.intlchar.php  
- PHP `Normalizer`: https://www.php.net/manual/en/class.normalizer.php  

---

## Contents
- Features
- Methods / checks
- Install
- Usage
- Examples
- False positive strategy
- PHP API details
- Security notes
- Limitations
- Troubleshooting

---

## Features
- Single-file web app (`index.html`) using vanilla JS
- Choose which checks to run
- “Run analysis” button is enabled only when input is non-empty
- URL masking to reduce payload false positives
- Strict Base64 mode to avoid noise hits
- Optional PHP API for higher-fidelity Unicode/confusable checks

---

## Methods / checks (what is detected)

### 1) Unicode invisibles & controls
Detects suspicious or hidden Unicode categories:
- Zero-width chars (ZWSP, ZWNJ, ZWJ), word joiner, BOM
- Control characters (excluding newline/tab if configured)
- Non-breaking spaces and uncommon Unicode spaces

Why it matters:
- Used for text stego/watermarking and “invisible markers”
- Can change tokenization or copy/paste semantics

### 2) BiDi / Trojan Source controls
Detects BiDi formatting chars (RLO/LRO, RLE/LRE, PDF, RLI/LRI/FSI, PDI, LRM/RLM) and performs simple pairing sanity checks.

Why it matters:
- Can make code **look** different from what compilers interpret.

### 3) Unicode normalization drift (NFKC)
Computes whether `NFKC` normalization changes the text and highlights differences.

Why it matters:
- Compatibility characters (fullwidth forms, ligatures) can hide signals or confuse reviews.

### 4) Homoglyphs / confusables / mixed-script identifiers (code-focused)
Client-only baseline:
- Detects a small set of common confusables and mixed-script runs.
Server (optional, recommended):
- ICU Spoofchecker flags confusable/mixed-script patterns more accurately.

Important:
- This check is **code-context aware** and should not flag normal prose diacritics (ä, ö, ü, ß).

### 5) Whitespace channel signals
Detects:
- Trailing spaces/tabs per line
- Mixed indentation patterns
- Uncommon Unicode spaces (if enabled)

Why it matters:
- Whitespace can encode bits or act as a watermark in code.

### 6) Encoded payloads
- Base64/Base64url (strict)
- Hex blobs / escape sequences (`\xNN`, `\uNNNN`, `\u{...}`)
- Percent-encoding runs

Strict Base64 mode:
- Only reports if decoding succeeds AND output is mostly printable UTF-8 OR matches known signatures.

### 7) High-entropy runs (heuristic)
Flags long alnum-like runs with high Shannon entropy.

Why it matters:
- Can indicate encoded/compressed hidden payloads.

### 8) URL tracking tokens
Flags common tracking params:
- `utm_*`, `gclid`, `fbclid`, `msclkid`, `srsltid`, etc.

### 9) Acrostics (lightweight)
Collects first letters of lines/sentences and checks for obvious embedded cue words (configurable).

### 10) Repetition / uniformity hints
Computes:
- token count, unique count, TTR
- entropy
- repeated trigrams

Important:
- This is a **hint** for template-like text or copy/paste artifacts, not a watermark proof.

---

## Install

### Client-only
1. Host `index.html` on any static server (or open locally).
2. Open in a modern browser.

### With PHP API (enhanced)
Layout:
```

/your-webroot
index.html
/api
analyze.php

````

Requirements:
- PHP 8+ recommended
- `ext-intl` strongly recommended (for Spoofchecker / IntlChar / Normalizer)

---

## Usage
1. Paste input text/code.
2. Select checks.
3. Click **Run analysis**.
4. (Optional) Enable **Use PHP API** to improve Unicode/confusables detection.

Recommended defaults:
- Mask URLs for payload checks: ON
- Strict Base64: ON

---

## Examples

### Example: Trojan Source BiDi controls
Input:
```txt
if (isAdmin) { /* safe */ } ‮ } /* evil */ if (isAdmin) { ‬
````

Expected:

* BiDi controls detected (RLO/PDF or isolates) + pairing warning.

### Example: Invisible Unicode marker

Input (contains U+200B ZWSP between “Test” and “case”):

```txt
Test​case
```

Expected:

* Unicode invisibles: shows U+200B and position.

### Example: Confusable identifier (code)

Input (`o` is Cyrillic U+043E):

```js
const paylоad = "x";
```

Expected:

* Identifier anomaly: mixed-script / confusable.

### Example: Strict Base64 payload

Input:

```txt
SGVsbG8sIFVsaSE=
```

Expected:

* Base64 detected + decoded preview “Hello, Uli!”

### Example: URL tracking tokens

Input:

```txt
https://example.com/?utm_source=newsletter&gclid=abc123
```

Expected:

* Tracking tokens: `utm_source`, `gclid`.

---

## False positive strategy (design principles)

* **Strict Base64**: requires valid decode + printable output/signature.
* **URL masking**: prevents percent/Base64/entropy false positives from URLs.
* **Code-context for identifier anomalies**: do not flag normal prose diacritics.
* **Heuristic checks marked as “Hints”**: repetition/entropy are not claims.

---

## PHP API details (optional)

Endpoint: `POST /api/analyze.php`

Request:

```json
{
  "text": "…",
  "selected": ["unicode_confusables","unicode_bidi","payload_base64"],
  "settings": { "maskUrls": true, "strictBase64": true }
}
```

Response (shape example):

```json
{
  "ok": true,
  "meta": {
    "intl_available": true,
    "spoofchecker_available": true,
    "normalizer_available": true
  },
  "server": {
    "unicode": { "findings": [] },
    "spoofchecker": { "suspicious": false, "details": [] },
    "bidi": { "findings": [] },
    "base64": { "hits": [] }
  }
}
```

Operational notes:

* If `ext-intl` is missing, the API returns `ok: true` but sets `*_available: false` and skips those checks.
* Ensure PHP warnings/notices are not printed into the response (keep JSON clean).

---

## Security notes

* The app never executes pasted code.
* If you expose the PHP API publicly:

  * add basic rate limiting
  * consider restricting origins (CORS) if needed
  * log errors server-side instead of printing them

---

## Limitations

* Many LLM watermark schemes are **not** detectable from a single text without knowing the watermark family/parameters.
* This tool detects **output-level artifacts** (Unicode/format/payload channels) and provides **non-proof hints**.

