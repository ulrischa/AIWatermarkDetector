# AIWatermarkDetector

A self-hostable web app that scans plain text and source code for detectable watermarking / steganography artifacts and related “hidden signal” techniques, with a conservative, false-positive-averse approach.

It runs client-only (single index.html, vanilla JS). An optional PHP 8+ API (with ext-intl / ICU) can improve a few Unicode security checks (confusables / spoofing heuristics) and normalization handling.


---

1) What this tool is (and is not)

What it can provide as verifiable evidence

This scanner can produce verifiable findings that you can independently validate, such as:

Presence of Unicode invisibles (e.g., ZWSP, ZWJ, BOM) and other special/control characters

BiDi controls used in Trojan Source style attacks (characters that can visually reorder code) 

Use of unusual Unicode whitespace (a known channel for text stego/watermarking) 

Encoded payload candidates (strict Base64 / hex / escapes / percent encoding) with decode evidence (Base64 per RFC 4648) 

Tracking parameters in URLs (utm_*, gclid, fbclid, msclkid, srsltid, …)


These are strong because they are objective properties of the text (code points, byte patterns, decode results).

What it cannot reliably prove on its own

It does not generically detect “LLM token-level watermarks” (greenlist / sampling bias schemes) from arbitrary text without knowing the watermark family/parameters/key. Token-level watermarking is an active research area and detection is typically scheme-specific. 

It does not prove authorship (“this was written by AI”) from style alone. Style heuristics can be suggestive but are not court-grade evidence.


Practical takeaway: use this tool for artifact-level evidence (hidden marks, encoding channels, Unicode security issues). For AI authorship/provenance, combine with provider provenance, logging, or watermark detectors specific to a known scheme.


---

2) Evidence model used by the UI

The UI groups findings into evidence levels:

PROOF (verifiable artifacts)

Findings that are directly inspectable and reproducible:

Specific code points (e.g., U+202E)

Decoded payload previews with validation

Concrete line/column locations


STRONG (validated decode / clear signal)

Still highly actionable, but may require interpretation:

Base64 blobs that decode cleanly to mostly-printable UTF-8

Strong Unicode-security flags (especially via ICU Spoofchecker)


MEDIUM (conservative indicators)

Signals that are suspicious but can appear naturally in some contexts:

Uncommon whitespace patterns (e.g., systematic trailing spaces)

Mixed indentation patterns consistent with a channel


HINT (heuristics, not proof)

Useful for triage, not suitable alone for “proof”:

Repetition/uniformity signals

Entropy flags

Acrostic hints



---

3) Detection methods (how they work, and how false positives are avoided)

3.1 Unicode invisibles & special controls

Goal: detect characters commonly used to hide bits or change interpretation without visible changes.

Typical targets:

Zero-width characters (ZWSP, ZWNJ, ZWJ)

Word joiner, BOM

Non-printing format controls (selectively)


Why it matters:

Frequently used in text steganography/watermarking.

Can survive copy/paste and travel through systems.


False-positive controls:

Newlines are allowed; tabs are usually allowed (configurable).

Findings report exact code points and positions so you can verify visually (code point display).



---

3.2 BiDi / Trojan Source controls

Goal: catch Unicode BiDi formatting characters that can make code look different from how it is interpreted.

Reference:

Trojan Source (“Invisible Vulnerabilities”) 


False-positive controls:

Only flags the known BiDi controls / isolates (e.g., RLO, PDF, RLI/PDI).

Includes pairing sanity checks (unbalanced isolates etc.) to reduce noise.



---

3.3 Unicode whitespace variants (format-based watermarking / stego channel)

Goal: detect replacement of ordinary spaces with visually similar Unicode spaces.

Why it matters:

A known family of text watermark/stego methods uses whitespace substitution. Example research and implementations:

Innamark (whitespace replacement information hiding) 

Unicode whitespace replacement watermarking method 



False-positive controls:

“Unusual whitespace” is only elevated when it is systematic (frequency/pattern) or appears in channel-like positions (e.g., repeated between words, trailing).

Findings show the exact whitespace code points to allow independent verification.



---

3.4 Unicode normalization drift (NFKC/NFC)

Goal: detect strings whose meaning/appearance changes under normalization.

Reference:

Unicode Normalization Forms (UAX #15) 


Why it matters:

Compatibility characters (fullwidth forms, ligatures) can obscure content, confuse comparisons, or be used as a channel.


False-positive controls:

Only reports when normalization actually changes the string.

Diffs are shown around changed spans (not “global scary warnings”).



---

3.5 Confusables / mixed-script identifiers (code-focused)

Goal: detect look-alike characters in identifiers (Trojan Source adjacent, but different: visual spoofing rather than reordering).

Reference:

Unicode Security Mechanisms (UTS #39), including mixed-script and confusables 


How the tool approaches it:

Client-only baseline: conservative heuristics in code-like contexts (identifiers).

Optional server check: ICU Spoofchecker for higher fidelity spoof detection. 


Critical false-positive rule (important for German prose):

Do not flag normal diacritics (ä, ö, ü, ß) as “identifier anomalies” unless they appear inside a code identifier and the rule explicitly targets “non-ASCII in identifiers” for a code review use-case.

In other words: plain German text should not be flooded with “non-ASCII” warnings.


Best practice:

Run identifier spoofing checks only when the input is actually code, or when “code mode” is enabled.



---

3.6 Whitespace channel signals (trailing spaces, indentation patterns)

Goal: detect channels based on:

trailing spaces/tabs per line

inconsistent indentation sequences

repeated per-line patterns consistent with bit encoding


False-positive controls:

Only reports when there is patterned repetition, not a single stray trailing space.

Scores depend on how systematic the pattern is.



---

3.7 Encoded payloads (Base64/Base64URL, hex, escapes, percent encoding)

Goal: detect hidden payloads embedded in otherwise normal text.

Standards / references:

Base64 (RFC 4648) 

URL parsing and percent encoding behavior (WHATWG URL Standard) 


False-positive controls (recommended defaults):

Strict Base64 mode:

candidate length threshold (avoid tiny accidental matches)

alphabet validation

padding rules

decode must succeed

decoded output must be mostly printable UTF-8 or match a known signature (JSON-like, XML-like, etc.)


URL masking for payload checks:

prevents percent/base64/entropy false positives coming from long URLs or tracking fragments.




---

3.8 High-entropy runs (heuristic)

Goal: flag long high-entropy alnum-like spans that might be compressed/encoded data.

False-positive controls:

Keep this in HINT level.

Require a minimum span length and entropy threshold.



---

3.9 URL tracking tokens

Goal: identify common tracking parameters (e.g., utm_source, gclid, fbclid, msclkid, srsltid).

False-positive controls:

Only flags known parameter keys; does not treat “any query string” as tracking.



---

3.10 Repetition/uniformity hints (token trigrams)

Goal: provide a lightweight “template-like text” hint (e.g., copy/paste blocks, repeated phrasing).

Important:

This is not a watermark detector.

It can fire on legitimate structured writing (guides, lists, policies).


False-positive controls:

Keep it in HINT.

Present as “may indicate templating or copy/paste” not as “AI watermark found”.



---

3.11 Acrostics (light heuristic)

Goal: catch obvious acrostic patterns across lines/sentences (rare, but cheap).

False-positive controls:

Strictly a hint; requires meaningful matches, not random strings.



---

4) Why scanning a README can legitimately show “watermarks”

If your documentation includes example strings that themselves contain:

BiDi controls (RLO/PDF),

ZWSP,

utm_* / gclid in URLs,


…then the scanner should report them. That is correct behavior: the scanner analyzes the actual characters present in the README.

Tip for documentation authors: keep such examples clearly marked (fenced code blocks) and, as a future improvement, add a “ignore fenced code blocks” toggle if you want the scanner to focus on narrative text only.


---

5) Optional PHP API (PHP 8+, ext-intl)

Why an API helps

Browsers provide good Unicode handling, but ICU offers higher quality tooling for:

spoofing/confusable checks via Spoofchecker 

normalization and code point categorization via Normalizer/IntlChar (both in ext-intl) 


Endpoint contract (recommended)

POST /api/analyze.php with JSON:

{
  "text": "…",
  "selected": ["unicode_confusables", "unicode_bidi", "payload_base64"],
  "settings": { "maskUrls": true, "strictBase64": true }
}

Response:

{
  "ok": true,
  "meta": {
    "intl_available": true,
    "spoofchecker_available": true,
    "normalizer_available": true
  },
  "server": {
    "spoofchecker": { "suspicious": false, "details": [] }
  }
}

Security guidance if you expose the API

Enforce a max input size (e.g., 200–500 KB).

Add basic rate limiting (even a simple token bucket).

Return JSON only; never echo warnings/notices into the body.

Consider restricting allowed origins (CORS) if used across sites.



---

6) Recommended usage workflow for “reliable evidence”

If your goal is defensible reporting, treat this like a forensic workflow:

1. Preserve the original text exactly as received (copy raw, avoid editors that normalize).


2. Run scanner with PROOF + STRONG checks enabled.


3. Export or screenshot:

the specific findings list

the exact code points (e.g., U+202E)

line/column context



4. Re-verify independently:

confirm the code points using another tool (Unicode inspector)

confirm Base64 decode using a second implementation (RFC 4648 compatible)



5. Report using “artifact language”:

“The text contains U+202E RIGHT-TO-LEFT OVERRIDE at index …”

“The text uses non-breaking space U+00A0 in 37 systematic positions”

Avoid “AI wrote this” unless you have scheme-specific watermark detection.





---

7) Limitations (be explicit in documentation and reports)

Token-level LLM watermarking detection is scheme-dependent and actively studied. 

Robustness of watermarks varies under paraphrase/mixing and is a known research topic. 

Code watermarking exists, but may require model-side cooperation or specialized detectors. 

This tool focuses on observable artifacts and conservative indicators.



---

8) Method references (papers, standards, docs)

LLM watermarking (background; not generically detectable here)

Kirchenbauer et al., “A Watermark for Large Language Models” 

Kirchenbauer et al., “On the Reliability of Watermarks for LLMs” 

“A Survey of Text Watermarking in the Era of Large Language Models” 

“Watermark under Fire / WaterPark” robustness evaluation 

“A Robustness Evaluation of LLM Watermarking” (Findings EMNLP 2025) 


Text steganography / format watermarking

Trojan Source 

Innamark (whitespace replacement) 

Unicode whitespace replacement watermarking method 


Unicode standards

UTS #39 (confusables / mixed script) 

UAX #15 (Unicode normalization) 


Encoding standards

RFC 4648 (Base16/Base32/Base64) 

WHATWG URL Standard 


PHP ICU (ext-intl) docs

Spoofchecker manual 

intl extension overview 


Code watermarking (background)

“Who Wrote this Code? Watermarking for Code Generation” 

“Practical and Effective Code Watermarking for LLMs” 



