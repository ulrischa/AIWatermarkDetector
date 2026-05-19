(() => {
  'use strict';

  // GEAENDERT: Main scanner logic moved into an external asset and extended with German AI-style API hints.
  const METHODS = [
    { id: 'unicode_specials', label: 'Unicode invisibles & controls', level: 'PROOF', score: 95, link: 'https://www.unicode.org/reports/tr44/#General_Category_Values' },
    { id: 'unicode_bidi', label: 'BiDi / Trojan Source controls', level: 'PROOF', score: 95, link: 'https://trojansource.codes/' },
    { id: 'unicode_normalization', label: 'Normalization drift (NFKC/NFC)', level: 'MEDIUM', score: 70, link: 'https://www.unicode.org/reports/tr15/' },
    { id: 'unicode_homoglyph', label: 'Mixed-script/confusables (code-only, conservative)', level: 'MEDIUM', score: 70, link: 'https://www.unicode.org/reports/tr39/' },
    { id: 'whitespace_channel', label: 'Whitespace channels (trailing/mixed indent)', level: 'MEDIUM', score: 70, link: 'https://en.wikipedia.org/wiki/Text_steganography' },
    { id: 'urls_tracking', label: 'URL tracking tokens (utm/gclid/fbclid/srsltid…)', level: 'PROOF', score: 90, link: 'https://en.wikipedia.org/wiki/UTM_parameters' },
    { id: 'payload_percent', label: 'Percent-encoding payload runs', level: 'STRONG', score: 85, link: 'https://url.spec.whatwg.org/#percent-encoded-bytes' },
    { id: 'payload_base64', label: 'Base64 payloads (strict decode graph)', level: 'STRONG', score: 85, link: 'https://www.rfc-editor.org/rfc/rfc4648' },
    { id: 'payload_hex_escapes', label: 'Hex blobs & escape payloads (\\xNN / \\uNNNN)', level: 'MEDIUM', score: 70, link: 'https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/String' },
    { id: 'payload_entropy', label: 'High-entropy runs (heuristic)', level: 'HINT', score: 40, link: 'https://en.wikipedia.org/wiki/Entropy_(information_theory)' },
    { id: 'acrostics', label: 'Acrostics (light heuristic)', level: 'HINT', score: 30, link: 'https://en.wikipedia.org/wiki/Acrostic' },
    { id: 'repetition', label: 'Repetition/uniformity hints (token trigrams)', level: 'HINT', score: 30, link: 'https://en.wikipedia.org/wiki/Type%E2%80%93token_ratio' },
    { id: 'de_ai_style', label: 'German AI-style heuristics (API, hint-only)', level: 'HINT', score: 25, link: './docs/de-ai-style-heuristics.md' },
  ];

  const DEFAULT_SELECTED = new Set([
    'unicode_specials',
    'unicode_bidi',
    'unicode_normalization',
    'unicode_homoglyph',
    'whitespace_channel',
    'urls_tracking',
    'payload_base64',
    'payload_percent',
    'payload_hex_escapes',
  ]);

  const $ = (id) => document.getElementById(id);
  const input_el = $('input');
  const run_btn = $('run');
  const clear_btn = $('clear');
  const copy_btn = $('copyJson');
  const download_btn = $('downloadJson');
  const checks_el = $('checks');
  const results_el = $('results');
  const api_status_el = $('apiStatus');

  let latest_report = null;

  function escape_html(value) {
    return String(value).replace(/[&<>"']/g, (char) => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      '"': '&quot;',
      "'": '&#39;',
    }[char]));
  }

  function now_iso() {
    return new Date().toISOString();
  }

  function get_mode_choice() {
    const radio = document.querySelector('input[name="mode"]:checked');
    return radio ? radio.value : 'auto';
  }

  function auto_detect_mode(text) {
    const has_fence = /```/.test(text);
    const code_signals = (text.match(/[{}()[\];<>=$]/g) || []).length;
    const lines = text.split(/\r?\n/);
    const looks_like_code_line = lines.some((line) => /^\s*(function|class|const|let|var|if|for|while|return|import|export|public|private|protected|final|readonly)\b/.test(line));
    if (has_fence || looks_like_code_line) return 'code';
    if (code_signals >= 40 && text.length >= 400) return 'code';
    return 'text';
  }

  function selected_methods() {
    const selected = [];
    document.querySelectorAll('.chip input[type="checkbox"]').forEach((checkbox) => {
      if (checkbox.checked) selected.push(checkbox.dataset.method);
    });
    return selected;
  }

  function api_status_should_show() {
    return $('useApi').checked || selected_methods().includes('de_ai_style');
  }

  function update_api_status(text) {
    api_status_el.textContent = api_status_should_show() ? text : 'API: off';
  }

  function set_run_enabled() {
    const value = input_el.value.trim();
    run_btn.disabled = value.length === 0;
    clear_btn.disabled = input_el.value.length === 0;
  }

  function render_checks() {
    checks_el.innerHTML = '';
    for (const method of METHODS) {
      const checked = DEFAULT_SELECTED.has(method.id);
      const wrapper = document.createElement('label');
      wrapper.className = 'chip';
      wrapper.innerHTML = `
        <input type="checkbox" data-method="${escape_html(method.id)}" ${checked ? 'checked' : ''}>
        <span>${escape_html(method.label)}</span>
        <a href="${escape_html(method.link)}" target="_blank" rel="noreferrer">ref</a>
      `;
      checks_el.appendChild(wrapper);
    }
  }

  function method_meta(id) {
    return METHODS.find((method) => method.id === id) || { id, label: id, level: 'HINT', score: 20, link: '' };
  }

  function evidence_sort_key(level) {
    return ({ PROOF: 0, STRONG: 1, MEDIUM: 2, HINT: 3 })[level] ?? 9;
  }

  function cp_hex(codepoint) {
    return 'U+' + codepoint.toString(16).toUpperCase().padStart(4, '0');
  }

  function bytes_to_hex(bytes, max = 32) {
    const limit = Math.min(bytes.length, max);
    let out = '';
    for (let i = 0; i < limit; i++) out += bytes[i].toString(16).padStart(2, '0');
    if (bytes.length > max) out += '…';
    return out;
  }

  function safe_excerpt(text, index, length = 50) {
    const start = Math.max(0, index - 18);
    const end = Math.min(text.length, index + length);
    return text.slice(start, end);
  }

  function compute_token_stats(text) {
    const tokens = text.match(/[\p{L}\p{N}]+|[^\s]/gu) || [];
    const unique = new Set(tokens);
    const ttr = unique.size / Math.max(1, tokens.length);

    const frequency = new Map();
    for (const token of tokens) frequency.set(token, (frequency.get(token) || 0) + 1);

    let entropy = 0;
    for (const count of frequency.values()) {
      const probability = count / Math.max(1, tokens.length);
      entropy += -probability * Math.log2(probability);
    }

    let repeated_trigrams = 0;
    const seen = new Map();
    for (let i = 0; i + 2 < tokens.length; i++) {
      const trigram = tokens[i] + '\u0001' + tokens[i + 1] + '\u0001' + tokens[i + 2];
      seen.set(trigram, (seen.get(trigram) || 0) + 1);
    }
    for (const count of seen.values()) if (count >= 2) repeated_trigrams += count - 1;

    return {
      tokens: tokens.length,
      unique: unique.size,
      ttr: Number(ttr.toFixed(3)),
      entropy: Number(entropy.toFixed(3)),
      repeated_trigrams,
    };
  }

  function extract_urls(text) {
    const regex = /\bhttps?:\/\/[^\s<>()"']+/gi;
    const urls = [];
    let match;
    while ((match = regex.exec(text)) !== null) urls.push({ url: match[0], index: match.index });
    return urls;
  }

  function clean_url_for_parsing(url) {
    return url.replace(/[)\].,;:!?]+$/g, '');
  }

  function mask_urls(text, urls) {
    if (!urls.length) return text;
    const chars = text.split('');
    for (const url of urls) {
      for (let i = url.index; i < url.index + url.url.length && i < chars.length; i++) chars[i] = ' ';
    }
    return chars.join('');
  }

  function tracking_findings_for_url(url_string) {
    const findings = [];
    const tracking_keys = [
      'utm_source',
      'utm_medium',
      'utm_campaign',
      'utm_term',
      'utm_content',
      'gclid',
      'dclid',
      'gbraid',
      'wbraid',
      'fbclid',
      'msclkid',
      'srsltid',
      'yclid',
      'mc_cid',
      'mc_eid',
    ];
    let parsed;
    try {
      parsed = new URL(clean_url_for_parsing(url_string));
    } catch {
      return findings;
    }
    for (const [key, value] of parsed.searchParams.entries()) {
      const normalized_key = key.toLowerCase();
      if (tracking_keys.includes(normalized_key)) findings.push({ key: normalized_key, value, kind: 'tracking_param' });
    }
    return findings;
  }

  function is_printable_text(value) {
    if (!value) return false;
    const bad = (value.match(/\uFFFD/g) || []).length;
    const ratio = 1 - (bad / value.length);
    return ratio >= 0.995;
  }

  function magic_bytes_kind(bytes) {
    if (bytes.length < 4) return null;
    if (bytes[0] === 0x1F && bytes[1] === 0x8B) return 'gzip';
    if (bytes[0] === 0x78 && (bytes[1] === 0x01 || bytes[1] === 0x5E || bytes[1] === 0x9C || bytes[1] === 0xDA)) return 'zlib';
    if (bytes[0] === 0x50 && bytes[1] === 0x4B && bytes[2] === 0x03 && bytes[3] === 0x04) return 'zip';
    if (bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46) return 'pdf';
    return null;
  }

  function utf8_preview(bytes, max_chars = 220) {
    try {
      const decoder = new TextDecoder('utf-8', { fatal: false });
      const value = decoder.decode(bytes);
      const preview = value.slice(0, max_chars);
      const bad = (preview.match(/\uFFFD/g) || []).length;
      const ratio = 1 - (bad / Math.max(1, preview.length));
      return { ok: ratio >= 0.98, ratio: Number(ratio.toFixed(3)), preview };
    } catch {
      return { ok: false, ratio: 0, preview: '' };
    }
  }

  function normalize_base64(value, url_safe) {
    let normalized = value;
    if (url_safe) normalized = normalized.replace(/-/g, '+').replace(/_/g, '/');
    const mod = normalized.length % 4;
    if (mod === 1) return null;
    if (mod === 2) normalized += '==';
    if (mod === 3) normalized += '=';
    return normalized;
  }

  function atob_bytes(base64) {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i) & 0xFF;
    return bytes;
  }

  async function decompress_bytes(bytes, format) {
    if (typeof DecompressionStream === 'undefined') return null;
    try {
      const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream(format));
      const buffer = await new Response(stream).arrayBuffer();
      return new Uint8Array(buffer);
    } catch {
      return null;
    }
  }

  function base64_candidates(text) {
    const out = [];
    let match;
    const base64_regex = /(^|[^A-Za-z0-9+\/=])([A-Za-z0-9+\/]{12,}(?:={0,2}))(?![A-Za-z0-9+\/=])/g;
    while ((match = base64_regex.exec(text)) !== null) {
      const prefix = match[1] || '';
      const candidate = match[2];
      if (candidate.length < 16) continue;
      if (!/[0-9=+\/]/.test(candidate)) continue;
      out.push({ kind: 'base64', cand: candidate, index: match.index + prefix.length });
    }

    const base64_url_regex = /(^|[^A-Za-z0-9_=-])([A-Za-z0-9_-]{12,}(?:={0,2}))(?![A-Za-z0-9_=-])/g;
    while ((match = base64_url_regex.exec(text)) !== null) {
      const prefix = match[1] || '';
      const candidate = match[2];
      if (candidate.length < 16) continue;
      if (!/[-_]/.test(candidate)) continue;
      if (!/[0-9=_-]/.test(candidate)) continue;
      out.push({ kind: 'base64url', cand: candidate, index: match.index + prefix.length });
    }
    return out;
  }

  function percent_runs(text, min_count = 12) {
    const hits = [];
    const regex = /%[0-9A-Fa-f]{2}/g;
    let match;
    let last = -10;
    let start = -1;
    let count = 0;
    while ((match = regex.exec(text)) !== null) {
      if (start === -1) {
        start = match.index;
        count = 1;
        last = match.index;
        continue;
      }
      if (match.index - last <= 4) {
        count++;
        last = match.index;
        continue;
      }
      if (count >= min_count) hits.push({ index: start, count });
      start = match.index;
      count = 1;
      last = match.index;
    }
    if (count >= min_count) hits.push({ index: start, count });
    return hits;
  }

  function shannon_entropy(value) {
    const frequency = new Map();
    for (const char of value) frequency.set(char, (frequency.get(char) || 0) + 1);
    const size = value.length || 1;
    let entropy = 0;
    for (const count of frequency.values()) {
      const probability = count / size;
      entropy += -probability * Math.log2(probability);
    }
    return entropy;
  }

  function entropy_runs(text) {
    const regex = /[A-Za-z0-9+/=_-]{80,}/g;
    const out = [];
    let match;
    while ((match = regex.exec(text)) !== null) {
      const value = match[0];
      const entropy = shannon_entropy(value);
      if (entropy >= 4.4) out.push({ index: match.index, length: value.length, entropy: Number(entropy.toFixed(3)) });
    }
    return out;
  }

  function unicode_findings_client(text) {
    const findings = [];
    const bidi = new Map([
      [0x202A, 'LRE'], [0x202B, 'RLE'], [0x202C, 'PDF'], [0x202D, 'LRO'], [0x202E, 'RLO'],
      [0x2066, 'LRI'], [0x2067, 'RLI'], [0x2068, 'FSI'], [0x2069, 'PDI'],
      [0x200E, 'LRM'], [0x200F, 'RLM'],
    ]);
    const invisibles = new Map([
      [0x200B, 'ZWSP'], [0x200C, 'ZWNJ'], [0x200D, 'ZWJ'], [0x2060, 'WORD JOINER'],
      [0xFEFF, 'BOM'], [0x00A0, 'NBSP'], [0x202F, 'NNBSP'], [0x2007, 'FIGURE SPACE'],
      [0x2009, 'THIN SPACE'], [0x200A, 'HAIR SPACE'], [0x3000, 'IDEOGRAPHIC SPACE'],
      [0x034F, 'COMBINING GRAPHEME JOINER'],
    ]);

    let index = 0;
    for (const char of text) {
      const codepoint = char.codePointAt(0);
      const is_variation_selector = (codepoint >= 0xFE00 && codepoint <= 0xFE0F) || (codepoint >= 0xE0100 && codepoint <= 0xE01EF);
      const is_tag = codepoint >= 0xE0000 && codepoint <= 0xE007F;
      const is_control = (codepoint < 32 && codepoint !== 9 && codepoint !== 10 && codepoint !== 13) || codepoint === 0x7F;

      if (bidi.has(codepoint)) {
        findings.push({ method: 'unicode_bidi', level: 'PROOF', score: 95, message: `BiDi control ${bidi.get(codepoint)} (${cp_hex(codepoint)})`, index, excerpt: safe_excerpt(text, index) });
      } else if (invisibles.has(codepoint)) {
        findings.push({ method: 'unicode_specials', level: 'PROOF', score: 95, message: `Invisible/special ${invisibles.get(codepoint)} (${cp_hex(codepoint)})`, index, excerpt: safe_excerpt(text, index) });
      } else if (is_variation_selector) {
        findings.push({ method: 'unicode_specials', level: 'PROOF', score: 92, message: `Variation Selector (${cp_hex(codepoint)})`, index, excerpt: safe_excerpt(text, index) });
      } else if (is_tag) {
        findings.push({ method: 'unicode_specials', level: 'PROOF', score: 92, message: `Unicode Tag character (${cp_hex(codepoint)})`, index, excerpt: safe_excerpt(text, index) });
      } else if (is_control) {
        findings.push({ method: 'unicode_specials', level: 'PROOF', score: 95, message: `Control character (${cp_hex(codepoint)})`, index, excerpt: safe_excerpt(text, index) });
      }
      index += char.length;
    }

    try {
      const mark_regex = /\p{M}+/gu;
      let match;
      while ((match = mark_regex.exec(text)) !== null) {
        if (match[0].length >= 3) findings.push({ method: 'unicode_specials', level: 'HINT', score: 25, message: `Combining marks run length ${match[0].length}`, index: match.index, excerpt: safe_excerpt(text, match.index) });
      }
    } catch {}
    return findings;
  }

  function bidi_pairing_issues_client(text) {
    const issues = [];
    const open_embed = new Set([0x202A, 0x202B, 0x202D, 0x202E]);
    const open_isolate = new Set([0x2066, 0x2067, 0x2068]);
    const close_pdf = 0x202C;
    const close_pdi = 0x2069;
    const lines = text.split(/\r?\n/);
    for (let line_index = 0; line_index < lines.length; line_index++) {
      const stack = [];
      for (const char of lines[line_index]) {
        const codepoint = char.codePointAt(0);
        if (open_embed.has(codepoint)) stack.push(close_pdf);
        else if (open_isolate.has(codepoint)) stack.push(close_pdi);
        else if (codepoint === close_pdf || codepoint === close_pdi) {
          if (!stack.length) issues.push({ line: line_index + 1, issue: 'unmatched_close', cp: codepoint });
          else {
            const expected = stack.pop();
            if (expected !== codepoint) issues.push({ line: line_index + 1, issue: 'mismatched_close', cp: codepoint, expected });
          }
        }
      }
      while (stack.length) issues.push({ line: line_index + 1, issue: 'unclosed_open', expected: stack.pop() });
    }
    return issues;
  }

  function normalization_findings(text) {
    const out = [];
    try {
      if (text.normalize('NFC') !== text) out.push({ method: 'unicode_normalization', level: 'MEDIUM', score: 60, message: 'Text differs from NFC normalization (canonical drift).', index: 0, excerpt: '' });
      if (text.normalize('NFKC') !== text) out.push({ method: 'unicode_normalization', level: 'MEDIUM', score: 70, message: 'Text differs from NFKC normalization (compatibility drift).', index: 0, excerpt: '' });
    } catch {}
    return out;
  }

  function whitespace_findings(text) {
    const out = [];
    const lines = text.split(/\r?\n/);
    let trailing_count = 0;
    let trailing_tabs = 0;
    let mixed_indent_lines = 0;
    const examples = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (/[ \t]+$/.test(line)) {
        trailing_count++;
        if (/\t+$/.test(line)) trailing_tabs++;
        if (examples.length < 5) examples.push({ line: i + 1, kind: 'trailing_whitespace' });
      }
      const indent = line.match(/^\s+/)?.[0] || '';
      if (indent.includes('\t') && indent.includes(' ')) {
        mixed_indent_lines++;
        if (examples.length < 5) examples.push({ line: i + 1, kind: 'mixed_indent' });
      }
    }

    if (trailing_tabs > 0 || trailing_count >= 3) {
      out.push({ method: 'whitespace_channel', level: 'MEDIUM', score: 70, message: `Trailing whitespace in ${trailing_count} line(s)${trailing_tabs ? ` (includes ${trailing_tabs} trailing tab line(s))` : ''}.`, index: 0, excerpt: JSON.stringify(examples) });
    }
    if (mixed_indent_lines >= 2) {
      out.push({ method: 'whitespace_channel', level: 'MEDIUM', score: 70, message: `Mixed indentation (tabs+spaces) detected in ${mixed_indent_lines} line(s).`, index: 0, excerpt: '' });
    }
    return out;
  }

  function is_latin_only_with_diacritics(token) {
    try {
      return /^[\p{Script=Latin}\p{N}_$]+$/u.test(token);
    } catch {
      return /^[\w$À-ÿ]+$/.test(token);
    }
  }

  function contains_proof_unicode(token) {
    return /[\u200B\u200C\u200D\u2060\uFEFF\u034F\u202A-\u202E\u2066-\u2069\u200E\u200F]/u.test(token);
  }

  function scripts_in_token(token) {
    const scripts = new Set();
    try {
      if (/\p{Script=Latin}/u.test(token)) scripts.add('Latin');
      if (/\p{Script=Cyrillic}/u.test(token)) scripts.add('Cyrillic');
      if (/\p{Script=Greek}/u.test(token)) scripts.add('Greek');
      if (/\p{Script=Arabic}/u.test(token)) scripts.add('Arabic');
      if (/\p{Script=Hebrew}/u.test(token)) scripts.add('Hebrew');
      if (/\p{Script=Han}/u.test(token)) scripts.add('Han');
      if (/\p{Script=Hangul}/u.test(token)) scripts.add('Hangul');
      if (/\p{Script=Devanagari}/u.test(token)) scripts.add('Devanagari');
    } catch {}
    return scripts;
  }

  function code_identifier_findings(text, mode) {
    const out = [];
    if (mode !== 'code') return out;
    const blocks = [];
    const fenced = text.match(/```[\s\S]*?```/g);
    if (fenced && fenced.length) {
      for (const block of fenced) blocks.push(block.replace(/^```[^\n]*\n?/, '').replace(/```$/, ''));
    } else {
      blocks.push(text);
    }

    const identifier_regex = (() => {
      try {
        return /(?<![\p{L}\p{N}_$])([\p{L}_$][\p{L}\p{N}_$]{1,80})/gu;
      } catch {
        return /(^|[^A-Za-z0-9_$])([A-Za-z_$][A-Za-z0-9_$]{1,80})/g;
      }
    })();

    for (const block of blocks) {
      let match;
      while ((match = identifier_regex.exec(block)) !== null) {
        const token = match[1] || match[2];
        if (!token) continue;
        if (is_latin_only_with_diacritics(token) && !contains_proof_unicode(token)) continue;
        if (contains_proof_unicode(token)) {
          out.push({ method: 'unicode_homoglyph', level: 'PROOF', score: 92, message: `Identifier contains invisible/BiDi control: "${token}"`, index: match.index, excerpt: token });
          continue;
        }
        const scripts = scripts_in_token(token);
        if (scripts.size >= 2) out.push({ method: 'unicode_homoglyph', level: 'MEDIUM', score: 75, message: `Mixed scripts in identifier "${token}" (${Array.from(scripts).join(', ')})`, index: match.index, excerpt: token });
      }
    }
    return out;
  }

  async function strict_base64_findings(text, strict_base64) {
    const out = [];
    const candidates = base64_candidates(text);
    for (const candidate of candidates) {
      if (!strict_base64) {
        out.push({ method: 'payload_base64', level: 'HINT', score: 25, message: `Base64-like run (${candidate.kind}) length ${candidate.cand.length}`, index: candidate.index, excerpt: safe_excerpt(text, candidate.index) });
        continue;
      }
      const normalized = normalize_base64(candidate.cand, candidate.kind === 'base64url');
      if (!normalized) continue;
      let bytes;
      try {
        bytes = atob_bytes(normalized);
      } catch {
        continue;
      }

      const magic = magic_bytes_kind(bytes);
      const utf8 = utf8_preview(bytes);
      if (utf8.ok) {
        let is_json = false;
        try {
          JSON.parse(utf8.preview);
          is_json = true;
        } catch {}
        out.push({ method: 'payload_base64', level: 'STRONG', score: is_json ? 92 : 85, message: `Decoded ${candidate.kind}: UTF-8 printable (ratio ${utf8.ratio})${is_json ? ', JSON-like' : ''}`, index: candidate.index, excerpt: utf8.preview });
        continue;
      }

      if (magic === 'gzip' || magic === 'zlib') {
        const format = magic === 'gzip' ? 'gzip' : 'deflate';
        const decoded = await decompress_bytes(bytes, format);
        if (decoded) {
          const utf2 = utf8_preview(decoded);
          if (utf2.ok) {
            let is_json = false;
            try {
              JSON.parse(utf2.preview);
              is_json = true;
            } catch {}
            out.push({ method: 'payload_base64', level: 'STRONG', score: 94, message: `Decoded ${candidate.kind} → ${format}: UTF-8 printable (ratio ${utf2.ratio})${is_json ? ', JSON-like' : ''}`, index: candidate.index, excerpt: utf2.preview });
          } else {
            out.push({ method: 'payload_base64', level: 'MEDIUM', score: 70, message: `Decoded ${candidate.kind}: ${magic} bytes (not readable UTF-8)`, index: candidate.index, excerpt: `magic=${magic}, bytes[0..]=${bytes_to_hex(bytes, 24)}` });
          }
        } else {
          out.push({ method: 'payload_base64', level: 'MEDIUM', score: 70, message: `Decoded ${candidate.kind}: ${magic} bytes (browser cannot decompress)`, index: candidate.index, excerpt: `magic=${magic}, bytes[0..]=${bytes_to_hex(bytes, 24)}` });
        }
        continue;
      }

      if (magic) {
        out.push({ method: 'payload_base64', level: 'MEDIUM', score: 70, message: `Decoded ${candidate.kind}: magic bytes detected (${magic})`, index: candidate.index, excerpt: `magic=${magic}, bytes[0..]=${bytes_to_hex(bytes, 24)}` });
      }
    }
    return out;
  }

  function percent_payload_findings(text, strict) {
    const out = [];
    const hits = percent_runs(text, 12);
    for (const hit of hits) {
      const window_text = text.slice(hit.index, Math.min(text.length, hit.index + 400));
      let decoded = null;
      try {
        decoded = decodeURIComponent(window_text.replace(/%(?![0-9A-Fa-f]{2})/g, '%25'));
      } catch {}
      if (decoded && decoded.length >= 40 && is_printable_text(decoded)) {
        out.push({ method: 'payload_percent', level: 'STRONG', score: 85, message: `Percent-encoded run decoded to readable text (${hit.count} sequences)`, index: hit.index, excerpt: decoded.slice(0, 220) });
      } else if (!strict) {
        out.push({ method: 'payload_percent', level: 'HINT', score: 25, message: `Percent-encoded run (${hit.count} sequences)`, index: hit.index, excerpt: safe_excerpt(text, hit.index) });
      }
    }
    return out;
  }

  function hex_escape_findings(text) {
    const out = [];
    const hex_regex = /(?:0x)?[0-9A-Fa-f]{64,}/g;
    let match;
    while ((match = hex_regex.exec(text)) !== null) {
      if (!/[A-Fa-f]/.test(match[0])) continue;
      out.push({ method: 'payload_hex_escapes', level: 'MEDIUM', score: 65, message: `Long hex-like blob length ${match[0].length}`, index: match.index, excerpt: match[0].slice(0, 80) + (match[0].length > 80 ? '…' : '') });
    }

    const escape_regex = /(\\x[0-9A-Fa-f]{2}|\\u[0-9A-Fa-f]{4}|\\u\{[0-9A-Fa-f]{1,6}\})/g;
    const hits = [];
    while ((match = escape_regex.exec(text)) !== null) hits.push(match.index);
    if (hits.length >= 12) out.push({ method: 'payload_hex_escapes', level: 'MEDIUM', score: 65, message: `High density of escape sequences (${hits.length})`, index: hits[0], excerpt: safe_excerpt(text, hits[0]) });
    return out;
  }

  function entropy_findings(text) {
    const out = [];
    for (const hit of entropy_runs(text)) out.push({ method: 'payload_entropy', level: 'HINT', score: 35, message: `High-entropy run (H=${hit.entropy}, len=${hit.length})`, index: hit.index, excerpt: safe_excerpt(text, hit.index) });
    return out;
  }

  function acrostic_findings(text) {
    const out = [];
    const lines = text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);
    const first_letters = lines.map((line) => line[0]).join('').slice(0, 120);
    if (first_letters.length >= 18) out.push({ method: 'acrostics', level: 'HINT', score: 25, message: `Line acrostic sample: "${first_letters}"`, index: 0, excerpt: '' });

    const sentences = text.split(/[.!?]\s+/).map((sentence) => sentence.trim()).filter((sentence) => sentence.length >= 10);
    const sentence_letters = sentences.map((sentence) => sentence[0]).join('').slice(0, 120);
    if (sentence_letters.length >= 18) out.push({ method: 'acrostics', level: 'HINT', score: 25, message: `Sentence acrostic sample: "${sentence_letters}"`, index: 0, excerpt: '' });
    return out;
  }

  function repetition_findings(text) {
    const stats = compute_token_stats(text);
    const out = [];
    if (stats.repeated_trigrams >= 6) out.push({ method: 'repetition', level: 'HINT', score: 30, message: `Repeated trigrams detected: ${stats.repeated_trigrams} (template/copy-paste hint)`, index: 0, excerpt: JSON.stringify(stats) });
    return { out, stats };
  }

  async function sha256_hex(text) {
    const encoded = new TextEncoder().encode(text);
    const hash = await crypto.subtle.digest('SHA-256', encoded);
    const bytes = new Uint8Array(hash);
    return Array.from(bytes).map((byte) => byte.toString(16).padStart(2, '0')).join('');
  }

  async function call_json_endpoint(endpoint, payload, timeout_ms = 3500) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout_ms);
    try {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
        signal: controller.signal,
      });
      clearTimeout(timer);
      if (!response.ok) return { ok: false, error: `HTTP ${response.status}` };
      return await response.json();
    } catch (error) {
      clearTimeout(timer);
      return { ok: false, error: error && error.name === 'AbortError' ? 'timeout' : 'fetch_failed' };
    }
  }

  async function call_api(text, selected, settings) {
    const endpoint = $('apiEndpoint').value.trim() || './api/analyze.php';
    return call_json_endpoint(endpoint, { text, selected, settings }, 3500);
  }

  // GEAENDERT: Separate endpoint call for German style metrics.
  async function call_de_style_api(text, settings) {
    return call_json_endpoint(settings.deStyleEndpoint || './api/de_ai_style_analyze.php', {
      text,
      settings: {
        include_catalog: false,
      },
    }, 5000);
  }

  function dedupe_findings(report) {
    const seen = new Set();
    report.findings = report.findings.filter((finding) => {
      const key = `${finding.method}|${finding.level}|${finding.index ?? ''}|${finding.line ?? ''}|${finding.message}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }

  function merge_api_findings(report, api_data) {
    if (!api_data || !api_data.ok) return;
    report.meta.api = api_data.meta || {};
    report.meta.urls_from_api = api_data.urls || [];
    const add = (finding) => report.findings.push(finding);

    if (api_data.server && Array.isArray(api_data.server.unicode)) {
      for (const item of api_data.server.unicode) add({ method: item.kind === 'bidi' ? 'unicode_bidi' : 'unicode_specials', level: item.evidence || 'PROOF', score: item.score || 90, message: `${item.name || 'Unicode'} (${item.hex || ''})`, index: typeof item.char_index === 'number' ? item.char_index : null, excerpt: '', source: 'server' });
    }

    if (api_data.server && Array.isArray(api_data.server.bidi_pairing)) {
      for (const item of api_data.server.bidi_pairing) add({ method: 'unicode_bidi', level: 'PROOF', score: 90, message: `BiDi pairing issue: ${item.issue} (${item.hex || ''} ${item.name || ''})`, line: item.line || null, index: null, excerpt: '', source: 'server' });
    }

    if (api_data.server && api_data.server.spoofchecker && api_data.server.spoofchecker.available) {
      for (const item of (api_data.server.spoofchecker.items || [])) add({ method: 'unicode_homoglyph', level: item.evidence || 'MEDIUM', score: item.score || 70, message: `ICU Spoofchecker suspicious token: "${item.token}"`, index: null, excerpt: item.skeleton ? `skeleton: ${item.skeleton}` : '', source: 'server' });
    }

    if (api_data.server && Array.isArray(api_data.server.base64)) {
      for (const hit of api_data.server.base64) add({ method: 'payload_base64', level: hit.evidence || 'STRONG', score: hit.score || 85, message: `Server decode: ${hit.kind} (magic=${hit.magic ? 'yes' : 'no'}, utf8_ratio=${hit.utf8_ratio ?? 'n/a'})`, index: hit.index || null, excerpt: hit.preview || '', source: 'server' });
    }
  }

  // GEAENDERT: Merge German style API findings into the existing report model.
  function merge_de_style_findings(report, style_data) {
    if (!style_data || !style_data.ok || !style_data.style) return;
    report.meta.de_ai_style_api = style_data.meta || {};
    report.stats.de_ai_style = style_data.style.metrics || {};

    for (const finding of (style_data.style.findings || [])) {
      if (finding.id === 'de_style_insufficient_length') {
        report.meta.de_ai_style_note = finding.message;
        continue;
      }
      const value_excerpt = finding.matches && finding.matches.length
        ? JSON.stringify(finding.matches.slice(0, 5))
        : (finding.value ? JSON.stringify(finding.value) : '');
      report.findings.push({
        method: 'de_ai_style',
        level: 'HINT',
        score: finding.score || 15,
        message: finding.message || finding.id || 'German AI-style hint',
        index: null,
        excerpt: value_excerpt,
        source: 'server',
      });
    }
  }

  function finalize_report(report) {
    dedupe_findings(report);
    report.findings.sort((a, b) => {
      const a_key = evidence_sort_key(a.level);
      const b_key = evidence_sort_key(b.level);
      if (a_key !== b_key) return a_key - b_key;
      const a_index = typeof a.index === 'number' ? a.index : 1e12;
      const b_index = typeof b.index === 'number' ? b.index : 1e12;
      return a_index - b_index;
    });
    return report;
  }

  function render_report(report) {
    results_el.innerHTML = '';
    const groups = [
      { key: 'PROOF', title: 'PROOF (verifiable artifacts)', cls: 'proof' },
      { key: 'STRONG', title: 'STRONG (validated decode / clear signal)', cls: 'strong' },
      { key: 'MEDIUM', title: 'MEDIUM (conservative indicators)', cls: 'medium' },
      { key: 'HINT', title: 'HINT (heuristics, not proof)', cls: 'hint' },
    ];

    for (const group of groups) {
      const items = report.findings.filter((finding) => finding.level === group.key);
      const box = document.createElement('div');
      box.className = 'group';
      box.innerHTML = `
        <div class="ghead">
          <div class="left">
            <span class="pill ${group.cls}">${group.key}</span>
            <span class="title">${escape_html(group.title)}</span>
          </div>
          <div class="meta">${items.length} finding(s)</div>
        </div>
        <div class="items"></div>
      `;
      const items_el = box.querySelector('.items');
      if (!items.length) {
        const empty = document.createElement('div');
        empty.className = 'item';
        empty.innerHTML = '<div class="imeta">No findings at this evidence level.</div>';
        items_el.appendChild(empty);
      } else {
        for (const finding of items.slice(0, 120)) {
          const meta = method_meta(finding.method);
          const item = document.createElement('div');
          item.className = 'item';
          item.innerHTML = `
            <div class="itemtop">
              <div>
                <div class="ititle">${escape_html(meta.label)}</div>
                <div class="imeta">score ${escape_html(finding.score)} · method <code class="inline">${escape_html(finding.method)}</code> · ${finding.source ? escape_html(finding.source) : 'client'}</div>
              </div>
              <div class="imeta">${typeof finding.index === 'number' ? `idx ${finding.index}` : ''}${finding.line ? ` · line ${finding.line}` : ''}</div>
            </div>
            <div class="irow">${escape_html(finding.message || '')}</div>
            ${finding.excerpt ? `<div class="irow"><code class="inline">${escape_html(finding.excerpt)}</code></div>` : ''}
          `;
          items_el.appendChild(item);
        }
      }
      results_el.appendChild(box);
    }
  }

  async function run_analysis() {
    const t0 = performance.now();
    const text_raw = input_el.value;
    const text = text_raw.trimEnd();
    const selected = selected_methods();
    const settings = {
      maskUrls: $('maskUrls').checked,
      strictBase64: $('strictBase64').checked,
      analyzeUrlParams: $('analyzeUrlParams').checked,
      useApi: $('useApi').checked,
      apiEndpoint: $('apiEndpoint').value.trim() || './api/analyze.php',
      deStyleEndpoint: './api/de_ai_style_analyze.php',
      modeChoice: get_mode_choice(),
    };

    const mode = settings.modeChoice === 'auto' ? auto_detect_mode(text) : settings.modeChoice;
    const urls = extract_urls(text);
    const scan_text = settings.maskUrls ? mask_urls(text, urls) : text;
    const report = {
      meta: { timestamp: now_iso(), userAgent: navigator.userAgent, detectedMode: mode, urlCount: urls.length },
      settings,
      selected,
      stats: {},
      urls: [],
      findings: [],
    };

    if (selected.includes('urls_tracking') || selected.includes('payload_percent') || selected.includes('payload_base64')) {
      for (const url of urls) {
        const tracking = tracking_findings_for_url(url.url);
        if (settings.analyzeUrlParams && tracking.length && selected.includes('urls_tracking')) {
          for (const item of tracking) {
            report.findings.push({ method: 'urls_tracking', level: 'PROOF', score: 90, message: `Tracking-like URL parameter "${item.key}"`, index: url.index, excerpt: url.url.length > 220 ? url.url.slice(0, 220) + '…' : url.url, source: 'client' });
          }
        }
        report.urls.push({ ...url, tracking });
      }
    }

    if (selected.includes('unicode_specials') || selected.includes('unicode_bidi')) report.findings.push(...unicode_findings_client(text));
    if (selected.includes('unicode_bidi')) {
      const issues = bidi_pairing_issues_client(text);
      for (const issue of issues) {
        report.findings.push({
          method: 'unicode_bidi',
          level: 'PROOF',
          score: 90,
          message: issue.issue === 'unclosed_open'
            ? `BiDi pairing issue: unclosed open (expected ${cp_hex(issue.expected)})`
            : issue.issue === 'mismatched_close'
              ? `BiDi pairing issue: mismatched close (${cp_hex(issue.cp)} expected ${cp_hex(issue.expected)})`
              : `BiDi pairing issue: unmatched close (${cp_hex(issue.cp)})`,
          line: issue.line,
          index: null,
          excerpt: '',
          source: 'client',
        });
      }
    }

    if (selected.includes('unicode_normalization')) report.findings.push(...normalization_findings(text));
    if (selected.includes('whitespace_channel')) report.findings.push(...whitespace_findings(text));
    if (selected.includes('unicode_homoglyph')) report.findings.push(...code_identifier_findings(text, mode));
    if (selected.includes('payload_percent')) report.findings.push(...percent_payload_findings(scan_text, true));
    if (selected.includes('payload_hex_escapes')) report.findings.push(...hex_escape_findings(scan_text));
    if (selected.includes('payload_entropy')) report.findings.push(...entropy_findings(scan_text));
    if (selected.includes('payload_base64')) report.findings.push(...await strict_base64_findings(scan_text, settings.strictBase64));
    if (selected.includes('acrostics')) report.findings.push(...acrostic_findings(text));

    let repetition_stats = null;
    if (selected.includes('repetition')) {
      const repetition = repetition_findings(text);
      report.findings.push(...repetition.out);
      repetition_stats = repetition.stats;
    }

    const stats = compute_token_stats(text);
    report.stats = { chars: text.length, lines: text.split(/\r?\n/).length, ...stats, repetitionStats: repetition_stats || null };

    const api_notes = [];
    if (settings.useApi) {
      update_api_status('API: calling main…');
      const api_data = await call_api(text, selected, settings);
      if (api_data.ok) {
        merge_api_findings(report, api_data);
        api_notes.push(`main ok (intl=${api_data.meta?.intl_available ? 'yes' : 'no'}, spoof=${api_data.meta?.spoofchecker_available ? 'yes' : 'no'})`);
      } else {
        report.meta.api = { ok: false, error: api_data.error || 'error' };
        api_notes.push(`main unavailable (${api_data.error || 'error'})`);
      }
    }

    // GEAENDERT: Run German style analysis when the new method is selected.
    if (selected.includes('de_ai_style')) {
      update_api_status('API: calling German style…');
      const style_data = await call_de_style_api(text, settings);
      if (style_data.ok) {
        merge_de_style_findings(report, style_data);
        api_notes.push('German style ok');
      } else {
        report.meta.de_ai_style_api = { ok: false, error: style_data.error || 'error' };
        api_notes.push(`German style unavailable (${style_data.error || 'error'})`);
      }
    }

    if (api_notes.length) update_api_status(`API: ${api_notes.join('; ')}`);
    else update_api_status('API: off');

    finalize_report(report);

    $('sha').textContent = '…';
    const hash = await sha256_hex(text);
    report.meta.sha256 = hash;

    const t1 = performance.now();
    $('sha').textContent = hash;
    $('detMode').textContent = mode;
    $('tot').textContent = String(report.findings.length);
    $('rt').textContent = (t1 - t0).toFixed(1) + ' ms';
    render_report(report);

    latest_report = report;
    copy_btn.disabled = false;
    download_btn.disabled = false;
  }

  function set_input_stats() {
    const value = input_el.value;
    $('inputStats').textContent = `${value.length} chars`;
  }

  function download_json(report) {
    const json = JSON.stringify(report, null, 2);
    const blob = new Blob([json], { type: 'application/json;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = `artifact-report-${new Date().toISOString().replace(/[:.]/g, '-')}.json`;
    document.body.appendChild(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(url);
  }

  function copy_json(report) {
    return navigator.clipboard.writeText(JSON.stringify(report, null, 2));
  }

  function reset_ui() {
    results_el.innerHTML = '';
    $('sha').textContent = '—';
    $('detMode').textContent = '—';
    $('tot').textContent = '0';
    $('rt').textContent = '—';
    latest_report = null;
    copy_btn.disabled = true;
    download_btn.disabled = true;
    update_api_status(api_status_should_show() ? 'API: enabled (will call on Run if required)' : 'API: off');
  }

  render_checks();
  set_run_enabled();
  set_input_stats();
  reset_ui();

  input_el.addEventListener('input', () => {
    set_run_enabled();
    set_input_stats();
  });

  $('useApi').addEventListener('change', () => {
    update_api_status(api_status_should_show() ? 'API: enabled (will call on Run if required)' : 'API: off');
  });

  checks_el.addEventListener('change', () => {
    update_api_status(api_status_should_show() ? 'API: enabled (will call on Run if required)' : 'API: off');
  });

  run_btn.addEventListener('click', async () => {
    run_btn.disabled = true;
    try {
      await run_analysis();
    } finally {
      set_run_enabled();
    }
  });

  clear_btn.addEventListener('click', () => {
    input_el.value = '';
    set_input_stats();
    set_run_enabled();
    reset_ui();
  });

  copy_btn.addEventListener('click', async () => {
    if (!latest_report) return;
    try {
      await copy_json(latest_report);
      copy_btn.textContent = 'Copied!';
      setTimeout(() => { copy_btn.textContent = 'Copy JSON report'; }, 900);
    } catch {
      copy_btn.textContent = 'Copy failed';
      setTimeout(() => { copy_btn.textContent = 'Copy JSON report'; }, 900);
    }
  });

  download_btn.addEventListener('click', () => {
    if (!latest_report) return;
    download_json(latest_report);
  });
})();
