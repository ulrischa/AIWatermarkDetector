<?php
declare(strict_types=1);

/**
 * Optional server-side analyzer (PHP 8+, ext-intl).
 * Conservative: avoids false positives, returns only evidence-grade artifacts.
 */

function json_response(array $data, int $status = 200): void
{
    header('Content-Type: application/json; charset=utf-8');
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Methods: POST, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type');
    http_response_code($status);
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

function read_json_body(): array
{
    $raw = file_get_contents('php://input');
    if (!is_string($raw)) return [];
    $data = json_decode($raw, true);
    return is_array($data) ? $data : [];
}

function to_hex_u(int $cp): string
{
    return 'U+' . strtoupper(str_pad(dechex($cp), 4, '0', STR_PAD_LEFT));
}

function utf8_chars(string $s): array
{
    $a = preg_split('//u', $s, -1, PREG_SPLIT_NO_EMPTY);
    return is_array($a) ? $a : [];
}

function is_bidi_control(int $cp): bool
{
    static $set = [
        0x202A => true, 0x202B => true, 0x202C => true, 0x202D => true, 0x202E => true,
        0x2066 => true, 0x2067 => true, 0x2068 => true, 0x2069 => true,
        0x200E => true, 0x200F => true,
    ];
    return isset($set[$cp]);
}

function bidi_name(int $cp): string
{
    static $names = [
        0x202A => 'LRE', 0x202B => 'RLE', 0x202C => 'PDF', 0x202D => 'LRO', 0x202E => 'RLO',
        0x2066 => 'LRI', 0x2067 => 'RLI', 0x2068 => 'FSI', 0x2069 => 'PDI',
        0x200E => 'LRM', 0x200F => 'RLM',
    ];
    return $names[$cp] ?? 'UNKNOWN';
}

function is_variation_selector(int $cp): bool
{
    if ($cp >= 0xFE00 && $cp <= 0xFE0F) return true;
    if ($cp >= 0xE0100 && $cp <= 0xE01EF) return true;
    return false;
}

function is_tag_char(int $cp): bool
{
    return ($cp >= 0xE0000 && $cp <= 0xE007F);
}

function is_common_invisible_space(int $cp): bool
{
    static $set = [
        0x200B => true, 0x200C => true, 0x200D => true, 0x2060 => true, 0xFEFF => true,
        0x00A0 => true, 0x202F => true, 0x2007 => true, 0x2009 => true, 0x200A => true, 0x3000 => true,
        0x034F => true, // Combining Grapheme Joiner
    ];
    return isset($set[$cp]);
}

function unicode_findings(string $text, int $max = 500): array
{
    $out = [];
    if (!class_exists('IntlChar')) return $out;

    $chars = utf8_chars($text);
    foreach ($chars as $i => $ch) {
        $cp = IntlChar::ord($ch);

        $type = IntlChar::charType($cp);
        $is_control_or_format = ($type === IntlChar::CHAR_CATEGORY_CONTROL_CHAR || $type === IntlChar::CHAR_CATEGORY_FORMAT_CHAR);

        $hit = false;
        $kind = '';
        if (is_bidi_control($cp)) { $hit = true; $kind = 'bidi'; }
        else if (is_common_invisible_space($cp)) { $hit = true; $kind = 'invisible_space'; }
        else if (is_variation_selector($cp)) { $hit = true; $kind = 'variation_selector'; }
        else if (is_tag_char($cp)) { $hit = true; $kind = 'tag_char'; }
        else if ($is_control_or_format) { $hit = true; $kind = 'control_or_format'; }

        if ($hit) {
            $out[] = [
                'char_index' => $i,
                'codepoint' => $cp,
                'hex' => to_hex_u($cp),
                'name' => (string)IntlChar::charName($cp),
                'kind' => $kind,
                'evidence' => 'PROOF',
                'score' => 95,
            ];
            if (count($out) >= $max) break;
        }
    }
    return $out;
}

function bidi_pairing_issues(string $text): array
{
    $issues = [];
    $lines = preg_split("/\r?\n/", $text);
    if (!is_array($lines)) $lines = [$text];

    $open_embed = [0x202A, 0x202B, 0x202D, 0x202E];
    $open_isol  = [0x2066, 0x2067, 0x2068];

    foreach ($lines as $ln => $line) {
        $stack = [];
        foreach (utf8_chars((string)$line) as $ch) {
            $cp = class_exists('IntlChar') ? IntlChar::ord($ch) : ord($ch);

            if (in_array($cp, $open_embed, true)) $stack[] = 0x202C;
            else if (in_array($cp, $open_isol, true)) $stack[] = 0x2069;
            else if ($cp === 0x202C || $cp === 0x2069) {
                if (empty($stack)) {
                    $issues[] = ['line' => $ln + 1, 'issue' => 'unmatched_close', 'hex' => to_hex_u($cp), 'name' => bidi_name($cp)];
                } else {
                    $expected = array_pop($stack);
                    if ($expected !== $cp) {
                        $issues[] = ['line' => $ln + 1, 'issue' => 'mismatched_close', 'hex' => to_hex_u($cp), 'name' => bidi_name($cp)];
                    }
                }
            }
        }
        while (!empty($stack)) {
            $expected = array_pop($stack);
            $issues[] = ['line' => $ln + 1, 'issue' => 'unclosed_open', 'hex' => to_hex_u($expected), 'name' => bidi_name($expected)];
        }
    }

    return $issues;
}

function extract_urls(string $text): array
{
    $urls = [];
    if (preg_match_all('~https?://[^\s<>()"\']+~', $text, $m, PREG_OFFSET_CAPTURE)) {
        foreach ($m[0] as $hit) $urls[] = ['url' => (string)$hit[0], 'index' => (int)$hit[1]];
    }
    return $urls;
}

function looks_like_magic_bytes(string $bytes): bool
{
    $len = strlen($bytes);
    if ($len < 4) return false;

    if (ord($bytes[0]) === 0x1F && ord($bytes[1]) === 0x8B) return true; // gzip
    if (ord($bytes[0]) === 0x78) { // zlib
        $b1 = ord($bytes[1]);
        if ($b1 === 0x01 || $b1 === 0x5E || $b1 === 0x9C || $b1 === 0xDA) return true;
    }
    if ($bytes[0] === 'P' && $bytes[1] === 'K' && ord($bytes[2]) === 0x03 && ord($bytes[3]) === 0x04) return true; // zip
    if ($bytes[0] === '%' && $bytes[1] === 'P' && $bytes[2] === 'D' && $bytes[3] === 'F') return true; // pdf
    return false;
}

function utf8_printable_ratio(string $bytes): array
{
    if (preg_match('//u', $bytes) !== 1) return ['ok' => false];

    $chars = utf8_chars($bytes);
    if (!$chars) return ['ok' => false];

    $printable = 0;
    foreach ($chars as $ch) {
        $cp = class_exists('IntlChar') ? IntlChar::ord($ch) : ord($ch);
        $is_print = ($ch === "\n" || $ch === "\r" || $ch === "\t" || ($cp >= 32 && $cp <= 126) || ($cp >= 160));
        if ($is_print) $printable++;
    }
    $ratio = $printable / max(1, count($chars));
    return ['ok' => $ratio >= 0.90, 'ratio' => $ratio, 'preview' => implode('', array_slice($chars, 0, 220))];
}

function normalize_b64(string $s, bool $url_safe): ?string
{
    $t = $url_safe ? str_replace(['-','_'], ['+','/'], $s) : $s;
    $mod = strlen($t) % 4;
    if ($mod === 1) return null;
    if ($mod === 2) $t .= '==';
    if ($mod === 3) $t .= '=';
    return $t;
}

function try_decompress(string $bytes): array
{
    $out = [];

    if (function_exists('gzdecode')) {
        $g = @gzdecode($bytes);
        if (is_string($g) && $g !== '') $out[] = ['kind' => 'gzip', 'bytes' => $g];
    }

    if (function_exists('gzinflate')) {
        $d1 = @gzinflate($bytes);
        if (is_string($d1) && $d1 !== '') $out[] = ['kind' => 'deflate', 'bytes' => $d1];

        if (strlen($bytes) > 2) {
            $d2 = @gzinflate(substr($bytes, 2));
            if (is_string($d2) && $d2 !== '') $out[] = ['kind' => 'deflate_skip2', 'bytes' => $d2];
        }
    }

    return $out;
}

function strict_base64_hits(string $text, int $max = 120): array
{
    $hits = [];

    if (preg_match_all('/(^|[^A-Za-z0-9+\/=])([A-Za-z0-9+\/]{32,}(?:={0,2}))(?![A-Za-z0-9+\/=])/', $text, $m1, PREG_OFFSET_CAPTURE)) {
        foreach ($m1[2] as $hit) {
            if (count($hits) >= $max) break;
            $cand = (string)$hit[0];
            $idx = (int)$hit[1];

            $norm = normalize_b64($cand, false);
            if ($norm === null) continue;

            $dec = base64_decode($norm, true);
            if ($dec === false) continue;

            $magic = looks_like_magic_bytes($dec);
            $u = utf8_printable_ratio($dec);

            $best = null;

            if ($magic || ($u['ok'] ?? false)) {
                $best = [
                    'index' => $idx,
                    'kind' => 'base64',
                    'candidate' => $cand,
                    'evidence' => 'STRONG',
                    'score' => $magic ? 92 : 85,
                    'magic' => $magic,
                    'utf8_ratio' => $u['ratio'] ?? null,
                    'preview' => $u['preview'] ?? null,
                ];
            } else {
                foreach (try_decompress($dec) as $alt) {
                    $u2 = utf8_printable_ratio((string)$alt['bytes']);
                    if ($u2['ok'] ?? false) {
                        $best = [
                            'index' => $idx,
                            'kind' => 'base64->' . $alt['kind'],
                            'candidate' => $cand,
                            'evidence' => 'STRONG',
                            'score' => 94,
                            'magic' => true,
                            'utf8_ratio' => $u2['ratio'] ?? null,
                            'preview' => $u2['preview'] ?? null,
                        ];
                        break;
                    }
                }
            }

            if ($best) $hits[] = $best;
        }
    }

    if (preg_match_all('/(^|[^A-Za-z0-9_=-])([A-Za-z0-9_-]{43,}(?:={0,2}))(?![A-Za-z0-9_=-])/', $text, $m2, PREG_OFFSET_CAPTURE)) {
        foreach ($m2[2] as $hit) {
            if (count($hits) >= $max) break;
            $cand = (string)$hit[0];
            $idx = (int)$hit[1];

            $norm = normalize_b64($cand, true);
            if ($norm === null) continue;

            $dec = base64_decode($norm, true);
            if ($dec === false) continue;

            $magic = looks_like_magic_bytes($dec);
            $u = utf8_printable_ratio($dec);

            $best = null;

            if ($magic || ($u['ok'] ?? false)) {
                $best = [
                    'index' => $idx,
                    'kind' => 'base64url',
                    'candidate' => $cand,
                    'evidence' => 'STRONG',
                    'score' => $magic ? 92 : 85,
                    'magic' => $magic,
                    'utf8_ratio' => $u['ratio'] ?? null,
                    'preview' => $u['preview'] ?? null,
                ];
            } else {
                foreach (try_decompress($dec) as $alt) {
                    $u2 = utf8_printable_ratio((string)$alt['bytes']);
                    if ($u2['ok'] ?? false) {
                        $best = [
                            'index' => $idx,
                            'kind' => 'base64url->' . $alt['kind'],
                            'candidate' => $cand,
                            'evidence' => 'STRONG',
                            'score' => 94,
                            'magic' => true,
                            'utf8_ratio' => $u2['ratio'] ?? null,
                            'preview' => $u2['preview'] ?? null,
                        ];
                        break;
                    }
                }
            }

            if ($best) $hits[] = $best;
        }
    }

    return $hits;
}

function spoofcheck_tokens(string $text): array
{
    if (!class_exists('Spoofchecker')) {
        return ['available' => false, 'scanned' => 0, 'suspicious' => 0, 'items' => []];
    }

    $sc = new Spoofchecker();
    $checks = 0;
    if (defined('Spoofchecker::MIXED_SCRIPT_CONFUSABLE')) $checks |= Spoofchecker::MIXED_SCRIPT_CONFUSABLE;
    if (defined('Spoofchecker::SINGLE_SCRIPT_CONFUSABLE')) $checks |= Spoofchecker::SINGLE_SCRIPT_CONFUSABLE;
    if (defined('Spoofchecker::INVISIBLE')) $checks |= Spoofchecker::INVISIBLE;
    if ($checks) $sc->setChecks($checks);

    $tokens = [];
    if (preg_match_all('/[^\s]{3,}/u', $text, $m)) {
        $tokens = array_unique($m[0]);
        $tokens = array_slice($tokens, 0, 2000);
    }

    $items = [];
    $scanned = 0;

    foreach ($tokens as $t) {
        $t = (string)$t;

        // Conservative selection: non-Latin scripts OR contains suspicious invisibles/bidi.
        $nonLatin = (preg_match('/\p{Script=Cyrillic}|\p{Script=Greek}|\p{Script=Arabic}|\p{Script=Hebrew}|\p{Script=Han}|\p{Script=Hangul}|\p{Script=Devanagari}/u', $t) === 1);
        $hasSpecial = (preg_match('/[\x{200B}\x{200C}\x{200D}\x{2060}\x{FEFF}\x{034F}\x{202A}-\x{202E}\x{2066}-\x{2069}\x{200E}\x{200F}]/u', $t) === 1);

        if (!$nonLatin && !$hasSpecial) continue;

        $scanned++;
        $flags = 0;
        $is = $sc->isSuspicious($t, $flags);
        if ($is) {
            $entry = ['token' => $t, 'icu_flags' => $flags, 'evidence' => 'MEDIUM', 'score' => 70];
            if (method_exists($sc, 'getSkeleton') && defined('Spoofchecker::ANY_CASE')) {
                try {
                    $sk = $sc->getSkeleton(Spoofchecker::ANY_CASE, $t);
                    if (is_string($sk) && $sk !== '') $entry['skeleton'] = $sk;
                } catch (Throwable $e) {}
            }
            $items[] = $entry;
            if (count($items) >= 200) break;
        }

        if ($scanned >= 500) break;
    }

    return ['available' => true, 'scanned' => $scanned, 'suspicious' => count($items), 'items' => $items];
}

if (($_SERVER['REQUEST_METHOD'] ?? '') === 'OPTIONS') json_response(['ok' => true], 200);
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') json_response(['ok' => false, 'error' => 'Use POST JSON'], 405);

$body = read_json_body();
$text = isset($body['text']) && is_string($body['text']) ? $body['text'] : '';
$selected = isset($body['selected']) && is_array($body['selected']) ? array_map('strval', $body['selected']) : [];
$settings = isset($body['settings']) && is_array($body['settings']) ? $body['settings'] : [];

$sel = array_fill_keys($selected, true);

$server = [];
$urls = extract_urls($text);

if (isset($sel['unicode_specials']) || isset($sel['unicode_bidi'])) {
    $server['unicode'] = unicode_findings($text);
}
if (isset($sel['unicode_bidi'])) {
    $server['bidi_pairing'] = bidi_pairing_issues($text);
}
if (isset($sel['unicode_homoglyph'])) {
    $server['spoofchecker'] = spoofcheck_tokens($text);
}
if (isset($sel['payload_base64'])) {
    $server['base64'] = strict_base64_hits($text);
}

json_response([
    'ok' => true,
    'meta' => [
        'php' => PHP_VERSION,
        'intl_available' => extension_loaded('intl'),
        'intlchar_available' => class_exists('IntlChar'),
        'spoofchecker_available' => class_exists('Spoofchecker'),
    ],
    'urls' => $urls,
    'server' => $server,
], 200);
