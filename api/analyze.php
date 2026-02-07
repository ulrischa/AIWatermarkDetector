<?php
declare(strict_types=1);

/**
 * analyze.php
 * Optional server-side analysis that improves Unicode and confusable detection using ICU (ext-intl).
 * Robustness goals:
 * - Always return JSON
 * - Avoid noisy scans and false positives (e.g., German umlauts)
 */

function json_response(array $data, int $status_code = 200): void
{
    header('Content-Type: application/json; charset=utf-8');
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Methods: POST, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type');
    http_response_code($status_code);
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

function to_hex_u(int $codepoint): string
{
    return 'U+' . strtoupper(str_pad(dechex($codepoint), 4, '0', STR_PAD_LEFT));
}

function utf8_chars(string $text): array
{
    $chars = preg_split('//u', $text, -1, PREG_SPLIT_NO_EMPTY);
    return is_array($chars) ? $chars : [];
}

function str_sub_u(string $s, int $start, int $len): string
{
    $chars = utf8_chars($s);
    if (empty($chars)) return '';
    return implode('', array_slice($chars, $start, $len));
}

function unicode_char_name(int $cp): string
{
    if (class_exists('IntlChar')) {
        $name = IntlChar::charName($cp);
        if (is_string($name) && $name !== '') return $name;
    }
    return 'UNKNOWN';
}

function unicode_category_label(int $cp): string
{
    if (!class_exists('IntlChar')) return 'unknown';
    $type = IntlChar::charType($cp);
    return 'type_' . (string)$type;
}

function is_bidi_control(int $cp): bool
{
    static $bidi = [
        0x202A => true, 0x202B => true, 0x202C => true, 0x202D => true, 0x202E => true,
        0x2066 => true, 0x2067 => true, 0x2068 => true, 0x2069 => true,
        0x200E => true, 0x200F => true,
    ];
    return isset($bidi[$cp]);
}

function bidi_name(int $cp): string
{
    static $bidi = [
        0x202A => 'LRE', 0x202B => 'RLE', 0x202C => 'PDF', 0x202D => 'LRO', 0x202E => 'RLO',
        0x2066 => 'LRI', 0x2067 => 'RLI', 0x2068 => 'FSI', 0x2069 => 'PDI',
        0x200E => 'LRM', 0x200F => 'RLM',
    ];
    return $bidi[$cp] ?? 'UNKNOWN';
}

function is_suspicious_unicode(int $cp): bool
{
    if ($cp === 0x00A0 || $cp === 0x202F || $cp === 0x2007 || $cp === 0x2060 || $cp === 0xFEFF || $cp === 0x200B) return true;
    if (is_bidi_control($cp)) return true;

    if (!class_exists('IntlChar')) return false;

    $type = IntlChar::charType($cp);
    // ICU: 15=CONTROL, 16=FORMAT
    return ($type === 15 || $type === 16);
}

function extract_urls(string $text): array
{
    $urls = [];
    if (preg_match_all('~https?://[^\s<>()"\']+~', $text, $m, PREG_OFFSET_CAPTURE)) {
        foreach ($m[0] as $hit) {
            $urls[] = ['url' => (string)$hit[0], 'index' => (int)$hit[1]];
        }
    }
    return $urls;
}

function mask_urls(string $text, array $urls): string
{
    if (empty($urls)) return $text;
    for ($i = count($urls) - 1; $i >= 0; $i--) {
        $url = (string)$urls[$i]['url'];
        $idx = (int)$urls[$i]['index'];
        $repl = str_repeat(' ', strlen($url));
        $text = substr($text, 0, $idx) . $repl . substr($text, $idx + strlen($url));
    }
    return $text;
}

function server_unicode_scan(string $text, int $max = 400): array
{
    if (!class_exists('IntlChar')) return [];
    $out = [];
    $chars = utf8_chars($text);
    $count = 0;

    foreach ($chars as $i => $ch) {
        $cp = IntlChar::ord($ch);
        if (is_suspicious_unicode($cp)) {
            $out[] = [
                'char_index' => $i,
                'codepoint' => $cp,
                'hex' => to_hex_u($cp),
                'name' => unicode_char_name($cp),
                'category' => unicode_category_label($cp),
            ];
            $count++;
            if ($count >= $max) break;
        }
    }
    return $out;
}

function server_bidi_pairing(string $text): array
{
    $lines = preg_split("/\r?\n/", $text);
    if (!is_array($lines)) $lines = [$text];

    $issues = [];
    $open_embed = [0x202A, 0x202B, 0x202D, 0x202E];
    $open_isol  = [0x2066, 0x2067, 0x2068];

    foreach ($lines as $ln => $line) {
        $chars = utf8_chars((string)$line);
        $stack = [];

        foreach ($chars as $ch) {
            $cp = class_exists('IntlChar') ? IntlChar::ord($ch) : ord($ch);

            if (in_array($cp, $open_embed, true)) {
                $stack[] = ['cp' => $cp, 'close' => 0x202C];
            } elseif (in_array($cp, $open_isol, true)) {
                $stack[] = ['cp' => $cp, 'close' => 0x2069];
            } elseif ($cp === 0x202C || $cp === 0x2069) {
                if (empty($stack)) {
                    $issues[] = ['line' => $ln + 1, 'issue' => 'unmatched_close', 'hex' => to_hex_u($cp), 'name' => bidi_name($cp)];
                } else {
                    $top = array_pop($stack);
                    if ((int)$top['close'] !== $cp) {
                        $issues[] = ['line' => $ln + 1, 'issue' => 'mismatched_close', 'hex' => to_hex_u($cp), 'name' => bidi_name($cp)];
                    }
                }
            }
        }

        while (!empty($stack)) {
            $top = array_pop($stack);
            $issues[] = ['line' => $ln + 1, 'issue' => 'unclosed_open', 'hex' => to_hex_u((int)$top['cp']), 'name' => bidi_name((int)$top['cp'])];
        }
    }

    return ['issues' => $issues];
}

function normalize_base64_candidate(string $s, bool $url_safe): ?string
{
    $t = $s;
    if ($url_safe) $t = str_replace(['-','_'], ['+','/'], $t);

    $mod = strlen($t) % 4;
    if ($mod === 2) $t .= '==';
    elseif ($mod === 3) $t .= '=';
    elseif ($mod === 1) return null;

    return $t;
}

function looks_like_magic_bytes(string $bytes): bool
{
    $len = strlen($bytes);
    if ($len < 2) return false;

    if (ord($bytes[0]) === 0x1F && ord($bytes[1]) === 0x8B) return true;

    if (ord($bytes[0]) === 0x78) {
        $b1 = ord($bytes[1]);
        if ($b1 === 0x01 || $b1 === 0x5E || $b1 === 0x9C || $b1 === 0xDA) return true;
    }

    if ($len >= 4 && $bytes[0] === 'P' && $bytes[1] === 'K' && ord($bytes[2]) === 0x03 && ord($bytes[3]) === 0x04) return true;
    if ($len >= 4 && $bytes[0] === '%' && $bytes[1] === 'P' && $bytes[2] === 'D' && $bytes[3] === 'F') return true;

    return false;
}

function bytes_is_valid_utf8(string $bytes): bool
{
    return preg_match('//u', $bytes) === 1;
}

function looks_like_utf8_text(string $bytes, float $min_printable_ratio = 0.90): array
{
    if (!bytes_is_valid_utf8($bytes) || $bytes === '') return ['ok' => false];

    $chars = utf8_chars($bytes);
    $len = count($chars);
    if ($len <= 0) return ['ok' => false];

    $printable = 0;
    foreach ($chars as $ch) {
        $cp = class_exists('IntlChar') ? IntlChar::ord($ch) : ord($ch);
        $is_print = ($ch === "\n" || $ch === "\r" || $ch === "\t" || ($cp >= 32 && $cp <= 126) || ($cp >= 160));
        if ($is_print) $printable++;
    }

    $ratio = $printable / $len;
    return ['ok' => ($ratio > $min_printable_ratio), 'ratio' => $ratio, 'preview' => str_sub_u($bytes, 0, 220)];
}

function server_strict_base64(string $text, bool $mask_urls, array $urls): array
{
    $payload_text = $mask_urls ? mask_urls($text, $urls) : $text;
    $out = [];
    $max = 120;

    if (preg_match_all('/(^|[^A-Za-z0-9+\/=])([A-Za-z0-9+\/]{32,}(?:={0,2}))(?![A-Za-z0-9+\/=])/', $payload_text, $m1, PREG_OFFSET_CAPTURE)) {
        foreach ($m1[2] as $hit) {
            if (count($out) >= $max) break;
            $cand = (string)$hit[0];
            $idx = (int)$hit[1];

            $norm = normalize_base64_candidate($cand, false);
            if ($norm === null) continue;

            $decoded = base64_decode($norm, true);
            if ($decoded === false) continue;

            $magic = looks_like_magic_bytes($decoded);
            $utf8 = looks_like_utf8_text($decoded);

            if ($magic || ($utf8['ok'] ?? false)) {
                $out[] = [
                    'index' => $idx,
                    'length' => strlen($cand),
                    'candidate' => $cand,
                    'kind' => 'base64',
                    'magic' => $magic ? 'yes' : 'no',
                    'utf8_ratio' => $utf8['ratio'] ?? null,
                ];
            }
        }
    }

    // IMPORTANT: keep '-' at end inside the char class to avoid invalid ranges
    if (preg_match_all('/(^|[^A-Za-z0-9_=-])([A-Za-z0-9_-]{43,}(?:={0,2}))(?![A-Za-z0-9_=-])/', $payload_text, $m2, PREG_OFFSET_CAPTURE)) {
        foreach ($m2[2] as $hit) {
            if (count($out) >= $max) break;
            $cand = (string)$hit[0];
            $idx = (int)$hit[1];

            $norm = normalize_base64_candidate($cand, true);
            if ($norm === null) continue;

            $decoded = base64_decode($norm, true);
            if ($decoded === false) continue;

            $magic = looks_like_magic_bytes($decoded);
            $utf8 = looks_like_utf8_text($decoded);

            if ($magic || ($utf8['ok'] ?? false)) {
                $out[] = [
                    'index' => $idx,
                    'length' => strlen($cand),
                    'candidate' => $cand,
                    'kind' => 'base64url',
                    'magic' => $magic ? 'yes' : 'no',
                    'utf8_ratio' => $utf8['ratio'] ?? null,
                ];
            }
        }
    }

    return $out;
}

function server_normalization(string $text): array
{
    if (!class_exists('Normalizer')) return ['available' => false, 'differs' => false];

    $nfkc = Normalizer::normalize($text, Normalizer::FORM_KC);
    if (!is_string($nfkc)) return ['available' => true, 'differs' => false];

    return [
        'available' => true,
        'differs' => ($nfkc !== $text),
        'nfkc_preview' => str_sub_u($nfkc, 0, 240),
    ];
}

function token_contains_non_latin_letters(string $token): bool
{
    // Do NOT treat German umlauts as suspicious; they are Script=Latin.
    return preg_match('/\p{Script=Cyrillic}|\p{Script=Greek}|\p{Script=Arabic}|\p{Script=Hebrew}|\p{Script=Han}|\p{Script=Hangul}|\p{Script=Devanagari}/u', $token) === 1;
}

function token_contains_bidi_or_invisible(string $token): bool
{
    $chars = utf8_chars($token);
    foreach ($chars as $ch) {
        if (!class_exists('IntlChar')) continue;
        $cp = IntlChar::ord($ch);
        if (is_bidi_control($cp)) return true;
        if (is_suspicious_unicode($cp)) return true;
    }
    return false;
}

function token_maybe_spoofworthy(string $token): bool
{
    if (strlen($token) < 3) return false;
    if (!preg_match('/[A-Za-z0-9_.:-]/', $token)) return false;

    // Only check tokens that can realistically be spoofed, not every umlaut word.
    if (token_contains_non_latin_letters($token)) return true;
    if (token_contains_bidi_or_invisible($token)) return true;

    return false;
}

function extract_tokens_for_spoofcheck(string $text): array
{
    if (!preg_match_all('/[A-Za-z0-9_.:-]{3,}/u', $text, $m)) return [];
    $tokens = array_unique($m[0]);
    return array_slice($tokens, 0, 2000);
}

function server_spoof_tokens(string $text): array
{
    if (!class_exists('Spoofchecker')) {
        return [
            'available' => false,
            'scanned_count' => 0,
            'suspicious_count' => 0,
            'suspicious' => [],
        ];
    }

    $sc = new Spoofchecker();

    $checks = 0;
    if (defined('Spoofchecker::MIXED_SCRIPT_CONFUSABLE')) $checks |= Spoofchecker::MIXED_SCRIPT_CONFUSABLE;
    if (defined('Spoofchecker::SINGLE_SCRIPT_CONFUSABLE')) $checks |= Spoofchecker::SINGLE_SCRIPT_CONFUSABLE;
    if (defined('Spoofchecker::INVISIBLE'))               $checks |= Spoofchecker::INVISIBLE;
    if ($checks !== 0) $sc->setChecks($checks);

    $tokens = extract_tokens_for_spoofcheck($text);

    $scanned = 0;
    $suspicious = [];

    foreach ($tokens as $tok) {
        $tok = (string)$tok;

        if (!token_maybe_spoofworthy($tok)) continue;

        $scanned++;
        $ret = 0;
        $is = $sc->isSuspicious($tok, $ret);

        if ($is) {
            $entry = [
                'token' => $tok,
                'reason' => 'icu_suspicious',
                'icu_flags' => $ret,
            ];

            if (method_exists($sc, 'getSkeleton') && defined('Spoofchecker::ANY_CASE')) {
                try {
                    $sk = $sc->getSkeleton(Spoofchecker::ANY_CASE, $tok);
                    if (is_string($sk) && $sk !== '') $entry['skeleton'] = $sk;
                } catch (Throwable $e) { /* ignore */ }
            }

            $suspicious[] = $entry;
            if (count($suspicious) >= 200) break;
        }

        if ($scanned >= 500) break;
    }

    return [
        'available' => true,
        'scanned_count' => $scanned,
        'suspicious_count' => count($suspicious),
        'suspicious' => $suspicious,
    ];
}

if (($_SERVER['REQUEST_METHOD'] ?? '') === 'OPTIONS') json_response(['ok' => true], 200);
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') json_response(['ok' => false, 'error' => 'Use POST JSON'], 405);

$body = read_json_body();
$text = isset($body['text']) && is_string($body['text']) ? $body['text'] : '';
$selected = isset($body['selected']) && is_array($body['selected']) ? $body['selected'] : [];
$settings = isset($body['settings']) && is_array($body['settings']) ? $body['settings'] : [];

$mask_urls = isset($settings['maskUrls']) ? (bool)$settings['maskUrls'] : true;

$selected_set = array_fill_keys(array_map('strval', $selected), true);

$intl_available = extension_loaded('intl');
$spoofchecker_available = class_exists('Spoofchecker');
$intlchar_available = class_exists('IntlChar');
$normalizer_available = class_exists('Normalizer');

$urls = extract_urls($text);
$server = [];

if (isset($selected_set['unicode_specials']) || isset($selected_set['unicode_bidi']) || isset($selected_set['unicode_homoglyph'])) {
    $server['unicode_scan'] = $intlchar_available ? server_unicode_scan($text, 400) : [];
}

if (isset($selected_set['unicode_bidi'])) {
    $server['bidi_pairing'] = server_bidi_pairing($text);
}

if (isset($selected_set['unicode_homoglyph'])) {
    $server['spoof_tokens'] = server_spoof_tokens($text);
}

if (isset($selected_set['unicode_norm'])) {
    $server['normalization'] = server_normalization($text);
}

if (isset($selected_set['payload_base64'])) {
    $server['base64'] = server_strict_base64($text, $mask_urls, $urls);
}

json_response([
    'ok' => true,
    'meta' => [
        'intl_available' => $intl_available,
        'spoofchecker_available' => $spoofchecker_available,
        'intlchar_available' => $intlchar_available,
        'normalizer_available' => $normalizer_available,
    ],
    'server' => $server,
], 200);
