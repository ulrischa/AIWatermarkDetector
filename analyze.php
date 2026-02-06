<?php
declare(strict_types=1);

/**
 * analyze.php
 * Optional server-side analysis for stronger Unicode/confusable checks using ICU (ext-intl) when available.
 *
 * Endpoints:
 *   POST JSON: { "text": "...", "selected": ["unicode_invisible", ...] }
 *
 * Returns JSON:
 *   { ok: true, meta: {...}, server: {...} }
 */

// ---------------------------
// Basic response helpers
// ---------------------------

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
    if (!is_string($raw)) {
        return [];
    }
    $data = json_decode($raw, true);
    return is_array($data) ? $data : [];
}

function to_hex_u(int $codepoint): string
{
    return 'U+' . strtoupper(str_pad(dechex($codepoint), 4, '0', STR_PAD_LEFT));
}

// ---------------------------
// Unicode utilities
// ---------------------------

function utf8_chars(string $text): array
{
    // Split into Unicode characters. This returns an array of strings (each one codepoint).
    // Note: for surrogate pairs, PCRE should handle properly in UTF-8 mode.
    $chars = preg_split('//u', $text, -1, PREG_SPLIT_NO_EMPTY);
    return is_array($chars) ? $chars : [];
}

function unicode_char_name(int $cp): string
{
    if (class_exists('IntlChar')) {
        $name = IntlChar::charName($cp);
        if (is_string($name) && $name !== '') {
            return $name;
        }
    }
    return 'UNKNOWN';
}

function unicode_category(int $cp): string
{
    if (!class_exists('IntlChar')) {
        return 'unknown';
    }
    $type = IntlChar::charType($cp);

    // Map the more relevant categories for stego/watermark scanning
    // Values are IntlChar constants (e.g. IntlChar::CHAR_CATEGORY_FORMAT)
    // We avoid depending on constant names that may not exist in older builds.
    // We'll return the numeric type too.
    return 'type_' . (string)$type;
}

function is_suspicious_unicode_category(int $cp): bool
{
    if (!class_exists('IntlChar')) {
        return false;
    }
    $type = IntlChar::charType($cp);

    // Format and Control characters are often used for stealth markers.
    // IntlChar::CHAR_CATEGORY_FORMAT == 16, CONTROL == 15 (typical ICU values)
    // We match by numeric range approach: treat format/control as suspicious.
    // Also include "line separator" and "paragraph separator" if needed, but keep focus.
    return ($type === 15 || $type === 16);
}

function is_bidi_control(int $cp): bool
{
    static $bidi = [
        0x202A => 'LRE', 0x202B => 'RLE', 0x202C => 'PDF', 0x202D => 'LRO', 0x202E => 'RLO',
        0x2066 => 'LRI', 0x2067 => 'RLI', 0x2068 => 'FSI', 0x2069 => 'PDI',
        0x200E => 'LRM', 0x200F => 'RLM',
    ];
    return array_key_exists($cp, $bidi);
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

// ---------------------------
// Server checks
// ---------------------------

function server_unicode_scan(string $text, int $max = 400): array
{
    $out = [];
    $chars = utf8_chars($text);
    $count = 0;

    foreach ($chars as $i => $ch) {
        $cp = IntlChar::ord($ch);

        // Control/Format categories and Bidi controls are the highest signal.
        $flag = false;
        $category = 'unknown';

        if (class_exists('IntlChar')) {
            $category = unicode_category($cp);
            if (is_suspicious_unicode_category($cp)) {
                $flag = true;
            }
        }

        if (is_bidi_control($cp)) {
            $flag = true;
        }

        // Also report special whitespace-like codepoints
        $is_nbsp = ($cp === 0x00A0 || $cp === 0x202F || $cp === 0x2007 || $cp === 0x2060 || $cp === 0xFEFF);
        if ($is_nbsp) {
            $flag = true;
        }

        if ($flag) {
            $out[] = [
                'char_index' => $i,
                'codepoint' => $cp,
                'hex' => to_hex_u($cp),
                'name' => unicode_char_name($cp),
                'category' => $category,
            ];
            $count++;
            if ($count >= $max) {
                break;
            }
        }
    }

    return $out;
}

function server_bidi_pairing(string $text): array
{
    $lines = preg_split("/\r?\n/", $text);
    if (!is_array($lines)) {
        $lines = [$text];
    }

    $issues = [];
    $open_embed = [0x202A, 0x202B, 0x202D, 0x202E]; // ... closed by PDF (202C)
    $open_isol  = [0x2066, 0x2067, 0x2068];         // ... closed by PDI (2069)

    foreach ($lines as $ln => $line) {
        $chars = utf8_chars($line);
        $stack = [];

        foreach ($chars as $ch) {
            $cp = class_exists('IntlChar') ? IntlChar::ord($ch) : ord($ch);

            if (in_array($cp, $open_embed, true)) {
                $stack[] = ['cp' => $cp, 'close' => 0x202C];
            } elseif (in_array($cp, $open_isol, true)) {
                $stack[] = ['cp' => $cp, 'close' => 0x2069];
            } elseif ($cp === 0x202C || $cp === 0x2069) {
                if (empty($stack)) {
                    $issues[] = [
                        'line' => $ln + 1,
                        'issue' => 'unmatched_close',
                        'hex' => to_hex_u($cp),
                        'name' => bidi_name($cp),
                    ];
                } else {
                    $top = array_pop($stack);
                    if ($top['close'] !== $cp) {
                        $issues[] = [
                            'line' => $ln + 1,
                            'issue' => 'mismatched_close',
                            'hex' => to_hex_u($cp),
                            'name' => bidi_name($cp),
                        ];
                    }
                }
            }
        }

        while (!empty($stack)) {
            $top = array_pop($stack);
            $issues[] = [
                'line' => $ln + 1,
                'issue' => 'unclosed_open',
                'hex' => to_hex_u((int)$top['cp']),
                'name' => bidi_name((int)$top['cp']),
            ];
        }
    }

    return ['issues' => $issues];
}

function server_spoofcheck(string $text): array
{
    if (!class_exists('Spoofchecker')) {
        return [
            'available' => false,
            'suspicious' => false,
            'checks' => '',
            'issues' => ['Spoofchecker not available (install/enable ext-intl)'],
        ];
    }

    $sc = new Spoofchecker();

    // Use a reasonable set of checks (ICU):
    // - mixed script
    // - confusable
    // - invisible
    // The exact flags depend on ICU; we keep output descriptive.
    // setChecks expects an integer bitmask; if constants exist, use them.
    $checks = 0;
    $issues = [];

    if (defined('Spoofchecker::SINGLE_SCRIPT_CONFUSABLE')) {
        $checks |= Spoofchecker::SINGLE_SCRIPT_CONFUSABLE;
    }
    if (defined('Spoofchecker::MIXED_SCRIPT_CONFUSABLE')) {
        $checks |= Spoofchecker::MIXED_SCRIPT_CONFUSABLE;
    }
    if (defined('Spoofchecker::WHOLE_SCRIPT_CONFUSABLE')) {
        $checks |= Spoofchecker::WHOLE_SCRIPT_CONFUSABLE;
    }
    if (defined('Spoofchecker::INVISIBLE')) {
        $checks |= Spoofchecker::INVISIBLE;
    }
    if (defined('Spoofchecker::CHAR_LIMIT')) {
        $checks |= Spoofchecker::CHAR_LIMIT;
    }

    if ($checks !== 0) {
        $sc->setChecks($checks);
    }

    $ret = 0;
    $suspicious = $sc->isSuspicious($text, $ret);
    // ICU returns a bitmask in $ret describing which checks triggered.
    // We will expose both numeric and best-effort labels.
    $issue_labels = [];

    // Best-effort decoding of $ret:
    $const_map = [
        'SINGLE_SCRIPT_CONFUSABLE' => defined('Spoofchecker::SINGLE_SCRIPT_CONFUSABLE') ? Spoofchecker::SINGLE_SCRIPT_CONFUSABLE : null,
        'MIXED_SCRIPT_CONFUSABLE'  => defined('Spoofchecker::MIXED_SCRIPT_CONFUSABLE') ? Spoofchecker::MIXED_SCRIPT_CONFUSABLE : null,
        'WHOLE_SCRIPT_CONFUSABLE'  => defined('Spoofchecker::WHOLE_SCRIPT_CONFUSABLE') ? Spoofchecker::WHOLE_SCRIPT_CONFUSABLE : null,
        'INVISIBLE'                => defined('Spoofchecker::INVISIBLE') ? Spoofchecker::INVISIBLE : null,
        'CHAR_LIMIT'               => defined('Spoofchecker::CHAR_LIMIT') ? Spoofchecker::CHAR_LIMIT : null,
    ];

    foreach ($const_map as $name => $val) {
        if (is_int($val) && ($ret & $val)) {
            $issue_labels[] = $name;
        }
    }

    if ($suspicious && empty($issue_labels)) {
        $issue_labels[] = 'suspicious (unknown ICU flags)';
    }

    return [
        'available' => true,
        'suspicious' => (bool)$suspicious,
        'checks' => (string)$checks,
        'issues' => $issue_labels,
        'icu_flags' => $ret,
    ];
}

function server_normalization(string $text): array
{
    if (!class_exists('Normalizer')) {
        return ['available' => false, 'differs' => false];
    }
    $nfkc = Normalizer::normalize($text, Normalizer::FORM_KC);
    if (!is_string($nfkc)) {
        return ['available' => true, 'differs' => false];
    }
    return [
        'available' => true,
        'differs' => ($nfkc !== $text),
        'nfkc_preview' => mb_substr($nfkc, 0, 240, 'UTF-8'),
    ];
}

function server_strict_base64(string $text): array
{
    // Find base64-ish candidates and verify with strict base64_decode.
    // Keep this conservative and bounded.
    $out = [];
    $max = 120;

    if (!preg_match_all('/(^|[^A-Za-z0-9+\/_-])([A-Za-z0-9+\/_-]{14,}(?:==|=)?)/', $text, $m, PREG_OFFSET_CAPTURE)) {
        return $out;
    }

    foreach ($m[2] as $hit) {
        if (count($out) >= $max) {
            break;
        }
        $cand = $hit[0];
        $idx = (int)$hit[1];

        // Normalize base64url
        $norm = str_replace(['-','_'], ['+','/'], $cand);
        $pad = strlen($norm) % 4;
        if ($pad === 2) $norm .= '==';
        elseif ($pad === 3) $norm .= '=';
        elseif ($pad === 1) continue;

        $decoded = base64_decode($norm, true);
        if ($decoded === false) {
            continue;
        }

        $out[] = [
            'index' => $idx,
            'length' => strlen($cand),
            'candidate' => $cand,
        ];
    }

    return $out;
}

// ---------------------------
// Main
// ---------------------------

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    json_response(['ok' => true], 200);
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    json_response(['ok' => false, 'error' => 'Use POST JSON'], 405);
}

$body = read_json_body();
$text = isset($body['text']) && is_string($body['text']) ? $body['text'] : '';
$selected = isset($body['selected']) && is_array($body['selected']) ? $body['selected'] : [];

$intl_available = extension_loaded('intl');
$spoofchecker_available = class_exists('Spoofchecker');
$intlchar_available = class_exists('IntlChar');
$normalizer_available = class_exists('Normalizer');

$server = [];

$selected_set = array_fill_keys(array_map('strval', $selected), true);

if (isset($selected_set['unicode_invisible']) || isset($selected_set['unicode_bidi']) || isset($selected_set['unicode_homoglyph'])) {
    if ($intlchar_available) {
        $server['unicode_scan'] = server_unicode_scan($text, 400);
    } else {
        $server['unicode_scan'] = [];
    }
}

if (isset($selected_set['unicode_bidi'])) {
    $server['bidi_pairing'] = server_bidi_pairing($text);
}

if (isset($selected_set['unicode_homoglyph'])) {
    $server['spoofcheck'] = server_spoofcheck($text);
}

if (isset($selected_set['unicode_norm'])) {
    $server['normalization'] = server_normalization($text);
}

if (isset($selected_set['payload_base64'])) {
    $server['base64'] = server_strict_base64($text);
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
