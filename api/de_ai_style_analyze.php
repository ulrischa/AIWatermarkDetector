<?php
declare(strict_types=1);

// GEAENDERT: Added German AI-style heuristic analysis as hint-only evidence.

const DE_STYLE_MIN_WORDS = 120;
const DE_STYLE_MIN_SENTENCES = 6;
const DE_STYLE_MAX_INPUT_BYTES = 500000;

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
    if (!is_string($raw) || $raw === '') return [];
    if (strlen($raw) > DE_STYLE_MAX_INPUT_BYTES) {
        json_response(['ok' => false, 'error' => 'input_too_large', 'max_bytes' => DE_STYLE_MAX_INPUT_BYTES], 413);
    }
    $data = json_decode($raw, true);
    return is_array($data) ? $data : [];
}

function lower_text(string $text): string
{
    return function_exists('mb_strtolower') ? mb_strtolower($text, 'UTF-8') : strtolower($text);
}

function tokenize_words(string $text): array
{
    if (!preg_match_all("/[\p{L}\p{N}]+(?:[-’'][\p{L}\p{N}]+)?/u", lower_text($text), $matches)) return [];
    return array_values(array_filter($matches[0], static fn(string $word): bool => $word !== ''));
}

function split_sentences(string $text): array
{
    $normalized = trim(preg_replace('/\s+/u', ' ', $text) ?? $text);
    if ($normalized === '') return [];
    $parts = preg_split('/(?<=[.!?…])\s+(?=[\p{Lu}\p{N}"„»])/u', $normalized);
    if (!is_array($parts)) return [$normalized];
    return array_values(array_filter(array_map('trim', $parts), static fn(string $part): bool => $part !== ''));
}

function mean_value(array $values): float
{
    return $values ? array_sum($values) / count($values) : 0.0;
}

function population_stddev(array $values): float
{
    if (count($values) < 2) return 0.0;
    $mean = mean_value($values);
    $sum = 0.0;
    foreach ($values as $value) $sum += ($value - $mean) ** 2;
    return sqrt($sum / count($values));
}

function rounded(float $value, int $precision = 3): float
{
    return round($value, $precision);
}

function repeated_ngram_count(array $tokens, int $n): int
{
    $total = count($tokens);
    if ($total < ($n * 2)) return 0;
    $seen = [];
    for ($i = 0; $i <= $total - $n; $i++) {
        $gram = implode("\x01", array_slice($tokens, $i, $n));
        $seen[$gram] = ($seen[$gram] ?? 0) + 1;
    }
    $repeats = 0;
    foreach ($seen as $count) if ($count > 1) $repeats += $count - 1;
    return $repeats;
}

function yules_k(array $tokens): float
{
    $n = count($tokens);
    if ($n === 0) return 0.0;
    $freq = array_count_values($tokens);
    $sum = 0;
    foreach ($freq as $count) $sum += $count * $count;
    return (10000 * ($sum - $n)) / ($n * $n);
}

function hapax_ratio(array $tokens): float
{
    $n = count($tokens);
    if ($n === 0) return 0.0;
    $freq = array_count_values($tokens);
    $hapax = 0;
    foreach ($freq as $count) if ($count === 1) $hapax++;
    return $hapax / $n;
}

function count_regex_hits(string $text, array $patterns): array
{
    $items = [];
    $count = 0;
    foreach ($patterns as $id => $pattern) {
        $matches = [];
        $hit_count = preg_match_all($pattern, $text, $matches, PREG_OFFSET_CAPTURE);
        if ($hit_count === false || $hit_count === 0) continue;
        $count += $hit_count;
        foreach (array_slice($matches[0], 0, 8) as $match) {
            $items[] = ['pattern_id' => is_string($id) ? $id : 'pattern_' . (string)$id, 'text' => (string)$match[0], 'offset' => (int)$match[1]];
        }
    }
    return ['count' => $count, 'items' => array_slice($items, 0, 20)];
}

function de_ai_style_catalog(): array
{
    return [
        ['id' => 'de_low_burstiness', 'evidence' => 'HINT', 'metric' => 'sentence_word_count_stddev, sentence_word_count_cv'],
        ['id' => 'de_low_lexical_diversity', 'evidence' => 'HINT', 'metric' => 'type_token_ratio, yules_k, hapax_ratio'],
        ['id' => 'de_formulaic_transition_density', 'evidence' => 'HINT', 'metric' => 'formulaic_transition_count per 100 words'],
        ['id' => 'de_disclaimer_phrase_density', 'evidence' => 'HINT', 'metric' => 'disclaimer_phrase_count'],
        ['id' => 'de_parallel_or_triplet_style', 'evidence' => 'HINT', 'metric' => 'parallel_or_triplet_count'],
        ['id' => 'de_low_informality_in_informal_text', 'evidence' => 'HINT', 'metric' => 'informal_marker_count'],
        ['id' => 'de_punctuation_uniformity', 'evidence' => 'HINT', 'metric' => 'dash_count / sentence_count'],
        ['id' => 'de_repeated_ngram_uniformity', 'evidence' => 'HINT', 'metric' => 'repeated_trigrams, repeated_fourgrams'],
    ];
}

function de_ai_style_analyze(string $text): array
{
    $words = tokenize_words($text);
    $sentences = split_sentences($text);
    $sentence_lengths = [];
    foreach ($sentences as $sentence) $sentence_lengths[] = count(tokenize_words($sentence));
    $word_lengths = array_map(static fn(string $word): int => function_exists('mb_strlen') ? mb_strlen($word, 'UTF-8') : strlen($word), $words);

    $word_count = count($words);
    $sentence_count = count($sentences);
    $avg_sentence_words = mean_value($sentence_lengths);
    $sentence_stddev = population_stddev($sentence_lengths);
    $sentence_cv = $avg_sentence_words > 0 ? $sentence_stddev / $avg_sentence_words : 0.0;
    $unique_count = count(array_unique($words));
    $type_token_ratio = $word_count > 0 ? $unique_count / $word_count : 0.0;
    $lower = lower_text($text);

    $formulaic_patterns = [
        'additive' => '~\b(?:zudem|darüber hinaus|des weiteren|des Weiteren|ferner|außerdem)\b~iu',
        'conclusive' => '~\b(?:abschließend|zusammenfassend|insgesamt|letztlich|somit|folglich|daher|demnach)\b~iu',
        'framing' => '~\b(?:grundsätzlich|in diesem zusammenhang|vor diesem hintergrund|nicht zuletzt)\b~iu',
    ];
    $disclaimer_patterns = [
        'important_to_note' => '~\bes ist wichtig zu (?:beachten|betonen|erwähnen)\b~iu',
        'note_that' => '~\bdabei ist zu beachten\b~iu',
        'following' => '~\bim folgenden(?: wird| werden)?\b~iu',
        'depends' => '~\bdies hängt von.{1,80}ab\b~iu',
        'context' => '~\bje nach kontext\b~iu',
        'no_general_statement' => '~\bkeine (?:abschließende|pauschale) aussage\b~iu',
    ];
    $parallel_patterns = [
        'not_only_but_also' => '~\bnicht nur\b.{1,120}\bsondern auch\b~iu',
        'both_and' => '~\bsowohl\b.{1,120}\bals auch\b~iu',
        'on_one_hand' => '~\beinerseits\b.{1,120}\bandererseits\b~iu',
        'triplet' => '~\b[\p{L}äöüÄÖÜß]{4,},\s+[\p{L}äöüÄÖÜß]{4,}\s+und\s+[\p{L}äöüÄÖÜß]{4,}\b~iu',
    ];
    $informal_patterns = [
        'fillers' => '~\b(?:halt|eben|eigentlich|irgendwie|naja|also|quasi|eh|sozusagen|ziemlich)\b~iu',
        'colloquial' => '~\b(?:mega|krass|cool|geil|joa|okay|ok|klaro)\b~iu',
    ];

    $formulaic = count_regex_hits($lower, $formulaic_patterns);
    $disclaimers = count_regex_hits($lower, $disclaimer_patterns);
    $parallel = count_regex_hits($lower, $parallel_patterns);
    $informal = count_regex_hits($lower, $informal_patterns);
    $dash_count = preg_match_all('/[—–]/u', $text, $dash_matches);
    $dash_count = ($dash_count === false) ? 0 : $dash_count;

    $metrics = [
        'language_focus' => 'de',
        'word_count' => $word_count,
        'sentence_count' => $sentence_count,
        'avg_word_length' => rounded(mean_value($word_lengths)),
        'avg_sentence_words' => rounded($avg_sentence_words),
        'sentence_word_count_stddev' => rounded($sentence_stddev),
        'sentence_word_count_cv' => rounded($sentence_cv),
        'unique_word_count' => $unique_count,
        'type_token_ratio' => rounded($type_token_ratio),
        'yules_k' => rounded(yules_k($words)),
        'hapax_ratio' => rounded(hapax_ratio($words)),
        'repeated_trigrams' => repeated_ngram_count($words, 3),
        'repeated_fourgrams' => repeated_ngram_count($words, 4),
        'formulaic_transition_count' => $formulaic['count'],
        'formulaic_transition_per_100_words' => $word_count > 0 ? rounded(($formulaic['count'] / $word_count) * 100) : 0.0,
        'disclaimer_phrase_count' => $disclaimers['count'],
        'parallel_or_triplet_count' => $parallel['count'],
        'informal_marker_count' => $informal['count'],
        'dash_count' => $dash_count,
        'colon_count' => substr_count($text, ':'),
        'semicolon_count' => substr_count($text, ';'),
        'exclamation_count' => substr_count($text, '!'),
    ];

    $findings = [];
    $enough_text = ($word_count >= DE_STYLE_MIN_WORDS && $sentence_count >= DE_STYLE_MIN_SENTENCES);
    if (!$enough_text) {
        $findings[] = ['id' => 'de_style_insufficient_length', 'method' => 'de_ai_style', 'evidence' => 'HINT', 'score' => 0, 'message' => 'Not enough German prose for style heuristics. No authorship-style signal is evaluated.', 'value' => ['word_count' => $word_count, 'sentence_count' => $sentence_count], 'threshold' => ['min_words' => DE_STYLE_MIN_WORDS, 'min_sentences' => DE_STYLE_MIN_SENTENCES]];
    }
    if ($enough_text && $avg_sentence_words >= 10 && $avg_sentence_words <= 24 && $sentence_stddev <= 4.2 && $sentence_cv <= 0.38) {
        $findings[] = ['id' => 'de_low_burstiness', 'method' => 'de_ai_style', 'evidence' => 'HINT', 'score' => 25, 'message' => 'Sentence lengths are unusually uniform for longer German prose. This is only a weak style hint.', 'value' => ['stddev' => rounded($sentence_stddev), 'cv' => rounded($sentence_cv), 'avg_sentence_words' => rounded($avg_sentence_words)], 'threshold' => ['stddev_lte' => 4.2, 'cv_lte' => 0.38]];
    }
    if ($word_count >= 180 && $type_token_ratio < 0.52 && yules_k($words) > 115 && hapax_ratio($words) < 0.38) {
        $findings[] = ['id' => 'de_low_lexical_diversity', 'method' => 'de_ai_style', 'evidence' => 'HINT', 'score' => 25, 'message' => 'Lexical diversity is low and repetition-oriented. This can indicate templating or generated prose.', 'value' => ['ttr' => rounded($type_token_ratio), 'yules_k' => rounded(yules_k($words)), 'hapax_ratio' => rounded(hapax_ratio($words))]];
    }
    if ($enough_text && $formulaic['count'] >= 4 && (($formulaic['count'] / max(1, $word_count)) * 100) >= 1.6) {
        $findings[] = ['id' => 'de_formulaic_transition_density', 'method' => 'de_ai_style', 'evidence' => 'HINT', 'score' => 20, 'message' => 'Dense use of formal transitions and connective phrases.', 'value' => ['count' => $formulaic['count'], 'per_100_words' => rounded(($formulaic['count'] / max(1, $word_count)) * 100)], 'matches' => $formulaic['items']];
    }
    if ($disclaimers['count'] >= 2) {
        $findings[] = ['id' => 'de_disclaimer_phrase_density', 'method' => 'de_ai_style', 'evidence' => 'HINT', 'score' => 20, 'message' => 'Multiple assistant-like caveat or advisory phrases found.', 'value' => ['count' => $disclaimers['count']], 'matches' => $disclaimers['items']];
    }
    if ($parallel['count'] >= 3 || ($enough_text && (($parallel['count'] / max(1, $word_count)) * 100) >= 1.0)) {
        $findings[] = ['id' => 'de_parallel_or_triplet_style', 'method' => 'de_ai_style', 'evidence' => 'HINT', 'score' => 20, 'message' => 'Repeated parallel structures or triplet-style phrasing found.', 'value' => ['count' => $parallel['count']], 'matches' => $parallel['items']];
    }
    if ($metrics['repeated_trigrams'] >= 8 || $metrics['repeated_fourgrams'] >= 4) {
        $findings[] = ['id' => 'de_repeated_ngram_uniformity', 'method' => 'de_ai_style', 'evidence' => 'HINT', 'score' => 20, 'message' => 'Repeated word n-grams found. This may indicate templating, copy-paste, or repetitive generation.', 'value' => ['repeated_trigrams' => $metrics['repeated_trigrams'], 'repeated_fourgrams' => $metrics['repeated_fourgrams']]];
    }
    if ($sentence_count >= 6 && $dash_count >= 3 && ($dash_count / max(1, $sentence_count)) >= 0.35) {
        $findings[] = ['id' => 'de_punctuation_uniformity', 'method' => 'de_ai_style', 'evidence' => 'HINT', 'score' => 15, 'message' => 'High en/em dash density detected. This is a weak style hint and not evidence on its own.', 'value' => ['dash_count' => $dash_count, 'sentence_count' => $sentence_count]];
    }

    return ['metrics' => $metrics, 'findings' => $findings, 'matches' => ['formulaic_transitions' => $formulaic['items'], 'disclaimer_phrases' => $disclaimers['items'], 'parallel_or_triplet_phrases' => $parallel['items'], 'informal_markers' => $informal['items']]];
}

if (($_SERVER['REQUEST_METHOD'] ?? '') === 'OPTIONS') json_response(['ok' => true], 200);
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST') json_response(['ok' => false, 'error' => 'Use POST JSON'], 405);

$body = read_json_body();
$text = isset($body['text']) && is_string($body['text']) ? $body['text'] : '';
$settings = isset($body['settings']) && is_array($body['settings']) ? $body['settings'] : [];
$response = [
    'ok' => true,
    'meta' => ['version' => '2026-05-19', 'language_focus' => 'de', 'evidence_policy' => 'HINT_ONLY_NOT_AUTHORSHIP_PROOF', 'min_words' => DE_STYLE_MIN_WORDS, 'min_sentences' => DE_STYLE_MIN_SENTENCES, 'php' => PHP_VERSION],
    'style' => de_ai_style_analyze($text),
];
if ((bool)($settings['include_catalog'] ?? false)) $response['indicator_catalog'] = de_ai_style_catalog();
json_response($response, 200);
