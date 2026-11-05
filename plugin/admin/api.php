<?php
declare(strict_types=1);

/**
 * DirectAdmin Admin-Level JSON IPC Relay (invoked via admin/api.raw with `php -n`).
 * Relays requests over /var/run/da-wptoolkit.sock with Same-Origin, SO_PEERCRED,
 * DirectAdmin admin session verification, and root-secret HMAC-SHA256 CSRF protection.
 */

function emit_admin_json(array $body, int $status = 200): void
{
    $reason = match ($status) {
        200 => 'OK',
        400 => 'Bad Request',
        403 => 'Forbidden',
        405 => 'Method Not Allowed',
        default => 'Internal Server Error',
    };
    echo "HTTP/1.1 {$status} {$reason}\r\n";
    echo "Content-Type: application/json; charset=utf-8\r\n";
    echo "Cache-Control: no-store, no-cache, must-revalidate\r\n";
    echo "X-Content-Type-Options: nosniff\r\n\r\n";
    echo json_encode($body, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n";
    exit(0);
}

function parse_admin_form(string $raw): array
{
    $normalized = $raw;
    if (strpos($raw, '&amp;') !== false && preg_match('/&(?!amp;)/', $raw) === 0) {
        $normalized = str_replace('&amp;', '&', $raw);
    }
    $out = [];
    parse_str($normalized, $out);
    return is_array($out) ? $out : [];
}

function decode_admin_json(string $raw): ?array
{
    $trimmed = trim($raw);
    if ($trimmed === '') {
        return null;
    }
    if ($trimmed[0] === '{' || $trimmed[0] === '[') {
        $direct = json_decode($trimmed, true);
        if (is_array($direct)) {
            return $direct;
        }
    }
    if (strpos($trimmed, '&quot;') !== false || strpos($trimmed, '&#') !== false) {
        $unescaped = trim(html_entity_decode($trimmed, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8'));
        if ($unescaped !== '' && ($unescaped[0] === '{' || $unescaped[0] === '[')) {
            $fallback = json_decode($unescaped, true);
            if (is_array($fallback)) {
                return $fallback;
            }
        }
    }
    return null;
}

function extract_admin_session_id(): string
{
    $sid = trim((string) (getenv('SESSION_ID') ?: ''));
    if ($sid !== '') {
        return $sid;
    }
    $cookieHeader = (string) (getenv('HTTP_COOKIE') ?: '');
    if ($cookieHeader !== '') {
        foreach (explode(';', $cookieHeader) as $part) {
            $kv = explode('=', trim($part), 2);
            if (count($kv) === 2 && ($kv[0] === 'session' || $kv[0] === 'SESSION_ID' || $kv[0] === 'da_sess')) {
                return trim(urldecode($kv[1]));
            }
        }
    }
    return '';
}

function verify_admin_same_origin(): ?string
{
    $secFetch = strtolower(trim((string) (getenv('HTTP_SEC_FETCH_SITE') ?: '')));
    if ($secFetch !== '' && $secFetch !== 'same-origin' && $secFetch !== 'none') {
        return 'Forbidden: cross-site request blocked (Sec-Fetch-Site)';
    }
    $rawHost = strtolower(trim((string) (getenv('HTTP_HOST') ?: '')));
    if ($rawHost === '') {
        return null;
    }
    $allowed = [$rawHost];
    if (substr($rawHost, -4) === ':443') {
        $allowed[] = substr($rawHost, 0, -4);
    } elseif (substr($rawHost, -3) === ':80') {
        $allowed[] = substr($rawHost, 0, -3);
    }

    $origin = trim((string) (getenv('HTTP_ORIGIN') ?: ''));
    if ($origin !== '') {
        if (strtolower($origin) === 'null') {
            return 'Forbidden: null Origin header rejected';
        }
        $parts = @parse_url($origin);
        $host = is_array($parts) && !empty($parts['host']) ? strtolower((string) $parts['host']) : '';
        $port = is_array($parts) && isset($parts['port']) ? (int) $parts['port'] : 0;
        $auth = ($port > 0 && $port !== 80 && $port !== 443) ? ($host . ':' . $port) : $host;
        if ($auth === '' || !in_array($auth, $allowed, true)) {
            return 'Forbidden: Origin header does not match DirectAdmin host';
        }
    }
    return null;
}

$isPost = false;
$reqMeth = strtoupper((string) (getenv('REQUEST_METHOD') ?: 'GET'));
$input = [];

$postEnv = getenv('POST');
if (is_string($postEnv) && $postEnv !== '') {
    $isPost = true;
    $decoded = decode_admin_json($postEnv);
    $input = is_array($decoded) ? $decoded : parse_admin_form($postEnv);
} elseif (defined('STDIN') && is_resource(STDIN)) {
    $cLen = (int) (getenv('CONTENT_LENGTH') ?: 0);
    $waitUsec = ($reqMeth === 'POST' || $cLen > 0) ? 200000 : 0;
    $r = [STDIN];
    $w = null;
    $e = null;
    if (@stream_select($r, $w, $e, 0, $waitUsec) > 0) {
        @stream_set_blocking(STDIN, false);
        $maxBytes = ($cLen > 0 && $cLen <= 65536) ? $cLen : 65536;
        $rawStdin = @stream_get_contents(STDIN, $maxBytes);
        if (is_string($rawStdin) && trim($rawStdin) !== '') {
            $isPost = true;
            $decoded = decode_admin_json($rawStdin);
            $input = is_array($decoded) ? $decoded : parse_admin_form($rawStdin);
        }
    }
}

if (!$isPost && $reqMeth !== 'POST') {
    $qs = (string) (getenv('QUERY_STRING') ?: '');
    $input = $qs !== '' ? parse_admin_form($qs) : [];
} else {
    $isPost = true;
}

$action = strtolower(trim((string) ($input['action'] ?? 'get_overview')));
$readOnlyActions = ['ping', 'get_overview', 'list_instances', 'list_plugins', 'list_themes', 'check_core_updates', 'get_vulns', 'get_vulndb_status', 'get_security_status', 'get_tools_status', 'read_debug_log', 'get_safe_wpconfig', 'list_snapshots', 'get_snapshot_download', 'list_quarantine', 'get_quarantine_diff', 'list_whitelist', 'get_core_cache_status', 'list_sets', 'list_jobs', 'get_job', 'get_security_events', 'list_packages', 'get_updater_config', 'check_github_update', 'list_update_backups'];

if (!in_array($action, $readOnlyActions, true) && !$isPost) {
    emit_admin_json(['ok' => false, 'code' => 405, 'error' => 'Mutating admin actions require HTTP POST'], 405);
}

if ($isPost) {
    $err = verify_admin_same_origin();
    if ($err !== null) {
        emit_admin_json(['ok' => false, 'code' => 403, 'error' => $err], 403);
    }
}

$csrfToken = trim((string) ($input['csrf_token'] ?? ''));
if ($csrfToken === '') {
    $csrfToken = trim((string) (getenv('HTTP_X_DAWPTK_CSRF') ?: ''));
}

$rawParams = isset($input['params']) && is_array($input['params']) ? $input['params'] : [];
$ipcReq = [
    'action'      => $action,
    'username'    => trim((string) ($input['username'] ?? '')),
    'session_id'  => extract_admin_session_id(),
    'csrf_token'  => $csrfToken,
    'instance_id' => trim((string) ($input['instance_id'] ?? '')),
    'job_id'      => trim((string) ($input['job_id'] ?? '')),
    'limit'       => isset($input['limit']) ? (int) $input['limit'] : 0,
    'params'      => (object) $rawParams,
];

$sockPath = getenv('DA_WPTK_ADMIN_SOCK') ?: '/var/run/da-wptoolkit.sock';
$errno = 0;
$errstr = '';
$fp = @stream_socket_client('unix://' . $sockPath, $errno, $errstr, 5.0);
if ($fp === false) {
    emit_admin_json([
        'ok'    => false,
        'code'  => 503,
        'error' => "da-wptoolkitd daemon is offline ({$errstr}).",
    ], 200);
}

stream_set_timeout($fp, 120);
fwrite($fp, json_encode($ipcReq, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n");
$rawReply = fgets($fp);
fclose($fp);

if (!is_string($rawReply) || trim($rawReply) === '') {
    emit_admin_json(['ok' => false, 'code' => 502, 'error' => 'Empty response from da-wptoolkitd']);
}

$decoded = json_decode($rawReply, true);
if (!is_array($decoded)) {
    emit_admin_json(['ok' => false, 'code' => 502, 'error' => 'Invalid JSON response from da-wptoolkitd']);
}

emit_admin_json($decoded, 200);
