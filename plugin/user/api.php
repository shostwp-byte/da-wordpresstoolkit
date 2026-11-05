<?php
declare(strict_types=1);

/**
 * DirectAdmin End-User JSON IPC Relay (invoked via user/api.raw with `php -n`).
 * Relays requests strictly over /var/run/da-wptoolkit-user.sock where da-wptoolkitd enforces:
 *   1. Kernel SO_PEERCRED (UID + PID) verification.
 *   2. /proc/<pid>/stat & cgroup DirectAdmin lineage verification (blocks PHP-FPM/LSPHP web-shells).
 *   3. DirectAdmin active session file (da_sess_*) + root-secret HMAC-SHA256 CSRF token verification.
 */

function emit_json(array $body, int $status = 200): void
{
    $reason = match ($status) {
        200 => 'OK',
        400 => 'Bad Request',
        403 => 'Forbidden',
        404 => 'Not Found',
        405 => 'Method Not Allowed',
        429 => 'Too Many Requests',
        501 => 'Not Implemented',
        default => 'Internal Server Error',
    };
    echo "HTTP/1.1 {$status} {$reason}\r\n";
    echo "Content-Type: application/json; charset=utf-8\r\n";
    echo "Cache-Control: no-store, no-cache, must-revalidate\r\n";
    echo "X-Content-Type-Options: nosniff\r\n\r\n";
    echo json_encode($body, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n";
    exit(0);
}

function parse_da_form_string(string $raw): array
{
    $normalized = $raw;
    if (strpos($raw, '&amp;') !== false && preg_match('/&(?!amp;)/', $raw) === 0) {
        $normalized = str_replace('&amp;', '&', $raw);
    }
    $out = [];
    parse_str($normalized, $out);
    return is_array($out) ? $out : [];
}

function decode_da_json(string $raw): ?array
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

function extract_da_session_id(): string
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

function normalize_url_authority(string $url): string
{
    $parts = @parse_url(trim($url));
    if (!is_array($parts) || empty($parts['host'])) {
        return '';
    }
    $scheme = strtolower((string) ($parts['scheme'] ?? ''));
    $host = strtolower((string) $parts['host']);
    if (strpos($host, ':') !== false && $host[0] !== '[') {
        $host = '[' . $host . ']';
    }
    $port = isset($parts['port']) ? (int) $parts['port'] : 0;
    if ($port > 0 && !(($scheme === 'https' && $port === 443) || ($scheme === 'http' && $port === 80))) {
        return $host . ':' . $port;
    }
    return $host;
}

function verify_same_origin_post(): ?string
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
        $auth = normalize_url_authority($origin);
        if ($auth === '' || !in_array($auth, $allowed, true)) {
            return 'Forbidden: Origin header mismatch';
        }
        return null;
    }

    $referer = trim((string) (getenv('HTTP_REFERER') ?: ''));
    if ($referer !== '') {
        $auth = normalize_url_authority($referer);
        if ($auth === '' || !in_array($auth, $allowed, true)) {
            return 'Forbidden: Referer header mismatch';
        }
    }
    return null;
}

function read_request_payload(bool &$isPost): array
{
    $isPost = false;
    $reqMeth = strtoupper((string) (getenv('REQUEST_METHOD') ?: 'GET'));
    $postParams = [];

    $postEnv = getenv('POST');
    if (is_string($postEnv) && $postEnv !== '') {
        $isPost = true;
        $decoded = decode_da_json($postEnv);
        $postParams = is_array($decoded) ? $decoded : parse_da_form_string($postEnv);
    } elseif (defined('STDIN') && is_resource(STDIN)) {
        $cLen = (int) (getenv('CONTENT_LENGTH') ?: 0);
        $waitUsec = ($reqMeth === 'POST' || $cLen > 0) ? 200000 : 0;
        $r = [STDIN];
        $w = null;
        $e = null;
        if (@stream_select($r, $w, $e, 0, $waitUsec) > 0) {
            @stream_set_blocking(STDIN, false);
            $maxBytes = ($cLen > 0 && $cLen <= 524288) ? $cLen : 524288;
            $rawStdin = @stream_get_contents(STDIN, $maxBytes);
            if (is_string($rawStdin) && trim($rawStdin) !== '') {
                $isPost = true;
                $decoded = decode_da_json($rawStdin);
                $postParams = is_array($decoded) ? $decoded : parse_da_form_string($rawStdin);
            }
        }
    }

    if ($reqMeth === 'POST' || $isPost) {
        $isPost = true;
        return $postParams;
    }

    $qs = (string) (getenv('QUERY_STRING') ?: '');
    return $qs !== '' ? parse_da_form_string($qs) : [];
}

$isPost = false;
$input = read_request_payload($isPost);
$action = strtolower(trim((string) ($input['action'] ?? 'get_bootstrap')));

$readOnlyActions = [
    'ping',
    'get_bootstrap',
    'list_domains',
    'list_instances',
    'get_instance',
    'list_plugins',
    'list_themes',
    'list_all_plugins',
    'list_all_themes',
    'search_wporg',
    'check_core_updates',
    'get_vulns',
    'get_security_status',
    'get_tools_status',
    'read_debug_log',
    'get_safe_wpconfig',
    'list_snapshots',
    'get_snapshot_download',
    'list_quarantine',
    'get_quarantine_diff',
    'list_whitelist',
    'list_sets',
    'list_jobs',
    'get_job',
];

if (!in_array($action, $readOnlyActions, true) && !$isPost) {
    emit_json(['ok' => false, 'code' => 405, 'error' => 'Mutating actions require HTTP POST'], 405);
}

if ($isPost) {
    $originErr = verify_same_origin_post();
    if ($originErr !== null) {
        emit_json(['ok' => false, 'code' => 403, 'error' => $originErr], 403);
    }
}

$csrfToken = trim((string) ($input['csrf_token'] ?? ''));
if ($csrfToken === '') {
    $csrfToken = trim((string) (getenv('HTTP_X_DAWPTK_CSRF') ?: ''));
}

$ipcReq = [
    'action'      => $action,
    'username'    => trim((string) (getenv('USERNAME') ?: '')),
    'session_id'  => extract_da_session_id(),
    'csrf_token'  => $csrfToken,
    'instance_id' => trim((string) ($input['instance_id'] ?? '')),
    'job_id'      => trim((string) ($input['job_id'] ?? '')),
    'limit'       => isset($input['limit']) ? (int) $input['limit'] : 0,
    'params'      => isset($input['params']) && is_array($input['params']) ? $input['params'] : [],
];

$sockPath = trim((string) (getenv('DA_WPTK_USER_SOCK') ?: ''));
if ($sockPath === '') {
    foreach (['/run/da-wptoolkit/user.sock', '/var/run/da-wptoolkit/user.sock', '/var/run/da-wptoolkit-user.sock'] as $candidateSock) {
        if (file_exists($candidateSock)) {
            $sockPath = $candidateSock;
            break;
        }
    }
    if ($sockPath === '') {
        $sockPath = '/var/run/da-wptoolkit-user.sock';
    }
}

function call_user_daemon(string $sockPath, array $reqPayload): array
{
    if (isset($reqPayload['params']) && is_array($reqPayload['params'])) {
        $reqPayload['params'] = (object) $reqPayload['params'];
    }
    $errno = 0;
    $errstr = '';
    $fp = @stream_socket_client('unix://' . $sockPath, $errno, $errstr, 5.0);
    if ($fp === false) {
        emit_json([
            'ok'    => false,
            'code'  => 503,
            'error' => "WordPress Manager service is temporarily unavailable ({$errstr}).",
        ], 200);
    }
    stream_set_timeout($fp, 60);
    fwrite($fp, json_encode($reqPayload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n");
    $rawReply = fgets($fp);
    fclose($fp);
    if (!is_string($rawReply) || trim($rawReply) === '') {
        emit_json(['ok' => false, 'code' => 502, 'error' => 'Empty response from da-wptoolkitd']);
    }
    $decoded = json_decode($rawReply, true);
    if (!is_array($decoded)) {
        emit_json(['ok' => false, 'code' => 502, 'error' => 'Invalid JSON response from da-wptoolkitd']);
    }
    return $decoded;
}

if ($action === 'upload_zip_chunk') {
    if ($csrfToken === '') {
        emit_json(['ok' => false, 'code' => 403, 'error' => 'Missing CSRF security token'], 403);
    }
    $authPing = call_user_daemon($sockPath, [
        'action'     => 'ping',
        'username'   => $ipcReq['username'],
        'session_id' => $ipcReq['session_id'],
    ]);
    if (empty($authPing['ok'])) {
        emit_json($authPing, 200);
    }

    $params = $ipcReq['params'];
    $uploadId = strtolower(trim((string) ($params['upload_id'] ?? '')));
    if (!preg_match('/^[a-f0-9]{16,32}$/', $uploadId)) {
        emit_json(['ok' => false, 'code' => 400, 'error' => 'Invalid upload_id format'], 400);
    }
    $homeDir = '';
    if (function_exists('posix_geteuid') && function_exists('posix_getpwuid')) {
        $pw = @posix_getpwuid(@posix_geteuid());
        if (is_array($pw) && !empty($pw['dir'])) {
            $homeDir = (string) $pw['dir'];
        }
    }
    if ($homeDir === '') {
        $homeDir = trim((string) (getenv('HOME') ?: ''));
    }
    if ($homeDir === '' || !is_dir($homeDir) || is_link($homeDir)) {
        emit_json(['ok' => false, 'code' => 500, 'error' => 'Unable to resolve safe user home directory'], 500);
    }
    $stageDir = rtrim($homeDir, '/') . '/.da-wptk-uploads';
    if (is_link($stageDir)) {
        emit_json(['ok' => false, 'code' => 403, 'error' => 'Refusing symlinked staging directory'], 403);
    }
    if (!is_dir($stageDir) && !@mkdir($stageDir, 0700, true)) {
        emit_json(['ok' => false, 'code' => 500, 'error' => 'Failed to create staging directory'], 500);
    }
    foreach (@glob($stageDir . '/up_*.zip') ?: [] as $oldFile) {
        if (!is_link($oldFile) && @filemtime($oldFile) < (time() - 900)) {
            @unlink($oldFile);
        }
    }

    $stageFile = $stageDir . '/up_' . $uploadId . '.zip';
    if (is_link($stageFile)) {
        emit_json(['ok' => false, 'code' => 403, 'error' => 'Refusing symlinked upload file'], 403);
    }
    $chunkIndex = (int) ($params['chunk_index'] ?? 0);
    $chunkB64 = (string) ($params['chunk_base64'] ?? '');
    if ($chunkIndex === 0 && file_exists($stageFile)) {
        @unlink($stageFile);
    }
    if ($chunkB64 !== '') {
        $rawBytes = base64_decode($chunkB64, true);
        if ($rawBytes === false) {
            @unlink($stageFile);
            emit_json(['ok' => false, 'code' => 400, 'error' => 'Invalid Base64 zip chunk'], 400);
        }
        $curSize = file_exists($stageFile) ? (int) @filesize($stageFile) : 0;
        if ($curSize + strlen($rawBytes) > 67108864) {
            @unlink($stageFile);
            emit_json(['ok' => false, 'code' => 400, 'error' => 'Zip archive exceeds 64 MB upload limit'], 400);
        }
        if (@file_put_contents($stageFile, $rawBytes, FILE_APPEND | LOCK_EX) === false) {
            @unlink($stageFile);
            emit_json(['ok' => false, 'code' => 500, 'error' => 'Failed to write upload chunk (check disk quota)'], 500);
        }
        @chmod($stageFile, 0600);
    }

    if (empty($params['commit'])) {
        emit_json([
            'ok'         => true,
            'csrf_token' => $authPing['csrf_token'] ?? $csrfToken,
            'data'       => ['staged_bytes' => file_exists($stageFile) ? (int) @filesize($stageFile) : 0],
        ], 200);
    }

    $targetKind = strtolower(trim((string) ($params['kind'] ?? 'plugin')));
    $daemonAction = ($targetKind === 'theme') ? 'manage_theme' : 'manage_plugin';
    $installResp = call_user_daemon($sockPath, [
        'action'      => $daemonAction,
        'username'    => $ipcReq['username'],
        'session_id'  => $ipcReq['session_id'],
        'csrf_token'  => $csrfToken,
        'instance_id' => $ipcReq['instance_id'],
        'params'      => [
            'operation' => 'install_zip',
            'zip_path'  => $stageFile,
            'activate'  => !empty($params['activate']),
        ],
    ]);
    @unlink($stageFile);
    emit_json($installResp, 200);
}

$decoded = call_user_daemon($sockPath, $ipcReq);

if ($action === 'get_snapshot_download' && !empty($input['stream']) && !empty($decoded['ok']) && is_array($decoded['data'] ?? null)) {
    $archivePath = (string) ($decoded['data']['archive_path'] ?? '');
    $fileName = preg_replace('/[^a-zA-Z0-9._-]/', '_', (string) ($decoded['data']['file_name'] ?? 'snapshot.tar.zst'));
    if ($archivePath !== '' && !is_link($archivePath) && is_file($archivePath) && is_readable($archivePath)) {
        $size = (int) filesize($archivePath);
        echo "HTTP/1.1 200 OK\r\n";
        echo "Content-Type: application/zstd\r\n";
        echo "Content-Disposition: attachment; filename=\"{$fileName}\"\r\n";
        echo "Content-Length: {$size}\r\n";
        echo "Cache-Control: no-store\r\n";
        echo "X-Content-Type-Options: nosniff\r\n\r\n";
        readfile($archivePath);
        exit(0);
    }
}

emit_json($decoded, 200);
