<?php
declare(strict_types=1);

const DATA_DIR = __DIR__ . '/private';
const USERS_FILE = DATA_DIR . '/users.txt';
const MESSAGES_FILE = DATA_DIR . '/messages.json';
const FILES_DIR = DATA_DIR . '/files';

if (!is_dir(DATA_DIR)) {
    http_response_code(500);
    exit('Не найден каталог private.');
}
if (!is_dir(FILES_DIR)) {
    mkdir(FILES_DIR, 0700, true);
}

ini_set('session.use_cookies', '1');
ini_set('session.use_only_cookies', '1');
ini_set('session.use_strict_mode', '1');
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'secure' => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
    'httponly' => true,
    'samesite' => 'Lax',
]);
session_start();

header('X-Content-Type-Options: nosniff');
header('Cache-Control: no-store');
header('Referrer-Policy: no-referrer');

function jsonReply(array $data, int $status = 200): never
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

function readUserCredential(string $username): ?string
{
    $lines = is_file(USERS_FILE)
        ? file(USERS_FILE, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES)
        : false;

    if ($lines === false) {
        throw new RuntimeException('Не удалось прочитать файл пользователей.');
    }

    foreach ($lines as $line) {
        $parts = explode(':', $line, 2);
        if (count($parts) === 2 && hash_equals($parts[0], $username)) {
            return $parts[1];
        }
    }

    return null;
}

function requireLogin(): void
{
    if (empty($_SESSION['user'])) {
        jsonReply(['error' => 'Требуется вход'], 401);
    }

    try {
        $credential = readUserCredential((string) $_SESSION['user']);
    } catch (Throwable $exception) {
        error_log((string) $exception);
        jsonReply(['error' => 'Не удалось проверить сессию'], 500);
    }

    $sessionVersion = (string) ($_SESSION['auth_version'] ?? '');
    if (
        $credential === null ||
        $sessionVersion === '' ||
        !hash_equals(hash('sha256', $credential), $sessionVersion)
    ) {
        unset(
            $_SESSION['user'],
            $_SESSION['auth_version'],
            $_SESSION['chat_id'],
            $_SESSION['chat_name']
        );
        jsonReply(['error' => 'Сессия сброшена. Войдите снова.'], 401);
    }
}

function requireChat(): void
{
    requireLogin();

    if (
        empty($_SESSION['chat_id']) ||
        !preg_match('/^[a-f0-9]{64}$/', (string) $_SESSION['chat_id'])
    ) {
        jsonReply(['error' => 'Сначала выберите чат'], 403);
    }
}

function requestInput(): array
{
    static $input = null;

    if ($input === null) {
        $decoded = json_decode((string) file_get_contents('php://input'), true);
        $input = is_array($decoded) ? $decoded : [];
    }

    return $input;
}

function requestCsrfToken(): string
{
    $headerToken = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    if ($headerToken !== '') {
        return $headerToken;
    }

    return (string) (requestInput()['csrf'] ?? '');
}

function checkCsrfToken(): void
{
    $providedToken = requestCsrfToken();
    $sessionToken = (string) ($_SESSION['csrf'] ?? '');

    if ($sessionToken === '' || !hash_equals($sessionToken, $providedToken)) {
        jsonReply(['error' => 'Неверный CSRF-токен'], 403);
    }
}

function readMessages(): array
{
    if (!is_file(MESSAGES_FILE)) {
        return [];
    }

    $contents = file_get_contents(MESSAGES_FILE);
    if ($contents === false || trim($contents) === '') {
        return [];
    }

    $messages = json_decode($contents, true);
    return is_array($messages) ? $messages : [];
}

function saveFileCprf(string $iv, string $ciphertext): ?string
{
    $fileId = bin2hex(random_bytes(16));
    $filePath = FILES_DIR . '/' . $fileId . '.cprf';
    $fileData = json_encode(
        ['iv' => $iv, 'ciphertext' => $ciphertext],
        JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
    );

    if ($fileData === false || file_put_contents($filePath, $fileData, LOCK_EX) === false) {
        return null;
    }

    chmod($filePath, 0600);
    return $fileId;
}

function loadFileCprf(string $fileId): ?array
{
    if (!preg_match('/^[a-f0-9]{32}$/', $fileId)) {
        return null;
    }

    $filePath = FILES_DIR . '/' . $fileId . '.cprf';
    if (!is_file($filePath)) {
        return null;
    }

    $contents = file_get_contents($filePath);
    if ($contents === false) {
        return null;
    }

    $data = json_decode($contents, true);
    if (!is_array($data) || empty($data['iv']) || empty($data['ciphertext'])) {
        return null;
    }

    return ['iv' => $data['iv'], 'ciphertext' => $data['ciphertext']];
}

function validChatName(string $name): bool
{
    if (!preg_match('//u', $name)) {
        return false;
    }

    preg_match_all('/./us', $name, $characters);
    $length = count($characters[0]);

    return $length >= 3 && $length <= 80;
}

function randomChatName(): string
{
    $alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    $name = '';

    for ($i = 0; $i < 12; $i++) {
        $name .= $alphabet[random_int(0, strlen($alphabet) - 1)];
    }

    return $name;
}

$action = $_GET['action'] ?? '';

if ($action === 'login' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!is_file(USERS_FILE)) {
        jsonReply(['error' => 'Файл пользователей не найден'], 500);
    }

    $input = requestInput();
    $username = (string) ($input['username'] ?? '');
    $password = (string) ($input['password'] ?? '');

    if (!preg_match('/^[a-zA-Z0-9_.-]{1,40}$/', $username)) {
        jsonReply(['error' => 'Неверный логин или пароль'], 401);
    }

    try {
        $credential = readUserCredential($username);
    } catch (Throwable $exception) {
        error_log((string) $exception);
        jsonReply(['error' => 'Не удалось проверить учётную запись'], 500);
    }

    if (
        $credential === null ||
        !password_verify($password, explode(':', $credential, 2)[0])
    ) {
        jsonReply(['error' => 'Неверный логин или пароль'], 401);
    }

    session_regenerate_id(true);
    $_SESSION['user'] = $username;
    $_SESSION['auth_version'] = hash('sha256', $credential);
    $_SESSION['csrf'] = bin2hex(random_bytes(32));
    unset($_SESSION['chat_id'], $_SESSION['chat_name']);

    jsonReply([
        'ok' => true,
        'user' => $username,
        'csrf' => $_SESSION['csrf'],
    ]);
}

if ($action === 'join_room' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    requireLogin();
    checkCsrfToken();

    $input = requestInput();
    $chatName = trim((string) ($input['chatName'] ?? ''));

    if ($chatName === '') {
        $chatName = randomChatName();
    } elseif (!validChatName($chatName)) {
        jsonReply(['error' => 'Название чата должно содержать от 3 до 80 символов'], 400);
    }

    $_SESSION['chat_name'] = $chatName;
    $_SESSION['chat_id'] = hash('sha256', $chatName);

    jsonReply([
        'ok' => true,
        'chatName' => $chatName,
        'chatId' => $_SESSION['chat_id'],
    ]);
}

if ($action === 'me' && $_SERVER['REQUEST_METHOD'] === 'GET') {
    requireLogin();
    jsonReply([
        'user' => $_SESSION['user'],
        'csrf' => $_SESSION['csrf'] ?? '',
        'chatName' => $_SESSION['chat_name'] ?? null,
    ]);
}

if ($action === 'logout' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    requireLogin();
    checkCsrfToken();

    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(
            session_name(),
            '',
            time() - 42000,
            $params['path'],
            $params['domain'],
            $params['secure'],
            $params['httponly']
        );
    }

    session_destroy();
    jsonReply(['ok' => true]);
}

if ($action === 'messages') {
    requireChat();

    if ($_SERVER['REQUEST_METHOD'] === 'GET') {
        $chatId = (string) $_SESSION['chat_id'];
        $messages = array_values(array_filter(
            readMessages(),
            static fn ($message): bool =>
                is_array($message) &&
                isset($message['chatId']) &&
                hash_equals($chatId, (string) $message['chatId'])
        ));

        jsonReply([
            'messages' => $messages,
            'csrf' => $_SESSION['csrf'],
        ]);
    }

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        checkCsrfToken();

        $input = requestInput();
        $iv = (string) ($input['iv'] ?? '');
        $ciphertext = (string) ($input['ciphertext'] ?? '');

        if (
            $iv === '' ||
            strlen($iv) > 100 ||
            $ciphertext === '' ||
            strlen($ciphertext) > 12000000
        ) {
            jsonReply(['error' => 'Некорректные данные сообщения'], 400);
        }

        $fileId = saveFileCprf($iv, $ciphertext);
        if ($fileId === null) {
            jsonReply(['error' => 'Не удалось сохранить файл данных'], 500);
        }

        $file = fopen(MESSAGES_FILE, 'c+');
        if ($file === false || !flock($file, LOCK_EX)) {
            if (is_resource($file)) {
                fclose($file);
            }
            jsonReply(['error' => 'Не удалось открыть хранилище сообщений'], 500);
        }

        rewind($file);
        $contents = stream_get_contents($file);
        $messages = json_decode($contents ?: '[]', true);
        if (!is_array($messages)) {
            $messages = [];
        }

        $messages[] = [
            'id' => bin2hex(random_bytes(16)),
            'sender' => $_SESSION['user'],
            'createdAt' => gmdate('c'),
            'fileId' => $fileId,
            'chatId' => $_SESSION['chat_id'],
        ];

        $encoded = json_encode(
            $messages,
            JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES
        );

        if ($encoded === false) {
            flock($file, LOCK_UN);
            fclose($file);
            jsonReply(['error' => 'Не удалось сохранить сообщения'], 500);
        }

        rewind($file);
        ftruncate($file, 0);
        fwrite($file, $encoded);
        fflush($file);
        flock($file, LOCK_UN);
        fclose($file);

        jsonReply(['ok' => true]);
    }

    jsonReply(['error' => 'Метод не поддерживается'], 405);
}

if ($action === 'file' && $_SERVER['REQUEST_METHOD'] === 'GET') {
    requireChat();

    $fileId = (string) ($_GET['id'] ?? '');
    $chatId = (string) $_SESSION['chat_id'];
    $belongsToChat = false;

    foreach (readMessages() as $message) {
        if (
            is_array($message) &&
            isset($message['fileId'], $message['chatId']) &&
            hash_equals((string) $message['fileId'], $fileId) &&
            hash_equals($chatId, (string) $message['chatId'])
        ) {
            $belongsToChat = true;
            break;
        }
    }

    if (!$belongsToChat) {
        jsonReply(['error' => 'Файл не найден'], 404);
    }

    $fileData = loadFileCprf($fileId);
    if ($fileData === null) {
        jsonReply(['error' => 'Файл не найден'], 404);
    }

    $filePath = FILES_DIR . '/' . $fileId . '.cprf';
    $contents = file_get_contents($filePath);
    if ($contents === false) {
        jsonReply(['error' => 'Не удалось прочитать файл'], 500);
    }

    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . $fileId . '.cprf"');
    header('Content-Length: ' . strlen($contents));
    echo $contents;
    exit;
}

if ($action !== '') {
    jsonReply(['error' => 'Неизвестный запрос'], 404);
}
?>
<!doctype html>
<html lang="ru">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <body>
        <button class="primary login-submit" type="button" onclick="window.location.href='/ec8/web.html'">Веб версия</button>
    </body>
</html>
