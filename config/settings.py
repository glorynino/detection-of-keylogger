"""
Configuration du système de détection de keyloggers
"""

# Seuils de scoring
SCORE_THRESHOLDS = {
    'LOW': 10,
    'MEDIUM': 20,
    'HIGH': 30,
    'CRITICAL': 50
}

# Scores par comportement
BEHAVIOR_SCORES = {
    'SUSPICIOUS_API': 10,
    'FILE_WRITE': 15,
    'NETWORK_COMM': 20,
    'PERSISTENCE': 25,
    'DLL_INJECTION': 30,
    'HOOK_INSTALLATION': 15
}

# API suspectes à surveiller
SUSPICIOUS_APIS = [
    'SetWindowsHookEx',
    'SetWindowsHookExA',
    'SetWindowsHookExW',
    'GetAsyncKeyState',
    'GetKeyState',
    'ReadProcessMemory',
    'WriteProcessMemory',
    'VirtualAllocEx',
    'CreateRemoteThread',
    'SetWindowsHook',
    'UnhookWindowsHookEx'
]

# Chemins suspects
SUSPICIOUS_PATHS = [
    '%TEMP%',
    '%APPDATA%',
    '%LOCALAPPDATA%',
    'C:\\Windows\\Temp',
    'C:\\Users\\Public'
]

# Extensions de fichiers suspects
SUSPICIOUS_EXTENSIONS = [
    '.log',
    '.txt',
    '.dat',
    '.tmp',
    '.key'
]

# Ports suspects pour communication
SUSPICIOUS_PORTS = [
    80, 443, 8080, 8443, 4444, 6666, 7777
]

# Configuration des logs ma3netha les appelle li rahom yesraw ze3ma proces 3eyet l api
LOG_CONFIG = {
    'level': 'INFO',
    'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    'file': 'keylogger_detector.log',
    'max_size': 10485760,  # 10MB
    'backup_count': 5
}

# Configuration de surveillance
MONITOR_CONFIG = {
    'scan_interval': 5,  # secondes
    'process_check_interval': 2,
    'file_check_interval': 10,
    'network_check_interval': 15
}
