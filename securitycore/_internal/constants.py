from typing import Final

# Общие настройки
DEFAULT_ENCODING: Final[str] = "utf-8"
DEFAULT_SALT_LENGTH: Final[int] = 16  # Длина соли для PBKDF2
DEFAULT_TOKEN_LENGTH: Final[int] = 32  # Длина токенов и ключ

# Лимиты и параметры паролей
MIN_PASSWORD_LENGTH: Final[int] = 8
MAX_PASSWORD_LENGTH: Final[int] = 128
SPECIAL_CHARS: Final[str] = "!@#$%^&*()-_=+[]{};:,.<>?/\\|"

# Безопасность URL и Email
MAX_EMAIL_LENGTH: Final[int] = 254
MAX_URL_LENGTH: Final[int] = 2048
ALLOWED_URL_SCHEMES: Final[tuple[str, ...]] = ("http", "https")

# Настройки Криптографии
HASH_ITERATIONS: Final[int] = 600_000
HASH_ALGORITHM: Final[str] = "sha256"

# Настройки аудита
AUDIT_TIMESTAMP_FORMAT: Final[str] = "%Y-%m-%dT%H:%M:%S.%fZ"
AUDIT_DEFAULT_CHANNEL: Final[str] = "securitycore"

# Лимиты аудита
MAX_LOG_MESSAGE_LENGTH: Final[int] = 4096

# Безопасность файловой системы
MAX_PATH_LENGTH: Final[int] = 255
FORBIDDEN_FILENAMES: Final[set[str]] = {
    "con", "prn", "aux", "nul", "com1",
    "com2", "com3", "com4", "com5", "com6",
    "com7", "com8", "com9", "lpt1", "lpt2",
    "lpt3", "lpt4", "lpt5", "lpt6", "lpt7",
    "lpt8", "lpt9",
}

FORBIDDEN_EXTENSIONS: Final[set[str]] = {
    ".exe", ".bat", ".cmd", ".sh",
    ".ps1", ".js", ".vbs", ".msi",
    ".scr",
}

# Лимиты ввода
MAX_SQL_INPUT_LENGTH: Final[int] = 500
MAX_INPUT_LENGTH: Final[int] = 5000
MAX_IP_LENGTH: Final[int] = 64

# Время жизни токенов
TOKEN_EXPIRATION_SECONDS: Final[int] = 3600  # 1 час
