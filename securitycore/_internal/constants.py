# Общие настройки
DEFAULT_ENCODING = "utf-8"
DEFAULT_SALT_LENGTH = 16
DEFAULT_TOKEN_LENGTH = 32


# Лимиты и параметры паролей
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128

# Разрешённые специальные символы для паролей
SPECIAL_CHARS = "!@#$%^&*()-_=+[]{};:,.<>?/\\|"


# Лимиты для пользовательских данных
MAX_EMAIL_LENGTH = 254
MAX_URL_LENGTH = 2048
MAX_LOG_MESSAGE_LENGTH = 5000


# Безопасные протоколы
ALLOWED_URL_SCHEMES = ("http", "https")


# Настройки аудита
AUDIT_TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
AUDIT_DEFAULT_CHANNEL = "securitycore"


# Настройки криптографии
HASH_ITERATIONS = 100_000
HASH_ALGORITHM = "sha256"

# Время жизни токенов (в секундах)
TOKEN_EXPIRATION_SECONDS = 3600  # 1 час


# Внутренние флаги
DEBUG_MODE = False


# Максимальная длина имени файла или пути
MAX_PATH_LENGTH = 255


# Запрещённые имена файлов (безопасность + совместимость)
FORBIDDEN_FILENAMES = {
    "con", "prn", "aux", "nul",
    "com1", "com2", "com3", "com4", "com5", "com6", "com7", "com8", "com9",
    "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6", "lpt7", "lpt8", "lpt9",
}


# Запрещённые расширения (опасные форматы)
FORBIDDEN_EXTENSIONS = {
    ".exe", ".bat", ".cmd", ".sh", ".ps1",
    ".js", ".vbs", ".msi", ".scr",
}


# Максимальная длина SQL-параметра
MAX_SQL_INPUT_LENGTH = 500


# Максимальная длина пользовательского ввода
MAX_INPUT_LENGTH = 5000


# Максимальная длина строки IP-адреса.
# 64 символа достаточно для всех форм IPv6 (включая сжатие, зоны, двоеточия),
# и при этом защищают от чрезмерно длинных или вредоносных входных данных.
MAX_IP_LENGTH = 64