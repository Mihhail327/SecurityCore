import logging
from datetime import datetime
from pathlib import Path

# Папка для логов
LOG_DIR = Path("logs")
LOG_DIR.mkdir(exist_ok=True)

# Основной файл логов
LOG_FILE = LOG_DIR / "security_audit.log"

# Настройка логирования
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

def log_event(event: str, level: str = "info"):
    """Логирует события безопасности.
    :param event: описание события
    :param level: уровень ('info', 'warning', 'error', 'critical')
    """
    if level == "info":
        logging.info(event)
    elif level == "warning":
        logging.warning(event)
    elif level == "error":
        logging.error(event)
    elif level == "critical":
        logging.critical(event)
    else:
        logging.debug(event)

def log_access(user: str, action: str, resource: str):
    """
    Логирует доступ пользователя к ресурсу.
    """
    event = f"ACCESS: user={user}, action={action}, resource={resource}"
    log_event(event, level="info")

def log_violation(user: str, violation: str):
    """
    Логирует нарушение безопасности.
    """
    event = f"VIOLATION: user={user}, violation={violation}"
    log_event(event, level="warning")

def log_system_error(error: str):
    """
    Логирует системную ошибку.
    """
    event = f"SYSTEM ERROR: {error}"
    log_event(event, level="error")

def log_critical_alert(alert: str):
    """
    Логирует критическое событие.
    """
    event = f"CRITICAL ALERT: {alert}"
    log_event(event, level="critical")