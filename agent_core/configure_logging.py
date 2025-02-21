import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

def configure_logging(log_dir_path: str, console_level: str) -> logging.Logger:
    log_dir = Path(log_dir_path)
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / 'installation.log'
    logger = logging.getLogger("InstallationLogger")
    # Remove any existing handlers
    logger.handlers = []
    # Prevent propagation to root logger
    logger.propagate = False
    logger.setLevel(logging.DEBUG)
    # File handler (captures all logs)
    file_handler = RotatingFileHandler(str(log_file), maxBytes=5 * 1024 * 1024, backupCount=2)
    file_handler.setLevel(logging.DEBUG)
    file_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(file_formatter)
    logger.addHandler(file_handler)
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(getattr(logging, console_level.upper(), logging.INFO))
    console_formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s')
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    return logger
