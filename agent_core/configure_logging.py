import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

def configure_logging(log_dir_path: str, console_level: str) -> logging.Logger:
    """
    Configure and return the named logger "InstallationLogger", writing only to a file.
    Omits logger name in the format and does NOT add a console handler.
    """
    log_dir = Path(log_dir_path)
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / 'installation.log'

    # Create (or get) the logger
    logger = logging.getLogger("InstallationLogger")

    # Remove any existing handlers to avoid duplicates
    logger.handlers = []
    # Prevent propagation to root logger => no extra printing
    logger.propagate = False

    # Capture everything internally
    logger.setLevel(logging.DEBUG)

    # File handler: always at DEBUG to capture all logs
    file_handler = RotatingFileHandler(str(log_file), maxBytes=5*1024*1024, backupCount=2)
    file_handler.setLevel(logging.DEBUG)

    # Format WITHOUT logger name (i.e. no %(name)s)
    file_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s'
    )
    file_handler.setFormatter(file_formatter)

    # Attach only the file handler (no console handler)
    logger.addHandler(file_handler)

    return logger
