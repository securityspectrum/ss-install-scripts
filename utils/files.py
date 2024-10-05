import tempfile
from pathlib import Path


def get_temp_file_path(file_name):
    # Determine the appropriate download directory based on the OS
    import platform
    if platform.system() == "Linux":
        temp_dir = tempfile.gettempdir()
        dest_path = Path(temp_dir) / file_name
    elif platform.system() == "Darwin":
        temp_dir = tempfile.gettempdir()
        dest_path = Path(temp_dir) / file_name
    elif platform.system() == "Windows":
        temp_dir = tempfile.gettempdir()
        dest_path = Path(temp_dir) / file_name
    else:
        raise NotImplementedError(f"Unsupported OS: {platform.system()}")
    return dest_path
