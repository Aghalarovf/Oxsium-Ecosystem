from pathlib import Path
import os
import shutil
import stat


ROOT = Path(__file__).resolve().parent
CACHE_DIRECTORY_NAMES = {"__pycache__", "pycache"}


def remove_read_only(func, path, _exc_info):
    """Make a failed removal writable and retry it."""
    os.chmod(path, stat.S_IWRITE)
    func(path)


def remove_pycache_directories() -> int:
    directories = [
        path
        for path in ROOT.rglob("*")
        if path.is_dir() and path.name.casefold() in CACHE_DIRECTORY_NAMES
    ]

    for directory in directories:
        shutil.rmtree(directory, onerror=remove_read_only)

    return len(directories)


if __name__ == "__main__":
    removed_count = remove_pycache_directories()
    print(f"Removed {removed_count} __pycache__ directorie(s).")
