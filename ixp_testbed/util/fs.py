"""Helper functions for working with the file system."""

import os
from pathlib import Path
from typing import Union


def clear_directory(directory: Union[str, Path]):
    """Delete all files and subdirectories in the given directory.
    :param directory: Directory to clear.
    """
    for root, dirs, files in os.walk(directory, topdown=False):
        for file in files:
            os.remove(os.path.join(root, file))
        for dir in dirs:
            os.rmdir(os.path.join(root, dir))
