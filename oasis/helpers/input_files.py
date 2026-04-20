from pathlib import Path
from typing import Callable, Optional

from ..tools import parse_input


def resolve_valid_embedding_input_files(
    input_path: str,
    is_valid_file: Callable[[Path], bool],
    *,
    files_to_analyze: Optional[list[Path]] = None,
    pre_parsed: bool = False,
) -> tuple[list[Path], int, list[Path]]:
    """
    Resolve embedding input files and split them into valid/unsupported groups.
    """
    parsed_input_files = (
        [Path(file_path) for file_path in (files_to_analyze or [])]
        if pre_parsed
        else (
            list(files_to_analyze)
            if files_to_analyze is not None
            else parse_input(input_path)
        )
    )
    if not parsed_input_files:
        return [], 0, []

    valid_files: list[Path] = []
    unsupported_files: list[Path] = []
    for file_path in parsed_input_files:
        if is_valid_file(file_path):
            valid_files.append(file_path)
        else:
            unsupported_files.append(file_path)
    return valid_files, len(parsed_input_files), unsupported_files
