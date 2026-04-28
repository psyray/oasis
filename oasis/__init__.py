"""
OASIS - Ollama Automated Security Intelligence Scanner
"""

__version__ = "0.6.0"


def main():
    from .oasis import main as _main

    return _main()