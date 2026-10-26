"""Paths as they should read in an artifact.

A sheet or a record is meant to be handed to someone else, so it must not carry
this machine's home directory. Inside the repo, print repo-relative; under home,
print with a tilde; anything else stays absolute.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
HOME = Path.home()


def display(value):
    if value is None:
        return None
    text = str(value)
    try:
        resolved = Path(text).resolve()
    except OSError:
        return text
    if resolved == ROOT or ROOT in resolved.parents:
        return str(resolved.relative_to(ROOT))
    if resolved == HOME or HOME in resolved.parents:
        return '~/' + str(resolved.relative_to(HOME))
    return text


def shorten(text):
    """For blobs that quote paths inside them, such as a written foundry.toml."""
    if text is None:
        return None
    return (str(text).replace(str(HOME), '~').replace(str(ROOT) + '/', ''))
