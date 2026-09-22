"""Tests for the AttackLens CLI."""

from attacklens import __version__
from attacklens.cli import build_parser


def test_version() -> None:
    """The package exposes the expected version."""
    assert __version__ == "0.1.0"


def test_parser() -> None:
    """The CLI parser can be created."""
    parser = build_parser()

    assert parser.prog == "attacklens"