"""Dependency version-range matching helpers."""

from __future__ import annotations

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version
from semantic_version import NpmSpec
from semantic_version import Version as NpmVersion


def version_matches(version: str, version_range: str, ecosystem: str) -> bool:
    """Return whether a normalized version satisfies a package version range."""
    if not version or version == "*" or not version_range:
        return False
    if ecosystem.lower() == "npm":
        try:
            candidate = NpmVersion.coerce(version.lstrip("v"))
            return bool(NpmSpec(version_range).match(candidate))
        except (ValueError, TypeError):
            return False
    try:
        return Version(version) in SpecifierSet(version_range)
    except (InvalidVersion, InvalidSpecifier):
        return False
