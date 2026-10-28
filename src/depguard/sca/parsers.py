"""Bounded parsers for common dependency manifest formats."""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path
from typing import Any

from packaging.requirements import InvalidRequirement, Requirement

from depguard.models import Component

MAX_MANIFEST_BYTES = 2_000_000


class ManifestError(ValueError):
    """Raised when a manifest is invalid or exceeds safety limits."""


def parse_manifest(path: Path) -> list[Component]:
    """Parse a supported manifest based on its filename."""
    name = path.name.lower()
    if name in {"package.json", "package-lock.json"}:
        return parse_npm(path)
    if name == "requirements.txt" or name.endswith(".requirements"):
        return parse_requirements(path)
    if name == "pyproject.toml":
        return parse_pyproject(path)
    if name == "pipfile.lock":
        return parse_pipfile_lock(path)
    raise ManifestError(f"Unsupported manifest: {path.name}")


def _read_text(path: Path) -> str:
    """Read a bounded UTF-8 manifest."""
    try:
        if path.stat().st_size > MAX_MANIFEST_BYTES:
            raise ManifestError(f"Manifest exceeds {MAX_MANIFEST_BYTES} bytes")
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        raise ManifestError(f"Cannot read manifest {path}: {exc}") from exc


def _npm_component(name: str, version: str, direct: bool) -> Component:
    normalized = name.lower()
    return Component(
        name=name,
        version=version,
        ecosystem="npm",
        purl=f"pkg:npm/{normalized.replace('@', '%40')}@{version}",
        direct=direct,
    )


def parse_npm(path: Path) -> list[Component]:
    """Parse package.json or npm package-lock v1/v2/v3."""
    try:
        data: dict[str, Any] = json.loads(_read_text(path))
    except (json.JSONDecodeError, TypeError) as exc:
        raise ManifestError(f"Malformed npm JSON: {exc}") from exc

    if path.name.lower() == "package-lock.json" or "lockfileVersion" in data:
        found: dict[tuple[str, str], Component] = {}
        packages = data.get("packages")
        if isinstance(packages, dict):
            for package_path, details in packages.items():
                if not package_path or not isinstance(details, dict):
                    continue
                package_name = details.get("name") or _npm_name_from_path(package_path)
                version = details.get("version")
                if package_name and version:
                    key = (package_name, str(version))
                    found[key] = _npm_component(
                        package_name, str(version), package_path.count("node_modules/") <= 1
                    )
        else:
            _walk_npm_dependencies(data.get("dependencies", {}), found, direct=True)
        return sorted(found.values(), key=lambda item: (item.name.lower(), item.version))

    dependencies: dict[str, Any] = {}
    for dependency_group in ("dependencies", "devDependencies", "optionalDependencies"):
        value = data.get(dependency_group, {})
        if isinstance(value, dict):
            dependencies.update(value)
    return [
        _npm_component(package_name, str(version), True)
        for package_name, version in sorted(dependencies.items())
        if isinstance(version, str)
    ]


def _npm_name_from_path(package_path: str) -> str | None:
    marker = "node_modules/"
    if marker not in package_path:
        return None
    return package_path.rsplit(marker, 1)[-1]


def _walk_npm_dependencies(
    dependencies: Any,
    found: dict[tuple[str, str], Component],
    *,
    direct: bool,
) -> None:
    if not isinstance(dependencies, dict):
        return
    for package_name, details in dependencies.items():
        if not isinstance(details, dict):
            continue
        version = details.get("version")
        if version:
            found[(package_name, str(version))] = _npm_component(package_name, str(version), direct)
        _walk_npm_dependencies(details.get("dependencies", {}), found, direct=False)


def parse_requirements(
    path: Path,
    _seen: set[Path] | None = None,
    _root: Path | None = None,
) -> list[Component]:
    """Parse requirements with bounded, root-confined recursive includes."""
    root = _root or path.resolve().parent
    seen = _seen or set()
    resolved = path.resolve()
    if resolved in seen:
        return []
    if not resolved.is_relative_to(root):
        raise ManifestError("Requirement include escapes the manifest directory")
    seen.add(resolved)
    components: list[Component] = []
    for raw_line in _read_text(resolved).splitlines():
        line = re.split(r"\s+#", raw_line, maxsplit=1)[0].strip()
        if not line or line.startswith(("--index-url", "--extra-index-url", "--trusted-host")):
            continue
        if line.startswith(("-r ", "--requirement ")):
            include = line.split(maxsplit=1)[1]
            include_path = (resolved.parent / include).resolve()
            if not include_path.is_relative_to(root):
                raise ManifestError("Requirement include escapes the manifest directory")
            components.extend(parse_requirements(include_path, seen, root))
            continue
        line = re.sub(r"^-e\s+", "", line)
        try:
            requirement = Requirement(line)
        except InvalidRequirement:
            # VCS references can be retained as unresolved components when they name a project.
            match = re.search(r"#egg=([A-Za-z0-9_.-]+)", line)
            if not match:
                continue
            package_name, version = match.group(1), "*"
        else:
            package_name = requirement.name
            version = str(requirement.specifier) or "*"
        normalized = re.sub(r"[-_.]+", "-", package_name).lower()
        components.append(
            Component(
                name=package_name,
                version=version,
                ecosystem="PyPI",
                purl=f"pkg:pypi/{normalized}@{version}",
                direct=True,
                source=str(resolved),
            )
        )
    return components


def parse_pyproject(path: Path) -> list[Component]:
    """Parse PEP 621 and Poetry dependency declarations."""
    try:
        data = tomllib.loads(_read_text(path))
    except tomllib.TOMLDecodeError as exc:
        raise ManifestError(f"Malformed pyproject.toml: {exc}") from exc
    candidates: list[tuple[str, Any]] = []
    project = data.get("project", {})
    for item in project.get("dependencies", []):
        try:
            requirement = Requirement(item)
        except (InvalidRequirement, TypeError):
            continue
        candidates.append((requirement.name, str(requirement.specifier) or "*"))
    poetry = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    if isinstance(poetry, dict):
        for package_name, declaration in poetry.items():
            if package_name.lower() == "python":
                continue
            version = (
                declaration.get("version", "*") if isinstance(declaration, dict) else declaration
            )
            candidates.append((package_name, str(version)))
    return [_pypi_component(name, version) for name, version in candidates]


def parse_pipfile_lock(path: Path) -> list[Component]:
    """Parse Pipfile.lock default and development package sets."""
    try:
        data = json.loads(_read_text(path))
    except (json.JSONDecodeError, TypeError) as exc:
        raise ManifestError(f"Malformed Pipfile.lock JSON: {exc}") from exc
    components: list[Component] = []
    for group in ("default", "develop"):
        packages = data.get(group, {})
        if isinstance(packages, dict):
            for package_name, details in packages.items():
                version = details.get("version", "*") if isinstance(details, dict) else "*"
                components.append(_pypi_component(package_name, str(version).removeprefix("==")))
    return components


def _pypi_component(name: str, version: str) -> Component:
    normalized = re.sub(r"[-_.]+", "-", name).lower()
    return Component(
        name=name,
        version=version,
        ecosystem="PyPI",
        purl=f"pkg:pypi/{normalized}@{version}",
    )
