"""OSV.dev batch vulnerability lookup client."""

from __future__ import annotations

import asyncio
import hashlib
from typing import Any

import httpx

from depguard.feeds.cache import SQLiteCache
from depguard.models import Component

OSV_QUERY_URL = "https://api.osv.dev/v1/query"


class OsvClient:
    """Query OSV with bounded timeouts and stale-cache fallback."""

    def __init__(
        self,
        cache: SQLiteCache | None = None,
        timeout: float = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.cache = cache or SQLiteCache()
        self.timeout = timeout
        self.transport = transport

    async def lookup(
        self, components: list[Component], *, offline: bool = False
    ) -> tuple[list[dict[str, Any]], bool]:
        """Return per-component OSV responses and whether stale data was used."""
        query_records: list[tuple[int, dict[str, Any], str]] = []
        for index, component in enumerate(components):
            if component.version == "*" or any(char in component.version for char in "<>~^|,*"):
                continue
            ecosystem = "PyPI" if component.ecosystem.lower() in {"pypi", "python"} else "npm"
            query = {
                "package": {"name": component.name, "ecosystem": ecosystem},
                "version": component.version.lstrip("=v"),
            }
            key_material = f"{ecosystem}:{component.name.lower()}@{query['version']}"
            key = "osv:" + hashlib.sha256(key_material.encode()).hexdigest()
            query_records.append((index, query, key))
        if not query_records:
            return [{} for _ in components], False

        expanded: list[dict[str, Any]] = [{} for _ in components]
        stale_used = False
        semaphore = asyncio.Semaphore(5)
        async with httpx.AsyncClient(
            timeout=self.timeout,
            follow_redirects=False,
            transport=self.transport,
        ) as client:

            async def lookup_one(index: int, query: dict[str, Any], key: str) -> None:
                nonlocal stale_used
                cached = self.cache.get(key, allow_stale=offline)
                if cached and (offline or not cached[1]):
                    expanded[index] = cached[0]
                    stale_used = stale_used or cached[1]
                    return
                if offline:
                    return
                async with semaphore:
                    try:
                        response = await client.post(OSV_QUERY_URL, json=query)
                        response.raise_for_status()
                        payload = response.json()
                        self.cache.set(key, payload)
                        expanded[index] = payload
                    except (httpx.HTTPError, ValueError):
                        stale = self.cache.get(key, allow_stale=True)
                        if stale:
                            expanded[index] = stale[0]
                            stale_used = True

            await asyncio.gather(
                *(lookup_one(index, query, key) for index, query, key in query_records)
            )
        return expanded, stale_used
